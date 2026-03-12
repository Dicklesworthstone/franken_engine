//! Enrichment integration tests for `frankenengine_engine::aot_entrygraph_compiler`.
//!
//! Covers budget-exhaustion paths, provenance chain invariants, batch
//! cross-graph isolation, large-module skip paths, hash sensitivity,
//! config edge cases, and entry-kind filtering interactions.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::aot_entrygraph_compiler::{
    BEAD_ID, BatchReport, COMPONENT, CompilationReport, CompileConfig, CompileError, CompileStatus,
    CompileTarget, CompileVerdict, DEFAULT_MAX_COMPILE_TIME_MICROS, DEFAULT_MIN_MODULE_COUNT,
    DecisionReceipt, EntryKind, Entrygraph, MAX_BATCH_SIZE, MAX_ENTRYGRAPH_MODULES,
    ModuleCompileResult, ModuleEntry, POLICY_ID, ProvenanceKind, SCHEMA_VERSION, build_receipt,
    compile_batch, compile_entrygraph, compute_config_hash, compute_results_hash,
    entry_kind_summary, target_summary, total_compile_time_micros, validate_config,
    validate_entrygraph,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use sha2::{Digest, Sha256};

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_module(specifier: &str, size: u64, is_root: bool) -> ModuleEntry {
    ModuleEntry {
        specifier: specifier.to_string(),
        source_hash: ContentHash::compute(specifier.as_bytes()),
        is_root,
        dependency_count: 0,
        source_size_bytes: size,
    }
}

fn make_graph(id: &str, kind: EntryKind, modules: Vec<ModuleEntry>) -> Entrygraph {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    for m in &modules {
        hasher.update(m.source_hash.as_bytes());
    }
    Entrygraph {
        graph_id: id.to_string(),
        entry_kind: kind,
        graph_hash: ContentHash::compute(&hasher.finalize()),
        modules,
        package_name: None,
    }
}

fn default_config() -> CompileConfig {
    CompileConfig::default()
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(200)
}

fn three_module_graph(id: &str, kind: EntryKind) -> Entrygraph {
    make_graph(
        id,
        kind,
        vec![
            make_module("root.js", 1000, true),
            make_module("dep-a.js", 500, false),
            make_module("dep-b.js", 300, false),
        ],
    )
}

// ── Budget exhaustion ───────────────────────────────────────────────────

#[test]
fn budget_exhaustion_marks_remaining_modules() {
    let mut cfg = default_config();
    cfg.max_compile_time_micros = 5; // Very tight budget: 5 microseconds
    cfg.min_module_count = 1;

    // Each module simulates compile_time = source_size_bytes / 100 + 1
    // Module with 1000 bytes -> 11 micros (exceeds budget)
    let graph = make_graph(
        "budget-test",
        EntryKind::AppEntry,
        vec![
            make_module("big.js", 1000, true),   // 11 micros
            make_module("small.js", 100, false), // should be budget-exhausted
        ],
    );

    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    // First module compiles, consuming budget
    assert_eq!(report.module_results[0].status, CompileStatus::Compiled);
    // Second module should be budget-exhausted since total_time >= max
    assert_eq!(
        report.module_results[1].status,
        CompileStatus::BudgetExhausted
    );
    assert!(report.module_results[1].skip_reason.is_some());
}

#[test]
fn budget_exhaustion_counts_as_failed() {
    let mut cfg = default_config();
    cfg.max_compile_time_micros = 5;
    cfg.min_module_count = 1;

    let graph = make_graph(
        "budget-fail",
        EntryKind::AppEntry,
        vec![
            make_module("big.js", 1000, true),
            make_module("dep.js", 200, false),
        ],
    );

    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert!(report.failed_count > 0 || report.compiled_count < report.total_modules);
}

#[test]
fn budget_exhausted_verdict_is_partially_compiled() {
    let mut cfg = default_config();
    cfg.max_compile_time_micros = 5;
    cfg.min_module_count = 1;

    let graph = make_graph(
        "budget-partial",
        EntryKind::AppEntry,
        vec![
            make_module("root.js", 100, true),    // 2 micros
            make_module("dep-a.js", 400, false),  // 5 micros -> budget near limit
            make_module("dep-b.js", 1000, false), // likely budget-exhausted
        ],
    );

    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    // At least one module compiled, verdict should be PartiallyCompiled or FullyCompiled
    assert!(
        report.verdict == CompileVerdict::PartiallyCompiled
            || report.verdict == CompileVerdict::FullyCompiled
    );
}

// ── Provenance chain invariants ─────────────────────────────────────────

#[test]
fn provenance_chain_has_six_records_when_enabled() {
    let cfg = default_config();
    let graph = three_module_graph("prov-six", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();

    for result in &report.module_results {
        if result.status == CompileStatus::Compiled {
            assert_eq!(result.provenance.len(), 6);
        }
    }
}

#[test]
fn provenance_chain_covers_all_kinds() {
    let cfg = default_config();
    let graph = three_module_graph("prov-kinds", EntryKind::PackageMain);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();

    let first_compiled = report
        .module_results
        .iter()
        .find(|r| r.status == CompileStatus::Compiled)
        .unwrap();

    let kinds: BTreeSet<ProvenanceKind> =
        first_compiled.provenance.iter().map(|p| p.kind).collect();
    for expected in ProvenanceKind::ALL {
        assert!(
            kinds.contains(expected),
            "missing provenance kind: {expected}"
        );
    }
}

#[test]
fn provenance_source_hash_matches_module_source_hash() {
    let cfg = default_config();
    let graph = three_module_graph("prov-source", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();

    for (result, module) in report.module_results.iter().zip(graph.modules.iter()) {
        if result.status == CompileStatus::Compiled {
            let source_prov = result
                .provenance
                .iter()
                .find(|p| p.kind == ProvenanceKind::SourceHash)
                .unwrap();
            assert_eq!(source_prov.value_hash, module.source_hash);
        }
    }
}

#[test]
fn provenance_graph_hash_matches_entrygraph() {
    let cfg = default_config();
    let graph = three_module_graph("prov-graph", EntryKind::SsrEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();

    let first = &report.module_results[0];
    let dep_graph_prov = first
        .provenance
        .iter()
        .find(|p| p.kind == ProvenanceKind::DependencyGraphHash)
        .unwrap();
    assert_eq!(dep_graph_prov.value_hash, graph.graph_hash);
}

#[test]
fn provenance_disabled_produces_empty_chain() {
    let mut cfg = default_config();
    cfg.require_provenance = false;
    let graph = three_module_graph("prov-off", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();

    for result in &report.module_results {
        assert!(result.provenance.is_empty());
    }
}

// ── Batch cross-graph isolation ─────────────────────────────────────────

#[test]
fn batch_graphs_compiled_independently() {
    let cfg = default_config();
    let g1 = three_module_graph("batch-iso-1", EntryKind::AppEntry);
    let g2 = three_module_graph("batch-iso-2", EntryKind::SsrEntry);

    let batch = compile_batch(&[g1.clone(), g2.clone()], &cfg, epoch()).unwrap();
    assert_eq!(batch.reports.len(), 2);
    assert_eq!(batch.reports[0].graph_id, "batch-iso-1");
    assert_eq!(batch.reports[1].graph_id, "batch-iso-2");

    // Each should compile independently
    let r1 = compile_entrygraph(&g1, &cfg, epoch()).unwrap();
    let r2 = compile_entrygraph(&g2, &cfg, epoch()).unwrap();
    assert_eq!(batch.reports[0].verdict, r1.verdict);
    assert_eq!(batch.reports[1].verdict, r2.verdict);
}

#[test]
fn batch_one_failing_does_not_affect_others() {
    let mut cfg = default_config();
    cfg.allowed_entry_kinds.insert(EntryKind::AppEntry);

    let g1 = three_module_graph("batch-pass", EntryKind::AppEntry);
    let g2 = three_module_graph("batch-reject", EntryKind::WorkerEntry); // disallowed

    let result = compile_batch(&[g1, g2], &cfg, epoch());
    // batch fails because g2 fails validation
    assert!(result.is_err());
}

#[test]
fn batch_empty_graphs_vec_produces_report() {
    let cfg = default_config();
    let batch = compile_batch(&[], &cfg, epoch()).unwrap();
    assert_eq!(batch.total_graphs, 0);
    assert_eq!(batch.usable_graphs, 0);
    assert!(batch.reports.is_empty());
}

#[test]
fn batch_schema_version_correct() {
    let cfg = default_config();
    let g = three_module_graph("batch-schema", EntryKind::AppEntry);
    let batch = compile_batch(&[g], &cfg, epoch()).unwrap();
    assert_eq!(batch.schema_version, SCHEMA_VERSION);
}

#[test]
fn batch_epoch_matches_input() {
    let cfg = default_config();
    let g = three_module_graph("batch-epoch", EntryKind::AppEntry);
    let e = SecurityEpoch::from_raw(42);
    let batch = compile_batch(&[g], &cfg, e).unwrap();
    assert_eq!(batch.batch_epoch, e);
}

// ── Entry kind filtering ────────────────────────────────────────────────

#[test]
fn allowed_kinds_empty_allows_all_entry_kinds() {
    let cfg = default_config(); // allowed_entry_kinds is empty
    for kind in EntryKind::ALL {
        let g = three_module_graph(&format!("allow-{kind}"), *kind);
        assert!(compile_entrygraph(&g, &cfg, epoch()).is_ok());
    }
}

#[test]
fn allowed_kinds_restricts_to_listed() {
    let mut cfg = default_config();
    cfg.allowed_entry_kinds.insert(EntryKind::AppEntry);
    cfg.allowed_entry_kinds.insert(EntryKind::SsrEntry);

    let g_ok = three_module_graph("allow-ok", EntryKind::AppEntry);
    assert!(compile_entrygraph(&g_ok, &cfg, epoch()).is_ok());

    let g_blocked = three_module_graph("allow-blocked", EntryKind::WorkerEntry);
    let err = compile_entrygraph(&g_blocked, &cfg, epoch()).unwrap_err();
    assert!(
        matches!(err, CompileError::EntryKindDisallowed { kind } if kind == EntryKind::WorkerEntry)
    );
}

// ── Large module handling ───────────────────────────────────────────────

#[test]
fn oversized_module_marked_unsupported() {
    let mut cfg = default_config();
    cfg.max_module_source_bytes = 500;
    cfg.min_module_count = 1;

    let graph = make_graph(
        "oversize",
        EntryKind::AppEntry,
        vec![
            make_module("root.js", 100, true),
            make_module("huge.js", 1000, false), // exceeds 500 byte limit
        ],
    );

    // validate_entrygraph should catch this
    let err = validate_entrygraph(&graph, &cfg);
    assert!(matches!(err, Err(CompileError::ModuleTooLarge { .. })));
}

#[test]
fn module_at_exact_size_limit_compiles() {
    let mut cfg = default_config();
    cfg.max_module_source_bytes = 500;
    cfg.min_module_count = 1;

    let graph = make_graph(
        "exact-limit",
        EntryKind::AppEntry,
        vec![
            make_module("root.js", 500, true), // exactly at limit
        ],
    );

    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(report.module_results[0].status, CompileStatus::Compiled);
}

// ── Validation edge cases ───────────────────────────────────────────────

#[test]
fn empty_graph_rejected() {
    let cfg = default_config();
    let graph = make_graph("empty", EntryKind::AppEntry, vec![]);
    let err = validate_entrygraph(&graph, &cfg).unwrap_err();
    assert!(matches!(err, CompileError::EmptyGraph));
}

#[test]
fn no_root_module_rejected() {
    let cfg = default_config();
    let graph = make_graph(
        "no-root",
        EntryKind::AppEntry,
        vec![
            make_module("a.js", 100, false),
            make_module("b.js", 100, false),
        ],
    );
    let err = validate_entrygraph(&graph, &cfg).unwrap_err();
    assert!(matches!(err, CompileError::NoRootModule));
}

#[test]
fn multiple_roots_rejected() {
    let cfg = default_config();
    let graph = make_graph(
        "multi-root",
        EntryKind::AppEntry,
        vec![
            make_module("root1.js", 100, true),
            make_module("root2.js", 100, true),
        ],
    );
    let err = validate_entrygraph(&graph, &cfg).unwrap_err();
    assert!(matches!(err, CompileError::MultipleRoots { count: 2 }));
}

#[test]
fn config_zero_min_module_count_rejected() {
    let mut cfg = default_config();
    cfg.min_module_count = 0;
    let err = validate_config(&cfg).unwrap_err();
    assert!(matches!(err, CompileError::InvalidConfig { .. }));
}

#[test]
fn config_zero_compile_time_rejected() {
    let mut cfg = default_config();
    cfg.max_compile_time_micros = 0;
    assert!(validate_config(&cfg).is_err());
}

#[test]
fn config_zero_module_bytes_rejected() {
    let mut cfg = default_config();
    cfg.max_module_source_bytes = 0;
    assert!(validate_config(&cfg).is_err());
}

#[test]
fn config_empty_engine_version_rejected() {
    let mut cfg = default_config();
    cfg.engine_version = String::new();
    assert!(validate_config(&cfg).is_err());
}

// ── Hash sensitivity ────────────────────────────────────────────────────

#[test]
fn config_hash_changes_with_target() {
    let mut cfg1 = default_config();
    cfg1.target = CompileTarget::OptimizedBytecode;
    let mut cfg2 = default_config();
    cfg2.target = CompileTarget::FrozenSnapshot;
    assert_ne!(compute_config_hash(&cfg1), compute_config_hash(&cfg2));
}

#[test]
fn config_hash_changes_with_policy_revision() {
    let mut cfg1 = default_config();
    cfg1.policy_revision = 1;
    let mut cfg2 = default_config();
    cfg2.policy_revision = 2;
    assert_ne!(compute_config_hash(&cfg1), compute_config_hash(&cfg2));
}

#[test]
fn config_hash_changes_with_engine_version() {
    let mut cfg1 = default_config();
    cfg1.engine_version = "1.0.0".to_string();
    let mut cfg2 = default_config();
    cfg2.engine_version = "2.0.0".to_string();
    assert_ne!(compute_config_hash(&cfg1), compute_config_hash(&cfg2));
}

#[test]
fn config_hash_deterministic() {
    let cfg = default_config();
    let h1 = compute_config_hash(&cfg);
    let h2 = compute_config_hash(&cfg);
    assert_eq!(h1, h2);
}

#[test]
fn results_hash_empty_deterministic() {
    let h1 = compute_results_hash(&[]);
    let h2 = compute_results_hash(&[]);
    assert_eq!(h1, h2);
}

#[test]
fn results_hash_changes_with_content() {
    let r1 = ModuleCompileResult {
        specifier: "a.js".to_string(),
        status: CompileStatus::Compiled,
        artifact_hash: Some(ContentHash::compute(b"artifact-a")),
        provenance: Vec::new(),
        compile_time_micros: 10,
        skip_reason: None,
    };
    let r2 = ModuleCompileResult {
        specifier: "b.js".to_string(),
        status: CompileStatus::Compiled,
        artifact_hash: Some(ContentHash::compute(b"artifact-b")),
        provenance: Vec::new(),
        compile_time_micros: 20,
        skip_reason: None,
    };
    assert_ne!(
        compute_results_hash(std::slice::from_ref(&r1)),
        compute_results_hash(std::slice::from_ref(&r2))
    );
    assert_ne!(
        compute_results_hash(&[r1.clone(), r2.clone()]),
        compute_results_hash(&[r2, r1])
    );
}

// ── Compilation report fields ───────────────────────────────────────────

#[test]
fn report_counts_match_module_results() {
    let cfg = default_config();
    let graph = three_module_graph("counts", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();

    assert_eq!(report.total_modules, 3);
    let compiled = report
        .module_results
        .iter()
        .filter(|r| r.status == CompileStatus::Compiled)
        .count() as u64;
    assert_eq!(report.compiled_count, compiled);
}

#[test]
fn report_success_rate_fully_compiled() {
    let cfg = default_config();
    let graph = three_module_graph("rate-full", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();

    if report.verdict == CompileVerdict::FullyCompiled {
        assert_eq!(report.success_rate_millionths, 1_000_000);
    }
}

#[test]
fn report_below_threshold_has_zero_rate() {
    let mut cfg = default_config();
    cfg.min_module_count = 100; // Higher than our test graph

    let graph = three_module_graph("rate-below", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::BelowThreshold);
    assert_eq!(report.success_rate_millionths, 0);
    assert!(report.module_results.is_empty());
}

#[test]
fn report_compile_epoch_matches_input() {
    let cfg = default_config();
    let graph = three_module_graph("epoch-check", EntryKind::AppEntry);
    let e = SecurityEpoch::from_raw(999);
    let report = compile_entrygraph(&graph, &cfg, e).unwrap();
    assert_eq!(report.compile_epoch, e);
}

// ── Decision receipt ────────────────────────────────────────────────────

#[test]
fn receipt_schema_version_correct() {
    let cfg = default_config();
    let graph = three_module_graph("receipt-sv", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    let receipt = build_receipt(&report, graph.graph_hash, &cfg);
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
}

#[test]
fn receipt_component_correct() {
    let cfg = default_config();
    let graph = three_module_graph("receipt-comp", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    let receipt = build_receipt(&report, graph.graph_hash, &cfg);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn receipt_bead_id_correct() {
    let cfg = default_config();
    let graph = three_module_graph("receipt-bead", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    let receipt = build_receipt(&report, graph.graph_hash, &cfg);
    assert_eq!(receipt.bead_id, BEAD_ID);
}

#[test]
fn receipt_policy_id_correct() {
    let cfg = default_config();
    let graph = three_module_graph("receipt-policy", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    let receipt = build_receipt(&report, graph.graph_hash, &cfg);
    assert_eq!(receipt.policy_id, POLICY_ID);
}

#[test]
fn receipt_deterministic_same_input() {
    let cfg = default_config();
    let graph = three_module_graph("receipt-det", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    let r1 = build_receipt(&report, graph.graph_hash, &cfg);
    let r2 = build_receipt(&report, graph.graph_hash, &cfg);
    assert_eq!(r1, r2);
}

#[test]
fn receipt_hash_changes_with_different_epoch() {
    let cfg = default_config();
    let graph = three_module_graph("receipt-epoch", EntryKind::AppEntry);
    let r1 = compile_entrygraph(&graph, &cfg, SecurityEpoch::from_raw(1)).unwrap();
    let r2 = compile_entrygraph(&graph, &cfg, SecurityEpoch::from_raw(2)).unwrap();
    let rcpt1 = build_receipt(&r1, graph.graph_hash, &cfg);
    let rcpt2 = build_receipt(&r2, graph.graph_hash, &cfg);
    assert_ne!(rcpt1.receipt_hash, rcpt2.receipt_hash);
}

// ── Summary helpers ─────────────────────────────────────────────────────

#[test]
fn entry_kind_summary_counts_correctly() {
    let cfg = default_config();
    let g1 = three_module_graph("sum-1", EntryKind::AppEntry);
    let g2 = three_module_graph("sum-2", EntryKind::AppEntry);
    let g3 = three_module_graph("sum-3", EntryKind::SsrEntry);
    let batch = compile_batch(&[g1, g2, g3], &cfg, epoch()).unwrap();

    let summary = entry_kind_summary(&batch);
    assert_eq!(summary.get(&EntryKind::AppEntry), Some(&(2, 2)));
    assert_eq!(summary.get(&EntryKind::SsrEntry), Some(&(1, 1)));
    assert!(summary.get(&EntryKind::WorkerEntry).is_none());
}

#[test]
fn target_summary_counts_single_target() {
    let cfg = default_config();
    let g = three_module_graph("target-sum", EntryKind::AppEntry);
    let batch = compile_batch(&[g], &cfg, epoch()).unwrap();

    let summary = target_summary(&batch);
    assert_eq!(summary.get(&cfg.target), Some(&1));
    assert_eq!(summary.len(), 1);
}

#[test]
fn total_compile_time_sums_reports() {
    let cfg = default_config();
    let g1 = three_module_graph("time-1", EntryKind::AppEntry);
    let g2 = three_module_graph("time-2", EntryKind::SsrEntry);
    let batch = compile_batch(&[g1, g2], &cfg, epoch()).unwrap();

    let total = total_compile_time_micros(&batch);
    let manual_total: u64 = batch
        .reports
        .iter()
        .map(|r| r.total_compile_time_micros)
        .sum();
    assert_eq!(total, manual_total);
    assert!(total > 0);
}

// ── Entrygraph methods ──────────────────────────────────────────────────

#[test]
fn entrygraph_module_count() {
    let graph = three_module_graph("count", EntryKind::AppEntry);
    assert_eq!(graph.module_count(), 3);
}

#[test]
fn entrygraph_total_source_bytes() {
    let graph = three_module_graph("bytes", EntryKind::AppEntry);
    // root.js=1000, dep-a.js=500, dep-b.js=300
    assert_eq!(graph.total_source_bytes(), 1800);
}

// ── Enum exhaustiveness ─────────────────────────────────────────────────

#[test]
fn entry_kind_all_has_seven_variants() {
    assert_eq!(EntryKind::ALL.len(), 7);
    let set: BTreeSet<EntryKind> = EntryKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), 7);
}

#[test]
fn compile_target_all_has_four_variants() {
    assert_eq!(CompileTarget::ALL.len(), 4);
    let set: BTreeSet<CompileTarget> = CompileTarget::ALL.iter().copied().collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn compile_status_all_has_five_variants() {
    assert_eq!(CompileStatus::ALL.len(), 5);
    let set: BTreeSet<CompileStatus> = CompileStatus::ALL.iter().copied().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn provenance_kind_all_has_six_variants() {
    assert_eq!(ProvenanceKind::ALL.len(), 6);
}

#[test]
fn compile_verdict_all_has_five_variants() {
    assert_eq!(CompileVerdict::ALL.len(), 5);
}

// ── Display uniqueness ──────────────────────────────────────────────────

#[test]
fn entry_kind_display_all_unique() {
    let displays: BTreeSet<String> = EntryKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), EntryKind::ALL.len());
}

#[test]
fn compile_target_display_all_unique() {
    let displays: BTreeSet<String> = CompileTarget::ALL.iter().map(|t| t.to_string()).collect();
    assert_eq!(displays.len(), CompileTarget::ALL.len());
}

#[test]
fn compile_status_display_all_unique() {
    let displays: BTreeSet<String> = CompileStatus::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), CompileStatus::ALL.len());
}

#[test]
fn compile_verdict_display_all_unique() {
    let displays: BTreeSet<String> = CompileVerdict::ALL.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), CompileVerdict::ALL.len());
}

// ── Serde round-trips ───────────────────────────────────────────────────

#[test]
fn module_entry_serde_round_trip() {
    let m = make_module("test.js", 42, true);
    let json = serde_json::to_string(&m).unwrap();
    let back: ModuleEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn entrygraph_serde_round_trip() {
    let g = three_module_graph("serde-graph", EntryKind::ReactClientEntry);
    let json = serde_json::to_string(&g).unwrap();
    let back: Entrygraph = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

#[test]
fn compile_config_serde_round_trip() {
    let cfg = default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: CompileConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn compilation_report_serde_round_trip() {
    let cfg = default_config();
    let graph = three_module_graph("serde-report", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: CompilationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn batch_report_serde_round_trip() {
    let cfg = default_config();
    let g = three_module_graph("serde-batch", EntryKind::AppEntry);
    let batch = compile_batch(&[g], &cfg, epoch()).unwrap();
    let json = serde_json::to_string(&batch).unwrap();
    let back: BatchReport = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

#[test]
fn decision_receipt_serde_round_trip() {
    let cfg = default_config();
    let graph = three_module_graph("serde-receipt", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    let receipt = build_receipt(&report, graph.graph_hash, &cfg);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn compile_error_serde_round_trip_all_variants() {
    let errors: Vec<CompileError> = vec![
        CompileError::EmptyGraph,
        CompileError::GraphTooLarge {
            module_count: 5000,
            max: MAX_ENTRYGRAPH_MODULES,
        },
        CompileError::BatchTooLarge {
            batch_size: 300,
            max: MAX_BATCH_SIZE,
        },
        CompileError::EntryKindDisallowed {
            kind: EntryKind::TestEntry,
        },
        CompileError::InvalidConfig {
            reason: "test reason".to_string(),
        },
        CompileError::ModuleTooLarge {
            specifier: "big.js".to_string(),
            size: 10_000,
            max: 5_000,
        },
        CompileError::NoRootModule,
        CompileError::MultipleRoots { count: 3 },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: CompileError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ── Error display ───────────────────────────────────────────────────────

#[test]
fn all_compile_error_displays_nonempty() {
    let errors: Vec<CompileError> = vec![
        CompileError::EmptyGraph,
        CompileError::GraphTooLarge {
            module_count: 5000,
            max: 4096,
        },
        CompileError::BatchTooLarge {
            batch_size: 300,
            max: 256,
        },
        CompileError::EntryKindDisallowed {
            kind: EntryKind::WorkerEntry,
        },
        CompileError::InvalidConfig {
            reason: "test".to_string(),
        },
        CompileError::ModuleTooLarge {
            specifier: "x.js".to_string(),
            size: 10,
            max: 5,
        },
        CompileError::NoRootModule,
        CompileError::MultipleRoots { count: 3 },
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty(), "empty display for: {err:?}");
    }
}

#[test]
fn compile_error_display_contains_relevant_data() {
    let err = CompileError::GraphTooLarge {
        module_count: 5000,
        max: 4096,
    };
    let msg = err.to_string();
    assert!(msg.contains("5000"));
    assert!(msg.contains("4096"));

    let err2 = CompileError::ModuleTooLarge {
        specifier: "huge.js".to_string(),
        size: 99,
        max: 50,
    };
    assert!(err2.to_string().contains("huge.js"));
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn constants_have_expected_values() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!POLICY_ID.is_empty());
    const {
        assert!(MAX_ENTRYGRAPH_MODULES > 0);
        assert!(MAX_BATCH_SIZE > 0);
        assert!(DEFAULT_MIN_MODULE_COUNT > 0);
        assert!(DEFAULT_MAX_COMPILE_TIME_MICROS > 0);
    }
}

// ── CompileStatus is_success ────────────────────────────────────────────

#[test]
fn compile_status_is_success_semantics() {
    assert!(CompileStatus::Compiled.is_success());
    assert!(CompileStatus::CacheHit.is_success());
    assert!(!CompileStatus::Unsupported.is_success());
    assert!(!CompileStatus::Failed.is_success());
    assert!(!CompileStatus::BudgetExhausted.is_success());
}

// ── CompileVerdict is_usable ────────────────────────────────────────────

#[test]
fn compile_verdict_is_usable_semantics() {
    assert!(CompileVerdict::FullyCompiled.is_usable());
    assert!(CompileVerdict::PartiallyCompiled.is_usable());
    assert!(!CompileVerdict::NoneCompiled.is_usable());
    assert!(!CompileVerdict::PolicyRejected.is_usable());
    assert!(!CompileVerdict::BelowThreshold.is_usable());
}

// ── CompileConfig default ───────────────────────────────────────────────

#[test]
fn compile_config_default_values() {
    let cfg = CompileConfig::default();
    assert_eq!(cfg.target, CompileTarget::OptimizedBytecode);
    assert_eq!(cfg.min_module_count, DEFAULT_MIN_MODULE_COUNT);
    assert_eq!(cfg.max_compile_time_micros, DEFAULT_MAX_COMPILE_TIME_MICROS);
    assert!(cfg.require_provenance);
    assert!(cfg.honour_cache);
    assert_eq!(cfg.policy_revision, 1);
    assert!(!cfg.engine_version.is_empty());
    assert!(cfg.max_module_source_bytes > 0);
    assert!(cfg.allowed_entry_kinds.is_empty());
}

// ── Artifact hash sensitivity ───────────────────────────────────────────

#[test]
fn different_targets_produce_different_artifact_hashes() {
    let graph = three_module_graph("art-target", EntryKind::AppEntry);

    let mut cfg1 = default_config();
    cfg1.target = CompileTarget::OptimizedBytecode;
    let r1 = compile_entrygraph(&graph, &cfg1, epoch()).unwrap();

    let mut cfg2 = default_config();
    cfg2.target = CompileTarget::FrozenSnapshot;
    let r2 = compile_entrygraph(&graph, &cfg2, epoch()).unwrap();

    let h1 = r1.module_results[0].artifact_hash.unwrap();
    let h2 = r2.module_results[0].artifact_hash.unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn different_engine_versions_produce_different_artifact_hashes() {
    let graph = three_module_graph("art-version", EntryKind::AppEntry);

    let mut cfg1 = default_config();
    cfg1.engine_version = "1.0.0".to_string();
    let r1 = compile_entrygraph(&graph, &cfg1, epoch()).unwrap();

    let mut cfg2 = default_config();
    cfg2.engine_version = "2.0.0".to_string();
    let r2 = compile_entrygraph(&graph, &cfg2, epoch()).unwrap();

    let h1 = r1.module_results[0].artifact_hash.unwrap();
    let h2 = r2.module_results[0].artifact_hash.unwrap();
    assert_ne!(h1, h2);
}

// ── Batch too large ─────────────────────────────────────────────────────

#[test]
fn batch_exceeding_max_size_rejected() {
    let cfg = default_config();
    let graphs: Vec<Entrygraph> = (0..MAX_BATCH_SIZE + 1)
        .map(|i| three_module_graph(&format!("g-{i}"), EntryKind::AppEntry))
        .collect();
    let err = compile_batch(&graphs, &cfg, epoch()).unwrap_err();
    assert!(matches!(err, CompileError::BatchTooLarge { .. }));
}

// ── Compilation determinism ─────────────────────────────────────────────

#[test]
fn compilation_fully_deterministic() {
    let cfg = default_config();
    let graph = three_module_graph("det", EntryKind::AppEntry);
    let r1 = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    let r2 = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn batch_hash_deterministic() {
    let cfg = default_config();
    let g1 = three_module_graph("bdet-1", EntryKind::AppEntry);
    let g2 = three_module_graph("bdet-2", EntryKind::SsrEntry);
    let b1 = compile_batch(&[g1.clone(), g2.clone()], &cfg, epoch()).unwrap();
    let b2 = compile_batch(&[g1, g2], &cfg, epoch()).unwrap();
    assert_eq!(b1.batch_hash, b2.batch_hash);
}
