//! Integration tests for the AOT entrygraph compiler module.

use std::collections::BTreeSet;

use frankenengine_engine::aot_entrygraph_compiler::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

fn make_graph_with_package(
    id: &str,
    kind: EntryKind,
    modules: Vec<ModuleEntry>,
    pkg: &str,
) -> Entrygraph {
    let mut g = make_graph(id, kind, modules);
    g.package_name = Some(pkg.to_string());
    g
}

fn default_config() -> CompileConfig {
    CompileConfig::default()
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn three_module_graph(id: &str, kind: EntryKind) -> Entrygraph {
    make_graph(
        id,
        kind,
        vec![
            make_module("root.js", 500, true),
            make_module("dep1.js", 300, false),
            make_module("dep2.js", 200, false),
        ],
    )
}

// ---------------------------------------------------------------------------
// Basic compilation
// ---------------------------------------------------------------------------

#[test]
fn test_compile_app_entry_fully() {
    let graph = three_module_graph("g1", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
    assert_eq!(report.compiled_count, 3);
    assert_eq!(report.failed_count, 0);
    assert_eq!(report.success_rate_millionths, 1_000_000);
}

#[test]
fn test_compile_ssr_entry() {
    let graph = three_module_graph("ssr1", EntryKind::SsrEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
    assert_eq!(report.entry_kind, EntryKind::SsrEntry);
}

#[test]
fn test_compile_react_client_entry() {
    let graph = three_module_graph("react1", EntryKind::ReactClientEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
    assert_eq!(report.entry_kind, EntryKind::ReactClientEntry);
}

#[test]
fn test_compile_worker_entry() {
    let graph = three_module_graph("w1", EntryKind::WorkerEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
}

#[test]
fn test_compile_package_main() {
    let graph = three_module_graph("p1", EntryKind::PackageMain);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
}

#[test]
fn test_compile_package_subpath() {
    let graph = three_module_graph("ps1", EntryKind::PackageSubpath);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
}

#[test]
fn test_compile_test_entry() {
    let graph = three_module_graph("t1", EntryKind::TestEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
}

// ---------------------------------------------------------------------------
// Below threshold
// ---------------------------------------------------------------------------

#[test]
fn test_below_threshold_single_module() {
    let graph = make_graph(
        "small",
        EntryKind::AppEntry,
        vec![make_module("only.js", 100, true)],
    );
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::BelowThreshold);
    assert_eq!(report.compiled_count, 0);
    assert!(report.module_results.is_empty());
}

#[test]
fn test_below_threshold_two_modules() {
    let graph = make_graph(
        "small2",
        EntryKind::AppEntry,
        vec![
            make_module("a.js", 100, true),
            make_module("b.js", 100, false),
        ],
    );
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::BelowThreshold);
}

#[test]
fn test_at_threshold_compiles() {
    let graph = make_graph(
        "exact",
        EntryKind::AppEntry,
        vec![
            make_module("a.js", 100, true),
            make_module("b.js", 100, false),
            make_module("c.js", 100, false),
        ],
    );
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
}

#[test]
fn test_custom_threshold() {
    let graph = make_graph(
        "custom",
        EntryKind::AppEntry,
        vec![
            make_module("a.js", 100, true),
            make_module("b.js", 100, false),
            make_module("c.js", 100, false),
        ],
    );
    let mut cfg = default_config();
    cfg.min_module_count = 10;
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::BelowThreshold);
}

// ---------------------------------------------------------------------------
// Compile targets
// ---------------------------------------------------------------------------

#[test]
fn test_compile_optimized_bytecode_target() {
    let graph = three_module_graph("t1", EntryKind::AppEntry);
    let mut cfg = default_config();
    cfg.target = CompileTarget::OptimizedBytecode;
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(report.target, CompileTarget::OptimizedBytecode);
}

#[test]
fn test_compile_pre_lowered_ir_target() {
    let graph = three_module_graph("t2", EntryKind::AppEntry);
    let mut cfg = default_config();
    cfg.target = CompileTarget::PreLoweredIr;
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(report.target, CompileTarget::PreLoweredIr);
}

#[test]
fn test_compile_frozen_snapshot_target() {
    let graph = three_module_graph("t3", EntryKind::AppEntry);
    let mut cfg = default_config();
    cfg.target = CompileTarget::FrozenSnapshot;
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(report.target, CompileTarget::FrozenSnapshot);
}

#[test]
fn test_compile_cache_artifact_target() {
    let graph = three_module_graph("t4", EntryKind::AppEntry);
    let mut cfg = default_config();
    cfg.target = CompileTarget::CacheArtifact;
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(report.target, CompileTarget::CacheArtifact);
}

#[test]
fn test_different_targets_produce_different_artifacts() {
    let graph = three_module_graph("td", EntryKind::AppEntry);
    let mut cfg1 = default_config();
    cfg1.target = CompileTarget::OptimizedBytecode;
    let mut cfg2 = default_config();
    cfg2.target = CompileTarget::FrozenSnapshot;
    let r1 = compile_entrygraph(&graph, &cfg1, epoch()).unwrap();
    let r2 = compile_entrygraph(&graph, &cfg2, epoch()).unwrap();
    assert_ne!(
        r1.module_results[0].artifact_hash,
        r2.module_results[0].artifact_hash
    );
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

#[test]
fn test_provenance_chain_complete() {
    let graph = three_module_graph("prov1", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    for mr in &report.module_results {
        assert_eq!(mr.provenance.len(), 6);
        let kinds: BTreeSet<_> = mr.provenance.iter().map(|p| p.kind).collect();
        for pk in ProvenanceKind::ALL {
            assert!(kinds.contains(pk), "missing provenance kind {pk}");
        }
    }
}

#[test]
fn test_provenance_source_hash_matches() {
    let modules = vec![
        make_module("src.js", 100, true),
        make_module("dep.js", 50, false),
        make_module("dep2.js", 50, false),
    ];
    let graph = make_graph("ph", EntryKind::AppEntry, modules.clone());
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    for (mr, m) in report.module_results.iter().zip(modules.iter()) {
        let source_prov = mr
            .provenance
            .iter()
            .find(|p| p.kind == ProvenanceKind::SourceHash)
            .unwrap();
        assert_eq!(source_prov.value_hash, m.source_hash);
    }
}

#[test]
fn test_provenance_disabled() {
    let graph = three_module_graph("noprov", EntryKind::AppEntry);
    let mut cfg = default_config();
    cfg.require_provenance = false;
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    for mr in &report.module_results {
        assert!(mr.provenance.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

#[test]
fn test_empty_graph_error() {
    let graph = make_graph("empty", EntryKind::AppEntry, vec![]);
    let result = compile_entrygraph(&graph, &default_config(), epoch());
    assert!(matches!(result, Err(CompileError::EmptyGraph)));
}

#[test]
fn test_no_root_error() {
    let graph = make_graph(
        "noroot",
        EntryKind::AppEntry,
        vec![make_module("a.js", 100, false)],
    );
    let result = compile_entrygraph(&graph, &default_config(), epoch());
    assert!(matches!(result, Err(CompileError::NoRootModule)));
}

#[test]
fn test_multiple_roots_error() {
    let graph = make_graph(
        "multi",
        EntryKind::AppEntry,
        vec![
            make_module("a.js", 100, true),
            make_module("b.js", 100, true),
        ],
    );
    let result = compile_entrygraph(&graph, &default_config(), epoch());
    assert!(matches!(
        result,
        Err(CompileError::MultipleRoots { count: 2 })
    ));
}

#[test]
fn test_entry_kind_disallowed() {
    let graph = three_module_graph("dis", EntryKind::TestEntry);
    let mut cfg = default_config();
    cfg.allowed_entry_kinds.insert(EntryKind::AppEntry);
    cfg.allowed_entry_kinds.insert(EntryKind::SsrEntry);
    let result = compile_entrygraph(&graph, &cfg, epoch());
    assert!(matches!(
        result,
        Err(CompileError::EntryKindDisallowed {
            kind: EntryKind::TestEntry
        })
    ));
}

#[test]
fn test_module_too_large() {
    let graph = make_graph(
        "big",
        EntryKind::AppEntry,
        vec![
            make_module("root.js", 100, true),
            make_module("huge.js", 10_000_000, false),
            make_module("small.js", 100, false),
        ],
    );
    let result = compile_entrygraph(&graph, &default_config(), epoch());
    assert!(matches!(result, Err(CompileError::ModuleTooLarge { .. })));
}

#[test]
fn test_invalid_config_zero_min() {
    let graph = three_module_graph("ic", EntryKind::AppEntry);
    let mut cfg = default_config();
    cfg.min_module_count = 0;
    let result = compile_entrygraph(&graph, &cfg, epoch());
    assert!(matches!(result, Err(CompileError::InvalidConfig { .. })));
}

#[test]
fn test_invalid_config_zero_time() {
    let mut cfg = default_config();
    cfg.max_compile_time_micros = 0;
    assert!(matches!(
        validate_config(&cfg),
        Err(CompileError::InvalidConfig { .. })
    ));
}

#[test]
fn test_invalid_config_empty_version() {
    let mut cfg = default_config();
    cfg.engine_version = String::new();
    assert!(matches!(
        validate_config(&cfg),
        Err(CompileError::InvalidConfig { .. })
    ));
}

// ---------------------------------------------------------------------------
// Batch compilation
// ---------------------------------------------------------------------------

#[test]
fn test_batch_single_graph() {
    let graph = three_module_graph("b1", EntryKind::AppEntry);
    let batch = compile_batch(&[graph], &default_config(), epoch()).unwrap();
    assert_eq!(batch.total_graphs, 1);
    assert_eq!(batch.usable_graphs, 1);
}

#[test]
fn test_batch_mixed_kinds() {
    let g1 = three_module_graph("g1", EntryKind::AppEntry);
    let g2 = three_module_graph("g2", EntryKind::SsrEntry);
    let g3 = three_module_graph("g3", EntryKind::ReactClientEntry);
    let batch = compile_batch(&[g1, g2, g3], &default_config(), epoch()).unwrap();
    assert_eq!(batch.total_graphs, 3);
    assert_eq!(batch.usable_graphs, 3);
}

#[test]
fn test_batch_with_below_threshold() {
    let g1 = three_module_graph("g1", EntryKind::AppEntry);
    let g2 = make_graph(
        "g2",
        EntryKind::AppEntry,
        vec![make_module("solo.js", 100, true)],
    );
    let batch = compile_batch(&[g1, g2], &default_config(), epoch()).unwrap();
    assert_eq!(batch.total_graphs, 2);
    assert_eq!(batch.usable_graphs, 1);
}

#[test]
fn test_batch_empty() {
    let batch = compile_batch(&[], &default_config(), epoch()).unwrap();
    assert_eq!(batch.total_graphs, 0);
    assert_eq!(batch.usable_graphs, 0);
    assert_eq!(batch.aggregate_success_rate_millionths, 0);
}

#[test]
fn test_batch_too_large() {
    let graphs: Vec<_> = (0..257)
        .map(|i| {
            make_graph(
                &format!("g{i}"),
                EntryKind::AppEntry,
                vec![make_module(&format!("m{i}.js"), 100, true)],
            )
        })
        .collect();
    let result = compile_batch(&graphs, &default_config(), epoch());
    assert!(matches!(result, Err(CompileError::BatchTooLarge { .. })));
}

#[test]
fn test_batch_aggregate_rate() {
    let g1 = three_module_graph("g1", EntryKind::AppEntry);
    let g2 = three_module_graph("g2", EntryKind::SsrEntry);
    let batch = compile_batch(&[g1, g2], &default_config(), epoch()).unwrap();
    assert_eq!(batch.aggregate_success_rate_millionths, 1_000_000);
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_fields() {
    let graph = three_module_graph("rg1", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    let receipt = build_receipt(&report, graph.graph_hash, &default_config());
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.policy_id, POLICY_ID);
    assert_eq!(receipt.graph_id, "rg1");
    assert_eq!(receipt.verdict, CompileVerdict::FullyCompiled);
    assert_eq!(receipt.decision_epoch.as_u64(), 100);
}

#[test]
fn test_receipt_deterministic() {
    let graph = three_module_graph("det", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    let r1 = build_receipt(&report, graph.graph_hash.clone(), &default_config());
    let r2 = build_receipt(&report, graph.graph_hash, &default_config());
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
    assert_eq!(r1.config_hash, r2.config_hash);
    assert_eq!(r1.results_hash, r2.results_hash);
}

#[test]
fn test_receipt_changes_with_config() {
    let graph = three_module_graph("rc", EntryKind::AppEntry);
    let cfg1 = default_config();
    let mut cfg2 = default_config();
    cfg2.policy_revision = 42;
    let r1 = compile_entrygraph(&graph, &cfg1, epoch()).unwrap();
    let r2 = compile_entrygraph(&graph, &cfg2, epoch()).unwrap();
    let rec1 = build_receipt(&r1, graph.graph_hash.clone(), &cfg1);
    let rec2 = build_receipt(&r2, graph.graph_hash, &cfg2);
    assert_ne!(rec1.config_hash, rec2.config_hash);
    assert_ne!(rec1.receipt_hash, rec2.receipt_hash);
}

#[test]
fn test_receipt_changes_with_epoch() {
    let graph = three_module_graph("re", EntryKind::AppEntry);
    let r1 = compile_entrygraph(&graph, &default_config(), SecurityEpoch::from_raw(1)).unwrap();
    let r2 = compile_entrygraph(&graph, &default_config(), SecurityEpoch::from_raw(2)).unwrap();
    let rec1 = build_receipt(&r1, graph.graph_hash.clone(), &default_config());
    let rec2 = build_receipt(&r2, graph.graph_hash, &default_config());
    assert_ne!(rec1.receipt_hash, rec2.receipt_hash);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn test_compilation_deterministic() {
    let graph = three_module_graph("det1", EntryKind::AppEntry);
    let r1 = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    let r2 = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(r1.module_results.len(), r2.module_results.len());
    for (a, b) in r1.module_results.iter().zip(r2.module_results.iter()) {
        assert_eq!(a.artifact_hash, b.artifact_hash);
        assert_eq!(a.status, b.status);
    }
}

#[test]
fn test_batch_hash_deterministic() {
    let g1 = three_module_graph("g1", EntryKind::AppEntry);
    let g2 = three_module_graph("g2", EntryKind::SsrEntry);
    let b1 = compile_batch(&[g1.clone(), g2.clone()], &default_config(), epoch()).unwrap();
    let b2 = compile_batch(&[g1, g2], &default_config(), epoch()).unwrap();
    assert_eq!(b1.batch_hash, b2.batch_hash);
}

// ---------------------------------------------------------------------------
// Summary helpers
// ---------------------------------------------------------------------------

#[test]
fn test_entry_kind_summary_counts() {
    let g1 = three_module_graph("g1", EntryKind::AppEntry);
    let g2 = three_module_graph("g2", EntryKind::AppEntry);
    let g3 = three_module_graph("g3", EntryKind::SsrEntry);
    let batch = compile_batch(&[g1, g2, g3], &default_config(), epoch()).unwrap();
    let summary = entry_kind_summary(&batch);
    assert_eq!(summary[&EntryKind::AppEntry], (2, 2));
    assert_eq!(summary[&EntryKind::SsrEntry], (1, 1));
}

#[test]
fn test_target_summary_single() {
    let g = three_module_graph("g1", EntryKind::AppEntry);
    let batch = compile_batch(&[g], &default_config(), epoch()).unwrap();
    let summary = target_summary(&batch);
    assert_eq!(summary[&CompileTarget::OptimizedBytecode], 1);
}

#[test]
fn test_total_compile_time_positive() {
    let g = three_module_graph("g1", EntryKind::AppEntry);
    let batch = compile_batch(&[g], &default_config(), epoch()).unwrap();
    assert!(total_compile_time_micros(&batch) > 0);
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_compilation_report_serde() {
    let graph = three_module_graph("sr1", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: CompilationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn test_batch_report_serde() {
    let g1 = three_module_graph("g1", EntryKind::AppEntry);
    let g2 = three_module_graph("g2", EntryKind::SsrEntry);
    let batch = compile_batch(&[g1, g2], &default_config(), epoch()).unwrap();
    let json = serde_json::to_string(&batch).unwrap();
    let back: BatchReport = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

#[test]
fn test_receipt_serde() {
    let graph = three_module_graph("rs1", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    let receipt = build_receipt(&report, graph.graph_hash, &default_config());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn test_entry_kind_serde() {
    for k in EntryKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: EntryKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn test_compile_target_serde() {
    for t in CompileTarget::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: CompileTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn test_compile_status_serde() {
    for s in CompileStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: CompileStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn test_compile_verdict_serde() {
    for v in CompileVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: CompileVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn test_compile_error_serde() {
    let errors = vec![
        CompileError::EmptyGraph,
        CompileError::NoRootModule,
        CompileError::MultipleRoots { count: 3 },
        CompileError::GraphTooLarge {
            module_count: 5000,
            max: 4096,
        },
        CompileError::BatchTooLarge {
            batch_size: 300,
            max: 256,
        },
        CompileError::EntryKindDisallowed {
            kind: EntryKind::TestEntry,
        },
        CompileError::InvalidConfig {
            reason: "test".into(),
        },
        CompileError::ModuleTooLarge {
            specifier: "big.js".into(),
            size: 999,
            max: 100,
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: CompileError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_large_graph() {
    let mut modules = vec![make_module("root.js", 100, true)];
    for i in 0..100 {
        modules.push(make_module(&format!("dep{i}.js"), 50, false));
    }
    let graph = make_graph("large", EntryKind::AppEntry, modules);
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
    assert_eq!(report.total_modules, 101);
    assert_eq!(report.compiled_count, 101);
}

#[test]
fn test_graph_with_package_name() {
    let modules = vec![
        make_module("index.js", 100, true),
        make_module("lib.js", 200, false),
        make_module("util.js", 150, false),
    ];
    let graph = make_graph_with_package("pkg1", EntryKind::PackageMain, modules, "my-package");
    assert_eq!(graph.package_name.as_deref(), Some("my-package"));
    let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
}

#[test]
fn test_allowed_entry_kinds_empty_allows_all() {
    let cfg = default_config();
    assert!(cfg.allowed_entry_kinds.is_empty());
    for kind in EntryKind::ALL {
        let graph = three_module_graph("ak", *kind);
        let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
        assert!(report.verdict.is_usable() || report.verdict == CompileVerdict::BelowThreshold);
    }
}

#[test]
fn test_allowed_entry_kinds_restricts() {
    let mut cfg = default_config();
    cfg.allowed_entry_kinds.insert(EntryKind::AppEntry);
    let graph = three_module_graph("restricted", EntryKind::SsrEntry);
    let result = compile_entrygraph(&graph, &cfg, epoch());
    assert!(matches!(
        result,
        Err(CompileError::EntryKindDisallowed {
            kind: EntryKind::SsrEntry
        })
    ));
}

#[test]
fn test_min_module_count_one() {
    let graph = make_graph(
        "min1",
        EntryKind::AppEntry,
        vec![make_module("only.js", 100, true)],
    );
    let mut cfg = default_config();
    cfg.min_module_count = 1;
    let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
    assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
}

#[test]
fn test_different_engine_versions_different_artifacts() {
    let graph = three_module_graph("ev", EntryKind::AppEntry);
    let mut cfg1 = default_config();
    cfg1.engine_version = "1.0.0".into();
    let mut cfg2 = default_config();
    cfg2.engine_version = "2.0.0".into();
    let r1 = compile_entrygraph(&graph, &cfg1, epoch()).unwrap();
    let r2 = compile_entrygraph(&graph, &cfg2, epoch()).unwrap();
    assert_ne!(
        r1.module_results[0].artifact_hash,
        r2.module_results[0].artifact_hash
    );
}

#[test]
fn test_different_policy_revisions_different_artifacts() {
    let graph = three_module_graph("pr", EntryKind::AppEntry);
    let mut cfg1 = default_config();
    cfg1.policy_revision = 1;
    let mut cfg2 = default_config();
    cfg2.policy_revision = 2;
    let r1 = compile_entrygraph(&graph, &cfg1, epoch()).unwrap();
    let r2 = compile_entrygraph(&graph, &cfg2, epoch()).unwrap();
    assert_ne!(
        r1.module_results[0].artifact_hash,
        r2.module_results[0].artifact_hash
    );
}

#[test]
fn test_epoch_in_report() {
    let e = SecurityEpoch::from_raw(42);
    let graph = three_module_graph("ep", EntryKind::AppEntry);
    let report = compile_entrygraph(&graph, &default_config(), e).unwrap();
    assert_eq!(report.compile_epoch.as_u64(), 42);
}

#[test]
fn test_compile_time_proportional_to_size() {
    let small_graph = make_graph(
        "small",
        EntryKind::AppEntry,
        vec![
            make_module("a.js", 100, true),
            make_module("b.js", 100, false),
            make_module("c.js", 100, false),
        ],
    );
    let large_graph = make_graph(
        "large",
        EntryKind::AppEntry,
        vec![
            make_module("a.js", 10_000, true),
            make_module("b.js", 10_000, false),
            make_module("c.js", 10_000, false),
        ],
    );
    let small_report = compile_entrygraph(&small_graph, &default_config(), epoch()).unwrap();
    let large_report = compile_entrygraph(&large_graph, &default_config(), epoch()).unwrap();
    assert!(large_report.total_compile_time_micros > small_report.total_compile_time_micros);
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

#[test]
fn test_config_hash_stable() {
    let h1 = compute_config_hash(&default_config());
    let h2 = compute_config_hash(&default_config());
    assert_eq!(h1, h2);
}

#[test]
fn test_config_hash_changes_on_target() {
    let mut c1 = default_config();
    c1.target = CompileTarget::OptimizedBytecode;
    let mut c2 = default_config();
    c2.target = CompileTarget::CacheArtifact;
    assert_ne!(compute_config_hash(&c1), compute_config_hash(&c2));
}

#[test]
fn test_results_hash_empty() {
    let h = compute_results_hash(&[]);
    // Should produce a valid hash even for empty input
    assert_ne!(h.as_bytes(), &[0u8; 32]);
}

#[test]
fn test_results_hash_changes_on_content() {
    let r1 = vec![ModuleCompileResult {
        specifier: "a.js".into(),
        status: CompileStatus::Compiled,
        artifact_hash: Some(ContentHash::compute(b"art1")),
        provenance: vec![],
        compile_time_micros: 100,
        skip_reason: None,
    }];
    let r2 = vec![ModuleCompileResult {
        specifier: "b.js".into(),
        status: CompileStatus::Compiled,
        artifact_hash: Some(ContentHash::compute(b"art2")),
        provenance: vec![],
        compile_time_micros: 100,
        skip_reason: None,
    }];
    assert_ne!(compute_results_hash(&r1), compute_results_hash(&r2));
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn test_all_errors_display_nonempty() {
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
            kind: EntryKind::TestEntry,
        },
        CompileError::InvalidConfig {
            reason: "bad".into(),
        },
        CompileError::ModuleTooLarge {
            specifier: "x.js".into(),
            size: 999,
            max: 100,
        },
        CompileError::NoRootModule,
        CompileError::MultipleRoots { count: 5 },
    ];
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty(), "empty display for {e:?}");
    }
}

// ---------------------------------------------------------------------------
// Display impls
// ---------------------------------------------------------------------------

#[test]
fn test_all_entry_kind_display() {
    for k in EntryKind::ALL {
        let s = k.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn test_all_compile_target_display() {
    for t in CompileTarget::ALL {
        let s = t.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn test_all_compile_status_display() {
    for s in CompileStatus::ALL {
        let d = s.to_string();
        assert!(!d.is_empty());
    }
}

#[test]
fn test_all_provenance_kind_display() {
    for p in ProvenanceKind::ALL {
        let s = p.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn test_all_compile_verdict_display() {
    for v in CompileVerdict::ALL {
        let s = v.to_string();
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
}

#[test]
fn test_bead_id_correct() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.10.2");
}

#[test]
fn test_component_correct() {
    assert_eq!(COMPONENT, "aot_entrygraph_compiler");
}

#[test]
fn test_max_entrygraph_modules() {
    assert_eq!(MAX_ENTRYGRAPH_MODULES, 4096);
}

#[test]
fn test_max_batch_size() {
    assert_eq!(MAX_BATCH_SIZE, 256);
}

#[test]
fn test_default_config_values() {
    let cfg = default_config();
    assert_eq!(cfg.target, CompileTarget::OptimizedBytecode);
    assert_eq!(cfg.min_module_count, DEFAULT_MIN_MODULE_COUNT);
    assert_eq!(cfg.max_compile_time_micros, DEFAULT_MAX_COMPILE_TIME_MICROS);
    assert!(cfg.require_provenance);
    assert!(cfg.honour_cache);
    assert_eq!(cfg.policy_revision, 1);
    assert!(cfg.allowed_entry_kinds.is_empty());
}
