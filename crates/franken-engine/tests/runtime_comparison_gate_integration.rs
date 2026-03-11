//! Integration tests for the runtime_comparison_gate module.
//!
//! Validates the Node/Bun comparison harness reproducibility and publishability
//! gate from a pure external API perspective.

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

use std::collections::BTreeMap;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_comparison_gate::{
    ArtifactBundleAudit, BenchmarkCategory, BenchmarkResult, DEFAULT_MAX_CV_MILLIONTHS,
    DEFAULT_MIN_RUNS_PER_BENCHMARK, EnvironmentFingerprint, GATE_COMPONENT, GATE_SCHEMA_VERSION,
    GateBlocker, GateError, GateEvidenceBundle, GateInput, GateOutcome, MethodologyAudit,
    REQUIRED_CATEGORIES, ReproducibilityResult, RuntimeId, evaluate_gate, generate_log_entries,
    passes_release_gate,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bench(
    id: &str,
    cat: BenchmarkCategory,
    runtime: RuntimeId,
    wall_ns: u64,
    memory: u64,
) -> BenchmarkResult {
    BenchmarkResult {
        benchmark_id: id.to_string(),
        category: cat,
        runtime,
        wall_time_ns: wall_ns,
        memory_peak_bytes: memory,
        run_count: 30,
        cv_millionths: 20_000, // 2%, well under 3% default
    }
}

fn passing_methodology() -> MethodologyAudit {
    MethodologyAudit {
        selection_rationale: true,
        warmup_policy: true,
        gc_jit_settling: true,
        statistical_treatment: true,
        known_limitations: true,
        peer_reviewed: true,
        reviewer_ids: vec!["reviewer-1".to_string()],
    }
}

fn passing_artifacts() -> ArtifactBundleAudit {
    ArtifactBundleAudit {
        raw_timing_data: true,
        environment_fingerprint: true,
        run_manifest: true,
        replay_script: true,
        dependency_manifests: true,
        bundle_hash: ContentHash::compute(b"test-bundle"),
    }
}

fn passing_environment() -> EnvironmentFingerprint {
    let mut rt_versions = BTreeMap::new();
    rt_versions.insert("franken_engine".to_string(), "0.1.0".to_string());
    rt_versions.insert("node".to_string(), "20.11.0".to_string());
    rt_versions.insert("bun".to_string(), "1.0.30".to_string());
    EnvironmentFingerprint {
        cpu_model: "AMD EPYC 7763".to_string(),
        cpu_cores: 64,
        ram_bytes: 256 * 1024 * 1024 * 1024,
        os_version: "Ubuntu 24.04".to_string(),
        kernel_version: "6.17.0".to_string(),
        runtime_versions: rt_versions,
        runtime_flags: BTreeMap::new(),
        fingerprint_hash: ContentHash::compute(b"test-fingerprint"),
    }
}

/// Generate a complete set of benchmark results covering all required categories
/// and all runtimes. FrankenEngine is fastest, Node second, Bun third.
fn full_benchmark_results() -> Vec<BenchmarkResult> {
    let categories = [
        (BenchmarkCategory::Micro, "micro_bench"),
        (BenchmarkCategory::Macro, "macro_bench"),
        (BenchmarkCategory::Startup, "startup_bench"),
        (BenchmarkCategory::Throughput, "throughput_bench"),
        (BenchmarkCategory::Memory, "memory_bench"),
    ];
    let mut results = Vec::new();
    for (cat, id) in &categories {
        // FrankenEngine is fastest
        results.push(bench(id, *cat, RuntimeId::FrankenEngine, 800, 4000));
        // Node is baseline
        results.push(bench(id, *cat, RuntimeId::NodeLts, 1000, 5000));
        // Bun slightly faster than Node
        results.push(bench(id, *cat, RuntimeId::BunStable, 900, 4500));
    }
    results
}

fn passing_input<'a>(
    results: &'a [BenchmarkResult],
    methodology: &'a MethodologyAudit,
    artifacts: &'a ArtifactBundleAudit,
    reproducibility: &'a [ReproducibilityResult],
    environment: &'a EnvironmentFingerprint,
) -> GateInput<'a> {
    GateInput {
        run_id: "run-1",
        trace_id: "trace-001",
        epoch: SecurityEpoch::from_raw(1),
        results,
        methodology,
        artifacts,
        reproducibility,
        environment,
        max_cv_millionths: DEFAULT_MAX_CV_MILLIONTHS,
        min_runs_per_benchmark: DEFAULT_MIN_RUNS_PER_BENCHMARK,
        benchmark_sniffing_check_passed: true,
        benchmark_sniffing_detail: "",
    }
}

// ---------------------------------------------------------------------------
// Full passing gate
// ---------------------------------------------------------------------------

#[test]
fn gate_passes_all_criteria() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(bundle.outcome.is_pass());
    assert!(bundle.blockers.is_empty());
    assert_eq!(bundle.schema_version, GATE_SCHEMA_VERSION);
    assert_eq!(bundle.run_id, "run-1");
    assert_eq!(bundle.total_benchmarks, 5);
    assert!(bundle.performance_summary.overall_vs_node_delta_millionths > 0);
}

#[test]
fn gate_deterministic_evidence_hash() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);

    let b1 = evaluate_gate(&input).unwrap();
    let b2 = evaluate_gate(&input).unwrap();
    assert_eq!(b1.evidence_hash, b2.evidence_hash);
}

#[test]
fn gate_different_run_ids_different_hashes() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();

    let i1 = passing_input(&results, &method, &artifacts, &[], &env);
    let i2 = GateInput {
        run_id: "run-2",
        ..i1.clone()
    };

    let b1 = evaluate_gate(&i1).unwrap();
    let b2 = evaluate_gate(&i2).unwrap();
    assert_ne!(b1.evidence_hash, b2.evidence_hash);
}

// ---------------------------------------------------------------------------
// Gate failure modes
// ---------------------------------------------------------------------------

#[test]
fn gate_error_empty_benchmarks() {
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&[], &method, &artifacts, &[], &env);
    assert!(matches!(
        evaluate_gate(&input),
        Err(GateError::EmptyBenchmarks)
    ));
}

#[test]
fn gate_fails_missing_category() {
    // Only provide Micro and Macro — missing Startup, Throughput, Memory
    let results = vec![
        bench(
            "micro_1",
            BenchmarkCategory::Micro,
            RuntimeId::FrankenEngine,
            800,
            4000,
        ),
        bench(
            "micro_1",
            BenchmarkCategory::Micro,
            RuntimeId::NodeLts,
            1000,
            5000,
        ),
        bench(
            "micro_1",
            BenchmarkCategory::Micro,
            RuntimeId::BunStable,
            900,
            4500,
        ),
        bench(
            "macro_1",
            BenchmarkCategory::Macro,
            RuntimeId::FrankenEngine,
            800,
            4000,
        ),
        bench(
            "macro_1",
            BenchmarkCategory::Macro,
            RuntimeId::NodeLts,
            1000,
            5000,
        ),
        bench(
            "macro_1",
            BenchmarkCategory::Macro,
            RuntimeId::BunStable,
            900,
            4500,
        ),
    ];
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    let missing_cats: Vec<_> = bundle
        .blockers
        .iter()
        .filter_map(|b| match b {
            GateBlocker::MissingCategory { category } => Some(category.as_str()),
            _ => None,
        })
        .collect();
    assert!(missing_cats.contains(&"startup"));
    assert!(missing_cats.contains(&"throughput"));
    assert!(missing_cats.contains(&"memory"));
}

#[test]
fn gate_fails_missing_runtime() {
    // Only provide FrankenEngine and NodeLts — missing BunStable
    let results = vec![
        bench(
            "micro_1",
            BenchmarkCategory::Micro,
            RuntimeId::FrankenEngine,
            800,
            4000,
        ),
        bench(
            "micro_1",
            BenchmarkCategory::Micro,
            RuntimeId::NodeLts,
            1000,
            5000,
        ),
        bench(
            "macro_1",
            BenchmarkCategory::Macro,
            RuntimeId::FrankenEngine,
            800,
            4000,
        ),
        bench(
            "macro_1",
            BenchmarkCategory::Macro,
            RuntimeId::NodeLts,
            1000,
            5000,
        ),
        bench(
            "startup_1",
            BenchmarkCategory::Startup,
            RuntimeId::FrankenEngine,
            800,
            4000,
        ),
        bench(
            "startup_1",
            BenchmarkCategory::Startup,
            RuntimeId::NodeLts,
            1000,
            5000,
        ),
        bench(
            "tp_1",
            BenchmarkCategory::Throughput,
            RuntimeId::FrankenEngine,
            800,
            4000,
        ),
        bench(
            "tp_1",
            BenchmarkCategory::Throughput,
            RuntimeId::NodeLts,
            1000,
            5000,
        ),
        bench(
            "mem_1",
            BenchmarkCategory::Memory,
            RuntimeId::FrankenEngine,
            800,
            4000,
        ),
        bench(
            "mem_1",
            BenchmarkCategory::Memory,
            RuntimeId::NodeLts,
            1000,
            5000,
        ),
    ];
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    assert!(bundle.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::MissingRuntime {
            runtime: RuntimeId::BunStable
        }
    )));
}

#[test]
fn gate_fails_excessive_variance() {
    let mut results = full_benchmark_results();
    results[0].cv_millionths = 50_000; // 5% > 3% default
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    assert!(bundle.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::ExcessiveVariance { cv_millionths, .. } if *cv_millionths == 50_000
    )));
}

#[test]
fn gate_fails_insufficient_runs() {
    let mut results = full_benchmark_results();
    results[0].run_count = 5; // below 30 default
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    assert!(bundle.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::InsufficientRuns { run_count, .. } if *run_count == 5
    )));
}

#[test]
fn gate_fails_incomplete_methodology() {
    let results = full_benchmark_results();
    let method = MethodologyAudit {
        selection_rationale: true,
        warmup_policy: true,
        gc_jit_settling: false, // missing
        statistical_treatment: true,
        known_limitations: false, // missing
        peer_reviewed: false,
        reviewer_ids: vec![],
    };
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    assert!(
        bundle
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::IncompleteMethodology { .. }))
    );
}

#[test]
fn gate_fails_incomplete_artifacts() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = ArtifactBundleAudit {
        raw_timing_data: true,
        environment_fingerprint: true,
        run_manifest: false,  // missing
        replay_script: false, // missing
        dependency_manifests: true,
        bundle_hash: ContentHash::compute(b"partial"),
    };
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    assert!(
        bundle
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::IncompleteArtifactBundle { .. }))
    );
}

#[test]
fn gate_fails_reproducibility() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let repro = vec![ReproducibilityResult {
        benchmark_id: "micro_bench".to_string(),
        runtime: RuntimeId::FrankenEngine,
        original_ns: 800,
        replay_ns: 1200, // 50% deviation
        deviation_millionths: 500_000,
        within_tolerance: false,
    }];
    let input = passing_input(&results, &method, &artifacts, &repro, &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    assert!(
        bundle
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::ReproducibilityFailed { .. }))
    );
}

#[test]
fn gate_fails_benchmark_sniffing() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let mut input = passing_input(&results, &method, &artifacts, &[], &env);
    input.benchmark_sniffing_check_passed = false;
    input.benchmark_sniffing_detail = "config divergence detected in JIT flags";
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    assert!(bundle.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::BenchmarkSniffingDetected { detail } if detail.contains("JIT flags")
    )));
}

#[test]
fn gate_accumulates_multiple_blockers() {
    let mut results = full_benchmark_results();
    results[0].cv_millionths = 50_000; // excessive variance
    results[0].run_count = 5; // insufficient runs
    let method = MethodologyAudit {
        selection_rationale: false,
        ..passing_methodology()
    };
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(!bundle.outcome.is_pass());
    assert!(bundle.blockers.len() >= 3);
}

// ---------------------------------------------------------------------------
// Performance summary
// ---------------------------------------------------------------------------

#[test]
fn performance_summary_categories() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert_eq!(bundle.performance_summary.category_summaries.len(), 5);
    for cs in &bundle.performance_summary.category_summaries {
        assert_eq!(cs.benchmark_count, 1);
        // FrankenEngine is faster than both Node and Bun
        assert!(cs.vs_node_delta_millionths > 0);
        assert!(cs.vs_bun_delta_millionths > 0);
    }
}

#[test]
fn performance_summary_overall_deltas_positive() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    assert!(bundle.performance_summary.overall_vs_node_delta_millionths > 0);
    assert!(bundle.performance_summary.overall_vs_bun_delta_millionths > 0);
}

// ---------------------------------------------------------------------------
// MethodologyAudit
// ---------------------------------------------------------------------------

#[test]
fn methodology_complete_passes() {
    let m = passing_methodology();
    assert!(m.is_complete());
    assert!(m.missing_sections().is_empty());
}

#[test]
fn methodology_missing_sections() {
    let m = MethodologyAudit {
        selection_rationale: true,
        warmup_policy: false,
        gc_jit_settling: true,
        statistical_treatment: false,
        known_limitations: true,
        peer_reviewed: false,
        reviewer_ids: vec![],
    };
    assert!(!m.is_complete());
    let missing = m.missing_sections();
    assert!(missing.contains(&"warmup_policy"));
    assert!(missing.contains(&"statistical_treatment"));
    assert_eq!(missing.len(), 2);
}

// ---------------------------------------------------------------------------
// ArtifactBundleAudit
// ---------------------------------------------------------------------------

#[test]
fn artifact_bundle_complete_passes() {
    let a = passing_artifacts();
    assert!(a.is_complete());
    assert!(a.missing_artifacts().is_empty());
}

#[test]
fn artifact_bundle_missing_items() {
    let a = ArtifactBundleAudit {
        raw_timing_data: true,
        environment_fingerprint: false,
        run_manifest: true,
        replay_script: false,
        dependency_manifests: true,
        bundle_hash: ContentHash::compute(b"partial"),
    };
    assert!(!a.is_complete());
    let missing = a.missing_artifacts();
    assert!(missing.contains(&"environment_fingerprint"));
    assert!(missing.contains(&"replay_script"));
    assert_eq!(missing.len(), 2);
}

// ---------------------------------------------------------------------------
// passes_release_gate
// ---------------------------------------------------------------------------

#[test]
fn release_gate_pass() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    assert!(passes_release_gate(&bundle));
}

#[test]
fn release_gate_fail() {
    let mut results = full_benchmark_results();
    results[0].cv_millionths = 50_000;
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    assert!(!passes_release_gate(&bundle));
}

// ---------------------------------------------------------------------------
// generate_log_entries
// ---------------------------------------------------------------------------

#[test]
fn log_entries_summary() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-1", &bundle);

    assert!(!entries.is_empty());
    assert_eq!(entries[0].event, "gate_evaluation_complete");
    assert_eq!(entries[0].outcome, "PASS");
    assert_eq!(entries[0].component, GATE_COMPONENT);
    assert!(entries[0].error_code.is_none());
}

#[test]
fn log_entries_per_category() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-1", &bundle);

    let cat_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.event == "category_summary")
        .collect();
    assert_eq!(cat_entries.len(), 5);
}

#[test]
fn log_entries_failure_has_error_code() {
    let mut results = full_benchmark_results();
    results[0].cv_millionths = 50_000;
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-1", &bundle);

    assert_eq!(entries[0].error_code, Some("GATE_FAILED".to_string()));
}

// ---------------------------------------------------------------------------
// Enum Display / Serde
// ---------------------------------------------------------------------------

#[test]
fn runtime_id_as_str_and_display() {
    assert_eq!(RuntimeId::FrankenEngine.as_str(), "franken_engine");
    assert_eq!(RuntimeId::NodeLts.as_str(), "node_lts");
    assert_eq!(RuntimeId::BunStable.as_str(), "bun_stable");
    assert_eq!(format!("{}", RuntimeId::FrankenEngine), "franken_engine");
}

#[test]
fn runtime_id_all() {
    assert_eq!(RuntimeId::all().len(), 3);
}

#[test]
fn benchmark_category_as_str_and_display() {
    assert_eq!(BenchmarkCategory::Micro.as_str(), "micro");
    assert_eq!(BenchmarkCategory::Macro.as_str(), "macro");
    assert_eq!(BenchmarkCategory::Startup.as_str(), "startup");
    assert_eq!(BenchmarkCategory::Throughput.as_str(), "throughput");
    assert_eq!(BenchmarkCategory::Memory.as_str(), "memory");
    assert_eq!(format!("{}", BenchmarkCategory::Memory), "memory");
}

#[test]
fn benchmark_category_all() {
    assert_eq!(BenchmarkCategory::all().len(), 5);
    assert_eq!(REQUIRED_CATEGORIES.len(), 5);
}

#[test]
fn gate_outcome_display() {
    assert_eq!(format!("{}", GateOutcome::Pass), "PASS");
    assert_eq!(format!("{}", GateOutcome::Fail), "FAIL");
    assert!(GateOutcome::Pass.is_pass());
    assert!(!GateOutcome::Fail.is_pass());
}

#[test]
fn gate_error_display() {
    assert_eq!(
        format!("{}", GateError::EmptyBenchmarks),
        "no benchmark results provided"
    );
    let e = GateError::InvalidFingerprint {
        detail: "bad".to_string(),
    };
    assert!(format!("{e}").contains("bad"));
}

#[test]
fn gate_blocker_display_all() {
    let blockers: Vec<GateBlocker> = vec![
        GateBlocker::MissingCategory {
            category: "micro".to_string(),
        },
        GateBlocker::ExcessiveVariance {
            benchmark_id: "b1".to_string(),
            runtime: RuntimeId::FrankenEngine,
            cv_millionths: 50_000,
            max_cv_millionths: 30_000,
        },
        GateBlocker::InsufficientRuns {
            benchmark_id: "b1".to_string(),
            runtime: RuntimeId::NodeLts,
            run_count: 5,
            required: 30,
        },
        GateBlocker::IncompleteMethodology {
            missing_sections: vec!["warmup".to_string()],
        },
        GateBlocker::IncompleteArtifactBundle {
            missing_artifacts: vec!["replay_script".to_string()],
        },
        GateBlocker::ReproducibilityFailed {
            benchmark_id: "b1".to_string(),
            original_ns: 1000,
            replay_ns: 1500,
            deviation_millionths: 500_000,
        },
        GateBlocker::MissingRuntime {
            runtime: RuntimeId::BunStable,
        },
        GateBlocker::NoBenchmarks,
        GateBlocker::BenchmarkSniffingDetected {
            detail: "JIT flags differ".to_string(),
        },
    ];
    for b in &blockers {
        assert!(!format!("{b}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_evidence_bundle_roundtrip() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let back: GateEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn serde_runtime_id_roundtrip() {
    for rt in RuntimeId::all() {
        let json = serde_json::to_string(rt).unwrap();
        let back: RuntimeId = serde_json::from_str(&json).unwrap();
        assert_eq!(*rt, back);
    }
}

#[test]
fn serde_benchmark_category_roundtrip() {
    for cat in BenchmarkCategory::all() {
        let json = serde_json::to_string(cat).unwrap();
        let back: BenchmarkCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn serde_gate_error_roundtrip() {
    let e = GateError::EmptyBenchmarks;
    let json = serde_json::to_string(&e).unwrap();
    let back: GateError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn serde_blocker_roundtrip() {
    let b = GateBlocker::MissingCategory {
        category: "micro".to_string(),
    };
    let json = serde_json::to_string(&b).unwrap();
    let back: GateBlocker = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_stable() {
    assert_eq!(DEFAULT_MAX_CV_MILLIONTHS, 30_000);
    assert_eq!(DEFAULT_MIN_RUNS_PER_BENCHMARK, 30);
    assert_eq!(GATE_COMPONENT, "runtime_comparison_gate");
    assert!(GATE_SCHEMA_VERSION.contains("runtime-comparison-gate"));
    assert_eq!(REQUIRED_CATEGORIES.len(), 5);
}

// ---------------------------------------------------------------------------
// Additional coverage
// ---------------------------------------------------------------------------

#[test]
fn gate_passes_with_all_runtimes_and_categories() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    assert_eq!(bundle.outcome, GateOutcome::Pass);
    assert!(bundle.blockers.is_empty());
}

#[test]
fn gate_evidence_has_correct_schema_version() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    assert_eq!(bundle.schema_version, GATE_SCHEMA_VERSION);
}

#[test]
fn gate_reproduces_epoch_in_bundle() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let epoch = SecurityEpoch::from_raw(42);
    let input = GateInput {
        run_id: "epoch-test",
        trace_id: "t-epoch",
        epoch,
        results: &results,
        methodology: &method,
        artifacts: &artifacts,
        reproducibility: &[],
        environment: &env,
        max_cv_millionths: DEFAULT_MAX_CV_MILLIONTHS,
        min_runs_per_benchmark: DEFAULT_MIN_RUNS_PER_BENCHMARK,
        benchmark_sniffing_check_passed: true,
        benchmark_sniffing_detail: "",
    };
    let bundle = evaluate_gate(&input).unwrap();
    assert_eq!(bundle.epoch.as_u64(), 42);
}

#[test]
fn gate_multiple_blockers_accumulated() {
    // Fail with both missing runtime and excessive variance.
    let mut results: Vec<BenchmarkResult> = full_benchmark_results()
        .into_iter()
        .filter(|r| r.runtime != RuntimeId::BunStable)
        .collect();
    results[0].cv_millionths = 100_000; // > 30_000
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    assert_eq!(bundle.outcome, GateOutcome::Fail);
    // Should have at least 2 blockers.
    assert!(bundle.blockers.len() >= 2);
}

#[test]
fn reproducibility_passing_does_not_add_blocker() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let repro = vec![ReproducibilityResult {
        benchmark_id: "b_repro".to_string(),
        runtime: RuntimeId::NodeLts,
        original_ns: 1_000_000,
        replay_ns: 1_010_000,
        deviation_millionths: 10_000,
        within_tolerance: true,
    }];
    let input = passing_input(&results, &method, &artifacts, &repro, &env);
    let bundle = evaluate_gate(&input).unwrap();
    assert!(
        !bundle
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::ReproducibilityFailed { .. }))
    );
}

#[test]
fn gate_outcome_serde_roundtrip() {
    for outcome in [GateOutcome::Pass, GateOutcome::Fail] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: GateOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

#[test]
fn performance_summary_total_benchmarks_matches_unique_ids() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    // Unique benchmark IDs across all runtimes.
    let unique_ids: std::collections::BTreeSet<&str> =
        results.iter().map(|r| r.benchmark_id.as_str()).collect();
    assert_eq!(
        bundle.performance_summary.total_benchmarks,
        unique_ids.len() as u64
    );
}

#[test]
fn log_entries_trace_id_propagated() {
    let results = full_benchmark_results();
    let method = passing_methodology();
    let artifacts = passing_artifacts();
    let env = passing_environment();
    let input = passing_input(&results, &method, &artifacts, &[], &env);
    let bundle = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("my-trace-42", &bundle);
    assert!(entries.iter().all(|e| e.trace_id == "my-trace-42"));
}
