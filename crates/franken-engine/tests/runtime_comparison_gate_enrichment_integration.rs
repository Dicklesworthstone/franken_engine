#![forbid(unsafe_code)]
//! Enrichment integration tests for `runtime_comparison_gate`.
//!
//! Adds JSON field-name stability, serde roundtrips for under-tested types,
//! Debug distinctness, Display exact values, GateOutcome predicates,
//! and MethodologyAudit/ArtifactBundleAudit completeness edge cases
//! beyond the existing 30 integration tests.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_comparison_gate::{
    ArtifactBundleAudit, BenchmarkCategory, BenchmarkResult, CategorySummary,
    DEFAULT_MAX_CV_MILLIONTHS, DEFAULT_MIN_RUNS_PER_BENCHMARK, GATE_COMPONENT, GATE_SCHEMA_VERSION,
    GateBlocker, GateError, GateLogEntry, GateOutcome, MethodologyAudit, REQUIRED_CATEGORIES,
    ReproducibilityResult, RuntimeId,
};

// ===========================================================================
// 1) RuntimeId — as_str exact values
// ===========================================================================

#[test]
fn runtime_id_as_str_franken_engine() {
    assert_eq!(RuntimeId::FrankenEngine.as_str(), "franken_engine");
}

#[test]
fn runtime_id_as_str_node_lts() {
    assert_eq!(RuntimeId::NodeLts.as_str(), "node_lts");
}

#[test]
fn runtime_id_as_str_bun_stable() {
    assert_eq!(RuntimeId::BunStable.as_str(), "bun_stable");
}

// ===========================================================================
// 2) BenchmarkCategory — as_str exact values
// ===========================================================================

#[test]
fn benchmark_category_as_str_micro() {
    assert_eq!(BenchmarkCategory::Micro.as_str(), "micro");
}

#[test]
fn benchmark_category_as_str_macro_cat() {
    assert_eq!(BenchmarkCategory::Macro.as_str(), "macro");
}

#[test]
fn benchmark_category_as_str_startup() {
    assert_eq!(BenchmarkCategory::Startup.as_str(), "startup");
}

#[test]
fn benchmark_category_as_str_throughput() {
    assert_eq!(BenchmarkCategory::Throughput.as_str(), "throughput");
}

#[test]
fn benchmark_category_as_str_memory() {
    assert_eq!(BenchmarkCategory::Memory.as_str(), "memory");
}

// ===========================================================================
// 3) GateOutcome — Display + is_pass
// ===========================================================================

#[test]
fn gate_outcome_display_pass() {
    assert_eq!(GateOutcome::Pass.to_string(), "PASS");
}

#[test]
fn gate_outcome_display_fail() {
    assert_eq!(GateOutcome::Fail.to_string(), "FAIL");
}

#[test]
fn gate_outcome_is_pass_true() {
    assert!(GateOutcome::Pass.is_pass());
}

#[test]
fn gate_outcome_is_pass_false() {
    assert!(!GateOutcome::Fail.is_pass());
}

// ===========================================================================
// 4) GateError — Display
// ===========================================================================

#[test]
fn gate_error_display_empty_benchmarks() {
    let e = GateError::EmptyBenchmarks;
    assert_eq!(e.to_string(), "no benchmark results provided");
}

#[test]
fn gate_error_display_invalid_fingerprint() {
    let e = GateError::InvalidFingerprint {
        detail: "empty cpu_model".into(),
    };
    let s = e.to_string();
    assert!(s.contains("empty cpu_model"), "should contain detail: {s}");
}

// ===========================================================================
// 5) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_runtime_id() {
    let variants: Vec<String> = RuntimeId::all().iter().map(|r| format!("{r:?}")).collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_benchmark_category() {
    let variants: Vec<String> = BenchmarkCategory::all()
        .iter()
        .map(|c| format!("{c:?}"))
        .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn debug_distinct_gate_outcome() {
    let variants = [
        format!("{:?}", GateOutcome::Pass),
        format!("{:?}", GateOutcome::Fail),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 2);
}

// ===========================================================================
// 6) Constants — exact values
// ===========================================================================

#[test]
fn constant_default_max_cv() {
    assert_eq!(DEFAULT_MAX_CV_MILLIONTHS, 30_000);
}

#[test]
fn constant_default_min_runs() {
    assert_eq!(DEFAULT_MIN_RUNS_PER_BENCHMARK, 30);
}

#[test]
fn constant_gate_component() {
    assert_eq!(GATE_COMPONENT, "runtime_comparison_gate");
}

#[test]
fn constant_gate_schema_version() {
    assert_eq!(
        GATE_SCHEMA_VERSION,
        "franken-engine.runtime-comparison-gate.v1"
    );
}

#[test]
fn constant_required_categories_count() {
    assert_eq!(REQUIRED_CATEGORIES.len(), 5);
}

// ===========================================================================
// 7) JSON field-name stability — BenchmarkResult
// ===========================================================================

#[test]
fn json_fields_benchmark_result() {
    let br = BenchmarkResult {
        benchmark_id: "fib-40".into(),
        category: BenchmarkCategory::Micro,
        runtime: RuntimeId::FrankenEngine,
        wall_time_ns: 1_000_000,
        memory_peak_bytes: 1024,
        run_count: 30,
        cv_millionths: 5_000,
    };
    let v: serde_json::Value = serde_json::to_value(&br).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "benchmark_id",
        "category",
        "runtime",
        "wall_time_ns",
        "memory_peak_bytes",
        "run_count",
        "cv_millionths",
    ] {
        assert!(
            obj.contains_key(key),
            "BenchmarkResult missing field: {key}"
        );
    }
}

// ===========================================================================
// 8) JSON field-name stability — CategorySummary
// ===========================================================================

#[test]
fn json_fields_category_summary() {
    let cs = CategorySummary {
        category: BenchmarkCategory::Startup,
        benchmark_count: 5,
        vs_node_delta_millionths: -100_000,
        vs_bun_delta_millionths: -50_000,
        vs_node_memory_delta_millionths: -200_000,
        vs_bun_memory_delta_millionths: -80_000,
    };
    let v: serde_json::Value = serde_json::to_value(&cs).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "category",
        "benchmark_count",
        "vs_node_delta_millionths",
        "vs_bun_delta_millionths",
        "vs_node_memory_delta_millionths",
        "vs_bun_memory_delta_millionths",
    ] {
        assert!(
            obj.contains_key(key),
            "CategorySummary missing field: {key}"
        );
    }
}

// ===========================================================================
// 9) JSON field-name stability — ReproducibilityResult
// ===========================================================================

#[test]
fn json_fields_reproducibility_result() {
    let rr = ReproducibilityResult {
        benchmark_id: "fib-40".into(),
        runtime: RuntimeId::NodeLts,
        original_ns: 1_000_000,
        replay_ns: 1_010_000,
        deviation_millionths: 10_000,
        within_tolerance: true,
    };
    let v: serde_json::Value = serde_json::to_value(&rr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "benchmark_id",
        "runtime",
        "original_ns",
        "replay_ns",
        "deviation_millionths",
        "within_tolerance",
    ] {
        assert!(
            obj.contains_key(key),
            "ReproducibilityResult missing field: {key}"
        );
    }
}

// ===========================================================================
// 10) JSON field-name stability — GateLogEntry
// ===========================================================================

#[test]
fn json_fields_gate_log_entry() {
    let le = GateLogEntry {
        trace_id: "t".into(),
        component: "runtime_comparison_gate".into(),
        benchmark_id: None,
        runtime: None,
        variant: None,
        event: "gate_evaluation_complete".into(),
        outcome: "PASS".into(),
        wall_time_ns: None,
        memory_peak_bytes: None,
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&le).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "component",
        "benchmark_id",
        "runtime",
        "variant",
        "event",
        "outcome",
        "wall_time_ns",
        "memory_peak_bytes",
        "error_code",
    ] {
        assert!(obj.contains_key(key), "GateLogEntry missing field: {key}");
    }
}

// ===========================================================================
// 11) JSON field-name stability — MethodologyAudit
// ===========================================================================

#[test]
fn json_fields_methodology_audit() {
    let ma = MethodologyAudit {
        selection_rationale: true,
        warmup_policy: true,
        gc_jit_settling: true,
        statistical_treatment: true,
        known_limitations: true,
        peer_reviewed: true,
        reviewer_ids: vec!["reviewer-1".into()],
    };
    let v: serde_json::Value = serde_json::to_value(&ma).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "selection_rationale",
        "warmup_policy",
        "gc_jit_settling",
        "statistical_treatment",
        "known_limitations",
        "peer_reviewed",
        "reviewer_ids",
    ] {
        assert!(
            obj.contains_key(key),
            "MethodologyAudit missing field: {key}"
        );
    }
}

// ===========================================================================
// 12) MethodologyAudit — completeness
// ===========================================================================

#[test]
fn methodology_audit_complete_has_no_missing() {
    let ma = MethodologyAudit {
        selection_rationale: true,
        warmup_policy: true,
        gc_jit_settling: true,
        statistical_treatment: true,
        known_limitations: true,
        peer_reviewed: true,
        reviewer_ids: vec![],
    };
    assert!(ma.is_complete());
    assert!(ma.missing_sections().is_empty());
}

#[test]
fn methodology_audit_missing_one_section() {
    let ma = MethodologyAudit {
        selection_rationale: true,
        warmup_policy: false,
        gc_jit_settling: true,
        statistical_treatment: true,
        known_limitations: true,
        peer_reviewed: true,
        reviewer_ids: vec![],
    };
    assert!(!ma.is_complete());
    let missing = ma.missing_sections();
    assert!(missing.contains(&"warmup_policy"));
}

// ===========================================================================
// 13) ArtifactBundleAudit — completeness
// ===========================================================================

#[test]
fn artifact_bundle_audit_complete_has_no_missing() {
    let ab = ArtifactBundleAudit {
        raw_timing_data: true,
        environment_fingerprint: true,
        run_manifest: true,
        replay_script: true,
        dependency_manifests: true,
        bundle_hash: ContentHash::compute(b"bundle"),
    };
    assert!(ab.is_complete());
    assert!(ab.missing_artifacts().is_empty());
}

#[test]
fn artifact_bundle_audit_missing_one() {
    let ab = ArtifactBundleAudit {
        raw_timing_data: true,
        environment_fingerprint: true,
        run_manifest: false,
        replay_script: true,
        dependency_manifests: true,
        bundle_hash: ContentHash::compute(b"bundle"),
    };
    assert!(!ab.is_complete());
    let missing = ab.missing_artifacts();
    assert!(missing.contains(&"run_manifest"));
}

// ===========================================================================
// 14) Serde roundtrips — additional types
// ===========================================================================

#[test]
fn serde_roundtrip_benchmark_result() {
    let br = BenchmarkResult {
        benchmark_id: "sort-10k".into(),
        category: BenchmarkCategory::Throughput,
        runtime: RuntimeId::BunStable,
        wall_time_ns: 500_000,
        memory_peak_bytes: 2048,
        run_count: 50,
        cv_millionths: 3_000,
    };
    let json = serde_json::to_string(&br).unwrap();
    let rt: BenchmarkResult = serde_json::from_str(&json).unwrap();
    assert_eq!(br, rt);
}

#[test]
fn serde_roundtrip_category_summary() {
    let cs = CategorySummary {
        category: BenchmarkCategory::Memory,
        benchmark_count: 3,
        vs_node_delta_millionths: -50_000,
        vs_bun_delta_millionths: 10_000,
        vs_node_memory_delta_millionths: -30_000,
        vs_bun_memory_delta_millionths: 5_000,
    };
    let json = serde_json::to_string(&cs).unwrap();
    let rt: CategorySummary = serde_json::from_str(&json).unwrap();
    assert_eq!(cs, rt);
}

#[test]
fn serde_roundtrip_reproducibility_result() {
    let rr = ReproducibilityResult {
        benchmark_id: "regex-match".into(),
        runtime: RuntimeId::FrankenEngine,
        original_ns: 2_000_000,
        replay_ns: 2_050_000,
        deviation_millionths: 25_000,
        within_tolerance: true,
    };
    let json = serde_json::to_string(&rr).unwrap();
    let rt: ReproducibilityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, rt);
}

#[test]
fn serde_roundtrip_gate_log_entry() {
    let le = GateLogEntry {
        trace_id: "t1".into(),
        component: GATE_COMPONENT.into(),
        benchmark_id: Some("fib-40".into()),
        runtime: Some(RuntimeId::FrankenEngine),
        variant: Some("micro".into()),
        event: "category_summary".into(),
        outcome: "vs_node=-10% vs_bun=-5%".into(),
        wall_time_ns: Some(1_000_000),
        memory_peak_bytes: Some(4096),
        error_code: None,
    };
    let json = serde_json::to_string(&le).unwrap();
    let rt: GateLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(le, rt);
}

#[test]
fn serde_roundtrip_methodology_audit() {
    let ma = MethodologyAudit {
        selection_rationale: true,
        warmup_policy: false,
        gc_jit_settling: true,
        statistical_treatment: true,
        known_limitations: false,
        peer_reviewed: true,
        reviewer_ids: vec!["alice".into(), "bob".into()],
    };
    let json = serde_json::to_string(&ma).unwrap();
    let rt: MethodologyAudit = serde_json::from_str(&json).unwrap();
    assert_eq!(ma, rt);
}

#[test]
fn serde_roundtrip_gate_blocker_all_variants() {
    let blockers: Vec<GateBlocker> = vec![
        GateBlocker::MissingCategory {
            category: "startup".into(),
        },
        GateBlocker::ExcessiveVariance {
            benchmark_id: "fib".into(),
            runtime: RuntimeId::FrankenEngine,
            cv_millionths: 50_000,
            max_cv_millionths: 30_000,
        },
        GateBlocker::InsufficientRuns {
            benchmark_id: "sort".into(),
            runtime: RuntimeId::NodeLts,
            run_count: 5,
            required: 30,
        },
        GateBlocker::IncompleteMethodology {
            missing_sections: vec!["warmup_policy".into()],
        },
        GateBlocker::IncompleteArtifactBundle {
            missing_artifacts: vec!["replay_script".into()],
        },
        GateBlocker::ReproducibilityFailed {
            benchmark_id: "regex".into(),
            original_ns: 1000,
            replay_ns: 2000,
            deviation_millionths: 500_000,
        },
        GateBlocker::MissingRuntime {
            runtime: RuntimeId::BunStable,
        },
        GateBlocker::NoBenchmarks,
        GateBlocker::BenchmarkSniffingDetected {
            detail: "suspected sniffing".into(),
        },
    ];
    for blocker in &blockers {
        let json = serde_json::to_string(blocker).unwrap();
        let rt: GateBlocker = serde_json::from_str(&json).unwrap();
        assert_eq!(*blocker, rt);
    }
}

// ===========================================================================
// 15) GateBlocker — Display for all variants
// ===========================================================================

#[test]
fn gate_blocker_display_no_benchmarks() {
    assert_eq!(
        GateBlocker::NoBenchmarks.to_string(),
        "no benchmarks provided"
    );
}

#[test]
fn gate_blocker_display_missing_runtime() {
    let b = GateBlocker::MissingRuntime {
        runtime: RuntimeId::BunStable,
    };
    let s = b.to_string();
    assert!(s.contains("bun_stable"), "should contain runtime: {s}");
}

#[test]
fn gate_blocker_display_benchmark_sniffing() {
    let b = GateBlocker::BenchmarkSniffingDetected {
        detail: "adaptive".into(),
    };
    let s = b.to_string();
    assert!(s.contains("adaptive"), "should contain detail: {s}");
}
