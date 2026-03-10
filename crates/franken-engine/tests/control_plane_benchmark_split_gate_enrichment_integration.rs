//! Enrichment integration tests for `control_plane_benchmark_split_gate`
//! (FRX-10.13, item 17).
//!
//! Covers: JSON field-name stability, serde roundtrips, Display/as_str exact
//! values, Debug distinctness, BenchmarkSplitFailureCode coverage,
//! BenchmarkSplitThresholds defaults, snapshot hashing, gate evaluation
//! pipeline, regression detection, and log event invariants.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::control_plane_benchmark_split_gate::*;

// ── helpers ────────────────────────────────────────────────────────────

fn mk_metrics(throughput: u64, p50: u64, p95: u64, p99: u64, rss: u64) -> SplitBenchmarkMetrics {
    SplitBenchmarkMetrics {
        throughput_ops_per_sec: throughput,
        latency_ns: LatencyStatsNs {
            p50_ns: p50,
            p95_ns: p95,
            p99_ns: p99,
        },
        peak_rss_delta_bytes: rss,
    }
}

fn all_splits_metrics() -> BTreeMap<BenchmarkSplit, SplitBenchmarkMetrics> {
    BTreeMap::from([
        (
            BenchmarkSplit::Baseline,
            mk_metrics(1_000_000, 900_000, 1_000_000, 1_050_000, 0),
        ),
        (
            BenchmarkSplit::CxThreading,
            mk_metrics(995_000, 910_000, 1_010_000, 1_060_000, 8_000_000),
        ),
        (
            BenchmarkSplit::DecisionContracts,
            mk_metrics(990_000, 920_000, 1_050_000, 1_100_000, 16_000_000),
        ),
        (
            BenchmarkSplit::EvidenceEmission,
            mk_metrics(980_000, 930_000, 1_060_000, 1_110_000, 24_000_000),
        ),
        (
            BenchmarkSplit::FullIntegration,
            mk_metrics(960_000, 940_000, 1_070_000, 1_120_000, 30_000_000),
        ),
    ])
}

fn baseline_runs() -> Vec<u64> {
    vec![
        1_000_100, 1_000_200, 999_900, 1_000_050, 1_000_150, 999_950, 1_000_300, 1_000_000,
        1_000_250, 1_000_175,
    ]
}

fn mk_snapshot(id: &str, run_id: &str) -> BenchmarkSplitSnapshot {
    BenchmarkSplitSnapshot {
        snapshot_id: id.to_string(),
        benchmark_run_id: run_id.to_string(),
        split_metrics: all_splits_metrics(),
        baseline_throughput_runs_ops_per_sec: baseline_runs(),
    }
}

fn mk_input() -> BenchmarkSplitGateInput {
    BenchmarkSplitGateInput {
        trace_id: "trace-enrich".to_string(),
        policy_id: "policy-enrich".to_string(),
        previous_snapshot: mk_snapshot("prev-snap", "prev-run"),
        candidate_snapshot: mk_snapshot("cand-snap", "cand-run"),
    }
}

// ── BenchmarkSplit Display/as_str ──────────────────────────────────────

#[test]
fn benchmark_split_as_str_exact_baseline() {
    assert_eq!(BenchmarkSplit::Baseline.as_str(), "baseline");
}

#[test]
fn benchmark_split_as_str_exact_cx_threading() {
    assert_eq!(BenchmarkSplit::CxThreading.as_str(), "cx_threading");
}

#[test]
fn benchmark_split_as_str_exact_decision_contracts() {
    assert_eq!(
        BenchmarkSplit::DecisionContracts.as_str(),
        "decision_contracts"
    );
}

#[test]
fn benchmark_split_as_str_exact_evidence_emission() {
    assert_eq!(
        BenchmarkSplit::EvidenceEmission.as_str(),
        "evidence_emission"
    );
}

#[test]
fn benchmark_split_as_str_exact_full_integration() {
    assert_eq!(BenchmarkSplit::FullIntegration.as_str(), "full_integration");
}

#[test]
fn benchmark_split_display_matches_as_str() {
    for s in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn benchmark_split_debug_distinct() {
    let mut dbgs = BTreeSet::new();
    for s in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        dbgs.insert(format!("{s:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn benchmark_split_ordering() {
    assert!(BenchmarkSplit::Baseline < BenchmarkSplit::CxThreading);
    assert!(BenchmarkSplit::CxThreading < BenchmarkSplit::DecisionContracts);
    assert!(BenchmarkSplit::DecisionContracts < BenchmarkSplit::EvidenceEmission);
    assert!(BenchmarkSplit::EvidenceEmission < BenchmarkSplit::FullIntegration);
}

#[test]
fn benchmark_split_serde_roundtrip_all() {
    for s in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        let json = serde_json::to_vec(&s).unwrap();
        let back: BenchmarkSplit = serde_json::from_slice(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ── BenchmarkSplitFailureCode ──────────────────────────────────────────

#[test]
fn failure_code_display_exact_missing_split() {
    assert_eq!(
        BenchmarkSplitFailureCode::MissingSplitMetrics.to_string(),
        "missing_split_metrics"
    );
}

#[test]
fn failure_code_display_exact_insufficient_baseline() {
    assert_eq!(
        BenchmarkSplitFailureCode::InsufficientBaselineRuns.to_string(),
        "insufficient_baseline_runs"
    );
}

#[test]
fn failure_code_display_exact_baseline_variance() {
    assert_eq!(
        BenchmarkSplitFailureCode::BaselineVarianceExceeded.to_string(),
        "baseline_variance_exceeded"
    );
}

#[test]
fn failure_code_display_exact_invalid_metric() {
    assert_eq!(
        BenchmarkSplitFailureCode::InvalidMetric.to_string(),
        "invalid_metric"
    );
}

#[test]
fn failure_code_display_exact_throughput_regression() {
    assert_eq!(
        BenchmarkSplitFailureCode::ThroughputRegressionExceeded.to_string(),
        "throughput_regression_exceeded"
    );
}

#[test]
fn failure_code_display_exact_latency_regression() {
    assert_eq!(
        BenchmarkSplitFailureCode::LatencyRegressionExceeded.to_string(),
        "latency_regression_exceeded"
    );
}

#[test]
fn failure_code_display_exact_memory_overhead() {
    assert_eq!(
        BenchmarkSplitFailureCode::MemoryOverheadExceeded.to_string(),
        "memory_overhead_exceeded"
    );
}

#[test]
fn failure_code_display_exact_previous_run_regression() {
    assert_eq!(
        BenchmarkSplitFailureCode::PreviousRunRegressionExceeded.to_string(),
        "previous_run_regression_exceeded"
    );
}

#[test]
fn failure_code_debug_distinct() {
    let codes = [
        BenchmarkSplitFailureCode::MissingSplitMetrics,
        BenchmarkSplitFailureCode::InsufficientBaselineRuns,
        BenchmarkSplitFailureCode::BaselineVarianceExceeded,
        BenchmarkSplitFailureCode::InvalidMetric,
        BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
        BenchmarkSplitFailureCode::LatencyRegressionExceeded,
        BenchmarkSplitFailureCode::MemoryOverheadExceeded,
        BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
    ];
    let mut dbgs = BTreeSet::new();
    for c in &codes {
        dbgs.insert(format!("{c:?}"));
    }
    assert_eq!(dbgs.len(), 8);
}

#[test]
fn failure_code_serde_roundtrip_all() {
    for c in [
        BenchmarkSplitFailureCode::MissingSplitMetrics,
        BenchmarkSplitFailureCode::InsufficientBaselineRuns,
        BenchmarkSplitFailureCode::BaselineVarianceExceeded,
        BenchmarkSplitFailureCode::InvalidMetric,
        BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
        BenchmarkSplitFailureCode::LatencyRegressionExceeded,
        BenchmarkSplitFailureCode::MemoryOverheadExceeded,
        BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
    ] {
        let json = serde_json::to_vec(&c).unwrap();
        let back: BenchmarkSplitFailureCode = serde_json::from_slice(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ── LatencyStatsNs ─────────────────────────────────────────────────────

#[test]
fn latency_stats_json_fields() {
    let stats = LatencyStatsNs {
        p50_ns: 100,
        p95_ns: 200,
        p99_ns: 300,
    };
    let v: serde_json::Value = serde_json::to_value(&stats).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("p50_ns"));
    assert!(obj.contains_key("p95_ns"));
    assert!(obj.contains_key("p99_ns"));
}

#[test]
fn latency_stats_serde_roundtrip() {
    let stats = LatencyStatsNs {
        p50_ns: 1_000,
        p95_ns: 2_000,
        p99_ns: 3_000,
    };
    let json = serde_json::to_vec(&stats).unwrap();
    let back: LatencyStatsNs = serde_json::from_slice(&json).unwrap();
    assert_eq!(stats, back);
}

// ── SplitBenchmarkMetrics ──────────────────────────────────────────────

#[test]
fn split_metrics_json_fields() {
    let m = mk_metrics(1_000_000, 100, 200, 300, 1024);
    let v: serde_json::Value = serde_json::to_value(&m).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("throughput_ops_per_sec"));
    assert!(obj.contains_key("latency_ns"));
    assert!(obj.contains_key("peak_rss_delta_bytes"));
}

#[test]
fn split_metrics_serde_roundtrip() {
    let m = mk_metrics(500_000, 50, 100, 150, 2048);
    let json = serde_json::to_vec(&m).unwrap();
    let back: SplitBenchmarkMetrics = serde_json::from_slice(&json).unwrap();
    assert_eq!(m, back);
}

// ── BenchmarkSplitSnapshot ─────────────────────────────────────────────

#[test]
fn snapshot_json_fields() {
    let snap = mk_snapshot("s-1", "r-1");
    let v: serde_json::Value = serde_json::to_value(&snap).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("snapshot_id"));
    assert!(obj.contains_key("benchmark_run_id"));
    assert!(obj.contains_key("split_metrics"));
    assert!(obj.contains_key("baseline_throughput_runs_ops_per_sec"));
}

#[test]
fn snapshot_serde_roundtrip() {
    let snap = mk_snapshot("s-rt", "r-rt");
    let json = serde_json::to_vec(&snap).unwrap();
    let back: BenchmarkSplitSnapshot = serde_json::from_slice(&json).unwrap();
    assert_eq!(snap, back);
}

#[test]
fn snapshot_hash_deterministic() {
    let snap = mk_snapshot("s-det", "r-det");
    assert_eq!(snap.snapshot_hash(), snap.snapshot_hash());
}

#[test]
fn snapshot_hash_differs_for_different_data() {
    let snap1 = mk_snapshot("s-1", "r-1");
    let mut snap2 = mk_snapshot("s-2", "r-2");
    snap2.baseline_throughput_runs_ops_per_sec = vec![500_000; 10];
    assert_ne!(snap1.snapshot_hash(), snap2.snapshot_hash());
}

#[test]
fn snapshot_hash_stable_across_baseline_run_ordering() {
    let snap_a = mk_snapshot("s-ord", "r-ord");
    let mut snap_b = mk_snapshot("s-ord", "r-ord");
    snap_b.baseline_throughput_runs_ops_per_sec.reverse();
    // The canonical value sorts baseline runs, so hash should be identical
    assert_eq!(snap_a.snapshot_hash(), snap_b.snapshot_hash());
}

// ── BenchmarkSplitGateInput ────────────────────────────────────────────

#[test]
fn gate_input_json_fields() {
    let inp = mk_input();
    let v: serde_json::Value = serde_json::to_value(&inp).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("policy_id"));
    assert!(obj.contains_key("previous_snapshot"));
    assert!(obj.contains_key("candidate_snapshot"));
}

#[test]
fn gate_input_serde_roundtrip() {
    let inp = mk_input();
    let json = serde_json::to_vec(&inp).unwrap();
    let back: BenchmarkSplitGateInput = serde_json::from_slice(&json).unwrap();
    assert_eq!(inp, back);
}

// ── BenchmarkSplitThresholds ───────────────────────────────────────────

#[test]
fn thresholds_default_min_baseline_runs() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(t.min_baseline_runs, 10);
}

#[test]
fn thresholds_default_max_baseline_cv() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(t.max_baseline_cv_millionths, 50_000);
}

#[test]
fn thresholds_default_has_all_five_splits_for_rss() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(t.max_peak_rss_delta_bytes.len(), 5);
    for s in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        assert!(t.max_peak_rss_delta_bytes.contains_key(&s));
    }
}

#[test]
fn thresholds_default_has_all_five_splits_for_throughput() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(t.max_previous_run_throughput_regression_millionths.len(), 5);
}

#[test]
fn thresholds_default_baseline_rss_zero() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(t.max_peak_rss_delta_bytes[&BenchmarkSplit::Baseline], 0);
}

#[test]
fn thresholds_serde_roundtrip() {
    let t = BenchmarkSplitThresholds::default();
    let json = serde_json::to_vec(&t).unwrap();
    let back: BenchmarkSplitThresholds = serde_json::from_slice(&json).unwrap();
    assert_eq!(t.min_baseline_runs, back.min_baseline_runs);
    assert_eq!(
        t.max_baseline_cv_millionths,
        back.max_baseline_cv_millionths
    );
    assert_eq!(t.max_peak_rss_delta_bytes, back.max_peak_rss_delta_bytes);
}

// ── BenchmarkSplitFinding ──────────────────────────────────────────────

#[test]
fn finding_json_fields() {
    let f = BenchmarkSplitFinding {
        code: BenchmarkSplitFailureCode::MemoryOverheadExceeded,
        split: Some(BenchmarkSplit::CxThreading),
        metric: Some("peak_rss_delta_bytes".to_string()),
        detail: "exceeded".to_string(),
        observed_millionths: Some(100),
        threshold_millionths: Some(50),
    };
    let v: serde_json::Value = serde_json::to_value(&f).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("code"));
    assert!(obj.contains_key("split"));
    assert!(obj.contains_key("metric"));
    assert!(obj.contains_key("detail"));
    assert!(obj.contains_key("observed_millionths"));
    assert!(obj.contains_key("threshold_millionths"));
}

#[test]
fn finding_serde_roundtrip() {
    let f = BenchmarkSplitFinding {
        code: BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
        split: Some(BenchmarkSplit::FullIntegration),
        metric: Some("throughput".to_string()),
        detail: "regressed".to_string(),
        observed_millionths: Some(200_000),
        threshold_millionths: Some(50_000),
    };
    let json = serde_json::to_vec(&f).unwrap();
    let back: BenchmarkSplitFinding = serde_json::from_slice(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn finding_serde_with_nulls() {
    let f = BenchmarkSplitFinding {
        code: BenchmarkSplitFailureCode::InvalidMetric,
        split: None,
        metric: None,
        detail: "unknown".to_string(),
        observed_millionths: None,
        threshold_millionths: None,
    };
    let json = serde_json::to_vec(&f).unwrap();
    let back: BenchmarkSplitFinding = serde_json::from_slice(&json).unwrap();
    assert_eq!(f, back);
}

// ── BenchmarkSplitLogEvent ─────────────────────────────────────────────

#[test]
fn log_event_json_fields() {
    let log = BenchmarkSplitLogEvent {
        trace_id: "trace".to_string(),
        decision_id: "dec".to_string(),
        policy_id: "pol".to_string(),
        component: "comp".to_string(),
        event: "ev".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        split: Some("baseline".to_string()),
        metric: Some("cv".to_string()),
    };
    let v: serde_json::Value = serde_json::to_value(&log).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("decision_id"));
    assert!(obj.contains_key("policy_id"));
    assert!(obj.contains_key("component"));
    assert!(obj.contains_key("event"));
    assert!(obj.contains_key("outcome"));
    assert!(obj.contains_key("error_code"));
    assert!(obj.contains_key("split"));
    assert!(obj.contains_key("metric"));
}

#[test]
fn log_event_serde_roundtrip() {
    let log = BenchmarkSplitLogEvent {
        trace_id: "t-rt".to_string(),
        decision_id: "d-rt".to_string(),
        policy_id: "p-rt".to_string(),
        component: "gate".to_string(),
        event: "check".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("error_1".to_string()),
        split: None,
        metric: None,
    };
    let json = serde_json::to_vec(&log).unwrap();
    let back: BenchmarkSplitLogEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(log, back);
}

// ── SplitBenchmarkEvaluation ───────────────────────────────────────────

#[test]
fn evaluation_json_fields() {
    let eval = SplitBenchmarkEvaluation {
        split: BenchmarkSplit::Baseline,
        previous_metrics: mk_metrics(1_000_000, 100, 200, 300, 0),
        candidate_metrics: mk_metrics(999_000, 100, 200, 300, 0),
        throughput_regression_vs_previous_millionths: 1_000,
        latency_p95_regression_vs_previous_millionths: 0,
        latency_p99_regression_vs_previous_millionths: 0,
        pass: true,
    };
    let v: serde_json::Value = serde_json::to_value(&eval).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("split"));
    assert!(obj.contains_key("previous_metrics"));
    assert!(obj.contains_key("candidate_metrics"));
    assert!(obj.contains_key("throughput_regression_vs_previous_millionths"));
    assert!(obj.contains_key("latency_p95_regression_vs_previous_millionths"));
    assert!(obj.contains_key("latency_p99_regression_vs_previous_millionths"));
    assert!(obj.contains_key("pass"));
}

#[test]
fn evaluation_serde_roundtrip() {
    let eval = SplitBenchmarkEvaluation {
        split: BenchmarkSplit::CxThreading,
        previous_metrics: mk_metrics(1_000_000, 100, 200, 300, 1024),
        candidate_metrics: mk_metrics(990_000, 105, 210, 310, 1024),
        throughput_regression_vs_previous_millionths: 10_000,
        latency_p95_regression_vs_previous_millionths: 50_000,
        latency_p99_regression_vs_previous_millionths: 33_333,
        pass: true,
    };
    let json = serde_json::to_vec(&eval).unwrap();
    let back: SplitBenchmarkEvaluation = serde_json::from_slice(&json).unwrap();
    assert_eq!(eval, back);
}

// ── BenchmarkSplitGateDecision ─────────────────────────────────────────

#[test]
fn decision_json_fields() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    let v: serde_json::Value = serde_json::to_value(&d).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("decision_id"));
    assert!(obj.contains_key("pass"));
    assert!(obj.contains_key("rollback_required"));
    assert!(obj.contains_key("previous_snapshot_hash"));
    assert!(obj.contains_key("candidate_snapshot_hash"));
    assert!(obj.contains_key("baseline_cv_millionths"));
    assert!(obj.contains_key("evaluations"));
    assert!(obj.contains_key("findings"));
    assert!(obj.contains_key("logs"));
}

#[test]
fn decision_serde_roundtrip() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    let json = serde_json::to_vec(&d).unwrap();
    let back: BenchmarkSplitGateDecision = serde_json::from_slice(&json).unwrap();
    assert_eq!(d.decision_id, back.decision_id);
    assert_eq!(d.pass, back.pass);
    assert_eq!(d.evaluations, back.evaluations);
    assert_eq!(d.findings, back.findings);
}

// ── Gate evaluation: passing scenario ──────────────────────────────────

#[test]
fn gate_passes_for_matching_snapshots() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    assert!(d.pass);
    assert!(!d.rollback_required);
    assert!(d.findings.is_empty());
    assert_eq!(d.evaluations.len(), 5);
}

#[test]
fn gate_pass_and_rollback_are_inverse() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    assert_eq!(d.pass, !d.rollback_required);
}

#[test]
fn gate_decision_id_starts_with_cp_bench_split() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    assert!(d.decision_id.starts_with("cp-bench-split-"));
}

#[test]
fn gate_decision_id_deterministic() {
    let inp = mk_input();
    let t = BenchmarkSplitThresholds::default();
    let d1 = evaluate_control_plane_benchmark_split(&inp, &t);
    let d2 = evaluate_control_plane_benchmark_split(&inp, &t);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn gate_decision_id_changes_with_trace() {
    let mut inp = mk_input();
    let t = BenchmarkSplitThresholds::default();
    let d1 = evaluate_control_plane_benchmark_split(&inp, &t);
    inp.trace_id = "different-trace".to_string();
    let d2 = evaluate_control_plane_benchmark_split(&inp, &t);
    assert_ne!(d1.decision_id, d2.decision_id);
}

#[test]
fn gate_baseline_cv_computed() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    assert!(d.baseline_cv_millionths.is_some());
    let cv = d.baseline_cv_millionths.unwrap();
    assert!(cv < 50_000, "stable baseline should have low CV");
}

// ── Gate evaluation: failure scenarios ─────────────────────────────────

#[test]
fn gate_fails_missing_candidate_split() {
    let mut inp = mk_input();
    inp.candidate_snapshot
        .split_metrics
        .remove(&BenchmarkSplit::FullIntegration);
    let d = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::MissingSplitMetrics
            && f.split == Some(BenchmarkSplit::FullIntegration)
    }));
}

#[test]
fn gate_fails_missing_previous_split() {
    let mut inp = mk_input();
    inp.previous_snapshot
        .split_metrics
        .remove(&BenchmarkSplit::CxThreading);
    let d = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::MissingSplitMetrics
            && f.split == Some(BenchmarkSplit::CxThreading)
            && f.detail.contains("previous")
    }));
}

#[test]
fn gate_fails_insufficient_baseline_runs() {
    let mut inp = mk_input();
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![1_000_000; 3]; // < 10
    let d = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == BenchmarkSplitFailureCode::InsufficientBaselineRuns)
    );
}

#[test]
fn gate_fails_high_baseline_variance() {
    let mut inp = mk_input();
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![
        500_000, 1_500_000, 600_000, 1_400_000, 550_000, 1_450_000, 620_000, 1_380_000, 510_000,
        1_490_000,
    ];
    let d = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == BenchmarkSplitFailureCode::BaselineVarianceExceeded)
    );
}

#[test]
fn gate_fails_zero_throughput() {
    let mut inp = mk_input();
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::Baseline)
        .unwrap()
        .throughput_ops_per_sec = 0;
    let d = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::InvalidMetric
            && f.split == Some(BenchmarkSplit::Baseline)
    }));
}

#[test]
fn gate_fails_memory_overhead_exceeded() {
    let mut inp = mk_input();
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::CxThreading)
        .unwrap()
        .peak_rss_delta_bytes = 100 * 1024 * 1024; // 100MB >> 16MB limit
    let d = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::MemoryOverheadExceeded
            && f.split == Some(BenchmarkSplit::CxThreading)
    }));
}

// ── Log events ─────────────────────────────────────────────────────────

#[test]
fn logs_carry_trace_and_policy() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    for log in &d.logs {
        assert_eq!(log.trace_id, "trace-enrich");
        assert_eq!(log.policy_id, "policy-enrich");
        assert_eq!(log.component, "control_plane_benchmark_split_gate");
    }
}

#[test]
fn logs_include_baseline_stability_check() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    assert!(d.logs.iter().any(|l| l.event == "baseline_stability_check"));
}

#[test]
fn logs_final_event_is_benchmark_split_decision() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    let last = d.logs.last().unwrap();
    assert_eq!(last.event, "benchmark_split_decision");
    assert_eq!(last.outcome, "pass");
    assert!(last.error_code.is_none());
}

#[test]
fn logs_split_evaluations_present() {
    let d =
        evaluate_control_plane_benchmark_split(&mk_input(), &BenchmarkSplitThresholds::default());
    let split_eval_count = d
        .logs
        .iter()
        .filter(|l| l.event == "split_evaluation")
        .count();
    assert_eq!(split_eval_count, 5);
}

#[test]
fn logs_failing_gate_has_error_code() {
    let mut inp = mk_input();
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![1_000_000; 3];
    let d = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    let last = d.logs.last().unwrap();
    assert_eq!(last.outcome, "fail");
    assert!(last.error_code.is_some());
}

// ── Snapshot hash edge cases ───────────────────────────────────────────

#[test]
fn snapshot_hashes_in_decision_match_direct_computation() {
    let inp = mk_input();
    let d = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert_eq!(
        d.previous_snapshot_hash,
        inp.previous_snapshot.snapshot_hash()
    );
    assert_eq!(
        d.candidate_snapshot_hash,
        inp.candidate_snapshot.snapshot_hash()
    );
}
