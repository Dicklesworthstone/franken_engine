#![forbid(unsafe_code)]

//! Integration tests for the `control_plane_benchmark_split_gate` module.
//!
//! Covers: BenchmarkSplit enum, LatencyStatsNs, SplitBenchmarkMetrics,
//! BenchmarkSplitSnapshot, BenchmarkSplitGateInput, BenchmarkSplitThresholds,
//! BenchmarkSplitFailureCode, BenchmarkSplitFinding, SplitBenchmarkEvaluation,
//! BenchmarkSplitLogEvent, BenchmarkSplitGateDecision,
//! evaluate_control_plane_benchmark_split.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::control_plane_benchmark_split_gate::{
    BenchmarkSplit, BenchmarkSplitFailureCode, BenchmarkSplitFinding, BenchmarkSplitGateDecision,
    BenchmarkSplitGateInput, BenchmarkSplitLogEvent, BenchmarkSplitSnapshot,
    BenchmarkSplitThresholds, LatencyStatsNs, SplitBenchmarkEvaluation, SplitBenchmarkMetrics,
    evaluate_control_plane_benchmark_split,
};

// ── Helpers ───────────────────────────────────────────────────────────────

fn make_metrics(
    throughput: u64,
    p50: u64,
    p95: u64,
    p99: u64,
    rss_delta: u64,
) -> SplitBenchmarkMetrics {
    SplitBenchmarkMetrics {
        throughput_ops_per_sec: throughput,
        latency_ns: LatencyStatsNs {
            p50_ns: p50,
            p95_ns: p95,
            p99_ns: p99,
        },
        peak_rss_delta_bytes: rss_delta,
    }
}

fn all_splits_metrics() -> BTreeMap<BenchmarkSplit, SplitBenchmarkMetrics> {
    BTreeMap::from([
        (
            BenchmarkSplit::Baseline,
            make_metrics(1_000_000, 900_000, 1_000_000, 1_050_000, 0),
        ),
        (
            BenchmarkSplit::CxThreading,
            make_metrics(995_000, 910_000, 1_005_000, 1_055_000, 8 * 1024 * 1024),
        ),
        (
            BenchmarkSplit::DecisionContracts,
            make_metrics(990_000, 920_000, 1_010_000, 1_060_000, 16 * 1024 * 1024),
        ),
        (
            BenchmarkSplit::EvidenceEmission,
            make_metrics(985_000, 930_000, 1_015_000, 1_065_000, 24 * 1024 * 1024),
        ),
        (
            BenchmarkSplit::FullIntegration,
            make_metrics(960_000, 940_000, 1_020_000, 1_070_000, 30 * 1024 * 1024),
        ),
    ])
}

fn stable_baseline_runs() -> Vec<u64> {
    vec![
        1_000_000, 1_000_010, 999_990, 1_000_005, 999_995, 1_000_008, 999_992, 1_000_003, 999_997,
        1_000_001,
    ]
}

fn make_snapshot(id: &str, run_id: &str) -> BenchmarkSplitSnapshot {
    BenchmarkSplitSnapshot {
        snapshot_id: id.to_string(),
        benchmark_run_id: run_id.to_string(),
        split_metrics: all_splits_metrics(),
        baseline_throughput_runs_ops_per_sec: stable_baseline_runs(),
    }
}

fn make_input() -> BenchmarkSplitGateInput {
    BenchmarkSplitGateInput {
        trace_id: "trace-integ".to_string(),
        policy_id: "policy-integ".to_string(),
        previous_snapshot: make_snapshot("prev-snap", "prev-run"),
        candidate_snapshot: make_snapshot("cand-snap", "cand-run"),
    }
}

// ── Section 1: BenchmarkSplit enum ────────────────────────────────────────

#[test]
fn split_as_str_returns_expected_strings() {
    assert_eq!(BenchmarkSplit::Baseline.as_str(), "baseline");
    assert_eq!(BenchmarkSplit::CxThreading.as_str(), "cx_threading");
    assert_eq!(
        BenchmarkSplit::DecisionContracts.as_str(),
        "decision_contracts"
    );
    assert_eq!(
        BenchmarkSplit::EvidenceEmission.as_str(),
        "evidence_emission"
    );
    assert_eq!(BenchmarkSplit::FullIntegration.as_str(), "full_integration");
}

#[test]
fn split_display_matches_as_str() {
    let all = [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ];
    for split in &all {
        assert_eq!(split.to_string(), split.as_str());
    }
}

#[test]
fn split_ordering_is_declaration_order() {
    assert!(BenchmarkSplit::Baseline < BenchmarkSplit::CxThreading);
    assert!(BenchmarkSplit::CxThreading < BenchmarkSplit::DecisionContracts);
    assert!(BenchmarkSplit::DecisionContracts < BenchmarkSplit::EvidenceEmission);
    assert!(BenchmarkSplit::EvidenceEmission < BenchmarkSplit::FullIntegration);
}

#[test]
fn split_clone_and_copy_equality() {
    let s = BenchmarkSplit::DecisionContracts;
    let cloned = s;
    let copied = s;
    assert_eq!(s, cloned);
    assert_eq!(s, copied);
}

#[test]
fn split_serde_roundtrip_all_variants() {
    for split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        let json = serde_json::to_string(&split).unwrap();
        let back: BenchmarkSplit = serde_json::from_str(&json).unwrap();
        assert_eq!(back, split);
    }
}

#[test]
fn split_debug_is_non_empty() {
    let dbg = format!("{:?}", BenchmarkSplit::Baseline);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Baseline"));
}

#[test]
fn split_display_produces_unique_strings() {
    let mut set = BTreeSet::new();
    for split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        set.insert(split.to_string());
    }
    assert_eq!(set.len(), 5);
}

// ── Section 2: BenchmarkSplitFailureCode ──────────────────────────────────

#[test]
fn failure_code_display_all_variants() {
    let expected = [
        (
            BenchmarkSplitFailureCode::MissingSplitMetrics,
            "missing_split_metrics",
        ),
        (
            BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            "insufficient_baseline_runs",
        ),
        (
            BenchmarkSplitFailureCode::BaselineVarianceExceeded,
            "baseline_variance_exceeded",
        ),
        (BenchmarkSplitFailureCode::InvalidMetric, "invalid_metric"),
        (
            BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
            "throughput_regression_exceeded",
        ),
        (
            BenchmarkSplitFailureCode::LatencyRegressionExceeded,
            "latency_regression_exceeded",
        ),
        (
            BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            "memory_overhead_exceeded",
        ),
        (
            BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
            "previous_run_regression_exceeded",
        ),
    ];
    for (code, display) in &expected {
        assert_eq!(code.to_string(), *display);
    }
}

#[test]
fn failure_code_ordering() {
    assert!(
        BenchmarkSplitFailureCode::MissingSplitMetrics
            < BenchmarkSplitFailureCode::PreviousRunRegressionExceeded
    );
}

#[test]
fn failure_code_serde_roundtrip() {
    for code in [
        BenchmarkSplitFailureCode::MissingSplitMetrics,
        BenchmarkSplitFailureCode::InsufficientBaselineRuns,
        BenchmarkSplitFailureCode::BaselineVarianceExceeded,
        BenchmarkSplitFailureCode::InvalidMetric,
        BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
        BenchmarkSplitFailureCode::LatencyRegressionExceeded,
        BenchmarkSplitFailureCode::MemoryOverheadExceeded,
        BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let back: BenchmarkSplitFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, code);
    }
}

// ── Section 3: LatencyStatsNs ─────────────────────────────────────────────

#[test]
fn latency_stats_serde_roundtrip() {
    let stats = LatencyStatsNs {
        p50_ns: 100,
        p95_ns: 200,
        p99_ns: 300,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let back: LatencyStatsNs = serde_json::from_str(&json).unwrap();
    assert_eq!(back, stats);
}

#[test]
fn latency_stats_debug() {
    let stats = LatencyStatsNs {
        p50_ns: 1,
        p95_ns: 2,
        p99_ns: 3,
    };
    let dbg = format!("{stats:?}");
    assert!(dbg.contains("p50_ns"));
    assert!(dbg.contains("p95_ns"));
    assert!(dbg.contains("p99_ns"));
}

#[test]
fn latency_stats_clone_equality() {
    let stats = LatencyStatsNs {
        p50_ns: 42,
        p95_ns: 84,
        p99_ns: 126,
    };
    assert_eq!(stats.clone(), stats);
}

// ── Section 4: SplitBenchmarkMetrics ──────────────────────────────────────

#[test]
fn split_benchmark_metrics_serde_roundtrip() {
    let m = make_metrics(500_000, 100, 200, 300, 4096);
    let json = serde_json::to_string(&m).unwrap();
    let back: SplitBenchmarkMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}

#[test]
fn split_benchmark_metrics_debug() {
    let m = make_metrics(1, 2, 3, 4, 5);
    let dbg = format!("{m:?}");
    assert!(dbg.contains("throughput_ops_per_sec"));
    assert!(dbg.contains("peak_rss_delta_bytes"));
}

// ── Section 5: BenchmarkSplitSnapshot ─────────────────────────────────────

#[test]
fn snapshot_hash_is_deterministic() {
    let snap = make_snapshot("s1", "r1");
    assert_eq!(snap.snapshot_hash(), snap.snapshot_hash());
}

#[test]
fn snapshot_hash_differs_by_id() {
    let a = make_snapshot("snap-a", "run-1");
    let b = make_snapshot("snap-b", "run-1");
    assert_ne!(a.snapshot_hash(), b.snapshot_hash());
}

#[test]
fn snapshot_hash_differs_by_run_id() {
    let a = make_snapshot("snap-1", "run-a");
    let b = make_snapshot("snap-1", "run-b");
    assert_ne!(a.snapshot_hash(), b.snapshot_hash());
}

#[test]
fn snapshot_hash_stable_across_baseline_run_order() {
    let mut a = make_snapshot("s", "r");
    let mut b = make_snapshot("s", "r");
    b.baseline_throughput_runs_ops_per_sec.reverse();
    // The canonical_value sorts baseline runs, so hash should match
    assert_eq!(a.snapshot_hash(), b.snapshot_hash());

    // But changing a value changes the hash
    a.baseline_throughput_runs_ops_per_sec[0] = 999;
    assert_ne!(a.snapshot_hash(), b.snapshot_hash());
}

#[test]
fn snapshot_serde_roundtrip() {
    let snap = make_snapshot("s1", "r1");
    let json = serde_json::to_string(&snap).unwrap();
    let back: BenchmarkSplitSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, snap);
}

// ── Section 6: BenchmarkSplitThresholds ───────────────────────────────────

#[test]
fn thresholds_default_contains_all_splits_in_rss_map() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(t.max_peak_rss_delta_bytes.len(), 5);
    for split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        assert!(
            t.max_peak_rss_delta_bytes.contains_key(&split),
            "missing RSS limit for {split}"
        );
    }
}

#[test]
fn thresholds_default_contains_all_splits_in_prev_run_map() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(t.max_previous_run_throughput_regression_millionths.len(), 5);
}

#[test]
fn thresholds_default_positive_values() {
    let t = BenchmarkSplitThresholds::default();
    assert!(t.min_baseline_runs > 0);
    assert!(t.max_baseline_cv_millionths > 0);
    assert!(t.max_cx_throughput_regression_millionths > 0);
    assert!(t.max_decision_latency_regression_millionths > 0);
    assert!(t.max_evidence_throughput_regression_millionths > 0);
    assert!(t.max_full_integration_throughput_regression_millionths > 0);
    assert!(t.max_previous_run_latency_regression_millionths > 0);
}

#[test]
fn thresholds_serde_roundtrip() {
    let t = BenchmarkSplitThresholds::default();
    let json = serde_json::to_string(&t).unwrap();
    let back: BenchmarkSplitThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(back.min_baseline_runs, t.min_baseline_runs);
    assert_eq!(
        back.max_baseline_cv_millionths,
        t.max_baseline_cv_millionths
    );
    assert_eq!(
        back.max_cx_throughput_regression_millionths,
        t.max_cx_throughput_regression_millionths
    );
    assert_eq!(back.max_peak_rss_delta_bytes, t.max_peak_rss_delta_bytes);
}

#[test]
fn thresholds_baseline_rss_is_zero() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(
        *t.max_peak_rss_delta_bytes
            .get(&BenchmarkSplit::Baseline)
            .unwrap(),
        0
    );
}

// ── Section 7: BenchmarkSplitFinding serde ────────────────────────────────

#[test]
fn finding_serde_roundtrip_with_all_fields() {
    let f = BenchmarkSplitFinding {
        code: BenchmarkSplitFailureCode::MemoryOverheadExceeded,
        split: Some(BenchmarkSplit::CxThreading),
        metric: Some("peak_rss_delta_bytes".to_string()),
        detail: "over budget".to_string(),
        observed_millionths: Some(200_000),
        threshold_millionths: Some(100_000),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: BenchmarkSplitFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
}

#[test]
fn finding_serde_roundtrip_with_none_fields() {
    let f = BenchmarkSplitFinding {
        code: BenchmarkSplitFailureCode::InvalidMetric,
        split: None,
        metric: None,
        detail: "no details".to_string(),
        observed_millionths: None,
        threshold_millionths: None,
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: BenchmarkSplitFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
}

// ── Section 8: SplitBenchmarkEvaluation serde ─────────────────────────────

#[test]
fn evaluation_serde_roundtrip() {
    let eval = SplitBenchmarkEvaluation {
        split: BenchmarkSplit::Baseline,
        previous_metrics: make_metrics(1_000_000, 100, 200, 300, 0),
        candidate_metrics: make_metrics(999_000, 101, 201, 301, 0),
        throughput_regression_vs_previous_millionths: 1_000,
        latency_p95_regression_vs_previous_millionths: 5_000,
        latency_p99_regression_vs_previous_millionths: 3_333,
        pass: true,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let back: SplitBenchmarkEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, eval);
}

// ── Section 9: BenchmarkSplitLogEvent serde ───────────────────────────────

#[test]
fn log_event_serde_roundtrip() {
    let log = BenchmarkSplitLogEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "test".to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        split: Some("baseline".to_string()),
        metric: Some("throughput".to_string()),
    };
    let json = serde_json::to_string(&log).unwrap();
    let back: BenchmarkSplitLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, log);
}

#[test]
fn log_event_serde_roundtrip_with_error() {
    let log = BenchmarkSplitLogEvent {
        trace_id: "t2".to_string(),
        decision_id: "d2".to_string(),
        policy_id: "p2".to_string(),
        component: "gate".to_string(),
        event: "fail_event".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("some_error".to_string()),
        split: None,
        metric: None,
    };
    let json = serde_json::to_string(&log).unwrap();
    let back: BenchmarkSplitLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, log);
}

// ── Section 10: BenchmarkSplitGateDecision serde ──────────────────────────

#[test]
fn decision_serde_roundtrip() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    let json = serde_json::to_string(&decision).unwrap();
    let back: BenchmarkSplitGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back.decision_id, decision.decision_id);
    assert_eq!(back.pass, decision.pass);
    assert_eq!(back.rollback_required, decision.rollback_required);
    assert_eq!(back.previous_snapshot_hash, decision.previous_snapshot_hash);
    assert_eq!(
        back.candidate_snapshot_hash,
        decision.candidate_snapshot_hash
    );
    assert_eq!(back.baseline_cv_millionths, decision.baseline_cv_millionths);
    assert_eq!(back.evaluations, decision.evaluations);
    assert_eq!(back.findings, decision.findings);
    assert_eq!(back.logs, decision.logs);
}

// ── Section 11: evaluate_control_plane_benchmark_split — happy path ───────

#[test]
fn gate_passes_for_identical_snapshots() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    assert!(decision.pass, "identical snapshots should pass");
    assert!(!decision.rollback_required);
    assert!(decision.findings.is_empty());
    assert_eq!(decision.evaluations.len(), 5);
    assert!(decision.evaluations.iter().all(|e| e.pass));
}

#[test]
fn gate_decision_id_starts_with_prefix() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    assert!(decision.decision_id.starts_with("cp-bench-split-"));
}

#[test]
fn gate_pass_and_rollback_are_inverse() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    assert_eq!(decision.pass, !decision.rollback_required);
}

#[test]
fn gate_produces_baseline_cv_for_valid_runs() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    assert!(
        decision.baseline_cv_millionths.is_some(),
        "baseline CV should be computed for valid inputs"
    );
}

#[test]
fn gate_evaluations_cover_all_splits() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    let evaluated: BTreeSet<BenchmarkSplit> =
        decision.evaluations.iter().map(|e| e.split).collect();
    assert!(evaluated.contains(&BenchmarkSplit::Baseline));
    assert!(evaluated.contains(&BenchmarkSplit::CxThreading));
    assert!(evaluated.contains(&BenchmarkSplit::DecisionContracts));
    assert!(evaluated.contains(&BenchmarkSplit::EvidenceEmission));
    assert!(evaluated.contains(&BenchmarkSplit::FullIntegration));
}

// ── Section 12: Logs structure ────────────────────────────────────────────

#[test]
fn gate_logs_contain_baseline_stability_check() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    assert!(
        decision
            .logs
            .iter()
            .any(|l| l.event == "baseline_stability_check")
    );
}

#[test]
fn gate_logs_final_event_is_benchmark_split_decision() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    let last = decision.logs.last().unwrap();
    assert_eq!(last.event, "benchmark_split_decision");
    assert_eq!(last.outcome, "pass");
    assert!(last.error_code.is_none());
}

#[test]
fn gate_logs_all_carry_trace_and_policy() {
    let inp = make_input();
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    for log in &decision.logs {
        assert_eq!(log.trace_id, inp.trace_id);
        assert_eq!(log.policy_id, inp.policy_id);
        assert_eq!(log.component, "control_plane_benchmark_split_gate");
        assert_eq!(log.decision_id, decision.decision_id);
    }
}

#[test]
fn gate_logs_include_split_evaluations() {
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    let split_eval_logs: Vec<_> = decision
        .logs
        .iter()
        .filter(|l| l.event == "split_evaluation")
        .collect();
    assert_eq!(split_eval_logs.len(), 5, "one log per split evaluation");
}

#[test]
fn gate_logs_on_failure_final_has_error_code() {
    let mut inp = make_input();
    inp.candidate_snapshot
        .split_metrics
        .remove(&BenchmarkSplit::FullIntegration);
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    let last = decision.logs.last().unwrap();
    assert_eq!(last.outcome, "fail");
    assert_eq!(
        last.error_code.as_deref(),
        Some("control_plane_benchmark_split_failed")
    );
}

// ── Section 13: Missing split detection ───────────────────────────────────

#[test]
fn gate_fails_when_candidate_missing_split() {
    let mut inp = make_input();
    inp.candidate_snapshot
        .split_metrics
        .remove(&BenchmarkSplit::EvidenceEmission);
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!decision.pass);
    assert!(decision.rollback_required);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::MissingSplitMetrics
            && f.split == Some(BenchmarkSplit::EvidenceEmission)
            && f.detail.contains("candidate")
    }));
}

#[test]
fn gate_fails_when_previous_missing_split() {
    let mut inp = make_input();
    inp.previous_snapshot
        .split_metrics
        .remove(&BenchmarkSplit::CxThreading);
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::MissingSplitMetrics
            && f.split == Some(BenchmarkSplit::CxThreading)
            && f.detail.contains("previous")
    }));
}

#[test]
fn gate_fails_when_both_missing_same_split() {
    let mut inp = make_input();
    inp.previous_snapshot
        .split_metrics
        .remove(&BenchmarkSplit::Baseline);
    inp.candidate_snapshot
        .split_metrics
        .remove(&BenchmarkSplit::Baseline);
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!decision.pass);
    let baseline_findings: Vec<_> = decision
        .findings
        .iter()
        .filter(|f| {
            f.code == BenchmarkSplitFailureCode::MissingSplitMetrics
                && f.split == Some(BenchmarkSplit::Baseline)
        })
        .collect();
    assert_eq!(
        baseline_findings.len(),
        2,
        "both previous and candidate missing findings"
    );
}

// ── Section 14: Insufficient baseline runs ────────────────────────────────

#[test]
fn gate_fails_with_insufficient_baseline_runs() {
    let mut inp = make_input();
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![1_000_000; 3];
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::InsufficientBaselineRuns
            && f.split == Some(BenchmarkSplit::Baseline)
            && f.observed_millionths == Some(3)
    }));
    assert!(decision.baseline_cv_millionths.is_none());
}

// ── Section 15: Baseline variance exceeded ────────────────────────────────

#[test]
fn gate_fails_with_high_baseline_variance() {
    let mut inp = make_input();
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![
        500_000, 1_500_000, 500_000, 1_500_000, 500_000, 1_500_000, 500_000, 1_500_000, 500_000,
        1_500_000,
    ];
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::BaselineVarianceExceeded
            && f.split == Some(BenchmarkSplit::Baseline)
    }));
    // CV is still computed even when exceeding threshold
    assert!(decision.baseline_cv_millionths.is_some());
}

// ── Section 16: Invalid metric (zero throughput) ──────────────────────────

#[test]
fn gate_finds_zero_throughput_in_candidate() {
    let mut inp = make_input();
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::Baseline)
        .unwrap()
        .throughput_ops_per_sec = 0;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::InvalidMetric
            && f.split == Some(BenchmarkSplit::Baseline)
            && f.metric.as_deref() == Some("throughput_ops_per_sec")
    }));
}

#[test]
fn gate_finds_zero_throughput_in_previous() {
    let mut inp = make_input();
    inp.previous_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::DecisionContracts)
        .unwrap()
        .throughput_ops_per_sec = 0;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::InvalidMetric
            && f.split == Some(BenchmarkSplit::DecisionContracts)
    }));
}

// ── Section 17: Invalid baseline CV (all zeros) ───────────────────────────

#[test]
fn gate_finds_invalid_baseline_cv_for_all_zeros() {
    let mut inp = make_input();
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![0; 10];
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::InvalidMetric
            && f.metric.as_deref() == Some("baseline_cv")
    }));
    assert!(decision.baseline_cv_millionths.is_none());
}

// ── Section 18: Cx threading throughput regression ────────────────────────

#[test]
fn gate_detects_cx_threading_throughput_regression_vs_baseline() {
    let mut inp = make_input();
    // CxThreading throughput far below baseline
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::CxThreading)
        .unwrap()
        .throughput_ops_per_sec = 800_000;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::ThroughputRegressionExceeded
            && f.split == Some(BenchmarkSplit::CxThreading)
    }));
}

// ── Section 19: Decision contract latency regression ──────────────────────

#[test]
fn gate_detects_decision_latency_regression() {
    let mut inp = make_input();
    // Decision contracts latency much higher than CxThreading
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::DecisionContracts)
        .unwrap()
        .latency_ns
        .p95_ns = 2_000_000;
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::DecisionContracts)
        .unwrap()
        .latency_ns
        .p99_ns = 2_500_000;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::LatencyRegressionExceeded
            && f.split == Some(BenchmarkSplit::DecisionContracts)
            && f.metric.as_deref() == Some("latency_ns.p95_p99")
    }));
}

// ── Section 20: Evidence throughput regression ────────────────────────────

#[test]
fn gate_detects_evidence_throughput_regression() {
    let mut inp = make_input();
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::EvidenceEmission)
        .unwrap()
        .throughput_ops_per_sec = 500_000;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::ThroughputRegressionExceeded
            && f.split == Some(BenchmarkSplit::EvidenceEmission)
    }));
}

// ── Section 21: Full integration throughput regression ────────────────────

#[test]
fn gate_detects_full_integration_throughput_regression() {
    let mut inp = make_input();
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::FullIntegration)
        .unwrap()
        .throughput_ops_per_sec = 400_000;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::ThroughputRegressionExceeded
            && f.split == Some(BenchmarkSplit::FullIntegration)
    }));
}

// ── Section 22: Memory overhead exceeded ──────────────────────────────────

#[test]
fn gate_detects_memory_overhead_exceeded_cx_threading() {
    let mut inp = make_input();
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::CxThreading)
        .unwrap()
        .peak_rss_delta_bytes = 200 * 1024 * 1024;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::MemoryOverheadExceeded
            && f.split == Some(BenchmarkSplit::CxThreading)
    }));
}

#[test]
fn gate_detects_memory_overhead_exceeded_baseline_nonzero() {
    let mut inp = make_input();
    // Baseline RSS limit is 0, so any delta should fail
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::Baseline)
        .unwrap()
        .peak_rss_delta_bytes = 1;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::MemoryOverheadExceeded
            && f.split == Some(BenchmarkSplit::Baseline)
    }));
}

// ── Section 23: Previous run throughput regression ────────────────────────

#[test]
fn gate_detects_previous_run_throughput_regression() {
    let mut inp = make_input();
    // Big drop in baseline throughput vs previous
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::Baseline)
        .unwrap()
        .throughput_ops_per_sec = 700_000;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::PreviousRunRegressionExceeded
            && f.metric.as_deref() == Some("throughput_ops_per_sec")
    }));
}

// ── Section 24: Previous run latency regression ───────────────────────────

#[test]
fn gate_detects_previous_run_latency_regression() {
    let mut inp = make_input();
    // Big latency increase in candidate vs previous
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::Baseline)
        .unwrap()
        .latency_ns
        .p95_ns = 3_000_000;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkSplitFailureCode::PreviousRunRegressionExceeded
            && f.metric.as_deref() == Some("latency_ns.p95_p99")
    }));
}

// ── Section 25: Evaluation pass flag accuracy ─────────────────────────────

#[test]
fn evaluation_pass_false_when_finding_targets_that_split() {
    let mut inp = make_input();
    // Force a finding on CxThreading
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::CxThreading)
        .unwrap()
        .peak_rss_delta_bytes = 200 * 1024 * 1024;
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    let cx_eval = decision
        .evaluations
        .iter()
        .find(|e| e.split == BenchmarkSplit::CxThreading)
        .unwrap();
    assert!(!cx_eval.pass, "CxThreading evaluation should fail");
    // Other splits should still pass
    let baseline_eval = decision
        .evaluations
        .iter()
        .find(|e| e.split == BenchmarkSplit::Baseline)
        .unwrap();
    assert!(baseline_eval.pass, "Baseline evaluation should still pass");
}

// ── Section 26: Decision ID determinism ───────────────────────────────────

#[test]
fn decision_id_is_deterministic_for_same_input() {
    let inp = make_input();
    let t = BenchmarkSplitThresholds::default();
    let d1 = evaluate_control_plane_benchmark_split(&inp, &t);
    let d2 = evaluate_control_plane_benchmark_split(&inp, &t);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn decision_id_changes_with_trace_id() {
    let mut inp = make_input();
    let t = BenchmarkSplitThresholds::default();
    let d1 = evaluate_control_plane_benchmark_split(&inp, &t);
    inp.trace_id = "different-trace".to_string();
    let d2 = evaluate_control_plane_benchmark_split(&inp, &t);
    assert_ne!(d1.decision_id, d2.decision_id);
}

#[test]
fn decision_id_changes_with_policy_id() {
    let mut inp = make_input();
    let t = BenchmarkSplitThresholds::default();
    let d1 = evaluate_control_plane_benchmark_split(&inp, &t);
    inp.policy_id = "different-policy".to_string();
    let d2 = evaluate_control_plane_benchmark_split(&inp, &t);
    assert_ne!(d1.decision_id, d2.decision_id);
}

// ── Section 27: Snapshot hashes in decision ───────────────────────────────

#[test]
fn decision_carries_correct_snapshot_hashes() {
    let inp = make_input();
    let expected_prev = inp.previous_snapshot.snapshot_hash();
    let expected_cand = inp.candidate_snapshot.snapshot_hash();
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert_eq!(decision.previous_snapshot_hash, expected_prev);
    assert_eq!(decision.candidate_snapshot_hash, expected_cand);
}

// ── Section 28: Evaluation regression values ──────────────────────────────

#[test]
fn evaluation_regression_zero_when_candidate_equal_or_better() {
    // Candidate has slightly better throughput and same latency
    let decision =
        evaluate_control_plane_benchmark_split(&make_input(), &BenchmarkSplitThresholds::default());
    for eval in &decision.evaluations {
        // Our helpers use same or very similar values, so regressions should be small
        assert!(
            eval.throughput_regression_vs_previous_millionths < 50_000,
            "throughput regression for {:?} should be small, got {}",
            eval.split,
            eval.throughput_regression_vs_previous_millionths
        );
    }
}

// ── Section 29: Multiple findings accumulate ──────────────────────────────

#[test]
fn gate_accumulates_multiple_findings() {
    let mut inp = make_input();
    // Trigger memory overhead on CxThreading
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::CxThreading)
        .unwrap()
        .peak_rss_delta_bytes = 200 * 1024 * 1024;
    // Trigger memory overhead on Baseline (limit is 0)
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::Baseline)
        .unwrap()
        .peak_rss_delta_bytes = 1;
    // Also make baseline runs insufficient
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![1_000_000; 3];

    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision.findings.len() >= 3,
        "should have at least 3 findings, got {}",
        decision.findings.len()
    );
}

// ── Section 30: Custom thresholds ─────────────────────────────────────────

#[test]
fn gate_passes_with_relaxed_thresholds() {
    let mut inp = make_input();
    // Create a scenario that fails with defaults
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::CxThreading)
        .unwrap()
        .throughput_ops_per_sec = 800_000;

    // Verify it fails with defaults
    let d_default =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!d_default.pass);

    // Now use relaxed thresholds
    let mut t = BenchmarkSplitThresholds {
        max_cx_throughput_regression_millionths: 500_000, // allow up to 50% regression
        ..BenchmarkSplitThresholds::default()
    };
    // Also need to relax previous-run regression limit for CxThreading
    t.max_previous_run_throughput_regression_millionths
        .insert(BenchmarkSplit::CxThreading, 500_000);
    let d_relaxed = evaluate_control_plane_benchmark_split(&inp, &t);
    assert!(
        d_relaxed.pass,
        "should pass with relaxed thresholds, findings: {:?}",
        d_relaxed.findings
    );
}

#[test]
fn gate_with_strict_thresholds_catches_small_regression() {
    let mut inp = make_input();
    // Tiny regression
    inp.candidate_snapshot
        .split_metrics
        .get_mut(&BenchmarkSplit::FullIntegration)
        .unwrap()
        .throughput_ops_per_sec = 959_000;

    // Should pass with defaults
    let d_default =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(d_default.pass);

    // Strict threshold: 0 regression allowed
    let t = BenchmarkSplitThresholds {
        max_full_integration_throughput_regression_millionths: 0,
        ..BenchmarkSplitThresholds::default()
    };
    let d_strict = evaluate_control_plane_benchmark_split(&inp, &t);
    // With 960k -> 959k, the regression is (1000/1000000)*1000000 = 1000 ppm vs baseline,
    // but the full_integration check compares vs baseline throughput (1M) not previous full_integration
    // 1_000_000 -> 959_000 regression = 41_000 ppm. Threshold is 0. Should fail.
    assert!(!d_strict.pass);
}

// ── Section 31: BenchmarkSplitGateInput serde ─────────────────────────────

#[test]
fn gate_input_serde_roundtrip() {
    let inp = make_input();
    let json = serde_json::to_string(&inp).unwrap();
    let back: BenchmarkSplitGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, inp.trace_id);
    assert_eq!(back.policy_id, inp.policy_id);
    assert_eq!(back.previous_snapshot, inp.previous_snapshot);
    assert_eq!(back.candidate_snapshot, inp.candidate_snapshot);
}

// ── Section 32: Empty split_metrics ───────────────────────────────────────

#[test]
fn gate_fails_when_all_splits_missing() {
    let mut inp = make_input();
    inp.candidate_snapshot.split_metrics.clear();
    inp.previous_snapshot.split_metrics.clear();
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    assert!(!decision.pass);
    // Should have 10 missing findings (5 previous + 5 candidate)
    let missing_count = decision
        .findings
        .iter()
        .filter(|f| f.code == BenchmarkSplitFailureCode::MissingSplitMetrics)
        .count();
    assert_eq!(missing_count, 10);
    // No evaluations since no split data is available
    assert!(decision.evaluations.is_empty());
}

// ── Section 33: Baseline stability log on failure ─────────────────────────

#[test]
fn baseline_stability_log_shows_fail_when_variance_too_high() {
    let mut inp = make_input();
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![
        100_000, 900_000, 100_000, 900_000, 100_000, 900_000, 100_000, 900_000, 100_000, 900_000,
    ];
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    let stability_log = decision
        .logs
        .iter()
        .find(|l| l.event == "baseline_stability_check")
        .unwrap();
    assert_eq!(stability_log.outcome, "fail");
    assert!(stability_log.error_code.is_some());
}

#[test]
fn baseline_stability_log_shows_fail_when_insufficient_runs() {
    let mut inp = make_input();
    inp.candidate_snapshot.baseline_throughput_runs_ops_per_sec = vec![1_000_000; 5];
    let decision =
        evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
    let stability_log = decision
        .logs
        .iter()
        .find(|l| l.event == "baseline_stability_check")
        .unwrap();
    assert_eq!(stability_log.outcome, "fail");
}
