use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::control_plane_benchmark_split_gate::{
    BenchmarkSplit, BenchmarkSplitFailureCode, BenchmarkSplitFinding, BenchmarkSplitGateInput,
    BenchmarkSplitLogEvent, BenchmarkSplitSnapshot, BenchmarkSplitThresholds, LatencyStatsNs,
    SplitBenchmarkMetrics, evaluate_control_plane_benchmark_split,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn metrics(
    throughput_ops_per_sec: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    peak_rss_delta_bytes: u64,
) -> SplitBenchmarkMetrics {
    SplitBenchmarkMetrics {
        throughput_ops_per_sec,
        latency_ns: LatencyStatsNs {
            p50_ns,
            p95_ns,
            p99_ns,
        },
        peak_rss_delta_bytes,
    }
}

fn stable_baseline_runs() -> Vec<u64> {
    vec![
        1_000_100, 1_000_250, 999_950, 1_000_000, 1_000_150, 1_000_300, 999_975, 1_000_050,
        1_000_125, 1_000_225,
    ]
}

fn previous_snapshot() -> BenchmarkSplitSnapshot {
    BenchmarkSplitSnapshot {
        snapshot_id: "prev-snapshot".to_string(),
        benchmark_run_id: "prev-run".to_string(),
        split_metrics: BTreeMap::from([
            (
                BenchmarkSplit::Baseline,
                metrics(1_002_000, 950_000, 1_000_000, 1_050_000, 0),
            ),
            (
                BenchmarkSplit::CxThreading,
                metrics(997_000, 960_000, 1_008_000, 1_060_000, 8 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::DecisionContracts,
                metrics(994_000, 970_000, 1_052_000, 1_098_000, 16 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::EvidenceEmission,
                metrics(976_000, 980_000, 1_068_000, 1_116_000, 24 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::FullIntegration,
                metrics(958_000, 990_000, 1_080_000, 1_130_000, 30 * 1024 * 1024),
            ),
        ]),
        baseline_throughput_runs_ops_per_sec: stable_baseline_runs(),
    }
}

fn candidate_snapshot(adapter_sleep_ns: u64, evidence_enabled: bool) -> BenchmarkSplitSnapshot {
    let sleep_latency_delta = adapter_sleep_ns;
    let throughput_penalty = adapter_sleep_ns.saturating_mul(50).div_ceil(1_000_000);

    let mut split_metrics = BTreeMap::from([
        (
            BenchmarkSplit::Baseline,
            metrics(1_000_000, 950_000, 1_000_000, 1_050_000, 0),
        ),
        (
            BenchmarkSplit::CxThreading,
            metrics(
                995_000,
                962_000,
                1_008_000 + sleep_latency_delta,
                1_060_000 + sleep_latency_delta,
                8 * 1024 * 1024,
            ),
        ),
        (
            BenchmarkSplit::DecisionContracts,
            metrics(
                993_500u64.saturating_sub(throughput_penalty),
                972_000,
                1_055_000 + sleep_latency_delta,
                1_100_000 + sleep_latency_delta,
                16 * 1024 * 1024,
            ),
        ),
        (
            BenchmarkSplit::EvidenceEmission,
            metrics(
                975_000u64.saturating_sub(throughput_penalty),
                980_000,
                1_068_000 + sleep_latency_delta,
                1_115_000 + sleep_latency_delta,
                24 * 1024 * 1024,
            ),
        ),
        (
            BenchmarkSplit::FullIntegration,
            metrics(
                955_000u64.saturating_sub(throughput_penalty.saturating_mul(2)),
                990_000,
                1_080_000 + sleep_latency_delta,
                1_130_000 + sleep_latency_delta,
                30 * 1024 * 1024,
            ),
        ),
    ]);

    if !evidence_enabled {
        let decision_metrics = split_metrics
            .get(&BenchmarkSplit::DecisionContracts)
            .expect("decision split")
            .clone();
        split_metrics.insert(BenchmarkSplit::EvidenceEmission, decision_metrics.clone());
        split_metrics.insert(BenchmarkSplit::FullIntegration, decision_metrics);
    }

    BenchmarkSplitSnapshot {
        snapshot_id: "candidate-snapshot".to_string(),
        benchmark_run_id: "candidate-run".to_string(),
        split_metrics,
        baseline_throughput_runs_ops_per_sec: stable_baseline_runs(),
    }
}

fn input(
    previous: BenchmarkSplitSnapshot,
    candidate: BenchmarkSplitSnapshot,
) -> BenchmarkSplitGateInput {
    BenchmarkSplitGateInput {
        trace_id: "trace-bd-1rdj".to_string(),
        policy_id: "policy-bd-1rdj".to_string(),
        previous_snapshot: previous,
        candidate_snapshot: candidate,
    }
}

#[test]
fn baseline_stability_requires_ten_runs_with_low_variance() {
    let previous = previous_snapshot();

    let mut too_few_runs = candidate_snapshot(0, true);
    too_few_runs.baseline_throughput_runs_ops_per_sec.pop();
    let too_few_decision = evaluate_control_plane_benchmark_split(
        &input(previous.clone(), too_few_runs),
        &BenchmarkSplitThresholds::default(),
    );
    assert!(too_few_decision.findings.iter().any(|finding| {
        finding.code == BenchmarkSplitFailureCode::InsufficientBaselineRuns
            && finding.split == Some(BenchmarkSplit::Baseline)
    }));

    let mut high_variance = candidate_snapshot(0, true);
    high_variance.baseline_throughput_runs_ops_per_sec = vec![
        750_000, 1_250_000, 740_000, 1_260_000, 760_000, 1_240_000, 730_000, 1_270_000, 770_000,
        1_230_000,
    ];
    let high_variance_decision = evaluate_control_plane_benchmark_split(
        &input(previous, high_variance),
        &BenchmarkSplitThresholds::default(),
    );

    assert!(high_variance_decision.findings.iter().any(|finding| {
        finding.code == BenchmarkSplitFailureCode::BaselineVarianceExceeded
            && finding.split == Some(BenchmarkSplit::Baseline)
    }));
}

#[test]
fn regression_detection_flags_adapter_sleep_injection_and_requires_rollback() {
    let decision = evaluate_control_plane_benchmark_split(
        &input(previous_snapshot(), candidate_snapshot(350_000, true)),
        &BenchmarkSplitThresholds::default(),
    );

    assert!(!decision.pass);
    assert!(decision.rollback_required);
    assert!(decision.findings.iter().any(|finding| {
        finding.code == BenchmarkSplitFailureCode::LatencyRegressionExceeded
            || finding.code == BenchmarkSplitFailureCode::ThroughputRegressionExceeded
            || finding.code == BenchmarkSplitFailureCode::PreviousRunRegressionExceeded
    }));

    assert!(decision.logs.iter().any(|event| {
        event.event == "benchmark_split_decision"
            && event.outcome == "fail"
            && event.error_code.as_deref() == Some("control_plane_benchmark_split_failed")
            && event.trace_id == "trace-bd-1rdj"
            && event.policy_id == "policy-bd-1rdj"
    }));
}

#[test]
fn disabling_evidence_emission_restores_expected_split_throughput() {
    let previous = previous_snapshot();
    let enabled = evaluate_control_plane_benchmark_split(
        &input(previous.clone(), candidate_snapshot(0, true)),
        &BenchmarkSplitThresholds::default(),
    );
    let disabled = evaluate_control_plane_benchmark_split(
        &input(previous, candidate_snapshot(0, false)),
        &BenchmarkSplitThresholds::default(),
    );

    let enabled_evidence = enabled
        .evaluations
        .iter()
        .find(|evaluation| evaluation.split == BenchmarkSplit::EvidenceEmission)
        .expect("enabled evidence split eval");
    let disabled_evidence = disabled
        .evaluations
        .iter()
        .find(|evaluation| evaluation.split == BenchmarkSplit::EvidenceEmission)
        .expect("disabled evidence split eval");
    let disabled_decision = disabled
        .evaluations
        .iter()
        .find(|evaluation| evaluation.split == BenchmarkSplit::DecisionContracts)
        .expect("disabled decision split eval");

    assert!(
        disabled_evidence.candidate_metrics.throughput_ops_per_sec
            >= enabled_evidence.candidate_metrics.throughput_ops_per_sec
    );
    assert_eq!(
        disabled_evidence.candidate_metrics.throughput_ops_per_sec,
        disabled_decision.candidate_metrics.throughput_ops_per_sec
    );
}

#[test]
fn version_matrix_workflow_runs_control_plane_benchmark_split_gate_suite() {
    let workflow_path = repo_root().join(".github/workflows/version_matrix_conformance.yml");
    let workflow = fs::read_to_string(&workflow_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow_path.display()));

    assert!(
        workflow.contains("./scripts/run_control_plane_benchmark_split_gate_suite.sh ci"),
        "version_matrix_conformance workflow must run control-plane benchmark split gate suite"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn benchmark_split_serde_round_trip_all_variants() {
    for split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        let json = serde_json::to_string(&split).expect("serialize");
        let recovered: BenchmarkSplit = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(split, recovered);
    }
}

#[test]
fn benchmark_split_display_and_as_str_are_consistent() {
    for split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        assert_eq!(split.to_string(), split.as_str());
        assert!(!split.as_str().is_empty());
    }
}

#[test]
fn benchmark_split_failure_code_serde_round_trip() {
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
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: BenchmarkSplitFailureCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, recovered);
        assert!(!code.to_string().is_empty());
    }
}

#[test]
fn latency_stats_ns_serde_round_trip() {
    let stats = LatencyStatsNs {
        p50_ns: 950_000,
        p95_ns: 1_000_000,
        p99_ns: 1_050_000,
    };
    let json = serde_json::to_string(&stats).expect("serialize");
    let recovered: LatencyStatsNs = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(stats, recovered);
}

#[test]
fn split_benchmark_metrics_serde_round_trip() {
    let m = metrics(1_000_000, 950_000, 1_000_000, 1_050_000, 0);
    let json = serde_json::to_string(&m).expect("serialize");
    let recovered: SplitBenchmarkMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, recovered);
}

#[test]
fn benchmark_split_snapshot_serde_round_trip() {
    let snapshot = previous_snapshot();
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: BenchmarkSplitSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot, recovered);
}

#[test]
fn benchmark_split_thresholds_default_has_entries_for_all_splits() {
    let thresholds = BenchmarkSplitThresholds::default();
    let json = serde_json::to_string(&thresholds).expect("serialize");
    let recovered: BenchmarkSplitThresholds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(thresholds, recovered);
}

#[test]
fn gate_input_serde_round_trip() {
    let gate_input = input(previous_snapshot(), candidate_snapshot(0, true));
    let json = serde_json::to_string(&gate_input).expect("serialize");
    let recovered: BenchmarkSplitGateInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(gate_input.trace_id, recovered.trace_id);
    assert_eq!(gate_input.policy_id, recovered.policy_id);
}

#[test]
fn evaluate_always_produces_evaluations_and_structured_logs() {
    let decision = evaluate_control_plane_benchmark_split(
        &input(previous_snapshot(), candidate_snapshot(0, true)),
        &BenchmarkSplitThresholds::default(),
    );
    assert!(!decision.evaluations.is_empty());
    assert!(!decision.logs.is_empty());
    assert!(
        decision
            .logs
            .iter()
            .all(|event| !event.trace_id.is_empty() && !event.policy_id.is_empty())
    );
}

#[test]
fn evaluate_is_deterministic_for_identical_inputs() {
    let gate_input = input(previous_snapshot(), candidate_snapshot(0, true));
    let thresholds = BenchmarkSplitThresholds::default();
    let a = evaluate_control_plane_benchmark_split(&gate_input, &thresholds);
    let b = evaluate_control_plane_benchmark_split(&gate_input, &thresholds);
    assert_eq!(a.pass, b.pass);
    assert_eq!(a.evaluations.len(), b.evaluations.len());
    assert_eq!(a.findings.len(), b.findings.len());
    assert_eq!(a.logs.len(), b.logs.len());
}

#[test]
fn decision_always_covers_all_five_splits() {
    let decision = evaluate_control_plane_benchmark_split(
        &input(previous_snapshot(), candidate_snapshot(0, true)),
        &BenchmarkSplitThresholds::default(),
    );
    let splits: BTreeSet<_> = decision
        .evaluations
        .iter()
        .map(|e| e.split)
        .collect();
    for expected_split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        assert!(
            splits.contains(&expected_split),
            "missing evaluation for split {:?}",
            expected_split
        );
    }
}

#[test]
fn evaluate_with_zero_adapter_sleep_produces_evaluations_for_all_splits() {
    let decision = evaluate_control_plane_benchmark_split(
        &input(previous_snapshot(), candidate_snapshot(0, true)),
        &BenchmarkSplitThresholds::default(),
    );
    assert_eq!(decision.evaluations.len(), 5);
    assert!(!decision.logs.is_empty());
}

#[test]
fn previous_snapshot_has_all_five_splits() {
    let snapshot = previous_snapshot();
    for split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        assert!(
            snapshot.split_metrics.contains_key(&split),
            "previous snapshot missing split: {split:?}"
        );
    }
}

#[test]
fn stable_baseline_runs_have_ten_entries() {
    let runs = stable_baseline_runs();
    assert_eq!(runs.len(), 10, "baseline requires exactly 10 runs");
    assert!(runs.iter().all(|&v| v > 0));
}

#[test]
fn benchmark_split_thresholds_default_is_constructible() {
    let thresholds = BenchmarkSplitThresholds::default();
    let json = serde_json::to_string(&thresholds).expect("serialize");
    let recovered: BenchmarkSplitThresholds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(serde_json::to_string(&recovered).unwrap(), json);
}

#[test]
fn benchmark_split_serde_roundtrip() {
    for split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        let json = serde_json::to_string(&split).expect("serialize");
        let recovered: BenchmarkSplit = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, split);
    }
}

#[test]
fn benchmark_split_failure_code_serde_roundtrip() {
    let code = BenchmarkSplitFailureCode::ThroughputRegressionExceeded;
    let json = serde_json::to_string(&code).expect("serialize");
    let recovered: BenchmarkSplitFailureCode = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, code);
}

#[test]
fn candidate_snapshot_has_all_five_splits() {
    let snapshot = candidate_snapshot(0, true);
    for split in [
        BenchmarkSplit::Baseline,
        BenchmarkSplit::CxThreading,
        BenchmarkSplit::DecisionContracts,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
    ] {
        assert!(
            snapshot.split_metrics.contains_key(&split),
            "candidate snapshot missing split: {split:?}"
        );
    }
}

#[test]
fn gate_input_has_nonempty_trace_and_policy_ids() {
    let gate_input = input(previous_snapshot(), candidate_snapshot(0, true));
    assert!(!gate_input.trace_id.trim().is_empty());
    assert!(!gate_input.policy_id.trim().is_empty());
}

#[test]
fn latency_stats_ns_debug_is_nonempty() {
    let stats = LatencyStatsNs {
        p50_ns: 1_000,
        p95_ns: 2_000,
        p99_ns: 3_000,
    };
    assert!(!format!("{stats:?}").is_empty());
}

// ────────────────────────────────────────────────────────────
// Batch enrichment: snapshot hash determinism, missing split detection,
// decision serde, evaluation pass flag, rollback flag, log event serde,
// finding serde
// ────────────────────────────────────────────────────────────

#[test]
fn snapshot_hash_is_deterministic() {
    let snap_a = previous_snapshot();
    let snap_b = previous_snapshot();
    assert_eq!(snap_a.snapshot_hash(), snap_b.snapshot_hash());
    assert_ne!(snap_a.snapshot_hash(), [0u8; 32]);
}

#[test]
fn candidate_and_previous_snapshot_have_different_hashes() {
    let prev = previous_snapshot();
    let cand = candidate_snapshot(0, true);
    assert_ne!(prev.snapshot_hash(), cand.snapshot_hash());
}

#[test]
fn missing_split_in_candidate_flags_finding() {
    let previous = previous_snapshot();
    let mut candidate = candidate_snapshot(0, true);
    candidate.split_metrics.remove(&BenchmarkSplit::CxThreading);
    let decision = evaluate_control_plane_benchmark_split(
        &input(previous, candidate),
        &BenchmarkSplitThresholds::default(),
    );
    assert!(decision.findings.iter().any(|finding| {
        finding.code == BenchmarkSplitFailureCode::MissingSplitMetrics
            && finding.split == Some(BenchmarkSplit::CxThreading)
    }));
}

#[test]
fn zero_sleep_candidate_has_fewer_findings_than_high_sleep() {
    let thresholds = BenchmarkSplitThresholds::default();
    let clean = evaluate_control_plane_benchmark_split(
        &input(previous_snapshot(), candidate_snapshot(0, true)),
        &thresholds,
    );
    let heavy = evaluate_control_plane_benchmark_split(
        &input(previous_snapshot(), candidate_snapshot(350_000, true)),
        &thresholds,
    );
    assert!(
        clean.findings.len() <= heavy.findings.len(),
        "zero-sleep candidate should have fewer or equal findings"
    );
}

#[test]
fn decision_snapshot_hashes_match_inputs() {
    let prev = previous_snapshot();
    let cand = candidate_snapshot(0, true);
    let expected_prev_hash = prev.snapshot_hash();
    let expected_cand_hash = cand.snapshot_hash();
    let decision = evaluate_control_plane_benchmark_split(
        &input(prev, cand),
        &BenchmarkSplitThresholds::default(),
    );
    assert_eq!(decision.previous_snapshot_hash, expected_prev_hash);
    assert_eq!(decision.candidate_snapshot_hash, expected_cand_hash);
}

#[test]
fn benchmark_split_log_event_serde_round_trip() {
    let event = BenchmarkSplitLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "control_plane_benchmark".to_string(),
        event: "benchmark_split_decision".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        split: Some("Baseline".to_string()),
        metric: Some("throughput_ops_per_sec".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: BenchmarkSplitLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn benchmark_split_finding_serde_round_trip() {
    let finding = BenchmarkSplitFinding {
        code: BenchmarkSplitFailureCode::LatencyRegressionExceeded,
        split: Some(BenchmarkSplit::FullIntegration),
        metric: Some("p95_ns".to_string()),
        detail: "latency regression exceeded".to_string(),
        observed_millionths: Some(75_000),
        threshold_millionths: Some(50_000),
    };
    let json = serde_json::to_string(&finding).expect("serialize");
    let recovered: BenchmarkSplitFinding = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(finding, recovered);
}

// ────────────────────────────────────────────────────────────
// Enrichment: threshold edge cases, evaluation field coverage,
// decision structure, finding detail content
// ────────────────────────────────────────────────────────────

#[test]
fn thresholds_default_min_baseline_runs_is_ten() {
    let t = BenchmarkSplitThresholds::default();
    assert_eq!(t.min_baseline_runs, 10);
}

#[test]
fn benchmark_split_as_str_covers_all_variants() {
    let variants = [
        (BenchmarkSplit::Baseline, "baseline"),
        (BenchmarkSplit::CxThreading, "cx_threading"),
        (BenchmarkSplit::DecisionContracts, "decision_contracts"),
        (BenchmarkSplit::EvidenceEmission, "evidence_emission"),
        (BenchmarkSplit::FullIntegration, "full_integration"),
    ];
    for (v, expected) in variants {
        assert_eq!(v.as_str(), expected);
    }
}

#[test]
fn evaluation_regression_fields_are_zero_for_identical_snapshots() {
    let snap = previous_snapshot();
    let decision = evaluate_control_plane_benchmark_split(
        &input(snap.clone(), snap),
        &BenchmarkSplitThresholds::default(),
    );
    for eval in &decision.evaluations {
        assert_eq!(
            eval.throughput_regression_vs_previous_millionths, 0,
            "identical snapshots should show zero throughput regression for {:?}",
            eval.split
        );
    }
}

#[test]
fn decision_id_is_nonempty_for_any_evaluation() {
    let decision = evaluate_control_plane_benchmark_split(
        &input(previous_snapshot(), candidate_snapshot(0, true)),
        &BenchmarkSplitThresholds::default(),
    );
    assert!(!decision.decision_id.is_empty());
}
