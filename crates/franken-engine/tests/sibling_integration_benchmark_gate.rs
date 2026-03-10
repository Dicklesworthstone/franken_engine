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

use frankenengine_engine::sibling_integration_benchmark_gate::{
    BaselineLedger, BaselineLedgerError, BenchmarkGateDecision, BenchmarkGateFailureCode,
    BenchmarkGateInput, BenchmarkGateThresholds, BenchmarkSnapshot, ControlPlaneOperation,
    OperationLatencySamples, SiblingIntegration, evaluate_sibling_integration_benchmark,
};

fn required_integrations() -> BTreeSet<SiblingIntegration> {
    BTreeSet::from([
        SiblingIntegration::Frankentui,
        SiblingIntegration::Frankensqlite,
        SiblingIntegration::SqlmodelRust,
        SiblingIntegration::FastapiRust,
    ])
}

fn op_samples(without: &[u64], with: &[u64]) -> OperationLatencySamples {
    OperationLatencySamples {
        without_integrations_ns: without.to_vec(),
        with_integrations_ns: with.to_vec(),
    }
}

fn snapshot(id: &str, run_id: &str, policy_query_with: &[u64]) -> BenchmarkSnapshot {
    let mut operation_samples = BTreeMap::new();
    operation_samples.insert(
        ControlPlaneOperation::EvidenceWrite,
        op_samples(
            &[1_000_000, 1_010_000, 1_020_000, 1_030_000, 1_040_000],
            &[1_200_000, 1_210_000, 1_220_000, 1_230_000, 1_240_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        op_samples(
            &[800_000, 810_000, 820_000, 830_000, 840_000],
            policy_query_with,
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        op_samples(
            &[900_000, 910_000, 920_000, 930_000, 940_000],
            &[1_080_000, 1_090_000, 1_100_000, 1_110_000, 1_120_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::TuiDataUpdate,
        op_samples(
            &[1_200_000, 1_210_000, 1_220_000, 1_230_000, 1_240_000],
            &[1_420_000, 1_430_000, 1_440_000, 1_450_000, 1_460_000],
        ),
    );
    BenchmarkSnapshot {
        snapshot_id: id.to_string(),
        benchmark_run_id: run_id.to_string(),
        integrations: required_integrations(),
        operation_samples,
    }
}

#[test]
fn benchmark_gate_rejects_policy_query_regression_and_sets_rollback() {
    let baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate",
        "candidate-run",
        &[1_350_000, 1_360_000, 1_370_000, 1_380_000, 1_390_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-bench-regress".to_string(),
        policy_id: "policy-bench-regress".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    assert!(!decision.pass);
    assert!(decision.rollback_required);
    assert!(
        decision
            .findings
            .iter()
            .any(|finding| finding.code == BenchmarkGateFailureCode::RegressionThresholdExceeded)
    );
    let summary_log = decision
        .logs
        .last()
        .expect("decision log must be present for failed gate");
    assert_eq!(summary_log.component, "sibling_integration_benchmark_gate");
    assert_eq!(summary_log.event, "benchmark_gate_decision");
    assert_eq!(summary_log.outcome, "fail");
}

#[test]
fn benchmark_gate_decision_is_replay_deterministic() {
    let baseline = snapshot(
        "baseline-replay",
        "baseline-run-replay",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate-replay",
        "candidate-run-replay",
        &[970_000, 975_000, 980_000, 985_000, 990_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-bench-replay".to_string(),
        policy_id: "policy-bench-replay".to_string(),
        baseline,
        candidate,
    };

    let first = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let second =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    assert_eq!(first.decision_id, second.decision_id);
    assert_eq!(first.findings, second.findings);
    assert_eq!(first.evaluations, second.evaluations);
    assert_eq!(first.pass, second.pass);
}

#[test]
fn baseline_ledger_latest_snapshot_can_drive_next_gate_run() {
    let mut ledger = BaselineLedger::default();
    let baseline = snapshot(
        "baseline-ledger",
        "baseline-run-ledger",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    ledger
        .record(1, baseline)
        .expect("initial baseline must record");

    let next_baseline = ledger
        .latest()
        .expect("latest baseline must be available")
        .snapshot
        .clone();
    let candidate = snapshot(
        "candidate-ledger",
        "candidate-run-ledger",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-ledger".to_string(),
        policy_id: "policy-ledger".to_string(),
        baseline: next_baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(decision.pass);
    assert!(!decision.rollback_required);
}

// ── Enrichment: PearlTower 2026-03-04 ────────────────────────────────

// ── Failure modes ────────────────────────────────────────────────────

#[test]
fn gate_fails_when_candidate_missing_required_integration() {
    let baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let mut candidate = snapshot(
        "candidate",
        "candidate-run",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    candidate
        .integrations
        .remove(&SiblingIntegration::FastapiRust);

    let input = BenchmarkGateInput {
        trace_id: "trace-missing-integ".to_string(),
        policy_id: "policy-missing-integ".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.rollback_required);
    assert!(decision.findings.iter().any(|f| f.code
        == BenchmarkGateFailureCode::MissingRequiredIntegration
        && f.detail.contains("candidate")));
}

#[test]
fn gate_fails_when_baseline_missing_required_integration() {
    let mut baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    baseline
        .integrations
        .remove(&SiblingIntegration::Frankentui);
    let candidate = snapshot(
        "candidate",
        "candidate-run",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-baseline-missing".to_string(),
        policy_id: "policy-baseline-missing".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| f.code
        == BenchmarkGateFailureCode::MissingRequiredIntegration
        && f.detail.contains("baseline")));
}

#[test]
fn gate_fails_when_candidate_has_empty_samples() {
    let baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let mut candidate = snapshot(
        "candidate",
        "candidate-run",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    candidate.operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        op_samples(&[], &[960_000]),
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-empty-samp".to_string(),
        policy_id: "policy-empty-samp".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == BenchmarkGateFailureCode::EmptySamples)
    );
}

#[test]
fn gate_fails_when_missing_operation_samples() {
    let baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let mut candidate = snapshot(
        "candidate",
        "candidate-run",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    candidate
        .operation_samples
        .remove(&ControlPlaneOperation::EvidenceWrite);

    let input = BenchmarkGateInput {
        trace_id: "trace-missing-op".to_string(),
        policy_id: "policy-missing-op".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::MissingOperationSamples
            && f.operation == Some(ControlPlaneOperation::EvidenceWrite)
    }));
}

#[test]
fn gate_fails_when_slo_threshold_exceeded() {
    let baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let mut candidate = snapshot(
        "candidate",
        "candidate-run",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    // PolicyQuery SLO p95 = 3_000_000. Set candidate with-integrations above that.
    candidate.operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        op_samples(
            &[800_000, 810_000, 820_000, 830_000, 840_000],
            &[3_100_000, 3_200_000, 3_300_000, 3_400_000, 3_500_000],
        ),
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-slo-exceed".to_string(),
        policy_id: "policy-slo-exceed".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::SloThresholdExceeded
            && f.operation == Some(ControlPlaneOperation::PolicyQuery)
    }));
}

#[test]
fn gate_fails_when_integration_overhead_exceeded() {
    let baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let mut candidate = snapshot(
        "candidate",
        "candidate-run",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    // TelemetryIngestion: overhead > 200_000 ppm (20%)
    candidate.operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        op_samples(
            &[900_000, 910_000, 920_000, 930_000, 940_000],
            &[1_500_000, 1_550_000, 1_600_000, 1_650_000, 1_700_000],
        ),
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-overhead".to_string(),
        policy_id: "policy-overhead".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::IntegrationOverheadExceeded
            && f.operation == Some(ControlPlaneOperation::TelemetryIngestion)
    }));
}

#[test]
fn multiple_failures_accumulate_in_decision() {
    let mut baseline = snapshot(
        "baseline",
        "baseline-run",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    baseline
        .integrations
        .remove(&SiblingIntegration::SqlmodelRust);
    let mut candidate = snapshot(
        "candidate",
        "candidate-run",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    candidate
        .integrations
        .remove(&SiblingIntegration::SqlmodelRust);
    // Also set regression-exceeding latency on PolicyQuery
    candidate.operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        op_samples(
            &[800_000, 810_000, 820_000, 830_000, 840_000],
            &[1_400_000, 1_410_000, 1_420_000, 1_430_000, 1_440_000],
        ),
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-multi-fail".to_string(),
        policy_id: "policy-multi-fail".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    let codes: BTreeSet<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&BenchmarkGateFailureCode::MissingRequiredIntegration));
    assert!(codes.len() >= 2, "should have multiple failure codes");
}

// ── Decision structure ───────────────────────────────────────────────

#[test]
fn passing_decision_has_correct_structure() {
    let baseline = snapshot(
        "baseline-struct",
        "baseline-run-struct",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate-struct",
        "candidate-run-struct",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-struct".to_string(),
        policy_id: "policy-struct".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    assert!(decision.pass);
    assert!(!decision.rollback_required);
    assert!(decision.findings.is_empty());
    assert_eq!(decision.evaluations.len(), 4);
    assert!(decision.evaluations.iter().all(|e| e.pass));

    // Decision ID format
    assert!(decision.decision_id.starts_with("sib-bench-gate-"));

    // Logs
    assert!(!decision.logs.is_empty());
    let last_log = decision.logs.last().unwrap();
    assert_eq!(last_log.event, "benchmark_gate_decision");
    assert_eq!(last_log.outcome, "pass");
    assert!(last_log.error_code.is_none());
}

#[test]
fn failing_decision_has_error_code_in_final_log() {
    let baseline = snapshot(
        "baseline-fail-log",
        "baseline-run-fail-log",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate-fail-log",
        "candidate-run-fail-log",
        &[1_400_000, 1_410_000, 1_420_000, 1_430_000, 1_440_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-fail-log".to_string(),
        policy_id: "policy-fail-log".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    let last_log = decision.logs.last().unwrap();
    assert_eq!(last_log.outcome, "fail");
    assert_eq!(
        last_log.error_code.as_deref(),
        Some("benchmark_gate_failed")
    );
}

#[test]
fn decision_logs_carry_trace_and_policy_ids() {
    let baseline = snapshot(
        "baseline-ids",
        "baseline-run-ids",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate-ids",
        "candidate-run-ids",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "my-trace-123".to_string(),
        policy_id: "my-policy-456".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    for log in &decision.logs {
        assert_eq!(log.trace_id, "my-trace-123");
        assert_eq!(log.policy_id, "my-policy-456");
        assert_eq!(log.component, "sibling_integration_benchmark_gate");
    }
}

#[test]
fn evaluations_cover_all_four_operations() {
    let baseline = snapshot(
        "baseline-ops",
        "baseline-run-ops",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate-ops",
        "candidate-run-ops",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-ops".to_string(),
        policy_id: "policy-ops".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    let ops: BTreeSet<_> = decision.evaluations.iter().map(|e| e.operation).collect();
    assert!(ops.contains(&ControlPlaneOperation::EvidenceWrite));
    assert!(ops.contains(&ControlPlaneOperation::PolicyQuery));
    assert!(ops.contains(&ControlPlaneOperation::TelemetryIngestion));
    assert!(ops.contains(&ControlPlaneOperation::TuiDataUpdate));
}

// ── Baseline ledger ──────────────────────────────────────────────────

#[test]
fn baseline_ledger_rejects_non_monotonic_epochs() {
    let mut ledger = BaselineLedger::default();
    let snap1 = snapshot(
        "bl-1",
        "run-1",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let snap2 = snapshot(
        "bl-2",
        "run-2",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    ledger.record(5, snap1).expect("first record");
    let err = ledger
        .record(3, snap2)
        .expect_err("non-monotonic must fail");
    assert!(matches!(err, BaselineLedgerError::NonMonotonicEpoch { .. }));
    assert!(err.to_string().contains("strictly increasing"));
}

#[test]
fn baseline_ledger_rejects_duplicate_snapshot_hash() {
    let mut ledger = BaselineLedger::default();
    let snap = snapshot(
        "bl-dup",
        "run-dup",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    ledger.record(1, snap.clone()).expect("first record");
    let err = ledger
        .record(2, snap)
        .expect_err("duplicate hash must fail");
    assert!(matches!(
        err,
        BaselineLedgerError::DuplicateSnapshotHash { .. }
    ));
}

#[test]
fn baseline_ledger_latest_returns_none_when_empty() {
    let ledger = BaselineLedger::default();
    assert!(ledger.latest().is_none());
}

#[test]
fn baseline_ledger_multiple_entries_tracks_latest() {
    let mut ledger = BaselineLedger::default();
    let snap1 = snapshot(
        "bl-m1",
        "run-m1",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let snap2 = snapshot(
        "bl-m2",
        "run-m2",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    ledger.record(1, snap1).unwrap();
    ledger.record(2, snap2).unwrap();
    assert_eq!(ledger.entries.len(), 2);
    assert_eq!(ledger.latest().unwrap().epoch, 2);
}

// ── Serde roundtrips ─────────────────────────────────────────────────

#[test]
fn decision_serde_roundtrip() {
    let baseline = snapshot(
        "baseline-serde",
        "baseline-run-serde",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "candidate-serde",
        "candidate-run-serde",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-serde".to_string(),
        policy_id: "policy-serde".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    let json = serde_json::to_string(&decision).expect("serialize");
    let restored: BenchmarkGateDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision.decision_id, restored.decision_id);
    assert_eq!(decision.pass, restored.pass);
    assert_eq!(decision.evaluations, restored.evaluations);
    assert_eq!(decision.findings, restored.findings);
}

#[test]
fn input_serde_roundtrip() {
    let input = BenchmarkGateInput {
        trace_id: "trace-input-serde".to_string(),
        policy_id: "policy-input-serde".to_string(),
        baseline: snapshot(
            "bl-serde",
            "run-serde",
            &[950_000, 960_000, 970_000, 980_000, 990_000],
        ),
        candidate: snapshot(
            "cand-serde",
            "run-cand-serde",
            &[960_000, 965_000, 970_000, 975_000, 980_000],
        ),
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let restored: BenchmarkGateInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, restored);
}

#[test]
fn thresholds_serde_roundtrip() {
    let thresholds = BenchmarkGateThresholds::default();
    let json = serde_json::to_string(&thresholds).expect("serialize");
    let restored: BenchmarkGateThresholds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(thresholds, restored);
}

#[test]
fn snapshot_serde_roundtrip() {
    let snap = snapshot(
        "snap-serde",
        "run-serde",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let json = serde_json::to_string(&snap).expect("serialize");
    let restored: BenchmarkSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snap, restored);
}

#[test]
fn ledger_serde_roundtrip() {
    let mut ledger = BaselineLedger::default();
    ledger
        .record(
            1,
            snapshot(
                "bl-ls",
                "run-ls",
                &[950_000, 960_000, 970_000, 980_000, 990_000],
            ),
        )
        .unwrap();
    let json = serde_json::to_string(&ledger).expect("serialize");
    let restored: BaselineLedger = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ledger, restored);
}

#[test]
fn ledger_error_serde_roundtrip() {
    let errs: Vec<BaselineLedgerError> = vec![
        BaselineLedgerError::NonMonotonicEpoch {
            previous_epoch: 5,
            next_epoch: 3,
        },
        BaselineLedgerError::DuplicateSnapshotHash {
            snapshot_hash: [0xAB; 32],
        },
    ];
    for err in &errs {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: BaselineLedgerError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ── Clone independence ───────────────────────────────────────────────

#[test]
fn decision_clone_independence() {
    let baseline = snapshot(
        "bl-clone",
        "run-clone",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "cand-clone",
        "run-cand-clone",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-clone".to_string(),
        policy_id: "policy-clone".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let mut cloned = decision.clone();
    cloned.decision_id = "modified".to_string();
    assert_ne!(decision.decision_id, cloned.decision_id);
    assert_eq!(decision.pass, cloned.pass);
}

#[test]
fn snapshot_clone_independence() {
    let snap = snapshot(
        "snap-clone",
        "run-clone",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let mut cloned = snap.clone();
    cloned.snapshot_id = "modified-id".to_string();
    assert_ne!(snap.snapshot_id, cloned.snapshot_id);
    assert_eq!(snap.benchmark_run_id, cloned.benchmark_run_id);
}

// ── Display uniqueness ───────────────────────────────────────────────

#[test]
fn sibling_integration_display_uniqueness() {
    let variants = [
        SiblingIntegration::Frankentui,
        SiblingIntegration::Frankensqlite,
        SiblingIntegration::SqlmodelRust,
        SiblingIntegration::FastapiRust,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn control_plane_operation_display_uniqueness() {
    let variants = [
        ControlPlaneOperation::EvidenceWrite,
        ControlPlaneOperation::PolicyQuery,
        ControlPlaneOperation::TelemetryIngestion,
        ControlPlaneOperation::TuiDataUpdate,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn failure_code_display_uniqueness() {
    let variants = [
        BenchmarkGateFailureCode::MissingRequiredIntegration,
        BenchmarkGateFailureCode::MissingOperationSamples,
        BenchmarkGateFailureCode::EmptySamples,
        BenchmarkGateFailureCode::SloThresholdExceeded,
        BenchmarkGateFailureCode::RegressionThresholdExceeded,
        BenchmarkGateFailureCode::IntegrationOverheadExceeded,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

// ── JSON field contracts ─────────────────────────────────────────────

#[test]
fn decision_json_field_names() {
    let baseline = snapshot(
        "bl-json",
        "run-json",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "cand-json",
        "run-cand-json",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-json".to_string(),
        policy_id: "policy-json".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    let json: serde_json::Value = serde_json::to_value(&decision).expect("to_value");
    let obj = json.as_object().expect("must be object");
    let expected_fields = [
        "decision_id",
        "pass",
        "rollback_required",
        "baseline_snapshot_hash",
        "candidate_snapshot_hash",
        "evaluations",
        "findings",
        "logs",
    ];
    for field in &expected_fields {
        assert!(obj.contains_key(*field), "missing field: {field}");
    }
}

#[test]
fn evaluation_json_field_names() {
    let baseline = snapshot(
        "bl-eval-json",
        "run-eval-json",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "cand-eval-json",
        "run-cand-eval-json",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-eval-json".to_string(),
        policy_id: "policy-eval-json".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    let eval = &decision.evaluations[0];
    let json: serde_json::Value = serde_json::to_value(eval).expect("to_value");
    let obj = json.as_object().expect("must be object");
    let expected_fields = [
        "operation",
        "baseline_p95_ns",
        "baseline_p99_ns",
        "candidate_p95_ns",
        "candidate_p99_ns",
        "candidate_without_integrations_p95_ns",
        "candidate_without_integrations_p99_ns",
        "regression_p95_millionths",
        "regression_p99_millionths",
        "integration_overhead_p95_millionths",
        "integration_overhead_p99_millionths",
        "pass",
    ];
    for field in &expected_fields {
        assert!(obj.contains_key(*field), "missing field: {field}");
    }
    assert_eq!(obj.len(), expected_fields.len());
}

// ── Deterministic replay ─────────────────────────────────────────────

#[test]
fn same_input_produces_same_decision_id() {
    let baseline = snapshot(
        "bl-replay",
        "run-replay",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "cand-replay",
        "run-cand-replay",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-replay".to_string(),
        policy_id: "policy-replay".to_string(),
        baseline,
        candidate,
    };

    let first = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let second =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());

    assert_eq!(first.decision_id, second.decision_id);
    assert_eq!(first.pass, second.pass);
    assert_eq!(first.evaluations, second.evaluations);
}

#[test]
fn different_trace_id_produces_different_decision_id() {
    let baseline = snapshot(
        "bl-diff-trace",
        "run-diff-trace",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let candidate = snapshot(
        "cand-diff-trace",
        "run-cand-diff-trace",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );

    let d1 = evaluate_sibling_integration_benchmark(
        &BenchmarkGateInput {
            trace_id: "trace-A".to_string(),
            policy_id: "policy-A".to_string(),
            baseline: baseline.clone(),
            candidate: candidate.clone(),
        },
        &BenchmarkGateThresholds::default(),
    );
    let d2 = evaluate_sibling_integration_benchmark(
        &BenchmarkGateInput {
            trace_id: "trace-B".to_string(),
            policy_id: "policy-A".to_string(),
            baseline,
            candidate,
        },
        &BenchmarkGateThresholds::default(),
    );

    assert_ne!(d1.decision_id, d2.decision_id);
}

// ── Snapshot hash ────────────────────────────────────────────────────

#[test]
fn snapshot_hash_is_deterministic() {
    let snap = snapshot(
        "snap-hash",
        "run-hash",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    assert_eq!(snap.snapshot_hash(), snap.snapshot_hash());
}

#[test]
fn snapshot_hash_differs_for_different_data() {
    let a = snapshot(
        "snap-a",
        "run-a",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let b = snapshot(
        "snap-b",
        "run-b",
        &[1_050_000, 1_060_000, 1_070_000, 1_080_000, 1_090_000],
    );
    assert_ne!(a.snapshot_hash(), b.snapshot_hash());
}

#[test]
fn snapshot_hash_invariant_to_sample_order() {
    let snap_a = snapshot(
        "snap-ord-a",
        "run-ord",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );
    let mut snap_b = snap_a.clone();
    // Reverse sample order — sorted_with/sorted_without normalizes
    if let Some(samples) = snap_b
        .operation_samples
        .get_mut(&ControlPlaneOperation::PolicyQuery)
    {
        samples.with_integrations_ns.reverse();
        samples.without_integrations_ns.reverse();
    }
    assert_eq!(snap_a.snapshot_hash(), snap_b.snapshot_hash());
}

// ── Ordering ─────────────────────────────────────────────────────────

#[test]
fn sibling_integration_ordering() {
    assert!(SiblingIntegration::Frankentui < SiblingIntegration::Frankensqlite);
    assert!(SiblingIntegration::Frankensqlite < SiblingIntegration::SqlmodelRust);
    assert!(SiblingIntegration::SqlmodelRust < SiblingIntegration::FastapiRust);
}

#[test]
fn control_plane_operation_ordering() {
    assert!(ControlPlaneOperation::EvidenceWrite < ControlPlaneOperation::PolicyQuery);
    assert!(ControlPlaneOperation::PolicyQuery < ControlPlaneOperation::TelemetryIngestion);
    assert!(ControlPlaneOperation::TelemetryIngestion < ControlPlaneOperation::TuiDataUpdate);
}

#[test]
fn failure_code_ordering() {
    assert!(
        BenchmarkGateFailureCode::MissingRequiredIntegration
            < BenchmarkGateFailureCode::MissingOperationSamples
    );
    assert!(
        BenchmarkGateFailureCode::MissingOperationSamples < BenchmarkGateFailureCode::EmptySamples
    );
    assert!(
        BenchmarkGateFailureCode::EmptySamples < BenchmarkGateFailureCode::SloThresholdExceeded
    );
}

// ── Thresholds default ───────────────────────────────────────────────

#[test]
fn thresholds_default_has_all_integrations_and_operations() {
    let t = BenchmarkGateThresholds::default();
    assert_eq!(t.required_integrations.len(), 4);
    assert_eq!(t.per_operation.len(), 4);
    assert!(
        t.per_operation
            .contains_key(&ControlPlaneOperation::EvidenceWrite)
    );
    assert!(
        t.per_operation
            .contains_key(&ControlPlaneOperation::TuiDataUpdate)
    );
}

// ── Pass/rollback symmetry ───────────────────────────────────────────

#[test]
fn pass_and_rollback_are_always_inverse() {
    let baseline = snapshot(
        "bl-sym",
        "run-sym",
        &[950_000, 960_000, 970_000, 980_000, 990_000],
    );

    // Passing case
    let cand_pass = snapshot(
        "cand-sym-pass",
        "run-sym-pass",
        &[960_000, 965_000, 970_000, 975_000, 980_000],
    );
    let input_pass = BenchmarkGateInput {
        trace_id: "trace-sym-pass".to_string(),
        policy_id: "policy-sym-pass".to_string(),
        baseline: baseline.clone(),
        candidate: cand_pass,
    };
    let d_pass =
        evaluate_sibling_integration_benchmark(&input_pass, &BenchmarkGateThresholds::default());
    assert_eq!(d_pass.pass, !d_pass.rollback_required);

    // Failing case
    let cand_fail = snapshot(
        "cand-sym-fail",
        "run-sym-fail",
        &[1_400_000, 1_410_000, 1_420_000, 1_430_000, 1_440_000],
    );
    let input_fail = BenchmarkGateInput {
        trace_id: "trace-sym-fail".to_string(),
        policy_id: "policy-sym-fail".to_string(),
        baseline,
        candidate: cand_fail,
    };
    let d_fail =
        evaluate_sibling_integration_benchmark(&input_fail, &BenchmarkGateThresholds::default());
    assert_eq!(d_fail.pass, !d_fail.rollback_required);
}
