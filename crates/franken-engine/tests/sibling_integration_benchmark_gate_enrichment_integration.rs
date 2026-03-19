//! Enrichment integration tests for `sibling_integration_benchmark_gate`.
//!
//! Covers: advanced SLO violation combinations, snapshot hash stability,
//! ledger monotonicity edge cases, log event field correctness,
//! evaluation coverage across all operations, serde round-trips for
//! deep structures, and determinism under sample reordering.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::sibling_integration_benchmark_gate::{
    BaselineLedger, BaselineLedgerError, BenchmarkGateDecision, BenchmarkGateFailureCode,
    BenchmarkGateFinding, BenchmarkGateInput, BenchmarkGateLogEvent, BenchmarkGateThresholds,
    BenchmarkSnapshot, ControlPlaneOperation, OperationBenchmarkEvaluation,
    OperationLatencySamples, OperationSloThreshold, SiblingIntegration,
    evaluate_sibling_integration_benchmark,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn full_integrations() -> BTreeSet<SiblingIntegration> {
    BTreeSet::from([
        SiblingIntegration::Frankentui,
        SiblingIntegration::Frankensqlite,
        SiblingIntegration::SqlmodelRust,
        SiblingIntegration::FastapiRust,
    ])
}

fn make_samples(without: &[u64], with_int: &[u64]) -> OperationLatencySamples {
    OperationLatencySamples {
        without_integrations_ns: without.to_vec(),
        with_integrations_ns: with_int.to_vec(),
    }
}

fn good_operation_samples() -> BTreeMap<ControlPlaneOperation, OperationLatencySamples> {
    let mut map = BTreeMap::new();
    // Keep overhead well below 200_000 ppm (< 15% overhead)
    map.insert(
        ControlPlaneOperation::EvidenceWrite,
        make_samples(
            &[1_000_000, 1_020_000, 1_010_000, 1_050_000, 1_040_000],
            &[1_100_000, 1_110_000, 1_105_000, 1_130_000, 1_120_000],
        ),
    );
    map.insert(
        ControlPlaneOperation::PolicyQuery,
        make_samples(
            &[800_000, 820_000, 810_000, 830_000, 840_000],
            &[880_000, 890_000, 885_000, 900_000, 910_000],
        ),
    );
    map.insert(
        ControlPlaneOperation::TelemetryIngestion,
        make_samples(
            &[900_000, 910_000, 920_000, 930_000, 940_000],
            &[990_000, 1_000_000, 1_010_000, 1_020_000, 1_030_000],
        ),
    );
    map.insert(
        ControlPlaneOperation::TuiDataUpdate,
        make_samples(
            &[1_200_000, 1_220_000, 1_230_000, 1_240_000, 1_250_000],
            &[1_320_000, 1_330_000, 1_340_000, 1_350_000, 1_360_000],
        ),
    );
    map
}

fn baseline_snapshot() -> BenchmarkSnapshot {
    BenchmarkSnapshot {
        snapshot_id: "bl-snap".to_string(),
        benchmark_run_id: "bl-run".to_string(),
        integrations: full_integrations(),
        operation_samples: good_operation_samples(),
    }
}

fn candidate_snapshot() -> BenchmarkSnapshot {
    let mut samples = good_operation_samples();
    // Slightly different values for candidate
    samples.insert(
        ControlPlaneOperation::EvidenceWrite,
        make_samples(
            &[1_010_000, 1_020_000, 1_030_000, 1_040_000, 1_050_000],
            &[1_220_000, 1_230_000, 1_240_000, 1_250_000, 1_260_000],
        ),
    );
    BenchmarkSnapshot {
        snapshot_id: "cand-snap".to_string(),
        benchmark_run_id: "cand-run".to_string(),
        integrations: full_integrations(),
        operation_samples: samples,
    }
}

fn make_input(baseline: BenchmarkSnapshot, candidate: BenchmarkSnapshot) -> BenchmarkGateInput {
    BenchmarkGateInput {
        trace_id: "enrichment-trace".to_string(),
        policy_id: "enrichment-policy".to_string(),
        baseline,
        candidate,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_passing_decision_has_no_findings_and_four_evaluations() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(d.pass);
    assert!(!d.rollback_required);
    assert!(d.findings.is_empty());
    assert_eq!(d.evaluations.len(), 4);
}

#[test]
fn enrichment_decision_id_prefix_is_sib_bench_gate() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(d.decision_id.starts_with("sib-bench-gate-"));
}

#[test]
fn enrichment_snapshot_hash_differs_for_different_snapshot_ids() {
    let mut a = baseline_snapshot();
    let mut b = baseline_snapshot();
    a.snapshot_id = "snap-a".to_string();
    b.snapshot_id = "snap-b".to_string();
    assert_ne!(a.snapshot_hash(), b.snapshot_hash());
}

#[test]
fn enrichment_snapshot_hash_deterministic_regardless_of_sample_order() {
    let s1 = baseline_snapshot();
    let mut s2 = baseline_snapshot();
    // Reverse samples in one operation
    if let Some(samples) = s2.operation_samples.get_mut(&ControlPlaneOperation::PolicyQuery) {
        samples.with_integrations_ns.reverse();
        samples.without_integrations_ns.reverse();
    }
    // Hashes should be the same because the snapshot uses sorted samples
    assert_eq!(s1.snapshot_hash(), s2.snapshot_hash());
}

#[test]
fn enrichment_all_four_sibling_integrations_have_unique_as_str() {
    let integrations = [
        SiblingIntegration::Frankentui,
        SiblingIntegration::Frankensqlite,
        SiblingIntegration::SqlmodelRust,
        SiblingIntegration::FastapiRust,
    ];
    let strs: BTreeSet<&str> = integrations.iter().map(|i| i.as_str()).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_all_four_operations_have_unique_as_str() {
    let ops = [
        ControlPlaneOperation::EvidenceWrite,
        ControlPlaneOperation::PolicyQuery,
        ControlPlaneOperation::TelemetryIngestion,
        ControlPlaneOperation::TuiDataUpdate,
    ];
    let strs: BTreeSet<&str> = ops.iter().map(|o| o.as_str()).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_gate_failure_when_both_snapshots_miss_different_integrations() {
    let mut baseline = baseline_snapshot();
    let mut candidate = candidate_snapshot();
    baseline.integrations.remove(&SiblingIntegration::Frankentui);
    candidate.integrations.remove(&SiblingIntegration::FastapiRust);
    let input = make_input(baseline, candidate);
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!d.pass);
    assert!(d.rollback_required);
    // At least 2 findings: one for baseline, one for candidate
    let missing_count = d
        .findings
        .iter()
        .filter(|f| f.code == BenchmarkGateFailureCode::MissingRequiredIntegration)
        .count();
    assert!(missing_count >= 2);
}

#[test]
fn enrichment_slo_exceeded_for_evidence_write() {
    let mut candidate = candidate_snapshot();
    // Push evidence write p95/p99 above SLO (5ms p95, 10ms p99)
    candidate.operation_samples.insert(
        ControlPlaneOperation::EvidenceWrite,
        make_samples(
            &[1_000_000; 5],
            &[6_000_000, 6_100_000, 6_200_000, 6_300_000, 6_400_000],
        ),
    );
    let input = make_input(baseline_snapshot(), candidate);
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::SloThresholdExceeded
            && f.operation == Some(ControlPlaneOperation::EvidenceWrite)
    }));
}

#[test]
fn enrichment_integration_overhead_exceeded_for_tui_data_update() {
    let mut candidate = candidate_snapshot();
    // Very low without-integration, very high with-integration -> excessive overhead
    candidate.operation_samples.insert(
        ControlPlaneOperation::TuiDataUpdate,
        make_samples(
            &[1_000_000, 1_010_000, 1_020_000, 1_030_000, 1_040_000],
            &[2_500_000, 2_600_000, 2_700_000, 2_800_000, 2_900_000],
        ),
    );
    let input = make_input(baseline_snapshot(), candidate);
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::IntegrationOverheadExceeded
            && f.operation == Some(ControlPlaneOperation::TuiDataUpdate)
    }));
}

#[test]
fn enrichment_empty_with_integrations_samples_triggers_empty_samples() {
    let mut candidate = candidate_snapshot();
    candidate.operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        make_samples(&[1_000_000], &[]),
    );
    let input = make_input(baseline_snapshot(), candidate);
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::EmptySamples
            && f.operation == Some(ControlPlaneOperation::TelemetryIngestion)
    }));
}

#[test]
fn enrichment_missing_operation_in_candidate_triggers_missing_samples() {
    let mut candidate = candidate_snapshot();
    candidate
        .operation_samples
        .remove(&ControlPlaneOperation::PolicyQuery);
    let input = make_input(baseline_snapshot(), candidate);
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::MissingOperationSamples
            && f.operation == Some(ControlPlaneOperation::PolicyQuery)
    }));
}

#[test]
fn enrichment_logs_last_event_is_benchmark_gate_decision() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let last = d.logs.last().expect("should have at least one log");
    assert_eq!(last.event, "benchmark_gate_decision");
    assert_eq!(last.component, "sibling_integration_benchmark_gate");
}

#[test]
fn enrichment_logs_carry_trace_and_policy_ids_on_all_entries() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    for log in &d.logs {
        assert_eq!(log.trace_id, "enrichment-trace");
        assert_eq!(log.policy_id, "enrichment-policy");
    }
}

#[test]
fn enrichment_passing_decision_final_log_has_no_error_code() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let last = d.logs.last().unwrap();
    assert!(last.error_code.is_none());
    assert_eq!(last.outcome, "pass");
}

#[test]
fn enrichment_failing_decision_final_log_has_error_code() {
    let mut candidate = candidate_snapshot();
    candidate
        .integrations
        .remove(&SiblingIntegration::Frankensqlite);
    let input = make_input(baseline_snapshot(), candidate);
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let last = d.logs.last().unwrap();
    assert_eq!(last.outcome, "fail");
    assert_eq!(last.error_code.as_deref(), Some("benchmark_gate_failed"));
}

#[test]
fn enrichment_ledger_record_returns_hash_and_tracks_latest() {
    let mut ledger = BaselineLedger::default();
    let snap = baseline_snapshot();
    let hash = ledger.record(1, snap.clone()).unwrap();
    assert_eq!(ledger.latest().unwrap().epoch, 1);
    assert_eq!(ledger.latest().unwrap().snapshot_hash, hash);
}

#[test]
fn enrichment_ledger_non_monotonic_epoch_error() {
    let mut ledger = BaselineLedger::default();
    ledger.record(10, baseline_snapshot()).unwrap();
    let err = ledger.record(5, candidate_snapshot()).unwrap_err();
    match err {
        BaselineLedgerError::NonMonotonicEpoch {
            previous_epoch,
            next_epoch,
        } => {
            assert_eq!(previous_epoch, 10);
            assert_eq!(next_epoch, 5);
        }
        other => panic!("expected NonMonotonicEpoch, got {other}"),
    }
}

#[test]
fn enrichment_ledger_same_epoch_error() {
    let mut ledger = BaselineLedger::default();
    ledger.record(10, baseline_snapshot()).unwrap();
    let err = ledger.record(10, candidate_snapshot()).unwrap_err();
    assert!(matches!(
        err,
        BaselineLedgerError::NonMonotonicEpoch { .. }
    ));
}

#[test]
fn enrichment_ledger_duplicate_snapshot_hash_error() {
    let mut ledger = BaselineLedger::default();
    let snap = baseline_snapshot();
    ledger.record(1, snap.clone()).unwrap();
    let err = ledger.record(2, snap).unwrap_err();
    assert!(matches!(
        err,
        BaselineLedgerError::DuplicateSnapshotHash { .. }
    ));
}

#[test]
fn enrichment_ledger_empty_returns_none_for_latest() {
    let ledger = BaselineLedger::default();
    assert!(ledger.latest().is_none());
}

#[test]
fn enrichment_ledger_multiple_entries_latest_is_last() {
    let mut ledger = BaselineLedger::default();
    ledger.record(1, baseline_snapshot()).unwrap();
    ledger.record(2, candidate_snapshot()).unwrap();
    assert_eq!(ledger.entries.len(), 2);
    assert_eq!(ledger.latest().unwrap().epoch, 2);
}

#[test]
fn enrichment_decision_serde_roundtrip_preserves_all_fields() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let json = serde_json::to_string(&d).unwrap();
    let back: BenchmarkGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d.decision_id, back.decision_id);
    assert_eq!(d.pass, back.pass);
    assert_eq!(d.rollback_required, back.rollback_required);
    assert_eq!(d.baseline_snapshot_hash, back.baseline_snapshot_hash);
    assert_eq!(d.candidate_snapshot_hash, back.candidate_snapshot_hash);
    assert_eq!(d.evaluations, back.evaluations);
    assert_eq!(d.findings, back.findings);
    assert_eq!(d.logs, back.logs);
}

#[test]
fn enrichment_thresholds_serde_roundtrip() {
    let t = BenchmarkGateThresholds::default();
    let json = serde_json::to_string(&t).unwrap();
    let back: BenchmarkGateThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrichment_custom_thresholds_with_single_operation() {
    let mut thresholds = BenchmarkGateThresholds::default();
    // Keep only one operation to check
    thresholds
        .per_operation
        .retain(|op, _| *op == ControlPlaneOperation::PolicyQuery);
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &thresholds);
    // Should still evaluate since samples exist
    assert_eq!(d.evaluations.len(), 1);
    assert_eq!(
        d.evaluations[0].operation,
        ControlPlaneOperation::PolicyQuery
    );
}

#[test]
fn enrichment_custom_thresholds_tight_slo_triggers_failure() {
    let mut thresholds = BenchmarkGateThresholds::default();
    // Set very tight SLO for policy query (100ns p95)
    thresholds.per_operation.insert(
        ControlPlaneOperation::PolicyQuery,
        OperationSloThreshold {
            p95_ns: 100,
            p99_ns: 200,
            max_regression_millionths: 150_000,
            max_integration_overhead_millionths: 200_000,
        },
    );
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &thresholds);
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::SloThresholdExceeded
            && f.operation == Some(ControlPlaneOperation::PolicyQuery)
    }));
}

#[test]
fn enrichment_custom_thresholds_tight_regression_triggers_failure() {
    let mut thresholds = BenchmarkGateThresholds::default();
    // Set very tight regression threshold (0 ppm max regression)
    thresholds.per_operation.insert(
        ControlPlaneOperation::EvidenceWrite,
        OperationSloThreshold {
            p95_ns: 50_000_000,
            p99_ns: 100_000_000,
            max_regression_millionths: 0, // zero tolerance
            max_integration_overhead_millionths: 200_000,
        },
    );
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &thresholds);
    assert!(!d.pass);
    assert!(d.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::RegressionThresholdExceeded
            && f.operation == Some(ControlPlaneOperation::EvidenceWrite)
    }));
}

#[test]
fn enrichment_pass_and_rollback_always_inverse() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert_eq!(d.pass, !d.rollback_required);
}

#[test]
fn enrichment_pass_and_rollback_always_inverse_failing() {
    let mut candidate = candidate_snapshot();
    candidate
        .integrations
        .remove(&SiblingIntegration::FastapiRust);
    let input = make_input(baseline_snapshot(), candidate);
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert_eq!(d.pass, !d.rollback_required);
}

#[test]
fn enrichment_evaluations_cover_all_default_operations() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    let ops: BTreeSet<ControlPlaneOperation> = d.evaluations.iter().map(|e| e.operation).collect();
    assert!(ops.contains(&ControlPlaneOperation::EvidenceWrite));
    assert!(ops.contains(&ControlPlaneOperation::PolicyQuery));
    assert!(ops.contains(&ControlPlaneOperation::TelemetryIngestion));
    assert!(ops.contains(&ControlPlaneOperation::TuiDataUpdate));
}

#[test]
fn enrichment_evaluation_regression_ratio_near_one_for_similar_data() {
    let input = make_input(baseline_snapshot(), candidate_snapshot());
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    for eval in &d.evaluations {
        assert!(
            eval.regression_p95_millionths >= 800_000
                && eval.regression_p95_millionths <= 1_300_000,
            "regression for {:?} = {} should be near 1.0",
            eval.operation,
            eval.regression_p95_millionths,
        );
    }
}

#[test]
fn enrichment_multiple_failure_codes_accumulate() {
    let mut candidate = candidate_snapshot();
    // Missing integration
    candidate
        .integrations
        .remove(&SiblingIntegration::SqlmodelRust);
    // Empty samples for one operation
    candidate.operation_samples.insert(
        ControlPlaneOperation::EvidenceWrite,
        make_samples(&[], &[1_000_000]),
    );
    // Remove another operation entirely
    candidate
        .operation_samples
        .remove(&ControlPlaneOperation::TelemetryIngestion);
    let input = make_input(baseline_snapshot(), candidate);
    let d = evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!d.pass);
    let codes: BTreeSet<BenchmarkGateFailureCode> = d.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&BenchmarkGateFailureCode::MissingRequiredIntegration));
    assert!(codes.contains(&BenchmarkGateFailureCode::EmptySamples));
    assert!(codes.contains(&BenchmarkGateFailureCode::MissingOperationSamples));
}

#[test]
fn enrichment_finding_serde_roundtrip() {
    let finding = BenchmarkGateFinding {
        code: BenchmarkGateFailureCode::IntegrationOverheadExceeded,
        operation: Some(ControlPlaneOperation::TuiDataUpdate),
        detail: "overhead too high".to_string(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: BenchmarkGateFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, back);
}

#[test]
fn enrichment_log_event_serde_roundtrip() {
    let log = BenchmarkGateLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "sibling_integration_benchmark_gate".to_string(),
        event: "operation_slo_check".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        operation: Some("evidence_write".to_string()),
        candidate_p95_ns: Some(1_200_000),
        candidate_p99_ns: Some(1_300_000),
        baseline_p95_ns: Some(1_100_000),
        baseline_p99_ns: Some(1_200_000),
    };
    let json = serde_json::to_string(&log).unwrap();
    let back: BenchmarkGateLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}

#[test]
fn enrichment_evaluation_serde_roundtrip() {
    let eval = OperationBenchmarkEvaluation {
        operation: ControlPlaneOperation::PolicyQuery,
        baseline_p95_ns: 900_000,
        baseline_p99_ns: 1_000_000,
        candidate_p95_ns: 920_000,
        candidate_p99_ns: 1_020_000,
        candidate_without_integrations_p95_ns: 800_000,
        candidate_without_integrations_p99_ns: 880_000,
        regression_p95_millionths: 1_022_222,
        regression_p99_millionths: 1_020_000,
        integration_overhead_p95_millionths: 150_000,
        integration_overhead_p99_millionths: 159_090,
        pass: true,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let back: OperationBenchmarkEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

#[test]
fn enrichment_snapshot_serde_roundtrip() {
    let snap = baseline_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let back: BenchmarkSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
}

#[test]
fn enrichment_ledger_serde_roundtrip() {
    let mut ledger = BaselineLedger::default();
    ledger.record(1, baseline_snapshot()).unwrap();
    ledger.record(2, candidate_snapshot()).unwrap();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: BaselineLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn enrichment_ledger_error_serde_roundtrip_non_monotonic() {
    let err = BaselineLedgerError::NonMonotonicEpoch {
        previous_epoch: 42,
        next_epoch: 10,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: BaselineLedgerError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_ledger_error_serde_roundtrip_duplicate() {
    let err = BaselineLedgerError::DuplicateSnapshotHash {
        snapshot_hash: [0xde; 32],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: BaselineLedgerError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_ledger_error_display_contains_epoch_values() {
    let err = BaselineLedgerError::NonMonotonicEpoch {
        previous_epoch: 99,
        next_epoch: 42,
    };
    let msg = err.to_string();
    assert!(msg.contains("99"));
    assert!(msg.contains("42"));
}

#[test]
fn enrichment_decision_id_changes_with_policy_id() {
    let d1 = evaluate_sibling_integration_benchmark(
        &BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "policy-a".into(),
            baseline: baseline_snapshot(),
            candidate: candidate_snapshot(),
        },
        &BenchmarkGateThresholds::default(),
    );
    let d2 = evaluate_sibling_integration_benchmark(
        &BenchmarkGateInput {
            trace_id: "t".into(),
            policy_id: "policy-b".into(),
            baseline: baseline_snapshot(),
            candidate: candidate_snapshot(),
        },
        &BenchmarkGateThresholds::default(),
    );
    assert_ne!(d1.decision_id, d2.decision_id);
}
