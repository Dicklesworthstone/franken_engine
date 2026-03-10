//! Integration tests for sibling_integration_benchmark_gate module.
//!
//! Covers every public type, trait impl, and the evaluate_sibling_integration_benchmark
//! function across pass, failure-code, and edge-case scenarios.

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
    BaselineLedger, BaselineLedgerError, BenchmarkGateFailureCode, BenchmarkGateInput,
    BenchmarkGateThresholds, BenchmarkSnapshot, ControlPlaneOperation, OperationLatencySamples,
    OperationSloThreshold, SiblingIntegration, evaluate_sibling_integration_benchmark,
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

fn make_samples(without: &[u64], with_: &[u64]) -> OperationLatencySamples {
    OperationLatencySamples {
        without_integrations_ns: without.to_vec(),
        with_integrations_ns: with_.to_vec(),
    }
}

fn base_snapshot() -> BenchmarkSnapshot {
    let mut operation_samples = BTreeMap::new();
    operation_samples.insert(
        ControlPlaneOperation::EvidenceWrite,
        make_samples(
            &[1_000_000, 1_020_000, 1_010_000, 1_050_000, 1_040_000],
            &[1_200_000, 1_220_000, 1_210_000, 1_260_000, 1_240_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        make_samples(
            &[800_000, 820_000, 810_000, 830_000, 840_000],
            &[950_000, 960_000, 955_000, 980_000, 990_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        make_samples(
            &[900_000, 910_000, 920_000, 930_000, 940_000],
            &[1_080_000, 1_090_000, 1_100_000, 1_120_000, 1_130_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::TuiDataUpdate,
        make_samples(
            &[1_200_000, 1_220_000, 1_230_000, 1_240_000, 1_250_000],
            &[1_420_000, 1_430_000, 1_440_000, 1_460_000, 1_470_000],
        ),
    );
    BenchmarkSnapshot {
        snapshot_id: "baseline-snapshot-1".to_string(),
        benchmark_run_id: "baseline-run-1".to_string(),
        integrations: full_integrations(),
        operation_samples,
    }
}

fn candidate_snapshot_pass() -> BenchmarkSnapshot {
    let mut operation_samples = BTreeMap::new();
    operation_samples.insert(
        ControlPlaneOperation::EvidenceWrite,
        make_samples(
            &[1_010_000, 1_020_000, 1_030_000, 1_040_000, 1_050_000],
            &[1_220_000, 1_230_000, 1_240_000, 1_250_000, 1_260_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        make_samples(
            &[810_000, 820_000, 825_000, 830_000, 835_000],
            &[970_000, 975_000, 980_000, 985_000, 990_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        make_samples(
            &[910_000, 920_000, 930_000, 935_000, 940_000],
            &[1_090_000, 1_100_000, 1_110_000, 1_115_000, 1_120_000],
        ),
    );
    operation_samples.insert(
        ControlPlaneOperation::TuiDataUpdate,
        make_samples(
            &[1_210_000, 1_220_000, 1_230_000, 1_235_000, 1_240_000],
            &[1_430_000, 1_435_000, 1_440_000, 1_445_000, 1_450_000],
        ),
    );
    BenchmarkSnapshot {
        snapshot_id: "candidate-snapshot-pass".to_string(),
        benchmark_run_id: "candidate-run-pass".to_string(),
        integrations: full_integrations(),
        operation_samples,
    }
}

fn pass_input() -> BenchmarkGateInput {
    BenchmarkGateInput {
        trace_id: "trace-pass".to_string(),
        policy_id: "policy-pass".to_string(),
        baseline: base_snapshot(),
        candidate: candidate_snapshot_pass(),
    }
}

// ===========================================================================
// SiblingIntegration — Display and as_str
// ===========================================================================

#[test]
fn sibling_integration_display_frankentui() {
    assert_eq!(SiblingIntegration::Frankentui.to_string(), "frankentui");
}

#[test]
fn sibling_integration_display_frankensqlite() {
    assert_eq!(
        SiblingIntegration::Frankensqlite.to_string(),
        "frankensqlite"
    );
}

#[test]
fn sibling_integration_display_sqlmodel_rust() {
    assert_eq!(
        SiblingIntegration::SqlmodelRust.to_string(),
        "sqlmodel_rust"
    );
}

#[test]
fn sibling_integration_display_fastapi_rust() {
    assert_eq!(SiblingIntegration::FastapiRust.to_string(), "fastapi_rust");
}

#[test]
fn sibling_integration_as_str_matches_display() {
    let all = [
        SiblingIntegration::Frankentui,
        SiblingIntegration::Frankensqlite,
        SiblingIntegration::SqlmodelRust,
        SiblingIntegration::FastapiRust,
    ];
    for variant in all {
        assert_eq!(variant.as_str(), variant.to_string());
    }
}

// ===========================================================================
// ControlPlaneOperation — Display and as_str
// ===========================================================================

#[test]
fn control_plane_operation_display_evidence_write() {
    assert_eq!(
        ControlPlaneOperation::EvidenceWrite.to_string(),
        "evidence_write"
    );
}

#[test]
fn control_plane_operation_display_policy_query() {
    assert_eq!(
        ControlPlaneOperation::PolicyQuery.to_string(),
        "policy_query"
    );
}

#[test]
fn control_plane_operation_display_telemetry_ingestion() {
    assert_eq!(
        ControlPlaneOperation::TelemetryIngestion.to_string(),
        "telemetry_ingestion"
    );
}

#[test]
fn control_plane_operation_display_tui_data_update() {
    assert_eq!(
        ControlPlaneOperation::TuiDataUpdate.to_string(),
        "tui_data_update"
    );
}

#[test]
fn control_plane_operation_as_str_matches_display() {
    let all = [
        ControlPlaneOperation::EvidenceWrite,
        ControlPlaneOperation::PolicyQuery,
        ControlPlaneOperation::TelemetryIngestion,
        ControlPlaneOperation::TuiDataUpdate,
    ];
    for variant in all {
        assert_eq!(variant.as_str(), variant.to_string());
    }
}

// ===========================================================================
// BenchmarkGateFailureCode — Display
// ===========================================================================

#[test]
fn failure_code_display_missing_required_integration() {
    assert_eq!(
        BenchmarkGateFailureCode::MissingRequiredIntegration.to_string(),
        "missing_required_integration"
    );
}

#[test]
fn failure_code_display_missing_operation_samples() {
    assert_eq!(
        BenchmarkGateFailureCode::MissingOperationSamples.to_string(),
        "missing_operation_samples"
    );
}

#[test]
fn failure_code_display_empty_samples() {
    assert_eq!(
        BenchmarkGateFailureCode::EmptySamples.to_string(),
        "empty_samples"
    );
}

#[test]
fn failure_code_display_slo_threshold_exceeded() {
    assert_eq!(
        BenchmarkGateFailureCode::SloThresholdExceeded.to_string(),
        "slo_threshold_exceeded"
    );
}

#[test]
fn failure_code_display_regression_threshold_exceeded() {
    assert_eq!(
        BenchmarkGateFailureCode::RegressionThresholdExceeded.to_string(),
        "regression_threshold_exceeded"
    );
}

#[test]
fn failure_code_display_integration_overhead_exceeded() {
    assert_eq!(
        BenchmarkGateFailureCode::IntegrationOverheadExceeded.to_string(),
        "integration_overhead_exceeded"
    );
}

// ===========================================================================
// BaselineLedgerError — Display and Error
// ===========================================================================

#[test]
fn baseline_ledger_error_display_non_monotonic_epoch() {
    let err = BaselineLedgerError::NonMonotonicEpoch {
        previous_epoch: 10,
        next_epoch: 5,
    };
    let display = err.to_string();
    assert!(display.contains("strictly increasing"));
    assert!(display.contains("10"));
    assert!(display.contains("5"));
}

#[test]
fn baseline_ledger_error_display_duplicate_snapshot_hash() {
    let err = BaselineLedgerError::DuplicateSnapshotHash {
        snapshot_hash: [0xab; 32],
    };
    let display = err.to_string();
    assert!(display.contains("already recorded"));
    assert!(display.contains("abababab"));
}

#[test]
fn baseline_ledger_error_is_std_error() {
    let err = BaselineLedgerError::NonMonotonicEpoch {
        previous_epoch: 1,
        next_epoch: 0,
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

// ===========================================================================
// Serde round-trips
// ===========================================================================

#[test]
fn serde_round_trip_sibling_integration() {
    for variant in [
        SiblingIntegration::Frankentui,
        SiblingIntegration::Frankensqlite,
        SiblingIntegration::SqlmodelRust,
        SiblingIntegration::FastapiRust,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let parsed: SiblingIntegration = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, parsed);
    }
}

#[test]
fn serde_round_trip_control_plane_operation() {
    for variant in [
        ControlPlaneOperation::EvidenceWrite,
        ControlPlaneOperation::PolicyQuery,
        ControlPlaneOperation::TelemetryIngestion,
        ControlPlaneOperation::TuiDataUpdate,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let parsed: ControlPlaneOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, parsed);
    }
}

#[test]
fn serde_round_trip_failure_code() {
    for variant in [
        BenchmarkGateFailureCode::MissingRequiredIntegration,
        BenchmarkGateFailureCode::MissingOperationSamples,
        BenchmarkGateFailureCode::EmptySamples,
        BenchmarkGateFailureCode::SloThresholdExceeded,
        BenchmarkGateFailureCode::RegressionThresholdExceeded,
        BenchmarkGateFailureCode::IntegrationOverheadExceeded,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let parsed: BenchmarkGateFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, parsed);
    }
}

#[test]
fn serde_round_trip_operation_latency_samples() {
    let samples = make_samples(&[100, 200, 300], &[110, 210, 310]);
    let json = serde_json::to_string(&samples).unwrap();
    let parsed: OperationLatencySamples = serde_json::from_str(&json).unwrap();
    assert_eq!(samples, parsed);
}

#[test]
fn serde_round_trip_benchmark_snapshot() {
    let snap = base_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let parsed: BenchmarkSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, parsed);
}

#[test]
fn serde_round_trip_baseline_ledger_error() {
    let err = BaselineLedgerError::NonMonotonicEpoch {
        previous_epoch: 5,
        next_epoch: 3,
    };
    let json = serde_json::to_string(&err).unwrap();
    let parsed: BaselineLedgerError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, parsed);
}

#[test]
fn serde_round_trip_benchmark_gate_thresholds() {
    let thresholds = BenchmarkGateThresholds::default();
    let json = serde_json::to_string(&thresholds).unwrap();
    let parsed: BenchmarkGateThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(thresholds, parsed);
}

#[test]
fn serde_round_trip_benchmark_gate_decision() {
    let decision =
        evaluate_sibling_integration_benchmark(&pass_input(), &BenchmarkGateThresholds::default());
    let json = serde_json::to_string(&decision).unwrap();
    let parsed: frankenengine_engine::sibling_integration_benchmark_gate::BenchmarkGateDecision =
        serde_json::from_str(&json).unwrap();
    assert_eq!(decision, parsed);
}

// ===========================================================================
// BenchmarkGateThresholds — Default
// ===========================================================================

#[test]
fn default_thresholds_has_all_four_integrations() {
    let thresholds = BenchmarkGateThresholds::default();
    assert!(
        thresholds
            .required_integrations
            .contains(&SiblingIntegration::Frankentui)
    );
    assert!(
        thresholds
            .required_integrations
            .contains(&SiblingIntegration::Frankensqlite)
    );
    assert!(
        thresholds
            .required_integrations
            .contains(&SiblingIntegration::SqlmodelRust)
    );
    assert!(
        thresholds
            .required_integrations
            .contains(&SiblingIntegration::FastapiRust)
    );
    assert_eq!(thresholds.required_integrations.len(), 4);
}

#[test]
fn default_thresholds_has_all_four_operations() {
    let thresholds = BenchmarkGateThresholds::default();
    assert!(
        thresholds
            .per_operation
            .contains_key(&ControlPlaneOperation::EvidenceWrite)
    );
    assert!(
        thresholds
            .per_operation
            .contains_key(&ControlPlaneOperation::PolicyQuery)
    );
    assert!(
        thresholds
            .per_operation
            .contains_key(&ControlPlaneOperation::TelemetryIngestion)
    );
    assert!(
        thresholds
            .per_operation
            .contains_key(&ControlPlaneOperation::TuiDataUpdate)
    );
    assert_eq!(thresholds.per_operation.len(), 4);
}

#[test]
fn default_thresholds_evidence_write_slo_values() {
    let thresholds = BenchmarkGateThresholds::default();
    let slo = &thresholds.per_operation[&ControlPlaneOperation::EvidenceWrite];
    assert_eq!(slo.p95_ns, 5_000_000);
    assert_eq!(slo.p99_ns, 10_000_000);
    assert_eq!(slo.max_regression_millionths, 150_000);
    assert_eq!(slo.max_integration_overhead_millionths, 200_000);
}

#[test]
fn default_thresholds_policy_query_slo_values() {
    let thresholds = BenchmarkGateThresholds::default();
    let slo = &thresholds.per_operation[&ControlPlaneOperation::PolicyQuery];
    assert_eq!(slo.p95_ns, 3_000_000);
    assert_eq!(slo.p99_ns, 6_000_000);
}

#[test]
fn default_thresholds_telemetry_ingestion_slo_values() {
    let thresholds = BenchmarkGateThresholds::default();
    let slo = &thresholds.per_operation[&ControlPlaneOperation::TelemetryIngestion];
    assert_eq!(slo.p95_ns, 4_000_000);
    assert_eq!(slo.p99_ns, 8_000_000);
}

#[test]
fn default_thresholds_tui_data_update_slo_values() {
    let thresholds = BenchmarkGateThresholds::default();
    let slo = &thresholds.per_operation[&ControlPlaneOperation::TuiDataUpdate];
    assert_eq!(slo.p95_ns, 7_000_000);
    assert_eq!(slo.p99_ns, 12_000_000);
}

// ===========================================================================
// BenchmarkSnapshot — snapshot_hash
// ===========================================================================

#[test]
fn snapshot_hash_is_deterministic() {
    let a = base_snapshot().snapshot_hash();
    let b = base_snapshot().snapshot_hash();
    assert_eq!(a, b);
}

#[test]
fn snapshot_hash_differs_with_different_content() {
    let hash_a = base_snapshot().snapshot_hash();
    let hash_b = candidate_snapshot_pass().snapshot_hash();
    assert_ne!(hash_a, hash_b);
}

#[test]
fn snapshot_hash_stable_across_sample_reordering() {
    let mut snap = base_snapshot();
    let hash_a = snap.snapshot_hash();
    // reverse the samples for one operation
    let evidence = snap
        .operation_samples
        .get_mut(&ControlPlaneOperation::EvidenceWrite)
        .unwrap();
    evidence.with_integrations_ns.reverse();
    evidence.without_integrations_ns.reverse();
    let hash_b = snap.snapshot_hash();
    assert_eq!(
        hash_a, hash_b,
        "hash should be stable across sample reordering"
    );
}

// ===========================================================================
// BaselineLedger
// ===========================================================================

#[test]
fn baseline_ledger_default_is_empty() {
    let ledger = BaselineLedger::default();
    assert!(ledger.entries.is_empty());
    assert!(ledger.latest().is_none());
}

#[test]
fn baseline_ledger_record_and_latest() {
    let mut ledger = BaselineLedger::default();
    let snap = base_snapshot();
    let hash = ledger.record(1, snap.clone()).unwrap();
    assert_eq!(hash, snap.snapshot_hash());
    let entry = ledger.latest().unwrap();
    assert_eq!(entry.epoch, 1);
    assert_eq!(entry.snapshot_hash, hash);
    assert_eq!(entry.snapshot, snap);
}

#[test]
fn baseline_ledger_multiple_records_ascending_epochs() {
    let mut ledger = BaselineLedger::default();
    ledger.record(1, base_snapshot()).unwrap();
    ledger.record(2, candidate_snapshot_pass()).unwrap();
    assert_eq!(ledger.entries.len(), 2);
    assert_eq!(ledger.latest().unwrap().epoch, 2);
}

#[test]
fn baseline_ledger_rejects_equal_epoch() {
    let mut ledger = BaselineLedger::default();
    ledger.record(5, base_snapshot()).unwrap();
    let err = ledger.record(5, candidate_snapshot_pass()).unwrap_err();
    match err {
        BaselineLedgerError::NonMonotonicEpoch {
            previous_epoch,
            next_epoch,
        } => {
            assert_eq!(previous_epoch, 5);
            assert_eq!(next_epoch, 5);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn baseline_ledger_rejects_decreasing_epoch() {
    let mut ledger = BaselineLedger::default();
    ledger.record(10, base_snapshot()).unwrap();
    let err = ledger.record(3, candidate_snapshot_pass()).unwrap_err();
    match err {
        BaselineLedgerError::NonMonotonicEpoch {
            previous_epoch,
            next_epoch,
        } => {
            assert_eq!(previous_epoch, 10);
            assert_eq!(next_epoch, 3);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn baseline_ledger_rejects_duplicate_snapshot_hash() {
    let mut ledger = BaselineLedger::default();
    let snap = base_snapshot();
    ledger.record(1, snap.clone()).unwrap();
    let err = ledger.record(2, snap).unwrap_err();
    assert!(matches!(
        err,
        BaselineLedgerError::DuplicateSnapshotHash { .. }
    ));
}

// ===========================================================================
// evaluate_sibling_integration_benchmark — pass scenario
// ===========================================================================

#[test]
fn gate_passes_for_valid_input() {
    let decision =
        evaluate_sibling_integration_benchmark(&pass_input(), &BenchmarkGateThresholds::default());
    assert!(decision.pass);
    assert!(!decision.rollback_required);
    assert!(decision.findings.is_empty());
}

#[test]
fn gate_pass_has_four_evaluations() {
    let decision =
        evaluate_sibling_integration_benchmark(&pass_input(), &BenchmarkGateThresholds::default());
    assert_eq!(decision.evaluations.len(), 4);
    for eval in &decision.evaluations {
        assert!(eval.pass);
    }
}

#[test]
fn gate_pass_evaluations_contain_all_operations() {
    let decision =
        evaluate_sibling_integration_benchmark(&pass_input(), &BenchmarkGateThresholds::default());
    let ops: BTreeSet<_> = decision.evaluations.iter().map(|e| e.operation).collect();
    assert!(ops.contains(&ControlPlaneOperation::EvidenceWrite));
    assert!(ops.contains(&ControlPlaneOperation::PolicyQuery));
    assert!(ops.contains(&ControlPlaneOperation::TelemetryIngestion));
    assert!(ops.contains(&ControlPlaneOperation::TuiDataUpdate));
}

#[test]
fn gate_pass_decision_id_starts_with_prefix() {
    let decision =
        evaluate_sibling_integration_benchmark(&pass_input(), &BenchmarkGateThresholds::default());
    assert!(
        decision.decision_id.starts_with("sib-bench-gate-"),
        "decision_id should start with sib-bench-gate-: {}",
        decision.decision_id
    );
}

#[test]
fn gate_pass_baseline_and_candidate_hashes() {
    let input = pass_input();
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert_eq!(
        decision.baseline_snapshot_hash,
        input.baseline.snapshot_hash()
    );
    assert_eq!(
        decision.candidate_snapshot_hash,
        input.candidate.snapshot_hash()
    );
}

// ===========================================================================
// evaluate_sibling_integration_benchmark — logs
// ===========================================================================

#[test]
fn gate_pass_emits_five_logs() {
    let decision =
        evaluate_sibling_integration_benchmark(&pass_input(), &BenchmarkGateThresholds::default());
    // 4 operation_slo_check + 1 benchmark_gate_decision
    assert_eq!(decision.logs.len(), 5);
}

#[test]
fn gate_pass_last_log_is_decision_event() {
    let decision =
        evaluate_sibling_integration_benchmark(&pass_input(), &BenchmarkGateThresholds::default());
    let last = decision.logs.last().unwrap();
    assert_eq!(last.event, "benchmark_gate_decision");
    assert_eq!(last.outcome, "pass");
    assert!(last.error_code.is_none());
    assert!(last.operation.is_none());
}

#[test]
fn gate_pass_operation_logs_carry_latency_data() {
    let input = pass_input();
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    for log in &decision.logs[..4] {
        assert_eq!(log.event, "operation_slo_check");
        assert_eq!(log.trace_id, "trace-pass");
        assert_eq!(log.policy_id, "policy-pass");
        assert_eq!(log.component, "sibling_integration_benchmark_gate");
        assert!(log.operation.is_some());
        assert!(log.candidate_p95_ns.is_some());
        assert!(log.candidate_p99_ns.is_some());
        assert!(log.baseline_p95_ns.is_some());
        assert!(log.baseline_p99_ns.is_some());
    }
}

// ===========================================================================
// evaluate_sibling_integration_benchmark — decision_id determinism
// ===========================================================================

#[test]
fn decision_id_deterministic_same_input() {
    let input = pass_input();
    let thresholds = BenchmarkGateThresholds::default();
    let d1 = evaluate_sibling_integration_benchmark(&input, &thresholds);
    let d2 = evaluate_sibling_integration_benchmark(&input, &thresholds);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn decision_id_deterministic_across_sample_reorder() {
    let input_a = pass_input();
    let mut input_b = pass_input();
    let tel = input_b
        .candidate
        .operation_samples
        .get_mut(&ControlPlaneOperation::TelemetryIngestion)
        .unwrap();
    tel.with_integrations_ns.reverse();
    tel.without_integrations_ns.reverse();

    let thresholds = BenchmarkGateThresholds::default();
    let d1 = evaluate_sibling_integration_benchmark(&input_a, &thresholds);
    let d2 = evaluate_sibling_integration_benchmark(&input_b, &thresholds);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn decision_id_differs_for_different_trace_ids() {
    let mut input_a = pass_input();
    input_a.trace_id = "trace-A".to_string();
    let mut input_b = pass_input();
    input_b.trace_id = "trace-B".to_string();

    let thresholds = BenchmarkGateThresholds::default();
    let d1 = evaluate_sibling_integration_benchmark(&input_a, &thresholds);
    let d2 = evaluate_sibling_integration_benchmark(&input_b, &thresholds);
    assert_ne!(d1.decision_id, d2.decision_id);
}

// ===========================================================================
// evaluate — failure: MissingRequiredIntegration
// ===========================================================================

#[test]
fn gate_fails_missing_baseline_integration() {
    let mut baseline = base_snapshot();
    baseline
        .integrations
        .remove(&SiblingIntegration::Frankentui);
    let input = BenchmarkGateInput {
        trace_id: "trace-miss-base".to_string(),
        policy_id: "policy-miss-base".to_string(),
        baseline,
        candidate: candidate_snapshot_pass(),
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.rollback_required);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::MissingRequiredIntegration
            && f.detail.contains("baseline")
            && f.detail.contains("frankentui")
    }));
}

#[test]
fn gate_fails_missing_candidate_integration() {
    let mut candidate = candidate_snapshot_pass();
    candidate
        .integrations
        .remove(&SiblingIntegration::FastapiRust);
    let input = BenchmarkGateInput {
        trace_id: "trace-miss-cand".to_string(),
        policy_id: "policy-miss-cand".to_string(),
        baseline: base_snapshot(),
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::MissingRequiredIntegration
            && f.detail.contains("candidate")
            && f.detail.contains("fastapi_rust")
    }));
}

#[test]
fn gate_fails_missing_both_baseline_and_candidate_integration() {
    let mut baseline = base_snapshot();
    baseline
        .integrations
        .remove(&SiblingIntegration::SqlmodelRust);
    let mut candidate = candidate_snapshot_pass();
    candidate
        .integrations
        .remove(&SiblingIntegration::SqlmodelRust);
    let input = BenchmarkGateInput {
        trace_id: "trace-miss-both".to_string(),
        policy_id: "policy-miss-both".to_string(),
        baseline,
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    let missing_findings: Vec<_> = decision
        .findings
        .iter()
        .filter(|f| f.code == BenchmarkGateFailureCode::MissingRequiredIntegration)
        .collect();
    assert!(missing_findings.len() >= 2);
}

// ===========================================================================
// evaluate — failure: MissingOperationSamples
// ===========================================================================

#[test]
fn gate_fails_missing_operation_from_baseline() {
    let mut baseline = base_snapshot();
    baseline
        .operation_samples
        .remove(&ControlPlaneOperation::PolicyQuery);
    let input = BenchmarkGateInput {
        trace_id: "trace-miss-op".to_string(),
        policy_id: "policy-miss-op".to_string(),
        baseline,
        candidate: candidate_snapshot_pass(),
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::MissingOperationSamples
            && f.operation == Some(ControlPlaneOperation::PolicyQuery)
    }));
}

#[test]
fn gate_fails_missing_operation_from_candidate() {
    let mut candidate = candidate_snapshot_pass();
    candidate
        .operation_samples
        .remove(&ControlPlaneOperation::TuiDataUpdate);
    let input = BenchmarkGateInput {
        trace_id: "trace-miss-op-c".to_string(),
        policy_id: "policy-miss-op-c".to_string(),
        baseline: base_snapshot(),
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::MissingOperationSamples
            && f.operation == Some(ControlPlaneOperation::TuiDataUpdate)
    }));
}

// ===========================================================================
// evaluate — failure: EmptySamples
// ===========================================================================

#[test]
fn gate_fails_empty_candidate_with_integrations() {
    let mut candidate = candidate_snapshot_pass();
    candidate.operation_samples.insert(
        ControlPlaneOperation::EvidenceWrite,
        make_samples(
            &[1_010_000, 1_020_000],
            &[], // empty with_integrations
        ),
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-empty".to_string(),
        policy_id: "policy-empty".to_string(),
        baseline: base_snapshot(),
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::EmptySamples
            && f.operation == Some(ControlPlaneOperation::EvidenceWrite)
    }));
}

#[test]
fn gate_fails_empty_baseline_without_integrations() {
    let mut baseline = base_snapshot();
    baseline.operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        make_samples(
            &[], // empty without_integrations
            &[950_000, 960_000],
        ),
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-empty-base".to_string(),
        policy_id: "policy-empty-base".to_string(),
        baseline,
        candidate: candidate_snapshot_pass(),
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::EmptySamples
            && f.operation == Some(ControlPlaneOperation::PolicyQuery)
    }));
}

// ===========================================================================
// evaluate — failure: SloThresholdExceeded
// ===========================================================================

#[test]
fn gate_fails_slo_p95_exceeded() {
    let mut candidate = candidate_snapshot_pass();
    // PolicyQuery p95 SLO = 3_000_000 ns — push p95 above that
    candidate.operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        make_samples(
            &[810_000, 820_000, 825_000, 830_000, 835_000],
            &[2_900_000, 2_950_000, 3_000_000, 3_100_000, 3_200_000],
        ),
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-slo-p95".to_string(),
        policy_id: "policy-slo-p95".to_string(),
        baseline: base_snapshot(),
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
fn gate_fails_slo_p99_exceeded() {
    // TuiDataUpdate p99 SLO = 12_000_000 ns — push p99 above that
    let mut candidate = candidate_snapshot_pass();
    candidate.operation_samples.insert(
        ControlPlaneOperation::TuiDataUpdate,
        make_samples(
            &[1_210_000, 1_220_000, 1_230_000, 1_235_000, 1_240_000],
            &[6_000_000, 6_500_000, 6_800_000, 7_000_000, 13_000_000],
        ),
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-slo-p99".to_string(),
        policy_id: "policy-slo-p99".to_string(),
        baseline: base_snapshot(),
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::SloThresholdExceeded
            && f.operation == Some(ControlPlaneOperation::TuiDataUpdate)
    }));
}

// ===========================================================================
// evaluate — failure: RegressionThresholdExceeded
// ===========================================================================

#[test]
fn gate_fails_regression_exceeded() {
    // max_regression_millionths = 150_000 → ratio must exceed 1_150_000 ppm
    // baseline PolicyQuery p95 ~ 990_000 (sorted: 950,955,960,980,990 → p95=990_000)
    // candidate needs p95 > 990_000 * 1.15 = 1_138_500
    let mut candidate = candidate_snapshot_pass();
    candidate.operation_samples.insert(
        ControlPlaneOperation::PolicyQuery,
        make_samples(
            &[810_000, 820_000, 825_000, 830_000, 835_000],
            &[1_200_000, 1_210_000, 1_220_000, 1_250_000, 1_300_000],
        ),
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-regress".to_string(),
        policy_id: "policy-regress".to_string(),
        baseline: base_snapshot(),
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == BenchmarkGateFailureCode::RegressionThresholdExceeded
            && f.operation == Some(ControlPlaneOperation::PolicyQuery)
    }));
}

// ===========================================================================
// evaluate — failure: IntegrationOverheadExceeded
// ===========================================================================

#[test]
fn gate_fails_integration_overhead_exceeded() {
    // max_integration_overhead_millionths = 200_000 → overhead must exceed 20%
    // candidate without_integrations TelemetryIngestion: ~940k
    // candidate with_integrations must be > 940_000 * 1.2 = 1_128_000
    let mut candidate = candidate_snapshot_pass();
    candidate.operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        make_samples(
            &[900_000, 910_000, 920_000, 930_000, 940_000],
            &[1_600_000, 1_650_000, 1_700_000, 1_750_000, 1_800_000],
        ),
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-overhead".to_string(),
        policy_id: "policy-overhead".to_string(),
        baseline: base_snapshot(),
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

// ===========================================================================
// evaluate — multiple failures compound
// ===========================================================================

#[test]
fn gate_accumulates_multiple_failure_codes() {
    let mut candidate = candidate_snapshot_pass();
    // Remove an operation entirely → MissingOperationSamples
    candidate
        .operation_samples
        .remove(&ControlPlaneOperation::EvidenceWrite);
    // Remove an integration → MissingRequiredIntegration
    candidate
        .integrations
        .remove(&SiblingIntegration::Frankensqlite);
    // Break overhead on another → IntegrationOverheadExceeded
    candidate.operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        make_samples(
            &[900_000, 910_000, 920_000, 930_000, 940_000],
            &[2_000_000, 2_050_000, 2_100_000, 2_150_000, 2_200_000],
        ),
    );

    let input = BenchmarkGateInput {
        trace_id: "trace-multi".to_string(),
        policy_id: "policy-multi".to_string(),
        baseline: base_snapshot(),
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.rollback_required);

    let codes: BTreeSet<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&BenchmarkGateFailureCode::MissingRequiredIntegration));
    assert!(codes.contains(&BenchmarkGateFailureCode::MissingOperationSamples));
    assert!(codes.contains(&BenchmarkGateFailureCode::IntegrationOverheadExceeded));
}

// ===========================================================================
// evaluate — fail decision log
// ===========================================================================

#[test]
fn gate_fail_decision_log_has_error_code() {
    let mut candidate = candidate_snapshot_pass();
    candidate
        .integrations
        .remove(&SiblingIntegration::Frankentui);
    let input = BenchmarkGateInput {
        trace_id: "trace-fail-log".to_string(),
        policy_id: "policy-fail-log".to_string(),
        baseline: base_snapshot(),
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    assert!(!decision.pass);
    let last = decision.logs.last().unwrap();
    assert_eq!(last.event, "benchmark_gate_decision");
    assert_eq!(last.outcome, "fail");
    assert_eq!(last.error_code.as_deref(), Some("benchmark_gate_failed"));
}

// ===========================================================================
// evaluate — custom thresholds
// ===========================================================================

#[test]
fn gate_passes_with_relaxed_custom_thresholds() {
    // Create very relaxed thresholds that even bad candidates pass
    let mut per_operation = BTreeMap::new();
    for op in [
        ControlPlaneOperation::EvidenceWrite,
        ControlPlaneOperation::PolicyQuery,
        ControlPlaneOperation::TelemetryIngestion,
        ControlPlaneOperation::TuiDataUpdate,
    ] {
        per_operation.insert(
            op,
            OperationSloThreshold {
                p95_ns: 100_000_000,                            // 100ms
                p99_ns: 200_000_000,                            // 200ms
                max_regression_millionths: 5_000_000,           // 500%
                max_integration_overhead_millionths: 5_000_000, // 500%
            },
        );
    }
    let thresholds = BenchmarkGateThresholds {
        required_integrations: full_integrations(),
        per_operation,
    };
    let decision = evaluate_sibling_integration_benchmark(&pass_input(), &thresholds);
    assert!(decision.pass);
}

#[test]
fn gate_fails_with_tight_custom_thresholds() {
    // Create impossibly tight thresholds
    let mut per_operation = BTreeMap::new();
    for op in [
        ControlPlaneOperation::EvidenceWrite,
        ControlPlaneOperation::PolicyQuery,
        ControlPlaneOperation::TelemetryIngestion,
        ControlPlaneOperation::TuiDataUpdate,
    ] {
        per_operation.insert(
            op,
            OperationSloThreshold {
                p95_ns: 1, // 1ns — impossible to meet
                p99_ns: 1,
                max_regression_millionths: 0,
                max_integration_overhead_millionths: 0,
            },
        );
    }
    let thresholds = BenchmarkGateThresholds {
        required_integrations: full_integrations(),
        per_operation,
    };
    let decision = evaluate_sibling_integration_benchmark(&pass_input(), &thresholds);
    assert!(!decision.pass);
    assert!(decision.rollback_required);
}

// ===========================================================================
// evaluate — empty thresholds (no required integrations, no operations)
// ===========================================================================

#[test]
fn gate_passes_with_empty_thresholds() {
    let thresholds = BenchmarkGateThresholds {
        required_integrations: BTreeSet::new(),
        per_operation: BTreeMap::new(),
    };
    let decision = evaluate_sibling_integration_benchmark(&pass_input(), &thresholds);
    assert!(decision.pass);
    assert!(decision.findings.is_empty());
    assert!(decision.evaluations.is_empty());
    // Should still have the final decision log
    assert_eq!(decision.logs.len(), 1);
    assert_eq!(decision.logs[0].event, "benchmark_gate_decision");
}

// ===========================================================================
// evaluate — operation evaluation fields are populated correctly
// ===========================================================================

#[test]
fn operation_evaluation_fields_populated() {
    let decision =
        evaluate_sibling_integration_benchmark(&pass_input(), &BenchmarkGateThresholds::default());
    let ev_write = decision
        .evaluations
        .iter()
        .find(|e| e.operation == ControlPlaneOperation::EvidenceWrite)
        .expect("should have EvidenceWrite evaluation");

    assert!(ev_write.pass);
    assert!(ev_write.baseline_p95_ns > 0);
    assert!(ev_write.baseline_p99_ns > 0);
    assert!(ev_write.candidate_p95_ns > 0);
    assert!(ev_write.candidate_p99_ns > 0);
    assert!(ev_write.candidate_without_integrations_p95_ns > 0);
    assert!(ev_write.candidate_without_integrations_p99_ns > 0);
    // p99 should be >= p95
    assert!(ev_write.baseline_p99_ns >= ev_write.baseline_p95_ns);
    assert!(ev_write.candidate_p99_ns >= ev_write.candidate_p95_ns);
}

// ===========================================================================
// evaluate — operation logs for failures carry error_code
// ===========================================================================

#[test]
fn operation_fail_log_carries_error_code() {
    let mut candidate = candidate_snapshot_pass();
    candidate.operation_samples.insert(
        ControlPlaneOperation::TelemetryIngestion,
        make_samples(
            &[900_000, 910_000, 920_000, 930_000, 940_000],
            &[1_600_000, 1_650_000, 1_700_000, 1_750_000, 1_800_000],
        ),
    );
    let input = BenchmarkGateInput {
        trace_id: "trace-op-fail-log".to_string(),
        policy_id: "policy-op-fail-log".to_string(),
        baseline: base_snapshot(),
        candidate,
    };
    let decision =
        evaluate_sibling_integration_benchmark(&input, &BenchmarkGateThresholds::default());
    // Find the log for TelemetryIngestion
    let tel_log = decision
        .logs
        .iter()
        .find(|l| l.operation.as_deref() == Some("telemetry_ingestion"))
        .expect("should have telemetry log");
    assert_eq!(tel_log.outcome, "fail");
    assert!(tel_log.error_code.is_some());
}

// ===========================================================================
// Ordering impls
// ===========================================================================

#[test]
fn sibling_integration_ord_is_consistent() {
    let mut v = [
        SiblingIntegration::FastapiRust,
        SiblingIntegration::Frankentui,
        SiblingIntegration::SqlmodelRust,
        SiblingIntegration::Frankensqlite,
    ];
    v.sort();
    // Derive order follows variant declaration order
    assert_eq!(v[0], SiblingIntegration::Frankentui);
    assert_eq!(v[1], SiblingIntegration::Frankensqlite);
    assert_eq!(v[2], SiblingIntegration::SqlmodelRust);
    assert_eq!(v[3], SiblingIntegration::FastapiRust);
}

#[test]
fn control_plane_operation_ord_is_consistent() {
    let mut v = [
        ControlPlaneOperation::TuiDataUpdate,
        ControlPlaneOperation::EvidenceWrite,
        ControlPlaneOperation::TelemetryIngestion,
        ControlPlaneOperation::PolicyQuery,
    ];
    v.sort();
    assert_eq!(v[0], ControlPlaneOperation::EvidenceWrite);
    assert_eq!(v[1], ControlPlaneOperation::PolicyQuery);
    assert_eq!(v[2], ControlPlaneOperation::TelemetryIngestion);
    assert_eq!(v[3], ControlPlaneOperation::TuiDataUpdate);
}

#[test]
fn failure_code_ord_is_consistent() {
    let mut v = [
        BenchmarkGateFailureCode::IntegrationOverheadExceeded,
        BenchmarkGateFailureCode::MissingRequiredIntegration,
        BenchmarkGateFailureCode::SloThresholdExceeded,
        BenchmarkGateFailureCode::EmptySamples,
        BenchmarkGateFailureCode::RegressionThresholdExceeded,
        BenchmarkGateFailureCode::MissingOperationSamples,
    ];
    v.sort();
    assert_eq!(v[0], BenchmarkGateFailureCode::MissingRequiredIntegration);
    assert_eq!(v[1], BenchmarkGateFailureCode::MissingOperationSamples);
    assert_eq!(v[2], BenchmarkGateFailureCode::EmptySamples);
    assert_eq!(v[3], BenchmarkGateFailureCode::SloThresholdExceeded);
    assert_eq!(v[4], BenchmarkGateFailureCode::RegressionThresholdExceeded);
    assert_eq!(v[5], BenchmarkGateFailureCode::IntegrationOverheadExceeded);
}
