//! Integration tests for the specialization_lane_gate module.
//!
//! Validates dual-lane gate evaluation, receipt coverage audit, fallback
//! injection testing, performance delta computation, structured logging,
//! and release gate decision from a pure external API perspective.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::specialization_lane_gate::{
    DEFAULT_SIGNIFICANCE_THRESHOLD_MILLIONTHS, FallbackTestResult, GATE_COMPONENT,
    GATE_SCHEMA_VERSION, GateBlocker, GateError, GateEvidenceBundle, GateInput, GateLogEntry,
    GateOutcome, InjectionKind, LaneType, MIN_SAMPLE_COUNT, MIN_WORKLOAD_COUNT, PerformanceDelta,
    REQUIRED_COVERAGE_MILLIONTHS, ReceiptRef, WorkloadMetrics, evaluate_gate, generate_log_entries,
    passes_release_gate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn digest(s: &str) -> ContentHash {
    ContentHash::compute(s.as_bytes())
}

fn metrics(
    id: &str,
    lane: LaneType,
    throughput: u64,
    latency_p95: u64,
    memory: u64,
    dig: &str,
) -> WorkloadMetrics {
    WorkloadMetrics {
        workload_id: id.to_string(),
        lane_type: lane,
        output_digest: digest(dig),
        throughput_ops_per_sec: throughput,
        latency_p50_ns: latency_p95 / 2,
        latency_p95_ns: latency_p95,
        latency_p99_ns: latency_p95 * 2,
        memory_peak_bytes: memory,
        sample_count: 10,
    }
}

fn receipt(id: &str, verified: bool) -> ReceiptRef {
    ReceiptRef {
        receipt_id: id.to_string(),
        optimization_class: "hostcall_dispatch".to_string(),
        receipt_hash: digest(id),
        signature_verified: verified,
        issued_epoch: SecurityEpoch::from_raw(1),
    }
}

fn fallback_pass(workload_id: &str, kind: InjectionKind) -> FallbackTestResult {
    let d = digest("canonical_output");
    FallbackTestResult {
        workload_id: workload_id.to_string(),
        injection_kind: kind,
        correct_output: true,
        fallback_receipt_emitted: true,
        crash_or_hang: false,
        fallback_output_digest: d.clone(),
        expected_output_digest: d,
        fallback_latency_ns: 1000,
        ambient_latency_ns: 1000,
    }
}

fn fallback_fail(workload_id: &str, kind: InjectionKind) -> FallbackTestResult {
    FallbackTestResult {
        workload_id: workload_id.to_string(),
        injection_kind: kind,
        correct_output: false,
        fallback_receipt_emitted: true,
        crash_or_hang: false,
        fallback_output_digest: digest("wrong"),
        expected_output_digest: digest("canonical_output"),
        fallback_latency_ns: 1000,
        ambient_latency_ns: 1000,
    }
}

fn spec_metrics(n: usize) -> Vec<WorkloadMetrics> {
    (0..n)
        .map(|i| {
            metrics(
                &format!("w{i}"),
                LaneType::ProofSpecialized,
                1200,
                800,
                4000,
                "out",
            )
        })
        .collect()
}

fn amb_metrics(n: usize) -> Vec<WorkloadMetrics> {
    (0..n)
        .map(|i| {
            metrics(
                &format!("w{i}"),
                LaneType::AmbientAuthority,
                1000,
                1000,
                5000,
                "out",
            )
        })
        .collect()
}

fn receipts(n: u64) -> Vec<ReceiptRef> {
    (0..n).map(|i| receipt(&format!("r{i}"), true)).collect()
}

fn fallbacks() -> Vec<FallbackTestResult> {
    vec![
        fallback_pass("w0", InjectionKind::ProofFailure),
        fallback_pass("w1", InjectionKind::CapabilityRevocation),
        fallback_pass("w2", InjectionKind::EpochTransition),
        fallback_pass("w3", InjectionKind::ProofExpiry),
    ]
}

fn passing_input<'a>(
    spec: &'a [WorkloadMetrics],
    amb: &'a [WorkloadMetrics],
    rcpts: &'a [ReceiptRef],
    fbs: &'a [FallbackTestResult],
) -> GateInput<'a> {
    GateInput {
        run_id: "run-1",
        trace_id: "trace-001",
        epoch: SecurityEpoch::from_raw(1),
        specialized_metrics: spec,
        ambient_metrics: amb,
        receipts: rcpts,
        total_specialization_decisions: rcpts.len() as u64,
        fallback_results: fbs,
        significance_threshold_millionths: DEFAULT_SIGNIFICANCE_THRESHOLD_MILLIONTHS,
    }
}

// ---------------------------------------------------------------------------
// Full passing gate
// ---------------------------------------------------------------------------

#[test]
fn gate_passes_all_criteria() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(result.outcome.is_pass());
    assert!(result.blockers.is_empty());
    assert_eq!(result.workload_count, 12);
    assert_eq!(result.schema_version, GATE_SCHEMA_VERSION);
    assert_eq!(result.run_id, "run-1");
    assert_eq!(result.epoch, SecurityEpoch::from_raw(1));
    assert!(result.summary.mean_throughput_delta_millionths > 0);
    assert_eq!(
        result.receipt_coverage.coverage_millionths,
        REQUIRED_COVERAGE_MILLIONTHS
    );
}

#[test]
fn gate_deterministic_evidence_hash() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);

    let r1 = evaluate_gate(&input).unwrap();
    let r2 = evaluate_gate(&input).unwrap();
    assert_eq!(r1.evidence_hash, r2.evidence_hash);
}

#[test]
fn gate_different_run_ids_different_hashes() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();

    let input1 = passing_input(&s, &a, &r, &f);
    let input2 = GateInput {
        run_id: "run-2",
        ..input1.clone()
    };

    let r1 = evaluate_gate(&input1).unwrap();
    let r2 = evaluate_gate(&input2).unwrap();
    assert_ne!(r1.evidence_hash, r2.evidence_hash);
}

// ---------------------------------------------------------------------------
// Gate failure modes
// ---------------------------------------------------------------------------

#[test]
fn gate_error_empty_workloads() {
    let input = GateInput {
        run_id: "empty",
        trace_id: "t1",
        epoch: SecurityEpoch::from_raw(1),
        specialized_metrics: &[],
        ambient_metrics: &[],
        receipts: &[],
        total_specialization_decisions: 0,
        fallback_results: &[],
        significance_threshold_millionths: 0,
    };
    assert!(matches!(
        evaluate_gate(&input),
        Err(GateError::EmptyWorkloads)
    ));
}

#[test]
fn gate_fails_insufficient_workloads() {
    let s = spec_metrics(3);
    let a = amb_metrics(3);
    let r = receipts(3);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::InsufficientWorkloads {
            required,
            actual,
        } if *required == MIN_WORKLOAD_COUNT && *actual == 3
    )));
}

#[test]
fn gate_fails_output_divergence() {
    let mut s = spec_metrics(12);
    s[0].output_digest = digest("different");
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(
        result
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::OutputDivergence { .. }))
    );
}

#[test]
fn gate_fails_no_positive_delta() {
    let s: Vec<WorkloadMetrics> = (0..12)
        .map(|i| {
            metrics(
                &format!("w{i}"),
                LaneType::ProofSpecialized,
                1000,
                1000,
                5000,
                "out",
            )
        })
        .collect();
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(
        result
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::NoPositiveDelta { .. }))
    );
}

#[test]
fn gate_fails_insufficient_receipt_coverage() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(3);
    let f = fallbacks();
    let input = GateInput {
        run_id: "low-cov",
        trace_id: "t1",
        epoch: SecurityEpoch::from_raw(1),
        specialized_metrics: &s,
        ambient_metrics: &a,
        receipts: &r,
        total_specialization_decisions: 10, // 3/10 = 30%
        fallback_results: &f,
        significance_threshold_millionths: 0,
    };
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(
        result
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::InsufficientReceiptCoverage { .. }))
    );
}

#[test]
fn gate_fails_unverified_receipt() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let mut r = receipts(5);
    r[2].signature_verified = false;
    let f = fallbacks();
    let input = GateInput {
        run_id: "unver",
        trace_id: "t1",
        epoch: SecurityEpoch::from_raw(1),
        specialized_metrics: &s,
        ambient_metrics: &a,
        receipts: &r,
        total_specialization_decisions: 5,
        fallback_results: &f,
        significance_threshold_millionths: 0,
    };
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(
        result
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::UnverifiedReceipt { .. }))
    );
}

#[test]
fn gate_fails_fallback_test_incorrect_output() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = vec![
        fallback_pass("w0", InjectionKind::ProofFailure),
        fallback_fail("w1", InjectionKind::CapabilityRevocation),
    ];
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(
        result
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::FallbackTestFailed { .. }))
    );
}

#[test]
fn gate_fails_fallback_performance_regression() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let mut fb = fallback_pass("w0", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 1000;
    fb.fallback_latency_ns = 2000; // 100% slower
    let f = vec![fb];
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(
        result
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::FallbackPerformanceRegression { .. }))
    );
}

#[test]
fn gate_fails_workload_mismatch() {
    let mut s = spec_metrics(12);
    s[0].workload_id = "orphan_workload".to_string();
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(
        result
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::WorkloadMismatch { .. }))
    );
}

#[test]
fn gate_fails_insufficient_samples() {
    let mut s = spec_metrics(12);
    s[0].sample_count = 2; // below MIN_SAMPLE_COUNT
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(result.blockers.iter().any(|b| matches!(
        b,
        GateBlocker::InsufficientSamples { sample_count, .. } if *sample_count == 2
    )));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn gate_zero_specialization_decisions_vacuous_coverage() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let f = fallbacks();
    let input = GateInput {
        run_id: "vacuous",
        trace_id: "t1",
        epoch: SecurityEpoch::from_raw(1),
        specialized_metrics: &s,
        ambient_metrics: &a,
        receipts: &[],
        total_specialization_decisions: 0,
        fallback_results: &f,
        significance_threshold_millionths: 0,
    };
    let result = evaluate_gate(&input).unwrap();
    assert_eq!(
        result.receipt_coverage.coverage_millionths,
        REQUIRED_COVERAGE_MILLIONTHS
    );
}

#[test]
fn gate_significance_threshold_blocks_marginal_improvement() {
    // 1% improvement, but threshold requires 5%.
    let s: Vec<WorkloadMetrics> = (0..12)
        .map(|i| {
            metrics(
                &format!("w{i}"),
                LaneType::ProofSpecialized,
                1010,
                990,
                4950,
                "out",
            )
        })
        .collect();
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = GateInput {
        run_id: "marginal",
        trace_id: "t1",
        epoch: SecurityEpoch::from_raw(1),
        specialized_metrics: &s,
        ambient_metrics: &a,
        receipts: &r,
        total_specialization_decisions: 5,
        fallback_results: &f,
        significance_threshold_millionths: 50_000, // 5%
    };
    let result = evaluate_gate(&input).unwrap();
    assert!(!result.outcome.is_pass());
    assert!(
        result
            .blockers
            .iter()
            .any(|b| matches!(b, GateBlocker::NoPositiveDelta { .. }))
    );
}

#[test]
fn gate_multiple_blockers_accumulated() {
    // Too few workloads AND incorrect output.
    let mut s = spec_metrics(3);
    s[0].output_digest = digest("different");
    let a = amb_metrics(3);
    let r = receipts(3);
    let f = vec![fallback_fail("w0", InjectionKind::ProofFailure)];
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    assert!(!result.outcome.is_pass());
    assert!(
        result.blockers.len() >= 2,
        "should accumulate multiple blockers"
    );
}

// ---------------------------------------------------------------------------
// PerformanceDelta
// ---------------------------------------------------------------------------

#[test]
fn delta_compute_positive_all_dimensions() {
    let spec = metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out");
    let amb = metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);

    assert_eq!(delta.throughput_delta_millionths, 200_000);
    assert_eq!(delta.latency_p95_improvement_millionths, 200_000);
    assert_eq!(delta.memory_improvement_millionths, 200_000);
    assert!(delta.has_positive_delta());
    assert!(delta.output_equivalent);
}

#[test]
fn delta_compute_negative_throughput() {
    let spec = metrics("w1", LaneType::ProofSpecialized, 800, 1200, 6000, "out");
    let amb = metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.throughput_delta_millionths, -200_000);
}

#[test]
fn delta_zero_ambient_no_panic() {
    let spec = metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out");
    let amb = metrics("w1", LaneType::AmbientAuthority, 0, 0, 0, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert_eq!(delta.throughput_delta_millionths, 0);
    assert_eq!(delta.latency_p95_improvement_millionths, 0);
    assert_eq!(delta.memory_improvement_millionths, 0);
}

#[test]
fn delta_output_divergence_detected() {
    let spec = metrics("w1", LaneType::ProofSpecialized, 1200, 800, 4000, "out_a");
    let amb = metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out_b");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert!(!delta.output_equivalent);
}

#[test]
fn delta_neutral_not_positive() {
    let spec = metrics("w1", LaneType::ProofSpecialized, 1000, 1000, 5000, "out");
    let amb = metrics("w1", LaneType::AmbientAuthority, 1000, 1000, 5000, "out");
    let delta = PerformanceDelta::compute(&spec, &amb);
    assert!(!delta.has_positive_delta());
}

// ---------------------------------------------------------------------------
// FallbackTestResult
// ---------------------------------------------------------------------------

#[test]
fn fallback_pass_all_criteria() {
    let fb = fallback_pass("w1", InjectionKind::ProofFailure);
    assert!(fb.passed());
    assert!(!fb.performance_regressed());
}

#[test]
fn fallback_fail_incorrect_output() {
    let fb = fallback_fail("w1", InjectionKind::ProofFailure);
    assert!(!fb.passed());
}

#[test]
fn fallback_fail_crash() {
    let mut fb = fallback_pass("w1", InjectionKind::ProofFailure);
    fb.crash_or_hang = true;
    assert!(!fb.passed());
}

#[test]
fn fallback_fail_no_receipt_emitted() {
    let mut fb = fallback_pass("w1", InjectionKind::ProofFailure);
    fb.fallback_receipt_emitted = false;
    assert!(!fb.passed());
}

#[test]
fn fallback_fail_digest_mismatch() {
    let mut fb = fallback_pass("w1", InjectionKind::ProofFailure);
    fb.fallback_output_digest = digest("different");
    assert!(!fb.passed());
}

#[test]
fn fallback_performance_regression_above_threshold() {
    let mut fb = fallback_pass("w1", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 1000;
    fb.fallback_latency_ns = 1200; // 20% > 10% threshold
    assert!(fb.performance_regressed());
}

#[test]
fn fallback_performance_within_threshold() {
    let mut fb = fallback_pass("w1", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 1000;
    fb.fallback_latency_ns = 1050; // 5% < 10% threshold
    assert!(!fb.performance_regressed());
}

#[test]
fn fallback_zero_ambient_no_regression() {
    let mut fb = fallback_pass("w1", InjectionKind::ProofFailure);
    fb.ambient_latency_ns = 0;
    fb.fallback_latency_ns = 1000;
    assert!(!fb.performance_regressed());
}

// ---------------------------------------------------------------------------
// passes_release_gate
// ---------------------------------------------------------------------------

#[test]
fn release_gate_pass() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();
    assert!(passes_release_gate(&result));
}

#[test]
fn release_gate_fail() {
    let s = spec_metrics(3);
    let a = amb_metrics(3);
    let r = receipts(3);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();
    assert!(!passes_release_gate(&result));
}

// ---------------------------------------------------------------------------
// generate_log_entries
// ---------------------------------------------------------------------------

#[test]
fn log_entries_summary_for_passing_gate() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-1", &result);

    assert!(!entries.is_empty());
    let summary = &entries[0];
    assert_eq!(summary.event, "gate_evaluation_complete");
    assert_eq!(summary.outcome, "PASS");
    assert_eq!(summary.component, GATE_COMPONENT);
    assert!(summary.error_code.is_none());
}

#[test]
fn log_entries_per_workload_deltas() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-1", &result);

    let delta_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.event == "workload_delta")
        .collect();
    assert_eq!(delta_entries.len(), 12);
    for de in &delta_entries {
        assert_eq!(de.lane_type, Some(LaneType::ProofSpecialized));
        assert!(de.workload_id.is_some());
    }
}

#[test]
fn log_entries_fallback_tests() {
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-1", &result);

    let fb_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.event.starts_with("fallback_test_"))
        .collect();
    assert_eq!(fb_entries.len(), 4);
    for fe in &fb_entries {
        assert_eq!(fe.lane_type, Some(LaneType::Fallback));
        assert_eq!(fe.fallback_triggered, Some(true));
    }
}

#[test]
fn log_entries_failure_has_error_code() {
    let s = spec_metrics(3);
    let a = amb_metrics(3);
    let r = receipts(3);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();
    let entries = generate_log_entries("trace-1", &result);

    assert_eq!(entries[0].error_code, Some("GATE_FAILED".to_string()));
}

// ---------------------------------------------------------------------------
// Enum Display / Serde
// ---------------------------------------------------------------------------

#[test]
fn lane_type_as_str_and_display() {
    assert_eq!(LaneType::ProofSpecialized.as_str(), "proof_specialized");
    assert_eq!(LaneType::AmbientAuthority.as_str(), "ambient_authority");
    assert_eq!(LaneType::Fallback.as_str(), "fallback");
    assert_eq!(
        format!("{}", LaneType::ProofSpecialized),
        "proof_specialized"
    );
}

#[test]
fn lane_type_ordering() {
    assert!(LaneType::ProofSpecialized < LaneType::AmbientAuthority);
    assert!(LaneType::AmbientAuthority < LaneType::Fallback);
}

#[test]
fn injection_kind_all_variants() {
    assert_eq!(InjectionKind::all().len(), 4);
}

#[test]
fn injection_kind_as_str_and_display() {
    assert_eq!(InjectionKind::ProofFailure.as_str(), "proof_failure");
    assert_eq!(format!("{}", InjectionKind::ProofExpiry), "proof_expiry");
}

#[test]
fn gate_outcome_display() {
    assert_eq!(format!("{}", GateOutcome::Pass), "PASS");
    assert_eq!(format!("{}", GateOutcome::Fail), "FAIL");
    assert!(GateOutcome::Pass.is_pass());
    assert!(!GateOutcome::Fail.is_pass());
}

#[test]
fn gate_error_display_all() {
    let errors: Vec<GateError> = vec![
        GateError::EmptyWorkloads,
        GateError::WorkloadSetMismatch {
            detail: "test".to_string(),
        },
        GateError::EmptyReceipts,
        GateError::InvalidMetric {
            workload_id: "w1".to_string(),
            detail: "neg".to_string(),
        },
    ];
    for e in &errors {
        assert!(!format!("{e}").is_empty());
    }
}

#[test]
fn gate_blocker_display_all() {
    let blockers: Vec<GateBlocker> = vec![
        GateBlocker::InsufficientWorkloads {
            required: 10,
            actual: 3,
        },
        GateBlocker::OutputDivergence {
            workload_id: "w1".to_string(),
        },
        GateBlocker::InsufficientReceiptCoverage {
            coverage_millionths: 500_000,
        },
        GateBlocker::UnverifiedReceipt {
            receipt_id: "r1".to_string(),
        },
        GateBlocker::NoPositiveDelta {
            mean_throughput_delta_millionths: -100_000,
        },
        GateBlocker::FallbackTestFailed {
            workload_id: "w1".to_string(),
            injection_kind: InjectionKind::ProofFailure,
            reason: "crash".to_string(),
        },
        GateBlocker::FallbackPerformanceRegression {
            workload_id: "w1".to_string(),
            injection_kind: InjectionKind::ProofExpiry,
        },
        GateBlocker::InsufficientSamples {
            workload_id: "w1".to_string(),
            lane_type: LaneType::ProofSpecialized,
            sample_count: 2,
        },
        GateBlocker::WorkloadMismatch {
            missing_workload_ids: vec!["w99".to_string()],
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
    let s = spec_metrics(12);
    let a = amb_metrics(12);
    let r = receipts(5);
    let f = fallbacks();
    let input = passing_input(&s, &a, &r, &f);
    let result = evaluate_gate(&input).unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let back: GateEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn serde_lane_type_roundtrip() {
    for lt in &[
        LaneType::ProofSpecialized,
        LaneType::AmbientAuthority,
        LaneType::Fallback,
    ] {
        let json = serde_json::to_string(lt).unwrap();
        let back: LaneType = serde_json::from_str(&json).unwrap();
        assert_eq!(*lt, back);
    }
}

#[test]
fn serde_gate_outcome_roundtrip() {
    for o in &[GateOutcome::Pass, GateOutcome::Fail] {
        let json = serde_json::to_string(o).unwrap();
        let back: GateOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

#[test]
fn serde_fallback_result_roundtrip() {
    let fb = fallback_pass("w1", InjectionKind::ProofFailure);
    let json = serde_json::to_string(&fb).unwrap();
    let back: FallbackTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

#[test]
fn serde_blocker_roundtrip() {
    let b = GateBlocker::OutputDivergence {
        workload_id: "w1".to_string(),
    };
    let json = serde_json::to_string(&b).unwrap();
    let back: GateBlocker = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn serde_error_roundtrip() {
    let e = GateError::EmptyWorkloads;
    let json = serde_json::to_string(&e).unwrap();
    let back: GateError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn serde_log_entry_roundtrip() {
    let entry = GateLogEntry {
        trace_id: "t1".to_string(),
        component: GATE_COMPONENT.to_string(),
        lane_type: Some(LaneType::ProofSpecialized),
        event: "test".to_string(),
        outcome: "pass".to_string(),
        workload_id: Some("w1".to_string()),
        optimization_pass: None,
        proof_status: None,
        capability_witness_ref: None,
        specialization_receipt_hash: None,
        fallback_triggered: Some(false),
        wall_time_ns: Some(1000),
        memory_peak_bytes: None,
        error_code: None,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: GateLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_stable() {
    assert_eq!(MIN_WORKLOAD_COUNT, 10);
    assert_eq!(MIN_SAMPLE_COUNT, 5);
    assert_eq!(REQUIRED_COVERAGE_MILLIONTHS, 1_000_000);
    assert_eq!(GATE_COMPONENT, "specialization_lane_gate");
    assert!(GATE_SCHEMA_VERSION.contains("specialization-lane-gate"));
}
