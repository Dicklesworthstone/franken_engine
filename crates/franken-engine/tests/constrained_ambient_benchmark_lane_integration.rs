#![forbid(unsafe_code)]

//! Comprehensive integration tests for `constrained_ambient_benchmark_lane`.
//!
//! Exercises the public API from outside the crate boundary covering:
//! - Public constants
//! - All public structs: construction, field access, Clone, Eq, serde roundtrip
//! - Error type: Display, stable_code, std::error::Error
//! - `run_constrained_ambient_benchmark_lane`: happy path, validation errors,
//!   digest mismatch, performance regression, attribution gap, proof expiry,
//!   proof revocation, optimization class mismatch, conflicting claims,
//!   multi-workload, report ordering, report_id determinism, event structure
//! - `allows_publication` method
//! - Serde defaults on `ProofAttributionSample`
//! - Edge cases: whitespace-only fields, zero metrics, duplicate workloads,
//!   duplicate proof/spec pairs, empty proof attribution vec, rollback tokens

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

use frankenengine_engine::constrained_ambient_benchmark_lane::{
    CONSTRAINED_AMBIENT_COMPONENT, CONSTRAINED_AMBIENT_SCHEMA_VERSION,
    ConstrainedAmbientBenchmarkDecision, ConstrainedAmbientBenchmarkRequest,
    ConstrainedAmbientEvent, ConstrainedAmbientSummary, LaneWorkloadMetrics,
    ProofAttributionReport, ProofAttributionSample, WorkloadDeltaReport,
    run_constrained_ambient_benchmark_lane,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_workload(id: &str, throughput: u64, latency_p50: u64) -> LaneWorkloadMetrics {
    LaneWorkloadMetrics {
        workload_id: id.into(),
        output_digest: format!("digest-{id}"),
        throughput_ops_per_sec: throughput,
        latency_p50_ns: latency_p50,
        latency_p95_ns: latency_p50 * 2,
        latency_p99_ns: latency_p50 * 4,
        memory_peak_bytes: 1_000_000,
        allocation_count: 500,
    }
}

fn make_attribution(proof_id: &str, spec_id: &str) -> ProofAttributionSample {
    ProofAttributionSample {
        proof_id: proof_id.into(),
        specialization_id: spec_id.into(),
        optimization_class: "ifc_check_elision".into(),
        validated_optimization_class: "ifc_check_elision".into(),
        constrained_throughput_ops_per_sec: 2000,
        without_proof_throughput_ops_per_sec: 1000,
        constrained_latency_p95_ns: 500,
        without_proof_latency_p95_ns: 1000,
        validity_epoch: Some(10),
        evaluation_epoch: Some(10),
        rollback_token: Some(format!("rollback-{proof_id}-{spec_id}")),
        revoked: false,
    }
}

fn valid_request() -> ConstrainedAmbientBenchmarkRequest {
    ConstrainedAmbientBenchmarkRequest {
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        benchmark_run_id: "run-1".into(),
        constrained_lane: vec![make_workload("w1", 2000, 500)],
        ambient_lane: vec![make_workload("w1", 1000, 1000)],
        proof_attribution: vec![make_attribution("proof-1", "spec-1")],
    }
}

// ---------------------------------------------------------------------------
// 1. Public constants
// ---------------------------------------------------------------------------

#[test]
fn constant_component_is_non_empty() {
    assert!(!CONSTRAINED_AMBIENT_COMPONENT.is_empty());
    assert_eq!(
        CONSTRAINED_AMBIENT_COMPONENT,
        "constrained_ambient_benchmark_lane"
    );
}

#[test]
fn constant_schema_version_is_non_empty() {
    assert!(!CONSTRAINED_AMBIENT_SCHEMA_VERSION.is_empty());
    assert_eq!(
        CONSTRAINED_AMBIENT_SCHEMA_VERSION,
        "franken-engine.constrained-ambient-lane.v1"
    );
}

// ---------------------------------------------------------------------------
// 2. Struct construction, field access, Clone, Eq
// ---------------------------------------------------------------------------

#[test]
fn lane_workload_metrics_construction_and_fields() {
    let m = make_workload("w1", 5000, 250);
    assert_eq!(m.workload_id, "w1");
    assert_eq!(m.output_digest, "digest-w1");
    assert_eq!(m.throughput_ops_per_sec, 5000);
    assert_eq!(m.latency_p50_ns, 250);
    assert_eq!(m.latency_p95_ns, 500);
    assert_eq!(m.latency_p99_ns, 1000);
    assert_eq!(m.memory_peak_bytes, 1_000_000);
    assert_eq!(m.allocation_count, 500);
}

#[test]
fn lane_workload_metrics_clone_eq() {
    let a = make_workload("w1", 100, 50);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn proof_attribution_sample_construction_and_fields() {
    let s = make_attribution("p1", "s1");
    assert_eq!(s.proof_id, "p1");
    assert_eq!(s.specialization_id, "s1");
    assert_eq!(s.optimization_class, "ifc_check_elision");
    assert_eq!(s.validated_optimization_class, "ifc_check_elision");
    assert_eq!(s.constrained_throughput_ops_per_sec, 2000);
    assert_eq!(s.without_proof_throughput_ops_per_sec, 1000);
    assert_eq!(s.constrained_latency_p95_ns, 500);
    assert_eq!(s.without_proof_latency_p95_ns, 1000);
    assert_eq!(s.validity_epoch, Some(10));
    assert_eq!(s.evaluation_epoch, Some(10));
    assert!(s.rollback_token.is_some());
    assert!(!s.revoked);
}

#[test]
fn proof_attribution_sample_clone_eq() {
    let a = make_attribution("p1", "s1");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn workload_delta_report_clone_eq() {
    let a = WorkloadDeltaReport {
        workload_id: "w1".into(),
        canonical_output_digest: "d".into(),
        throughput_delta_millionths: 500_000,
        latency_p50_improvement_millionths: 300_000,
        latency_p95_improvement_millionths: 200_000,
        latency_p99_improvement_millionths: 100_000,
        memory_improvement_millionths: 50_000,
        allocation_improvement_millionths: 25_000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn proof_attribution_report_clone_eq() {
    let a = ProofAttributionReport {
        proof_id: "p".into(),
        specialization_id: "s".into(),
        throughput_gain_millionths: 100_000,
        latency_p95_improvement_millionths: 50_000,
        supports_uplift: true,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn constrained_ambient_summary_clone_eq() {
    let a = ConstrainedAmbientSummary {
        workload_count: 3,
        attribution_count: 2,
        mean_throughput_delta_millionths: 500_000,
        mean_latency_p95_improvement_millionths: 200_000,
        mean_memory_improvement_millionths: 100_000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn constrained_ambient_event_clone_eq() {
    let a = ConstrainedAmbientEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: Some("FE-CABL-1001".into()),
        workload_id: Some("w1".into()),
        proof_id: None,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn constrained_ambient_benchmark_decision_clone_eq() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    let dec2 = dec.clone();
    assert_eq!(dec, dec2);
}

// ---------------------------------------------------------------------------
// 3. Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_lane_workload_metrics() {
    let m = make_workload("w1", 100, 50);
    let json = serde_json::to_string(&m).unwrap();
    let back: LaneWorkloadMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn serde_roundtrip_proof_attribution_sample() {
    let s = make_attribution("p1", "s1");
    let json = serde_json::to_string(&s).unwrap();
    let back: ProofAttributionSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn serde_roundtrip_workload_delta_report() {
    let r = WorkloadDeltaReport {
        workload_id: "w".into(),
        canonical_output_digest: "d".into(),
        throughput_delta_millionths: -123_456,
        latency_p50_improvement_millionths: 200,
        latency_p95_improvement_millionths: 300,
        latency_p99_improvement_millionths: 400,
        memory_improvement_millionths: 500,
        allocation_improvement_millionths: 600,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: WorkloadDeltaReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn serde_roundtrip_proof_attribution_report() {
    let r = ProofAttributionReport {
        proof_id: "p".into(),
        specialization_id: "s".into(),
        throughput_gain_millionths: 100_000,
        latency_p95_improvement_millionths: 50_000,
        supports_uplift: false,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ProofAttributionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn serde_roundtrip_constrained_ambient_summary() {
    let s = ConstrainedAmbientSummary {
        workload_count: 7,
        attribution_count: 3,
        mean_throughput_delta_millionths: -100_000,
        mean_latency_p95_improvement_millionths: 500_000,
        mean_memory_improvement_millionths: 0,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: ConstrainedAmbientSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn serde_roundtrip_constrained_ambient_event() {
    let e = ConstrainedAmbientEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "pass".into(),
        error_code: Some("FE-CABL-1005".into()),
        workload_id: None,
        proof_id: Some("proof-1".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ConstrainedAmbientEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn serde_roundtrip_full_decision() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    let json = serde_json::to_string(&dec).unwrap();
    let back: ConstrainedAmbientBenchmarkDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, back);
}

#[test]
fn serde_defaults_on_proof_attribution_sample() {
    let json = r#"{
        "proof_id": "p1",
        "specialization_id": "s1",
        "constrained_throughput_ops_per_sec": 2000,
        "without_proof_throughput_ops_per_sec": 1000,
        "constrained_latency_p95_ns": 500,
        "without_proof_latency_p95_ns": 1000
    }"#;
    let sample: ProofAttributionSample = serde_json::from_str(json).unwrap();
    assert_eq!(sample.optimization_class, "unspecified");
    assert_eq!(sample.validated_optimization_class, "unspecified");
    assert_eq!(sample.validity_epoch, None);
    assert_eq!(sample.evaluation_epoch, None);
    assert_eq!(sample.rollback_token, None);
    assert!(!sample.revoked);
}

// ---------------------------------------------------------------------------
// 4. Happy-path evaluation
// ---------------------------------------------------------------------------

#[test]
fn happy_path_single_workload_single_proof() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    assert_eq!(dec.outcome, "allow");
    assert!(!dec.blocked);
    assert!(dec.blockers.is_empty());
    assert!(dec.error_code.is_none());
    assert!(dec.allows_publication());
    assert_eq!(dec.schema_version, CONSTRAINED_AMBIENT_SCHEMA_VERSION);
    assert_eq!(dec.benchmark_run_id, "run-1");
    assert!(dec.report_id.starts_with("cabl_"));
    assert_eq!(dec.report_id.len(), 25); // "cabl_" + 20 hex chars
    assert_eq!(dec.workload_reports.len(), 1);
    assert_eq!(dec.attribution_reports.len(), 1);
    assert_eq!(dec.summary.workload_count, 1);
    assert_eq!(dec.summary.attribution_count, 1);
}

#[test]
fn happy_path_workload_delta_values_correct() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    let wr = &dec.workload_reports[0];
    assert_eq!(wr.workload_id, "w1");
    assert_eq!(wr.canonical_output_digest, "digest-w1");
    // constrained throughput=2000, ambient throughput=1000 -> delta=+100%=1_000_000
    assert_eq!(wr.throughput_delta_millionths, 1_000_000);
    // latency improvement: ambient_p50=1000, constrained_p50=500 -> improvement=(1000-500)/1000=50%=500_000
    assert_eq!(wr.latency_p50_improvement_millionths, 500_000);
}

#[test]
fn happy_path_attribution_report_values_correct() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    let ar = &dec.attribution_reports[0];
    assert_eq!(ar.proof_id, "proof-1");
    assert_eq!(ar.specialization_id, "spec-1");
    // constrained_throughput=2000, without_proof=1000 -> gain=+100%=1_000_000
    assert_eq!(ar.throughput_gain_millionths, 1_000_000);
    assert!(ar.supports_uplift);
}

#[test]
fn happy_path_events_structure() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    let names: Vec<&str> = dec.events.iter().map(|e| e.event.as_str()).collect();
    assert!(names.contains(&"constrained_ambient_evaluation_started"));
    assert!(names.contains(&"constrained_ambient_evaluation_completed"));
    assert!(names.contains(&"workload_compared"));
    assert!(names.contains(&"proof_attribution_evaluated"));
    // All events carry the request's trace/decision/policy IDs
    for event in &dec.events {
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.decision_id, "dec-1");
        assert_eq!(event.policy_id, "pol-1");
        assert_eq!(event.component, CONSTRAINED_AMBIENT_COMPONENT);
    }
}

#[test]
fn happy_path_multi_workload_multi_proof() {
    let request = ConstrainedAmbientBenchmarkRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        constrained_lane: vec![
            make_workload("w1", 2000, 500),
            make_workload("w2", 3000, 300),
        ],
        ambient_lane: vec![
            make_workload("w1", 1000, 1000),
            make_workload("w2", 1500, 600),
        ],
        proof_attribution: vec![make_attribution("p1", "s1"), make_attribution("p2", "s2")],
    };
    let dec = run_constrained_ambient_benchmark_lane(&request);
    assert!(dec.allows_publication());
    assert_eq!(dec.workload_reports.len(), 2);
    assert_eq!(dec.attribution_reports.len(), 2);
    assert_eq!(dec.summary.workload_count, 2);
    assert_eq!(dec.summary.attribution_count, 2);
}

// ---------------------------------------------------------------------------
// 5. Validation errors (empty fields, zero metrics, etc.)
// ---------------------------------------------------------------------------

#[test]
fn validation_empty_trace_id() {
    let mut r = valid_request();
    r.trace_id = "".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1001"));
}

#[test]
fn validation_whitespace_only_trace_id() {
    let mut r = valid_request();
    r.trace_id = "   ".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1001"));
}

#[test]
fn validation_empty_decision_id() {
    let mut r = valid_request();
    r.decision_id = "  ".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_empty_policy_id() {
    let mut r = valid_request();
    r.policy_id = "".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_empty_benchmark_run_id() {
    let mut r = valid_request();
    r.benchmark_run_id = "".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_empty_constrained_lane() {
    let mut r = valid_request();
    r.constrained_lane.clear();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1001"));
}

#[test]
fn validation_empty_ambient_lane() {
    let mut r = valid_request();
    r.ambient_lane.clear();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1001"));
}

#[test]
fn validation_zero_throughput_in_workload() {
    let mut r = valid_request();
    r.constrained_lane[0].throughput_ops_per_sec = 0;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1002"));
}

#[test]
fn validation_zero_latency_p50_in_workload() {
    let mut r = valid_request();
    r.ambient_lane[0].latency_p50_ns = 0;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1002"));
}

#[test]
fn validation_zero_memory_peak_in_workload() {
    let mut r = valid_request();
    r.constrained_lane[0].memory_peak_bytes = 0;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1002"));
}

#[test]
fn validation_zero_allocation_count_in_workload() {
    let mut r = valid_request();
    r.ambient_lane[0].allocation_count = 0;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_empty_workload_id() {
    let mut r = valid_request();
    r.constrained_lane[0].workload_id = "".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_empty_output_digest() {
    let mut r = valid_request();
    r.constrained_lane[0].output_digest = "  ".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_duplicate_workload_id_constrained() {
    let mut r = valid_request();
    r.constrained_lane.push(make_workload("w1", 1500, 600));
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_empty_proof_id() {
    let mut r = valid_request();
    r.proof_attribution[0].proof_id = "".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1001"));
}

#[test]
fn validation_empty_specialization_id() {
    let mut r = valid_request();
    r.proof_attribution[0].specialization_id = "  ".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_empty_optimization_class() {
    let mut r = valid_request();
    r.proof_attribution[0].optimization_class = "  ".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_empty_validated_optimization_class() {
    let mut r = valid_request();
    r.proof_attribution[0].validated_optimization_class = "".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

#[test]
fn validation_zero_constrained_throughput_in_attribution() {
    let mut r = valid_request();
    r.proof_attribution[0].constrained_throughput_ops_per_sec = 0;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1002"));
}

#[test]
fn validation_zero_without_proof_latency_in_attribution() {
    let mut r = valid_request();
    r.proof_attribution[0].without_proof_latency_p95_ns = 0;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1002"));
}

#[test]
fn validation_empty_proof_attribution_vec() {
    let mut r = valid_request();
    r.proof_attribution.clear();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1001"));
}

#[test]
fn validation_duplicate_proof_specialization_pair() {
    let mut r = valid_request();
    r.proof_attribution
        .push(make_attribution("proof-1", "spec-1"));
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec.outcome, "fail");
    assert!(dec.blocked);
}

// ---------------------------------------------------------------------------
// 6. Workload set mismatch
// ---------------------------------------------------------------------------

#[test]
fn workload_set_mismatch_different_ids() {
    let request = ConstrainedAmbientBenchmarkRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        constrained_lane: vec![make_workload("w1", 2000, 500)],
        ambient_lane: vec![make_workload("w2", 1000, 1000)],
        proof_attribution: vec![make_attribution("p1", "s1")],
    };
    let dec = run_constrained_ambient_benchmark_lane(&request);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1003"));
    assert!(
        dec.blockers
            .iter()
            .any(|b| b.contains("workload sets differ"))
    );
}

// ---------------------------------------------------------------------------
// 7. Digest mismatch
// ---------------------------------------------------------------------------

#[test]
fn digest_mismatch_blocks_decision() {
    let mut r = valid_request();
    r.constrained_lane[0].output_digest = "different-digest".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.outcome, "deny");
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1004"));
    assert!(
        dec.blockers
            .iter()
            .any(|b| b.contains("output digest mismatch"))
    );
}

// ---------------------------------------------------------------------------
// 8. Performance regression
// ---------------------------------------------------------------------------

#[test]
fn regression_blocks_when_constrained_slower() {
    let mut r = valid_request();
    // constrained throughput < ambient throughput
    r.constrained_lane[0].throughput_ops_per_sec = 500;
    r.constrained_lane[0].latency_p50_ns = 2000;
    r.constrained_lane[0].latency_p95_ns = 4000;
    r.constrained_lane[0].latency_p99_ns = 8000;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1005"));
    assert!(dec.blockers.iter().any(|b| b.contains("regressed")));
}

// ---------------------------------------------------------------------------
// 9. Attribution gap (no uplift)
// ---------------------------------------------------------------------------

#[test]
fn attribution_gap_when_equal_throughput_and_latency() {
    let mut r = valid_request();
    r.proof_attribution[0].constrained_throughput_ops_per_sec = 1000;
    r.proof_attribution[0].without_proof_throughput_ops_per_sec = 1000;
    r.proof_attribution[0].constrained_latency_p95_ns = 1000;
    r.proof_attribution[0].without_proof_latency_p95_ns = 1000;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1006"));
    assert!(dec.blockers.iter().any(|b| b.contains("uplift")));
    assert!(dec.attribution_reports.iter().any(|ar| !ar.supports_uplift));
}

// ---------------------------------------------------------------------------
// 10. Proof revocation
// ---------------------------------------------------------------------------

#[test]
fn proof_revoked_blocks_and_sets_event() {
    let mut r = valid_request();
    r.proof_attribution[0].revoked = true;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1009"));
    assert!(dec.blockers.iter().any(|b| b.contains("revoked")));
    assert!(
        dec.events
            .iter()
            .any(|e| e.event == "proof_revoked_specialization_deactivated")
    );
    // supports_uplift should be false when contract_blocked
    assert!(!dec.attribution_reports[0].supports_uplift);
}

// ---------------------------------------------------------------------------
// 11. Proof expiry
// ---------------------------------------------------------------------------

#[test]
fn proof_expired_no_rollback_token() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = Some(5);
    r.proof_attribution[0].evaluation_epoch = Some(10);
    r.proof_attribution[0].rollback_token = None;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1008"));
    assert!(dec.blockers.iter().any(|b| b.contains("no rollback token")));
    assert!(
        dec.events
            .iter()
            .any(|e| e.event == "proof_expired_no_rollback_token")
    );
}

#[test]
fn proof_expired_empty_rollback_token() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = Some(5);
    r.proof_attribution[0].evaluation_epoch = Some(10);
    r.proof_attribution[0].rollback_token = Some("  ".into());
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1008"));
    assert!(dec.blockers.iter().any(|b| b.contains("no rollback token")));
}

#[test]
fn proof_expired_with_rollback_token() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = Some(5);
    r.proof_attribution[0].evaluation_epoch = Some(6);
    r.proof_attribution[0].rollback_token = Some("rollback-token-1".into());
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1008"));
    assert!(dec.blockers.iter().any(|b| b.contains("rollback token")));
    assert!(
        dec.events
            .iter()
            .any(|e| e.event == "proof_expired_rollback_applied")
    );
}

#[test]
fn proof_not_expired_when_eval_equals_validity() {
    // evaluation_epoch == validity_epoch should NOT trigger expiry
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = Some(10);
    r.proof_attribution[0].evaluation_epoch = Some(10);
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.allows_publication());
}

#[test]
fn proof_not_expired_when_eval_before_validity() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = Some(10);
    r.proof_attribution[0].evaluation_epoch = Some(5);
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.allows_publication());
}

#[test]
fn proof_not_expired_when_epochs_absent() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = None;
    r.proof_attribution[0].evaluation_epoch = None;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.allows_publication());
}

// ---------------------------------------------------------------------------
// 12. Optimization class mismatch
// ---------------------------------------------------------------------------

#[test]
fn optimization_class_mismatch_blocks() {
    let mut r = valid_request();
    r.proof_attribution[0].optimization_class = "class-A".into();
    r.proof_attribution[0].validated_optimization_class = "class-B".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1007"));
    assert!(
        dec.blockers
            .iter()
            .any(|b| b.contains("optimization class mismatch"))
    );
}

// ---------------------------------------------------------------------------
// 13. Conflicting proof claims
// ---------------------------------------------------------------------------

#[test]
fn conflicting_proof_claims_for_same_specialization() {
    let mut r = valid_request();
    let mut second = make_attribution("proof-2", "spec-1");
    second.optimization_class = "different_class".into();
    second.validated_optimization_class = "different_class".into();
    r.proof_attribution.push(second);
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1010"));
    assert!(
        dec.blockers
            .iter()
            .any(|b| b.contains("conflicting proof claims"))
    );
}

// ---------------------------------------------------------------------------
// 14. Report ordering
// ---------------------------------------------------------------------------

#[test]
fn workload_reports_sorted_by_workload_id() {
    let request = ConstrainedAmbientBenchmarkRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        constrained_lane: vec![
            make_workload("zzz", 2000, 500),
            make_workload("aaa", 3000, 300),
        ],
        ambient_lane: vec![
            make_workload("zzz", 1000, 1000),
            make_workload("aaa", 1500, 600),
        ],
        proof_attribution: vec![make_attribution("p1", "s1")],
    };
    let dec = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(dec.workload_reports[0].workload_id, "aaa");
    assert_eq!(dec.workload_reports[1].workload_id, "zzz");
}

#[test]
fn attribution_reports_sorted_by_proof_then_spec() {
    let request = ConstrainedAmbientBenchmarkRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        constrained_lane: vec![make_workload("w1", 2000, 500)],
        ambient_lane: vec![make_workload("w1", 1000, 1000)],
        proof_attribution: vec![
            make_attribution("proof-Z", "spec-1"),
            make_attribution("proof-A", "spec-2"),
        ],
    };
    let dec = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(dec.attribution_reports[0].proof_id, "proof-A");
    assert_eq!(dec.attribution_reports[1].proof_id, "proof-Z");
}

// ---------------------------------------------------------------------------
// 15. Report ID determinism
// ---------------------------------------------------------------------------

#[test]
fn report_id_deterministic() {
    let r = valid_request();
    let dec1 = run_constrained_ambient_benchmark_lane(&r);
    let dec2 = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(dec1.report_id, dec2.report_id);
    assert!(dec1.report_id.starts_with("cabl_"));
    assert_eq!(dec1.report_id.len(), 25);
}

#[test]
fn report_id_changes_with_different_inputs() {
    let r1 = valid_request();
    let mut r2 = valid_request();
    r2.benchmark_run_id = "run-different".into();
    let dec1 = run_constrained_ambient_benchmark_lane(&r1);
    let dec2 = run_constrained_ambient_benchmark_lane(&r2);
    assert_ne!(dec1.report_id, dec2.report_id);
}

// ---------------------------------------------------------------------------
// 16. allows_publication method
// ---------------------------------------------------------------------------

#[test]
fn allows_publication_true_when_allow() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    assert!(dec.allows_publication());
}

#[test]
fn allows_publication_false_when_deny() {
    let mut r = valid_request();
    r.proof_attribution[0].revoked = true;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(!dec.allows_publication());
}

#[test]
fn allows_publication_false_when_fail() {
    let mut r = valid_request();
    r.trace_id = "".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(!dec.allows_publication());
    assert_eq!(dec.outcome, "fail");
}

// ---------------------------------------------------------------------------
// 17. Summary correctness
// ---------------------------------------------------------------------------

#[test]
fn summary_means_computed_correctly_multi_workload() {
    let request = ConstrainedAmbientBenchmarkRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "r".into(),
        constrained_lane: vec![
            make_workload("w1", 2000, 500),
            make_workload("w2", 3000, 300),
        ],
        ambient_lane: vec![
            make_workload("w1", 1000, 1000),
            make_workload("w2", 1500, 600),
        ],
        proof_attribution: vec![make_attribution("p1", "s1")],
    };
    let dec = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(dec.summary.workload_count, 2);
    assert_eq!(dec.summary.attribution_count, 1);
    // mean_throughput_delta: w1 delta=1_000_000, w2 delta=1_000_000 -> mean=1_000_000
    assert_eq!(dec.summary.mean_throughput_delta_millionths, 1_000_000);
}

// ---------------------------------------------------------------------------
// 18. Error type via public API
// ---------------------------------------------------------------------------

#[test]
fn error_type_display_on_validation_failure() {
    let mut r = valid_request();
    r.trace_id = "".into();
    let dec = run_constrained_ambient_benchmark_lane(&r);
    // The blocker string is derived from the error Display
    assert!(!dec.blockers.is_empty());
    let blocker = &dec.blockers[0];
    assert!(blocker.contains("trace_id"));
}

// ---------------------------------------------------------------------------
// 19. Error_code first-wins semantics (observable through multi-error requests)
// ---------------------------------------------------------------------------

#[test]
fn first_error_code_wins_digest_before_regression() {
    let mut r = valid_request();
    // Trigger digest mismatch AND regression
    r.constrained_lane[0].output_digest = "bad-digest".into();
    r.constrained_lane[0].throughput_ops_per_sec = 100; // regression
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    // Digest mismatch should be detected first
    assert_eq!(dec.error_code.as_deref(), Some("FE-CABL-1004"));
}

// ---------------------------------------------------------------------------
// 20. Combined lifecycle: multiple blockers accumulate
// ---------------------------------------------------------------------------

#[test]
fn multiple_blockers_accumulate() {
    let mut r = valid_request();
    // Trigger digest mismatch + regression
    r.constrained_lane[0].output_digest = "bad".into();
    r.constrained_lane[0].throughput_ops_per_sec = 100;
    r.constrained_lane[0].latency_p50_ns = 5000;
    r.constrained_lane[0].latency_p95_ns = 10000;
    r.constrained_lane[0].latency_p99_ns = 20000;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    // At least digest mismatch + regression blocker
    assert!(dec.blockers.len() >= 2);
}

// ---------------------------------------------------------------------------
// 21. Decision serde with blockers
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_blocked_decision() {
    let mut r = valid_request();
    r.proof_attribution[0].revoked = true;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.blocked);
    let json = serde_json::to_string(&dec).unwrap();
    let back: ConstrainedAmbientBenchmarkDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, back);
}

// ---------------------------------------------------------------------------
// 22. Edge: only validity_epoch without evaluation_epoch (no expiry)
// ---------------------------------------------------------------------------

#[test]
fn no_expiry_when_only_validity_epoch_set() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = Some(5);
    r.proof_attribution[0].evaluation_epoch = None;
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.allows_publication());
}

#[test]
fn no_expiry_when_only_evaluation_epoch_set() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = None;
    r.proof_attribution[0].evaluation_epoch = Some(100);
    let dec = run_constrained_ambient_benchmark_lane(&r);
    assert!(dec.allows_publication());
}

// ---------------------------------------------------------------------------
// 23. Decision events count
// ---------------------------------------------------------------------------

#[test]
fn event_count_for_single_workload_single_proof() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    // started + workload_compared + proof_attribution_evaluated + completed = 4
    assert_eq!(dec.events.len(), 4);
}

// ---------------------------------------------------------------------------
// 24. JSON field presence
// ---------------------------------------------------------------------------

#[test]
fn json_field_presence_in_decision() {
    let dec = run_constrained_ambient_benchmark_lane(&valid_request());
    let json = serde_json::to_string(&dec).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"report_id\""));
    assert!(json.contains("\"benchmark_run_id\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"blocked\""));
    assert!(json.contains("\"blockers\""));
    assert!(json.contains("\"workload_reports\""));
    assert!(json.contains("\"attribution_reports\""));
    assert!(json.contains("\"summary\""));
    assert!(json.contains("\"events\""));
}
