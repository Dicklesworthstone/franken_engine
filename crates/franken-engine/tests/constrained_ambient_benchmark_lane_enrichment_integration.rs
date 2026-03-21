#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `constrained_ambient_benchmark_lane`.

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
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_component_name_matches() {
    assert_eq!(
        CONSTRAINED_AMBIENT_COMPONENT,
        "constrained_ambient_benchmark_lane"
    );
}

#[test]
fn enrichment_schema_version_contains_v1() {
    assert!(CONSTRAINED_AMBIENT_SCHEMA_VERSION.contains("v1"));
}

// ---------------------------------------------------------------------------
// LaneWorkloadMetrics serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_metrics_serde_roundtrip() {
    let m = make_workload("w-test", 5000, 200);
    let json = serde_json::to_string(&m).unwrap();
    let back: LaneWorkloadMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_workload_metrics_clone_eq() {
    let m = make_workload("w-1", 1000, 100);
    let m2 = m.clone();
    assert_eq!(m, m2);
}

// ---------------------------------------------------------------------------
// ProofAttributionSample serde + defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proof_attribution_sample_serde_roundtrip() {
    let s = make_attribution("p-1", "s-1");
    let json = serde_json::to_string(&s).unwrap();
    let back: ProofAttributionSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_proof_attribution_sample_defaults() {
    // When optional fields are missing from JSON, serde defaults should kick in
    let json = r#"{
        "proof_id": "p",
        "specialization_id": "s",
        "constrained_throughput_ops_per_sec": 100,
        "without_proof_throughput_ops_per_sec": 50,
        "constrained_latency_p95_ns": 10,
        "without_proof_latency_p95_ns": 20
    }"#;
    let sample: ProofAttributionSample = serde_json::from_str(json).unwrap();
    assert_eq!(sample.optimization_class, "unspecified");
    assert_eq!(sample.validated_optimization_class, "unspecified");
    assert!(sample.validity_epoch.is_none());
    assert!(sample.evaluation_epoch.is_none());
    assert!(sample.rollback_token.is_none());
    assert!(!sample.revoked);
}

// ---------------------------------------------------------------------------
// ConstrainedAmbientEvent serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_serde_roundtrip() {
    let e = ConstrainedAmbientEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "ev".into(),
        outcome: "pass".into(),
        error_code: Some("E01".into()),
        workload_id: Some("w1".into()),
        proof_id: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ConstrainedAmbientEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// WorkloadDeltaReport serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_delta_report_serde_roundtrip() {
    let r = WorkloadDeltaReport {
        workload_id: "w".into(),
        canonical_output_digest: "d".into(),
        throughput_delta_millionths: 500_000,
        latency_p50_improvement_millionths: 300_000,
        latency_p95_improvement_millionths: 200_000,
        latency_p99_improvement_millionths: 100_000,
        memory_improvement_millionths: 50_000,
        allocation_improvement_millionths: 25_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: WorkloadDeltaReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// ProofAttributionReport serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_attribution_report_serde_roundtrip() {
    let r = ProofAttributionReport {
        proof_id: "p".into(),
        specialization_id: "s".into(),
        throughput_gain_millionths: 100_000,
        latency_p95_improvement_millionths: 50_000,
        supports_uplift: true,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ProofAttributionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// ConstrainedAmbientSummary serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_serde_roundtrip() {
    let s = ConstrainedAmbientSummary {
        workload_count: 3,
        attribution_count: 2,
        mean_throughput_delta_millionths: 500_000,
        mean_latency_p95_improvement_millionths: 200_000,
        mean_memory_improvement_millionths: 100_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: ConstrainedAmbientSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// ConstrainedAmbientBenchmarkDecision
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_allows_publication_true() {
    let d = run_constrained_ambient_benchmark_lane(&valid_request());
    assert!(d.allows_publication());
    assert_eq!(d.outcome, "allow");
}

#[test]
fn enrichment_decision_serde_roundtrip() {
    let d = run_constrained_ambient_benchmark_lane(&valid_request());
    let json = serde_json::to_string(&d).unwrap();
    let back: ConstrainedAmbientBenchmarkDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// run_constrained_ambient_benchmark_lane: validation errors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_trace_id_fails() {
    let mut r = valid_request();
    r.trace_id = "".into();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert_eq!(d.outcome, "fail");
}

#[test]
fn enrichment_empty_decision_id_fails() {
    let mut r = valid_request();
    r.decision_id = "  ".into();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
}

#[test]
fn enrichment_empty_policy_id_fails() {
    let mut r = valid_request();
    r.policy_id = "".into();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
}

#[test]
fn enrichment_empty_benchmark_run_id_fails() {
    let mut r = valid_request();
    r.benchmark_run_id = "".into();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
}

#[test]
fn enrichment_empty_constrained_lane_fails() {
    let mut r = valid_request();
    r.constrained_lane.clear();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
}

#[test]
fn enrichment_empty_ambient_lane_fails() {
    let mut r = valid_request();
    r.ambient_lane.clear();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
}

#[test]
fn enrichment_empty_proof_attribution_fails() {
    let mut r = valid_request();
    r.proof_attribution.clear();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert_eq!(d.outcome, "fail");
}

// ---------------------------------------------------------------------------
// run_constrained_ambient_benchmark_lane: gating logic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_digest_mismatch_blocks() {
    let mut r = valid_request();
    r.ambient_lane[0].output_digest = "different-digest".into();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(d.blockers.iter().any(|b| b.contains("digest mismatch")));
}

#[test]
fn enrichment_performance_regression_blocks() {
    let mut r = valid_request();
    r.constrained_lane[0].throughput_ops_per_sec = 500;
    r.constrained_lane[0].latency_p50_ns = 2000;
    r.constrained_lane[0].latency_p95_ns = 4000;
    r.constrained_lane[0].latency_p99_ns = 8000;
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(d.blockers.iter().any(|b| b.contains("regressed")));
}

#[test]
fn enrichment_attribution_gap_blocks() {
    let mut r = valid_request();
    r.proof_attribution[0].constrained_throughput_ops_per_sec = 1000;
    r.proof_attribution[0].without_proof_throughput_ops_per_sec = 1000;
    r.proof_attribution[0].constrained_latency_p95_ns = 1000;
    r.proof_attribution[0].without_proof_latency_p95_ns = 1000;
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(d.blockers.iter().any(|b| b.contains("uplift")));
}

#[test]
fn enrichment_revoked_proof_blocks() {
    let mut r = valid_request();
    r.proof_attribution[0].revoked = true;
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(
        d.events
            .iter()
            .any(|e| e.event == "proof_revoked_specialization_deactivated")
    );
}

#[test]
fn enrichment_expired_proof_with_rollback_blocks() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = Some(5);
    r.proof_attribution[0].evaluation_epoch = Some(6);
    r.proof_attribution[0].rollback_token = Some("rb-1".into());
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(
        d.events
            .iter()
            .any(|e| e.event == "proof_expired_rollback_applied")
    );
}

#[test]
fn enrichment_expired_proof_without_rollback_blocks() {
    let mut r = valid_request();
    r.proof_attribution[0].validity_epoch = Some(5);
    r.proof_attribution[0].evaluation_epoch = Some(6);
    r.proof_attribution[0].rollback_token = None;
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(
        d.events
            .iter()
            .any(|e| e.event == "proof_expired_no_rollback_token")
    );
}

#[test]
fn enrichment_optimization_class_mismatch_blocks() {
    let mut r = valid_request();
    r.proof_attribution[0].optimization_class = "class_a".into();
    r.proof_attribution[0].validated_optimization_class = "class_b".into();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(
        d.blockers
            .iter()
            .any(|b| b.contains("optimization class mismatch"))
    );
}

#[test]
fn enrichment_conflicting_proof_claims_blocks() {
    let mut r = valid_request();
    let mut conflicting = make_attribution("proof-2", "spec-1");
    conflicting.optimization_class = "plas_dispatch".into();
    conflicting.validated_optimization_class = "plas_dispatch".into();
    r.proof_attribution.push(conflicting);
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(
        d.blockers
            .iter()
            .any(|b| b.contains("conflicting proof claims"))
    );
}

// ---------------------------------------------------------------------------
// report_id determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_id_deterministic() {
    let r = valid_request();
    let d1 = run_constrained_ambient_benchmark_lane(&r);
    let d2 = run_constrained_ambient_benchmark_lane(&r);
    assert_eq!(d1.report_id, d2.report_id);
    assert!(d1.report_id.starts_with("cabl_"));
}

#[test]
fn enrichment_report_id_changes_with_input() {
    let r1 = valid_request();
    let mut r2 = valid_request();
    r2.benchmark_run_id = "run-2".into();
    let d1 = run_constrained_ambient_benchmark_lane(&r1);
    let d2 = run_constrained_ambient_benchmark_lane(&r2);
    assert_ne!(d1.report_id, d2.report_id);
}

// ---------------------------------------------------------------------------
// Multiple workloads
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multiple_workloads_all_pass() {
    let r = ConstrainedAmbientBenchmarkRequest {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        benchmark_run_id: "run".into(),
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
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.allows_publication());
    assert_eq!(d.summary.workload_count, 2);
}

#[test]
fn enrichment_workload_set_mismatch_blocks() {
    let mut r = valid_request();
    r.ambient_lane[0].workload_id = "w-other".into();
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert!(
        d.blockers
            .iter()
            .any(|b| b.contains("workload sets differ"))
    );
}

// ---------------------------------------------------------------------------
// Event structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_events_contain_started_and_completed() {
    let d = run_constrained_ambient_benchmark_lane(&valid_request());
    assert!(d.events.iter().any(|e| e.event.contains("started")));
    assert!(d.events.iter().any(|e| e.event.contains("completed")));
}

#[test]
fn enrichment_events_have_correct_component() {
    let d = run_constrained_ambient_benchmark_lane(&valid_request());
    for e in &d.events {
        assert_eq!(e.component, CONSTRAINED_AMBIENT_COMPONENT);
    }
}

#[test]
fn enrichment_events_trace_ids_match() {
    let r = valid_request();
    let d = run_constrained_ambient_benchmark_lane(&r);
    for e in &d.events {
        assert_eq!(e.trace_id, r.trace_id);
        assert_eq!(e.decision_id, r.decision_id);
        assert_eq!(e.policy_id, r.policy_id);
    }
}

// ---------------------------------------------------------------------------
// Zero metric validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_zero_throughput_in_workload_fails() {
    let mut r = valid_request();
    r.constrained_lane[0].throughput_ops_per_sec = 0;
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert_eq!(d.outcome, "fail");
}

#[test]
fn enrichment_zero_latency_in_workload_fails() {
    let mut r = valid_request();
    r.constrained_lane[0].latency_p50_ns = 0;
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
}

#[test]
fn enrichment_zero_attribution_throughput_fails() {
    let mut r = valid_request();
    r.proof_attribution[0].constrained_throughput_ops_per_sec = 0;
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
}

// ---------------------------------------------------------------------------
// Duplicate proof/specialization
// ---------------------------------------------------------------------------

#[test]
fn enrichment_duplicate_proof_spec_pair_fails() {
    let mut r = valid_request();
    r.proof_attribution
        .push(make_attribution("proof-1", "spec-1"));
    let d = run_constrained_ambient_benchmark_lane(&r);
    assert!(d.blocked);
    assert_eq!(d.outcome, "fail");
}
