#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::constrained_ambient_benchmark_lane::{
    ConstrainedAmbientBenchmarkRequest, LaneWorkloadMetrics, ProofAttributionSample,
    run_constrained_ambient_benchmark_lane,
};

#[allow(clippy::too_many_arguments)]
fn workload(
    workload_id: &str,
    output_digest: &str,
    throughput_ops_per_sec: u64,
    latency_p50_ns: u64,
    latency_p95_ns: u64,
    latency_p99_ns: u64,
    memory_peak_bytes: u64,
    allocation_count: u64,
) -> LaneWorkloadMetrics {
    LaneWorkloadMetrics {
        workload_id: workload_id.to_string(),
        output_digest: output_digest.to_string(),
        throughput_ops_per_sec,
        latency_p50_ns,
        latency_p95_ns,
        latency_p99_ns,
        memory_peak_bytes,
        allocation_count,
    }
}

fn attribution(
    proof_id: &str,
    specialization_id: &str,
    constrained_throughput_ops_per_sec: u64,
    without_proof_throughput_ops_per_sec: u64,
    constrained_latency_p95_ns: u64,
    without_proof_latency_p95_ns: u64,
) -> ProofAttributionSample {
    ProofAttributionSample {
        proof_id: proof_id.to_string(),
        specialization_id: specialization_id.to_string(),
        optimization_class: "ifc_check_elision".to_string(),
        validated_optimization_class: "ifc_check_elision".to_string(),
        constrained_throughput_ops_per_sec,
        without_proof_throughput_ops_per_sec,
        constrained_latency_p95_ns,
        without_proof_latency_p95_ns,
        validity_epoch: Some(10),
        evaluation_epoch: Some(10),
        rollback_token: Some(format!("rollback-{proof_id}-{specialization_id}")),
        revoked: false,
    }
}

fn baseline_request() -> ConstrainedAmbientBenchmarkRequest {
    ConstrainedAmbientBenchmarkRequest {
        trace_id: "trace-cabl-test".to_string(),
        decision_id: "decision-cabl-test".to_string(),
        policy_id: "policy-cabl-v1".to_string(),
        benchmark_run_id: "bench-run-cabl-001".to_string(),
        constrained_lane: vec![
            workload(
                "parser-hot",
                "digest-parser-hot",
                1_200,
                1_800_000,
                2_500_000,
                4_500_000,
                90_000_000,
                45_000,
            ),
            workload(
                "module-cache",
                "digest-module-cache",
                2_300,
                1_250_000,
                2_100_000,
                3_600_000,
                110_000_000,
                54_000,
            ),
        ],
        ambient_lane: vec![
            workload(
                "parser-hot",
                "digest-parser-hot",
                1_000,
                2_000_000,
                3_000_000,
                5_000_000,
                100_000_000,
                50_000,
            ),
            workload(
                "module-cache",
                "digest-module-cache",
                2_000,
                1_500_000,
                2_500_000,
                4_000_000,
                120_000_000,
                60_000,
            ),
        ],
        proof_attribution: vec![
            attribution(
                "proof-ifc-elide",
                "spec-parser-hot",
                1_200,
                1_000,
                2_500_000,
                3_000_000,
            ),
            attribution(
                "proof-plas-dispatch",
                "spec-module-cache",
                2_300,
                2_000,
                2_100_000,
                2_500_000,
            ),
        ],
    }
}

#[test]
fn allows_when_constrained_lane_beats_ambient_with_identical_outputs() {
    let request = baseline_request();
    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert!(decision.allows_publication());
    assert!(!decision.blocked);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.error_code, None);
    assert_eq!(decision.workload_reports.len(), 2);
    assert_eq!(decision.attribution_reports.len(), 2);
    assert_eq!(decision.summary.workload_count, 2);
    assert_eq!(decision.summary.attribution_count, 2);

    for report in &decision.workload_reports {
        assert!(report.throughput_delta_millionths > 0);
        assert!(report.latency_p95_improvement_millionths > 0);
    }
    for report in &decision.attribution_reports {
        assert!(report.supports_uplift);
    }
    for event in &decision.events {
        assert_eq!(event.component, "constrained_ambient_benchmark_lane");
        assert_eq!(event.trace_id, "trace-cabl-test");
        assert_eq!(event.decision_id, "decision-cabl-test");
        assert_eq!(event.policy_id, "policy-cabl-v1");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn denies_when_output_digests_do_not_match() {
    let mut request = baseline_request();
    request.constrained_lane[0].output_digest = "digest-mismatch".to_string();

    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-CABL-1004"));
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("output digest mismatch"))
    );
}

#[test]
fn denies_when_constrained_lane_regresses_performance() {
    let mut request = baseline_request();
    request.constrained_lane[1].throughput_ops_per_sec = 1_900;

    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-CABL-1005"));
    assert!(
        decision
            .blockers
            .iter()
            .any(|blocker| blocker.contains("regressed"))
    );
}

#[test]
fn denies_when_proof_attribution_shows_no_uplift() {
    let mut request = baseline_request();
    request.proof_attribution[0].constrained_throughput_ops_per_sec = 1_000;
    request.proof_attribution[0].without_proof_throughput_ops_per_sec = 1_000;
    request.proof_attribution[0].constrained_latency_p95_ns = 3_000_000;
    request.proof_attribution[0].without_proof_latency_p95_ns = 3_000_000;

    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-CABL-1006"));
    assert!(
        decision
            .attribution_reports
            .iter()
            .any(|report| !report.supports_uplift)
    );
}

#[test]
fn fails_on_invalid_request_metadata() {
    let mut request = baseline_request();
    request.trace_id.clear();

    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some("FE-CABL-1001"));
}

#[test]
fn report_id_is_deterministic_for_identical_inputs() {
    let request = baseline_request();
    let decision_a = run_constrained_ambient_benchmark_lane(&request);
    let decision_b = run_constrained_ambient_benchmark_lane(&request);
    assert_eq!(decision_a.report_id, decision_b.report_id);
    assert_eq!(decision_a.workload_reports, decision_b.workload_reports);
    assert_eq!(
        decision_a.attribution_reports,
        decision_b.attribution_reports
    );
}

// ---------- workload helper ----------

#[test]
fn workload_helper_sets_fields() {
    let w = workload("wl-a", "digest-a", 1000, 100, 200, 300, 400, 500);
    assert_eq!(w.workload_id, "wl-a");
    assert_eq!(w.output_digest, "digest-a");
    assert_eq!(w.throughput_ops_per_sec, 1000);
    assert_eq!(w.latency_p50_ns, 100);
    assert_eq!(w.latency_p95_ns, 200);
    assert_eq!(w.latency_p99_ns, 300);
    assert_eq!(w.memory_peak_bytes, 400);
    assert_eq!(w.allocation_count, 500);
}

// ---------- attribution helper ----------

#[test]
fn attribution_helper_sets_fields() {
    let a = attribution("proof-1", "spec-1", 1200, 1000, 2500, 3000);
    assert_eq!(a.proof_id, "proof-1");
    assert_eq!(a.specialization_id, "spec-1");
    assert_eq!(a.optimization_class, "ifc_check_elision");
    assert_eq!(a.constrained_throughput_ops_per_sec, 1200);
    assert_eq!(a.without_proof_throughput_ops_per_sec, 1000);
    assert!(!a.revoked);
}

// ---------- baseline_request ----------

#[test]
fn baseline_request_has_correct_ids() {
    let req = baseline_request();
    assert_eq!(req.trace_id, "trace-cabl-test");
    assert_eq!(req.decision_id, "decision-cabl-test");
    assert_eq!(req.policy_id, "policy-cabl-v1");
}

#[test]
fn baseline_request_has_two_workloads_per_lane() {
    let req = baseline_request();
    assert_eq!(req.constrained_lane.len(), 2);
    assert_eq!(req.ambient_lane.len(), 2);
}

// ---------- LaneWorkloadMetrics ----------

#[test]
fn lane_workload_metrics_serde_roundtrip() {
    let w = workload("wl-serde", "digest-serde", 100, 200, 300, 400, 500, 600);
    let json = serde_json::to_string(&w).expect("serialize");
    let recovered: LaneWorkloadMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.workload_id, "wl-serde");
}

// ---------- ProofAttributionSample ----------

#[test]
fn proof_attribution_sample_serde_roundtrip() {
    let a = attribution("proof-serde", "spec-serde", 1000, 800, 2000, 3000);
    let json = serde_json::to_string(&a).expect("serialize");
    let recovered: ProofAttributionSample = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.proof_id, "proof-serde");
    assert_eq!(recovered.validity_epoch, Some(10));
}

// ---------- ConstrainedAmbientBenchmarkRequest ----------

#[test]
fn request_serde_roundtrip() {
    let req = baseline_request();
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: ConstrainedAmbientBenchmarkRequest =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-cabl-test");
    assert_eq!(recovered.constrained_lane.len(), 2);
}

// ---------- decision events ----------

#[test]
fn decision_events_have_correct_component() {
    let decision = run_constrained_ambient_benchmark_lane(&baseline_request());
    for event in &decision.events {
        assert_eq!(event.component, "constrained_ambient_benchmark_lane");
    }
}

// ---------- empty request metadata ----------

#[test]
fn fails_on_empty_decision_id() {
    let mut req = baseline_request();
    req.decision_id.clear();
    let decision = run_constrained_ambient_benchmark_lane(&req);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
}

#[test]
fn fails_on_empty_policy_id() {
    let mut req = baseline_request();
    req.policy_id.clear();
    let decision = run_constrained_ambient_benchmark_lane(&req);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
}

// ---------- workload_ids match across lanes ----------

#[test]
fn baseline_request_workload_ids_match_across_lanes() {
    let req = baseline_request();
    let constrained_ids: std::collections::BTreeSet<&str> = req
        .constrained_lane
        .iter()
        .map(|w| w.workload_id.as_str())
        .collect();
    let ambient_ids: std::collections::BTreeSet<&str> = req
        .ambient_lane
        .iter()
        .map(|w| w.workload_id.as_str())
        .collect();
    assert_eq!(constrained_ids, ambient_ids);
}

// ---------- report has non-empty report_id ----------

#[test]
fn decision_report_id_is_nonempty() {
    let decision = run_constrained_ambient_benchmark_lane(&baseline_request());
    assert!(!decision.report_id.is_empty());
}

// ---------- allows_publication matches blocked ----------

#[test]
fn allows_publication_is_inverse_of_blocked() {
    let decision = run_constrained_ambient_benchmark_lane(&baseline_request());
    assert_eq!(decision.allows_publication(), !decision.blocked);
}

// ---------- enrichment: serde, error paths, edge cases ----------

use frankenengine_engine::constrained_ambient_benchmark_lane::{
    ConstrainedAmbientBenchmarkDecision, ConstrainedAmbientError,
};

#[test]
fn decision_serde_roundtrip() {
    let decision = run_constrained_ambient_benchmark_lane(&baseline_request());
    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: ConstrainedAmbientBenchmarkDecision =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision.report_id, recovered.report_id);
    assert_eq!(decision.outcome, recovered.outcome);
    assert_eq!(decision.blocked, recovered.blocked);
    assert_eq!(
        decision.workload_reports.len(),
        recovered.workload_reports.len()
    );
}

#[test]
fn decision_schema_version_is_nonempty() {
    let decision = run_constrained_ambient_benchmark_lane(&baseline_request());
    assert!(!decision.schema_version.is_empty());
}

#[test]
fn revoked_attribution_blocks_publication() {
    let mut request = baseline_request();
    request.proof_attribution[0].revoked = true;
    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert!(decision.blocked);
    assert!(decision.blockers.iter().any(|b| b.contains("revoked")));
}

#[test]
fn constrained_ambient_error_display_is_nonempty() {
    let err = ConstrainedAmbientError::InvalidRequest {
        field: "trace_id".to_string(),
        detail: "empty".to_string(),
    };
    assert!(!err.to_string().is_empty());
    assert!(err.to_string().contains("trace_id"));
}

#[test]
fn constrained_ambient_error_stable_codes_unique() {
    let request_err = ConstrainedAmbientError::InvalidRequest {
        field: "f".to_string(),
        detail: "d".to_string(),
    };
    let metric_err = ConstrainedAmbientError::InvalidMetric {
        field: "f".to_string(),
        subject: "s".to_string(),
        detail: "d".to_string(),
    };
    let code_req = request_err.stable_code();
    let code_met = metric_err.stable_code();
    assert!(code_req.starts_with("FE-CABL"));
    assert!(code_met.starts_with("FE-CABL"));
    assert_ne!(code_req, code_met);
}

#[test]
fn constrained_ambient_error_is_std_error() {
    let err = ConstrainedAmbientError::InvalidMetric {
        field: "throughput".to_string(),
        subject: "parser-hot".to_string(),
        detail: "negative".to_string(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn empty_lanes_produces_fail() {
    let mut request = baseline_request();
    request.constrained_lane.clear();
    request.ambient_lane.clear();
    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert!(decision.blocked);
}

#[test]
fn mismatched_lane_sizes_produces_deny() {
    let mut request = baseline_request();
    request.constrained_lane.pop();
    let decision = run_constrained_ambient_benchmark_lane(&request);
    assert!(decision.blocked);
}

#[test]
fn lane_workload_metrics_preserves_all_fields_through_serde() {
    let wl = workload(
        "wl-full",
        "digest-full",
        10_000,
        500,
        1_000,
        2_000,
        4096,
        100,
    );
    let json = serde_json::to_string(&wl).expect("serialize");
    let recovered: LaneWorkloadMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.workload_id, "wl-full");
    assert_eq!(recovered.latency_p95_ns, 1_000);
    assert_eq!(recovered.memory_peak_bytes, 4096);
}

#[test]
fn proof_attribution_speedup_is_consistent() {
    let sample = attribution("proof-consistent", "spec-x", 50_000, 40_000, 800, 1_200);
    assert!(
        sample.constrained_throughput_ops_per_sec >= sample.without_proof_throughput_ops_per_sec,
        "constrained should be faster or equal"
    );
}

#[test]
fn baseline_request_has_matching_lane_sizes() {
    let request = baseline_request();
    assert_eq!(request.constrained_lane.len(), request.ambient_lane.len());
}

#[test]
fn baseline_request_debug_is_nonempty() {
    let request = baseline_request();
    assert!(!format!("{request:?}").is_empty());
}

#[test]
fn lane_workload_metrics_debug_is_nonempty() {
    let m = workload("wl-dbg", "digest-dbg", 1000, 100, 200, 300, 400, 500);
    assert!(!format!("{m:?}").is_empty());
}

#[test]
fn proof_attribution_sample_debug_is_nonempty() {
    let sample = attribution("proof-dbg", "spec-dbg", 50_000, 40_000, 800, 1_200);
    assert!(!format!("{sample:?}").is_empty());
}
