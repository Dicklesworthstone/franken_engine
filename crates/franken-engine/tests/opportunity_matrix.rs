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

use frankenengine_engine::benchmark_denominator::BenchmarkCase;
use frankenengine_engine::flamegraph_pipeline::{
    FLAMEGRAPH_STORAGE_INTEGRATION_POINT, FlamegraphArtifact, FlamegraphDiffEntry,
    FlamegraphEvidenceLink, FlamegraphKind, FlamegraphMetadata, FoldedStackSample,
};
use frankenengine_engine::opportunity_matrix::{
    HotspotProfileEntry, OpportunityMatrixRequest, OpportunityOutcomeObservation,
    OpportunityStatus, benchmark_pressure_from_cases, derive_candidates_from_hotspots,
    hotspot_profile_from_flamegraphs, run_opportunity_matrix_scoring,
};

fn benchmark_case(workload: &str, franken: f64, baseline: f64) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload.to_string(),
        throughput_franken_tps: franken,
        throughput_baseline_tps: baseline,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn flamegraph_artifact(
    artifact_id: &str,
    benchmark_run_id: &str,
    folded_stacks: Vec<FoldedStackSample>,
) -> FlamegraphArtifact {
    let total_samples = folded_stacks
        .iter()
        .map(|entry| entry.sample_count)
        .sum::<u64>();
    let folded_stacks_text = folded_stacks
        .iter()
        .map(|entry| format!("{} {}", entry.stack, entry.sample_count))
        .collect::<Vec<_>>()
        .join("\n");

    FlamegraphArtifact {
        schema_version: "franken-engine.flamegraph-artifact.v1".to_string(),
        artifact_id: artifact_id.to_string(),
        kind: FlamegraphKind::Cpu,
        metadata: FlamegraphMetadata {
            benchmark_run_id: benchmark_run_id.to_string(),
            baseline_benchmark_run_id: None,
            workload_id: "workload-mixed".to_string(),
            benchmark_profile: "profile-s".to_string(),
            config_fingerprint: "cfg-001".to_string(),
            git_commit: "deadbeef".to_string(),
            generated_at_utc: "2026-02-22T00:00:00Z".to_string(),
        },
        evidence_link: FlamegraphEvidenceLink {
            trace_id: "trace-opportunity".to_string(),
            decision_id: "decision-opportunity".to_string(),
            policy_id: "policy-performance".to_string(),
            benchmark_run_id: benchmark_run_id.to_string(),
            optimization_decision_id: "opt-run-001".to_string(),
            evidence_node_id: "evidence-1".to_string(),
        },
        folded_stacks,
        folded_stacks_text,
        svg: "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".to_string(),
        total_samples,
        diff_from_artifact_id: None,
        diff_entries: Vec::<FlamegraphDiffEntry>::new(),
        warnings: Vec::new(),
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
    }
}

fn base_request_from_hotspots(hotspots: Vec<HotspotProfileEntry>) -> OpportunityMatrixRequest {
    let node_cases = vec![
        benchmark_case("boot-storm", 150.0, 100.0),
        benchmark_case("capability-churn", 140.0, 100.0),
    ];
    let bun_cases = vec![
        benchmark_case("boot-storm", 160.0, 100.0),
        benchmark_case("capability-churn", 155.0, 100.0),
    ];
    let pressure = benchmark_pressure_from_cases(&node_cases, &bun_cases);
    let candidates =
        derive_candidates_from_hotspots(&hotspots, pressure, 2, 200_000, 1_000_000, 1_000_000, 4);

    OpportunityMatrixRequest {
        trace_id: "trace-opportunity".to_string(),
        decision_id: "decision-opportunity".to_string(),
        policy_id: "policy-performance".to_string(),
        optimization_run_id: "opt-run-001".to_string(),
        benchmark_pressure_millionths: pressure,
        hotspots,
        candidates,
        historical_outcomes: vec![OpportunityOutcomeObservation {
            opportunity_id: "opp:vm:dispatch".to_string(),
            predicted_gain_millionths: 500_000,
            actual_gain_millionths: 420_000,
            completed_at_utc: "2026-02-22T12:00:00Z".to_string(),
        }],
    }
}

#[test]
fn end_to_end_profile_to_ranked_output() {
    let artifacts = vec![
        flamegraph_artifact(
            "fg-1",
            "bench-1",
            vec![
                FoldedStackSample {
                    stack: "vm;dispatch".to_string(),
                    sample_count: 700,
                },
                FoldedStackSample {
                    stack: "vm;gc_tick".to_string(),
                    sample_count: 200,
                },
                FoldedStackSample {
                    stack: "net;socket_poll".to_string(),
                    sample_count: 100,
                },
            ],
        ),
        flamegraph_artifact(
            "fg-2",
            "bench-2",
            vec![FoldedStackSample {
                stack: "vm;dispatch".to_string(),
                sample_count: 100,
            }],
        ),
    ];

    let hotspots = hotspot_profile_from_flamegraphs(&artifacts);
    assert!(!hotspots.is_empty());
    assert_eq!(hotspots[0].module, "vm");
    assert_eq!(hotspots[0].function, "dispatch");

    let request = base_request_from_hotspots(hotspots);
    let decision = run_opportunity_matrix_scoring(&request);

    assert_eq!(decision.outcome, "allow");
    assert!(decision.has_selected_opportunities());
    assert!(!decision.selected_opportunity_ids.is_empty());
    assert_eq!(
        decision.ranked_opportunities[0].target_function, "dispatch",
        "highest hotspot should rank first in deterministic ordering",
    );
}

#[test]
fn structured_events_contain_required_fields() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let request = base_request_from_hotspots(hotspots);
    let decision = run_opportunity_matrix_scoring(&request);

    assert!(!decision.events.is_empty());
    for event in &decision.events {
        assert_eq!(event.trace_id, "trace-opportunity");
        assert_eq!(event.decision_id, "decision-opportunity");
        assert_eq!(event.policy_id, "policy-performance");
        assert_eq!(event.component, "opportunity_matrix");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn historical_tracking_records_predicted_vs_actual_error() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    request.historical_outcomes = vec![
        OpportunityOutcomeObservation {
            opportunity_id: "opp:vm:dispatch".to_string(),
            predicted_gain_millionths: 400_000,
            actual_gain_millionths: 520_000,
            completed_at_utc: "2026-02-22T12:00:00Z".to_string(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp:vm:gc_tick".to_string(),
            predicted_gain_millionths: 300_000,
            actual_gain_millionths: 250_000,
            completed_at_utc: "2026-02-22T12:05:00Z".to_string(),
        },
    ];

    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.historical_tracking.len(), 2);
    assert_eq!(
        decision.historical_tracking[0].signed_error_millionths,
        120_000
    );
    assert_eq!(
        decision.historical_tracking[1].signed_error_millionths,
        -50_000
    );
    assert_eq!(
        decision.historical_tracking[1].absolute_error_millionths,
        50_000
    );
}

#[test]
fn invalid_historical_timestamp_causes_fail_outcome() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    request.historical_outcomes = vec![OpportunityOutcomeObservation {
        opportunity_id: "opp:vm:dispatch".to_string(),
        predicted_gain_millionths: 500_000,
        actual_gain_millionths: 450_000,
        completed_at_utc: "not-a-timestamp".to_string(),
    }];

    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.error_code.is_some());
}

#[test]
fn security_clearance_zero_prevents_selection() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    assert!(!request.candidates.is_empty());
    request.candidates[0].security_clearance_millionths = 0;

    let decision = run_opportunity_matrix_scoring(&request);
    let first = &decision.ranked_opportunities[0];
    assert_eq!(first.status, OpportunityStatus::RejectedSecurityClearance);
    assert!(!first.threshold_met);
}

// ---------- constants ----------

#[test]
fn opportunity_matrix_constants_are_nonempty() {
    use frankenengine_engine::opportunity_matrix::{
        OPPORTUNITY_MATRIX_COMPONENT, OPPORTUNITY_MATRIX_SCHEMA_VERSION,
        OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS,
    };
    assert!(!OPPORTUNITY_MATRIX_COMPONENT.is_empty());
    assert!(!OPPORTUNITY_MATRIX_SCHEMA_VERSION.is_empty());
    const { assert!(OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS > 0) };
}

// ---------- hotspot_profile_from_flamegraphs ----------

#[test]
fn hotspot_profile_from_empty_artifacts_is_empty() {
    let hotspots = hotspot_profile_from_flamegraphs(&[]);
    assert!(hotspots.is_empty());
}

#[test]
fn hotspot_profile_aggregates_across_artifacts() {
    let artifacts = vec![
        flamegraph_artifact(
            "fg-a",
            "bench-a",
            vec![FoldedStackSample {
                stack: "vm;dispatch".to_string(),
                sample_count: 100,
            }],
        ),
        flamegraph_artifact(
            "fg-b",
            "bench-b",
            vec![FoldedStackSample {
                stack: "vm;dispatch".to_string(),
                sample_count: 50,
            }],
        ),
    ];
    let hotspots = hotspot_profile_from_flamegraphs(&artifacts);
    let dispatch = hotspots
        .iter()
        .find(|h| h.function == "dispatch")
        .expect("dispatch hotspot");
    assert_eq!(dispatch.sample_count, 150);
}

#[test]
fn hotspot_profile_entry_key_combines_module_and_function() {
    let entry = HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    };
    assert_eq!(entry.key(), "vm::dispatch");
}

// ---------- benchmark_pressure_from_cases ----------

#[test]
fn benchmark_pressure_neutral_when_equal_throughput() {
    let cases = vec![benchmark_case("equal", 100.0, 100.0)];
    let pressure = benchmark_pressure_from_cases(&cases, &cases);
    assert!(
        pressure >= 1_000_000,
        "pressure must be at least neutral (1.0)"
    );
}

#[test]
fn benchmark_pressure_differs_for_different_throughput_ratios() {
    let franken_better = vec![benchmark_case("fast", 200.0, 100.0)];
    let equal = vec![benchmark_case("fast", 100.0, 100.0)];
    let pressure_win = benchmark_pressure_from_cases(&franken_better, &equal);
    let pressure_equal = benchmark_pressure_from_cases(&equal, &equal);
    assert_ne!(pressure_win, pressure_equal);
}

// ---------- derive_candidates_from_hotspots ----------

#[test]
fn derive_candidates_respects_max_candidates() {
    let hotspots = vec![
        HotspotProfileEntry {
            module: "a".to_string(),
            function: "f1".to_string(),
            sample_count: 100,
        },
        HotspotProfileEntry {
            module: "b".to_string(),
            function: "f2".to_string(),
            sample_count: 80,
        },
        HotspotProfileEntry {
            module: "c".to_string(),
            function: "f3".to_string(),
            sample_count: 60,
        },
    ];
    let candidates =
        derive_candidates_from_hotspots(&hotspots, 1_000_000, 2, 200_000, 1_000_000, 1_000_000, 2);
    assert!(candidates.len() <= 2);
}

#[test]
fn derive_candidates_from_empty_hotspots_is_empty() {
    let candidates =
        derive_candidates_from_hotspots(&[], 1_000_000, 2, 200_000, 1_000_000, 1_000_000, 4);
    assert!(candidates.is_empty());
}

// ---------- OpportunityStatus ----------

#[test]
fn opportunity_status_serde_roundtrip() {
    for status in [
        OpportunityStatus::Selected,
        OpportunityStatus::RejectedLowScore,
        OpportunityStatus::RejectedSecurityClearance,
        OpportunityStatus::RejectedMissingHotspot,
    ] {
        let json = serde_json::to_string(&status).expect("serialize");
        let recovered: OpportunityStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, status);
    }
}

// ---------- OpportunityMatrixDecision ----------

#[test]
fn decision_schema_version_matches_constant() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let request = base_request_from_hotspots(hotspots);
    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(
        decision.schema_version,
        frankenengine_engine::opportunity_matrix::OPPORTUNITY_MATRIX_SCHEMA_VERSION
    );
}

#[test]
fn decision_serde_roundtrip() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let request = base_request_from_hotspots(hotspots);
    let decision = run_opportunity_matrix_scoring(&request);
    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: frankenengine_engine::opportunity_matrix::OpportunityMatrixDecision =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.outcome, decision.outcome);
    assert_eq!(recovered.matrix_id, decision.matrix_id);
}

// ---------- OpportunityMatrixRequest serde ----------

#[test]
fn opportunity_matrix_request_serde_roundtrip() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let request = base_request_from_hotspots(hotspots);
    let json = serde_json::to_string(&request).expect("serialize");
    let recovered: OpportunityMatrixRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, request.trace_id);
    assert_eq!(recovered.candidates.len(), request.candidates.len());
}

// ---------- empty request ----------

#[test]
fn empty_candidates_produce_no_selections() {
    let request = OpportunityMatrixRequest {
        trace_id: "trace-empty".to_string(),
        decision_id: "decision-empty".to_string(),
        policy_id: "policy-empty".to_string(),
        optimization_run_id: "opt-empty".to_string(),
        benchmark_pressure_millionths: 1_000_000,
        hotspots: Vec::new(),
        candidates: Vec::new(),
        historical_outcomes: Vec::new(),
    };
    let decision = run_opportunity_matrix_scoring(&request);
    assert!(!decision.has_selected_opportunities());
    assert!(decision.selected_opportunity_ids.is_empty());
}

// ---------- historical tracking ----------

#[test]
fn historical_tracking_empty_when_no_outcomes() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    request.historical_outcomes = Vec::new();
    let decision = run_opportunity_matrix_scoring(&request);
    assert!(decision.historical_tracking.is_empty());
}

// ---------- enrichment: serde, error paths, edge cases ----------

use frankenengine_engine::opportunity_matrix::{
    OpportunityMatrixError, OptimizationCandidateInput,
};

#[test]
fn hotspot_profile_entry_serde_roundtrip() {
    let entry = HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 42,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: HotspotProfileEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, recovered);
}

#[test]
fn optimization_candidate_input_serde_roundtrip() {
    let candidate = OptimizationCandidateInput {
        opportunity_id: "opp:test".to_string(),
        target_module: "vm".to_string(),
        target_function: "dispatch".to_string(),
        estimated_speedup_millionths: 500_000,
        implementation_complexity: 3,
        regression_risk_millionths: 100_000,
        security_clearance_millionths: 1_000_000,
        engineering_effort_hours_millionths: 4_000_000,
        hotpath_weight_override_millionths: None,
    };
    let json = serde_json::to_string(&candidate).expect("serialize");
    let recovered: OptimizationCandidateInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(candidate, recovered);
}

#[test]
fn optimization_candidate_target_key() {
    let candidate = OptimizationCandidateInput {
        opportunity_id: "opp:test".to_string(),
        target_module: "vm".to_string(),
        target_function: "dispatch".to_string(),
        estimated_speedup_millionths: 500_000,
        implementation_complexity: 3,
        regression_risk_millionths: 100_000,
        security_clearance_millionths: 1_000_000,
        engineering_effort_hours_millionths: 4_000_000,
        hotpath_weight_override_millionths: None,
    };
    assert_eq!(candidate.target_key(), "vm::dispatch");
}

#[test]
fn opportunity_outcome_observation_serde_roundtrip() {
    let obs = OpportunityOutcomeObservation {
        opportunity_id: "opp:vm:dispatch".to_string(),
        predicted_gain_millionths: 500_000,
        actual_gain_millionths: 420_000,
        completed_at_utc: "2026-02-22T12:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: OpportunityOutcomeObservation =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, recovered);
}

#[test]
fn opportunity_matrix_error_display_is_nonempty() {
    let errors = [
        OpportunityMatrixError::InvalidRequest {
            field: "trace_id".to_string(),
            detail: "empty".to_string(),
        },
        OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "opp:dup".to_string(),
        },
        OpportunityMatrixError::InvalidTimestamp {
            value: "bad".to_string(),
        },
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn opportunity_matrix_error_stable_codes_unique() {
    let errors = [
        OpportunityMatrixError::InvalidRequest {
            field: "f".to_string(),
            detail: "d".to_string(),
        },
        OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "o".to_string(),
        },
        OpportunityMatrixError::InvalidTimestamp {
            value: "v".to_string(),
        },
    ];
    let mut codes: Vec<&str> = errors.iter().map(|e| e.stable_code()).collect();
    let original_len = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), original_len, "stable codes must be unique");
}

#[test]
fn opportunity_matrix_error_is_std_error() {
    let err = OpportunityMatrixError::InvalidTimestamp {
        value: "bad-ts".to_string(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn empty_trace_id_request_produces_fail() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    request.trace_id.clear();
    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.error_code.is_some());
}

#[test]
fn benchmark_pressure_from_cases_returns_i64() {
    let cases_a = [benchmark_case("wl-a", 100.0, 100.0)];
    let cases_b = [benchmark_case("wl-b", 100.0, 100.0)];
    let pressure = benchmark_pressure_from_cases(&cases_a, &cases_b);
    // Result is a millionths-scale i64 — verify it's in a reasonable range
    assert!(
        pressure.abs() <= 2_000_000,
        "pressure should be within ±2.0"
    );
}

#[test]
fn derive_candidates_from_empty_hotspots_returns_empty() {
    let candidates = derive_candidates_from_hotspots(&[], 0, 0, 0, 0, 0, 0);
    assert!(candidates.is_empty());
}

#[test]
fn opportunity_outcome_observation_deterministic_serde() {
    let obs = OpportunityOutcomeObservation {
        opportunity_id: "opp:det".to_string(),
        predicted_gain_millionths: 300_000,
        actual_gain_millionths: 280_000,
        completed_at_utc: "2026-02-22T12:00:00Z".to_string(),
    };
    let json1 = serde_json::to_string(&obs).expect("serialize");
    let json2 = serde_json::to_string(&obs).expect("serialize again");
    assert_eq!(json1, json2);
}
