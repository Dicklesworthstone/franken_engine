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

// ===== PearlTower enrichment =====

use frankenengine_engine::opportunity_matrix::{
    OpportunityHistoryRecord, OpportunityMatrixDecision, OpportunityMatrixEvent, ScoredOpportunity,
};

#[test]
fn enrichment_scored_opportunity_serde_roundtrip() {
    let scored = ScoredOpportunity {
        opportunity_id: "opp:vm:dispatch".to_string(),
        target_module: "vm".to_string(),
        target_function: "dispatch".to_string(),
        estimated_speedup_millionths: 1_500_000,
        hotpath_weight_millionths: 700_000,
        benchmark_pressure_millionths: 1_200_000,
        voi_millionths: 3_000_000,
        score_millionths: 2_500_000,
        threshold_met: true,
        status: OpportunityStatus::Selected,
        rejection_reason: None,
    };
    let json = serde_json::to_string(&scored).expect("serialize");
    let recovered: ScoredOpportunity = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, scored);
    assert!(recovered.threshold_met);
    assert_eq!(recovered.status, OpportunityStatus::Selected);
}

#[test]
fn enrichment_opportunity_history_record_serde_roundtrip() {
    let record = OpportunityHistoryRecord {
        opportunity_id: "opp:gc:tick".to_string(),
        predicted_gain_millionths: 400_000,
        actual_gain_millionths: 350_000,
        signed_error_millionths: -50_000,
        absolute_error_millionths: 50_000,
        completed_at_utc: "2026-03-01T08:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let recovered: OpportunityHistoryRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, record);
    assert_eq!(recovered.signed_error_millionths, -50_000);
    assert_eq!(recovered.absolute_error_millionths, 50_000);
}

#[test]
fn enrichment_opportunity_matrix_event_serde_roundtrip() {
    let event = OpportunityMatrixEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-perf".to_string(),
        component: "opportunity_matrix".to_string(),
        event: "opportunity_scored".to_string(),
        outcome: "allow".to_string(),
        error_code: None,
        opportunity_id: Some("opp:vm:dispatch".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: OpportunityMatrixEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
    assert_eq!(recovered.component, "opportunity_matrix");
}

#[test]
fn enrichment_all_candidates_rejected_security_clearance() {
    // All candidates have zero security clearance — none should be selected.
    let hotspots = vec![
        HotspotProfileEntry {
            module: "vm".to_string(),
            function: "dispatch".to_string(),
            sample_count: 500,
        },
        HotspotProfileEntry {
            module: "gc".to_string(),
            function: "tick".to_string(),
            sample_count: 300,
        },
    ];
    let mut request = base_request_from_hotspots(hotspots);
    for candidate in &mut request.candidates {
        candidate.security_clearance_millionths = 0;
    }
    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(!decision.has_selected_opportunities());
    assert!(decision.selected_opportunity_ids.is_empty());
    for opp in &decision.ranked_opportunities {
        assert_eq!(opp.status, OpportunityStatus::RejectedSecurityClearance);
        assert!(!opp.threshold_met);
    }
}

#[test]
fn enrichment_all_candidates_selected_when_high_scores() {
    // Candidates with very high speedup and full clearance should all be selected.
    let hotspots = vec![
        HotspotProfileEntry {
            module: "jit".to_string(),
            function: "compile".to_string(),
            sample_count: 600,
        },
        HotspotProfileEntry {
            module: "jit".to_string(),
            function: "optimize".to_string(),
            sample_count: 400,
        },
    ];
    let node_cases = vec![benchmark_case("jit-workload", 100.0, 100.0)];
    let bun_cases = vec![benchmark_case("jit-workload", 100.0, 100.0)];
    let pressure = benchmark_pressure_from_cases(&node_cases, &bun_cases);
    let mut candidates =
        derive_candidates_from_hotspots(&hotspots, pressure, 1, 1_000, 1_000_000, 100_000, 4);
    // Boost estimated speedup so scores clear the threshold.
    for candidate in &mut candidates {
        candidate.estimated_speedup_millionths = 10_000_000;
    }
    let request = OpportunityMatrixRequest {
        trace_id: "trace-allselect".to_string(),
        decision_id: "decision-allselect".to_string(),
        policy_id: "policy-allselect".to_string(),
        optimization_run_id: "opt-allselect".to_string(),
        benchmark_pressure_millionths: pressure,
        hotspots,
        candidates,
        historical_outcomes: Vec::new(),
    };
    let decision = run_opportunity_matrix_scoring(&request);
    // With extremely high speedup scores all should be selected.
    assert_eq!(decision.outcome, "allow");
    assert!(decision.has_selected_opportunities());
    for opp in &decision.ranked_opportunities {
        assert_eq!(
            opp.status,
            OpportunityStatus::Selected,
            "expected Selected but got {:?} for {}",
            opp.status,
            opp.opportunity_id
        );
    }
}

#[test]
fn enrichment_empty_candidates_produces_fail_outcome() {
    // Validation rejects requests with zero candidates.
    let request = OpportunityMatrixRequest {
        trace_id: "trace-nocandidates".to_string(),
        decision_id: "decision-nocandidates".to_string(),
        policy_id: "policy-nocandidates".to_string(),
        optimization_run_id: "opt-nocandidates".to_string(),
        benchmark_pressure_millionths: 1_200_000,
        hotspots: Vec::new(),
        candidates: Vec::new(),
        historical_outcomes: Vec::new(),
    };
    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.error_code.is_some());
    assert!(!decision.has_selected_opportunities());
    assert!(decision.ranked_opportunities.is_empty());
}

#[test]
fn enrichment_historical_tracking_signed_and_absolute_errors_consistent() {
    // absolute_error must always equal |signed_error|.
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    request.historical_outcomes = vec![
        OpportunityOutcomeObservation {
            opportunity_id: "opp:vm:dispatch".to_string(),
            predicted_gain_millionths: 600_000,
            actual_gain_millionths: 400_000,
            completed_at_utc: "2026-03-01T10:00:00Z".to_string(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp:gc:tick".to_string(),
            predicted_gain_millionths: 200_000,
            actual_gain_millionths: 350_000,
            completed_at_utc: "2026-03-01T11:00:00Z".to_string(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp:net:poll".to_string(),
            predicted_gain_millionths: 500_000,
            actual_gain_millionths: 500_000,
            completed_at_utc: "2026-03-01T12:00:00Z".to_string(),
        },
    ];
    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.historical_tracking.len(), 3);
    for record in &decision.historical_tracking {
        assert_eq!(
            record.absolute_error_millionths,
            record.signed_error_millionths.abs(),
            "absolute_error must equal |signed_error| for {}",
            record.opportunity_id
        );
        // signed_error = actual - predicted
        let expected_signed = record.actual_gain_millionths - record.predicted_gain_millionths;
        assert_eq!(
            record.signed_error_millionths, expected_signed,
            "signed_error mismatch for {}",
            record.opportunity_id
        );
    }
}

#[test]
fn enrichment_historical_tracking_sorted_by_timestamp() {
    // History records should come back sorted by completed_at_utc ascending.
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    // Provide observations out-of-order deliberately.
    request.historical_outcomes = vec![
        OpportunityOutcomeObservation {
            opportunity_id: "opp:z:last".to_string(),
            predicted_gain_millionths: 100_000,
            actual_gain_millionths: 90_000,
            completed_at_utc: "2026-03-03T00:00:00Z".to_string(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp:a:first".to_string(),
            predicted_gain_millionths: 200_000,
            actual_gain_millionths: 210_000,
            completed_at_utc: "2026-03-01T00:00:00Z".to_string(),
        },
        OpportunityOutcomeObservation {
            opportunity_id: "opp:m:mid".to_string(),
            predicted_gain_millionths: 150_000,
            actual_gain_millionths: 140_000,
            completed_at_utc: "2026-03-02T00:00:00Z".to_string(),
        },
    ];
    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.historical_tracking.len(), 3);
    let timestamps: Vec<&str> = decision
        .historical_tracking
        .iter()
        .map(|r| r.completed_at_utc.as_str())
        .collect();
    assert_eq!(timestamps[0], "2026-03-01T00:00:00Z");
    assert_eq!(timestamps[1], "2026-03-02T00:00:00Z");
    assert_eq!(timestamps[2], "2026-03-03T00:00:00Z");
}

#[test]
fn enrichment_hotspot_profile_entry_clone_and_debug() {
    let entry = HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 42,
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
    let debug_str = format!("{entry:?}");
    assert!(debug_str.contains("dispatch"));
    assert!(debug_str.contains("vm"));
}

#[test]
fn enrichment_opportunity_status_clone_and_debug() {
    for status in [
        OpportunityStatus::Selected,
        OpportunityStatus::RejectedLowScore,
        OpportunityStatus::RejectedSecurityClearance,
        OpportunityStatus::RejectedMissingHotspot,
    ] {
        let cloned = status.clone();
        assert_eq!(status, cloned);
        let debug_str = format!("{cloned:?}");
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn enrichment_decision_clone_and_debug() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let request = base_request_from_hotspots(hotspots);
    let decision = run_opportunity_matrix_scoring(&request);
    let cloned = decision.clone();
    assert_eq!(decision.matrix_id, cloned.matrix_id);
    assert_eq!(decision.outcome, cloned.outcome);
    let debug_str = format!("{decision:?}");
    assert!(debug_str.contains("matrix_id"));
}

#[test]
fn enrichment_deterministic_scoring_same_input_same_output() {
    // Running the scorer twice on identical input must produce byte-identical JSON.
    let hotspots = vec![
        HotspotProfileEntry {
            module: "vm".to_string(),
            function: "dispatch".to_string(),
            sample_count: 700,
        },
        HotspotProfileEntry {
            module: "gc".to_string(),
            function: "sweep".to_string(),
            sample_count: 200,
        },
    ];
    let request = base_request_from_hotspots(hotspots);
    let decision_a = run_opportunity_matrix_scoring(&request);
    let decision_b = run_opportunity_matrix_scoring(&request);

    let json_a = serde_json::to_string(&decision_a).expect("serialize a");
    let json_b = serde_json::to_string(&decision_b).expect("serialize b");
    assert_eq!(json_a, json_b, "scoring must be deterministic");
    assert_eq!(decision_a.matrix_id, decision_b.matrix_id);
    assert_eq!(
        decision_a.ranked_opportunities.len(),
        decision_b.ranked_opportunities.len()
    );
}

#[test]
fn enrichment_matrix_id_changes_when_request_changes() {
    // Changing any field in the request must change the matrix_id hash.
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let request_a = base_request_from_hotspots(hotspots.clone());
    let mut request_b = base_request_from_hotspots(hotspots);
    request_b.optimization_run_id = "opt-run-002-different".to_string();

    let decision_a = run_opportunity_matrix_scoring(&request_a);
    let decision_b = run_opportunity_matrix_scoring(&request_b);
    assert_ne!(
        decision_a.matrix_id, decision_b.matrix_id,
        "different requests must produce different matrix_ids"
    );
}

#[test]
fn enrichment_duplicate_opportunity_id_produces_fail() {
    let hotspots = vec![HotspotProfileEntry {
        module: "vm".to_string(),
        function: "dispatch".to_string(),
        sample_count: 100,
    }];
    let mut request = base_request_from_hotspots(hotspots);
    // Force a duplicate by inserting a second candidate with the same id.
    if let Some(first) = request.candidates.first().cloned() {
        request.candidates.push(first);
    }
    let decision = run_opportunity_matrix_scoring(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.error_code.is_some());
}

#[test]
fn enrichment_decision_serde_preserves_all_ranked_opportunities() {
    let artifacts = vec![flamegraph_artifact(
        "fg-serde",
        "bench-serde",
        vec![
            FoldedStackSample {
                stack: "vm;dispatch".to_string(),
                sample_count: 500,
            },
            FoldedStackSample {
                stack: "gc;sweep".to_string(),
                sample_count: 300,
            },
        ],
    )];
    let hotspots = hotspot_profile_from_flamegraphs(&artifacts);
    let request = base_request_from_hotspots(hotspots);
    let decision = run_opportunity_matrix_scoring(&request);
    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: OpportunityMatrixDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.ranked_opportunities.len(),
        decision.ranked_opportunities.len()
    );
    assert_eq!(recovered.schema_version, decision.schema_version);
    assert_eq!(recovered.optimization_run_id, decision.optimization_run_id);
    assert_eq!(
        recovered.score_threshold_millionths,
        decision.score_threshold_millionths
    );
}
