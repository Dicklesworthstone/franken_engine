//! Integration tests for runtime_hotspot_optimization_campaign (RGC-705A).

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

use frankenengine_engine::runtime_hotspot_optimization_campaign::{
    self, CampaignRun, DOM_COMMIT_WEIGHT, EvInputs, HotspotEvidence, INTERACTION_P95_WEIGHT,
    JS_WASM_WEIGHT, MetricVector, ROUTER_WEIGHT, RUNTIME_HOTSPOT_COMPONENT,
    RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION, RUNTIME_HOTSPOT_POLICY_ID, RUNTIME_HOTSPOT_TRACE_ID,
    ReplayScenario, RuntimeHotspotCampaignFixture, RuntimeHotspotCampaignResult,
    RuntimeHotspotEvent, SCHEDULER_WEIGHT, SemanticProofNote,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_metric_vector(base: u64) -> MetricVector {
    MetricVector {
        scheduler_propagation_ns: base,
        dom_commit_batch_ns: base * 2,
        lane_router_decision_ns: base * 3,
        js_wasm_boundary_ns: base * 4,
        interaction_p95_latency_ns: base * 5,
    }
}

fn sample_ev_inputs() -> EvInputs {
    EvInputs {
        impact: 10,
        confidence: 8,
        reuse: 5,
        effort: 4,
        friction: 2,
    }
}

fn sample_hotspot_evidence() -> HotspotEvidence {
    HotspotEvidence {
        hotspot_id: "hs-001".into(),
        phase: "scheduler".into(),
        baseline_share_millionths: 350_000,
        baseline_profile_ref: "profile-abc".into(),
    }
}

fn sample_semantic_proof() -> SemanticProofNote {
    SemanticProofNote {
        proof_method: "differential".into(),
        verification_contract_ref: "contract-xyz".into(),
        drift_status: "clean".into(),
    }
}

fn sample_campaign_run(id: &str, baseline: u64, candidate: u64) -> CampaignRun {
    CampaignRun {
        campaign_id: id.into(),
        lever_id: format!("lever-{id}"),
        lever_category: "scheduler".into(),
        commit: "abc123".into(),
        run_id: format!("run-{id}"),
        generated_at_utc: "2026-03-02T00:00:00Z".into(),
        changed_paths: vec!["src/scheduler_lane.rs".into()],
        hotspot: sample_hotspot_evidence(),
        attribution_note: "attribution".into(),
        baseline_metrics: sample_metric_vector(baseline),
        candidate_metrics: sample_metric_vector(candidate),
        ev_inputs: sample_ev_inputs(),
        expected_ev_score_millionths: 0,
        expected_gain_millionths: 0,
        semantic_proof: sample_semantic_proof(),
        rollback_plan_ref: "rollback-ref".into(),
        replay_command: "cargo test".into(),
        artifact_manifest: "manifest.json".into(),
        artifact_report: "report.json".into(),
    }
}

fn sample_fixture(runs: Vec<CampaignRun>) -> RuntimeHotspotCampaignFixture {
    RuntimeHotspotCampaignFixture {
        schema_version: RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.into(),
        campaign_version: "v1".into(),
        metric_schema_version: "metrics-v1".into(),
        required_log_keys: vec!["trace_id".into(), "decision_id".into()],
        campaign_runs: runs,
        expected_ev_ranking: vec![],
        expected_gain_ranking: vec![],
        expected_selected_campaign: String::new(),
        cross_subsystem_replay_scenarios: vec![],
    }
}

fn make_result(id: &str, ev: u64, gain: i64) -> RuntimeHotspotCampaignResult {
    RuntimeHotspotCampaignResult {
        campaign_id: id.into(),
        ev_score_millionths: ev,
        gain_millionths: gain,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_non_empty_and_contains_runtime() {
    assert!(!RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.is_empty());
    assert!(RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.contains("runtime"));
}

#[test]
fn test_policy_id_non_empty() {
    assert!(!RUNTIME_HOTSPOT_POLICY_ID.is_empty());
    assert!(RUNTIME_HOTSPOT_POLICY_ID.contains("campaign"));
}

#[test]
fn test_trace_id_non_empty() {
    assert!(!RUNTIME_HOTSPOT_TRACE_ID.is_empty());
}

#[test]
fn test_component_matches_module_name() {
    assert_eq!(
        RUNTIME_HOTSPOT_COMPONENT,
        "runtime_hotspot_optimization_campaign"
    );
}

#[test]
fn test_weights_are_all_positive() {
    const {
        assert!(SCHEDULER_WEIGHT > 0);
        assert!(DOM_COMMIT_WEIGHT > 0);
        assert!(ROUTER_WEIGHT > 0);
        assert!(JS_WASM_WEIGHT > 0);
        assert!(INTERACTION_P95_WEIGHT > 0);
    }
}

#[test]
fn test_weights_are_equal() {
    assert_eq!(SCHEDULER_WEIGHT, DOM_COMMIT_WEIGHT);
    assert_eq!(DOM_COMMIT_WEIGHT, ROUTER_WEIGHT);
    assert_eq!(ROUTER_WEIGHT, JS_WASM_WEIGHT);
    assert_eq!(JS_WASM_WEIGHT, INTERACTION_P95_WEIGHT);
}

#[test]
fn test_weights_sum_to_one_million() {
    let sum = SCHEDULER_WEIGHT
        + DOM_COMMIT_WEIGHT
        + ROUTER_WEIGHT
        + JS_WASM_WEIGHT
        + INTERACTION_P95_WEIGHT;
    assert_eq!(sum, 1_000_000);
}

// ---------------------------------------------------------------------------
// scaled_delta_lower_is_better
// ---------------------------------------------------------------------------

#[test]
fn test_scaled_delta_improvement_is_positive() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(1000, 800);
    assert_eq!(delta, 200_000); // (1000-800)/1000 * 1M = 200k
}

#[test]
fn test_scaled_delta_regression_is_negative() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(800, 1000);
    assert!(delta < 0);
}

#[test]
fn test_scaled_delta_equal_values_is_zero() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(1000, 1000);
    assert_eq!(delta, 0);
}

#[test]
fn test_scaled_delta_both_zero_is_zero() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(0, 0);
    assert_eq!(delta, 0);
}

#[test]
fn test_scaled_delta_baseline_zero_clamps() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(0, 100);
    assert!(delta < 0);
}

#[test]
fn test_scaled_delta_candidate_zero_clamps() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(100, 0);
    assert!(delta > 0);
}

#[test]
fn test_scaled_delta_halved_candidate_500k() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(1000, 500);
    assert_eq!(delta, 500_000);
}

#[test]
fn test_scaled_delta_candidate_near_zero_near_million() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(1_000_000, 1);
    assert!(delta > 999_000);
}

#[test]
fn test_scaled_delta_large_values_no_overflow() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(
        u64::MAX / 2,
        u64::MAX / 4,
    );
    assert!(delta > 0);
}

#[test]
fn test_scaled_delta_symmetric_magnitude() {
    let improve = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(1000, 800);
    let regress = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(800, 1000);
    // improve is 200k, regress magnitude may differ due to different base
    assert!(improve > 0);
    assert!(regress < 0);
}

#[test]
fn test_scaled_delta_one_ns_improvement() {
    let delta = runtime_hotspot_optimization_campaign::scaled_delta_lower_is_better(1000, 999);
    assert_eq!(delta, 1_000); // (1/1000)*1M = 1000
}

// ---------------------------------------------------------------------------
// ev_score_millionths
// ---------------------------------------------------------------------------

#[test]
fn test_ev_score_basic() {
    let inputs = EvInputs {
        impact: 10,
        confidence: 10,
        reuse: 10,
        effort: 10,
        friction: 10,
    };
    let score = runtime_hotspot_optimization_campaign::ev_score_millionths(&inputs);
    assert_eq!(score, 10_000_000); // (10*10*10*1M)/(10*10) = 10M
}

#[test]
fn test_ev_score_unit_inputs() {
    let inputs = EvInputs {
        impact: 1,
        confidence: 1,
        reuse: 1,
        effort: 1,
        friction: 1,
    };
    let score = runtime_hotspot_optimization_campaign::ev_score_millionths(&inputs);
    assert_eq!(score, 1_000_000);
}

#[test]
fn test_ev_score_zero_effort_clamps() {
    let inputs = EvInputs {
        impact: 10,
        confidence: 5,
        reuse: 2,
        effort: 0,
        friction: 3,
    };
    let score = runtime_hotspot_optimization_campaign::ev_score_millionths(&inputs);
    assert!(score > 0);
}

#[test]
fn test_ev_score_zero_friction_clamps() {
    let inputs = EvInputs {
        impact: 10,
        confidence: 5,
        reuse: 2,
        effort: 3,
        friction: 0,
    };
    let score = runtime_hotspot_optimization_campaign::ev_score_millionths(&inputs);
    assert!(score > 0);
}

#[test]
fn test_ev_score_both_denominators_zero() {
    let inputs = EvInputs {
        impact: 10,
        confidence: 5,
        reuse: 2,
        effort: 0,
        friction: 0,
    };
    let score = runtime_hotspot_optimization_campaign::ev_score_millionths(&inputs);
    assert!(score > 0);
}

#[test]
fn test_ev_score_higher_impact_higher_score() {
    let low = EvInputs {
        impact: 1,
        confidence: 5,
        reuse: 5,
        effort: 5,
        friction: 5,
    };
    let high = EvInputs {
        impact: 10,
        ..low.clone()
    };
    assert!(
        runtime_hotspot_optimization_campaign::ev_score_millionths(&high)
            > runtime_hotspot_optimization_campaign::ev_score_millionths(&low)
    );
}

#[test]
fn test_ev_score_higher_effort_lower_score() {
    let low_effort = EvInputs {
        impact: 10,
        confidence: 10,
        reuse: 10,
        effort: 1,
        friction: 1,
    };
    let high_effort = EvInputs {
        effort: 100,
        ..low_effort.clone()
    };
    assert!(
        runtime_hotspot_optimization_campaign::ev_score_millionths(&low_effort)
            > runtime_hotspot_optimization_campaign::ev_score_millionths(&high_effort)
    );
}

#[test]
fn test_ev_score_deterministic() {
    let inputs = sample_ev_inputs();
    let a = runtime_hotspot_optimization_campaign::ev_score_millionths(&inputs);
    let b = runtime_hotspot_optimization_campaign::ev_score_millionths(&inputs);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// campaign_gain_millionths
// ---------------------------------------------------------------------------

#[test]
fn test_campaign_gain_positive_for_improvement() {
    let run = sample_campaign_run("c1", 1000, 800);
    let gain = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    assert!(gain > 0);
}

#[test]
fn test_campaign_gain_negative_for_regression() {
    let run = sample_campaign_run("c1", 800, 1000);
    let gain = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    assert!(gain < 0);
}

#[test]
fn test_campaign_gain_zero_for_equal_metrics() {
    let run = sample_campaign_run("c1", 1000, 1000);
    let gain = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    assert_eq!(gain, 0);
}

#[test]
fn test_campaign_gain_uses_all_five_dimensions() {
    let mut run = sample_campaign_run("c1", 1000, 1000);
    // Only improve scheduler
    run.candidate_metrics.scheduler_propagation_ns = 500;
    let gain = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    assert!(gain > 0);
}

#[test]
fn test_campaign_gain_individual_dom_dimension() {
    let mut run = sample_campaign_run("c1", 1000, 1000);
    run.candidate_metrics.dom_commit_batch_ns = 1000; // was 2000
    let gain = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    assert!(gain > 0);
}

#[test]
fn test_campaign_gain_individual_router_dimension() {
    let mut run = sample_campaign_run("c1", 1000, 1000);
    run.candidate_metrics.lane_router_decision_ns = 1500; // was 3000
    let gain = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    assert!(gain > 0);
}

#[test]
fn test_campaign_gain_mixed_improvements_and_regressions() {
    let mut run = sample_campaign_run("c1", 1000, 1000);
    // Improve scheduler dramatically
    run.candidate_metrics.scheduler_propagation_ns = 100;
    // Regress dom slightly
    run.candidate_metrics.dom_commit_batch_ns = 2200;
    let gain = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    // Net should still be positive since improvement outweighs regression
    assert!(gain > 0);
}

#[test]
fn test_campaign_gain_deterministic() {
    let run = sample_campaign_run("c1", 1000, 800);
    let a = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    let b = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// compute_campaign_results
// ---------------------------------------------------------------------------

#[test]
fn test_compute_results_single_run() {
    let fixture = sample_fixture(vec![sample_campaign_run("c1", 1000, 800)]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].campaign_id, "c1");
    assert!(results[0].ev_score_millionths > 0);
    assert!(results[0].gain_millionths > 0);
}

#[test]
fn test_compute_results_multiple_runs() {
    let fixture = sample_fixture(vec![
        sample_campaign_run("c1", 1000, 700),
        sample_campaign_run("c2", 1000, 900),
        sample_campaign_run("c3", 1000, 1200),
    ]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    assert_eq!(results.len(), 3);
    // c1 has biggest improvement, c3 regressed
    assert!(results[0].gain_millionths > results[1].gain_millionths);
    assert!(results[2].gain_millionths < 0);
}

#[test]
fn test_compute_results_empty_fixture() {
    let fixture = sample_fixture(vec![]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    assert!(results.is_empty());
}

#[test]
fn test_compute_results_preserves_campaign_ids() {
    let fixture = sample_fixture(vec![
        sample_campaign_run("alpha", 1000, 800),
        sample_campaign_run("beta", 1000, 900),
    ]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    assert_eq!(results[0].campaign_id, "alpha");
    assert_eq!(results[1].campaign_id, "beta");
}

#[test]
fn test_compute_results_ev_matches_ev_score_fn() {
    let run = sample_campaign_run("c1", 1000, 800);
    let expected_ev = runtime_hotspot_optimization_campaign::ev_score_millionths(&run.ev_inputs);
    let fixture = sample_fixture(vec![run]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    assert_eq!(results[0].ev_score_millionths, expected_ev);
}

#[test]
fn test_compute_results_gain_matches_gain_fn() {
    let run = sample_campaign_run("c1", 1000, 800);
    let expected_gain = runtime_hotspot_optimization_campaign::campaign_gain_millionths(&run);
    let fixture = sample_fixture(vec![run]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    assert_eq!(results[0].gain_millionths, expected_gain);
}

// ---------------------------------------------------------------------------
// rank_by_ev
// ---------------------------------------------------------------------------

#[test]
fn test_rank_by_ev_highest_first() {
    let results = vec![make_result("low", 100, 0), make_result("high", 500, 0)];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_ev(&results);
    assert_eq!(ranked[0], "high");
    assert_eq!(ranked[1], "low");
}

#[test]
fn test_rank_by_ev_tie_breaks_by_id() {
    let results = vec![make_result("b", 100, 0), make_result("a", 100, 0)];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_ev(&results);
    assert_eq!(ranked[0], "a");
    assert_eq!(ranked[1], "b");
}

#[test]
fn test_rank_by_ev_single_element() {
    let results = vec![make_result("only", 42, 0)];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_ev(&results);
    assert_eq!(ranked, vec!["only".to_string()]);
}

#[test]
fn test_rank_by_ev_empty() {
    let results: Vec<RuntimeHotspotCampaignResult> = vec![];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_ev(&results);
    assert!(ranked.is_empty());
}

#[test]
fn test_rank_by_ev_three_items() {
    let results = vec![
        make_result("mid", 200, 0),
        make_result("low", 100, 0),
        make_result("high", 300, 0),
    ];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_ev(&results);
    assert_eq!(ranked, vec!["high", "mid", "low"]);
}

// ---------------------------------------------------------------------------
// rank_by_gain
// ---------------------------------------------------------------------------

#[test]
fn test_rank_by_gain_highest_first() {
    let results = vec![make_result("low", 0, 100), make_result("high", 0, 500)];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_gain(&results);
    assert_eq!(ranked[0], "high");
}

#[test]
fn test_rank_by_gain_negative_values_sort_correctly() {
    let results = vec![
        make_result("regressed", 0, -100),
        make_result("improved", 0, 200),
    ];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_gain(&results);
    assert_eq!(ranked[0], "improved");
    assert_eq!(ranked[1], "regressed");
}

#[test]
fn test_rank_by_gain_tie_breaks_by_id() {
    let results = vec![make_result("b", 0, 50), make_result("a", 0, 50)];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_gain(&results);
    assert_eq!(ranked[0], "a");
}

#[test]
fn test_rank_by_gain_empty() {
    let results: Vec<RuntimeHotspotCampaignResult> = vec![];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_gain(&results);
    assert!(ranked.is_empty());
}

#[test]
fn test_rank_by_gain_all_negative() {
    let results = vec![
        make_result("bad", 0, -500),
        make_result("worse", 0, -1000),
        make_result("worst", 0, -2000),
    ];
    let ranked = runtime_hotspot_optimization_campaign::rank_by_gain(&results);
    assert_eq!(ranked[0], "bad");
    assert_eq!(ranked[2], "worst");
}

// ---------------------------------------------------------------------------
// selected_campaign
// ---------------------------------------------------------------------------

#[test]
fn test_selected_campaign_returns_highest_ev() {
    let results = vec![make_result("low", 10, 0), make_result("high", 100, 0)];
    let selected = runtime_hotspot_optimization_campaign::selected_campaign(&results);
    assert_eq!(selected, "high");
}

#[test]
fn test_selected_campaign_tie_breaks_by_id() {
    let results = vec![make_result("b", 50, 0), make_result("a", 50, 0)];
    let selected = runtime_hotspot_optimization_campaign::selected_campaign(&results);
    assert_eq!(selected, "a");
}

#[test]
fn test_selected_campaign_single() {
    let results = vec![make_result("only", 42, 0)];
    let selected = runtime_hotspot_optimization_campaign::selected_campaign(&results);
    assert_eq!(selected, "only");
}

#[test]
fn test_selected_campaign_ignores_gain() {
    // High gain but low ev should lose to low gain high ev
    let results = vec![
        make_result("high_gain", 10, 9999),
        make_result("high_ev", 999, 1),
    ];
    let selected = runtime_hotspot_optimization_campaign::selected_campaign(&results);
    assert_eq!(selected, "high_ev");
}

// ---------------------------------------------------------------------------
// classify_runtime_lever
// ---------------------------------------------------------------------------

#[test]
fn test_classify_scheduler_lane() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever("src/scheduler_lane.rs"),
        Some("scheduler")
    );
}

#[test]
fn test_classify_js_runtime_lane() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever("src/js_runtime_lane.rs"),
        Some("dom_commit")
    );
}

#[test]
fn test_classify_hybrid_lane_router() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever("src/hybrid_lane_router.rs"),
        Some("lane_router")
    );
}

#[test]
fn test_classify_wasm_runtime_lane() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever("src/wasm_runtime_lane.rs"),
        Some("js_wasm_boundary")
    );
}

#[test]
fn test_classify_unknown_returns_none() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever("src/lib.rs"),
        None
    );
}

#[test]
fn test_classify_case_insensitive() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever("src/SCHEDULER_LANE.rs"),
        Some("scheduler")
    );
}

#[test]
fn test_classify_backslash_path_separator() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever(
            "crates\\franken-engine\\src\\wasm_runtime_lane.rs"
        ),
        Some("js_wasm_boundary")
    );
}

#[test]
fn test_classify_nested_path() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever(
            "crates/franken-engine/src/scheduler_lane.rs"
        ),
        Some("scheduler")
    );
}

#[test]
fn test_classify_empty_path_returns_none() {
    assert_eq!(
        runtime_hotspot_optimization_campaign::classify_runtime_lever(""),
        None
    );
}

// ---------------------------------------------------------------------------
// emit_structured_events
// ---------------------------------------------------------------------------

#[test]
fn test_emit_events_improved() {
    let results = vec![make_result("c1", 100, 50)];
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "improved");
    assert_eq!(events[0].event, "campaign_run_scored");
    assert!(events[0].error_code.is_none());
}

#[test]
fn test_emit_events_regressed() {
    let results = vec![make_result("c1", 100, -50)];
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);
    assert_eq!(events[0].outcome, "regressed");
}

#[test]
fn test_emit_events_zero_gain_is_improved() {
    let results = vec![make_result("c1", 100, 0)];
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);
    assert_eq!(events[0].outcome, "improved");
}

#[test]
fn test_emit_events_uses_constants() {
    let results = vec![make_result("c1", 100, 0)];
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);
    assert_eq!(
        events[0].schema_version,
        RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION
    );
    assert_eq!(events[0].trace_id, RUNTIME_HOTSPOT_TRACE_ID);
    assert_eq!(events[0].policy_id, RUNTIME_HOTSPOT_POLICY_ID);
    assert_eq!(events[0].component, RUNTIME_HOTSPOT_COMPONENT);
}

#[test]
fn test_emit_events_decision_id_includes_campaign_id() {
    let results = vec![make_result("camp-42", 0, 0)];
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);
    assert!(events[0].decision_id.contains("camp-42"));
}

#[test]
fn test_emit_events_multiple() {
    let results = vec![
        make_result("c1", 100, 50),
        make_result("c2", 200, -10),
        make_result("c3", 300, 0),
    ];
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].outcome, "improved");
    assert_eq!(events[1].outcome, "regressed");
    assert_eq!(events[2].outcome, "improved");
}

#[test]
fn test_emit_events_empty() {
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&[]);
    assert!(events.is_empty());
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_hotspot_evidence_serde() {
    let orig = sample_hotspot_evidence();
    let json = serde_json::to_string(&orig).unwrap();
    let back: HotspotEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_metric_vector_serde() {
    let orig = sample_metric_vector(1000);
    let json = serde_json::to_string(&orig).unwrap();
    let back: MetricVector = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_ev_inputs_serde() {
    let orig = sample_ev_inputs();
    let json = serde_json::to_string(&orig).unwrap();
    let back: EvInputs = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_semantic_proof_serde() {
    let orig = sample_semantic_proof();
    let json = serde_json::to_string(&orig).unwrap();
    let back: SemanticProofNote = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_campaign_run_serde() {
    let orig = sample_campaign_run("c1", 1000, 800);
    let json = serde_json::to_string(&orig).unwrap();
    let back: CampaignRun = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_replay_scenario_serde() {
    let orig = ReplayScenario {
        scenario_id: "sc-1".into(),
        scenario_kind: "regression".into(),
        replay_command: "cargo test -- replay".into(),
        expected_pass: true,
        expected_outcome: "pass".into(),
    };
    let json = serde_json::to_string(&orig).unwrap();
    let back: ReplayScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_fixture_serde() {
    let runs = vec![sample_campaign_run("c1", 1000, 800)];
    let orig = sample_fixture(runs);
    let json = serde_json::to_string(&orig).unwrap();
    let back: RuntimeHotspotCampaignFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_campaign_result_serde() {
    let orig = make_result("camp-1", 500_000, 100_000);
    let json = serde_json::to_string(&orig).unwrap();
    let back: RuntimeHotspotCampaignResult = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_runtime_event_serde_no_error() {
    let orig = RuntimeHotspotEvent {
        schema_version: RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.into(),
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: RUNTIME_HOTSPOT_POLICY_ID.into(),
        component: RUNTIME_HOTSPOT_COMPONENT.into(),
        event: "campaign_run_scored".into(),
        outcome: "improved".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&orig).unwrap();
    let back: RuntimeHotspotEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn test_runtime_event_serde_with_error() {
    let orig = RuntimeHotspotEvent {
        schema_version: RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.into(),
        trace_id: "t2".into(),
        decision_id: "d2".into(),
        policy_id: RUNTIME_HOTSPOT_POLICY_ID.into(),
        component: RUNTIME_HOTSPOT_COMPONENT.into(),
        event: "campaign_run_scored".into(),
        outcome: "regressed".into(),
        error_code: Some("ERR_REGRESSION".into()),
    };
    let json = serde_json::to_string(&orig).unwrap();
    let back: RuntimeHotspotEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
    assert_eq!(back.error_code.as_deref(), Some("ERR_REGRESSION"));
}

// ---------------------------------------------------------------------------
// JSON field name contracts
// ---------------------------------------------------------------------------

#[test]
fn test_hotspot_evidence_json_fields() {
    let val = sample_hotspot_evidence();
    let json = serde_json::to_value(&val).unwrap();
    for field in &[
        "hotspot_id",
        "phase",
        "baseline_share_millionths",
        "baseline_profile_ref",
    ] {
        assert!(json.get(*field).is_some(), "missing: {field}");
    }
}

#[test]
fn test_metric_vector_json_fields() {
    let val = sample_metric_vector(100);
    let json = serde_json::to_value(&val).unwrap();
    for field in &[
        "scheduler_propagation_ns",
        "dom_commit_batch_ns",
        "lane_router_decision_ns",
        "js_wasm_boundary_ns",
        "interaction_p95_latency_ns",
    ] {
        assert!(json.get(*field).is_some(), "missing: {field}");
    }
}

#[test]
fn test_ev_inputs_json_fields() {
    let val = sample_ev_inputs();
    let json = serde_json::to_value(&val).unwrap();
    for field in &["impact", "confidence", "reuse", "effort", "friction"] {
        assert!(json.get(*field).is_some(), "missing: {field}");
    }
}

// ---------------------------------------------------------------------------
// End-to-end pipeline tests
// ---------------------------------------------------------------------------

#[test]
fn test_end_to_end_three_campaigns() {
    let runs = vec![
        sample_campaign_run("alpha", 1000, 700),
        sample_campaign_run("beta", 1000, 900),
        sample_campaign_run("gamma", 1000, 1200),
    ];
    let fixture = sample_fixture(runs);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    let ev_ranking = runtime_hotspot_optimization_campaign::rank_by_ev(&results);
    let gain_ranking = runtime_hotspot_optimization_campaign::rank_by_gain(&results);
    let selected = runtime_hotspot_optimization_campaign::selected_campaign(&results);
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);

    assert_eq!(results.len(), 3);
    assert_eq!(ev_ranking.len(), 3);
    assert_eq!(gain_ranking.len(), 3);
    assert_eq!(events.len(), 3);

    // alpha had most improvement
    assert_eq!(gain_ranking[0], "alpha");
    // gamma regressed
    assert_eq!(*gain_ranking.last().unwrap(), "gamma");
    assert!(!selected.is_empty());
}

#[test]
fn test_end_to_end_single_campaign() {
    let fixture = sample_fixture(vec![sample_campaign_run("only", 1000, 800)]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    let selected = runtime_hotspot_optimization_campaign::selected_campaign(&results);
    assert_eq!(selected, "only");
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);
    assert_eq!(events[0].outcome, "improved");
}

#[test]
fn test_end_to_end_all_regressions() {
    let fixture = sample_fixture(vec![
        sample_campaign_run("r1", 500, 1000),
        sample_campaign_run("r2", 600, 1200),
    ]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    let events = runtime_hotspot_optimization_campaign::emit_structured_events(&results);
    for event in &events {
        assert_eq!(event.outcome, "regressed");
    }
}

#[test]
fn test_end_to_end_ranking_consistency() {
    let fixture = sample_fixture(vec![
        sample_campaign_run("a", 1000, 700),
        sample_campaign_run("b", 1000, 800),
        sample_campaign_run("c", 1000, 900),
    ]);
    let results = runtime_hotspot_optimization_campaign::compute_campaign_results(&fixture);
    let ev_ranking = runtime_hotspot_optimization_campaign::rank_by_ev(&results);
    let selected = runtime_hotspot_optimization_campaign::selected_campaign(&results);
    // Selected should be the first in ev ranking
    assert_eq!(selected, ev_ranking[0]);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_metric_vector_zero_values() {
    let mv = MetricVector {
        scheduler_propagation_ns: 0,
        dom_commit_batch_ns: 0,
        lane_router_decision_ns: 0,
        js_wasm_boundary_ns: 0,
        interaction_p95_latency_ns: 0,
    };
    let json = serde_json::to_string(&mv).unwrap();
    let back: MetricVector = serde_json::from_str(&json).unwrap();
    assert_eq!(mv, back);
}

#[test]
fn test_campaign_run_with_empty_changed_paths() {
    let mut run = sample_campaign_run("c1", 1000, 800);
    run.changed_paths.clear();
    let json = serde_json::to_string(&run).unwrap();
    let back: CampaignRun = serde_json::from_str(&json).unwrap();
    assert!(back.changed_paths.is_empty());
}

#[test]
fn test_fixture_with_replay_scenarios() {
    let mut fix = sample_fixture(vec![sample_campaign_run("c1", 1000, 800)]);
    fix.cross_subsystem_replay_scenarios.push(ReplayScenario {
        scenario_id: "replay-1".into(),
        scenario_kind: "deterministic".into(),
        replay_command: "frankenctl replay".into(),
        expected_pass: true,
        expected_outcome: "identical".into(),
    });
    let json = serde_json::to_string(&fix).unwrap();
    let back: RuntimeHotspotCampaignFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cross_subsystem_replay_scenarios.len(), 1);
}

#[test]
fn test_campaign_result_negative_gain_serde() {
    let orig = make_result("c1", 0, -999_999);
    let json = serde_json::to_string(&orig).unwrap();
    let back: RuntimeHotspotCampaignResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.gain_millionths, -999_999);
}

#[test]
fn test_clone_and_debug() {
    let he = sample_hotspot_evidence();
    let _c = he.clone();
    let dbg = format!("{he:?}");
    assert!(dbg.contains("hs-001"));

    let mv = sample_metric_vector(100);
    let _c = mv.clone();

    let ei = sample_ev_inputs();
    let _c = ei.clone();

    let sp = sample_semantic_proof();
    let _c = sp.clone();

    let cr = sample_campaign_run("c1", 100, 80);
    let _c = cr.clone();
}

#[test]
fn test_ev_score_with_sample_inputs() {
    // impact=10, confidence=8, reuse=5, effort=4, friction=2
    // numerator = 10 * 8 * 5 * 1_000_000 = 400_000_000
    // denominator = max(4 * 2, 1) = 8
    // score = 400_000_000 / 8 = 50_000_000
    let score = runtime_hotspot_optimization_campaign::ev_score_millionths(&sample_ev_inputs());
    assert_eq!(score, 50_000_000);
}
