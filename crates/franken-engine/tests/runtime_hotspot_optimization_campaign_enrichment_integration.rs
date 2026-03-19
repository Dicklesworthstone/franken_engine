//! Enrichment integration tests for `runtime_hotspot_optimization_campaign`.
//!
//! Covers: edge-case arithmetic, multi-campaign ordering invariants,
//! cross-function consistency, serde field completeness, mixed improvement
//! and regression scoring, deterministic replay, classify_runtime_lever
//! path normalization edge cases, and emit_structured_events contract
//! verification.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use frankenengine_engine::runtime_hotspot_optimization_campaign::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mv(base: u64) -> MetricVector {
    MetricVector {
        scheduler_propagation_ns: base,
        dom_commit_batch_ns: base * 2,
        lane_router_decision_ns: base * 3,
        js_wasm_boundary_ns: base * 4,
        interaction_p95_latency_ns: base * 5,
    }
}

fn ev(impact: u64, confidence: u64, reuse: u64, effort: u64, friction: u64) -> EvInputs {
    EvInputs {
        impact,
        confidence,
        reuse,
        effort,
        friction,
    }
}

fn run(id: &str, baseline: u64, candidate: u64, inputs: EvInputs) -> CampaignRun {
    CampaignRun {
        campaign_id: id.into(),
        lever_id: format!("lever-{id}"),
        lever_category: "scheduler".into(),
        commit: "abc123".into(),
        run_id: format!("run-{id}"),
        generated_at_utc: "2026-03-19T00:00:00Z".into(),
        changed_paths: vec!["src/scheduler_lane.rs".into()],
        hotspot: HotspotEvidence {
            hotspot_id: format!("hs-{id}"),
            phase: "scheduler".into(),
            baseline_share_millionths: 350_000,
            baseline_profile_ref: "profile-abc".into(),
        },
        attribution_note: "attr".into(),
        baseline_metrics: mv(baseline),
        candidate_metrics: mv(candidate),
        ev_inputs: inputs,
        expected_ev_score_millionths: 0,
        expected_gain_millionths: 0,
        semantic_proof: SemanticProofNote {
            proof_method: "differential".into(),
            verification_contract_ref: "contract-xyz".into(),
            drift_status: "clean".into(),
        },
        rollback_plan_ref: "rollback-ref".into(),
        replay_command: "cargo test".into(),
        artifact_manifest: "manifest.json".into(),
        artifact_report: "report.json".into(),
    }
}

fn fixture(runs: Vec<CampaignRun>) -> RuntimeHotspotCampaignFixture {
    RuntimeHotspotCampaignFixture {
        schema_version: RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.into(),
        campaign_version: "v1".into(),
        metric_schema_version: "metrics-v1".into(),
        required_log_keys: vec!["trace_id".into()],
        campaign_runs: runs,
        expected_ev_ranking: vec![],
        expected_gain_ranking: vec![],
        expected_selected_campaign: String::new(),
        cross_subsystem_replay_scenarios: vec![],
    }
}

fn result(id: &str, ev_score: u64, gain: i64) -> RuntimeHotspotCampaignResult {
    RuntimeHotspotCampaignResult {
        campaign_id: id.into(),
        ev_score_millionths: ev_score,
        gain_millionths: gain,
    }
}

// =========================================================================
// 1. scaled_delta_lower_is_better — arithmetic edge cases
// =========================================================================

#[test]
fn enrichment_scaled_delta_100_percent_improvement() {
    // candidate=1 (clamped from 0) vs baseline=1000 -> near full improvement
    let d = scaled_delta_lower_is_better(1000, 1);
    assert_eq!(d, 999_000); // (999/1000)*1M
}

#[test]
fn enrichment_scaled_delta_double_regression() {
    let d = scaled_delta_lower_is_better(500, 1000);
    // (500-1000)/500 * 1M = -1_000_000
    assert_eq!(d, -1_000_000);
}

#[test]
fn enrichment_scaled_delta_tiny_values() {
    let d = scaled_delta_lower_is_better(2, 1);
    assert_eq!(d, 500_000);
}

#[test]
fn enrichment_scaled_delta_candidate_equals_one() {
    let d = scaled_delta_lower_is_better(1, 1);
    assert_eq!(d, 0);
}

#[test]
fn enrichment_scaled_delta_max_u64_baseline() {
    let d = scaled_delta_lower_is_better(u64::MAX, u64::MAX);
    assert_eq!(d, 0);
}

#[test]
fn enrichment_scaled_delta_max_u64_with_half() {
    let d = scaled_delta_lower_is_better(u64::MAX, u64::MAX / 2);
    assert!(d > 0);
}

// =========================================================================
// 2. ev_score_millionths — proportional behaviour
// =========================================================================

#[test]
fn enrichment_ev_score_double_impact_doubles_score() {
    let base = ev(5, 5, 5, 5, 5);
    let doubled = ev(10, 5, 5, 5, 5);
    let score_base = ev_score_millionths(&base);
    let score_doubled = ev_score_millionths(&doubled);
    assert_eq!(score_doubled, score_base * 2);
}

#[test]
fn enrichment_ev_score_zero_impact_gives_zero() {
    let inputs = ev(0, 10, 10, 10, 10);
    assert_eq!(ev_score_millionths(&inputs), 0);
}

#[test]
fn enrichment_ev_score_zero_confidence_gives_zero() {
    let inputs = ev(10, 0, 10, 10, 10);
    assert_eq!(ev_score_millionths(&inputs), 0);
}

#[test]
fn enrichment_ev_score_zero_reuse_gives_zero() {
    let inputs = ev(10, 10, 0, 10, 10);
    assert_eq!(ev_score_millionths(&inputs), 0);
}

#[test]
fn enrichment_ev_score_all_ones() {
    let inputs = ev(1, 1, 1, 1, 1);
    assert_eq!(ev_score_millionths(&inputs), 1_000_000);
}

#[test]
fn enrichment_ev_score_all_zero_numerator() {
    let inputs = ev(0, 0, 0, 1, 1);
    assert_eq!(ev_score_millionths(&inputs), 0);
}

// =========================================================================
// 3. campaign_gain_millionths — per-dimension isolation
// =========================================================================

#[test]
fn enrichment_gain_only_js_wasm_improved() {
    let mut r = run("x", 1000, 1000, ev(1, 1, 1, 1, 1));
    r.candidate_metrics.js_wasm_boundary_ns = 2000; // was 4000 (base*4)
    let gain = campaign_gain_millionths(&r);
    assert!(gain > 0);
}

#[test]
fn enrichment_gain_only_interaction_p95_regressed() {
    let mut r = run("x", 1000, 1000, ev(1, 1, 1, 1, 1));
    r.candidate_metrics.interaction_p95_latency_ns = 10_000; // was 5000 (base*5)
    let gain = campaign_gain_millionths(&r);
    assert!(gain < 0);
}

#[test]
fn enrichment_gain_all_zero_metrics() {
    let mut r = run("x", 1, 1, ev(1, 1, 1, 1, 1));
    r.baseline_metrics = MetricVector {
        scheduler_propagation_ns: 0,
        dom_commit_batch_ns: 0,
        lane_router_decision_ns: 0,
        js_wasm_boundary_ns: 0,
        interaction_p95_latency_ns: 0,
    };
    r.candidate_metrics = r.baseline_metrics.clone();
    let gain = campaign_gain_millionths(&r);
    assert_eq!(gain, 0);
}

// =========================================================================
// 4. rank_by_ev / rank_by_gain ordering invariants
// =========================================================================

#[test]
fn enrichment_rank_ev_descending_order_verified() {
    let results = vec![
        result("a", 100, 0),
        result("b", 300, 0),
        result("c", 200, 0),
    ];
    let ranked = rank_by_ev(&results);
    assert_eq!(ranked, vec!["b", "c", "a"]);
}

#[test]
fn enrichment_rank_gain_handles_mixed_sign() {
    let results = vec![
        result("neg", 0, -500),
        result("zero", 0, 0),
        result("pos", 0, 500),
    ];
    let ranked = rank_by_gain(&results);
    assert_eq!(ranked, vec!["pos", "zero", "neg"]);
}

#[test]
fn enrichment_rank_ev_stable_with_identical_scores() {
    let results = vec![
        result("z", 100, 0),
        result("a", 100, 0),
        result("m", 100, 0),
    ];
    let r1 = rank_by_ev(&results);
    let r2 = rank_by_ev(&results);
    assert_eq!(r1, r2);
    // Tie-break by campaign_id lexicographic
    assert_eq!(r1, vec!["a", "m", "z"]);
}

#[test]
fn enrichment_rank_gain_stable_with_identical_gains() {
    let results = vec![result("z", 0, 42), result("a", 0, 42)];
    let ranked = rank_by_gain(&results);
    assert_eq!(ranked, vec!["a", "z"]);
}

// =========================================================================
// 5. selected_campaign consistency with rank_by_ev
// =========================================================================

#[test]
fn enrichment_selected_always_matches_first_rank_by_ev() {
    let results = vec![
        result("low", 10, 9999),
        result("mid", 50, 1),
        result("high", 100, 0),
    ];
    let ev_ranked = rank_by_ev(&results);
    let sel = selected_campaign(&results);
    assert_eq!(sel, ev_ranked[0]);
}

#[test]
fn enrichment_selected_with_two_equal_ev_prefers_lex_smaller_id() {
    let results = vec![result("beta", 100, 0), result("alpha", 100, 0)];
    assert_eq!(selected_campaign(&results), "alpha");
}

// =========================================================================
// 6. compute_campaign_results consistency
// =========================================================================

#[test]
fn enrichment_compute_matches_individual_functions() {
    let inputs = ev(8, 6, 4, 3, 2);
    let r = run("c1", 1000, 700, inputs.clone());
    let expected_ev = ev_score_millionths(&inputs);
    let expected_gain = campaign_gain_millionths(&r);

    let fix = fixture(vec![r]);
    let results = compute_campaign_results(&fix);
    assert_eq!(results[0].ev_score_millionths, expected_ev);
    assert_eq!(results[0].gain_millionths, expected_gain);
}

#[test]
fn enrichment_compute_preserves_order() {
    let fix = fixture(vec![
        run("first", 1000, 800, ev(1, 1, 1, 1, 1)),
        run("second", 1000, 900, ev(1, 1, 1, 1, 1)),
    ]);
    let results = compute_campaign_results(&fix);
    assert_eq!(results[0].campaign_id, "first");
    assert_eq!(results[1].campaign_id, "second");
}

#[test]
fn enrichment_compute_five_campaigns() {
    let fix = fixture(vec![
        run("a", 1000, 500, ev(10, 10, 10, 1, 1)),
        run("b", 1000, 600, ev(5, 5, 5, 1, 1)),
        run("c", 1000, 700, ev(3, 3, 3, 1, 1)),
        run("d", 1000, 800, ev(2, 2, 2, 1, 1)),
        run("e", 1000, 1200, ev(1, 1, 1, 1, 1)),
    ]);
    let results = compute_campaign_results(&fix);
    assert_eq!(results.len(), 5);
    // a has highest gain (most improvement)
    assert!(results[0].gain_millionths > results[4].gain_millionths);
    // e has negative gain (regression)
    assert!(results[4].gain_millionths < 0);
}

// =========================================================================
// 7. classify_runtime_lever edge cases
// =========================================================================

#[test]
fn enrichment_classify_partial_match_scheduler() {
    // Must contain "scheduler_lane", not just "scheduler"
    assert_eq!(classify_runtime_lever("src/scheduler.rs"), None);
}

#[test]
fn enrichment_classify_mixed_case_wasm() {
    assert_eq!(
        classify_runtime_lever("src/WASM_RUNTIME_LANE.rs"),
        Some("js_wasm_boundary")
    );
}

#[test]
fn enrichment_classify_windows_double_backslash() {
    assert_eq!(
        classify_runtime_lever("c:\\projects\\src\\hybrid_lane_router.rs"),
        Some("lane_router")
    );
}

#[test]
fn enrichment_classify_deeply_nested() {
    assert_eq!(
        classify_runtime_lever("a/b/c/d/e/js_runtime_lane.rs"),
        Some("dom_commit")
    );
}

#[test]
fn enrichment_classify_all_none_paths() {
    for path in &[
        "src/lib.rs",
        "Cargo.toml",
        "",
        "random_file.rs",
        "src/scheduler.rs",
    ] {
        assert_eq!(classify_runtime_lever(path), None);
    }
}

// =========================================================================
// 8. emit_structured_events — contract verification
// =========================================================================

#[test]
fn enrichment_emit_event_decision_id_format() {
    let results = vec![result("camp-99", 100, 50)];
    let events = emit_structured_events(&results);
    assert_eq!(events[0].decision_id, "decision-camp-99");
}

#[test]
fn enrichment_emit_all_events_have_no_error_code() {
    let results = vec![
        result("a", 100, 50),
        result("b", 100, -50),
        result("c", 100, 0),
    ];
    let events = emit_structured_events(&results);
    for e in &events {
        assert!(e.error_code.is_none());
    }
}

#[test]
fn enrichment_emit_event_component_is_module_name() {
    let events = emit_structured_events(&[result("x", 1, 1)]);
    assert_eq!(events[0].component, "runtime_hotspot_optimization_campaign");
}

#[test]
fn enrichment_emit_events_len_matches_input() {
    for n in 0..5 {
        let results: Vec<_> = (0..n).map(|i| result(&format!("c{i}"), 1, 1)).collect();
        let events = emit_structured_events(&results);
        assert_eq!(events.len(), n);
    }
}

#[test]
fn enrichment_emit_boundary_gain_minus_one_is_regressed() {
    let events = emit_structured_events(&[result("x", 1, -1)]);
    assert_eq!(events[0].outcome, "regressed");
}

// =========================================================================
// 9. Full pipeline — deterministic replay
// =========================================================================

#[test]
fn enrichment_full_pipeline_deterministic() {
    let make_fixture = || {
        fixture(vec![
            run("alpha", 1000, 700, ev(10, 8, 5, 4, 2)),
            run("beta", 1000, 900, ev(5, 5, 5, 5, 5)),
            run("gamma", 1000, 1200, ev(1, 1, 1, 10, 10)),
        ])
    };

    let run_pipeline = || {
        let fix = make_fixture();
        let results = compute_campaign_results(&fix);
        let ev_ranking = rank_by_ev(&results);
        let gain_ranking = rank_by_gain(&results);
        let sel = selected_campaign(&results);
        let events = emit_structured_events(&results);
        (results, ev_ranking, gain_ranking, sel, events)
    };

    let (r1, ev1, g1, s1, e1) = run_pipeline();
    let (r2, ev2, g2, s2, e2) = run_pipeline();

    assert_eq!(r1, r2);
    assert_eq!(ev1, ev2);
    assert_eq!(g1, g2);
    assert_eq!(s1, s2);
    assert_eq!(e1, e2);
}

// =========================================================================
// 10. Serde — JSON field name stability
// =========================================================================

#[test]
fn enrichment_campaign_run_json_has_all_18_fields() {
    let r = run("c1", 100, 80, ev(1, 1, 1, 1, 1));
    let json = serde_json::to_value(&r).unwrap();
    let expected_fields = [
        "campaign_id",
        "lever_id",
        "lever_category",
        "commit",
        "run_id",
        "generated_at_utc",
        "changed_paths",
        "hotspot",
        "attribution_note",
        "baseline_metrics",
        "candidate_metrics",
        "ev_inputs",
        "expected_ev_score_millionths",
        "expected_gain_millionths",
        "semantic_proof",
        "rollback_plan_ref",
        "replay_command",
        "artifact_manifest",
    ];
    for field in &expected_fields {
        assert!(json.get(*field).is_some(), "missing field: {field}");
    }
}

#[test]
fn enrichment_runtime_hotspot_event_json_has_8_fields() {
    let event = RuntimeHotspotEvent {
        schema_version: "v1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: Some("err".into()),
    };
    let json = serde_json::to_value(&event).unwrap();
    for field in &[
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(json.get(*field).is_some(), "missing field: {field}");
    }
}

#[test]
fn enrichment_replay_scenario_fields_stable() {
    let rs = ReplayScenario {
        scenario_id: "s".into(),
        scenario_kind: "k".into(),
        replay_command: "cmd".into(),
        expected_pass: false,
        expected_outcome: "fail".into(),
    };
    let json = serde_json::to_value(&rs).unwrap();
    for field in &[
        "scenario_id",
        "scenario_kind",
        "replay_command",
        "expected_pass",
        "expected_outcome",
    ] {
        assert!(json.get(*field).is_some(), "missing field: {field}");
    }
}

// =========================================================================
// 11. Weight constants — additional validation
// =========================================================================

#[test]
fn enrichment_each_weight_is_200k() {
    assert_eq!(SCHEDULER_WEIGHT, 200_000);
    assert_eq!(DOM_COMMIT_WEIGHT, 200_000);
    assert_eq!(ROUTER_WEIGHT, 200_000);
    assert_eq!(JS_WASM_WEIGHT, 200_000);
    assert_eq!(INTERACTION_P95_WEIGHT, 200_000);
}

// =========================================================================
// 12. Campaign gain — symmetry analysis
// =========================================================================

#[test]
fn enrichment_gain_improvement_and_regression_opposite_sign() {
    let improved = run("imp", 1000, 500, ev(1, 1, 1, 1, 1));
    let regressed = run("reg", 500, 1000, ev(1, 1, 1, 1, 1));
    let g_imp = campaign_gain_millionths(&improved);
    let g_reg = campaign_gain_millionths(&regressed);
    assert!(g_imp > 0);
    assert!(g_reg < 0);
}
