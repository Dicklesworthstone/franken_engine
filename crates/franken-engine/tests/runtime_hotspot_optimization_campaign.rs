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

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use frankenengine_engine::runtime_hotspot_optimization_campaign::{
    CampaignRun, DOM_COMMIT_WEIGHT, EvInputs, HotspotEvidence, INTERACTION_P95_WEIGHT,
    JS_WASM_WEIGHT, MetricVector, ROUTER_WEIGHT, RUNTIME_HOTSPOT_COMPONENT,
    RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION, RUNTIME_HOTSPOT_POLICY_ID, RUNTIME_HOTSPOT_TRACE_ID,
    ReplayScenario, RuntimeHotspotCampaignFixture, RuntimeHotspotCampaignResult,
    RuntimeHotspotEvent, SCHEDULER_WEIGHT, SemanticProofNote, campaign_gain_millionths,
    classify_runtime_lever, compute_campaign_results, emit_structured_events, ev_score_millionths,
    rank_by_ev, rank_by_gain, scaled_delta_lower_is_better, selected_campaign,
};

fn load_fixture() -> RuntimeHotspotCampaignFixture {
    let path = Path::new("tests/fixtures/runtime_hotspot_optimization_campaign_v1.json");
    let bytes = fs::read(path).expect("read runtime hotspot fixture");
    serde_json::from_slice(&bytes).expect("deserialize runtime hotspot fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/RUNTIME_HOTSPOT_OPTIMIZATION_CAMPAIGN.md");
    fs::read_to_string(path).expect("read runtime hotspot contract doc")
}

fn load_gate_script() -> String {
    let path = Path::new("../../scripts/run_runtime_hotspot_optimization_campaign.sh");
    fs::read_to_string(path).expect("read runtime hotspot gate script")
}

#[test]
fn runtime_hotspot_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Runtime Hotspot Optimization Campaign Contract (`bd-mjh3.6.3`)",
        "## Runtime Hotspot Targets",
        "## EV Scoring Contract",
        "## Gain Attribution Contract",
        "## Structured Log Contract",
        "./scripts/run_runtime_hotspot_optimization_campaign.sh ci",
        "./scripts/e2e/runtime_hotspot_optimization_campaign_replay.sh",
    ] {
        assert!(doc.contains(section), "missing doc section: {section}");
    }
}

#[test]
fn runtime_hotspot_fixture_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.runtime-hotspot-optimization-campaign.v1"
    );
    assert_eq!(fixture.campaign_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.runtime-hotspot-telemetry.v1"
    );
    assert!(!fixture.campaign_runs.is_empty());
    assert_eq!(fixture.campaign_runs.len(), 4);

    let required_keys: BTreeSet<&str> = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for key in [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(required_keys.contains(key), "missing required key `{key}`");
    }
}

#[test]
fn runtime_hotspot_campaigns_are_profile_justified_and_single_lever() {
    let fixture = load_fixture();

    for run in &fixture.campaign_runs {
        assert!(!run.campaign_id.trim().is_empty());
        assert!(!run.lever_id.trim().is_empty());
        assert!(!run.lever_category.trim().is_empty());
        assert!(!run.commit.trim().is_empty());
        assert!(!run.run_id.trim().is_empty());
        assert!(!run.generated_at_utc.trim().is_empty());
        assert!(!run.attribution_note.trim().is_empty());
        assert!(!run.rollback_plan_ref.trim().is_empty());
        assert!(!run.replay_command.trim().is_empty());
        assert!(!run.artifact_manifest.trim().is_empty());
        assert!(!run.artifact_report.trim().is_empty());
        assert!(run.hotspot.baseline_share_millionths > 0);
        assert!(run.hotspot.baseline_share_millionths <= 1_000_000);
        assert!(!run.hotspot.hotspot_id.trim().is_empty());
        assert!(!run.hotspot.phase.trim().is_empty());
        assert!(!run.hotspot.baseline_profile_ref.trim().is_empty());
        assert!(run.ev_inputs.effort > 0);
        assert!(run.ev_inputs.friction > 0);
        assert!(!run.semantic_proof.proof_method.trim().is_empty());
        assert!(
            !run.semantic_proof
                .verification_contract_ref
                .trim()
                .is_empty()
        );
        assert_eq!(run.semantic_proof.drift_status, "no_drift");

        let mut categories = BTreeSet::new();
        for path in &run.changed_paths {
            let category = classify_runtime_lever(path)
                .unwrap_or_else(|| panic!("unclassified runtime path `{path}`"));
            categories.insert(category);
        }
        assert_eq!(
            categories.len(),
            1,
            "campaign {} must remain single-lever",
            run.campaign_id
        );
    }
}

#[test]
fn runtime_hotspot_ev_and_gain_rankings_match_fixture() {
    let fixture = load_fixture();
    let results = compute_campaign_results(&fixture);
    assert_eq!(results.len(), fixture.campaign_runs.len());

    for run in &fixture.campaign_runs {
        let measured_ev = ev_score_millionths(&run.ev_inputs);
        assert_eq!(measured_ev, run.expected_ev_score_millionths);
        let measured_gain = campaign_gain_millionths(run);
        assert_eq!(measured_gain, run.expected_gain_millionths);
    }

    assert_eq!(rank_by_ev(&results), fixture.expected_ev_ranking);
    assert_eq!(rank_by_gain(&results), fixture.expected_gain_ranking);
    assert_eq!(
        selected_campaign(&results),
        fixture.expected_selected_campaign
    );
}

#[test]
fn runtime_hotspot_events_and_replay_contract_are_deterministic() {
    let fixture = load_fixture();
    let events = emit_structured_events(&compute_campaign_results(&fixture));
    assert_eq!(events.len(), fixture.campaign_runs.len());
    for event in events {
        let event = serde_json::to_value(event).expect("serialize runtime hotspot event");
        for key in [
            "schema_version",
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "outcome",
            "error_code",
        ] {
            assert!(event.get(key).is_some(), "missing event key `{key}`");
        }
    }

    let scenario_kinds = fixture
        .cross_subsystem_replay_scenarios
        .iter()
        .map(|scenario| scenario.scenario_kind.as_str())
        .collect::<BTreeSet<_>>();
    assert!(scenario_kinds.contains("normal"));
    assert!(scenario_kinds.contains("adversarial"));
    assert!(scenario_kinds.contains("recovery"));
    for scenario in &fixture.cross_subsystem_replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(!scenario.replay_command.trim().is_empty());
        assert!(!scenario.expected_outcome.trim().is_empty());
        if scenario.scenario_kind == "adversarial" {
            assert!(
                !scenario.expected_pass,
                "adversarial scenario should be fail-closed"
            );
        }
    }
}

#[test]
fn runtime_hotspot_gate_script_fail_closed_guards_are_present() {
    let script = load_gate_script();
    for marker in [
        "Remote toolchain failure, falling back to local",
        "running locally",
        "Dependency preflight blocked remote execution",
        "RCH-E326",
        "rch-local-fallback-detected",
        "rch_reject_missing_remote_exit",
        "rch-remote-exit-missing",
        "rch_reject_artifact_retrieval_failure",
        "rch_has_recoverable_artifact_timeout",
        "rch-artifact-retrieval-failed",
    ] {
        assert!(
            script.contains(marker),
            "missing fail-closed marker `{marker}` in gate script"
        );
    }
}

#[test]
fn runtime_hotspot_gate_script_ci_mode_short_circuits_on_first_failure() {
    let script = load_gate_script();
    let ci_block = script
        .split("ci)")
        .nth(1)
        .and_then(|rest| rest.split(";;").next())
        .expect("ci mode block must exist");
    for command in [
        "cargo check -p frankenengine-engine --test runtime_hotspot_optimization_campaign",
        "cargo test -p frankenengine-engine --test runtime_hotspot_optimization_campaign",
        "cargo clippy -p frankenengine-engine --test runtime_hotspot_optimization_campaign -- -D warnings",
    ] {
        let required = format!("{command} || return 1");
        assert!(
            ci_block.contains(&required),
            "ci mode must short-circuit failed step `{command}`"
        );
    }
}

#[test]
fn runtime_hotspot_gate_script_emits_step_log_artifacts() {
    let script = load_gate_script();
    for marker in [
        "step_logs_dir=\"${run_dir}/step_logs\"",
        "step_logs_index_path=\"${run_dir}/step_logs.txt\"",
        "printf '%s\\n' \"${step_logs[@]}\" >\"$step_logs_index_path\"",
        "echo \"    \\\"step_logs_index\\\": \\\"${step_logs_index_path}\\\",\"",
        "echo \"    \\\"step_logs_dir\\\": \\\"${step_logs_dir}\\\",\"",
        "echo \"    \\\"cat ${step_logs_index_path}\\\",\"",
    ] {
        assert!(
            script.contains(marker),
            "missing step-log artifact marker `{marker}` in gate script"
        );
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: Helper builders (shared across enrichment tests)
// ────────────────────────────────────────────────────────────

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
        hotspot_id: "hs-int-001".into(),
        phase: "scheduler".into(),
        baseline_share_millionths: 350_000,
        baseline_profile_ref: "profile-int-abc".into(),
    }
}

fn sample_semantic_proof() -> SemanticProofNote {
    SemanticProofNote {
        proof_method: "differential".into(),
        verification_contract_ref: "contract-int-xyz".into(),
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
        generated_at_utc: "2026-03-04T00:00:00Z".into(),
        changed_paths: vec!["src/scheduler_lane.rs".into()],
        hotspot: sample_hotspot_evidence(),
        attribution_note: "integration test attribution".into(),
        baseline_metrics: sample_metric_vector(baseline),
        candidate_metrics: sample_metric_vector(candidate),
        ev_inputs: sample_ev_inputs(),
        expected_ev_score_millionths: 0,
        expected_gain_millionths: 0,
        semantic_proof: sample_semantic_proof(),
        rollback_plan_ref: "rollback-ref-int".into(),
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

// ────────────────────────────────────────────────────────────
// Enrichment: Constants stability
// ────────────────────────────────────────────────────────────

#[test]
fn schema_version_constant_is_stable() {
    assert_eq!(
        RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION,
        "franken-engine.runtime-log-event.v1"
    );
}

#[test]
fn policy_id_constant_is_stable() {
    assert_eq!(
        RUNTIME_HOTSPOT_POLICY_ID,
        "policy-runtime-hotspot-campaign-v1"
    );
}

#[test]
fn trace_id_constant_is_stable() {
    assert_eq!(
        RUNTIME_HOTSPOT_TRACE_ID,
        "trace-runtime-hotspot-campaign-v1"
    );
}

#[test]
fn component_constant_is_stable() {
    assert_eq!(
        RUNTIME_HOTSPOT_COMPONENT,
        "runtime_hotspot_optimization_campaign"
    );
}

#[test]
fn weight_constants_sum_to_one_million() {
    let sum = SCHEDULER_WEIGHT
        + DOM_COMMIT_WEIGHT
        + ROUTER_WEIGHT
        + JS_WASM_WEIGHT
        + INTERACTION_P95_WEIGHT;
    assert_eq!(sum, 1_000_000);
}

#[test]
fn weight_constants_are_equal() {
    assert_eq!(SCHEDULER_WEIGHT, 200_000);
    assert_eq!(DOM_COMMIT_WEIGHT, 200_000);
    assert_eq!(ROUTER_WEIGHT, 200_000);
    assert_eq!(JS_WASM_WEIGHT, 200_000);
    assert_eq!(INTERACTION_P95_WEIGHT, 200_000);
}

// ────────────────────────────────────────────────────────────
// Enrichment: scaled_delta_lower_is_better
// ────────────────────────────────────────────────────────────

#[test]
fn scaled_delta_improvement_is_positive() {
    let delta = scaled_delta_lower_is_better(1000, 800);
    assert_eq!(delta, 200_000);
}

#[test]
fn scaled_delta_regression_is_negative() {
    let delta = scaled_delta_lower_is_better(800, 1000);
    assert!(delta < 0);
}

#[test]
fn scaled_delta_equal_values_is_zero() {
    assert_eq!(scaled_delta_lower_is_better(1000, 1000), 0);
}

#[test]
fn scaled_delta_both_zero_is_zero() {
    assert_eq!(scaled_delta_lower_is_better(0, 0), 0);
}

#[test]
fn scaled_delta_halved_candidate_returns_500k() {
    assert_eq!(scaled_delta_lower_is_better(1000, 500), 500_000);
}

#[test]
fn scaled_delta_large_values_no_overflow() {
    let delta = scaled_delta_lower_is_better(u64::MAX / 2, u64::MAX / 4);
    assert!(delta > 0);
}

// ────────────────────────────────────────────────────────────
// Enrichment: ev_score_millionths
// ────────────────────────────────────────────────────────────

#[test]
fn ev_score_basic_unit_inputs() {
    let inputs = EvInputs {
        impact: 1,
        confidence: 1,
        reuse: 1,
        effort: 1,
        friction: 1,
    };
    assert_eq!(ev_score_millionths(&inputs), 1_000_000);
}

#[test]
fn ev_score_10x_all_inputs() {
    let inputs = EvInputs {
        impact: 10,
        confidence: 10,
        reuse: 10,
        effort: 10,
        friction: 10,
    };
    assert_eq!(ev_score_millionths(&inputs), 10_000_000);
}

#[test]
fn ev_score_zero_effort_clamps() {
    let inputs = EvInputs {
        impact: 10,
        confidence: 5,
        reuse: 2,
        effort: 0,
        friction: 3,
    };
    assert!(ev_score_millionths(&inputs) > 0);
}

#[test]
fn ev_score_high_effort_reduces() {
    let low = EvInputs {
        impact: 10,
        confidence: 10,
        reuse: 10,
        effort: 1,
        friction: 1,
    };
    let high = EvInputs {
        effort: 100,
        ..low.clone()
    };
    assert!(ev_score_millionths(&low) > ev_score_millionths(&high));
}

// ────────────────────────────────────────────────────────────
// Enrichment: campaign_gain_millionths
// ────────────────────────────────────────────────────────────

#[test]
fn campaign_gain_positive_for_improvement() {
    let run = sample_campaign_run("c1", 1000, 800);
    assert!(campaign_gain_millionths(&run) > 0);
}

#[test]
fn campaign_gain_negative_for_regression() {
    let run = sample_campaign_run("c1", 800, 1000);
    assert!(campaign_gain_millionths(&run) < 0);
}

#[test]
fn campaign_gain_zero_for_equal() {
    let run = sample_campaign_run("c1", 1000, 1000);
    assert_eq!(campaign_gain_millionths(&run), 0);
}

#[test]
fn campaign_gain_uses_all_five_dimensions() {
    let mut run = sample_campaign_run("c1", 1000, 1000);
    run.candidate_metrics.scheduler_propagation_ns = 500;
    assert!(
        campaign_gain_millionths(&run) > 0,
        "should reflect scheduler improvement"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: classify_runtime_lever
// ────────────────────────────────────────────────────────────

#[test]
fn classify_all_known_lever_paths() {
    assert_eq!(
        classify_runtime_lever("src/scheduler_lane.rs"),
        Some("scheduler")
    );
    assert_eq!(
        classify_runtime_lever("src/js_runtime_lane.rs"),
        Some("dom_commit")
    );
    assert_eq!(
        classify_runtime_lever("src/hybrid_lane_router.rs"),
        Some("lane_router")
    );
    assert_eq!(
        classify_runtime_lever("src/wasm_runtime_lane.rs"),
        Some("js_wasm_boundary")
    );
}

#[test]
fn classify_unknown_path_returns_none() {
    assert_eq!(classify_runtime_lever("src/lib.rs"), None);
    assert_eq!(classify_runtime_lever("src/main.rs"), None);
}

#[test]
fn classify_case_insensitive() {
    assert_eq!(
        classify_runtime_lever("src/SCHEDULER_LANE.rs"),
        Some("scheduler")
    );
}

#[test]
fn classify_backslash_path_normalized() {
    assert_eq!(
        classify_runtime_lever("crates\\franken-engine\\src\\wasm_runtime_lane.rs"),
        Some("js_wasm_boundary")
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: compute_campaign_results
// ────────────────────────────────────────────────────────────

#[test]
fn compute_results_single_run() {
    let runs = vec![sample_campaign_run("c1", 1000, 800)];
    let fixture = sample_fixture(runs);
    let results = compute_campaign_results(&fixture);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].campaign_id, "c1");
    assert!(results[0].ev_score_millionths > 0);
    assert!(results[0].gain_millionths > 0);
}

#[test]
fn compute_results_multiple_runs_ordered_by_gain() {
    let runs = vec![
        sample_campaign_run("c1", 1000, 800),
        sample_campaign_run("c2", 1000, 900),
        sample_campaign_run("c3", 1000, 1100),
    ];
    let fixture = sample_fixture(runs);
    let results = compute_campaign_results(&fixture);
    assert_eq!(results.len(), 3);
    assert!(results[0].gain_millionths > results[1].gain_millionths);
    assert!(results[2].gain_millionths < 0);
}

#[test]
fn compute_results_empty_fixture() {
    let fixture = sample_fixture(vec![]);
    let results = compute_campaign_results(&fixture);
    assert!(results.is_empty());
}

// ────────────────────────────────────────────────────────────
// Enrichment: rank_by_ev and rank_by_gain
// ────────────────────────────────────────────────────────────

#[test]
fn rank_by_ev_highest_first() {
    let results = vec![
        RuntimeHotspotCampaignResult {
            campaign_id: "low".into(),
            ev_score_millionths: 100,
            gain_millionths: 0,
        },
        RuntimeHotspotCampaignResult {
            campaign_id: "high".into(),
            ev_score_millionths: 500,
            gain_millionths: 0,
        },
    ];
    assert_eq!(rank_by_ev(&results)[0], "high");
}

#[test]
fn rank_by_ev_tie_breaks_by_id() {
    let results = vec![
        RuntimeHotspotCampaignResult {
            campaign_id: "b".into(),
            ev_score_millionths: 100,
            gain_millionths: 0,
        },
        RuntimeHotspotCampaignResult {
            campaign_id: "a".into(),
            ev_score_millionths: 100,
            gain_millionths: 0,
        },
    ];
    assert_eq!(rank_by_ev(&results), vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn rank_by_ev_empty_returns_empty() {
    let results: Vec<RuntimeHotspotCampaignResult> = vec![];
    assert!(rank_by_ev(&results).is_empty());
}

#[test]
fn rank_by_gain_highest_first() {
    let results = vec![
        RuntimeHotspotCampaignResult {
            campaign_id: "low".into(),
            ev_score_millionths: 0,
            gain_millionths: 100,
        },
        RuntimeHotspotCampaignResult {
            campaign_id: "high".into(),
            ev_score_millionths: 0,
            gain_millionths: 500,
        },
    ];
    assert_eq!(rank_by_gain(&results)[0], "high");
}

#[test]
fn rank_by_gain_negative_sorts_correctly() {
    let results = vec![
        RuntimeHotspotCampaignResult {
            campaign_id: "regressed".into(),
            ev_score_millionths: 0,
            gain_millionths: -100,
        },
        RuntimeHotspotCampaignResult {
            campaign_id: "improved".into(),
            ev_score_millionths: 0,
            gain_millionths: 200,
        },
    ];
    let ranked = rank_by_gain(&results);
    assert_eq!(ranked[0], "improved");
    assert_eq!(ranked[1], "regressed");
}

// ────────────────────────────────────────────────────────────
// Enrichment: selected_campaign
// ────────────────────────────────────────────────────────────

#[test]
fn selected_campaign_returns_highest_ev() {
    let results = vec![
        RuntimeHotspotCampaignResult {
            campaign_id: "low".into(),
            ev_score_millionths: 10,
            gain_millionths: 0,
        },
        RuntimeHotspotCampaignResult {
            campaign_id: "high".into(),
            ev_score_millionths: 100,
            gain_millionths: 0,
        },
    ];
    assert_eq!(selected_campaign(&results), "high");
}

#[test]
fn selected_campaign_tie_breaks_by_id() {
    let results = vec![
        RuntimeHotspotCampaignResult {
            campaign_id: "b".into(),
            ev_score_millionths: 50,
            gain_millionths: 0,
        },
        RuntimeHotspotCampaignResult {
            campaign_id: "a".into(),
            ev_score_millionths: 50,
            gain_millionths: 0,
        },
    ];
    assert_eq!(selected_campaign(&results), "a");
}

// ────────────────────────────────────────────────────────────
// Enrichment: emit_structured_events
// ────────────────────────────────────────────────────────────

#[test]
fn emit_events_improved_campaign() {
    let results = vec![RuntimeHotspotCampaignResult {
        campaign_id: "c1".into(),
        ev_score_millionths: 100,
        gain_millionths: 50,
    }];
    let events = emit_structured_events(&results);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "improved");
    assert_eq!(events[0].event, "campaign_run_scored");
    assert!(events[0].error_code.is_none());
}

#[test]
fn emit_events_regressed_campaign() {
    let results = vec![RuntimeHotspotCampaignResult {
        campaign_id: "c1".into(),
        ev_score_millionths: 100,
        gain_millionths: -50,
    }];
    let events = emit_structured_events(&results);
    assert_eq!(events[0].outcome, "regressed");
}

#[test]
fn emit_events_zero_gain_is_improved() {
    let results = vec![RuntimeHotspotCampaignResult {
        campaign_id: "c1".into(),
        ev_score_millionths: 100,
        gain_millionths: 0,
    }];
    let events = emit_structured_events(&results);
    assert_eq!(events[0].outcome, "improved");
}

#[test]
fn emit_events_uses_schema_constants() {
    let results = vec![RuntimeHotspotCampaignResult {
        campaign_id: "c1".into(),
        ev_score_millionths: 100,
        gain_millionths: 0,
    }];
    let events = emit_structured_events(&results);
    assert_eq!(
        events[0].schema_version,
        RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION
    );
    assert_eq!(events[0].trace_id, RUNTIME_HOTSPOT_TRACE_ID);
    assert_eq!(events[0].policy_id, RUNTIME_HOTSPOT_POLICY_ID);
    assert_eq!(events[0].component, RUNTIME_HOTSPOT_COMPONENT);
}

#[test]
fn emit_events_decision_id_includes_campaign_id() {
    let results = vec![RuntimeHotspotCampaignResult {
        campaign_id: "camp-42".into(),
        ev_score_millionths: 0,
        gain_millionths: 0,
    }];
    let events = emit_structured_events(&results);
    assert!(events[0].decision_id.contains("camp-42"));
}

#[test]
fn emit_events_multiple_results() {
    let results = vec![
        RuntimeHotspotCampaignResult {
            campaign_id: "c1".into(),
            ev_score_millionths: 100,
            gain_millionths: 50,
        },
        RuntimeHotspotCampaignResult {
            campaign_id: "c2".into(),
            ev_score_millionths: 200,
            gain_millionths: -10,
        },
    ];
    let events = emit_structured_events(&results);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].outcome, "improved");
    assert_eq!(events[1].outcome, "regressed");
}

#[test]
fn emit_events_empty_input() {
    let events = emit_structured_events(&[]);
    assert!(events.is_empty());
}

// ────────────────────────────────────────────────────────────
// Enrichment: Serde round trips
// ────────────────────────────────────────────────────────────

#[test]
fn hotspot_evidence_serde_round_trip() {
    let orig = sample_hotspot_evidence();
    let json = serde_json::to_string(&orig).unwrap();
    let back: HotspotEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn metric_vector_serde_round_trip() {
    let orig = sample_metric_vector(1000);
    let json = serde_json::to_string(&orig).unwrap();
    let back: MetricVector = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn ev_inputs_serde_round_trip() {
    let orig = sample_ev_inputs();
    let json = serde_json::to_string(&orig).unwrap();
    let back: EvInputs = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn semantic_proof_note_serde_round_trip() {
    let orig = sample_semantic_proof();
    let json = serde_json::to_string(&orig).unwrap();
    let back: SemanticProofNote = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn campaign_run_serde_round_trip() {
    let orig = sample_campaign_run("c1", 1000, 800);
    let json = serde_json::to_string(&orig).unwrap();
    let back: CampaignRun = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn replay_scenario_serde_round_trip() {
    let orig = ReplayScenario {
        scenario_id: "sc-int-1".into(),
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
fn campaign_result_serde_round_trip() {
    let orig = RuntimeHotspotCampaignResult {
        campaign_id: "camp-int-1".into(),
        ev_score_millionths: 500_000,
        gain_millionths: 100_000,
    };
    let json = serde_json::to_string(&orig).unwrap();
    let back: RuntimeHotspotCampaignResult = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, back);
}

#[test]
fn runtime_hotspot_event_serde_round_trip() {
    let orig = RuntimeHotspotEvent {
        schema_version: RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.into(),
        trace_id: "t-int-1".into(),
        decision_id: "d-int-1".into(),
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
fn fixture_with_replay_scenarios_serde_round_trip() {
    let mut fix = sample_fixture(vec![sample_campaign_run("c1", 1000, 800)]);
    fix.cross_subsystem_replay_scenarios.push(ReplayScenario {
        scenario_id: "replay-int-1".into(),
        scenario_kind: "deterministic".into(),
        replay_command: "frankenctl replay".into(),
        expected_pass: true,
        expected_outcome: "identical".into(),
    });
    let json = serde_json::to_string(&fix).unwrap();
    let back: RuntimeHotspotCampaignFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(fix, back);
}

// ────────────────────────────────────────────────────────────
// Enrichment: End-to-end pipeline
// ────────────────────────────────────────────────────────────

#[test]
fn end_to_end_fixture_processing_pipeline() {
    let runs = vec![
        sample_campaign_run("alpha", 1000, 700),
        sample_campaign_run("beta", 1000, 900),
        sample_campaign_run("gamma", 1000, 1200),
    ];
    let fixture = sample_fixture(runs);
    let results = compute_campaign_results(&fixture);
    let ev_ranking = rank_by_ev(&results);
    let gain_ranking = rank_by_gain(&results);
    let selected = selected_campaign(&results);

    assert_eq!(results.len(), 3);
    assert_eq!(ev_ranking.len(), 3);
    assert_eq!(gain_ranking.len(), 3);
    assert_eq!(gain_ranking[0], "alpha", "alpha had most improvement");
    assert_eq!(*gain_ranking.last().unwrap(), "gamma", "gamma regressed");
    assert!(!selected.is_empty());

    let events = emit_structured_events(&results);
    assert_eq!(events.len(), 3);
}

// ────────────────────────────────────────────────────────────
// Enrichment: JSON field name contracts
// ────────────────────────────────────────────────────────────

#[test]
fn runtime_hotspot_event_json_field_names_stable() {
    let val = RuntimeHotspotEvent {
        schema_version: "v1".into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: None,
    };
    let json = serde_json::to_value(&val).unwrap();
    for field in [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(json.get(field).is_some(), "missing field: {field}");
    }
}

#[test]
fn campaign_run_json_field_names_stable() {
    let val = sample_campaign_run("c1", 100, 80);
    let json = serde_json::to_value(&val).unwrap();
    for field in [
        "campaign_id",
        "lever_id",
        "lever_category",
        "commit",
        "run_id",
        "changed_paths",
        "hotspot",
        "baseline_metrics",
        "candidate_metrics",
        "ev_inputs",
        "semantic_proof",
        "rollback_plan_ref",
        "replay_command",
    ] {
        assert!(json.get(field).is_some(), "missing field: {field}");
    }
}
