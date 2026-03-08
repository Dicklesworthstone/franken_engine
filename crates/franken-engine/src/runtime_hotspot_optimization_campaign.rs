use serde::{Deserialize, Serialize};

pub const RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION: &str = "franken-engine.runtime-log-event.v1";
pub const RUNTIME_HOTSPOT_POLICY_ID: &str = "policy-runtime-hotspot-campaign-v1";
pub const RUNTIME_HOTSPOT_TRACE_ID: &str = "trace-runtime-hotspot-campaign-v1";
pub const RUNTIME_HOTSPOT_COMPONENT: &str = "runtime_hotspot_optimization_campaign";

pub const SCHEDULER_WEIGHT: i64 = 200_000;
pub const DOM_COMMIT_WEIGHT: i64 = 200_000;
pub const ROUTER_WEIGHT: i64 = 200_000;
pub const JS_WASM_WEIGHT: i64 = 200_000;
pub const INTERACTION_P95_WEIGHT: i64 = 200_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HotspotEvidence {
    pub hotspot_id: String,
    pub phase: String,
    pub baseline_share_millionths: u64,
    pub baseline_profile_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetricVector {
    pub scheduler_propagation_ns: u64,
    pub dom_commit_batch_ns: u64,
    pub lane_router_decision_ns: u64,
    pub js_wasm_boundary_ns: u64,
    pub interaction_p95_latency_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct EvInputs {
    pub impact: u64,
    pub confidence: u64,
    pub reuse: u64,
    pub effort: u64,
    pub friction: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SemanticProofNote {
    pub proof_method: String,
    pub verification_contract_ref: String,
    pub drift_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CampaignRun {
    pub campaign_id: String,
    pub lever_id: String,
    pub lever_category: String,
    pub commit: String,
    pub run_id: String,
    pub generated_at_utc: String,
    pub changed_paths: Vec<String>,
    pub hotspot: HotspotEvidence,
    pub attribution_note: String,
    pub baseline_metrics: MetricVector,
    pub candidate_metrics: MetricVector,
    pub ev_inputs: EvInputs,
    pub expected_ev_score_millionths: u64,
    pub expected_gain_millionths: i64,
    pub semantic_proof: SemanticProofNote,
    pub rollback_plan_ref: String,
    pub replay_command: String,
    pub artifact_manifest: String,
    pub artifact_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReplayScenario {
    pub scenario_id: String,
    pub scenario_kind: String,
    pub replay_command: String,
    pub expected_pass: bool,
    pub expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RuntimeHotspotCampaignFixture {
    pub schema_version: String,
    pub campaign_version: String,
    pub metric_schema_version: String,
    pub required_log_keys: Vec<String>,
    pub campaign_runs: Vec<CampaignRun>,
    pub expected_ev_ranking: Vec<String>,
    pub expected_gain_ranking: Vec<String>,
    pub expected_selected_campaign: String,
    pub cross_subsystem_replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RuntimeHotspotCampaignResult {
    pub campaign_id: String,
    pub ev_score_millionths: u64,
    pub gain_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RuntimeHotspotEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

pub fn scaled_delta_lower_is_better(baseline: u64, candidate: u64) -> i64 {
    let base = i128::from(baseline.max(1));
    let cand = i128::from(candidate.max(1));
    (((base - cand) * i128::from(1_000_000_i64)) / base) as i64
}

pub fn ev_score_millionths(inputs: &EvInputs) -> u64 {
    let numerator = inputs
        .impact
        .saturating_mul(inputs.confidence)
        .saturating_mul(inputs.reuse)
        .saturating_mul(1_000_000);
    let denominator = inputs.effort.saturating_mul(inputs.friction).max(1);
    numerator / denominator
}

pub fn campaign_gain_millionths(run: &CampaignRun) -> i64 {
    let scheduler_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.scheduler_propagation_ns,
        run.candidate_metrics.scheduler_propagation_ns,
    );
    let dom_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.dom_commit_batch_ns,
        run.candidate_metrics.dom_commit_batch_ns,
    );
    let router_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.lane_router_decision_ns,
        run.candidate_metrics.lane_router_decision_ns,
    );
    let js_wasm_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.js_wasm_boundary_ns,
        run.candidate_metrics.js_wasm_boundary_ns,
    );
    let interaction_delta = scaled_delta_lower_is_better(
        run.baseline_metrics.interaction_p95_latency_ns,
        run.candidate_metrics.interaction_p95_latency_ns,
    );

    let weighted_sum = i128::from(scheduler_delta) * i128::from(SCHEDULER_WEIGHT)
        + i128::from(dom_delta) * i128::from(DOM_COMMIT_WEIGHT)
        + i128::from(router_delta) * i128::from(ROUTER_WEIGHT)
        + i128::from(js_wasm_delta) * i128::from(JS_WASM_WEIGHT)
        + i128::from(interaction_delta) * i128::from(INTERACTION_P95_WEIGHT);
    (weighted_sum / i128::from(1_000_000_i64)) as i64
}

pub fn compute_campaign_results(
    fixture: &RuntimeHotspotCampaignFixture,
) -> Vec<RuntimeHotspotCampaignResult> {
    fixture
        .campaign_runs
        .iter()
        .map(|run| RuntimeHotspotCampaignResult {
            campaign_id: run.campaign_id.clone(),
            ev_score_millionths: ev_score_millionths(&run.ev_inputs),
            gain_millionths: campaign_gain_millionths(run),
        })
        .collect()
}

pub fn rank_by_ev(results: &[RuntimeHotspotCampaignResult]) -> Vec<String> {
    let mut ranked = results.to_vec();
    ranked.sort_by(|left, right| {
        right
            .ev_score_millionths
            .cmp(&left.ev_score_millionths)
            .then_with(|| left.campaign_id.cmp(&right.campaign_id))
    });
    ranked.into_iter().map(|entry| entry.campaign_id).collect()
}

pub fn rank_by_gain(results: &[RuntimeHotspotCampaignResult]) -> Vec<String> {
    let mut ranked = results.to_vec();
    ranked.sort_by(|left, right| {
        right
            .gain_millionths
            .cmp(&left.gain_millionths)
            .then_with(|| left.campaign_id.cmp(&right.campaign_id))
    });
    ranked.into_iter().map(|entry| entry.campaign_id).collect()
}

pub fn selected_campaign(results: &[RuntimeHotspotCampaignResult]) -> String {
    let mut ranked = results.to_vec();
    ranked.sort_by(|left, right| {
        right
            .ev_score_millionths
            .cmp(&left.ev_score_millionths)
            .then_with(|| left.campaign_id.cmp(&right.campaign_id))
    });
    ranked
        .first()
        .expect("campaign results must not be empty")
        .campaign_id
        .clone()
}

pub fn classify_runtime_lever(path: &str) -> Option<&'static str> {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    if lower.contains("scheduler_lane") {
        return Some("scheduler");
    }
    if lower.contains("js_runtime_lane") {
        return Some("dom_commit");
    }
    if lower.contains("hybrid_lane_router") {
        return Some("lane_router");
    }
    if lower.contains("wasm_runtime_lane") {
        return Some("js_wasm_boundary");
    }
    None
}

pub fn emit_structured_events(
    results: &[RuntimeHotspotCampaignResult],
) -> Vec<RuntimeHotspotEvent> {
    results
        .iter()
        .map(|result| RuntimeHotspotEvent {
            schema_version: RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: RUNTIME_HOTSPOT_TRACE_ID.to_string(),
            decision_id: format!("decision-{}", result.campaign_id),
            policy_id: RUNTIME_HOTSPOT_POLICY_ID.to_string(),
            component: RUNTIME_HOTSPOT_COMPONENT.to_string(),
            event: "campaign_run_scored".to_string(),
            outcome: if result.gain_millionths >= 0 {
                "improved".to_string()
            } else {
                "regressed".to_string()
            },
            error_code: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper builders ──────────────────────────────────────────────

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

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn schema_version_constant_is_non_empty() {
        assert!(!RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.is_empty());
        assert!(RUNTIME_HOTSPOT_EVENT_SCHEMA_VERSION.contains("runtime-log-event"));
    }

    #[test]
    fn policy_id_constant_is_non_empty() {
        assert!(!RUNTIME_HOTSPOT_POLICY_ID.is_empty());
        assert!(RUNTIME_HOTSPOT_POLICY_ID.contains("campaign"));
    }

    #[test]
    fn trace_id_constant_is_non_empty() {
        assert!(!RUNTIME_HOTSPOT_TRACE_ID.is_empty());
    }

    #[test]
    fn component_constant_matches_module_name() {
        assert_eq!(
            RUNTIME_HOTSPOT_COMPONENT,
            "runtime_hotspot_optimization_campaign"
        );
    }

    #[test]
    fn weight_constants_are_positive_and_equal() {
        const { assert!(SCHEDULER_WEIGHT > 0) };
        assert_eq!(SCHEDULER_WEIGHT, DOM_COMMIT_WEIGHT);
        assert_eq!(DOM_COMMIT_WEIGHT, ROUTER_WEIGHT);
        assert_eq!(ROUTER_WEIGHT, JS_WASM_WEIGHT);
        assert_eq!(JS_WASM_WEIGHT, INTERACTION_P95_WEIGHT);
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

    // ── Serde roundtrips ─────────────────────────────────────────────

    #[test]
    fn hotspot_evidence_serde_roundtrip() {
        let orig = sample_hotspot_evidence();
        let json = serde_json::to_string(&orig).unwrap();
        let back: HotspotEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn metric_vector_serde_roundtrip() {
        let orig = sample_metric_vector(1000);
        let json = serde_json::to_string(&orig).unwrap();
        let back: MetricVector = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn metric_vector_zero_values_serde_roundtrip() {
        let orig = MetricVector {
            scheduler_propagation_ns: 0,
            dom_commit_batch_ns: 0,
            lane_router_decision_ns: 0,
            js_wasm_boundary_ns: 0,
            interaction_p95_latency_ns: 0,
        };
        let json = serde_json::to_string(&orig).unwrap();
        let back: MetricVector = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn ev_inputs_serde_roundtrip() {
        let orig = sample_ev_inputs();
        let json = serde_json::to_string(&orig).unwrap();
        let back: EvInputs = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn semantic_proof_note_serde_roundtrip() {
        let orig = sample_semantic_proof();
        let json = serde_json::to_string(&orig).unwrap();
        let back: SemanticProofNote = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn campaign_run_serde_roundtrip() {
        let orig = sample_campaign_run("c1", 1000, 800);
        let json = serde_json::to_string(&orig).unwrap();
        let back: CampaignRun = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn replay_scenario_serde_roundtrip() {
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
    fn replay_scenario_expected_fail_serde_roundtrip() {
        let orig = ReplayScenario {
            scenario_id: "sc-fail".into(),
            scenario_kind: "adversarial".into(),
            replay_command: "cargo test -- fuzz".into(),
            expected_pass: false,
            expected_outcome: "containment-triggered".into(),
        };
        let json = serde_json::to_string(&orig).unwrap();
        let back: ReplayScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
        assert!(!back.expected_pass);
    }

    #[test]
    fn fixture_serde_roundtrip() {
        let runs = vec![sample_campaign_run("c1", 1000, 800)];
        let orig = sample_fixture(runs);
        let json = serde_json::to_string(&orig).unwrap();
        let back: RuntimeHotspotCampaignFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn fixture_with_replay_scenarios_serde_roundtrip() {
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
        assert_eq!(fix, back);
    }

    #[test]
    fn campaign_result_serde_roundtrip() {
        let orig = RuntimeHotspotCampaignResult {
            campaign_id: "camp-1".into(),
            ev_score_millionths: 500_000,
            gain_millionths: 100_000,
        };
        let json = serde_json::to_string(&orig).unwrap();
        let back: RuntimeHotspotCampaignResult = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    #[test]
    fn runtime_hotspot_event_serde_roundtrip_no_error() {
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
    fn runtime_hotspot_event_serde_roundtrip_with_error() {
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

    // ── scaled_delta_lower_is_better ─────────────────────────────────

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
        let delta = scaled_delta_lower_is_better(1000, 1000);
        assert_eq!(delta, 0);
    }

    #[test]
    fn scaled_delta_both_zero_clamps_to_one() {
        let delta = scaled_delta_lower_is_better(0, 0);
        assert_eq!(delta, 0);
    }

    #[test]
    fn scaled_delta_baseline_zero_clamps_to_one() {
        let delta = scaled_delta_lower_is_better(0, 100);
        assert!(delta < 0);
    }

    #[test]
    fn scaled_delta_candidate_zero_clamps_to_one() {
        let delta = scaled_delta_lower_is_better(100, 0);
        assert!(delta > 0);
    }

    #[test]
    fn scaled_delta_halved_candidate_returns_500k() {
        let delta = scaled_delta_lower_is_better(1000, 500);
        assert_eq!(delta, 500_000);
    }

    #[test]
    fn scaled_delta_candidate_to_one_returns_near_million() {
        let delta = scaled_delta_lower_is_better(1_000_000, 1);
        assert!(delta > 999_000);
    }

    #[test]
    fn scaled_delta_large_values_no_overflow() {
        let delta = scaled_delta_lower_is_better(u64::MAX / 2, u64::MAX / 4);
        assert!(delta > 0);
    }

    // ── ev_score_millionths ──────────────────────────────────────────

    #[test]
    fn ev_score_basic_calculation() {
        let inputs = EvInputs {
            impact: 10,
            confidence: 10,
            reuse: 10,
            effort: 10,
            friction: 10,
        };
        let score = ev_score_millionths(&inputs);
        assert_eq!(score, 10_000_000);
    }

    #[test]
    fn ev_score_zero_effort_clamps_denominator() {
        let inputs = EvInputs {
            impact: 10,
            confidence: 5,
            reuse: 2,
            effort: 0,
            friction: 3,
        };
        let score = ev_score_millionths(&inputs);
        assert!(score > 0);
    }

    #[test]
    fn ev_score_zero_friction_clamps_denominator() {
        let inputs = EvInputs {
            impact: 10,
            confidence: 5,
            reuse: 2,
            effort: 3,
            friction: 0,
        };
        let score = ev_score_millionths(&inputs);
        assert!(score > 0);
    }

    #[test]
    fn ev_score_both_zero_clamps_denominator() {
        let inputs = EvInputs {
            impact: 10,
            confidence: 5,
            reuse: 2,
            effort: 0,
            friction: 0,
        };
        let score = ev_score_millionths(&inputs);
        assert!(score > 0);
    }

    #[test]
    fn ev_score_high_effort_reduces_score() {
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
        assert!(ev_score_millionths(&low_effort) > ev_score_millionths(&high_effort));
    }

    #[test]
    fn ev_score_unit_inputs() {
        let inputs = EvInputs {
            impact: 1,
            confidence: 1,
            reuse: 1,
            effort: 1,
            friction: 1,
        };
        let score = ev_score_millionths(&inputs);
        assert_eq!(score, 1_000_000);
    }

    // ── campaign_gain_millionths ─────────────────────────────────────

    #[test]
    fn campaign_gain_positive_for_improvement() {
        let run = sample_campaign_run("c1", 1000, 800);
        let gain = campaign_gain_millionths(&run);
        assert!(gain > 0);
    }

    #[test]
    fn campaign_gain_negative_for_regression() {
        let run = sample_campaign_run("c1", 800, 1000);
        let gain = campaign_gain_millionths(&run);
        assert!(gain < 0);
    }

    #[test]
    fn campaign_gain_zero_for_equal_metrics() {
        let run = sample_campaign_run("c1", 1000, 1000);
        let gain = campaign_gain_millionths(&run);
        assert_eq!(gain, 0);
    }

    #[test]
    fn campaign_gain_uses_all_five_dimensions() {
        let mut run = sample_campaign_run("c1", 1000, 1000);
        run.candidate_metrics.scheduler_propagation_ns = 500;
        let gain = campaign_gain_millionths(&run);
        assert!(gain > 0, "should reflect scheduler improvement");
    }

    // ── compute_campaign_results ─────────────────────────────────────

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
    fn compute_results_multiple_runs() {
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

    // ── rank_by_ev ───────────────────────────────────────────────────

    #[test]
    fn rank_by_ev_tie_breaks_by_campaign_id() {
        let results = vec![
            RuntimeHotspotCampaignResult {
                campaign_id: "b".to_string(),
                ev_score_millionths: 100,
                gain_millionths: 10,
            },
            RuntimeHotspotCampaignResult {
                campaign_id: "a".to_string(),
                ev_score_millionths: 100,
                gain_millionths: 11,
            },
        ];
        assert_eq!(rank_by_ev(&results), vec!["a".to_string(), "b".to_string()]);
    }

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
    fn rank_by_ev_single_element() {
        let results = vec![RuntimeHotspotCampaignResult {
            campaign_id: "only".into(),
            ev_score_millionths: 42,
            gain_millionths: 0,
        }];
        assert_eq!(rank_by_ev(&results), vec!["only".to_string()]);
    }

    #[test]
    fn rank_by_ev_empty_returns_empty() {
        let results: Vec<RuntimeHotspotCampaignResult> = vec![];
        assert!(rank_by_ev(&results).is_empty());
    }

    // ── rank_by_gain ─────────────────────────────────────────────────

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
    fn rank_by_gain_negative_values_sort_correctly() {
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

    #[test]
    fn rank_by_gain_tie_breaks_by_campaign_id() {
        let results = vec![
            RuntimeHotspotCampaignResult {
                campaign_id: "b".into(),
                ev_score_millionths: 0,
                gain_millionths: 50,
            },
            RuntimeHotspotCampaignResult {
                campaign_id: "a".into(),
                ev_score_millionths: 0,
                gain_millionths: 50,
            },
        ];
        let ranked = rank_by_gain(&results);
        assert_eq!(ranked[0], "a");
    }

    // ── selected_campaign ────────────────────────────────────────────

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

    // ── classify_runtime_lever ───────────────────────────────────────

    #[test]
    fn classify_runtime_lever_is_path_separator_agnostic() {
        assert_eq!(
            classify_runtime_lever("crates\\franken-engine\\src\\wasm_runtime_lane.rs"),
            Some("js_wasm_boundary")
        );
    }

    #[test]
    fn classify_scheduler_lane() {
        assert_eq!(
            classify_runtime_lever("src/scheduler_lane.rs"),
            Some("scheduler")
        );
    }

    #[test]
    fn classify_js_runtime_lane() {
        assert_eq!(
            classify_runtime_lever("src/js_runtime_lane.rs"),
            Some("dom_commit")
        );
    }

    #[test]
    fn classify_hybrid_lane_router() {
        assert_eq!(
            classify_runtime_lever("src/hybrid_lane_router.rs"),
            Some("lane_router")
        );
    }

    #[test]
    fn classify_wasm_runtime_lane() {
        assert_eq!(
            classify_runtime_lever("src/wasm_runtime_lane.rs"),
            Some("js_wasm_boundary")
        );
    }

    #[test]
    fn classify_unknown_path_returns_none() {
        assert_eq!(classify_runtime_lever("src/lib.rs"), None);
    }

    #[test]
    fn classify_case_insensitive() {
        assert_eq!(
            classify_runtime_lever("src/SCHEDULER_LANE.rs"),
            Some("scheduler")
        );
    }

    #[test]
    fn classify_nested_path() {
        assert_eq!(
            classify_runtime_lever("crates/franken-engine/src/scheduler_lane.rs"),
            Some("scheduler")
        );
    }

    // ── emit_structured_events ───────────────────────────────────────

    #[test]
    fn emit_events_for_improved_campaign() {
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
    fn emit_events_for_regressed_campaign() {
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

    // ── JSON field name contracts ────────────────────────────────────

    #[test]
    fn hotspot_evidence_json_field_names() {
        let val = sample_hotspot_evidence();
        let json = serde_json::to_value(&val).unwrap();
        assert!(json.get("hotspot_id").is_some());
        assert!(json.get("phase").is_some());
        assert!(json.get("baseline_share_millionths").is_some());
        assert!(json.get("baseline_profile_ref").is_some());
    }

    #[test]
    fn metric_vector_json_field_names() {
        let val = sample_metric_vector(100);
        let json = serde_json::to_value(&val).unwrap();
        assert!(json.get("scheduler_propagation_ns").is_some());
        assert!(json.get("dom_commit_batch_ns").is_some());
        assert!(json.get("lane_router_decision_ns").is_some());
        assert!(json.get("js_wasm_boundary_ns").is_some());
        assert!(json.get("interaction_p95_latency_ns").is_some());
    }

    #[test]
    fn ev_inputs_json_field_names() {
        let val = sample_ev_inputs();
        let json = serde_json::to_value(&val).unwrap();
        for field in &["impact", "confidence", "reuse", "effort", "friction"] {
            assert!(json.get(*field).is_some(), "missing field: {field}");
        }
    }

    #[test]
    fn campaign_run_json_field_names() {
        let val = sample_campaign_run("c1", 100, 80);
        let json = serde_json::to_value(&val).unwrap();
        for field in &[
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
            assert!(json.get(*field).is_some(), "missing field: {field}");
        }
    }

    #[test]
    fn runtime_hotspot_event_json_field_names() {
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

    // ── Clone + Debug contracts ──────────────────────────────────────

    #[test]
    fn all_types_implement_clone() {
        let he = sample_hotspot_evidence();
        let _cloned = he.clone();
        let mv = sample_metric_vector(100);
        let _cloned = mv.clone();
        let ei = sample_ev_inputs();
        let _cloned = ei.clone();
        let sp = sample_semantic_proof();
        let _cloned = sp.clone();
        let cr = sample_campaign_run("c1", 100, 80);
        let _cloned = cr.clone();
        let rs = ReplayScenario {
            scenario_id: "s".into(),
            scenario_kind: "k".into(),
            replay_command: "r".into(),
            expected_pass: true,
            expected_outcome: "o".into(),
        };
        let _cloned = rs.clone();
    }

    #[test]
    fn all_types_implement_debug() {
        let he = sample_hotspot_evidence();
        let dbg = format!("{he:?}");
        assert!(dbg.contains("hs-001"));
        let mv = sample_metric_vector(100);
        let dbg = format!("{mv:?}");
        assert!(dbg.contains("100"));
    }

    // ── Integration: end-to-end fixture processing ───────────────────

    #[test]
    fn end_to_end_fixture_processing() {
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
}
