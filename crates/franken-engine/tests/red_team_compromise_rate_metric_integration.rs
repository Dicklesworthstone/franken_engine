#![forbid(unsafe_code)]

use frankenengine_engine::disruptive_floor_metric_gate::{
    DisruptiveFloorGateConfig, DisruptiveMetricId, GateDecisionState, MetricArtifact,
    evaluate_disruptive_floor_gate,
};
use frankenengine_engine::red_team_compromise_rate_metric_gate::{
    RedTeamCompromiseRateDecision, RedTeamCompromiseRateMetricInput,
    evaluate_red_team_compromise_rate_metric,
};
use std::path::PathBuf;

const FIXTURE_PATH: &str = "tests/fixtures/red_team_compromise_rate_metric_input_v1.json";

#[test]
fn red_team_fixture_loads_and_passes() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    let fixture = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|_| panic!("fixture should be readable: {}", fixture_path.display()));
    let input: RedTeamCompromiseRateMetricInput =
        serde_json::from_str(&fixture).expect("fixture should deserialize");
    let report = evaluate_red_team_compromise_rate_metric(&input);

    assert_eq!(
        report.decision,
        RedTeamCompromiseRateDecision::Pass,
        "{}",
        report.reason
    );
    assert_eq!(report.scenarios_total, 5);
    assert_eq!(report.attacks_successful, 0);
    assert_eq!(report.compromise_millionths, 0);
    assert_eq!(report.baseline_compromise_millionths_node, 1_000_000);
    assert_eq!(report.baseline_compromise_millionths_bun, 1_000_000);
    assert_eq!(report.reduction_factor_x, u64::MAX);
}

#[test]
fn red_team_child_artifact_is_consumed_by_parent_integrator() {
    let input: RedTeamCompromiseRateMetricInput = serde_json::from_str(include_str!(
        "fixtures/red_team_compromise_rate_metric_input_v1.json"
    ))
    .expect("fixture should deserialize");
    let code_revision = input.code_revision.clone();
    let child_report = evaluate_red_team_compromise_rate_metric(&input);
    let mut artifacts = DisruptiveMetricId::ALL
        .into_iter()
        .map(|metric_id| {
            let mut artifact = MetricArtifact::for_metric(metric_id, metric_id.threshold());
            artifact.code_revision = code_revision.clone();
            artifact
        })
        .collect::<Vec<_>>();
    let red_team_slot = artifacts
        .iter_mut()
        .find(|artifact| artifact.metric_id == DisruptiveMetricId::RedTeamCompromiseRateReduction)
        .expect("parent should require red-team metric");
    *red_team_slot = child_report.metric_artifact;

    let parent_report =
        evaluate_disruptive_floor_gate(&DisruptiveFloorGateConfig::new(code_revision), &artifacts);

    assert_eq!(parent_report.decision, GateDecisionState::Pass);
    assert!(parent_report.observed_disruptive_floor_wording_allowed);
}

#[test]
fn structured_events_include_baseline_comparison_fields() {
    let input: RedTeamCompromiseRateMetricInput = serde_json::from_str(include_str!(
        "fixtures/red_team_compromise_rate_metric_input_v1.json"
    ))
    .expect("fixture should deserialize");
    let report = evaluate_red_team_compromise_rate_metric(&input);
    let event = report.events.first().expect("fixture has events");

    assert_eq!(
        event.metric_id,
        DisruptiveMetricId::RedTeamCompromiseRateReduction
    );
    assert_eq!(event.scenarios_total, 5);
    assert_eq!(event.attacks_successful, 0);
    assert_eq!(event.compromise_millionths, 0);
    assert_eq!(event.baseline_compromise_millionths_node, 1_000_000);
    assert_eq!(event.baseline_compromise_millionths_bun, 1_000_000);
    assert_eq!(event.reduction_factor_x, u64::MAX);
    assert_eq!(event.threshold_factor_x, 10);
}
