#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::disruptive_floor_metric_gate::{
    DisruptiveFloorGateConfig, DisruptiveMetricId, GateDecisionState, MetricArtifact,
    evaluate_disruptive_floor_gate,
};
use frankenengine_engine::production_feature_catalog_gate::{
    ProductionFeatureCatalogDecision, ProductionFeatureCatalogEvent, ProductionFeatureCatalogInput,
    evaluate_production_feature_catalog,
};
use frankenengine_engine::proof_artifact::{ProofMachineReport, ProofManifest, ProofRunStatus};

const PASS_FIXTURE: &str = "tests/fixtures/production_feature_catalog_pass_v1.json";
const FAIL_FIXTURE: &str = "tests/fixtures/production_feature_catalog_fail_two_observed_v1.json";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_fixture(path: &str) -> ProductionFeatureCatalogInput {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    let fixture = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|_| panic!("fixture should be readable: {}", fixture_path.display()));
    serde_json::from_str(&fixture).expect("fixture should deserialize")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("json artifact should be readable: {}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|error| panic!("json artifact should parse at {}: {error}", path.display()))
}

#[test]
fn production_feature_catalog_pass_fixture_supports_parent_metric() {
    let input = load_fixture(PASS_FIXTURE);
    let child = evaluate_production_feature_catalog(&input);

    assert_eq!(child.decision, ProductionFeatureCatalogDecision::Pass);
    assert_eq!(child.observed_feature_count, 3);
    assert_eq!(
        child.metric_artifact.metric_id,
        DisruptiveMetricId::ImpossibleByDefaultProductionFeatures
    );

    let mut artifacts = DisruptiveMetricId::ALL
        .into_iter()
        .map(|metric_id| MetricArtifact::for_metric(metric_id, metric_id.threshold()))
        .collect::<Vec<_>>();
    let slot = artifacts
        .iter_mut()
        .find(|artifact| {
            artifact.metric_id == DisruptiveMetricId::ImpossibleByDefaultProductionFeatures
        })
        .expect("feature catalog metric exists");
    *slot = child.metric_artifact;

    let parent = evaluate_disruptive_floor_gate(
        &DisruptiveFloorGateConfig::new("rev-under-test"),
        &artifacts,
    );

    assert_eq!(parent.decision, GateDecisionState::Pass);
    assert!(parent.observed_disruptive_floor_wording_allowed);
}

#[test]
fn two_observed_fixture_fails_closed_without_deleting_candidates() {
    let input = load_fixture(FAIL_FIXTURE);
    let report = evaluate_production_feature_catalog(&input);

    assert_eq!(
        report.decision,
        ProductionFeatureCatalogDecision::FailClosed
    );
    assert_eq!(report.reason, "fewer_than_three_observed_features");
    assert_eq!(report.observed_feature_count, 2);
    assert!(
        report
            .unsupported_candidate_feature_ids
            .contains(&"signed_policy_checkpoints".to_string())
    );
    assert!(!report.observed_disruptive_floor_wording_allowed);
}

#[test]
fn script_emits_pass_and_fail_closed_shared_proof_bundles() {
    let root = repo_root();
    let run_id = format!("integration-{}", std::process::id());
    let artifact_root = format!("target/production_feature_catalog_gate/{run_id}");
    let output = Command::new(root.join("scripts/run_production_feature_catalog_gate.sh"))
        .arg("ci")
        .current_dir(&root)
        .env("PRODUCTION_FEATURE_CATALOG_ARTIFACT_ROOT", &artifact_root)
        .env("PRODUCTION_FEATURE_CATALOG_RUN_ID", "script-proof")
        .env("PRODUCTION_FEATURE_CATALOG_CODE_REVISION", "rev-under-test")
        .output()
        .expect("production feature catalog script should execute");

    assert!(
        output.status.success(),
        "script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let pass_dir = root.join(&artifact_root).join("script-proof/pass");
    let fail_dir = root.join(&artifact_root).join("script-proof/fail_closed");
    let pass_manifest: ProofManifest = read_json(&pass_dir.join("manifest.json"));
    let fail_report: ProofMachineReport = read_json(&fail_dir.join("report.json"));
    let metric_artifact: MetricArtifact = read_json(&pass_dir.join("metric_artifact.json"));
    let source_report: serde_json::Value = read_json(&pass_dir.join("catalog_report.json"));

    pass_manifest.validate().expect("pass manifest validates");
    fail_report
        .validate()
        .expect("fail-closed proof report validates");

    assert_eq!(pass_manifest.status, ProofRunStatus::Pass);
    assert_eq!(pass_manifest.gate_name, "production_feature_catalog_gate");
    assert!(pass_manifest.bead_ids.contains(&"bd-1qr4f".to_string()));
    assert!(
        pass_manifest
            .claim_ids
            .contains(&"disruptive_floor.impossible_by_default_features_3".to_string())
    );
    assert_eq!(fail_report.status, ProofRunStatus::Fail);
    assert_eq!(fail_report.failure_count, 1);

    assert_eq!(
        metric_artifact.metric_id,
        DisruptiveMetricId::ImpossibleByDefaultProductionFeatures
    );
    assert_eq!(metric_artifact.observed_value, 3);
    assert_eq!(metric_artifact.threshold, 3);
    assert_eq!(metric_artifact.redaction_status, "redacted");
    assert_eq!(
        source_report["observed_disruptive_floor_wording_allowed"],
        true
    );

    let event_line = std::fs::read_to_string(pass_dir.join("events.jsonl"))
        .expect("pass events should be readable")
        .lines()
        .next()
        .expect("pass bundle emits at least one event")
        .to_string();
    let event: ProductionFeatureCatalogEvent =
        serde_json::from_str(&event_line).expect("structured event should parse");
    assert_eq!(event.feature_id, "posterior_policy_actions");
    assert_eq!(event.decision, "observed");
    assert_eq!(event.reason, "fresh_live_proof_artifact_observed");
}
