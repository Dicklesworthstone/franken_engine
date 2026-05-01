#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::containment_latency_metric_gate::{
    CONTAINMENT_LATENCY_THRESHOLD_MS, CONTAINMENT_LATENCY_THRESHOLD_US, ContainmentLatencyDecision,
    ContainmentLatencyMetricInput, ContainmentLatencyStructuredEvent,
    evaluate_containment_latency_metric,
};
use frankenengine_engine::disruptive_floor_metric_gate::{
    DisruptiveFloorGateConfig, DisruptiveMetricId, GateDecisionState, MetricArtifact,
    evaluate_disruptive_floor_gate,
};
use frankenengine_engine::proof_artifact::{ProofMachineReport, ProofManifest, ProofRunStatus};

const FIXTURE_PATH: &str = "tests/fixtures/containment_latency_metric_input_v1.json";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_fixture_input() -> ContainmentLatencyMetricInput {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
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
fn containment_latency_fixture_loads_and_passes() {
    let input = load_fixture_input();
    let report = evaluate_containment_latency_metric(&input);

    assert_eq!(report.decision, ContainmentLatencyDecision::Pass);
    assert_eq!(report.total_signal_events, 3);
    assert_eq!(report.contained_signal_events, 3);
    assert_eq!(report.median_latency_us, Some(120_456));
    assert_eq!(report.median_latency_ms, Some(121));
    assert_eq!(report.threshold_us, CONTAINMENT_LATENCY_THRESHOLD_US);
    assert_eq!(report.threshold_ms, CONTAINMENT_LATENCY_THRESHOLD_MS);
    assert_eq!(report.coverage_millionths, 1_000_000);
    assert!(report.invalid_trace_ids.is_empty());

    let event = report.events.first().expect("fixture emits events");
    assert_eq!(
        event.metric_id,
        DisruptiveMetricId::ContainmentLatencyMedianMs
    );
    assert_eq!(event.signal_detected_at_us, 1_000_000);
    assert_eq!(event.containment_action_applied_at_us, Some(1_080_123));
    assert_eq!(event.latency_us, Some(80_123));
    assert_eq!(event.median_latency_us, Some(120_456));
    assert_eq!(event.threshold_us, 250_000);
    assert_eq!(event.signal_detected_at_ms, 1_000);
    assert_eq!(event.containment_action_applied_at_ms, Some(1_080));
    assert_eq!(event.latency_ms, Some(81));
    assert_eq!(event.median_latency_ms, Some(121));
    assert_eq!(event.threshold_ms, 250);
    assert_eq!(event.clock_source, "monotonic_us");
    assert_eq!(event.redaction_status, "redacted");
}

#[test]
fn containment_latency_child_artifact_is_consumed_by_parent_integrator() {
    let input = load_fixture_input();
    let child_report = evaluate_containment_latency_metric(&input);
    let mut artifacts = DisruptiveMetricId::ALL
        .into_iter()
        .map(|metric_id| MetricArtifact::for_metric(metric_id, metric_id.threshold()))
        .collect::<Vec<_>>();
    let containment_slot = artifacts
        .iter_mut()
        .find(|artifact| artifact.metric_id == DisruptiveMetricId::ContainmentLatencyMedianMs)
        .expect("parent should require containment-latency metric");
    *containment_slot = child_report.metric_artifact;

    let parent_report = evaluate_disruptive_floor_gate(
        &DisruptiveFloorGateConfig::new("rev-under-test"),
        &artifacts,
    );

    assert_eq!(parent_report.decision, GateDecisionState::Pass);
    assert!(parent_report.observed_disruptive_floor_wording_allowed);
}

#[test]
fn script_emits_pass_and_fail_closed_proof_artifact_bundles() {
    let root = repo_root();
    let run_id = format!("integration-{}", std::process::id());
    let artifact_root = format!("target/containment_latency_metric_gate/{run_id}");
    let output = Command::new(root.join("scripts/run_containment_latency_metric_gate.sh"))
        .arg("ci")
        .current_dir(&root)
        .env("CONTAINMENT_LATENCY_METRIC_ARTIFACT_ROOT", &artifact_root)
        .env("CONTAINMENT_LATENCY_METRIC_RUN_ID", "script-proof")
        .env("CONTAINMENT_LATENCY_METRIC_CODE_REVISION", "rev-under-test")
        .output()
        .expect("containment latency script should execute");

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

    pass_manifest.validate().expect("pass manifest validates");
    fail_report
        .validate()
        .expect("fail-closed proof report validates");

    assert_eq!(pass_manifest.status, ProofRunStatus::Pass);
    assert_eq!(pass_manifest.gate_name, "containment_latency_metric_gate");
    assert!(pass_manifest.bead_ids.contains(&"bd-38mby".to_string()));
    assert!(
        pass_manifest
            .claim_ids
            .contains(&"disruptive_floor.containment_latency_250ms".to_string())
    );
    assert_eq!(fail_report.status, ProofRunStatus::Fail);
    assert_eq!(fail_report.failure_count, 1);

    assert_eq!(
        metric_artifact.metric_id,
        DisruptiveMetricId::ContainmentLatencyMedianMs
    );
    assert_eq!(metric_artifact.observed_value, 121);
    assert_eq!(metric_artifact.threshold, 250);
    assert_eq!(metric_artifact.redaction_status, "redacted");

    let event_line = std::fs::read_to_string(pass_dir.join("events.jsonl"))
        .expect("pass events should be readable")
        .lines()
        .next()
        .expect("pass bundle emits at least one event")
        .to_string();
    let event: ContainmentLatencyStructuredEvent =
        serde_json::from_str(&event_line).expect("structured event should parse");
    assert_eq!(event.signal_id, "ambient-write-denied");
    assert_eq!(event.latency_us, Some(80_123));
    assert_eq!(event.latency_ms, Some(81));
    assert_eq!(event.decision, "contained");
}
