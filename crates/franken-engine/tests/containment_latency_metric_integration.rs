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
use frankenengine_engine::proof_artifact::{ProofManifest, ProofRunStatus};

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

fn write_live_script_input(root: &Path, artifact_root: &str, run_id: &str) -> PathBuf {
    let mut input = load_fixture_input();
    input.code_revision = "rev-under-test".to_string();
    input.artifact_path = format!("{artifact_root}/{run_id}/raw_latency_details.json");
    input.artifact_hash =
        "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7".to_string();
    input.verification_command = "live-containment-latency-harness --emit-json".to_string();

    for (signal, (latency_us, duration_us)) in
        input
            .signals
            .iter_mut()
            .zip([(80_417_u64, 1_432_u64), (120_813, 1_765), (199_327, 2_103)])
    {
        signal.containment_action_applied_at_us = Some(signal.signal_detected_at_us + latency_us);
        signal.clock_id = "host-monotonic-clock-1".to_string();
        signal.duration_us = duration_us;
        signal.evidence_commit_hash = Some("rev-under-test".to_string());
        signal.evidence_test_name =
            Some("live_containment_latency_harness::signal_to_action_trace".to_string());
    }

    let input_path = root
        .join(artifact_root)
        .join(run_id)
        .join("live_metric_input.json");
    std::fs::create_dir_all(input_path.parent().expect("input path has parent"))
        .expect("script input dir should be creatable");
    std::fs::write(
        &input_path,
        serde_json::to_vec_pretty(&input).expect("script input should serialize"),
    )
    .expect("script input should be writable");
    input_path
}

fn write_synthetic_script_input(root: &Path, artifact_root: &str, run_id: &str) -> PathBuf {
    let input = load_fixture_input();
    let input_path = root
        .join(artifact_root)
        .join(run_id)
        .join("synthetic_metric_input.json");
    std::fs::create_dir_all(input_path.parent().expect("input path has parent"))
        .expect("script input dir should be creatable");
    std::fs::write(
        &input_path,
        serde_json::to_vec_pretty(&input).expect("script input should serialize"),
    )
    .expect("script input should be writable");
    input_path
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
fn containment_latency_preserves_sub_millisecond_precision() {
    let mut input = load_fixture_input();
    for signal in &mut input.signals {
        signal.containment_action_applied_at_us = Some(signal.signal_detected_at_us + 100);
        signal.duration_us = 100;
    }

    let report = evaluate_containment_latency_metric(&input);

    assert_eq!(report.decision, ContainmentLatencyDecision::Pass);
    assert_eq!(report.median_latency_us, Some(100));
    assert_eq!(report.median_latency_ms, Some(1));
    assert_eq!(report.metric_artifact.observed_value, 1);
    assert_eq!(report.events[0].latency_us, Some(100));
    assert_eq!(report.events[0].latency_ms, Some(1));
    assert_eq!(report.events[0].duration_us, 100);
    assert_eq!(report.events[0].duration_ms, 1);
}

#[test]
fn containment_latency_fails_one_microsecond_over_threshold() {
    let mut input = load_fixture_input();
    input.signals[0].containment_action_applied_at_us =
        Some(input.signals[0].signal_detected_at_us + 249_999);
    input.signals[1].containment_action_applied_at_us =
        Some(input.signals[1].signal_detected_at_us + 250_001);
    input.signals[2].containment_action_applied_at_us =
        Some(input.signals[2].signal_detected_at_us + 250_001);

    let report = evaluate_containment_latency_metric(&input);

    assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
    assert_eq!(report.reason, "median_latency_exceeds_threshold");
    assert_eq!(report.median_latency_us, Some(250_001));
    assert_eq!(report.median_latency_ms, Some(251));
    assert_eq!(report.metric_artifact.observed_value, 251);
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
fn script_rejects_synthetic_input_and_emits_measured_proof_artifact_bundle() {
    let root = repo_root();
    let run_id = format!("integration-{}", std::process::id());
    let artifact_root = format!("target/containment_latency_metric_gate/{run_id}");

    let missing_input = Command::new(root.join("scripts/run_containment_latency_metric_gate.sh"))
        .arg("pass")
        .current_dir(&root)
        .env("CONTAINMENT_LATENCY_METRIC_ARTIFACT_ROOT", &artifact_root)
        .env("CONTAINMENT_LATENCY_METRIC_RUN_ID", "missing-input")
        .env("CONTAINMENT_LATENCY_METRIC_CODE_REVISION", "rev-under-test")
        .output()
        .expect("containment latency script should execute");
    assert!(
        !missing_input.status.success(),
        "script should fail closed without live input"
    );
    assert!(
        String::from_utf8_lossy(&missing_input.stderr).contains("CONTAINMENT_LATENCY_METRIC_INPUT"),
        "stderr should explain missing input\nstderr:\n{}",
        String::from_utf8_lossy(&missing_input.stderr)
    );

    let synthetic_input = write_synthetic_script_input(&root, &artifact_root, "synthetic-input");
    let synthetic_output =
        Command::new(root.join("scripts/run_containment_latency_metric_gate.sh"))
            .arg("pass")
            .current_dir(&root)
            .env("CONTAINMENT_LATENCY_METRIC_ARTIFACT_ROOT", &artifact_root)
            .env("CONTAINMENT_LATENCY_METRIC_RUN_ID", "synthetic-input")
            .env("CONTAINMENT_LATENCY_METRIC_CODE_REVISION", "rev-under-test")
            .env("CONTAINMENT_LATENCY_METRIC_INPUT", &synthetic_input)
            .output()
            .expect("containment latency script should execute");
    assert!(
        !synthetic_output.status.success(),
        "script should reject synthetic timing evidence"
    );
    let synthetic_stderr = String::from_utf8_lossy(&synthetic_output.stderr);
    assert!(
        synthetic_stderr.contains("synthetic proof-clock clock_id")
            && synthetic_stderr.contains("synthetic duration_us=1137"),
        "stderr should identify hardcoded synthetic timings\nstderr:\n{synthetic_stderr}"
    );

    let live_input = write_live_script_input(&root, &artifact_root, "script-proof");
    let output = Command::new(root.join("scripts/run_containment_latency_metric_gate.sh"))
        .arg("ci")
        .current_dir(&root)
        .env("CONTAINMENT_LATENCY_METRIC_ARTIFACT_ROOT", &artifact_root)
        .env("CONTAINMENT_LATENCY_METRIC_RUN_ID", "script-proof")
        .env("CONTAINMENT_LATENCY_METRIC_CODE_REVISION", "rev-under-test")
        .env("CONTAINMENT_LATENCY_METRIC_INPUT", &live_input)
        .output()
        .expect("containment latency script should execute");

    assert!(
        output.status.success(),
        "script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let pass_dir = root.join(&artifact_root).join("script-proof/measured");
    let pass_manifest: ProofManifest = read_json(&pass_dir.join("manifest.json"));
    let metric_artifact: MetricArtifact = read_json(&pass_dir.join("metric_artifact.json"));

    pass_manifest.validate().expect("pass manifest validates");

    assert_eq!(pass_manifest.status, ProofRunStatus::Pass);
    assert_eq!(pass_manifest.gate_name, "containment_latency_metric_gate");
    assert!(pass_manifest.bead_ids.contains(&"bd-38mby".to_string()));
    assert!(
        pass_manifest
            .claim_ids
            .contains(&"disruptive_floor.containment_latency_250ms".to_string())
    );

    assert_eq!(
        metric_artifact.metric_id,
        DisruptiveMetricId::ContainmentLatencyMedianMs
    );
    assert_eq!(metric_artifact.observed_value, 121);
    assert_eq!(metric_artifact.threshold, 250);
    assert_eq!(metric_artifact.redaction_status, "redacted");
    assert_eq!(metric_artifact.coverage_millionths, 1_000_000);

    let event_line = std::fs::read_to_string(pass_dir.join("events.jsonl"))
        .expect("pass events should be readable")
        .lines()
        .next()
        .expect("pass bundle emits at least one event")
        .to_string();
    let event: ContainmentLatencyStructuredEvent =
        serde_json::from_str(&event_line).expect("structured event should parse");
    assert_eq!(event.signal_id, "ambient-write-denied");
    assert_eq!(event.latency_us, Some(80_417));
    assert_eq!(event.latency_ms, Some(81));
    assert_eq!(event.clock_id, "host-monotonic-clock-1");
    assert_eq!(event.duration_us, 1_432);
    assert_eq!(event.decision, "contained");
}
