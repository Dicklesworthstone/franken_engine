#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::tail_latency_control_plane::{
    GuardrailState, StressProfile, TAIL_LATENCY_CONTROL_PLANE_BEAD_ID,
    TAIL_LATENCY_CONTROL_PLANE_COMPONENT, TailLatencyControlPlaneReport,
    TailLatencyControlPlaneRunManifest, TailLatencyControlPlaneTraceIds,
    build_tail_latency_control_plane_report, write_tail_latency_control_plane_bundle,
};

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_tail_latency_control_plane_{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn extract_streamed_artifact(stdout: &str, artifact_name: &str) -> String {
    let begin = format!("__RGC_TAIL_LATENCY_CONTROL_PLANE_ARTIFACT__:BEGIN:{artifact_name}\n");
    let end = format!("\n__RGC_TAIL_LATENCY_CONTROL_PLANE_ARTIFACT__:END:{artifact_name}");
    let start = stdout
        .find(&begin)
        .unwrap_or_else(|| panic!("missing begin marker for {artifact_name}"))
        + begin.len();
    let end_offset = stdout[start..]
        .find(&end)
        .unwrap_or_else(|| panic!("missing end marker for {artifact_name}"));
    stdout[start..start + end_offset].to_string()
}

#[test]
fn synthetic_contention_report_engages_fallback() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 42).unwrap();
    assert_eq!(report.bead_id, TAIL_LATENCY_CONTROL_PLANE_BEAD_ID);
    assert_eq!(report.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert!(report.guardrails.fallback_activated);
    assert_eq!(report.guardrails.state, GuardrailState::FallbackEngaged);
    assert!(!report.violation_reports.is_empty());
}

#[test]
fn balanced_report_stays_dependency_safe() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 11).unwrap();
    assert!(!report.guardrails.fallback_activated);
    assert_eq!(report.admission_manifest.summary.total_shed, 0);
    assert!(report.end_to_end_bounds.budget_p99_ns >= report.end_to_end_bounds.observed_p99_ns);
}

#[test]
fn write_bundle_emits_expected_artifacts() {
    let out_dir = unique_dir("bundle");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        42,
        &[String::from(
            "cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- --out-dir <dir>",
        )],
    )
    .unwrap();

    assert!(artifacts.report_path.exists());
    assert!(artifacts.trace_ids_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.step_logs_dir.join("step_000.log").exists());
    assert!(artifacts.summary_path.exists());
    assert!(artifacts.env_path.exists());
    assert!(artifacts.repro_lock_path.exists());
}

#[test]
fn manifest_and_trace_ids_reference_latency_control_plane_bundle() {
    let out_dir = unique_dir("manifest");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        42,
        &[String::from(
            "cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- --out-dir <dir> --profile synthetic-contention --epoch 42",
        )],
    )
    .unwrap();

    let manifest: TailLatencyControlPlaneRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read run manifest"))
            .unwrap();
    let trace_ids: TailLatencyControlPlaneTraceIds =
        serde_json::from_slice(&fs::read(&artifacts.trace_ids_path).expect("read trace ids"))
            .unwrap();
    let commands = fs::read_to_string(&artifacts.commands_path).unwrap();

    assert_eq!(
        manifest.artifact_paths.latency_control_plane_report,
        "latency_control_plane_report.json"
    );
    assert_eq!(manifest.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert_eq!(trace_ids.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert!(commands.contains("franken_tail_latency_control_plane"));
    assert_eq!(manifest.trace_id, trace_ids.trace_id);
}

#[test]
fn balanced_binary_emits_streamed_artifacts_without_fallback() {
    let out_dir = unique_dir("balanced-stream");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_tail_latency_control_plane"))
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--profile")
        .arg("balanced")
        .arg("--epoch")
        .arg("77")
        .arg("--emit-artifact-stream")
        .output()
        .expect("run tail latency control plane binary");

    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let manifest: TailLatencyControlPlaneRunManifest =
        serde_json::from_str(&extract_streamed_artifact(&stdout, "run_manifest.json"))
            .expect("streamed manifest json");
    let report: TailLatencyControlPlaneReport = serde_json::from_str(&extract_streamed_artifact(
        &stdout,
        "latency_control_plane_report.json",
    ))
    .expect("streamed report json");
    let commands = extract_streamed_artifact(&stdout, "commands.txt");
    let step_log = extract_streamed_artifact(&stdout, "step_logs/step_000.log");

    assert_eq!(manifest.profile, StressProfile::Balanced);
    assert!(!manifest.fallback_activated);
    assert_eq!(manifest.guardrail_state, GuardrailState::Nominal);
    assert_eq!(report.guardrails.state, GuardrailState::Nominal);
    assert!(!report.guardrails.fallback_activated);
    assert!(commands.contains("--emit-artifact-stream"));
    assert!(step_log.contains("guardrail_state=nominal"));
    assert!(out_dir.join("run_manifest.json").exists());
    assert!(out_dir.join("latency_control_plane_report.json").exists());
}
