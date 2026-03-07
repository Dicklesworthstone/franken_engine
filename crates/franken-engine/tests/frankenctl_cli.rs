#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::deterministic_replay::{NondeterminismSource, NondeterminismTrace};
use frankenengine_engine::runtime_diagnostics_cli::{
    GcPressureSample, RuntimeDiagnosticsCliInput, RuntimeExtensionState, RuntimeStateInput,
    SchedulerLaneSample,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}.{}", std::process::id(), nonce, ext));
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}", std::process::id(), nonce));
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

fn write_source(path: &Path, source: &str) {
    fs::write(path, source).expect("source fixture should write");
}

fn parse_stdout_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout should contain valid json")
}

fn build_doctor_input() -> RuntimeDiagnosticsCliInput {
    RuntimeDiagnosticsCliInput {
        trace_id: "trace-frankenctl-doctor".to_string(),
        decision_id: "decision-frankenctl-doctor".to_string(),
        policy_id: "policy-frankenctl-doctor".to_string(),
        runtime_state: RuntimeStateInput {
            snapshot_timestamp_ns: 42_000,
            loaded_extensions: vec![RuntimeExtensionState {
                extension_id: "ext-doctor".to_string(),
                containment_state: ContainmentState::Running,
            }],
            active_policies: vec!["policy-main".to_string()],
            security_epoch: SecurityEpoch::from_raw(7),
            gc_pressure: vec![GcPressureSample {
                extension_id: "ext-doctor".to_string(),
                used_bytes: 128,
                budget_bytes: 1_024,
            }],
            scheduler_lanes: vec![SchedulerLaneSample {
                lane: "ready".to_string(),
                queue_depth: 1,
                max_depth: 8,
                tasks_submitted: 3,
                tasks_scheduled: 3,
                tasks_completed: 3,
                tasks_timed_out: 0,
            }],
        },
        evidence_entries: Vec::new(),
        hostcall_records: Vec::new(),
        containment_receipts: Vec::new(),
        replay_artifacts: Vec::new(),
    }
}

fn write_runtime_diagnostics_input(path: &Path, input: &RuntimeDiagnosticsCliInput) {
    fs::write(
        path,
        serde_json::to_vec_pretty(input).expect("runtime diagnostics input should serialize"),
    )
    .expect("runtime diagnostics input should write");
}

#[test]
fn frankenctl_help_lists_supported_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("--help")
        .output()
        .expect("help command should execute");

    assert!(
        output.status.success(),
        "help failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("frankenctl usage"));
    assert!(stdout.contains("frankenctl compile"));
    assert!(stdout.contains("frankenctl run"));
    assert!(stdout.contains("frankenctl doctor"));
    assert!(stdout.contains("frankenctl verify"));
    assert!(stdout.contains("frankenctl benchmark run"));
    assert!(stdout.contains("frankenctl benchmark score"));
    assert!(stdout.contains("frankenctl benchmark verify"));
    assert!(stdout.contains("frankenctl replay run"));
}

#[test]
fn frankenctl_compile_then_verify_compile_artifact_round_trip() {
    let source_path = temp_path("frankenctl_compile_source", "js");
    let artifact_path = temp_path("frankenctl_compile_artifact", "json");
    write_source(&source_path, "const answer = 40 + 2;\n");

    let compile_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path
                .to_str()
                .expect("source path should be valid utf8"),
            "--out",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
            "--goal",
            "script",
            "--trace-id",
            "trace-cli-compile",
            "--decision-id",
            "decision-cli-compile",
            "--policy-id",
            "policy-cli-compile",
        ])
        .output()
        .expect("compile command should execute");

    assert!(
        compile_output.status.success(),
        "compile failed with stderr={}",
        String::from_utf8_lossy(&compile_output.stderr)
    );
    let compile_json = parse_stdout_json(&compile_output);
    assert_eq!(
        compile_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(compile_json["parse_goal"].as_str(), Some("script"));
    assert_eq!(
        compile_json["artifact_path"].as_str(),
        artifact_path.to_str()
    );

    let artifact_bytes = fs::read(&artifact_path).expect("compile artifact should exist");
    let artifact_json: serde_json::Value =
        serde_json::from_slice(&artifact_bytes).expect("artifact should be valid json");
    assert_eq!(
        artifact_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.compile-artifact.v1")
    );

    let verify_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "compile-artifact",
            "--input",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
        ])
        .output()
        .expect("verify command should execute");

    assert!(
        verify_output.status.success(),
        "verify failed with stderr={}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_json = parse_stdout_json(&verify_output);
    assert_eq!(
        verify_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(verify_json["passed"].as_bool(), Some(true));
    assert_eq!(verify_json["errors"].as_array().map(Vec::len), Some(0));

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_run_writes_execution_report() {
    let source_path = temp_path("frankenctl_run_source", "js");
    let report_path = temp_path("frankenctl_run_report", "json");
    write_source(&source_path, "let value = 2 + 3;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path
                .to_str()
                .expect("source path should be valid utf8"),
            "--extension-id",
            "ext-cli-run",
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("run command should execute");

    assert!(
        output.status.success(),
        "run failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(stdout_json["extension_id"].as_str(), Some("ext-cli-run"));
    assert!(stdout_json["trace_id"].as_str().is_some());
    assert!(stdout_json["decision_id"].as_str().is_some());
    assert_eq!(
        stdout_json["lane"].as_str(),
        Some("baseline_deterministic_profile")
    );
    assert_eq!(
        stdout_json["lane_reason"].as_str(),
        Some("default_deterministic_profile")
    );
    assert!(stdout_json["containment_action"].as_str().is_some());

    let report_bytes = fs::read(&report_path).expect("run report should be written");
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report should parse as json");
    assert_eq!(report_json["extension_id"].as_str(), Some("ext-cli-run"));
    assert_eq!(
        report_json["lane"].as_str(),
        Some("baseline_deterministic_profile")
    );
    assert_eq!(
        report_json["lane_reason"].as_str(),
        Some("default_deterministic_profile")
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_replay_run_replays_trace_without_divergence() {
    let trace_path = temp_path("frankenctl_replay_trace", "json");
    let replay_report_path = temp_path("frankenctl_replay_report", "json");

    let mut trace = NondeterminismTrace::new("session-cli-replay");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![7],
        1,
        "integration-test",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![1, 2, 3],
        2,
        "integration-test",
    );
    trace.finalise(3);

    fs::write(
        &trace_path,
        serde_json::to_vec_pretty(&trace).expect("trace should serialize"),
    )
    .expect("trace file should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path
                .to_str()
                .expect("trace path should be valid utf8"),
            "--mode",
            "strict",
            "--out",
            replay_report_path
                .to_str()
                .expect("replay report path should be valid utf8"),
        ])
        .output()
        .expect("replay command should execute");

    assert!(
        output.status.success(),
        "replay failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(stdout_json["mode"].as_str(), Some("strict"));
    assert_eq!(stdout_json["event_count"].as_u64(), Some(2));
    assert_eq!(stdout_json["divergence_count"].as_u64(), Some(0));
    assert_eq!(stdout_json["critical_divergences"].as_u64(), Some(0));
    assert_eq!(stdout_json["complete"].as_bool(), Some(true));

    let report_bytes = fs::read(&replay_report_path).expect("replay report should be written");
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("replay report should parse as json");
    assert_eq!(
        report_json["session_id"].as_str(),
        Some("session-cli-replay")
    );

    let _ = fs::remove_file(trace_path);
    let _ = fs::remove_file(replay_report_path);
}

#[test]
fn frankenctl_verify_compile_artifact_failure_includes_trace_and_remediation() {
    let artifact_path = temp_path("frankenctl_invalid_compile_artifact", "json");
    fs::write(&artifact_path, "{}\n").expect("invalid artifact fixture should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "compile-artifact",
            "--input",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
        ])
        .output()
        .expect("verify command should execute");

    assert!(
        !output.status.success(),
        "verify compile-artifact should fail for invalid payload"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=verify"),
        "stderr should include command label, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Inspect input artifact/receipt payload and rerun `frankenctl verify ...`."
        ),
        "stderr should include remediation guidance, got: {stderr}"
    );

    let _ = fs::remove_file(artifact_path);
}

// ── Version and help tests ────────────────────────────────────────────

#[test]
fn frankenctl_version_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("version")
        .output()
        .expect("version command should execute");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(!stdout.trim().is_empty(), "version should output something");
}

#[test]
fn frankenctl_dash_h_shows_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("-h")
        .output()
        .expect("-h should execute");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("frankenctl"));
}

#[test]
fn frankenctl_unknown_command_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("nonexistent-command")
        .output()
        .expect("unknown command should execute");
    assert!(!output.status.success());
}

#[test]
fn frankenctl_no_args_shows_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .output()
        .expect("no-arg invocation should execute");
    // Should either show help or fail gracefully
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stdout.contains("frankenctl") || stderr.contains("frankenctl"),
        "should mention frankenctl in output"
    );
}

// ── Compile tests ─────────────────────────────────────────────────────

#[test]
fn frankenctl_compile_module_goal() {
    let source_path = temp_path("frankenctl_compile_module", "js");
    let artifact_path = temp_path("frankenctl_compile_module_artifact", "json");
    write_source(&source_path, "const x = 42;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path.to_str().unwrap(),
            "--out",
            artifact_path.to_str().unwrap(),
            "--goal",
            "module",
            "--trace-id",
            "trace-module-compile",
            "--decision-id",
            "decision-module-compile",
            "--policy-id",
            "policy-module-compile",
        ])
        .output()
        .expect("compile module should execute");

    assert!(
        output.status.success(),
        "compile module failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["parse_goal"].as_str(), Some("module"));
    assert_eq!(
        json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_missing_input_fails() {
    let artifact_path = temp_path("frankenctl_compile_no_input", "json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["compile", "--out", artifact_path.to_str().unwrap()])
        .output()
        .expect("compile with missing input should execute");

    assert!(!output.status.success());

    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_nonexistent_source_fails() {
    let artifact_path = temp_path("frankenctl_compile_nosource", "json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            "/tmp/nonexistent_source_file_12345.js",
            "--out",
            artifact_path.to_str().unwrap(),
        ])
        .output()
        .expect("compile with nonexistent source should execute");

    assert!(!output.status.success());

    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_default_trace_ids() {
    let source_path = temp_path("frankenctl_compile_defaults", "js");
    let artifact_path = temp_path("frankenctl_compile_defaults_art", "json");
    write_source(&source_path, "var x = 1;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path.to_str().unwrap(),
            "--out",
            artifact_path.to_str().unwrap(),
        ])
        .output()
        .expect("compile with defaults should execute");

    assert!(
        output.status.success(),
        "compile defaults failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["parse_goal"].as_str(), Some("script"));
    assert!(json["hashes"]["parse_event_ir"].as_str().is_some());
    assert!(json["hashes"]["ir0"].as_str().is_some());

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

// ── Run tests ─────────────────────────────────────────────────────────

#[test]
fn frankenctl_run_without_out_still_prints_json() {
    let source_path = temp_path("frankenctl_run_noout", "js");
    write_source(&source_path, "let z = 7;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path.to_str().unwrap(),
            "--extension-id",
            "ext-noout",
        ])
        .output()
        .expect("run without --out should execute");

    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(
        json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(json["extension_id"].as_str(), Some("ext-noout"));
    assert!(json["trace_id"].as_str().is_some());

    let _ = fs::remove_file(source_path);
}

#[test]
fn frankenctl_run_missing_extension_id_fails() {
    let source_path = temp_path("frankenctl_run_no_extid", "js");
    write_source(&source_path, "let a = 1;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input", source_path.to_str().unwrap()])
        .output()
        .expect("run without extension-id should execute");

    assert!(!output.status.success());

    let _ = fs::remove_file(source_path);
}

#[test]
fn frankenctl_doctor_outputs_json_and_writes_support_bundle() {
    let input_path = temp_path("frankenctl_doctor_input", "json");
    let out_dir = temp_dir("frankenctl_doctor_bundle");
    write_runtime_diagnostics_input(&input_path, &build_doctor_input());

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().unwrap(),
            "--workload-id",
            "demo-workload",
            "--package-name",
            "demo-package",
            "--target-platform",
            "linux-x86_64",
            "--out-dir",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("doctor command should execute");

    assert!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["preflight_verdict"].as_str(), Some("green"));
    assert_eq!(json["readiness"].as_str(), Some("ready"));
    assert_eq!(json["rollout_recommendation"].as_str(), Some("promote"));
    assert_eq!(json["blocked"].as_bool(), Some(false));
    assert_eq!(json["signal_counts"]["external_signals"].as_u64(), Some(0));
    assert_eq!(
        json["signal_counts"]["compatibility_signals"].as_u64(),
        Some(0)
    );
    assert_eq!(json["signal_counts"]["platform_signals"].as_u64(), Some(0));
    assert!(
        out_dir
            .join("support_bundle/preflight_report.json")
            .is_file(),
        "expected preflight report to be written"
    );
    assert!(
        out_dir
            .join("support_bundle/onboarding_scorecard.json")
            .is_file(),
        "expected onboarding scorecard to be written"
    );
    assert!(
        out_dir
            .join("support_bundle/rollout_decision_artifact.json")
            .is_file(),
        "expected rollout decision artifact to be written"
    );
    assert!(
        out_dir
            .join("support_bundle/frankenctl_doctor_report.json")
            .is_file(),
        "expected doctor report to be written"
    );

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn frankenctl_doctor_can_inline_compatibility_scenario_report() {
    let input_path = temp_path("frankenctl_doctor_input_with_advisories", "json");
    write_runtime_diagnostics_input(&input_path, &build_doctor_input());
    let scenario_report = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runtime_compatibility_scenario_report_v1.json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().unwrap(),
            "--scenario-report",
            scenario_report.to_str().unwrap(),
        ])
        .output()
        .expect("doctor command should execute");

    assert_eq!(
        output.status.code(),
        Some(25),
        "critical compatibility advisories should produce blocked exit code"
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["preflight_verdict"].as_str(), Some("green"));
    assert_eq!(
        json["signal_counts"]["compatibility_signals"].as_u64(),
        Some(1)
    );
    assert_eq!(json["blocked"].as_bool(), Some(true));
    assert!(
        json["rollout_decision"]["merged_signals"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "expected rollout decision to include compatibility advisory signal"
    );

    let _ = fs::remove_file(input_path);
}

#[test]
fn frankenctl_doctor_summary_mentions_verdict_and_recommendation() {
    let input_path = temp_path("frankenctl_doctor_summary_input", "json");
    write_runtime_diagnostics_input(&input_path, &build_doctor_input());

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().unwrap(),
            "--summary",
        ])
        .output()
        .expect("doctor --summary command should execute");

    assert!(
        output.status.success(),
        "doctor --summary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("preflight_verdict: green"));
    assert!(stdout.contains("recommendation: promote"));
    assert!(stdout.contains("blocked: false"));

    let _ = fs::remove_file(input_path);
}

// ── Verify tests ──────────────────────────────────────────────────────

#[test]
fn frankenctl_verify_missing_subcommand_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("verify")
        .output()
        .expect("verify without subcommand should execute");

    assert!(!output.status.success());
}

#[test]
fn frankenctl_verify_compile_artifact_nonexistent_file_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "compile-artifact",
            "--input",
            "/tmp/nonexistent_artifact_99999.json",
        ])
        .output()
        .expect("verify nonexistent file should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("[frankenctl"));
}

// ── Replay tests ──────────────────────────────────────────────────────

#[test]
fn frankenctl_replay_best_effort_mode() {
    let trace_path = temp_path("frankenctl_replay_besteffort", "json");
    let report_path = temp_path("frankenctl_replay_besteffort_report", "json");

    let mut trace = NondeterminismTrace::new("session-best-effort");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        1,
        "integration-test",
    );
    trace.finalise(2);
    fs::write(&trace_path, serde_json::to_vec_pretty(&trace).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "best-effort",
            "--out",
            report_path.to_str().unwrap(),
        ])
        .output()
        .expect("replay best-effort should execute");

    assert!(
        output.status.success(),
        "replay best-effort failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["mode"].as_str(), Some("best-effort"));
    assert_eq!(json["event_count"].as_u64(), Some(1));

    let _ = fs::remove_file(trace_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_replay_validate_mode() {
    let trace_path = temp_path("frankenctl_replay_validate", "json");

    let mut trace = NondeterminismTrace::new("session-validate");
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![10, 20],
        1,
        "integration-test",
    );
    trace.finalise(2);
    fs::write(&trace_path, serde_json::to_vec_pretty(&trace).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "validate",
        ])
        .output()
        .expect("replay validate should execute");

    assert!(
        output.status.success(),
        "replay validate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["mode"].as_str(), Some("validate"));

    let _ = fs::remove_file(trace_path);
}

#[test]
fn frankenctl_replay_nonexistent_trace_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            "/tmp/nonexistent_trace_99999.json",
        ])
        .output()
        .expect("replay nonexistent trace should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("[frankenctl"));
}

#[test]
fn frankenctl_replay_missing_trace_arg_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["replay", "run"])
        .output()
        .expect("replay without trace should execute");

    assert!(!output.status.success());
}

// ── Error output contract tests ───────────────────────────────────────

#[test]
fn frankenctl_error_output_includes_trace_id_and_remediation() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            "/tmp/nonexistent_source_for_error_test.js",
            "--out",
            "/tmp/out.json",
        ])
        .output()
        .expect("compile error should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id="),
        "error should include trace_id prefix: {stderr}"
    );
    assert!(
        stderr.contains("command=compile"),
        "error should include command label: {stderr}"
    );
    assert!(
        stderr.contains("remediation:"),
        "error should include remediation guidance: {stderr}"
    );
}

// ── Schema version contract tests ─────────────────────────────────────

#[test]
fn frankenctl_compile_output_schema_version_is_v1() {
    let source_path = temp_path("frankenctl_schema_check", "js");
    let artifact_path = temp_path("frankenctl_schema_check_art", "json");
    write_source(&source_path, "var q = true;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path.to_str().unwrap(),
            "--out",
            artifact_path.to_str().unwrap(),
        ])
        .output()
        .expect("compile should execute");

    if output.status.success() {
        let json = parse_stdout_json(&output);
        assert_eq!(
            json["schema_version"].as_str(),
            Some("franken-engine.frankenctl.v1")
        );

        let art: serde_json::Value =
            serde_json::from_slice(&fs::read(&artifact_path).expect("artifact should exist"))
                .expect("artifact should parse");
        assert_eq!(
            art["schema_version"].as_str(),
            Some("franken-engine.frankenctl.compile-artifact.v1")
        );
    }

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_run_output_has_execution_fields() {
    let source_path = temp_path("frankenctl_run_fields", "js");
    write_source(&source_path, "let b = 2 * 3;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path.to_str().unwrap(),
            "--extension-id",
            "ext-fields",
        ])
        .output()
        .expect("run should execute");

    assert!(output.status.success());
    let json = parse_stdout_json(&output);
    assert!(json["lane"].as_str().is_some());
    assert!(json["containment_action"].as_str().is_some());
    assert!(json["instructions_executed"].as_u64().is_some());
    assert!(json["evidence_entries"].as_u64().is_some());

    let _ = fs::remove_file(source_path);
}

#[test]
fn frankenctl_benchmark_score_and_verify_bundle_round_trip() {
    let score_input_path = temp_path("frankenctl_benchmark_score_input", "json");
    let score_results_path = temp_path("frankenctl_benchmark_score_results", "json");
    let verify_report_path = temp_path("frankenctl_benchmark_verify_report", "json");
    let bundle_dir = temp_dir("frankenctl_benchmark_bundle");

    let score_input = serde_json::json!({
        "node_cases": [
            {
                "workload_id": "boot-storm/s",
                "throughput_franken_tps": 3000.0,
                "throughput_baseline_tps": 900.0,
                "weight": null,
                "behavior_equivalent": true,
                "latency_envelope_ok": true,
                "error_envelope_ok": true
            }
        ],
        "bun_cases": [
            {
                "workload_id": "boot-storm/s",
                "throughput_franken_tps": 3000.0,
                "throughput_baseline_tps": 950.0,
                "weight": null,
                "behavior_equivalent": true,
                "latency_envelope_ok": true,
                "error_envelope_ok": true
            }
        ],
        "native_coverage_progression": [
            {
                "recorded_at_utc": "2026-03-01T00:00:00Z",
                "native_slots": 42,
                "total_slots": 48
            }
        ],
        "replacement_lineage_ids": ["lineage-a"]
    });
    fs::write(
        &score_input_path,
        serde_json::to_vec_pretty(&score_input).expect("score input should serialize"),
    )
    .expect("score input should write");

    let score_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "score",
            "--input",
            score_input_path
                .to_str()
                .expect("score input path should be valid utf8"),
            "--trace-id",
            "trace-bench-score-cli",
            "--decision-id",
            "decision-bench-score-cli",
            "--policy-id",
            "policy-bench-score-cli",
            "--output",
            score_results_path
                .to_str()
                .expect("score result path should be valid utf8"),
        ])
        .output()
        .expect("benchmark score command should execute");

    assert!(
        score_output.status.success(),
        "benchmark score failed with stderr={}",
        String::from_utf8_lossy(&score_output.stderr)
    );
    let score_json = parse_stdout_json(&score_output);
    assert_eq!(
        score_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(
        score_json["trace_id"].as_str(),
        Some("trace-bench-score-cli")
    );
    assert_eq!(
        score_json["decision_id"].as_str(),
        Some("decision-bench-score-cli")
    );
    assert_eq!(
        score_json["policy_id"].as_str(),
        Some("policy-bench-score-cli")
    );
    assert_eq!(score_json["publish_allowed"].as_bool(), Some(true));

    let results_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&score_results_path).expect("score results should be written"),
    )
    .expect("score results should parse");
    assert_eq!(
        results_json["trace_id"].as_str(),
        Some("trace-bench-score-cli")
    );
    assert_eq!(
        results_json["claimed"]["publish_allowed"].as_bool(),
        Some(true)
    );

    let bundle_results_path = bundle_dir.join("results.json");
    fs::copy(&score_results_path, &bundle_results_path).expect("results.json should copy");
    fs::write(
        bundle_dir.join("env.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "toolchain": "rust-1.86.0",
            "os": "linux",
            "arch": "x86_64"
        }))
        .expect("env fixture should serialize"),
    )
    .expect("env fixture should write");
    fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "franken-engine.benchmark.bundle.v1",
            "trace_id": "trace-bench-score-cli",
            "decision_id": "decision-bench-score-cli",
            "policy_id": "policy-bench-score-cli"
        }))
        .expect("manifest fixture should serialize"),
    )
    .expect("manifest fixture should write");
    fs::write(
        bundle_dir.join("repro.lock"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "franken-engine.benchmark.repro-lock.v1",
            "bundle_digest_sha256": "abc123"
        }))
        .expect("repro lock fixture should serialize"),
    )
    .expect("repro lock fixture should write");
    fs::write(
        bundle_dir.join("commands.txt"),
        "rch exec -- cargo test -p frankenengine-engine --test benchmark_denominator\n",
    )
    .expect("commands fixture should write");

    let verify_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir
                .to_str()
                .expect("bundle path should be valid utf8"),
            "--summary",
            "--output",
            verify_report_path
                .to_str()
                .expect("verify report path should be valid utf8"),
        ])
        .output()
        .expect("benchmark verify command should execute");

    assert!(
        verify_output.status.success(),
        "benchmark verify failed with stderr={}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_stdout = String::from_utf8(verify_output.stdout).expect("stdout should be utf8");
    assert!(verify_stdout.contains("claim_type=benchmark"));

    let verify_report: serde_json::Value = serde_json::from_slice(
        &fs::read(&verify_report_path).expect("verify report should be written"),
    )
    .expect("verify report should parse");
    assert_eq!(verify_report["claim_type"].as_str(), Some("benchmark"));
    assert_eq!(verify_report["verdict"].as_str(), Some("verified"));
    assert!(
        verify_report["checks"]
            .as_array()
            .is_some_and(|checks| !checks.is_empty())
    );
    assert!(
        verify_report["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty())
    );

    let _ = fs::remove_file(score_input_path);
    let _ = fs::remove_file(score_results_path);
    let _ = fs::remove_file(verify_report_path);
    let _ = fs::remove_dir_all(bundle_dir);
}

// ── Replay trace serde roundtrip tests ────────────────────────────────

#[test]
fn frankenctl_replay_trace_serde_roundtrip_preserves_all_source_kinds() {
    let trace_path = temp_path("frankenctl_replay_serde_all", "json");

    let mut trace = NondeterminismTrace::new("session-serde-all-sources");
    for (vts, source) in NondeterminismSource::ALL.iter().enumerate() {
        trace.capture(
            source.clone(),
            vec![(vts as u8)],
            (vts as u64) + 1,
            "serde-test",
        );
    }
    trace.finalise((NondeterminismSource::ALL.len() as u64) + 1);

    let serialized = serde_json::to_vec_pretty(&trace).expect("trace should serialize");
    fs::write(&trace_path, &serialized).expect("trace file should write");

    let read_back = fs::read(&trace_path).expect("trace file should be readable");
    let deserialized: NondeterminismTrace =
        serde_json::from_slice(&read_back).expect("trace should deserialize");

    assert_eq!(
        deserialized.event_count(),
        NondeterminismSource::ALL.len(),
        "deserialized trace should preserve all source kind events"
    );
    assert!(deserialized.is_finalised());

    // Verify the roundtripped trace replays successfully
    let report_path = temp_path("frankenctl_replay_serde_all_report", "json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "best-effort",
            "--out",
            report_path.to_str().unwrap(),
        ])
        .output()
        .expect("replay should execute");

    assert!(
        output.status.success(),
        "replay of roundtripped trace failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(
        json["event_count"].as_u64(),
        Some(NondeterminismSource::ALL.len() as u64)
    );

    let _ = fs::remove_file(trace_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_compile_empty_source_file_fails_with_structured_error() {
    let source_path = temp_path("frankenctl_compile_empty", "js");
    let artifact_path = temp_path("frankenctl_compile_empty_art", "json");
    write_source(&source_path, "");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path.to_str().unwrap(),
            "--out",
            artifact_path.to_str().unwrap(),
        ])
        .output()
        .expect("compile empty source should execute");

    assert!(
        !output.status.success(),
        "compile of empty source should fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl"),
        "error should include frankenctl prefix: {stderr}"
    );
    assert!(
        stderr.contains("remediation:"),
        "error should include remediation guidance: {stderr}"
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_deterministic_hashes_across_runs() {
    let source_path = temp_path("frankenctl_compile_determ", "js");
    let artifact_1 = temp_path("frankenctl_compile_determ_1", "json");
    let artifact_2 = temp_path("frankenctl_compile_determ_2", "json");
    write_source(&source_path, "const pi = 3;\n");

    let run_compile = |art: &std::path::Path| -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "compile",
                "--input",
                source_path.to_str().unwrap(),
                "--out",
                art.to_str().unwrap(),
                "--trace-id",
                "trace-determ",
                "--decision-id",
                "decision-determ",
                "--policy-id",
                "policy-determ",
            ])
            .output()
            .expect("compile should execute");
        assert!(output.status.success());
        parse_stdout_json(&output)
    };

    let json1 = run_compile(&artifact_1);
    let json2 = run_compile(&artifact_2);

    assert_eq!(
        json1["hashes"]["parse_event_ir"], json2["hashes"]["parse_event_ir"],
        "parse_event_ir hash must be deterministic across runs"
    );
    assert_eq!(
        json1["hashes"]["ir0"], json2["hashes"]["ir0"],
        "ir0 hash must be deterministic across runs"
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_1);
    let _ = fs::remove_file(artifact_2);
}

#[test]
fn frankenctl_replay_empty_trace_completes_immediately() {
    let trace_path = temp_path("frankenctl_replay_empty", "json");

    let mut trace = NondeterminismTrace::new("session-empty");
    trace.finalise(1);

    fs::write(
        &trace_path,
        serde_json::to_vec_pretty(&trace).expect("trace should serialize"),
    )
    .expect("trace file should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "strict",
        ])
        .output()
        .expect("replay empty trace should execute");

    assert!(
        output.status.success(),
        "replay empty trace failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["event_count"].as_u64(), Some(0));
    assert_eq!(json["divergence_count"].as_u64(), Some(0));
    assert_eq!(json["complete"].as_bool(), Some(true));

    let _ = fs::remove_file(trace_path);
}

#[test]
fn frankenctl_replay_unfinished_trace_fails_closed() {
    let trace_path = temp_path("frankenctl_replay_unfinished", "json");

    let mut trace = NondeterminismTrace::new("session-unfinished");
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![1, 2, 3],
        1,
        "integration-test",
    );

    fs::write(
        &trace_path,
        serde_json::to_vec_pretty(&trace).expect("trace should serialize"),
    )
    .expect("trace file should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "strict",
        ])
        .output()
        .expect("replay unfinished trace should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("trace is not finalised"), "{stderr}");

    let _ = fs::remove_file(trace_path);
}

#[test]
fn frankenctl_benchmark_verify_missing_bundle_dir_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            "/tmp/nonexistent_bundle_dir_99999",
        ])
        .output()
        .expect("benchmark verify with missing bundle should execute");

    assert!(
        !output.status.success(),
        "benchmark verify should fail for missing bundle dir"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl"),
        "error output should include frankenctl trace prefix: {stderr}"
    );
}
