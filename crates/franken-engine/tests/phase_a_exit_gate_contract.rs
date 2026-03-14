#![forbid(unsafe_code)]
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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_{label}_{nanos}_{}",
        std::process::id()
    ))
}

fn latest_run_dir(root: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = fs::read_dir(root)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", root.display()))
        .map(|entry| entry.expect("directory entry should load").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs.pop().expect("expected one phase-a run directory")
}

#[test]
fn phase_a_gate_blocked_mode_emits_standard_artifact_triad() {
    let artifacts_root = temp_dir("phase_a_exit_gate_contract");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate script should execute");

    assert!(
        !output.status.success(),
        "blocked dependency state should fail closed"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("Phase-A gate blocked by unresolved dependencies"),
        "expected blocked message in stderr, got: {stderr}"
    );

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");

    assert!(manifest_path.exists(), "manifest must exist");
    assert!(events_path.exists(), "events.jsonl must exist");
    assert!(commands_path.exists(), "commands.txt must exist");
    assert!(
        !run_dir.join("phase_a_exit_gate_events.jsonl").exists(),
        "legacy event filename must not be emitted"
    );

    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_path.display())),
    )
    .expect("manifest json should parse");

    assert_eq!(
        manifest["schema_version"],
        "franken-engine.phase-a-exit-gate.run-manifest.v1"
    );
    assert_eq!(manifest["component"], "phase_a_exit_gate");
    assert_eq!(manifest["bead_id"], "bd-1csl");
    assert_eq!(manifest["mode"], "check");
    assert_eq!(manifest["skip_subgates"], 1);
    assert_eq!(manifest["outcome"], "fail");
    let unmet_dependencies = manifest["unmet_dependencies"]
        .as_array()
        .expect("unmet dependencies should be array");
    assert!(
        unmet_dependencies.iter().any(|value| value
            .as_str()
            .is_some_and(|value| value.starts_with("bd-ntq="))),
        "expected unresolved phase-a dependencies in manifest: {manifest:#}"
    );
    let operator_verification: Vec<&str> = manifest["operator_verification"]
        .as_array()
        .expect("operator verification should be array")
        .iter()
        .map(|value| value.as_str().expect("operator command should be string"))
        .collect();
    assert!(
        operator_verification
            .iter()
            .any(|command| command.ends_with("/run_manifest.json")),
        "expected manifest inspection command in operator verification: {operator_verification:?}"
    );
    assert!(
        operator_verification
            .iter()
            .any(|command| command.ends_with("/events.jsonl")),
        "expected events inspection command in operator verification: {operator_verification:?}"
    );
    assert!(
        operator_verification
            .iter()
            .any(|command| command.contains("PHASE_A_GATE_SKIP_SUBGATES=1")),
        "expected skip-subgates replay command in operator verification: {operator_verification:?}"
    );

    let events = fs::read_to_string(&events_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", events_path.display()));
    assert!(
        events.contains("\"event\":\"phase_a_gate_completed\""),
        "expected completion event in events.jsonl: {events}"
    );
    assert!(
        events.contains("\"outcome\":\"fail\""),
        "expected fail outcome in events.jsonl: {events}"
    );
    assert!(
        events.contains("\"error_code\":\"FE-PHASE-A-GATE-1001\""),
        "expected fail-closed error code in events.jsonl: {events}"
    );

    let commands = fs::read_to_string(&commands_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", commands_path.display()));
    assert!(
        commands.trim().is_empty(),
        "skip-subgates blocked run should not record sub-gate commands: {commands}"
    );

    assert!(
        stdout.contains("phase-a gate run manifest:"),
        "expected manifest path in stdout, got: {stdout}"
    );
    assert!(
        stdout.contains("phase-a gate events:"),
        "expected events path in stdout, got: {stdout}"
    );
}

fn read_gate_script() -> String {
    let path = repo_root().join("scripts/run_phase_a_exit_gate.sh");
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read gate script: {err}"))
}

#[test]
fn phase_a_gate_script_exists_and_is_executable() {
    let path = repo_root().join("scripts/run_phase_a_exit_gate.sh");
    assert!(path.exists(), "gate script must exist");
    let metadata = fs::metadata(&path).expect("read metadata");
    let permissions = metadata.permissions();
    use std::os::unix::fs::PermissionsExt;
    assert!(
        permissions.mode() & 0o111 != 0,
        "gate script must be executable"
    );
}

#[test]
fn phase_a_gate_script_has_strict_bash_mode() {
    let script = read_gate_script();
    assert!(script.contains("set -euo pipefail"));
}

#[test]
fn phase_a_gate_script_references_component() {
    let script = read_gate_script();
    assert!(script.contains("component=\"phase_a_exit_gate\""));
}

#[test]
fn phase_a_gate_script_references_bead_id() {
    let script = read_gate_script();
    assert!(script.contains("bead_id=\"bd-1csl\""));
}

#[test]
fn phase_a_gate_script_references_policy_id() {
    let script = read_gate_script();
    assert!(script.contains("policy-phase-a-exit-gate-v1"));
}

#[test]
fn phase_a_gate_script_creates_run_directory() {
    let script = read_gate_script();
    assert!(script.contains("mkdir -p"));
}

#[test]
fn phase_a_gate_script_writes_manifest_events_commands() {
    let script = read_gate_script();
    assert!(script.contains("run_manifest.json"));
    assert!(script.contains("events.jsonl"));
    assert!(script.contains("commands.txt"));
}

#[test]
fn phase_a_gate_script_checks_dependencies() {
    let script = read_gate_script();
    assert!(script.contains("check_dependencies"));
    assert!(script.contains("dependency_ids"));
}

#[test]
fn phase_a_gate_script_dependency_list_includes_core_epics() {
    let script = read_gate_script();
    assert!(script.contains("bd-ntq"));
    assert!(script.contains("bd-3vk"));
    assert!(script.contains("bd-383"));
}

#[test]
fn phase_a_gate_script_supports_skip_subgates_env_var() {
    let script = read_gate_script();
    assert!(script.contains("PHASE_A_GATE_SKIP_SUBGATES"));
}

#[test]
fn phase_a_gate_script_supports_artifact_root_env_var() {
    let script = read_gate_script();
    assert!(script.contains("PHASE_A_GATE_ARTIFACT_ROOT"));
}

#[test]
fn phase_a_gate_script_uses_json_escape() {
    let script = read_gate_script();
    assert!(script.contains("json_escape"));
}

#[test]
fn phase_a_gate_script_uses_run_step_function() {
    let script = read_gate_script();
    assert!(script.contains("run_step"));
}

#[test]
fn phase_a_gate_script_includes_error_code() {
    let script = read_gate_script();
    assert!(script.contains("FE-PHASE-A-GATE-1001"));
}

#[test]
fn phase_a_gate_script_emits_structured_events() {
    let script = read_gate_script();
    assert!(script.contains("phase_a_gate_completed"));
}

#[test]
fn phase_a_gate_script_captures_step_logs() {
    let script = read_gate_script();
    assert!(script.contains("logs_dir"));
    assert!(script.contains("step_"));
}

#[test]
fn phase_a_gate_script_references_schema_version() {
    let script = read_gate_script();
    assert!(script.contains("franken-engine.phase-a-exit-gate.run-manifest.v1"));
}

#[test]
fn phase_a_gate_blocked_mode_manifest_has_expected_schema() {
    let artifacts_root = temp_dir("phase_a_schema_check");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    assert!(manifest["generated_at_utc"].is_string());
    assert!(manifest["trace_id"].is_string());
    assert!(manifest["decision_id"].is_string());
    assert!(manifest["policy_id"].is_string());
}

#[test]
fn phase_a_gate_blocked_mode_manifest_contains_dependency_list() {
    let artifacts_root = temp_dir("phase_a_deps_check");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let deps = manifest["unmet_dependencies"]
        .as_array()
        .expect("unmet_dependencies array");
    assert!(!deps.is_empty());
}

#[test]
fn phase_a_gate_blocked_events_contain_trace_and_decision_ids() {
    let artifacts_root = temp_dir("phase_a_trace_check");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let events = fs::read_to_string(run_dir.join("events.jsonl")).expect("read events");

    for line in events.lines() {
        let event: Value = serde_json::from_str(line).expect("event json");
        assert!(event["trace_id"].is_string());
        assert!(event["decision_id"].is_string());
        assert!(event["component"].is_string());
    }
}

#[test]
fn phase_a_gate_blocked_manifest_keys_are_complete() {
    let artifacts_root = temp_dir("phase_a_keys_check");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let required_keys: BTreeSet<&str> =
        ["schema_version", "component", "bead_id", "mode", "outcome"]
            .into_iter()
            .collect();

    let actual_keys: BTreeSet<&str> = manifest
        .as_object()
        .expect("manifest object")
        .keys()
        .map(String::as_str)
        .collect();

    for key in &required_keys {
        assert!(actual_keys.contains(key), "missing manifest key: {key}");
    }
}

#[test]
fn phase_a_gate_script_run_subgates_when_blocked_env_var() {
    let script = read_gate_script();
    assert!(script.contains("PHASE_A_GATE_RUN_SUBGATES_WHEN_BLOCKED"));
}

#[test]
fn phase_a_gate_script_does_not_contain_legacy_event_filename() {
    let script = read_gate_script();
    assert!(
        !script.contains("phase_a_exit_gate_events.jsonl"),
        "script must not reference legacy event filename"
    );
}

#[test]
fn phase_a_gate_script_supports_check_mode() {
    let script = read_gate_script();
    assert!(script.contains("check"));
}

#[test]
fn phase_a_gate_script_supports_ci_mode() {
    let script = read_gate_script();
    assert!(script.contains("ci"));
}

#[test]
fn phase_a_gate_blocked_run_dir_follows_timestamp_convention() {
    let artifacts_root = temp_dir("phase_a_timestamp_check");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let dir_name = run_dir.file_name().unwrap().to_str().unwrap();
    assert!(
        dir_name.len() > 10,
        "run dir name should be a timestamp, got: {dir_name}"
    );
    assert!(
        dir_name.starts_with("20"),
        "run dir should start with year prefix, got: {dir_name}"
    );
}

#[test]
fn phase_a_gate_script_has_shebang() {
    let script = read_gate_script();
    assert!(script.starts_with("#!/usr/bin/env bash"));
}

#[test]
fn phase_a_gate_script_captures_subgate_artifacts() {
    let script = read_gate_script();
    assert!(script.contains("capture_subgate_artifacts"));
}

#[test]
fn phase_a_gate_blocked_mode_logs_dir_exists() {
    let artifacts_root = temp_dir("phase_a_logs_check");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    assert!(run_dir.join("logs").exists(), "logs directory must exist");
}

#[test]
fn phase_a_gate_manifest_is_valid_json_object() {
    let artifacts_root = temp_dir("phase_a_valid_json");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest_text =
        fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest");
    let manifest: Value = serde_json::from_str(&manifest_text).expect("parse manifest");
    assert!(manifest.is_object(), "manifest must be a JSON object");
}

#[test]
fn phase_a_gate_manifest_dependency_statuses_array_has_entries() {
    let artifacts_root = temp_dir("phase_a_dep_statuses");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let dep_statuses = manifest["dependency_statuses"]
        .as_array()
        .expect("dependency_statuses array");
    assert!(
        !dep_statuses.is_empty(),
        "dependency_statuses should have at least one entry"
    );
    for dep in dep_statuses {
        assert!(
            dep["id"].is_string(),
            "each dependency status must have an 'id' string"
        );
        assert!(
            dep["status"].is_string(),
            "each dependency status must have a 'status' string"
        );
    }
}

#[test]
fn phase_a_gate_manifest_dependency_count_matches_script() {
    let artifacts_root = temp_dir("phase_a_dep_count");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let dep_statuses = manifest["dependency_statuses"]
        .as_array()
        .expect("dependency_statuses array");
    // The script defines 8 dependency_ids
    assert_eq!(
        dep_statuses.len(),
        8,
        "expected 8 dependency statuses matching dependency_ids array in script"
    );
}

#[test]
fn phase_a_gate_manifest_subgate_artifacts_section_exists() {
    let artifacts_root = temp_dir("phase_a_subgate_artifacts");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let subgate = manifest["subgate_artifacts"]
        .as_object()
        .expect("subgate_artifacts object");
    assert!(
        subgate.contains_key("test262_manifest"),
        "subgate_artifacts must contain test262_manifest key"
    );
    assert!(
        subgate.contains_key("parser_oracle_manifest"),
        "subgate_artifacts must contain parser_oracle_manifest key"
    );
}

#[test]
fn phase_a_gate_manifest_subgate_artifacts_null_when_skipped() {
    let artifacts_root = temp_dir("phase_a_subgate_null");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    assert!(
        manifest["subgate_artifacts"]["test262_manifest"].is_null(),
        "test262_manifest should be null when subgates are skipped"
    );
    assert!(
        manifest["subgate_artifacts"]["parser_oracle_manifest"].is_null(),
        "parser_oracle_manifest should be null when subgates are skipped"
    );
}

#[test]
fn phase_a_gate_manifest_operator_verification_has_six_entries() {
    let artifacts_root = temp_dir("phase_a_operator_count");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let ops = manifest["operator_verification"]
        .as_array()
        .expect("operator_verification array");
    assert_eq!(
        ops.len(),
        6,
        "operator_verification should have exactly 6 entries (3 cat, skip_subgates, run_subgates_when_blocked, ci)"
    );
}

#[test]
fn phase_a_gate_manifest_operator_verification_includes_run_subgates_when_blocked_replay() {
    let artifacts_root = temp_dir("phase_a_op_run_subgates");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let ops: Vec<&str> = manifest["operator_verification"]
        .as_array()
        .expect("operator verification array")
        .iter()
        .map(|v| v.as_str().expect("string entry"))
        .collect();
    assert!(
        ops.iter()
            .any(|cmd| cmd.contains("PHASE_A_GATE_RUN_SUBGATES_WHEN_BLOCKED=1")),
        "expected run_subgates_when_blocked replay in operator verification: {ops:?}"
    );
}

#[test]
fn phase_a_gate_manifest_operator_verification_includes_ci_replay() {
    let artifacts_root = temp_dir("phase_a_op_ci_replay");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let ops: Vec<&str> = manifest["operator_verification"]
        .as_array()
        .expect("operator verification array")
        .iter()
        .map(|v| v.as_str().expect("string entry"))
        .collect();
    assert!(
        ops.iter()
            .any(|cmd| cmd.contains("run_phase_a_exit_gate.sh ci")),
        "expected ci replay command in operator verification: {ops:?}"
    );
}

#[test]
fn phase_a_gate_manifest_commands_array_empty_when_skip_subgates() {
    let artifacts_root = temp_dir("phase_a_cmds_empty");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let commands = manifest["commands"].as_array().expect("commands array");
    assert!(
        commands.is_empty(),
        "commands array should be empty when subgates are skipped"
    );
}

#[test]
fn phase_a_gate_manifest_command_logs_array_empty_when_skip_subgates() {
    let artifacts_root = temp_dir("phase_a_cmd_logs_empty");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let command_logs = manifest["command_logs"]
        .as_array()
        .expect("command_logs array");
    assert!(
        command_logs.is_empty(),
        "command_logs array should be empty when subgates are skipped"
    );
}

#[test]
fn phase_a_gate_manifest_failed_log_null_when_no_subgate_failure() {
    let artifacts_root = temp_dir("phase_a_failed_log_null");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    assert!(
        manifest["failed_log"].is_null(),
        "failed_log should be null when no subgate command failed"
    );
}

#[test]
fn phase_a_gate_manifest_toolchain_field_is_string() {
    let artifacts_root = temp_dir("phase_a_toolchain");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    assert!(
        manifest["toolchain"].is_string(),
        "toolchain field must be a string"
    );
    let toolchain = manifest["toolchain"].as_str().unwrap();
    assert!(!toolchain.is_empty(), "toolchain should not be empty");
}

#[test]
fn phase_a_gate_manifest_run_subgates_when_blocked_field_present() {
    let artifacts_root = temp_dir("phase_a_rsb_field");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    assert!(
        manifest
            .as_object()
            .unwrap()
            .contains_key("run_subgates_when_blocked"),
        "manifest must contain run_subgates_when_blocked field"
    );
    assert_eq!(
        manifest["run_subgates_when_blocked"], 0,
        "run_subgates_when_blocked should default to 0"
    );
}

#[test]
fn phase_a_gate_events_jsonl_single_line_per_event() {
    let artifacts_root = temp_dir("phase_a_events_lines");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let events = fs::read_to_string(run_dir.join("events.jsonl")).expect("read events");

    let non_empty_lines: Vec<&str> = events.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !non_empty_lines.is_empty(),
        "events.jsonl must contain at least one event"
    );
    for line in &non_empty_lines {
        let parsed: Result<Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "each line in events.jsonl must be valid JSON, got error for: {line}"
        );
    }
}

#[test]
fn phase_a_gate_events_contain_policy_id() {
    let artifacts_root = temp_dir("phase_a_events_policy");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let events = fs::read_to_string(run_dir.join("events.jsonl")).expect("read events");

    assert!(
        events.contains("\"policy_id\":\"policy-phase-a-exit-gate-v1\""),
        "events must contain the policy_id field"
    );
}

#[test]
fn phase_a_gate_script_supports_test_mode() {
    let script = read_gate_script();
    assert!(
        script.contains("test)"),
        "script must support 'test' mode in case statement"
    );
}

#[test]
fn phase_a_gate_script_supports_clippy_mode() {
    let script = read_gate_script();
    assert!(
        script.contains("clippy)"),
        "script must support 'clippy' mode in case statement"
    );
}

#[test]
fn phase_a_gate_script_rejects_unknown_mode() {
    let script = read_gate_script();
    assert!(
        script.contains("*)"),
        "script must have a catch-all case for unknown modes"
    );
    assert!(
        script.contains("usage:"),
        "script must print usage for unknown modes"
    );
}

#[test]
fn phase_a_gate_script_invokes_test262_subgate() {
    let script = read_gate_script();
    assert!(
        script.contains("run_test262_es2020_gate.sh"),
        "script must invoke test262 sub-gate"
    );
}

#[test]
fn phase_a_gate_script_invokes_parser_oracle_subgate() {
    let script = read_gate_script();
    assert!(
        script.contains("run_parser_oracle_gate.sh"),
        "script must invoke parser oracle sub-gate"
    );
}

#[test]
fn phase_a_gate_manifest_trace_id_starts_with_prefix() {
    let artifacts_root = temp_dir("phase_a_trace_prefix");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let trace_id = manifest["trace_id"]
        .as_str()
        .expect("trace_id must be a string");
    assert!(
        trace_id.starts_with("trace-phase-a-gate-"),
        "trace_id should start with 'trace-phase-a-gate-', got: {trace_id}"
    );
}

#[test]
fn phase_a_gate_manifest_decision_id_starts_with_prefix() {
    let artifacts_root = temp_dir("phase_a_decision_prefix");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    let decision_id = manifest["decision_id"]
        .as_str()
        .expect("decision_id must be a string");
    assert!(
        decision_id.starts_with("decision-phase-a-gate-"),
        "decision_id should start with 'decision-phase-a-gate-', got: {decision_id}"
    );
}

#[test]
fn phase_a_gate_script_uses_exit_trap_for_manifest() {
    let script = read_gate_script();
    assert!(
        script.contains("trap") && script.contains("write_manifest"),
        "script must use EXIT trap to guarantee manifest is written"
    );
}

#[test]
fn phase_a_gate_blocked_stderr_lists_unmet_dependencies() {
    let artifacts_root = temp_dir("phase_a_stderr_deps");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    // Each unmet dependency should appear as a bullet point in stderr
    assert!(
        stderr.contains("  - "),
        "stderr should list unmet dependencies as bullet items, got: {stderr}"
    );
}

#[test]
fn phase_a_gate_manifest_error_code_present_on_failure() {
    let artifacts_root = temp_dir("phase_a_error_code_manifest");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let events = fs::read_to_string(run_dir.join("events.jsonl")).expect("read events");
    for line in events.lines().filter(|l| !l.trim().is_empty()) {
        let event: Value = serde_json::from_str(line).expect("parse event");
        if event["outcome"].as_str() == Some("fail") {
            assert_eq!(
                event["error_code"].as_str(),
                Some("FE-PHASE-A-GATE-1001"),
                "fail outcome must include error code FE-PHASE-A-GATE-1001"
            );
        }
    }
}

#[test]
fn phase_a_gate_script_dependency_list_includes_all_eight_ids() {
    let script = read_gate_script();
    let expected_deps = [
        "bd-ntq", "bd-3vk", "bd-383", "bd-1pi9", "bd-1b70", "bd-3rjg", "bd-1gfn", "bd-2mds",
    ];
    for dep in &expected_deps {
        assert!(
            script.contains(dep),
            "script dependency_ids must include {dep}"
        );
    }
}

#[test]
fn phase_a_gate_script_json_escape_handles_backslash_and_quote() {
    let script = read_gate_script();
    // The json_escape function must handle backslashes and quotes
    assert!(
        script.contains(r#"input="${input//\\/\\\\}""#),
        "json_escape must escape backslashes"
    );
    assert!(
        script.contains(r#"input="${input//\"/\\\"}""#),
        "json_escape must escape double quotes"
    );
}

#[test]
fn phase_a_gate_blocked_manifest_does_not_contain_failed_command() {
    let artifacts_root = temp_dir("phase_a_no_failed_cmd");
    fs::create_dir_all(&artifacts_root).expect("create artifact root");

    let _output = Command::new("bash")
        .arg("./scripts/run_phase_a_exit_gate.sh")
        .arg("check")
        .current_dir(repo_root())
        .env("PHASE_A_GATE_SKIP_SUBGATES", "1")
        .env("PHASE_A_GATE_ARTIFACT_ROOT", &artifacts_root)
        .output()
        .expect("phase-a gate should execute");

    let run_dir = latest_run_dir(&artifacts_root);
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(run_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");

    // When subgates are skipped, no command can fail, so failed_command should be absent
    assert!(
        !manifest.as_object().unwrap().contains_key("failed_command"),
        "failed_command should not appear when no subgate command was run"
    );
}
