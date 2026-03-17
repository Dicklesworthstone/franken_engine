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

use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::runtime_diagnostics_cli::{
    GcPressureSample, RuntimeDiagnosticsCliInput, RuntimeExtensionState, RuntimeStateInput,
    SchedulerLaneSample,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Deserialize;
use serde_json::Value;

const RGC_061_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-cli-operator-workflow-verification-pack.v1";
const RGC_061_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_cli_operator_workflow_verification_pack_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc061Contract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    workflow_stages: Vec<String>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    failure_scenarios: Vec<Rgc061FailureScenario>,
    gate_runner: Rgc061GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc061FailureScenario {
    scenario_id: String,
    path_type: String,
    command_template: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Rgc061GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> Rgc061Contract {
    serde_json::from_str(RGC_061_CONTRACT_JSON)
        .expect("RGC CLI/operator workflow verification contract must parse")
}

fn read_replay_script() -> String {
    let path =
        repo_root().join("scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh");
    read_to_string(&path)
}

fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    path.push(format!(
        "{prefix}_{}_{}.{}",
        std::process::id(),
        nonce,
        extension
    ));
    path
}

fn write_runtime_input(input: &RuntimeDiagnosticsCliInput) -> PathBuf {
    let path = unique_temp_path("rgc_061_runtime_input", "json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(input).expect("runtime diagnostics input should serialize"),
    )
    .expect("runtime diagnostics input should write");
    path
}

fn write_json_value(value: &Value) -> PathBuf {
    let path = unique_temp_path("rgc_061_signals", "json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(value).expect("json value should serialize"),
    )
    .expect("signals file should write");
    path
}

fn write_text_file(contents: &str) -> PathBuf {
    let path = unique_temp_path("rgc_061_invalid_signals", "json");
    fs::write(&path, contents).expect("text file should write");
    path
}

fn cleanup_path(path: &Path) {
    if !path.exists() {
        return;
    }

    if path.is_dir() {
        let _ = fs::remove_dir_all(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

fn build_clean_input() -> RuntimeDiagnosticsCliInput {
    RuntimeDiagnosticsCliInput {
        trace_id: "trace-rgc-061".to_string(),
        decision_id: "decision-rgc-061".to_string(),
        policy_id: "policy-rgc-061".to_string(),
        runtime_state: RuntimeStateInput {
            snapshot_timestamp_ns: 42_000,
            loaded_extensions: vec![RuntimeExtensionState {
                extension_id: "ext-weather".to_string(),
                containment_state: ContainmentState::Running,
            }],
            active_policies: vec!["policy-rgc-061".to_string()],
            security_epoch: SecurityEpoch::from_raw(7),
            gc_pressure: vec![GcPressureSample {
                extension_id: "ext-weather".to_string(),
                used_bytes: 64,
                budget_bytes: 8_192,
            }],
            scheduler_lanes: vec![SchedulerLaneSample {
                lane: "ready".to_string(),
                queue_depth: 0,
                max_depth: 32,
                tasks_submitted: 8,
                tasks_scheduled: 8,
                tasks_completed: 8,
                tasks_timed_out: 0,
            }],
        },
        evidence_entries: Vec::new(),
        hostcall_records: Vec::new(),
        containment_receipts: Vec::new(),
        replay_artifacts: Vec::new(),
    }
}

#[test]
fn rgc_061_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC CLI and Operator Workflow Verification Pack V1",
        "## Scope",
        "## Contract Version",
        "## Workflow Stages",
        "## Golden-Path and Failure-Path Matrix",
        "## Structured Logging Contract",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }

    assert!(
        doc.contains("$PWD/target_rch_rgc_cli_operator_workflow_verification_pack_verify"),
        "operator verification doc should use the repo-local target dir example"
    );
    assert!(
        !doc.contains("/tmp/rch_target_rgc_cli_operator_workflow_verification_pack"),
        "operator verification doc must not point back to /tmp-backed target dirs"
    );
}

#[test]
fn rgc_061_contract_is_versioned_and_actionable() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, RGC_061_CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.11");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-cli-operator-workflow-verification-pack-v1"
    );

    let stage_set: BTreeSet<_> = contract
        .workflow_stages
        .iter()
        .map(String::as_str)
        .collect();
    let expected_stage_set: BTreeSet<_> = [
        "init",
        "compile",
        "run",
        "verify",
        "benchmark",
        "replay",
        "triage",
    ]
    .into_iter()
    .collect();
    assert_eq!(stage_set, expected_stage_set);

    let required_log_keys: BTreeSet<_> = contract
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "scenario_id",
        "path_type",
        "outcome",
        "error_code",
    ] {
        assert!(
            required_log_keys.contains(key),
            "missing required log key {key}"
        );
    }

    let required_artifacts: BTreeSet<_> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "support_bundle/preflight_report.json",
        "support_bundle/onboarding_scorecard.json",
    ] {
        assert!(
            required_artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_cli_operator_workflow_verification_pack.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-cli-operator-workflow-verification-pack.run-manifest.v1"
    );

    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_input"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-061-INPUT-0001"
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_signals_json"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-061-SIGNALS-0002"
    }));

    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("$PWD/target_rch_rgc_cli_operator_workflow_verification_pack_verify")
        }),
        "operator verification should document the repo-local target dir example"
    );
    assert!(
        !contract.operator_verification.iter().any(|entry| {
            entry.contains("/tmp/rch_target_rgc_cli_operator_workflow_verification_pack")
        }),
        "operator verification must not point back to /tmp-backed target dirs"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_rgc_cli_operator_workflow_verification_pack.sh ci"))
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("rgc_cli_operator_workflow_verification_pack_replay.sh"))
    );
}

#[test]
fn rgc_061_onboarding_scorecard_golden_path_is_ready_and_writes_artifacts() {
    let input_path = write_runtime_input(&build_clean_input());
    let out_dir = unique_temp_path("rgc_061_out", "dir");

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--summary",
            "--out-dir",
            out_dir.to_str().expect("output dir should be utf8"),
            "--workload-id",
            "pkg/weather-clean",
            "--package-name",
            "weather-clean",
            "--target-platform",
            "linux-x64",
            "--target-platform",
            "linux-x64",
            "--target-platform",
            "macos-arm64",
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());

    let summary = String::from_utf8(output.stdout).expect("summary stdout should be utf8");
    assert!(
        summary
            .contains("schema_version: franken-engine.runtime-diagnostics.onboarding-scorecard.v1")
    );
    assert!(summary.contains("readiness: ready"));
    assert!(summary.contains("reproducible_commands:"));

    let scorecard_path = out_dir.join("support_bundle/onboarding_scorecard.json");
    let preflight_path = out_dir.join("support_bundle/preflight_report.json");
    assert!(scorecard_path.exists(), "scorecard artifact should exist");
    assert!(preflight_path.exists(), "preflight artifact should exist");

    let scorecard_json: Value = serde_json::from_str(&read_to_string(&scorecard_path))
        .expect("scorecard artifact should parse");
    assert_eq!(scorecard_json["readiness"], "ready");
    assert_eq!(scorecard_json["score"]["critical_signals"], 0);
    assert_eq!(
        scorecard_json["target_platforms"],
        serde_json::json!(["linux-x64", "macos-arm64"])
    );

    cleanup_path(&input_path);
    cleanup_path(&out_dir);
}

#[test]
fn rgc_061_onboarding_scorecard_failure_path_surfaces_blocked_with_actionable_steps() {
    let input_path = write_runtime_input(&build_clean_input());
    let signals_path = write_json_value(&serde_json::json!([
        {
            "signal_id": "compat:missing-node-fs-watch",
            "source": "compatibility_advisory",
            "severity": "critical",
            "summary": "missing fs.watch compatibility shim",
            "remediation": "enable fallback watcher shim and rerun compatibility probe",
            "reproducible_command": "frankenctl verify --workflow onboarding",
            "evidence_links": ["artifacts/compatibility/latest/report.json"],
            "owner_hint": "compatibility-lane"
        }
    ]));

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--signals",
            signals_path.to_str().expect("signals path should be utf8"),
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let output_json: Value = serde_json::from_str(&stdout).expect("output should be valid json");

    assert_eq!(output_json["readiness"], "blocked");
    assert_eq!(output_json["score"]["critical_signals"], 1);
    assert_eq!(output_json["next_steps"][0]["owner"], "compatibility-lane");
    assert_eq!(output_json["logs"][0]["event"], "onboarding_scorecard");
    assert_eq!(output_json["logs"][0]["outcome"], "fail");
    assert!(
        output_json["reproducible_commands"]
            .as_array()
            .is_some_and(|commands| commands
                .iter()
                .any(|command| command == "frankenctl verify --workflow onboarding"))
    );

    cleanup_path(&input_path);
    cleanup_path(&signals_path);
}

#[test]
fn rgc_061_missing_input_reports_actionable_error() {
    let missing_path = unique_temp_path("rgc_061_missing_input", "json");
    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            missing_path.to_str().expect("missing path should be utf8"),
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("failed to read input file"));
}

#[test]
fn rgc_061_invalid_signals_json_reports_actionable_error() {
    let input_path = write_runtime_input(&build_clean_input());
    let signals_path = write_text_file("this is not valid json");

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--signals",
            signals_path.to_str().expect("signals path should be utf8"),
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("failed to parse signal file"));
    assert!(stderr.contains("JSON array"));

    cleanup_path(&input_path);
    cleanup_path(&signals_path);
}

// ---------- contract field completeness ----------

#[test]
fn rgc_061_contract_failure_scenarios_have_nonempty_templates() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert!(
            !scenario.command_template.trim().is_empty(),
            "scenario {} must have a non-empty command_template",
            scenario.scenario_id
        );
        assert!(
            !scenario.expected_error_code.trim().is_empty(),
            "scenario {} must have a non-empty error code",
            scenario.scenario_id
        );
        assert!(
            !scenario.expected_message_fragment.trim().is_empty(),
            "scenario {} must have a non-empty message fragment",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_061_contract_failure_scenario_ids_are_unique() {
    let contract = parse_contract();
    let mut ids = BTreeSet::new();
    for scenario in &contract.failure_scenarios {
        assert!(
            ids.insert(scenario.scenario_id.as_str()),
            "duplicate failure scenario id: {}",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_061_contract_all_failure_scenarios_are_failure_path_type() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert_eq!(
            scenario.path_type, "failure",
            "scenario {} should be failure path_type",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_061_readme_gate_section_documents_contract_and_artifacts() {
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in [
        "## RGC CLI and Operator Workflow Verification Pack",
        "./scripts/run_rgc_cli_operator_workflow_verification_pack.sh ci",
        "./scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh ci",
        "docs/rgc_cli_operator_workflow_verification_pack_v1.json",
        "artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/run_manifest.json",
        "artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/events.jsonl",
        "artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/commands.txt",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }
}

// ---------- diagnostics subcommand ----------

#[test]
fn rgc_061_diagnostics_subcommand_produces_json_output() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "diagnostics",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
        ])
        .output()
        .expect("diagnostics command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert!(json["snapshot_timestamp_ns"].is_number());
    assert!(json["loaded_extensions"].is_array());

    cleanup_path(&input_path);
}

#[test]
fn rgc_061_diagnostics_summary_mode_produces_text() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "diagnostics",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--summary",
        ])
        .output()
        .expect("diagnostics --summary command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(
        stdout.contains("snapshot_timestamp_ns:"),
        "summary should contain snapshot_timestamp_ns"
    );

    cleanup_path(&input_path);
}

// ---------- export-evidence subcommand ----------

#[test]
fn rgc_061_export_evidence_produces_json_with_records_and_summary() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "export-evidence",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
        ])
        .output()
        .expect("export-evidence command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert!(json["records"].is_array());
    assert!(json["summary"].is_object());

    cleanup_path(&input_path);
}

// ---------- support-bundle subcommand ----------

#[test]
fn rgc_061_support_bundle_writes_artifacts_to_out_dir() {
    let input_path = write_runtime_input(&build_clean_input());
    let out_dir = unique_temp_path("rgc_061_bundle_out", "dir");

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "support-bundle",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--out-dir",
            out_dir.to_str().expect("output dir should be utf8"),
        ])
        .output()
        .expect("support-bundle command should execute");

    assert!(output.status.success());
    let index_path = out_dir.join("support_bundle/index.json");
    assert!(
        index_path.exists(),
        "support bundle index should exist at {}",
        index_path.display()
    );

    let index_json: Value =
        serde_json::from_str(&read_to_string(&index_path)).expect("index should parse");
    assert!(index_json["files"].is_array());
    assert!(index_json["bundle_id"].is_string());

    cleanup_path(&input_path);
    cleanup_path(&out_dir);
}

// ---------- doctor subcommand ----------

#[test]
fn rgc_061_doctor_subcommand_produces_preflight_verdict() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
        ])
        .output()
        .expect("doctor command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert!(
        ["green", "yellow", "red"]
            .iter()
            .any(|v| json["verdict"].as_str() == Some(v)),
        "doctor must produce a valid verdict"
    );

    cleanup_path(&input_path);
}

// ---------- onboarding-scorecard variations ----------

#[test]
fn rgc_061_onboarding_scorecard_no_signals_produces_ready() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--workload-id",
            "pkg/clean-app",
            "--package-name",
            "clean-app",
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert_eq!(json["readiness"], "ready");
    assert_eq!(json["score"]["critical_signals"], 0);
    assert_eq!(json["score"]["warning_signals"], 0);

    cleanup_path(&input_path);
}

#[test]
fn rgc_061_onboarding_scorecard_warning_signal_produces_conditional() {
    let input_path = write_runtime_input(&build_clean_input());
    let signals_path = write_json_value(&serde_json::json!([
        {
            "signal_id": "compat:deprecated-api",
            "source": "compatibility_advisory",
            "severity": "warning",
            "summary": "deprecated API usage",
            "remediation": "migrate to new API",
            "reproducible_command": "frankenctl verify --api-compat",
            "evidence_links": [],
            "owner_hint": "api-team"
        }
    ]));

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--signals",
            signals_path.to_str().expect("signals path should be utf8"),
            "--workload-id",
            "pkg/warn-app",
            "--package-name",
            "warn-app",
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert_eq!(json["readiness"], "conditional");
    assert_eq!(json["score"]["warning_signals"], 1);

    cleanup_path(&input_path);
    cleanup_path(&signals_path);
}

#[test]
fn rgc_061_onboarding_scorecard_multiple_critical_signals_produces_blocked() {
    let input_path = write_runtime_input(&build_clean_input());
    let signals_path = write_json_value(&serde_json::json!([
        {
            "signal_id": "sec:vuln-1",
            "source": "security_scan",
            "severity": "critical",
            "summary": "critical vulnerability",
            "remediation": "patch immediately",
            "reproducible_command": "frankenctl verify --security",
            "evidence_links": []
        },
        {
            "signal_id": "sec:vuln-2",
            "source": "security_scan",
            "severity": "critical",
            "summary": "another critical vulnerability",
            "remediation": "patch immediately",
            "reproducible_command": "frankenctl verify --security",
            "evidence_links": []
        }
    ]));

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--signals",
            signals_path.to_str().expect("signals path should be utf8"),
            "--workload-id",
            "pkg/vuln-app",
            "--package-name",
            "vuln-app",
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert_eq!(json["readiness"], "blocked");
    assert_eq!(json["score"]["critical_signals"], 2);

    cleanup_path(&input_path);
    cleanup_path(&signals_path);
}

#[test]
fn rgc_061_onboarding_scorecard_schema_version_is_correct() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--workload-id",
            "pkg/schema-check",
            "--package-name",
            "schema-check",
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert_eq!(
        json["schema_version"],
        "franken-engine.runtime-diagnostics.onboarding-scorecard.v1"
    );

    cleanup_path(&input_path);
}

#[test]
fn rgc_061_onboarding_scorecard_logs_contain_structured_events() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--workload-id",
            "pkg/log-check",
            "--package-name",
            "log-check",
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");

    let logs = json["logs"].as_array().expect("logs should be an array");
    assert!(
        !logs.is_empty(),
        "onboarding scorecard should produce structured logs"
    );
    for log in logs {
        assert!(log["event"].is_string(), "log event must be a string");
        assert!(log["outcome"].is_string(), "log outcome must be a string");
    }

    cleanup_path(&input_path);
}

#[test]
fn rgc_061_onboarding_scorecard_empty_signals_array_is_valid() {
    let input_path = write_runtime_input(&build_clean_input());
    let signals_path = write_json_value(&serde_json::json!([]));

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "onboarding-scorecard",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--signals",
            signals_path.to_str().expect("signals path should be utf8"),
            "--workload-id",
            "pkg/empty-signals",
            "--package-name",
            "empty-signals",
        ])
        .output()
        .expect("onboarding-scorecard command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert_eq!(json["readiness"], "ready");

    cleanup_path(&input_path);
    cleanup_path(&signals_path);
}

// ---------- lane script ----------

#[test]
fn rgc_061_lane_script_preserves_step_logs_and_failure_classification() {
    let path = repo_root().join("scripts/run_rgc_cli_operator_workflow_verification_pack.sh");
    let script = read_to_string(&path);

    for required_fragment in [
        "step_log_path=\"${run_dir}/step_",
        "(timeout-${rch_timeout_seconds}s)",
        "(rch-exit=${status}; remote-exit=${remote_exit_code})",
        "(rch-exit=${status}; missing-remote-exit-marker)",
        "(rch-local-fallback-detected)",
        "rgc-cli-operator-workflow-verification-pack.run-manifest.v1",
    ] {
        assert!(
            script.contains(required_fragment),
            "missing script fragment in {}: {required_fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_061_replay_wrapper_uses_latest_complete_bundle() {
    let script = read_replay_script();

    assert!(
        script.contains("latest_complete_run_dir()"),
        "replay wrapper should locate the latest complete artifact directory"
    );
    assert!(
        script.contains("newest directory ${latest_artifact_dir_path} is incomplete"),
        "replay wrapper should warn when it skips an incomplete newest directory"
    );
    assert!(
        script.contains("latest manifest: ${latest_run_dir}/run_manifest.json"),
        "replay wrapper should print the latest run manifest"
    );
    assert!(
        script.contains("latest events: ${latest_run_dir}/events.jsonl"),
        "replay wrapper should print the latest event log"
    );
    assert!(
        script.contains("latest commands: ${latest_run_dir}/commands.txt"),
        "replay wrapper should print the recorded command list"
    );
    assert!(
        script.contains("latest first step log: ${latest_run_dir}/step_000.log"),
        "replay wrapper should print the first step log for operator triage"
    );
}

// ---------- contract and doc files exist ----------

#[test]
fn rgc_061_contract_and_doc_files_exist_at_declared_paths() {
    let root = repo_root();
    for path in [
        "docs/RGC_CLI_OPERATOR_WORKFLOW_VERIFICATION_PACK_V1.md",
        "docs/rgc_cli_operator_workflow_verification_pack_v1.json",
        "scripts/run_rgc_cli_operator_workflow_verification_pack.sh",
        "scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh",
        "crates/franken-engine/tests/rgc_cli_operator_workflow_verification_pack.rs",
    ] {
        let full = root.join(path);
        assert!(full.exists(), "expected path to exist: {}", full.display());
    }
}

// ---------- rollout-decision-artifact subcommand ----------

#[test]
fn rgc_061_rollout_decision_artifact_subcommand_produces_output() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "rollout-decision-artifact",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--workload-id",
            "pkg/rollout-test",
            "--package-name",
            "rollout-test",
        ])
        .output()
        .expect("rollout-decision-artifact command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert!(
        ["promote", "canary_hold", "rollback", "defer"]
            .iter()
            .any(|r| json["recommendation"].as_str() == Some(r)),
        "rollout decision must produce a valid recommendation"
    );
    assert_eq!(
        json["schema_version"],
        "franken-engine.runtime-diagnostics.rollout-decision-artifact.v1"
    );

    cleanup_path(&input_path);
}

// ---------- runtime diagnostics input serde ----------

#[test]
fn rgc_061_runtime_diagnostics_input_serde_roundtrip() {
    let input = build_clean_input();
    let json = serde_json::to_string(&input).expect("input should serialize");
    let recovered: RuntimeDiagnosticsCliInput =
        serde_json::from_str(&json).expect("input should deserialize");
    assert_eq!(recovered.trace_id, input.trace_id);
    assert_eq!(recovered.decision_id, input.decision_id);
    assert_eq!(recovered.policy_id, input.policy_id);
    assert_eq!(
        recovered.runtime_state.loaded_extensions.len(),
        input.runtime_state.loaded_extensions.len()
    );
}

// ---------- contract schema invariants ----------

#[test]
fn rgc_061_contract_workflow_stages_are_unique_and_sorted() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for stage in &contract.workflow_stages {
        assert!(
            seen.insert(stage.as_str()),
            "duplicate workflow stage: {stage}"
        );
    }
}

#[test]
fn rgc_061_contract_required_log_keys_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for key in &contract.required_log_keys {
        assert!(
            seen.insert(key.as_str()),
            "duplicate required log key: {key}"
        );
    }
}

// ---------- doctor output structure ----------

#[test]
fn rgc_061_doctor_output_contains_mandatory_field_status() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
        ])
        .output()
        .expect("doctor command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");

    let mfs = &json["mandatory_field_status"];
    assert!(
        mfs.is_object(),
        "doctor output must contain mandatory_field_status"
    );
    assert!(
        mfs["valid"].is_boolean(),
        "mandatory_field_status.valid must be a boolean"
    );
    assert!(
        mfs["missing_fields"].is_array(),
        "mandatory_field_status.missing_fields must be an array"
    );

    cleanup_path(&input_path);
}

// ---------- diagnostics output structure ----------

#[test]
fn rgc_061_diagnostics_output_contains_scheduler_lanes() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "diagnostics",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
        ])
        .output()
        .expect("diagnostics command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    assert!(
        json["scheduler_lanes"].is_array(),
        "diagnostics output should include scheduler_lanes"
    );
    let lanes = json["scheduler_lanes"].as_array().unwrap();
    assert!(
        !lanes.is_empty(),
        "scheduler_lanes should contain the lane from the input"
    );
    assert_eq!(lanes[0]["lane"], "ready");

    cleanup_path(&input_path);
}

// ---------- rollout-decision-artifact with signals ----------

#[test]
fn rgc_061_rollout_decision_with_critical_signal_recommends_caution() {
    let input_path = write_runtime_input(&build_clean_input());
    let signals_path = write_json_value(&serde_json::json!([
        {
            "signal_id": "perf:regression-p99",
            "source": "benchmark_lane",
            "severity": "critical",
            "summary": "p99 latency regression detected",
            "remediation": "investigate benchmark results",
            "reproducible_command": "frankenctl bench --compare",
            "evidence_links": ["artifacts/bench/latest/report.json"]
        }
    ]));

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "rollout-decision-artifact",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--signals",
            signals_path.to_str().expect("signals path should be utf8"),
            "--workload-id",
            "pkg/perf-regress",
            "--package-name",
            "perf-regress",
        ])
        .output()
        .expect("rollout-decision-artifact command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: Value = serde_json::from_str(&stdout).expect("output should be valid json");
    // With a critical signal, the recommendation should NOT be "promote"
    assert_ne!(
        json["recommendation"].as_str().unwrap_or(""),
        "promote",
        "critical signal should prevent promote recommendation"
    );

    cleanup_path(&input_path);
    cleanup_path(&signals_path);
}

// ---------- contract operator_verification entries are nonempty ----------

#[test]
fn rgc_061_contract_operator_verification_entries_are_nonempty() {
    let contract = parse_contract();
    assert!(
        !contract.operator_verification.is_empty(),
        "operator_verification must have at least one entry"
    );
    for entry in &contract.operator_verification {
        assert!(
            !entry.trim().is_empty(),
            "operator_verification entry must not be empty"
        );
    }
}

// ---------- contract required_artifacts are unique ----------

#[test]
fn rgc_061_contract_required_artifacts_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for artifact in &contract.required_artifacts {
        assert!(
            seen.insert(artifact.as_str()),
            "duplicate required artifact: {artifact}"
        );
    }
}

// ---------- runtime diagnostics input schema version field ----------

#[test]
fn rgc_061_runtime_diagnostics_input_json_contains_required_fields() {
    let input = build_clean_input();
    let v: Value = serde_json::to_value(&input).expect("input should serialize to json value");
    let obj = v.as_object().expect("input should be a JSON object");
    for key in ["trace_id", "decision_id", "policy_id", "runtime_state"] {
        assert!(
            obj.contains_key(key),
            "RuntimeDiagnosticsCliInput missing JSON field: {key}"
        );
    }
}

// ---------- doctor summary output mode ----------

#[test]
fn rgc_061_doctor_summary_mode_produces_text_output() {
    let input_path = write_runtime_input(&build_clean_input());

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().expect("input path should be utf8"),
            "--summary",
        ])
        .output()
        .expect("doctor --summary command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(
        stdout.contains("verdict:"),
        "doctor summary should contain verdict"
    );

    cleanup_path(&input_path);
}

// ---------- contract failure scenarios error codes start with FE-RGC-061 ----------

#[test]
fn rgc_061_contract_failure_scenario_error_codes_start_with_fe_rgc_061() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert!(
            scenario.expected_error_code.starts_with("FE-RGC-061-"),
            "scenario {} error code should start with FE-RGC-061-: {}",
            scenario.scenario_id,
            scenario.expected_error_code
        );
    }
}
