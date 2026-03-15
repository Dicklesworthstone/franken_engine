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
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct IncidentScenario {
    scenario_id: String,
    symptom: String,
    severity: String,
    expected_triage: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserOperatorDeveloperRunbookFixture {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_modes: Vec<String>,
    required_manifest_keys: Vec<String>,
    required_log_keys: Vec<String>,
    drill_replay_commands: Vec<String>,
    incident_matrix: Vec<IncidentScenario>,
}

fn load_fixture() -> ParserOperatorDeveloperRunbookFixture {
    let path = Path::new("tests/fixtures/parser_operator_developer_runbook_v1.json");
    let bytes = fs::read(path).expect("read parser operator/developer runbook fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser operator/developer runbook fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_OPERATOR_DEVELOPER_RUNBOOK.md");
    fs::read_to_string(path).expect("read parser operator/developer runbook doc")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_parser_operator_developer_runbook.sh");
    fs::read_to_string(path).expect("read parser operator/developer runbook script")
}

fn load_replay_script() -> String {
    let path = Path::new("../../scripts/e2e/parser_operator_developer_runbook_replay.sh");
    fs::read_to_string(path).expect("read parser operator/developer runbook replay script")
}

fn load_readme() -> String {
    fs::read_to_string(Path::new("../../README.md"))
        .expect("read repository README for runbook references")
}

fn triage_action(scenario: &IncidentScenario) -> &'static str {
    let symptom = scenario.symptom.to_ascii_lowercase();
    let severity = scenario.severity.to_ascii_lowercase();

    if severity == "critical" && symptom.contains("user impact") {
        return "hold_rollout_and_rerun_user_impact_replay";
    }
    if severity == "critical" && symptom.contains("fallback") {
        return "fail_closed_and_rerun_failover_controls";
    }
    if symptom.contains("artifact retrieval") || symptom.contains("rsync artifact") {
        return "fail_closed_and_retry_rch_remote";
    }
    if symptom.contains("diagnostic") {
        return "rerun_diagnostics_rubric";
    }
    if symptom.contains("resync") {
        return "rerun_error_recovery_replay";
    }
    if symptom.contains("api compatibility") {
        return "rerun_api_compatibility_gate";
    }
    "unknown"
}

fn assert_required_event_keys(event: &Value, required_keys: &[String]) {
    let obj = event
        .as_object()
        .expect("structured event must be a json object");

    for key in required_keys {
        let value = obj
            .get(key)
            .unwrap_or_else(|| panic!("missing required key `{key}`"));
        if key == "error_code" {
            assert!(
                value.is_null() || value.as_str().is_some_and(|raw| !raw.is_empty()),
                "error_code must be null or non-empty string"
            );
            continue;
        }
        assert!(
            value.as_str().is_some_and(|raw| !raw.trim().is_empty()),
            "required key `{key}` must be non-empty string"
        );
    }
}

#[test]
fn parser_operator_runbook_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser Operator/Developer Runbook (`bd-2mds.1.10.4`)",
        "## Fresh-Operator Dry Run",
        "## Replay-First Troubleshooting Decision Tree",
        "## Scriptable Drill Lane",
        "## Escalation And Rollback Posture",
        "target_rch_parser_operator_developer_runbook_",
        "step_logs/step_*.log",
        "./scripts/run_parser_operator_developer_runbook.sh ci",
        "./scripts/e2e/parser_operator_developer_runbook_replay.sh drill",
        "latest complete directory",
    ] {
        assert!(
            doc.contains(section),
            "runbook doc missing required section or command: {section}"
        );
    }
}

#[test]
fn parser_operator_runbook_fixture_contract_versions_are_stable() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-operator-developer-runbook.fixture.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-2mds.1.10.4");
    assert_eq!(
        fixture.policy_id,
        "policy-parser-operator-developer-runbook-v1"
    );
}

#[test]
fn parser_operator_runbook_fixture_mode_and_key_sets_are_exact() {
    let fixture = load_fixture();

    let expected_modes: BTreeSet<_> = ["check", "test", "clippy", "ci", "drill"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let actual_modes: BTreeSet<_> = fixture.required_modes.iter().cloned().collect();
    assert_eq!(actual_modes, expected_modes);

    let expected_manifest: BTreeSet<_> = [
        "schema_version",
        "bead_id",
        "deterministic_env_schema_version",
        "cargo_target_dir",
        "trace_id",
        "decision_id",
        "policy_id",
        "deterministic_environment",
        "replay_command",
        "drill_replay_commands",
        "commands",
        "artifacts",
        "operator_verification",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_manifest: BTreeSet<_> = fixture.required_manifest_keys.iter().cloned().collect();
    assert_eq!(actual_manifest, expected_manifest);

    let expected_logs: BTreeSet<_> = [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_logs: BTreeSet<_> = fixture.required_log_keys.iter().cloned().collect();
    assert_eq!(actual_logs, expected_logs);
}

#[test]
fn parser_operator_runbook_replay_drills_cover_required_paths() {
    let fixture = load_fixture();
    assert_eq!(fixture.drill_replay_commands.len(), 2);
    for replay_command in &fixture.drill_replay_commands {
        assert!(
            replay_command.starts_with("./scripts/e2e/parser_"),
            "drill replay command must use parser e2e wrapper: {replay_command}"
        );
        assert!(
            replay_command.ends_with(".sh"),
            "drill replay command must be a shell entrypoint: {replay_command}"
        );
    }
}

#[test]
fn parser_operator_runbook_incident_matrix_triage_is_stable() {
    let fixture = load_fixture();
    assert_eq!(fixture.incident_matrix.len(), 6);
    for scenario in &fixture.incident_matrix {
        let derived = triage_action(scenario);
        assert_eq!(
            derived, scenario.expected_triage,
            "triage mismatch for scenario `{}`",
            scenario.scenario_id
        );
        assert!(
            scenario.replay_command.starts_with("./scripts/"),
            "scenario `{}` replay command must be script entrypoint",
            scenario.scenario_id
        );
    }
}

#[test]
fn parser_operator_runbook_emits_structured_event_contract() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-parser-operator-runbook-static",
        "decision_id": "decision-parser-operator-runbook-static",
        "policy_id": fixture.policy_id,
        "component": "parser_operator_developer_runbook_gate",
        "event": "gate_completed",
        "outcome": "pass",
        "error_code": Value::Null
    });
    assert_required_event_keys(&event, &fixture.required_log_keys);
}

#[test]
fn parser_operator_runbook_script_contains_required_markers() {
    let script = load_script();
    for marker in [
        "source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\"",
        "parser_frontier_bootstrap_env",
        "policy-parser-operator-developer-runbook-v1",
        "target_rch_parser_operator_developer_runbook_",
        "step_logs_dir=",
        "rch_reject_artifact_retrieval_failure",
        "rch-artifact-retrieval-failed",
        "./scripts/e2e/parser_operator_developer_runbook_replay.sh",
        "cat ${step_logs_dir}/step_000.log",
        "parser_frontier_emit_manifest_environment_fields",
        "validate_parser_log_schema.sh --events",
    ] {
        assert!(
            script.contains(marker),
            "runbook script missing required marker: {marker}"
        );
    }
}

#[test]
fn readme_references_operator_runbook_gate_and_replay() {
    let readme = load_readme();
    assert!(
        readme.contains("## Parser Operator/Developer Runbook Gate"),
        "README missing parser operator/developer runbook heading"
    );
    assert!(
        readme.contains("./scripts/run_parser_operator_developer_runbook.sh ci"),
        "README missing parser operator/developer runbook gate command"
    );
    assert!(
        readme.contains("target_rch_parser_operator_developer_runbook_"),
        "README missing repo-local parser operator/developer runbook target-dir guidance"
    );
    assert!(
        readme.contains("step_logs/step_*.log"),
        "README missing parser operator/developer runbook step log artifact"
    );
    assert!(
        readme.contains("./scripts/e2e/parser_operator_developer_runbook_replay.sh ci"),
        "README missing parser operator/developer runbook ci replay command"
    );
    assert!(
        readme.contains("./scripts/e2e/parser_operator_developer_runbook_replay.sh drill"),
        "README missing parser operator/developer runbook drill replay command"
    );
    assert!(
        readme.contains("latest complete artifact bundle"),
        "README missing parser operator/developer runbook latest-complete replay guidance"
    );
    assert!(
        readme.contains("skip a newer incomplete run directory"),
        "README missing parser operator/developer runbook incomplete-directory warning guidance"
    );
}

#[test]
fn parser_operator_runbook_triage_action_unknown() {
    let scenario = IncidentScenario {
        scenario_id: "novel".to_string(),
        symptom: "completely new failure".to_string(),
        severity: "high".to_string(),
        expected_triage: "unknown".to_string(),
        replay_command: "./scripts/e2e/novel.sh".to_string(),
    };
    assert_eq!(triage_action(&scenario), "unknown");
}

#[test]
fn parser_operator_runbook_scenario_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for scenario in &fixture.incident_matrix {
        assert!(
            seen.insert(&scenario.scenario_id),
            "duplicate scenario_id: {}",
            scenario.scenario_id
        );
    }
}

#[test]
fn parser_operator_runbook_deterministic_double_parse() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a, b);
}

#[test]
fn parser_operator_runbook_doc_file_is_nonempty() {
    let doc = load_doc();
    assert!(!doc.is_empty());
}

#[test]
fn parser_operator_runbook_drill_commands_are_unique() {
    let fixture = load_fixture();
    let unique: BTreeSet<_> = fixture.drill_replay_commands.iter().collect();
    assert_eq!(unique.len(), fixture.drill_replay_commands.len());
}

#[test]
fn parser_operator_runbook_incident_replay_commands_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for scenario in &fixture.incident_matrix {
        assert!(
            seen.insert(&scenario.replay_command),
            "duplicate incident replay_command: {}",
            scenario.replay_command
        );
    }
}

#[test]
fn parser_operator_runbook_required_log_keys_are_nonempty() {
    let fixture = load_fixture();
    assert!(!fixture.required_log_keys.is_empty());
    for key in &fixture.required_log_keys {
        assert!(!key.trim().is_empty(), "log key must not be empty");
    }
}

#[test]
fn parser_operator_runbook_all_symptoms_nonempty() {
    let fixture = load_fixture();
    for scenario in &fixture.incident_matrix {
        assert!(
            !scenario.symptom.trim().is_empty(),
            "scenario {} must have nonempty symptom",
            scenario.scenario_id
        );
    }
}

#[test]
fn parser_operator_runbook_fixture_has_bead_id() {
    let fixture = load_fixture();
    assert!(!fixture.bead_id.trim().is_empty());
}

#[test]
fn parser_operator_runbook_fixture_has_policy_id() {
    let fixture = load_fixture();
    assert!(!fixture.policy_id.trim().is_empty());
}

#[test]
fn parser_operator_runbook_fixture_has_contract_version() {
    let fixture = load_fixture();
    assert!(!fixture.contract_version.trim().is_empty());
}

#[test]
fn parser_operator_runbook_fixture_deterministic_double_load() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.bead_id, b.bead_id);
}

#[test]
fn parser_operator_runbook_fixture_has_nonempty_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn parser_operator_runbook_fixture_incidents_have_unique_ids() {
    let fixture = load_fixture();
    let ids: BTreeSet<&str> = fixture
        .incident_matrix
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert_eq!(ids.len(), fixture.incident_matrix.len());
}

#[test]
fn parser_operator_runbook_doc_has_more_than_50_lines() {
    let doc = load_doc();
    assert!(doc.lines().count() > 50);
}

#[test]
fn parser_operator_runbook_doc_file_exists() {
    let path = Path::new("../../docs/PARSER_OPERATOR_DEVELOPER_RUNBOOK.md");
    assert!(path.exists());
}

#[test]
fn parser_operator_runbook_doc_mentions_replay() {
    let doc = load_doc();
    assert!(doc.to_ascii_lowercase().contains("replay"));
}

// ---------- additional doc and contract validation ----------

#[test]
fn parser_operator_runbook_doc_word_count_exceeds_minimum() {
    let doc = load_doc();
    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 200,
        "runbook doc must have at least 200 words, found {word_count}"
    );
}

#[test]
fn parser_operator_runbook_doc_contains_required_keywords() {
    let doc = load_doc();
    for keyword in [
        "replay",
        "deterministic",
        "drill",
        "escalation",
        "rollback",
        "artifact",
        "remediation",
    ] {
        assert!(
            doc.to_ascii_lowercase().contains(keyword),
            "runbook doc missing required keyword: {keyword}"
        );
    }
}

#[test]
fn parser_operator_runbook_doc_section_ordering_is_correct() {
    let doc = load_doc();
    let sections = [
        "## Scope",
        "## Deterministic Environment And Log Contract",
        "## Fresh-Operator Dry Run",
        "## Replay-First Troubleshooting Decision Tree",
        "## Scriptable Drill Lane",
        "## Escalation And Rollback Posture",
        "## Operator Verification Checklist",
    ];
    let mut last_pos = 0;
    for section in sections {
        if let Some(pos) = doc.find(section) {
            assert!(
                pos >= last_pos,
                "section `{section}` appears out of order in runbook doc"
            );
            last_pos = pos;
        }
    }
}

#[test]
fn parser_operator_runbook_incident_severities_are_known() {
    let fixture = load_fixture();
    let known: BTreeSet<&str> = ["critical", "high", "medium", "low"].into_iter().collect();
    for scenario in &fixture.incident_matrix {
        assert!(
            known.contains(scenario.severity.to_ascii_lowercase().as_str()),
            "unknown severity `{}` in scenario `{}`",
            scenario.severity,
            scenario.scenario_id
        );
    }
}

#[test]
fn parser_operator_runbook_triage_critical_user_impact() {
    let scenario = IncidentScenario {
        scenario_id: "crit-ui".to_string(),
        symptom: "critical user impact alarm".to_string(),
        severity: "critical".to_string(),
        expected_triage: "hold_rollout_and_rerun_user_impact_replay".to_string(),
        replay_command: "./scripts/e2e/test.sh".to_string(),
    };
    assert_eq!(
        triage_action(&scenario),
        "hold_rollout_and_rerun_user_impact_replay"
    );
}

#[test]
fn parser_operator_runbook_triage_critical_fallback() {
    let scenario = IncidentScenario {
        scenario_id: "crit-fb".to_string(),
        symptom: "fallback path triggered unexpectedly".to_string(),
        severity: "critical".to_string(),
        expected_triage: "fail_closed_and_rerun_failover_controls".to_string(),
        replay_command: "./scripts/e2e/test.sh".to_string(),
    };
    assert_eq!(
        triage_action(&scenario),
        "fail_closed_and_rerun_failover_controls"
    );
}

#[test]
fn parser_operator_runbook_triage_diagnostic_symptom() {
    let scenario = IncidentScenario {
        scenario_id: "diag".to_string(),
        symptom: "diagnostic quality drift".to_string(),
        severity: "high".to_string(),
        expected_triage: "rerun_diagnostics_rubric".to_string(),
        replay_command: "./scripts/e2e/test.sh".to_string(),
    };
    assert_eq!(triage_action(&scenario), "rerun_diagnostics_rubric");
}

#[test]
fn parser_operator_runbook_triage_resync_symptom() {
    let scenario = IncidentScenario {
        scenario_id: "resync".to_string(),
        symptom: "resync regression found".to_string(),
        severity: "medium".to_string(),
        expected_triage: "rerun_error_recovery_replay".to_string(),
        replay_command: "./scripts/e2e/test.sh".to_string(),
    };
    assert_eq!(triage_action(&scenario), "rerun_error_recovery_replay");
}

#[test]
fn parser_operator_runbook_triage_api_compatibility_symptom() {
    let scenario = IncidentScenario {
        scenario_id: "api".to_string(),
        symptom: "api compatibility check failed".to_string(),
        severity: "high".to_string(),
        expected_triage: "rerun_api_compatibility_gate".to_string(),
        replay_command: "./scripts/e2e/test.sh".to_string(),
    };
    assert_eq!(triage_action(&scenario), "rerun_api_compatibility_gate");
}

#[test]
fn parser_operator_runbook_doc_references_cli_commands() {
    let doc = load_doc();
    for cli in [
        "./scripts/run_parser_operator_developer_runbook.sh",
        "./scripts/e2e/parser_operator_developer_runbook_replay.sh",
    ] {
        assert!(
            doc.contains(cli),
            "runbook doc missing CLI command reference: {cli}"
        );
    }
}

#[test]
fn parser_operator_runbook_replay_wrapper_surfaces_latest_complete_bundle() {
    let replay_script = load_replay_script();
    for marker in [
        "artifact_root=",
        "latest_artifact_dir()",
        "latest_complete_run_dir()",
        "missing_bundle_exit_code()",
        "newest directory ${latest_artifact_dir_path} is incomplete",
        "[parser-operator-runbook] latest manifest:",
        "[parser-operator-runbook] latest events:",
        "[parser-operator-runbook] latest commands:",
        "[parser-operator-runbook] latest first step log:",
        "step_logs/step_000.log",
    ] {
        assert!(
            replay_script.contains(marker),
            "replay wrapper missing required marker: {marker}"
        );
    }
}
