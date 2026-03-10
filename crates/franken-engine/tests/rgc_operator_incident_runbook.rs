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
struct RgcOperatorIncidentRunbookFixture {
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

fn load_fixture() -> RgcOperatorIncidentRunbookFixture {
    let path = Path::new("tests/fixtures/rgc_operator_incident_runbook_v1.json");
    let bytes = fs::read(path).expect("read rgc operator incident runbook fixture");
    serde_json::from_slice(&bytes).expect("deserialize rgc operator incident runbook fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/RGC_OPERATOR_INCIDENT_RUNBOOK.md");
    fs::read_to_string(path).expect("read rgc operator incident runbook doc")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_rgc_operator_incident_runbook.sh");
    fs::read_to_string(path).expect("read rgc operator incident runbook script")
}

fn triage_action(scenario: &IncidentScenario) -> &'static str {
    let symptom = scenario.symptom.to_ascii_lowercase();

    if symptom.contains("semantic drift") {
        return "rerun_runtime_semantics_replay";
    }
    if symptom.contains("performance regression") {
        return "rerun_performance_regression_replay";
    }
    if symptom.contains("containment false positive") {
        return "rerun_security_enforcement_replay";
    }
    if symptom.contains("lockstep divergence") {
        return "rerun_module_interop_replay";
    }
    if symptom.contains("replay mismatch") {
        return "rerun_execution_waves_replay";
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
fn rgc_operator_runbook_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# RGC Operator Incident Runbook (`bd-1lsy.10.2`)",
        "## Fresh-Operator Dry Run",
        "## Replay-First Incident Decision Tree",
        "## Scriptable Drill Lane",
        "## Escalation, Rollback, And Handoff",
        "./scripts/run_rgc_operator_incident_runbook.sh ci",
        "./scripts/e2e/rgc_operator_incident_runbook_replay.sh drill",
        "semantic drift",
        "performance regression",
        "containment false positive",
        "lockstep divergence",
        "replay mismatch",
    ] {
        assert!(
            doc.contains(section),
            "runbook doc missing required section or command: {section}"
        );
    }
}

#[test]
fn rgc_operator_runbook_fixture_contract_versions_are_stable() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.rgc-operator-incident-runbook.fixture.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-1lsy.10.2");
    assert_eq!(fixture.policy_id, "policy-rgc-operator-incident-runbook-v1");
}

#[test]
fn rgc_operator_runbook_fixture_mode_and_key_sets_are_exact() {
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
        "trace_id",
        "decision_id",
        "policy_id",
        "deterministic_environment",
        "replay_command",
        "incident_timeline",
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
fn rgc_operator_runbook_replay_drills_cover_required_paths() {
    let fixture = load_fixture();
    assert_eq!(fixture.drill_replay_commands.len(), 5);
    for replay_command in &fixture.drill_replay_commands {
        assert!(
            replay_command.starts_with("./scripts/e2e/rgc_"),
            "drill replay command must use rgc e2e wrapper: {replay_command}"
        );
        assert!(
            replay_command.ends_with(".sh"),
            "drill replay command must be a shell entrypoint: {replay_command}"
        );
    }
}

#[test]
fn rgc_operator_runbook_incident_matrix_has_required_classes() {
    let fixture = load_fixture();
    assert_eq!(fixture.incident_matrix.len(), 5);

    let scenario_ids: BTreeSet<_> = fixture
        .incident_matrix
        .iter()
        .map(|scenario| scenario.scenario_id.as_str())
        .collect();
    let expected_ids: BTreeSet<_> = [
        "semantic_drift",
        "performance_regression",
        "containment_false_positive",
        "lockstep_divergence",
        "replay_mismatch",
    ]
    .into_iter()
    .collect();
    assert_eq!(scenario_ids, expected_ids);

    for scenario in &fixture.incident_matrix {
        let derived = triage_action(scenario);
        assert_eq!(
            derived, scenario.expected_triage,
            "triage mismatch for scenario `{}`",
            scenario.scenario_id
        );
        assert!(
            scenario.replay_command.starts_with("./scripts/e2e/"),
            "scenario `{}` replay command must be e2e script entrypoint",
            scenario.scenario_id
        );
        let severity = scenario.severity.to_ascii_lowercase();
        assert!(
            severity == "high" || severity == "critical",
            "scenario `{}` severity must be high or critical",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_operator_runbook_emits_structured_event_contract() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-rgc-operator-runbook-static",
        "decision_id": "decision-rgc-operator-runbook-static",
        "policy_id": fixture.policy_id,
        "component": "rgc_operator_incident_runbook_gate",
        "event": "gate_completed",
        "outcome": "pass",
        "error_code": Value::Null
    });
    assert_required_event_keys(&event, &fixture.required_log_keys);
}

#[test]
fn rgc_operator_runbook_script_contains_required_markers() {
    let script = load_script();
    for marker in [
        "source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\"",
        "parser_frontier_bootstrap_env",
        "policy-rgc-operator-incident-runbook-v1",
        "./scripts/e2e/rgc_operator_incident_runbook_replay.sh",
        "incident_timeline",
        "validate_parser_log_schema.sh --events",
    ] {
        assert!(
            script.contains(marker),
            "runbook script missing required marker: {marker}"
        );
    }
}

#[test]
fn rgc_operator_runbook_triage_action_unknown_symptom() {
    let scenario = IncidentScenario {
        scenario_id: "unknown_symptom".to_string(),
        symptom: "completely novel failure mode".to_string(),
        severity: "high".to_string(),
        expected_triage: "unknown".to_string(),
        replay_command: "./scripts/e2e/rgc_unknown.sh".to_string(),
    };
    assert_eq!(triage_action(&scenario), "unknown");
}

#[test]
fn rgc_operator_runbook_triage_is_case_insensitive() {
    let scenario = IncidentScenario {
        scenario_id: "case_test".to_string(),
        symptom: "SEMANTIC DRIFT detected in module".to_string(),
        severity: "critical".to_string(),
        expected_triage: "rerun_runtime_semantics_replay".to_string(),
        replay_command: "./scripts/e2e/rgc_runtime_semantics.sh".to_string(),
    };
    assert_eq!(triage_action(&scenario), "rerun_runtime_semantics_replay");
}

#[test]
fn rgc_operator_runbook_scenario_ids_are_unique() {
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
fn rgc_operator_runbook_deterministic_double_parse() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a, b);
}

#[test]
fn rgc_operator_runbook_doc_file_is_nonempty() {
    let doc = load_doc();
    assert!(!doc.is_empty());
}

#[test]
fn rgc_operator_runbook_drill_commands_are_unique() {
    let fixture = load_fixture();
    let unique: BTreeSet<_> = fixture.drill_replay_commands.iter().collect();
    assert_eq!(
        unique.len(),
        fixture.drill_replay_commands.len(),
        "drill replay commands should be unique"
    );
}

#[test]
fn rgc_operator_runbook_incident_replay_commands_are_unique() {
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
fn rgc_operator_runbook_required_log_keys_are_nonempty() {
    let fixture = load_fixture();
    assert!(!fixture.required_log_keys.is_empty());
    for key in &fixture.required_log_keys {
        assert!(!key.trim().is_empty(), "log key must not be empty");
    }
}

#[test]
fn rgc_operator_runbook_all_symptoms_nonempty() {
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
fn rgc_operator_runbook_fixture_has_bead_id() {
    let fixture = load_fixture();
    assert!(!fixture.bead_id.trim().is_empty());
}

#[test]
fn rgc_operator_runbook_fixture_has_policy_id() {
    let fixture = load_fixture();
    assert!(!fixture.policy_id.trim().is_empty());
}

#[test]
fn rgc_operator_runbook_all_severities_are_nonempty() {
    let fixture = load_fixture();
    for scenario in &fixture.incident_matrix {
        assert!(
            !scenario.severity.trim().is_empty(),
            "scenario {} must have nonempty severity",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_operator_runbook_fixture_has_nonempty_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn rgc_operator_runbook_fixture_has_nonempty_contract_version() {
    let fixture = load_fixture();
    assert!(!fixture.contract_version.trim().is_empty());
}

#[test]
fn rgc_operator_runbook_fixture_deterministic_double_load() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.bead_id, b.bead_id);
}

// ---------- additional enrichment tests ----------

#[test]
fn rgc_operator_runbook_schema_version_follows_dotted_format() {
    let fixture = load_fixture();
    let parts: Vec<&str> = fixture.schema_version.split('.').collect();
    assert!(
        parts.len() >= 3,
        "schema_version should have at least 3 dot-separated segments, got: {}",
        fixture.schema_version
    );
    for part in &parts {
        assert!(
            !part.trim().is_empty(),
            "schema_version segment must not be empty"
        );
    }
}

#[test]
fn rgc_operator_runbook_contract_version_is_semver() {
    let fixture = load_fixture();
    let parts: Vec<&str> = fixture.contract_version.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "contract_version must be semver (major.minor.patch)"
    );
    for part in &parts {
        assert!(
            part.parse::<u32>().is_ok(),
            "contract_version segment '{}' must be a non-negative integer",
            part
        );
    }
}

#[test]
fn rgc_operator_runbook_severity_values_are_in_allowed_set() {
    let fixture = load_fixture();
    let allowed: BTreeSet<&str> = ["high", "critical"].into_iter().collect();
    for scenario in &fixture.incident_matrix {
        let sev = scenario.severity.to_ascii_lowercase();
        assert!(
            allowed.contains(sev.as_str()),
            "scenario {} has severity '{}', expected one of {:?}",
            scenario.scenario_id,
            scenario.severity,
            allowed
        );
    }
}

#[test]
fn rgc_operator_runbook_manifest_keys_contain_no_duplicates() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for key in &fixture.required_manifest_keys {
        assert!(seen.insert(key), "duplicate required_manifest_key: {}", key);
    }
}

#[test]
fn rgc_operator_runbook_log_keys_contain_no_duplicates() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for key in &fixture.required_log_keys {
        assert!(seen.insert(key), "duplicate required_log_key: {}", key);
    }
}

#[test]
fn rgc_operator_runbook_required_modes_contain_no_duplicates() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for mode in &fixture.required_modes {
        assert!(seen.insert(mode), "duplicate required_mode: {}", mode);
    }
}

#[test]
fn rgc_operator_runbook_triage_action_covers_all_scenarios() {
    let fixture = load_fixture();
    for scenario in &fixture.incident_matrix {
        let derived = triage_action(scenario);
        assert_ne!(
            derived, "unknown",
            "scenario {} should have a known triage action, but got 'unknown'",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_operator_runbook_replay_commands_end_with_sh() {
    let fixture = load_fixture();
    for scenario in &fixture.incident_matrix {
        assert!(
            scenario.replay_command.ends_with(".sh"),
            "scenario {} replay_command should end with .sh: {}",
            scenario.scenario_id,
            scenario.replay_command
        );
    }
}

#[test]
fn rgc_operator_runbook_structured_event_with_error_code() {
    let fixture = load_fixture();
    // An event with a non-null error_code should also pass validation
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-rgc-operator-runbook-err",
        "decision_id": "decision-rgc-operator-runbook-err",
        "policy_id": fixture.policy_id,
        "component": "rgc_operator_incident_runbook_gate",
        "event": "gate_completed",
        "outcome": "fail",
        "error_code": "FE-RUNBOOK-0001"
    });
    assert_required_event_keys(&event, &fixture.required_log_keys);
}

#[test]
fn rgc_operator_runbook_expected_triage_values_are_nonempty() {
    let fixture = load_fixture();
    for scenario in &fixture.incident_matrix {
        assert!(
            !scenario.expected_triage.trim().is_empty(),
            "scenario {} must have nonempty expected_triage",
            scenario.scenario_id
        );
    }
}
