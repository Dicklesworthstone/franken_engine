#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserFrontierHarnessFixture {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_modes: Vec<String>,
    required_scenarios: Vec<String>,
    required_manifest_keys: Vec<String>,
    required_event_keys: Vec<String>,
    required_artifacts: Vec<String>,
    required_child_runs: Vec<String>,
    replay_command_template: String,
}

fn load_fixture() -> ParserFrontierHarnessFixture {
    let path = Path::new("tests/fixtures/parser_frontier_harness_v1.json");
    let bytes = fs::read(path).expect("read parser frontier harness fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser frontier harness fixture")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_parser_frontier_harness.sh");
    fs::read_to_string(path).expect("read parser frontier harness script")
}

fn load_replay_script() -> String {
    let path = Path::new("../../scripts/e2e/parser_frontier_harness_replay.sh");
    fs::read_to_string(path).expect("read parser frontier harness replay script")
}

fn load_readme() -> String {
    fs::read_to_string(Path::new("../../README.md"))
        .expect("read repository README for parser frontier harness references")
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
fn parser_frontier_harness_fixture_schema_and_policy_are_stable() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-frontier-harness.contract.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-1lsy.2.6.4");
    assert_eq!(
        fixture.policy_id,
        "policy-parser-frontier-harness-v1"
    );
}

#[test]
fn parser_frontier_harness_fixture_declares_exact_modes_and_scenarios() {
    let fixture = load_fixture();

    let expected_modes: BTreeSet<_> = ["check", "test", "clippy", "ci"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let actual_modes: BTreeSet<_> = fixture.required_modes.iter().cloned().collect();
    assert_eq!(actual_modes, expected_modes);

    let expected_scenarios: BTreeSet<_> = ["positive", "negative", "inventory", "full"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let actual_scenarios: BTreeSet<_> = fixture.required_scenarios.iter().cloned().collect();
    assert_eq!(actual_scenarios, expected_scenarios);
}

#[test]
fn parser_frontier_harness_manifest_and_artifact_contract_is_complete() {
    let fixture = load_fixture();

    let expected_manifest: BTreeSet<_> = [
        "schema_version",
        "bead_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "deterministic_environment",
        "replay_command",
        "child_runs",
        "commands",
        "artifacts",
        "operator_verification",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_manifest: BTreeSet<_> = fixture.required_manifest_keys.iter().cloned().collect();
    assert_eq!(actual_manifest, expected_manifest);

    let expected_artifacts: BTreeSet<_> = [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "parser_gap_report.json",
        "case_diagnostics_dir",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_artifacts: BTreeSet<_> = fixture.required_artifacts.iter().cloned().collect();
    assert_eq!(actual_artifacts, expected_artifacts);

    let expected_child_runs: BTreeSet<_> = [
        "optional_chaining",
        "tagged_meta_frontier",
        "parser_gap_inventory",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_child_runs: BTreeSet<_> = fixture.required_child_runs.iter().cloned().collect();
    assert_eq!(actual_child_runs, expected_child_runs);
}

#[test]
fn parser_frontier_harness_event_contract_is_stable() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-parser-frontier-harness-static",
        "decision_id": "decision-parser-frontier-harness-static",
        "policy_id": fixture.policy_id,
        "component": "parser_frontier_harness",
        "event": "parser_frontier_harness_completed",
        "outcome": "pass",
        "error_code": Value::Null
    });
    assert_required_event_keys(&event, &fixture.required_event_keys);
}

#[test]
fn parser_frontier_harness_script_contains_required_markers() {
    let script = load_script();
    for marker in [
        "source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\"",
        "parser_frontier_bootstrap_env",
        "policy-parser-frontier-harness-v1",
        "scripts/run_parser_optional_chaining_suite.sh",
        "scripts/run_parser_tagged_meta_frontier_suite.sh",
        "franken_parser_gap_inventory",
        "verify_child_report_pass",
        "child-report-outcome:",
        "parser_frontier_emit_manifest_environment_fields",
        "parser_frontier_harness_completed",
        "case_diagnostics_dir",
        "validate_parser_log_schema.sh --events",
    ] {
        assert!(
            script.contains(marker),
            "parser frontier harness script missing marker: {marker}"
        );
    }
}

#[test]
fn parser_frontier_harness_replay_wrapper_is_one_command_entrypoint() {
    let fixture = load_fixture();
    let replay = load_replay_script();

    assert!(
        replay.contains("PARSER_FRONTIER_HARNESS_SCENARIO"),
        "replay wrapper must forward scenario through env"
    );
    assert!(
        replay.contains("./scripts/run_parser_frontier_harness.sh"),
        "replay wrapper must delegate to harness script"
    );
    assert_eq!(
        fixture.replay_command_template,
        "./scripts/e2e/parser_frontier_harness_replay.sh full ci"
    );
}

#[test]
fn readme_references_parser_frontier_harness_commands() {
    let readme = load_readme();
    for marker in [
        "## Parser Frontier Harness",
        "./scripts/run_parser_frontier_harness.sh ci",
        "./scripts/e2e/parser_frontier_harness_replay.sh full ci",
        "parser_gap_report.json",
    ] {
        assert!(
            readme.contains(marker),
            "README missing parser frontier harness reference: {marker}"
        );
    }
}
