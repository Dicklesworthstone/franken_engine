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

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
    assert_eq!(fixture.policy_id, "policy-parser-frontier-harness-v1");
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

// ---------- serde round-trip ----------

#[test]
fn fixture_serde_round_trip_preserves_all_fields() {
    let fixture = load_fixture();
    let serialized = serde_json::to_string(&serde_json::to_value(&fixture).unwrap()).unwrap();
    let deserialized: ParserFrontierHarnessFixture = serde_json::from_str(&serialized).unwrap();
    assert_eq!(fixture, deserialized);
}

#[test]
fn fixture_json_round_trip_through_value_is_lossless() {
    let path = Path::new("tests/fixtures/parser_frontier_harness_v1.json");
    let bytes = fs::read(path).expect("read fixture");
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let re_serialized = serde_json::to_vec_pretty(&value).unwrap();
    let value2: Value = serde_json::from_slice(&re_serialized).unwrap();
    assert_eq!(value, value2);
}

// ---------- determinism ----------

#[test]
fn fixture_loading_is_deterministic_across_calls() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a, b);
}

#[test]
fn fixture_field_ordering_is_deterministic() {
    let path = Path::new("tests/fixtures/parser_frontier_harness_v1.json");
    let bytes = fs::read(path).unwrap();
    let v1: Value = serde_json::from_slice(&bytes).unwrap();
    let v2: Value = serde_json::from_slice(&bytes).unwrap();
    let s1 = serde_json::to_string(&v1).unwrap();
    let s2 = serde_json::to_string(&v2).unwrap();
    assert_eq!(s1, s2);
}

// ---------- individual field constraints ----------

#[test]
fn fixture_schema_version_follows_naming_convention() {
    let fixture = load_fixture();
    assert!(
        fixture.schema_version.starts_with("franken-engine."),
        "schema_version must start with franken-engine."
    );
    assert!(
        fixture.schema_version.ends_with(".v1"),
        "schema_version must end with version suffix"
    );
    assert!(
        fixture.schema_version.contains("parser-frontier-harness"),
        "schema_version must reference parser-frontier-harness"
    );
}

#[test]
fn fixture_contract_version_is_semver() {
    let fixture = load_fixture();
    let parts: Vec<&str> = fixture.contract_version.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "contract_version must be semver (major.minor.patch)"
    );
    for part in &parts {
        part.parse::<u32>()
            .unwrap_or_else(|_| panic!("semver component `{part}` is not a valid integer"));
    }
}

#[test]
fn fixture_bead_id_follows_hierarchical_format() {
    let fixture = load_fixture();
    assert!(
        fixture.bead_id.starts_with("bd-"),
        "bead_id must start with bd- prefix"
    );
    let parts: Vec<&str> = fixture.bead_id.split('.').collect();
    assert!(
        parts.len() >= 2,
        "bead_id must be hierarchical (at least two dot-separated segments)"
    );
}

#[test]
fn fixture_policy_id_follows_naming_convention() {
    let fixture = load_fixture();
    assert!(
        fixture.policy_id.starts_with("policy-"),
        "policy_id must start with policy-"
    );
    assert!(
        fixture.policy_id.contains("parser-frontier-harness"),
        "policy_id must reference parser-frontier-harness"
    );
    assert!(
        fixture.policy_id.ends_with("-v1"),
        "policy_id must end with version tag"
    );
}

#[test]
fn fixture_replay_command_template_references_replay_script() {
    let fixture = load_fixture();
    assert!(
        fixture
            .replay_command_template
            .contains("parser_frontier_harness_replay.sh"),
        "replay_command_template must reference the replay script"
    );
    assert!(
        fixture.replay_command_template.starts_with("./scripts/"),
        "replay_command_template must be a relative script path"
    );
}

#[test]
fn fixture_required_modes_are_nonempty_and_distinct() {
    let fixture = load_fixture();
    assert!(
        !fixture.required_modes.is_empty(),
        "required_modes must not be empty"
    );
    let set: BTreeSet<_> = fixture.required_modes.iter().collect();
    assert_eq!(
        set.len(),
        fixture.required_modes.len(),
        "required_modes must not contain duplicates"
    );
    for mode in &fixture.required_modes {
        assert!(!mode.trim().is_empty(), "mode must not be blank");
    }
}

#[test]
fn fixture_required_scenarios_are_nonempty_and_distinct() {
    let fixture = load_fixture();
    assert!(
        !fixture.required_scenarios.is_empty(),
        "required_scenarios must not be empty"
    );
    let set: BTreeSet<_> = fixture.required_scenarios.iter().collect();
    assert_eq!(
        set.len(),
        fixture.required_scenarios.len(),
        "required_scenarios must not contain duplicates"
    );
    for scenario in &fixture.required_scenarios {
        assert!(!scenario.trim().is_empty(), "scenario must not be blank");
    }
}

#[test]
fn fixture_required_manifest_keys_are_nonempty_and_distinct() {
    let fixture = load_fixture();
    assert!(
        !fixture.required_manifest_keys.is_empty(),
        "required_manifest_keys must not be empty"
    );
    let set: BTreeSet<_> = fixture.required_manifest_keys.iter().collect();
    assert_eq!(
        set.len(),
        fixture.required_manifest_keys.len(),
        "required_manifest_keys must not contain duplicates"
    );
}

#[test]
fn fixture_required_event_keys_are_nonempty_and_distinct() {
    let fixture = load_fixture();
    assert!(
        !fixture.required_event_keys.is_empty(),
        "required_event_keys must not be empty"
    );
    let set: BTreeSet<_> = fixture.required_event_keys.iter().collect();
    assert_eq!(
        set.len(),
        fixture.required_event_keys.len(),
        "required_event_keys must not contain duplicates"
    );
}

#[test]
fn fixture_required_artifacts_are_nonempty_and_distinct() {
    let fixture = load_fixture();
    assert!(
        !fixture.required_artifacts.is_empty(),
        "required_artifacts must not be empty"
    );
    let set: BTreeSet<_> = fixture.required_artifacts.iter().collect();
    assert_eq!(
        set.len(),
        fixture.required_artifacts.len(),
        "required_artifacts must not contain duplicates"
    );
}

#[test]
fn fixture_required_child_runs_are_nonempty_and_distinct() {
    let fixture = load_fixture();
    assert!(
        !fixture.required_child_runs.is_empty(),
        "required_child_runs must not be empty"
    );
    let set: BTreeSet<_> = fixture.required_child_runs.iter().collect();
    assert_eq!(
        set.len(),
        fixture.required_child_runs.len(),
        "required_child_runs must not contain duplicates"
    );
}

// ---------- assert_required_event_keys edge cases ----------

#[test]
fn event_key_validator_accepts_null_error_code() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-test",
        "decision_id": "decision-test",
        "policy_id": fixture.policy_id,
        "component": "parser_frontier_harness",
        "event": "parser_frontier_harness_completed",
        "outcome": "pass",
        "error_code": Value::Null
    });
    assert_required_event_keys(&event, &fixture.required_event_keys);
}

#[test]
fn event_key_validator_accepts_non_empty_string_error_code() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-test",
        "decision_id": "decision-test",
        "policy_id": fixture.policy_id,
        "component": "parser_frontier_harness",
        "event": "parser_frontier_harness_completed",
        "outcome": "fail",
        "error_code": "FE-PARSER-FRONTIER-HARNESS-0001"
    });
    assert_required_event_keys(&event, &fixture.required_event_keys);
}

#[test]
#[should_panic(expected = "missing required key")]
fn event_key_validator_rejects_missing_key() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-test",
        "decision_id": "decision-test",
        "policy_id": fixture.policy_id,
        "component": "parser_frontier_harness",
        "event": "parser_frontier_harness_completed",
        "outcome": "pass"
        // error_code intentionally missing
    });
    assert_required_event_keys(&event, &fixture.required_event_keys);
}

#[test]
#[should_panic(expected = "must be non-empty string")]
fn event_key_validator_rejects_empty_string_value() {
    let event = json!({
        "trace_id": ""
    });
    assert_required_event_keys(&event, &["trace_id".to_owned()]);
}

#[test]
#[should_panic(expected = "must be non-empty string")]
fn event_key_validator_rejects_whitespace_only_value() {
    let event = json!({
        "component": "   "
    });
    assert_required_event_keys(&event, &["component".to_owned()]);
}

#[test]
#[should_panic(expected = "error_code must be null or non-empty string")]
fn event_key_validator_rejects_empty_string_error_code() {
    let event = json!({
        "error_code": ""
    });
    assert_required_event_keys(&event, &["error_code".to_owned()]);
}

#[test]
#[should_panic(expected = "structured event must be a json object")]
fn event_key_validator_rejects_non_object_event() {
    let event = json!("not_an_object");
    assert_required_event_keys(&event, &["schema_version".to_owned()]);
}

// ---------- cross-consistency: fixture ↔ script ----------

#[test]
fn script_validates_all_fixture_modes() {
    let fixture = load_fixture();
    let script = load_script();
    for mode in &fixture.required_modes {
        assert!(
            script.contains(mode.as_str()),
            "script does not reference mode `{mode}`"
        );
    }
}

#[test]
fn script_validates_all_fixture_scenarios() {
    let fixture = load_fixture();
    let script = load_script();
    for scenario in &fixture.required_scenarios {
        assert!(
            script.contains(scenario.as_str()),
            "script does not reference scenario `{scenario}`"
        );
    }
}

#[test]
fn script_references_all_child_runs() {
    let fixture = load_fixture();
    let script = load_script();
    for child_run in &fixture.required_child_runs {
        assert!(
            script.contains(child_run.as_str()),
            "script does not reference child_run `{child_run}`"
        );
    }
}

#[test]
fn script_references_all_required_artifacts() {
    let fixture = load_fixture();
    let script = load_script();
    for artifact in &fixture.required_artifacts {
        let artifact_stem = artifact
            .trim_end_matches(".json")
            .trim_end_matches(".jsonl")
            .trim_end_matches(".txt");
        assert!(
            script.contains(artifact_stem),
            "script does not reference artifact stem `{artifact_stem}` (from `{artifact}`)"
        );
    }
}

#[test]
fn script_references_fixture_policy_id() {
    let fixture = load_fixture();
    let script = load_script();
    assert!(
        script.contains(&fixture.policy_id),
        "script must reference the fixture policy_id"
    );
}

#[test]
fn script_references_fixture_bead_id() {
    let fixture = load_fixture();
    let script = load_script();
    assert!(
        script.contains(&fixture.bead_id),
        "script must reference the fixture bead_id"
    );
}

// ---------- deterministic environment script ----------

fn load_deterministic_env_script() -> String {
    let path = Path::new("../../scripts/e2e/parser_deterministic_env.sh");
    fs::read_to_string(path).expect("read parser deterministic env script")
}

#[test]
fn deterministic_env_script_sets_required_locale_vars() {
    let script = load_deterministic_env_script();
    for var in ["TZ", "LANG", "LC_ALL", "SOURCE_DATE_EPOCH"] {
        assert!(
            script.contains(var),
            "deterministic env script must set {var}"
        );
    }
}

#[test]
fn deterministic_env_script_exports_fingerprint_variables() {
    let script = load_deterministic_env_script();
    for var in [
        "PARSER_FRONTIER_RUSTC_VERSION",
        "PARSER_FRONTIER_CARGO_VERSION",
        "PARSER_FRONTIER_RUST_HOST",
        "PARSER_FRONTIER_CPU_FINGERPRINT",
        "PARSER_FRONTIER_RUSTC_VERBOSE_HASH",
        "PARSER_FRONTIER_TOOLCHAIN_FINGERPRINT",
    ] {
        assert!(
            script.contains(var),
            "deterministic env script must export {var}"
        );
    }
}

#[test]
fn deterministic_env_script_defines_sha256_helper() {
    let script = load_deterministic_env_script();
    assert!(
        script.contains("parser_frontier_sha256"),
        "deterministic env script must define sha256 helper"
    );
    // Must support at least sha256sum or shasum fallback
    assert!(
        script.contains("sha256sum") && script.contains("shasum"),
        "sha256 helper must support sha256sum and shasum fallbacks"
    );
}

#[test]
fn deterministic_env_script_defines_json_escape_helper() {
    let script = load_deterministic_env_script();
    assert!(
        script.contains("parser_frontier_json_escape"),
        "deterministic env script must define json_escape helper"
    );
}

#[test]
fn deterministic_env_script_defines_bootstrap_function() {
    let script = load_deterministic_env_script();
    assert!(
        script.contains("parser_frontier_bootstrap_env"),
        "deterministic env script must define bootstrap function"
    );
}

// ---------- validate_parser_log_schema.sh contract ----------

fn load_log_schema_validator() -> String {
    let path = Path::new("../../scripts/validate_parser_log_schema.sh");
    fs::read_to_string(path).expect("read validate_parser_log_schema.sh")
}

#[test]
fn log_schema_validator_checks_all_required_event_keys() {
    let fixture = load_fixture();
    let validator = load_log_schema_validator();
    for key in &fixture.required_event_keys {
        assert!(
            validator.contains(key.as_str()),
            "validate_parser_log_schema.sh must check required key `{key}`"
        );
    }
}

#[test]
fn log_schema_validator_rejects_sensitive_keys() {
    let validator = load_log_schema_validator();
    for sensitive_pattern in [
        "password",
        "secret",
        "api_key",
        "private_key",
        "access_token",
    ] {
        assert!(
            validator.contains(sensitive_pattern)
                || validator
                    .to_lowercase()
                    .contains(&sensitive_pattern.replace('_', "[_-]?")),
            "validator must check for sensitive pattern `{sensitive_pattern}`"
        );
    }
}

#[test]
fn log_schema_validator_enforces_schema_prefix() {
    let validator = load_log_schema_validator();
    assert!(
        validator.contains("schema_prefix"),
        "validator must enforce schema_version prefix"
    );
    assert!(
        validator.contains("franken-engine.parser"),
        "validator default prefix must be franken-engine.parser"
    );
}

// ---------- replay wrapper deeper checks ----------

#[test]
fn replay_wrapper_validates_scenario_and_mode_arguments() {
    let replay = load_replay_script();
    // Replay must validate scenario
    assert!(
        replay.contains("positive|negative|inventory|full"),
        "replay wrapper must validate scenario argument"
    );
    // Replay must validate mode
    assert!(
        replay.contains("check|test|clippy|ci"),
        "replay wrapper must validate mode argument"
    );
}

#[test]
fn replay_wrapper_sources_deterministic_env() {
    let replay = load_replay_script();
    assert!(
        replay.contains("parser_deterministic_env.sh"),
        "replay wrapper must source deterministic environment script"
    );
    assert!(
        replay.contains("parser_frontier_bootstrap_env"),
        "replay wrapper must call bootstrap function"
    );
}

// ---------- fixture JSON shape completeness ----------

#[test]
fn fixture_json_has_exactly_expected_top_level_keys() {
    let path = Path::new("tests/fixtures/parser_frontier_harness_v1.json");
    let bytes = fs::read(path).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let obj = value.as_object().expect("fixture must be an object");

    let expected_keys: BTreeSet<_> = [
        "schema_version",
        "contract_version",
        "bead_id",
        "policy_id",
        "required_modes",
        "required_scenarios",
        "required_manifest_keys",
        "required_event_keys",
        "required_artifacts",
        "required_child_runs",
        "replay_command_template",
    ]
    .into_iter()
    .collect();

    let actual_keys: BTreeSet<_> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        actual_keys, expected_keys,
        "fixture must have exactly the expected top-level keys"
    );
}

#[test]
fn fixture_all_array_fields_contain_only_strings() {
    let path = Path::new("tests/fixtures/parser_frontier_harness_v1.json");
    let bytes = fs::read(path).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let obj = value.as_object().unwrap();

    let array_fields = [
        "required_modes",
        "required_scenarios",
        "required_manifest_keys",
        "required_event_keys",
        "required_artifacts",
        "required_child_runs",
    ];

    for field in array_fields {
        let arr = obj
            .get(field)
            .unwrap_or_else(|| panic!("missing field `{field}`"))
            .as_array()
            .unwrap_or_else(|| panic!("`{field}` must be an array"));
        for (i, elem) in arr.iter().enumerate() {
            assert!(
                elem.is_string(),
                "`{field}[{i}]` must be a string, got {elem}"
            );
        }
    }
}

// ---------- script structural invariants ----------

#[test]
fn harness_script_starts_with_strict_mode() {
    let script = load_script();
    assert!(
        script.contains("set -euo pipefail"),
        "harness script must use strict bash mode"
    );
}

#[test]
fn harness_script_has_rch_dependency_check() {
    let script = load_script();
    assert!(
        script.contains("command -v rch"),
        "harness script must check for rch availability"
    );
}

#[test]
fn harness_script_has_jq_dependency_check() {
    let script = load_script();
    assert!(
        script.contains("command -v jq"),
        "harness script must check for jq availability"
    );
}

#[test]
fn harness_script_writes_manifest_on_exit() {
    let script = load_script();
    assert!(
        script.contains("write_manifest"),
        "harness script must call write_manifest"
    );
}

#[test]
fn harness_script_validates_log_schema_on_exit() {
    let script = load_script();
    assert!(
        script.contains("validate_parser_log_schema.sh"),
        "harness script must validate log schema"
    );
}

#[test]
fn harness_script_emits_error_code_on_failure() {
    let script = load_script();
    assert!(
        script.contains("FE-PARSER-FRONTIER-HARNESS-0001"),
        "harness script must emit a structured error code on failure"
    );
}

// ---------- event construction variants ----------

#[test]
fn event_with_pass_outcome_has_null_error_code() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-pass-test",
        "decision_id": "decision-pass-test",
        "policy_id": fixture.policy_id,
        "component": "parser_frontier_harness",
        "event": "parser_frontier_harness_completed",
        "outcome": "pass",
        "error_code": Value::Null
    });
    assert_required_event_keys(&event, &fixture.required_event_keys);
    assert!(event["error_code"].is_null());
    assert_eq!(event["outcome"].as_str().unwrap(), "pass");
}

#[test]
fn event_with_fail_outcome_has_non_null_error_code() {
    let fixture = load_fixture();
    let event = json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-fail-test",
        "decision_id": "decision-fail-test",
        "policy_id": fixture.policy_id,
        "component": "parser_frontier_harness",
        "event": "parser_frontier_harness_completed",
        "outcome": "fail",
        "error_code": "FE-PARSER-FRONTIER-HARNESS-0001"
    });
    assert_required_event_keys(&event, &fixture.required_event_keys);
    assert!(!event["error_code"].is_null());
    assert_eq!(event["outcome"].as_str().unwrap(), "fail");
}

// ---------- manifest key coverage ----------

#[test]
fn manifest_keys_include_essential_tracing_fields() {
    let fixture = load_fixture();
    let manifest_keys: BTreeSet<_> = fixture.required_manifest_keys.iter().cloned().collect();
    for essential in [
        "trace_id",
        "decision_id",
        "policy_id",
        "schema_version",
        "bead_id",
    ] {
        assert!(
            manifest_keys.contains(essential),
            "manifest keys must include `{essential}`"
        );
    }
}

#[test]
fn manifest_keys_include_operational_fields() {
    let fixture = load_fixture();
    let manifest_keys: BTreeSet<_> = fixture.required_manifest_keys.iter().cloned().collect();
    for operational in [
        "deterministic_environment",
        "replay_command",
        "child_runs",
        "commands",
        "artifacts",
        "operator_verification",
    ] {
        assert!(
            manifest_keys.contains(operational),
            "manifest keys must include operational field `{operational}`"
        );
    }
}

// ---------- child run cross-checks ----------

#[test]
fn child_runs_correspond_to_script_suites() {
    let fixture = load_fixture();
    let script = load_script();
    // Each child run should have a corresponding suite function or reference
    for child in &fixture.required_child_runs {
        let normalized = child.replace('-', "_");
        assert!(
            script.contains(&normalized),
            "script must reference child run `{child}` (as `{normalized}`)"
        );
    }
}

// ---------- README deeper coverage ----------

#[test]
fn readme_lists_all_required_artifacts_by_name() {
    let fixture = load_fixture();
    let readme = load_readme();
    for artifact in &fixture.required_artifacts {
        if artifact.ends_with("_dir") {
            // Directory references may appear as path patterns
            let stem = artifact.trim_end_matches("_dir");
            assert!(
                readme.contains(stem),
                "README must reference artifact directory stem `{stem}`"
            );
        } else {
            assert!(
                readme.contains(artifact.as_str()),
                "README must reference artifact `{artifact}`"
            );
        }
    }
}
