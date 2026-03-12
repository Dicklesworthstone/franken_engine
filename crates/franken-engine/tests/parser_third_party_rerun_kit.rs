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
struct ParserThirdPartyRerunKitFixture {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_modes: Vec<String>,
    required_manifest_keys: Vec<String>,
    required_log_keys: Vec<String>,
    matrix_input_statuses: Vec<String>,
    upstream_matrix_inputs: Vec<String>,
    replay_command: String,
}

fn load_fixture() -> ParserThirdPartyRerunKitFixture {
    let path = Path::new("tests/fixtures/parser_third_party_rerun_kit_v1.json");
    let bytes = fs::read(path).expect("read parser third-party rerun kit fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser third-party rerun kit fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_THIRD_PARTY_RERUN_KIT.md");
    fs::read_to_string(path).expect("read parser third-party rerun kit contract doc")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_parser_third_party_rerun_kit.sh");
    fs::read_to_string(path).expect("read parser third-party rerun kit script")
}

fn load_replay_wrapper() -> String {
    let path = Path::new("../../scripts/e2e/parser_third_party_rerun_kit_replay.sh");
    fs::read_to_string(path).expect("read parser third-party rerun kit replay wrapper")
}

fn classify_matrix_input_status(
    matrix_summary_provided: bool,
    matrix_complete: bool,
    critical_delta_count: u64,
) -> &'static str {
    if !matrix_summary_provided {
        return "pending_upstream_matrix";
    }
    if !matrix_complete {
        return "incomplete_matrix";
    }
    if critical_delta_count > 0 {
        return "blocked_critical_deltas";
    }
    "ready_for_external_rerun"
}

fn assert_required_event_keys(event: &Value, required_keys: &[String]) {
    for key in required_keys {
        let value = event
            .get(key)
            .unwrap_or_else(|| panic!("missing required key in event: {key}"));
        if key == "error_code" {
            assert!(
                value.is_null() || value.as_str().is_some_and(|raw| !raw.is_empty()),
                "error_code must be null or non-empty string"
            );
            continue;
        }
        assert!(
            value.as_str().is_some_and(|raw| !raw.is_empty()),
            "event key `{key}` must be non-empty string"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "# Parser Third-Party Rerun Kit Contract",
        "## Scope",
        "## Contract Version",
        "## Upstream Dependencies",
        "## Kit Contents",
        "## Matrix Input Status Model",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "third-party rerun kit doc missing section: {section}"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_fixture_declares_expected_versions() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-third-party-rerun-kit.fixture.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-2mds.1.7.3");
    assert_eq!(fixture.policy_id, "policy-parser-third-party-rerun-kit-v1");
    assert_eq!(
        fixture.replay_command,
        "./scripts/e2e/parser_third_party_rerun_kit_replay.sh package"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_modes_and_statuses_are_complete() {
    let fixture = load_fixture();

    let expected_modes: BTreeSet<_> = ["check", "test", "clippy", "ci", "package"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let actual_modes: BTreeSet<_> = fixture.required_modes.iter().cloned().collect();
    assert_eq!(actual_modes, expected_modes);

    let expected_statuses: BTreeSet<_> = [
        "pending_upstream_matrix",
        "incomplete_matrix",
        "blocked_critical_deltas",
        "ready_for_external_rerun",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    let actual_statuses: BTreeSet<_> = fixture.matrix_input_statuses.iter().cloned().collect();
    assert_eq!(actual_statuses, expected_statuses);

    let expected_inputs: BTreeSet<_> = ["summary", "deltas", "run_manifest"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let actual_inputs: BTreeSet<_> = fixture.upstream_matrix_inputs.iter().cloned().collect();
    assert_eq!(actual_inputs, expected_inputs);
}

#[test]
fn parser_third_party_rerun_kit_matrix_status_classifier_remains_stable() {
    assert_eq!(
        classify_matrix_input_status(false, false, 0),
        "pending_upstream_matrix"
    );
    assert_eq!(
        classify_matrix_input_status(true, false, 0),
        "incomplete_matrix"
    );
    assert_eq!(
        classify_matrix_input_status(true, true, 2),
        "blocked_critical_deltas"
    );
    assert_eq!(
        classify_matrix_input_status(true, true, 0),
        "ready_for_external_rerun"
    );
}

#[test]
fn parser_third_party_rerun_kit_structured_events_require_contract_keys() {
    let fixture = load_fixture();

    let gate_event = json!({
        "schema_version": "franken-engine.parser-third-party-rerun-kit.event.v1",
        "trace_id": "trace-parser-third-party-rerun-kit-static",
        "decision_id": "decision-parser-third-party-rerun-kit-static",
        "policy_id": fixture.policy_id,
        "component": "parser_third_party_rerun_kit_gate",
        "event": "gate_completed",
        "matrix_input_status": "pending_upstream_matrix",
        "outcome": "pass",
        "error_code": Value::Null
    });
    assert_required_event_keys(&gate_event, &fixture.required_log_keys);
}

#[test]
fn parser_third_party_rerun_kit_script_contains_required_markers() {
    let script = load_script();
    let required_markers = [
        "source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\"",
        "parser_frontier_bootstrap_env",
        "policy-parser-third-party-rerun-kit-v1",
        "RCH-E326",
        "running locally",
        "timeout --kill-after=30",
        "rch_last_remote_exit_code",
        "rch_reported_timeout_seconds",
        "rch_reject_artifact_retrieval_failure",
        "RCH_BUILD_TIMEOUT_SEC",
        "RCH_BUILD_TIMEOUT_SECONDS",
        "rch_build_timeout_sec",
        "rch-timeout-mismatch-",
        "missing-remote-exit-marker",
        "failed_step_log_path",
        "step_logs_dir",
        "PARSER_RERUN_KIT_MATRIX_SUMMARY",
        "PARSER_RERUN_KIT_AUTO_DISCOVER_MATRIX",
        "find_latest_matrix_summary",
        "auto_discover_matrix_inputs",
        "matrix_input_auto_discovery_enabled",
        "auto_discovered",
        "target_rch_parser_third_party_rerun_kit_",
        "parser_frontier_emit_manifest_environment_fields",
        "./scripts/e2e/parser_third_party_rerun_kit_replay.sh",
    ];

    for marker in required_markers {
        assert!(
            script.contains(marker),
            "rerun kit script missing marker: {marker}"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_script_uses_repo_local_target_dir() {
    let script = load_script();
    assert!(
        script.contains("${root_dir}/target_rch_parser_third_party_rerun_kit_"),
        "rerun kit script must default to a repo-local rch target dir"
    );
    assert!(
        !script.contains("/tmp/rch_target_franken_engine_parser_third_party_rerun_kit"),
        "rerun kit script must not default to /tmp for CARGO_TARGET_DIR"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_manifest_and_log_key_sets_are_exact() {
    let fixture = load_fixture();

    let expected_manifest: BTreeSet<_> = [
        "schema_version",
        "bead_id",
        "deterministic_env_schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "matrix_input_status",
        "deterministic_environment",
        "replay_command",
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
fn parser_third_party_rerun_kit_replay_wrapper_surfaces_latest_artifacts() {
    let replay_wrapper = load_replay_wrapper();
    for marker in [
        "artifact_root=\"${PARSER_RERUN_KIT_ARTIFACT_ROOT:-artifacts/parser_third_party_rerun_kit}\"",
        "latest manifest:",
        "latest rerun kit index:",
        "latest events:",
        "run_manifest.json",
        "rerun_kit_index.json",
        "events.jsonl",
    ] {
        assert!(
            replay_wrapper.contains(marker),
            "rerun kit replay wrapper missing marker: {marker}"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_classifier_is_deterministic() {
    for _ in 0..10 {
        assert_eq!(
            classify_matrix_input_status(false, false, 0),
            "pending_upstream_matrix"
        );
        assert_eq!(
            classify_matrix_input_status(true, true, 0),
            "ready_for_external_rerun"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_classifier_priority_order() {
    // pending_upstream_matrix takes priority over incomplete and blocked
    assert_eq!(
        classify_matrix_input_status(false, false, 5),
        "pending_upstream_matrix"
    );
    // incomplete_matrix takes priority over blocked
    assert_eq!(
        classify_matrix_input_status(true, false, 5),
        "incomplete_matrix"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_deterministic_double_parse() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a, b);
}

#[test]
fn parser_third_party_rerun_kit_doc_file_nonempty() {
    let doc = load_doc();
    assert!(!doc.is_empty());
}

#[test]
fn parser_third_party_rerun_kit_script_file_nonempty() {
    let script = load_script();
    assert!(!script.is_empty());
}

#[test]
fn parser_third_party_rerun_kit_upstream_inputs_are_nonempty_strings() {
    let fixture = load_fixture();
    for input in &fixture.upstream_matrix_inputs {
        assert!(!input.trim().is_empty(), "upstream input must not be empty");
    }
}

#[test]
fn parser_third_party_rerun_kit_required_modes_are_unique() {
    let fixture = load_fixture();
    let unique: BTreeSet<_> = fixture.required_modes.iter().collect();
    assert_eq!(
        unique.len(),
        fixture.required_modes.len(),
        "modes must be unique"
    );
}

#[test]
fn parser_third_party_rerun_kit_manifest_keys_are_unique() {
    let fixture = load_fixture();
    let unique: BTreeSet<_> = fixture.required_manifest_keys.iter().collect();
    assert_eq!(
        unique.len(),
        fixture.required_manifest_keys.len(),
        "manifest keys must be unique"
    );
}

#[test]
fn parser_third_party_rerun_kit_log_keys_are_unique() {
    let fixture = load_fixture();
    let unique: BTreeSet<_> = fixture.required_log_keys.iter().collect();
    assert_eq!(
        unique.len(),
        fixture.required_log_keys.len(),
        "log keys must be unique"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_has_replay_command() {
    let fixture = load_fixture();
    assert!(
        !fixture.replay_command.trim().is_empty(),
        "replay command must not be empty"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_has_bead_id() {
    let fixture = load_fixture();
    assert!(
        !fixture.bead_id.trim().is_empty(),
        "bead_id must not be empty"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_has_policy_id() {
    let fixture = load_fixture();
    assert!(
        !fixture.policy_id.trim().is_empty(),
        "policy_id must not be empty"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_has_contract_version() {
    let fixture = load_fixture();
    assert!(!fixture.contract_version.trim().is_empty());
}

#[test]
fn parser_third_party_rerun_kit_fixture_has_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn parser_third_party_rerun_kit_fixture_deterministic_double_load() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.bead_id, b.bead_id);
}

// ---------- additional doc and contract validation ----------

#[test]
fn parser_third_party_rerun_kit_doc_word_count_exceeds_minimum() {
    let doc = load_doc();
    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 200,
        "rerun kit doc must have at least 200 words, found {word_count}"
    );
}

#[test]
fn parser_third_party_rerun_kit_doc_contains_required_keywords() {
    let doc = load_doc();
    for keyword in [
        "deterministic",
        "replay",
        "artifact",
        "matrix",
        "verifier",
        "fail-closed",
        "rch",
    ] {
        assert!(
            doc.to_ascii_lowercase().contains(keyword),
            "rerun kit doc missing required keyword: {keyword}"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_doc_section_ordering_is_correct() {
    let doc = load_doc();
    let sections = [
        "## Scope",
        "## Contract Version",
        "## Upstream Dependencies",
        "## Kit Contents",
        "## Matrix Input Status Model",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ];
    let mut last_pos = 0;
    for section in sections {
        if let Some(pos) = doc.find(section) {
            assert!(
                pos >= last_pos,
                "section `{section}` appears out of order in rerun kit doc"
            );
            last_pos = pos;
        }
    }
}

#[test]
fn parser_third_party_rerun_kit_classifier_blocked_at_boundary() {
    // exactly 1 critical delta should still block
    assert_eq!(
        classify_matrix_input_status(true, true, 1),
        "blocked_critical_deltas"
    );
    // zero critical deltas should be ready
    assert_eq!(
        classify_matrix_input_status(true, true, 0),
        "ready_for_external_rerun"
    );
}

#[test]
fn parser_third_party_rerun_kit_classifier_high_delta_count() {
    assert_eq!(
        classify_matrix_input_status(true, true, 1_000),
        "blocked_critical_deltas"
    );
}

#[test]
fn parser_third_party_rerun_kit_replay_command_is_script_path() {
    let fixture = load_fixture();
    assert!(
        fixture.replay_command.starts_with("./scripts/"),
        "replay command must reference scripts/ directory"
    );
    assert!(
        fixture.replay_command.ends_with(".sh package") || fixture.replay_command.ends_with(".sh"),
        "replay command must invoke a shell script"
    );
}

#[test]
fn parser_third_party_rerun_kit_doc_mentions_rch_timeout() {
    let doc = load_doc();
    assert!(
        doc.contains("RCH_BUILD_TIMEOUT"),
        "rerun kit doc must mention RCH_BUILD_TIMEOUT env variable"
    );
}

#[test]
fn parser_third_party_rerun_kit_doc_mentions_auto_discovery_and_repo_local_target_dir() {
    let doc = load_doc();
    for marker in [
        "auto-discover",
        "PARSER_RERUN_KIT_AUTO_DISCOVER_MATRIX=0",
        "target_rch_parser_third_party_rerun_kit_<timestamp>_<pid>",
        "`env`, `auto_discovered`, or `missing`",
    ] {
        assert!(
            doc.contains(marker),
            "rerun kit doc missing auto-discovery/target-dir marker: {marker}"
        );
    }
    assert!(
        !doc.contains("/tmp/rch_target_franken_engine_parser_third_party_rerun_kit"),
        "rerun kit doc must not prescribe /tmp rch target dirs"
    );
}

#[test]
fn parser_third_party_rerun_kit_script_mentions_mode_package() {
    let script = load_script();
    assert!(
        script.contains("package"),
        "rerun kit script must support package mode"
    );
}

#[test]
fn parser_third_party_rerun_kit_fixture_matrix_statuses_cover_all_classifier_outputs() {
    let fixture = load_fixture();
    let statuses: BTreeSet<_> = fixture.matrix_input_statuses.iter().cloned().collect();
    // All four possible outputs of classify_matrix_input_status must be present
    let test_cases = [
        (false, false, 0u64, "pending_upstream_matrix"),
        (true, false, 0, "incomplete_matrix"),
        (true, true, 1, "blocked_critical_deltas"),
        (true, true, 0, "ready_for_external_rerun"),
    ];
    for (provided, complete, deltas, expected) in test_cases {
        let result = classify_matrix_input_status(provided, complete, deltas);
        assert_eq!(result, expected);
        assert!(
            statuses.contains(expected),
            "fixture matrix_input_statuses missing classifier output: {expected}"
        );
    }
}

#[test]
fn parser_third_party_rerun_kit_doc_references_cli_commands() {
    let doc = load_doc();
    for cli in [
        "./scripts/run_parser_third_party_rerun_kit.sh",
        "./scripts/e2e/parser_third_party_rerun_kit_replay.sh",
    ] {
        assert!(
            doc.contains(cli),
            "rerun kit doc missing CLI command reference: {cli}"
        );
    }
}
