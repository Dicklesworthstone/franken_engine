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

use serde::{Deserialize, Serialize};

const PACK_SCHEMA_VERSION: &str = "franken-engine.rgc-runtime-semantics-verification-pack.v1";
const VECTORS_SCHEMA_VERSION: &str = "franken-engine.rgc-runtime-semantics-verification-vectors.v1";
const PACK_JSON: &str =
    include_str!("../../../docs/rgc_runtime_semantics_verification_pack_v1.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/rgc_runtime_semantics_verification_vectors_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeSemanticsPackContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_semantics_classes: Vec<String>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    test_vectors_source: String,
    failure_scenarios: Vec<FailureScenario>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FailureScenario {
    scenario_id: String,
    path_type: String,
    command_template: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeSemanticsVectors {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    vectors: Vec<RuntimeSemanticsVector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeSemanticsVector {
    scenario_id: String,
    semantics_class: String,
    severity: String,
    path_type: String,
    deterministic_seed: u64,
    expected_outcome: String,
    expected_policy_action: String,
    command_template: String,
    minimal_repro_pointer: String,
    requires_replay: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_contract() -> RuntimeSemanticsPackContract {
    serde_json::from_str(PACK_JSON).expect("runtime semantics pack contract must parse")
}

fn parse_vectors() -> RuntimeSemanticsVectors {
    serde_json::from_str(VECTORS_JSON).expect("runtime semantics vectors must parse")
}

fn expected_policy_action_for_class(class_name: &str) -> &'static str {
    match class_name {
        "arithmetic_control_flow" => "execute",
        "object_closure_semantics" => "execute_with_closure_environment",
        "async_error_path" => "execute_with_async_replay",
        _ => "unknown",
    }
}

#[test]
fn rgc_057_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_RUNTIME_SEMANTICS_VERIFICATION_PACK_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Runtime Semantics Verification Pack V1",
        "## Scope",
        "## Contract Version",
        "## Required Semantics Classes",
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
}

#[test]
fn rgc_057_readme_gate_section_documents_contract_and_artifacts() {
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in [
        "## RGC Runtime Semantics Verification Pack",
        "./scripts/run_rgc_runtime_semantics_verification_pack.sh ci",
        "./scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh ci",
        "docs/rgc_runtime_semantics_verification_pack_v1.json",
        "docs/rgc_runtime_semantics_verification_vectors_v1.json",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/run_manifest.json",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/events.jsonl",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/commands.txt",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/runtime_semantics_verification_report.json",
        "artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/step_logs/step_*.log",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_057_contract_is_versioned_and_replay_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, PACK_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.7");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-runtime-semantics-verification-pack-v1"
    );
    assert_eq!(
        contract.test_vectors_source,
        "docs/rgc_runtime_semantics_verification_vectors_v1.json"
    );

    let required_classes: BTreeSet<&str> = contract
        .required_semantics_classes
        .iter()
        .map(String::as_str)
        .collect();
    for class_name in [
        "arithmetic_control_flow",
        "object_closure_semantics",
        "async_error_path",
    ] {
        assert!(
            required_classes.contains(class_name),
            "missing required semantics class {class_name}"
        );
    }

    let log_keys: BTreeSet<&str> = contract
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
        "semantics_class",
        "path_type",
        "outcome",
        "error_code",
    ] {
        assert!(log_keys.contains(key), "missing required log key {key}");
    }

    let artifacts: BTreeSet<&str> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "runtime_semantics_verification_report.json",
        "step_logs/step_*.log",
    ] {
        assert!(
            artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_runtime_semantics_verification_pack.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-runtime-semantics-verification-pack.run-manifest.v1"
    );

    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_vectors_file"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-057-VECTORS-0001"
            && scenario
                .expected_message_fragment
                .contains("missing vectors JSON")
            && !scenario.command_template.trim().is_empty()
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_json"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-057-VECTORS-0002"
            && scenario
                .expected_message_fragment
                .contains("failed to parse vectors JSON")
            && !scenario.command_template.trim().is_empty()
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_semantics"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-057-VECTORS-0003"
            && scenario
                .expected_message_fragment
                .contains("vector contract validation failed")
            && !scenario.command_template.trim().is_empty()
    }));

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| { entry.contains("run_rgc_runtime_semantics_verification_pack.sh ci") })
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| { entry.contains("rgc_runtime_semantics_verification_pack_replay.sh") })
    );
}

#[test]
fn rgc_057_vectors_are_deterministic_unique_and_complete() {
    let vectors = parse_vectors();
    let contract = parse_contract();

    assert_eq!(vectors.schema_version, VECTORS_SCHEMA_VERSION);
    assert_eq!(vectors.contract_version, "1.0.0");
    assert_eq!(vectors.bead_id, "bd-1lsy.11.7");
    assert_eq!(vectors.generated_by, "bd-1lsy.11.7");
    assert!(vectors.generated_at_utc.ends_with('Z'));
    assert_eq!(vectors.vectors.len(), 3);

    let mut scenario_ids = BTreeSet::new();
    let mut seeds = BTreeSet::new();
    let mut classes_seen = BTreeSet::new();

    for vector in &vectors.vectors {
        assert!(
            scenario_ids.insert(vector.scenario_id.as_str()),
            "duplicate scenario_id {}",
            vector.scenario_id
        );
        assert!(
            seeds.insert(vector.deterministic_seed),
            "duplicate deterministic_seed {}",
            vector.deterministic_seed
        );
        assert!(
            ["critical", "high", "medium", "low"].contains(&vector.severity.as_str()),
            "invalid severity {}",
            vector.severity
        );
        assert!(
            ["golden", "failure"].contains(&vector.path_type.as_str()),
            "invalid path_type {}",
            vector.path_type
        );
        assert!(
            ["expect_pass", "expect_fail_with_minimal_repro"]
                .contains(&vector.expected_outcome.as_str()),
            "invalid expected_outcome {}",
            vector.expected_outcome
        );
        assert!(
            [
                "execute",
                "execute_with_closure_environment",
                "execute_with_async_replay"
            ]
            .contains(&vector.expected_policy_action.as_str()),
            "invalid expected_policy_action {}",
            vector.expected_policy_action
        );
        assert!(vector.requires_replay, "all vectors must require replay");
        assert!(
            !vector.command_template.trim().is_empty(),
            "command_template must not be empty"
        );
        assert!(
            !vector.minimal_repro_pointer.trim().is_empty(),
            "minimal_repro_pointer must not be empty"
        );
        assert_eq!(
            vector.expected_outcome, "expect_pass",
            "runtime semantics vectors must currently be golden-path deterministic checks"
        );
        assert_eq!(
            vector.expected_policy_action,
            expected_policy_action_for_class(&vector.semantics_class),
            "unexpected policy action for class {}",
            vector.semantics_class
        );

        classes_seen.insert(vector.semantics_class.as_str());
    }

    let required_classes: BTreeSet<&str> = contract
        .required_semantics_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(classes_seen, required_classes);
}

#[test]
fn rgc_057_lane_script_preserves_step_logs_and_failure_classification() {
    let path = repo_root().join("scripts/run_rgc_runtime_semantics_verification_pack.sh");
    let script = read_to_string(&path);

    for required_fragment in [
        "step_logs_dir=\"${run_dir}/step_logs\"",
        "step_logs+=(\"${log_path}\")",
        "(timeout-${rch_timeout_seconds}s)",
        "(rch-exit=${status}; remote-exit=${remote_exit_code})",
        "(rch-exit=${status}; missing-remote-exit-marker)",
        "(rch-local-fallback-detected)",
        "rgc-runtime-semantics-verification-pack.run-manifest.v1",
    ] {
        assert!(
            script.contains(required_fragment),
            "missing script fragment in {}: {required_fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_057_contract_and_vectors_files_exist_at_declared_paths() {
    let root = repo_root();
    for path in [
        "docs/RGC_RUNTIME_SEMANTICS_VERIFICATION_PACK_V1.md",
        "docs/rgc_runtime_semantics_verification_pack_v1.json",
        "docs/rgc_runtime_semantics_verification_vectors_v1.json",
        "scripts/run_rgc_runtime_semantics_verification_pack.sh",
        "scripts/e2e/rgc_runtime_semantics_verification_pack_replay.sh",
        "crates/franken-engine/tests/rgc_runtime_semantics_verification_pack.rs",
    ] {
        let full = root.join(path);
        assert!(full.exists(), "expected path to exist: {}", full.display());
    }
}

// ---------- contract field completeness ----------

#[test]
fn rgc_057_contract_failure_scenarios_have_unique_ids() {
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
fn rgc_057_contract_failure_scenarios_all_have_failure_path_type() {
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
fn rgc_057_contract_error_codes_all_start_with_fe_rgc_057() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert!(
            scenario.expected_error_code.starts_with("FE-RGC-057-"),
            "scenario {} error code should start with FE-RGC-057-: {}",
            scenario.scenario_id,
            scenario.expected_error_code
        );
    }
}

#[test]
fn rgc_057_contract_semantics_classes_are_exactly_three() {
    let contract = parse_contract();
    assert_eq!(contract.required_semantics_classes.len(), 3);
    let classes: BTreeSet<&str> = contract
        .required_semantics_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        classes,
        [
            "arithmetic_control_flow",
            "async_error_path",
            "object_closure_semantics"
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
}

#[test]
fn rgc_057_contract_required_log_keys_exactly_ten() {
    let contract = parse_contract();
    assert_eq!(contract.required_log_keys.len(), 10);
}

#[test]
fn rgc_057_contract_required_artifacts_exactly_five() {
    let contract = parse_contract();
    assert_eq!(contract.required_artifacts.len(), 5);
}

// ---------- vectors cross-referencing ----------

#[test]
fn rgc_057_vectors_match_contract_version() {
    let contract = parse_contract();
    let vectors = parse_vectors();
    assert_eq!(contract.contract_version, vectors.contract_version);
}

#[test]
fn rgc_057_vectors_bead_id_matches_contract() {
    let contract = parse_contract();
    let vectors = parse_vectors();
    assert_eq!(contract.bead_id, vectors.bead_id);
}

#[test]
fn rgc_057_vectors_test_vectors_source_path_matches_actual_file() {
    let contract = parse_contract();
    let root = repo_root();
    let vectors_path = root.join(&contract.test_vectors_source);
    assert!(
        vectors_path.exists(),
        "test_vectors_source path should exist: {}",
        vectors_path.display()
    );
}

#[test]
fn rgc_057_all_vector_scenario_ids_are_nonempty() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        assert!(
            !vector.scenario_id.trim().is_empty(),
            "scenario_id must not be empty"
        );
    }
}

#[test]
fn rgc_057_all_vector_semantics_classes_are_in_contract() {
    let contract = parse_contract();
    let vectors = parse_vectors();
    let required: BTreeSet<&str> = contract
        .required_semantics_classes
        .iter()
        .map(String::as_str)
        .collect();
    for vector in &vectors.vectors {
        assert!(
            required.contains(vector.semantics_class.as_str()),
            "vector semantics_class {} not in contract required classes",
            vector.semantics_class
        );
    }
}

#[test]
fn rgc_057_vectors_have_positive_deterministic_seeds() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        assert!(
            vector.deterministic_seed > 0,
            "deterministic_seed must be positive for {}",
            vector.scenario_id
        );
    }
}

#[test]
fn rgc_057_all_vectors_have_nonempty_minimal_repro_pointer() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        assert!(
            !vector.minimal_repro_pointer.trim().is_empty(),
            "minimal_repro_pointer must not be empty for {}",
            vector.scenario_id
        );
    }
}

// ---------- serde roundtrip ----------

#[test]
fn rgc_057_contract_json_serde_roundtrip() {
    let contract = parse_contract();
    let json = serde_json::to_string(&contract).expect("contract should serialize");
    let recovered: RuntimeSemanticsPackContract =
        serde_json::from_str(&json).expect("contract should deserialize");
    assert_eq!(contract, recovered);
}

#[test]
fn rgc_057_vectors_json_serde_roundtrip() {
    let vectors = parse_vectors();
    let json = serde_json::to_string(&vectors).expect("vectors should serialize");
    let recovered: RuntimeSemanticsVectors =
        serde_json::from_str(&json).expect("vectors should deserialize");
    assert_eq!(vectors, recovered);
}

// ---------- gate runner fields ----------

#[test]
fn rgc_057_gate_runner_script_exists_on_disk() {
    let contract = parse_contract();
    let root = repo_root();
    let script_path = root.join(&contract.gate_runner.script);
    assert!(
        script_path.exists(),
        "gate runner script should exist: {}",
        script_path.display()
    );
}

#[test]
fn rgc_057_gate_runner_replay_wrapper_exists_on_disk() {
    let contract = parse_contract();
    let root = repo_root();
    let replay_path = root.join(&contract.gate_runner.replay_wrapper);
    assert!(
        replay_path.exists(),
        "gate runner replay wrapper should exist: {}",
        replay_path.display()
    );
}

// ---------- expected_policy_action_for_class coverage ----------

#[test]
fn rgc_057_expected_policy_action_for_class_unknown_returns_unknown() {
    assert_eq!(expected_policy_action_for_class("nonexistent"), "unknown");
}

#[test]
fn rgc_057_expected_policy_action_for_all_classes_is_not_unknown() {
    let contract = parse_contract();
    for class in &contract.required_semantics_classes {
        let action = expected_policy_action_for_class(class);
        assert_ne!(
            action, "unknown",
            "expected_policy_action_for_class should handle {class}"
        );
    }
}

// ---------- operator verification ----------

#[test]
fn rgc_057_operator_verification_entries_are_nonempty() {
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

// ---------- additional edge-case coverage ----------

#[test]
fn rgc_057_contract_pretty_json_serde_roundtrip_preserves_equality() {
    let contract = parse_contract();
    let pretty = serde_json::to_string_pretty(&contract).expect("pretty serialize");
    let recovered: RuntimeSemanticsPackContract =
        serde_json::from_str(&pretty).expect("pretty deserialize");
    assert_eq!(contract, recovered);
}

#[test]
fn rgc_057_vectors_generated_at_utc_is_iso8601_like() {
    let vectors = parse_vectors();
    assert!(
        vectors.generated_at_utc.contains('T'),
        "generated_at_utc should contain 'T' separator: {}",
        vectors.generated_at_utc
    );
    assert!(
        vectors.generated_at_utc.ends_with('Z'),
        "generated_at_utc should end with 'Z': {}",
        vectors.generated_at_utc
    );
    let year_part = &vectors.generated_at_utc[..4];
    assert!(
        year_part.chars().all(|c| c.is_ascii_digit()),
        "first 4 chars should be a year: {}",
        year_part
    );
}

#[test]
fn rgc_057_failure_scenario_exit_codes_are_nonzero() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert_ne!(
            scenario.expected_exit_code, 0,
            "failure scenario {} should have nonzero exit code",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_057_vectors_path_types_match_expected_outcome_pattern() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        // Golden path vectors should expect pass
        if vector.path_type == "golden" {
            assert_eq!(
                vector.expected_outcome, "expect_pass",
                "golden path_type vector {} should expect_pass",
                vector.scenario_id
            );
        }
        // Verify all minimal_repro_pointer values start with a path-like prefix
        assert!(
            vector.minimal_repro_pointer.contains('/')
                || vector.minimal_repro_pointer.contains('.'),
            "minimal_repro_pointer for {} should look like a path: {}",
            vector.scenario_id,
            vector.minimal_repro_pointer
        );
    }
}

// ---------- enrichment: struct clone/debug ----------

#[test]
fn rgc_057_contract_clone_equals_original() {
    let contract = parse_contract();
    let cloned = contract.clone();
    assert_eq!(contract, cloned);
}

#[test]
fn rgc_057_vectors_clone_equals_original() {
    let vectors = parse_vectors();
    let cloned = vectors.clone();
    assert_eq!(vectors, cloned);
}

#[test]
fn rgc_057_contract_debug_is_nonempty() {
    let contract = parse_contract();
    let debug = format!("{contract:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("RuntimeSemanticsPackContract"));
}

#[test]
fn rgc_057_vectors_debug_is_nonempty() {
    let vectors = parse_vectors();
    let debug = format!("{vectors:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("RuntimeSemanticsVectors"));
}

// ---------- enrichment: individual struct serde ----------

#[test]
fn rgc_057_failure_scenario_serde_roundtrip() {
    let scenario = FailureScenario {
        scenario_id: "test_scenario".to_string(),
        path_type: "failure".to_string(),
        command_template: "cargo test -- test_scenario".to_string(),
        expected_exit_code: 1,
        expected_error_code: "FE-RGC-057-TEST-0001".to_string(),
        expected_message_fragment: "test failure".to_string(),
    };
    let json = serde_json::to_string(&scenario).expect("serialize");
    let recovered: FailureScenario = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(scenario, recovered);
}

#[test]
fn rgc_057_gate_runner_serde_roundtrip() {
    let gate_runner = GateRunner {
        script: "scripts/run.sh".to_string(),
        replay_wrapper: "scripts/replay.sh".to_string(),
        strict_mode: "rch_only_no_local_fallback".to_string(),
        manifest_schema_version: "v1".to_string(),
    };
    let json = serde_json::to_string(&gate_runner).expect("serialize");
    let recovered: GateRunner = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(gate_runner, recovered);
}

#[test]
fn rgc_057_runtime_semantics_vector_serde_roundtrip() {
    let vector = RuntimeSemanticsVector {
        scenario_id: "test_scenario".to_string(),
        semantics_class: "arithmetic_control_flow".to_string(),
        severity: "critical".to_string(),
        path_type: "golden".to_string(),
        deterministic_seed: 42,
        expected_outcome: "expect_pass".to_string(),
        expected_policy_action: "execute".to_string(),
        command_template: "cargo test".to_string(),
        minimal_repro_pointer: "tests/foo.rs".to_string(),
        requires_replay: true,
    };
    let json = serde_json::to_string(&vector).expect("serialize");
    let recovered: RuntimeSemanticsVector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(vector, recovered);
}

// ---------- enrichment: JSON field name stability ----------

#[test]
fn rgc_057_contract_json_has_expected_top_level_fields() {
    let val: serde_json::Value = serde_json::from_str(PACK_JSON).expect("pack json must parse");
    let obj = val.as_object().expect("root must be object");
    for field in [
        "schema_version",
        "contract_version",
        "bead_id",
        "policy_id",
        "required_semantics_classes",
        "required_log_keys",
        "required_artifacts",
        "test_vectors_source",
        "failure_scenarios",
        "gate_runner",
        "operator_verification",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn rgc_057_vectors_json_has_expected_top_level_fields() {
    let val: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("vectors json must parse");
    let obj = val.as_object().expect("root must be object");
    for field in [
        "schema_version",
        "contract_version",
        "bead_id",
        "generated_by",
        "generated_at_utc",
        "vectors",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn rgc_057_each_vector_json_has_expected_fields() {
    let val: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("vectors json must parse");
    let vectors_arr = val["vectors"].as_array().expect("vectors must be array");
    for vector in vectors_arr {
        let obj = vector.as_object().expect("vector must be object");
        for field in [
            "scenario_id",
            "semantics_class",
            "severity",
            "path_type",
            "deterministic_seed",
            "expected_outcome",
            "expected_policy_action",
            "command_template",
            "minimal_repro_pointer",
            "requires_replay",
        ] {
            assert!(
                obj.contains_key(field),
                "missing field {field} in vector {}",
                vector["scenario_id"]
            );
        }
    }
}

// ---------- enrichment: cross-validation ----------

#[test]
fn rgc_057_contract_failure_scenario_error_codes_are_unique() {
    let contract = parse_contract();
    let mut codes = BTreeSet::new();
    for scenario in &contract.failure_scenarios {
        assert!(
            codes.insert(scenario.expected_error_code.as_str()),
            "duplicate error code: {}",
            scenario.expected_error_code
        );
    }
}

#[test]
fn rgc_057_contract_failure_scenario_message_fragments_are_nonempty() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert!(
            !scenario.expected_message_fragment.trim().is_empty(),
            "scenario {} must have non-empty message fragment",
            scenario.scenario_id
        );
    }
}

#[test]
fn rgc_057_vectors_deterministic_seeds_are_unique() {
    let vectors = parse_vectors();
    let mut seeds = BTreeSet::new();
    for vector in &vectors.vectors {
        assert!(
            seeds.insert(vector.deterministic_seed),
            "duplicate seed: {}",
            vector.deterministic_seed
        );
    }
}

#[test]
fn rgc_057_contract_schema_version_follows_naming_convention() {
    let contract = parse_contract();
    assert!(
        contract.schema_version.starts_with("franken-engine."),
        "schema_version should start with 'franken-engine.': {}",
        contract.schema_version
    );
    assert!(
        contract.schema_version.ends_with(".v1"),
        "schema_version should end with version suffix: {}",
        contract.schema_version
    );
}

#[test]
fn rgc_057_vectors_schema_version_follows_naming_convention() {
    let vectors = parse_vectors();
    assert!(
        vectors.schema_version.starts_with("franken-engine."),
        "schema_version should start with 'franken-engine.': {}",
        vectors.schema_version
    );
    assert!(
        vectors.schema_version.ends_with(".v1"),
        "schema_version should end with version suffix: {}",
        vectors.schema_version
    );
}
