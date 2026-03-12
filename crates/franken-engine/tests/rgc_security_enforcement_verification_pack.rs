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
use std::path::PathBuf;

use serde::Deserialize;

const PACK_SCHEMA_VERSION: &str = "franken-engine.rgc-security-enforcement-verification-pack.v1";
const VECTORS_SCHEMA_VERSION: &str =
    "franken-engine.rgc-security-enforcement-verification-vectors.v1";
const PACK_JSON: &str =
    include_str!("../../../docs/rgc_security_enforcement_verification_pack_v1.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/rgc_security_enforcement_verification_vectors_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SecurityVerificationPackContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_attack_classes: Vec<String>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    test_vectors_source: String,
    failure_scenarios: Vec<FailureScenario>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FailureScenario {
    scenario_id: String,
    path_type: String,
    command_template: String,
    expected_exit_code: u8,
    expected_error_code: String,
    expected_message_fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SecurityVerificationVectors {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    vectors: Vec<SecurityScenarioVector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SecurityScenarioVector {
    scenario_id: String,
    attack_class: String,
    severity: String,
    path_type: String,
    deterministic_seed: u64,
    expected_policy_action: String,
    expected_containment_state: String,
    expected_outcome: String,
    command_template: String,
    requires_replay: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> SecurityVerificationPackContract {
    serde_json::from_str(PACK_JSON).expect("security verification pack contract must parse")
}

fn parse_vectors() -> SecurityVerificationVectors {
    serde_json::from_str(VECTORS_JSON).expect("security verification vectors must parse")
}

fn read_gate_script() -> String {
    let path = repo_root().join("scripts/run_rgc_security_enforcement_verification_pack.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

#[test]
fn rgc_059_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# RGC Security Enforcement Verification Pack V1",
        "## Scope",
        "## Contract Version",
        "## Required Attack Classes",
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
fn rgc_059_contract_is_versioned_and_replay_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, PACK_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.11.9");
    assert_eq!(
        contract.policy_id,
        "policy-rgc-security-enforcement-verification-pack-v1"
    );

    let attack_classes: BTreeSet<&str> = contract
        .required_attack_classes
        .iter()
        .map(String::as_str)
        .collect();
    for class_name in [
        "capability_denial",
        "ifc_declassification",
        "containment_escalation",
    ] {
        assert!(
            attack_classes.contains(class_name),
            "missing required attack class {class_name}"
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
        "attack_class",
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
        "step_logs/step_*.log",
        "security_verification_report.json",
    ] {
        assert!(
            artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_security_enforcement_verification_pack.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh"
    );
    assert_eq!(
        contract.gate_runner.strict_mode,
        "rch_only_no_local_fallback"
    );
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-security-enforcement-verification-pack.run-manifest.v1"
    );

    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "missing_vectors_file"
            && scenario.path_type == "failure"
            && scenario.expected_exit_code == 1
            && scenario.expected_error_code == "FE-RGC-059-VECTORS-0001"
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_json"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-059-VECTORS-0002"
    }));
    assert!(contract.failure_scenarios.iter().any(|scenario| {
        scenario.scenario_id == "invalid_vectors_semantics"
            && scenario.path_type == "failure"
            && scenario.expected_error_code == "FE-RGC-059-VECTORS-0003"
    }));

    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("$PWD/target_rch_rgc_security_enforcement_verification_pack_verify")
        }),
        "operator verification should document a repo-local target dir example"
    );
    assert!(
        !contract.operator_verification.iter().any(|entry| {
            entry.contains("/tmp/rch_target_rgc_security_enforcement_verification_pack")
        }),
        "operator verification must not point operators back to /tmp-backed targets"
    );
    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("run_rgc_security_enforcement_verification_pack.sh ci")
        })
    );
    assert!(
        contract.operator_verification.iter().any(|entry| {
            entry.contains("rgc_security_enforcement_verification_pack_replay.sh")
        })
    );
}

#[test]
fn rgc_059_vectors_are_deterministic_unique_and_complete() {
    let vectors = parse_vectors();
    let contract = parse_contract();

    assert_eq!(vectors.schema_version, VECTORS_SCHEMA_VERSION);
    assert_eq!(vectors.contract_version, "1.0.0");
    assert_eq!(vectors.bead_id, "bd-1lsy.11.9");
    assert_eq!(vectors.generated_by, "bd-1lsy.11.9");
    assert!(vectors.generated_at_utc.ends_with('Z'));
    assert!(
        vectors.vectors.len() >= 3,
        "expected at least three vectors"
    );

    let mut scenario_ids = BTreeSet::new();
    let mut seeds = BTreeSet::new();
    let mut attack_classes_seen = BTreeSet::new();

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
            ["golden", "failure"].contains(&vector.path_type.as_str()),
            "invalid path_type {}",
            vector.path_type
        );
        assert!(
            ["critical", "high", "medium", "low"].contains(&vector.severity.as_str()),
            "invalid severity {}",
            vector.severity
        );
        assert!(
            ["deny", "quarantine", "terminate", "allow"]
                .contains(&vector.expected_policy_action.as_str()),
            "invalid expected_policy_action {}",
            vector.expected_policy_action
        );
        assert!(
            ["running", "quarantined", "terminated"]
                .contains(&vector.expected_containment_state.as_str()),
            "invalid expected_containment_state {}",
            vector.expected_containment_state
        );
        assert_eq!(vector.expected_outcome, "pass");
        assert!(vector.requires_replay, "all vectors must require replay");
        assert!(
            !vector.command_template.trim().is_empty(),
            "command_template must not be empty"
        );

        attack_classes_seen.insert(vector.attack_class.as_str());
    }

    let required_attack_classes: BTreeSet<&str> = contract
        .required_attack_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(attack_classes_seen, required_attack_classes);
}

#[test]
fn rgc_059_contract_and_vectors_files_exist_at_declared_paths() {
    let root = repo_root();
    for path in [
        "docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md",
        "docs/rgc_security_enforcement_verification_pack_v1.json",
        "docs/rgc_security_enforcement_verification_vectors_v1.json",
        "scripts/run_rgc_security_enforcement_verification_pack.sh",
        "scripts/e2e/rgc_security_enforcement_verification_pack_replay.sh",
    ] {
        let full = root.join(path);
        assert!(full.exists(), "expected path to exist: {}", full.display());
    }
}

#[test]
fn rgc_059_gate_script_uses_repo_local_target_dir() {
    let script = read_gate_script();

    assert!(
        script.contains("${root_dir}/target_rch_rgc_security_enforcement_verification_pack"),
        "gate script should use a repo-local target dir rooted at the workspace"
    );
    assert!(
        !script.contains("/tmp/rch_target_rgc_security_enforcement_verification_pack"),
        "gate script must not route heavy remote builds through /tmp"
    );
    assert!(
        !script.contains("rch exec -q -- env"),
        "gate script should preserve full rch output for fail-closed parsing"
    );
    assert!(
        script.contains("step_logs_dir="),
        "gate script should emit per-step logs under a dedicated step_logs directory"
    );
    assert!(
        script.contains("rch_strip_ansi()"),
        "gate script should strip ANSI escape sequences before parsing rch output"
    );
    assert!(
        script.contains("rch_remote_exit_code()"),
        "gate script should parse remote exit markers explicitly"
    );
    assert!(
        script.contains("rch_reject_artifact_retrieval_failure()"),
        "gate script should reject artifact retrieval failures"
    );
    assert!(
        script.contains("missing-remote-exit-marker"),
        "gate script should fail closed when rch omits the remote exit marker"
    );
    assert!(
        script.contains("rch-artifact-retrieval-failed"),
        "gate script should surface artifact retrieval failures in failed_command"
    );
}

// ---------- parse_contract ----------

#[test]
fn parse_contract_schema_matches_constant() {
    let contract = parse_contract();
    assert_eq!(contract.schema_version, PACK_SCHEMA_VERSION);
}

// ---------- parse_vectors ----------

#[test]
fn parse_vectors_schema_matches_constant() {
    let vectors = parse_vectors();
    assert_eq!(vectors.schema_version, VECTORS_SCHEMA_VERSION);
}

// ---------- contract fields ----------

#[test]
fn contract_failure_scenarios_nonempty() {
    let contract = parse_contract();
    assert!(!contract.failure_scenarios.is_empty());
}

#[test]
fn contract_failure_scenarios_have_unique_ids() {
    let contract = parse_contract();
    let ids: BTreeSet<&str> = contract
        .failure_scenarios
        .iter()
        .map(|s| s.scenario_id.as_str())
        .collect();
    assert_eq!(ids.len(), contract.failure_scenarios.len());
}

#[test]
fn contract_operator_verification_nonempty() {
    let contract = parse_contract();
    assert!(!contract.operator_verification.is_empty());
}

// ---------- vectors fields ----------

#[test]
fn vectors_bead_id_matches_contract() {
    let contract = parse_contract();
    let vectors = parse_vectors();
    assert_eq!(vectors.bead_id, contract.bead_id);
}

#[test]
fn vectors_have_unique_scenario_ids() {
    let vectors = parse_vectors();
    let ids: BTreeSet<&str> = vectors
        .vectors
        .iter()
        .map(|v| v.scenario_id.as_str())
        .collect();
    assert_eq!(ids.len(), vectors.vectors.len());
}

#[test]
fn vectors_have_unique_seeds() {
    let vectors = parse_vectors();
    let seeds: BTreeSet<u64> = vectors
        .vectors
        .iter()
        .map(|v| v.deterministic_seed)
        .collect();
    assert_eq!(seeds.len(), vectors.vectors.len());
}

#[test]
fn contract_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a, b);
}

#[test]
fn vectors_deterministic_double_parse() {
    let a = parse_vectors();
    let b = parse_vectors();
    assert_eq!(a, b);
}

#[test]
fn contract_failure_scenario_error_codes_are_nonempty() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert!(
            !scenario.expected_error_code.trim().is_empty(),
            "scenario {} has empty error_code",
            scenario.scenario_id
        );
    }
}

#[test]
fn contract_has_nonempty_bead_id() {
    let contract = parse_contract();
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn contract_has_nonempty_policy_id() {
    let contract = parse_contract();
    assert!(!contract.policy_id.trim().is_empty());
}

#[test]
fn vectors_have_nonempty_schema_version() {
    let vectors = parse_vectors();
    assert!(!vectors.schema_version.trim().is_empty());
}

#[test]
fn contract_schema_version_matches_constant() {
    let contract = parse_contract();
    assert_eq!(contract.schema_version, PACK_SCHEMA_VERSION);
}

#[test]
fn vectors_schema_version_matches_constant() {
    let vectors = parse_vectors();
    assert_eq!(vectors.schema_version, VECTORS_SCHEMA_VERSION);
}

#[test]
fn contract_failure_scenario_ids_are_unique_and_nonempty() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for scenario in &contract.failure_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(
            seen.insert(&scenario.scenario_id),
            "duplicate scenario_id: {}",
            scenario.scenario_id
        );
    }
}

#[test]
fn contract_debug_is_nonempty() {
    let contract = parse_contract();
    assert!(!format!("{contract:?}").is_empty());
}

#[test]
fn vectors_debug_is_nonempty() {
    let vectors = parse_vectors();
    assert!(!format!("{vectors:?}").is_empty());
}

#[test]
fn contract_has_nonempty_contract_version() {
    let contract = parse_contract();
    assert!(!contract.contract_version.trim().is_empty());
}

#[test]
fn contract_required_log_keys_are_nonempty_strings() {
    let contract = parse_contract();
    for key in &contract.required_log_keys {
        assert!(
            !key.trim().is_empty(),
            "required_log_keys must not contain empty strings"
        );
    }
}

#[test]
fn contract_required_artifacts_are_nonempty_strings() {
    let contract = parse_contract();
    for artifact in &contract.required_artifacts {
        assert!(
            !artifact.trim().is_empty(),
            "required_artifacts must not contain empty strings"
        );
    }
}

#[test]
fn contract_failure_scenario_command_templates_are_nonempty() {
    let contract = parse_contract();
    for scenario in &contract.failure_scenarios {
        assert!(
            !scenario.command_template.trim().is_empty(),
            "scenario {} must have a command_template",
            scenario.scenario_id
        );
    }
}

#[test]
fn vectors_contract_versions_are_aligned() {
    let contract = parse_contract();
    let vectors = parse_vectors();
    assert_eq!(
        contract.contract_version, vectors.contract_version,
        "contract and vectors must share the same contract_version"
    );
}

#[test]
fn contract_required_attack_classes_are_unique() {
    let contract = parse_contract();
    let unique: BTreeSet<&str> = contract
        .required_attack_classes
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        unique.len(),
        contract.required_attack_classes.len(),
        "required_attack_classes must be unique"
    );
}

#[test]
fn contract_gate_runner_fields_are_nonempty() {
    let contract = parse_contract();
    assert!(!contract.gate_runner.script.trim().is_empty());
    assert!(!contract.gate_runner.replay_wrapper.trim().is_empty());
    assert!(!contract.gate_runner.strict_mode.trim().is_empty());
    assert!(
        !contract
            .gate_runner
            .manifest_schema_version
            .trim()
            .is_empty()
    );
}

#[test]
fn vectors_all_command_templates_are_nonempty() {
    let vectors = parse_vectors();
    for vector in &vectors.vectors {
        assert!(
            !vector.command_template.trim().is_empty(),
            "vector {} must have a non-empty command_template",
            vector.scenario_id
        );
    }
}
