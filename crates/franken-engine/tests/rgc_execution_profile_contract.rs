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

use serde::{Deserialize, Serialize};
use serde_json::Value;

const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_execution_profile_contract_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExecutionProfileContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    audited_inputs: Vec<String>,
    required_readme_fragments: Vec<String>,
    banned_readme_fragments: Vec<String>,
    required_migration_fragments: Vec<String>,
    source_fragment_checks: Vec<SourceFragmentCheck>,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SourceFragmentCheck {
    path: String,
    fragment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> ExecutionProfileContract {
    serde_json::from_str(CONTRACT_JSON).expect("execution profile contract must parse")
}

#[test]
fn contract_parses_with_expected_schema_version() {
    let contract = parse_contract();
    assert_eq!(
        contract.schema_version,
        "franken-engine.rgc-execution-profile-contract.v1"
    );
}

#[test]
fn contract_version_is_semver() {
    let contract = parse_contract();
    let parts: Vec<&str> = contract.contract_version.split('.').collect();
    assert_eq!(parts.len(), 3, "contract_version must be semver");
    for part in &parts {
        assert!(
            part.parse::<u32>().is_ok(),
            "contract_version segment must be numeric: {}",
            part
        );
    }
}

#[test]
fn bead_id_and_policy_id_are_nonempty() {
    let contract = parse_contract();
    assert!(
        contract.bead_id.starts_with("bd-"),
        "bead_id must start with bd-: {}",
        contract.bead_id
    );
    assert!(
        contract.policy_id.starts_with("policy-"),
        "policy_id must start with policy-: {}",
        contract.policy_id
    );
}

#[test]
fn audited_inputs_exist_in_repo() {
    let contract = parse_contract();
    let root = repo_root();
    for input in &contract.audited_inputs {
        let path = root.join(input);
        assert!(
            path.exists(),
            "audited input must exist: {}",
            path.display()
        );
    }
}

#[test]
fn audited_inputs_are_repo_relative_and_safe() {
    let contract = parse_contract();
    for input in &contract.audited_inputs {
        assert!(
            !input.starts_with('/'),
            "audited input must be repo-relative: {input}"
        );
        assert!(
            !input.contains(".."),
            "audited input must not traverse upward: {input}"
        );
    }
}

#[test]
fn audited_inputs_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for input in &contract.audited_inputs {
        assert!(
            seen.insert(input.clone()),
            "duplicate audited input: {input}"
        );
    }
}

#[test]
fn required_readme_fragments_are_present_in_readme() {
    let contract = parse_contract();
    let readme =
        fs::read_to_string(repo_root().join("README.md")).expect("README.md must be readable");
    for fragment in &contract.required_readme_fragments {
        assert!(
            readme.contains(fragment),
            "README.md must contain required fragment: {fragment}"
        );
    }
}

#[test]
fn banned_readme_fragments_are_absent_from_readme() {
    let contract = parse_contract();
    let readme =
        fs::read_to_string(repo_root().join("README.md")).expect("README.md must be readable");
    for fragment in &contract.banned_readme_fragments {
        assert!(
            !readme.contains(fragment),
            "README.md must NOT contain banned fragment: {fragment}"
        );
    }
}

#[test]
fn required_migration_fragments_are_present_in_migration_doc() {
    let contract = parse_contract();
    let migration_doc =
        fs::read_to_string(repo_root().join("docs/RGC_EXECUTION_PROFILE_CONTRACT_MIGRATION_V1.md"))
            .expect("migration doc must be readable");
    for fragment in &contract.required_migration_fragments {
        assert!(
            migration_doc.contains(fragment),
            "migration doc must contain required fragment: {fragment}"
        );
    }
}

#[test]
fn source_fragment_checks_find_fragments_in_source_files() {
    let contract = parse_contract();
    let root = repo_root();
    for check in &contract.source_fragment_checks {
        let path = root.join(&check.path);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        assert!(
            source.contains(&check.fragment),
            "source file {} must contain fragment: {}",
            check.path,
            check.fragment
        );
    }
}

#[test]
fn source_fragment_check_paths_exist() {
    let contract = parse_contract();
    let root = repo_root();
    for check in &contract.source_fragment_checks {
        let path = root.join(&check.path);
        assert!(
            path.exists(),
            "source fragment check path must exist: {}",
            path.display()
        );
    }
}

#[test]
fn source_fragment_check_paths_are_repo_relative() {
    let contract = parse_contract();
    for check in &contract.source_fragment_checks {
        assert!(
            !check.path.starts_with('/'),
            "source fragment path must be repo-relative: {}",
            check.path
        );
        assert!(
            !check.path.contains(".."),
            "source fragment path must not traverse upward: {}",
            check.path
        );
    }
}

#[test]
fn required_artifacts_are_nonempty_and_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for artifact in &contract.required_artifacts {
        assert!(
            !artifact.trim().is_empty(),
            "required artifact must be non-empty"
        );
        assert!(
            seen.insert(artifact.clone()),
            "duplicate required artifact: {artifact}"
        );
    }
}

#[test]
fn required_artifacts_include_standard_rgc_set() {
    let contract = parse_contract();
    let artifacts: BTreeSet<&str> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for standard in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(
            artifacts.contains(standard),
            "missing standard RGC artifact: {standard}"
        );
    }
}

#[test]
fn gate_runner_scripts_exist_in_repo() {
    let contract = parse_contract();
    let root = repo_root();
    let script_path = root.join(&contract.gate_runner.script);
    assert!(
        script_path.exists(),
        "gate script must exist: {}",
        script_path.display()
    );
    let replay_path = root.join(&contract.gate_runner.replay_wrapper);
    assert!(
        replay_path.exists(),
        "replay script must exist: {}",
        replay_path.display()
    );
}

#[test]
fn gate_runner_strict_mode_is_ci() {
    let contract = parse_contract();
    assert_eq!(
        contract.gate_runner.strict_mode, "ci",
        "gate runner strict mode must be 'ci'"
    );
}

#[test]
fn operator_verification_commands_are_nonempty() {
    let contract = parse_contract();
    assert!(
        !contract.operator_verification.is_empty(),
        "operator_verification must not be empty"
    );
    for cmd in &contract.operator_verification {
        assert!(
            !cmd.trim().is_empty(),
            "operator verification command must not be empty"
        );
    }
}

#[test]
fn operator_verification_includes_gate_and_replay() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("execution_profile_contract")),
        "operator verification must reference execution_profile_contract"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("replay")),
        "operator verification must include a replay command"
    );
}

#[test]
fn top_level_keys_match_expected_schema() {
    let raw: Value = serde_json::from_str(CONTRACT_JSON).expect("must parse as Value");
    let obj = raw.as_object().expect("must be a JSON object");
    let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = BTreeSet::from([
        "schema_version",
        "contract_version",
        "bead_id",
        "policy_id",
        "audited_inputs",
        "required_readme_fragments",
        "banned_readme_fragments",
        "required_migration_fragments",
        "source_fragment_checks",
        "required_artifacts",
        "gate_runner",
        "operator_verification",
    ]);
    assert_eq!(keys, expected);
}

#[test]
fn banned_and_required_readme_fragments_are_disjoint() {
    let contract = parse_contract();
    let required: BTreeSet<&str> = contract
        .required_readme_fragments
        .iter()
        .map(String::as_str)
        .collect();
    let banned: BTreeSet<&str> = contract
        .banned_readme_fragments
        .iter()
        .map(String::as_str)
        .collect();
    let overlap: Vec<&&str> = required.intersection(&banned).collect();
    assert!(
        overlap.is_empty(),
        "required and banned readme fragments must be disjoint: {:?}",
        overlap
    );
}

#[test]
fn deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Enrichment: serde, structure, and field-level invariants
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_preserves_contract() {
    let original = parse_contract();
    let serialized = serde_json::to_string(&original).expect("must serialize");
    let deserialized: ExecutionProfileContract =
        serde_json::from_str(&serialized).expect("must deserialize roundtrip");
    assert_eq!(original, deserialized);
}

#[test]
fn gate_runner_manifest_schema_version_is_nonempty_and_prefixed() {
    let contract = parse_contract();
    let version = &contract.gate_runner.manifest_schema_version;
    assert!(
        !version.trim().is_empty(),
        "manifest_schema_version must be non-empty"
    );
    assert!(
        version.starts_with("frx") || version.starts_with("franken-engine"),
        "manifest_schema_version must start with 'frx' or 'franken-engine': {version}"
    );
}

#[test]
fn source_fragment_checks_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for check in &contract.source_fragment_checks {
        let key = format!("{}::{}", check.path, check.fragment);
        assert!(
            seen.insert(key.clone()),
            "duplicate source fragment check: {key}"
        );
    }
}

#[test]
fn source_fragment_check_fragments_are_nonempty() {
    let contract = parse_contract();
    for check in &contract.source_fragment_checks {
        assert!(
            !check.fragment.trim().is_empty(),
            "source fragment check fragment must be non-empty for path: {}",
            check.path
        );
    }
}

#[test]
fn required_readme_fragments_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for fragment in &contract.required_readme_fragments {
        assert!(
            seen.insert(fragment.clone()),
            "duplicate required readme fragment: {fragment}"
        );
    }
}

#[test]
fn banned_readme_fragments_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for fragment in &contract.banned_readme_fragments {
        assert!(
            seen.insert(fragment.clone()),
            "duplicate banned readme fragment: {fragment}"
        );
    }
}

#[test]
fn required_migration_fragments_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for fragment in &contract.required_migration_fragments {
        assert!(
            seen.insert(fragment.clone()),
            "duplicate required migration fragment: {fragment}"
        );
    }
}

#[test]
fn audited_inputs_reference_known_file_extensions() {
    let contract = parse_contract();
    let allowed_extensions = [".rs", ".md", ".toml", ".json", ".sh"];
    for input in &contract.audited_inputs {
        assert!(
            allowed_extensions.iter().any(|ext| input.ends_with(ext)),
            "audited input must have a recognized extension (.rs, .md, .toml, .json, .sh): {input}"
        );
    }
}

#[test]
fn clone_and_debug_derive_verification() {
    let contract = parse_contract();
    let cloned = contract.clone();
    assert_eq!(contract, cloned);
    let debug_repr = format!("{:?}", contract);
    assert!(
        debug_repr.contains("ExecutionProfileContract"),
        "Debug output must contain struct name"
    );
    let gate_debug = format!("{:?}", contract.gate_runner);
    assert!(
        gate_debug.contains("GateRunner"),
        "GateRunner Debug output must contain struct name"
    );
    if let Some(first_check) = contract.source_fragment_checks.first() {
        let check_debug = format!("{:?}", first_check);
        assert!(
            check_debug.contains("SourceFragmentCheck"),
            "SourceFragmentCheck Debug output must contain struct name"
        );
    }
}

#[test]
fn contract_has_minimum_audited_inputs() {
    let contract = parse_contract();
    assert!(
        contract.audited_inputs.len() >= 3,
        "contract must have at least 3 audited inputs, found {}",
        contract.audited_inputs.len()
    );
}

#[test]
fn contract_has_minimum_source_fragment_checks() {
    let contract = parse_contract();
    assert!(
        contract.source_fragment_checks.len() >= 2,
        "contract must have at least 2 source fragment checks, found {}",
        contract.source_fragment_checks.len()
    );
}

#[test]
fn gate_runner_paths_are_repo_relative() {
    let contract = parse_contract();
    for path_str in [
        &contract.gate_runner.script,
        &contract.gate_runner.replay_wrapper,
    ] {
        assert!(
            !path_str.starts_with('/'),
            "gate runner path must be repo-relative (no leading /): {path_str}"
        );
        assert!(
            !path_str.contains(".."),
            "gate runner path must not traverse upward: {path_str}"
        );
    }
}
