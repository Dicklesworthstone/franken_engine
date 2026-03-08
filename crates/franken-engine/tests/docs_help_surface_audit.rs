#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-docs-help-surface-audit.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_docs_help_surface_audit_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DocsHelpSurfaceAuditContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    audited_inputs: Vec<String>,
    supported_top_level_commands: Vec<String>,
    required_help_fragments: Vec<String>,
    banned_help_fragments: Vec<String>,
    required_readme_fragments: Vec<String>,
    banned_readme_fragments: Vec<String>,
    audited_claims: Vec<AuditedClaim>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct AuditedClaim {
    claim_id: String,
    surface: String,
    status: String,
    rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GateRunner {
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

fn parse_contract() -> DocsHelpSurfaceAuditContract {
    serde_json::from_str(CONTRACT_JSON).expect("docs/help audit contract must parse")
}

fn read_gate_script() -> String {
    let path = repo_root().join("scripts/run_rgc_docs_help_surface_audit.sh");
    read_to_string(&path)
}

fn actual_top_level_commands_from_help(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed == "frankenctl usage:" || !trimmed.starts_with("frankenctl ") {
                return None;
            }

            trimmed
                .strip_prefix("frankenctl ")
                .and_then(|rest| rest.split_whitespace().next())
                .map(str::to_owned)
        })
        .collect()
}

#[test]
fn rgc_911a_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_DOCS_HELP_SURFACE_AUDIT_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Docs and Help Surface Audit V1",
        "## Scope",
        "## Contract Version",
        "## Authoritative CLI Surface",
        "## Audited Claim Classes",
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
fn rgc_911a_contract_is_versioned_and_classifies_audited_claims() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.10.11.1");
    assert_eq!(contract.policy_id, "policy-rgc-docs-help-surface-audit-v1");

    let audited_inputs: BTreeSet<_> = contract.audited_inputs.iter().map(String::as_str).collect();
    for input in [
        "README.md",
        "crates/franken-engine/src/bin/frankenctl.rs",
        "crates/franken-engine/tests/frankenctl_cli.rs",
    ] {
        assert!(
            audited_inputs.contains(input),
            "missing audited input {input}"
        );
    }

    let statuses: BTreeSet<_> = contract
        .audited_claims
        .iter()
        .map(|claim| claim.status.as_str())
        .collect();
    for status in &statuses {
        assert!(
            matches!(*status, "accurate" | "narrowed" | "implemented"),
            "unexpected claim status {status}"
        );
    }
    assert!(
        contract
            .audited_claims
            .iter()
            .any(|claim| claim.status == "accurate"),
        "expected at least one accurate claim classification"
    );
    assert!(
        contract
            .audited_claims
            .iter()
            .any(|claim| claim.status == "narrowed"),
        "expected at least one narrowed claim classification"
    );

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
        "docs_help_surface_report.json",
        "frankenctl_help.txt",
        "step_logs/step_*.log",
    ] {
        assert!(
            required_artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_docs_help_surface_audit.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_docs_help_surface_audit_replay.sh"
    );
    assert_eq!(contract.gate_runner.strict_mode, "ci");
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-docs-help-surface-audit.run-manifest.v1"
    );

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|command| command.contains("docs_help_surface_audit")),
        "operator verification should reference the docs/help audit gate"
    );
}

#[test]
fn rgc_911a_readme_matches_contract_fragments() {
    let contract = parse_contract();
    let path = repo_root().join("README.md");
    let readme = read_to_string(&path);

    for fragment in &contract.required_readme_fragments {
        assert!(
            readme.contains(fragment),
            "missing README fragment in {}: {fragment}",
            path.display()
        );
    }

    for fragment in &contract.banned_readme_fragments {
        assert!(
            !readme.contains(fragment),
            "README still contains unsupported command fragment in {}: {fragment}",
            path.display()
        );
    }
}

#[test]
fn rgc_911a_help_output_matches_contract() {
    let contract = parse_contract();
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("--help")
        .output()
        .expect("frankenctl --help should execute");

    assert!(
        output.status.success(),
        "help failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid utf8");
    for fragment in &contract.required_help_fragments {
        assert!(
            stdout.contains(fragment),
            "help output missing required fragment: {fragment}"
        );
    }

    for fragment in &contract.banned_help_fragments {
        assert!(
            !stdout.contains(fragment),
            "help output unexpectedly contains unsupported fragment: {fragment}"
        );
    }

    let actual_commands = actual_top_level_commands_from_help(&stdout);
    let expected_commands: BTreeSet<_> = contract
        .supported_top_level_commands
        .iter()
        .cloned()
        .collect();
    assert_eq!(actual_commands, expected_commands);
}

#[test]
fn rgc_911a_gate_script_captures_live_help_output() {
    let script = read_gate_script();

    assert!(
        script.contains("cargo run -p frankenengine-engine --bin frankenctl -- --help"),
        "gate script must capture actual frankenctl help output"
    );
    assert!(
        script.contains("capture_actual_help_output"),
        "gate script should use a dedicated actual-help capture path"
    );
    assert!(
        !script.contains(
            "jq -r '.required_help_fragments[]' \"$contract_json\" >\"$help_output_path\""
        ),
        "gate script must not synthesize help output from contract fragments"
    );
}

#[test]
fn rgc_911a_gate_script_fails_closed_on_help_validation_and_uses_isolated_target_dir() {
    let script = read_gate_script();

    assert!(
        script.contains("validate_help_against_contract || main_exit=$?"),
        "gate script must fail when actual help output diverges from the contract"
    );
    assert!(
        !script.contains("validate_help_against_contract || true"),
        "gate script must not ignore help-validation failures"
    );
    assert!(
        script.contains("/tmp/rch_target_rgc_docs_help_surface_audit_"),
        "gate script should use an isolated remote target dir"
    );
    assert!(
        !script.contains("/data/projects/franken_engine/target_rch_rgc_docs_help_surface_audit"),
        "gate script must not reuse a fixed repo-local remote target dir"
    );
}

// ── Contract field-level assertions ──────────────────────────────────

#[test]
fn contract_schema_version_matches_constant() {
    let contract = parse_contract();
    assert_eq!(
        contract.schema_version, CONTRACT_SCHEMA_VERSION,
        "schema_version must match the constant"
    );
}

#[test]
fn contract_version_is_1_0_0() {
    let contract = parse_contract();
    assert_eq!(contract.contract_version, "1.0.0");
}

#[test]
fn contract_bead_id_is_stable() {
    let contract = parse_contract();
    assert_eq!(contract.bead_id, "bd-1lsy.10.11.1");
}

#[test]
fn contract_policy_id_is_stable() {
    let contract = parse_contract();
    assert_eq!(contract.policy_id, "policy-rgc-docs-help-surface-audit-v1");
}

#[test]
fn contract_json_include_str_is_valid_json() {
    let value: serde_json::Value =
        serde_json::from_str(CONTRACT_JSON).expect("CONTRACT_JSON must be valid JSON");
    assert!(value.is_object(), "top-level JSON must be an object");
}

// ── actual_top_level_commands_from_help unit tests ───────────────────

#[test]
fn commands_from_help_empty_string_returns_empty_set() {
    let result = actual_top_level_commands_from_help("");
    assert!(result.is_empty());
}

#[test]
fn commands_from_help_header_only_returns_empty_set() {
    let result = actual_top_level_commands_from_help("frankenctl usage:\n");
    assert!(result.is_empty());
}

#[test]
fn commands_from_help_one_valid_command_line() {
    let input = "frankenctl usage:\n  frankenctl compile --input <src>\n";
    let result = actual_top_level_commands_from_help(input);
    assert_eq!(result.len(), 1);
    assert!(result.contains("compile"));
}

#[test]
fn commands_from_help_multiple_command_lines() {
    let input = "frankenctl usage:\n  frankenctl compile --input <src>\n  frankenctl run --input <src>\n  frankenctl doctor --input <in>\n";
    let result = actual_top_level_commands_from_help(input);
    assert_eq!(result.len(), 3);
    assert!(result.contains("compile"));
    assert!(result.contains("run"));
    assert!(result.contains("doctor"));
}

#[test]
fn commands_from_help_ignores_non_frankenctl_lines() {
    let input = "Some random preamble\nfrankenctl usage:\n  frankenctl compile --input <src>\n  Not a frankenctl line\n  Also irrelevant\n  frankenctl verify compile-artifact\n";
    let result = actual_top_level_commands_from_help(input);
    assert_eq!(result.len(), 2);
    assert!(result.contains("compile"));
    assert!(result.contains("verify"));
}

// ── Audited claims structural assertions ────────────────────────────

#[test]
fn audited_claims_all_have_non_empty_claim_id() {
    let contract = parse_contract();
    for claim in &contract.audited_claims {
        assert!(!claim.claim_id.is_empty(), "claim_id must not be empty");
    }
}

#[test]
fn audited_claims_all_have_non_empty_surface() {
    let contract = parse_contract();
    for claim in &contract.audited_claims {
        assert!(
            !claim.surface.is_empty(),
            "surface must not be empty for claim {}",
            claim.claim_id
        );
    }
}

#[test]
fn audited_claims_all_have_non_empty_rationale() {
    let contract = parse_contract();
    for claim in &contract.audited_claims {
        assert!(
            !claim.rationale.is_empty(),
            "rationale must not be empty for claim {}",
            claim.claim_id
        );
    }
}

#[test]
fn audited_claims_count_is_at_least_expected_minimum() {
    let contract = parse_contract();
    assert!(
        contract.audited_claims.len() >= 5,
        "expected at least 5 audited claims, got {}",
        contract.audited_claims.len()
    );
}

#[test]
fn audited_claims_have_unique_claim_ids() {
    let contract = parse_contract();
    let ids: BTreeSet<_> = contract
        .audited_claims
        .iter()
        .map(|c| c.claim_id.as_str())
        .collect();
    assert_eq!(
        ids.len(),
        contract.audited_claims.len(),
        "all claim_ids must be unique"
    );
}

// ── Gate runner field assertions ─────────────────────────────────────

#[test]
fn gate_runner_script_path_is_non_empty() {
    let contract = parse_contract();
    assert!(!contract.gate_runner.script.is_empty());
}

#[test]
fn gate_runner_replay_wrapper_path_is_non_empty() {
    let contract = parse_contract();
    assert!(!contract.gate_runner.replay_wrapper.is_empty());
}

#[test]
fn gate_runner_strict_mode_is_ci() {
    let contract = parse_contract();
    assert_eq!(contract.gate_runner.strict_mode, "ci");
}

#[test]
fn gate_runner_manifest_schema_version_is_non_empty() {
    let contract = parse_contract();
    assert!(!contract.gate_runner.manifest_schema_version.is_empty());
}

// ── Required artifacts assertions ───────────────────────────────────

#[test]
fn required_artifacts_include_run_manifest_json() {
    let contract = parse_contract();
    assert!(
        contract
            .required_artifacts
            .contains(&"run_manifest.json".to_owned()),
        "required_artifacts must include run_manifest.json"
    );
}

#[test]
fn required_artifacts_include_events_jsonl() {
    let contract = parse_contract();
    assert!(
        contract
            .required_artifacts
            .contains(&"events.jsonl".to_owned()),
        "required_artifacts must include events.jsonl"
    );
}

#[test]
fn required_artifacts_include_commands_txt() {
    let contract = parse_contract();
    assert!(
        contract
            .required_artifacts
            .contains(&"commands.txt".to_owned()),
        "required_artifacts must include commands.txt"
    );
}

// ── Required log keys assertions ────────────────────────────────────

#[test]
fn required_log_keys_include_trace_id() {
    let contract = parse_contract();
    assert!(
        contract.required_log_keys.contains(&"trace_id".to_owned()),
        "required_log_keys must include trace_id"
    );
}

#[test]
fn required_log_keys_include_decision_id() {
    let contract = parse_contract();
    assert!(
        contract
            .required_log_keys
            .contains(&"decision_id".to_owned()),
        "required_log_keys must include decision_id"
    );
}

// ── Operator verification assertions ────────────────────────────────

#[test]
fn operator_verification_commands_are_non_empty() {
    let contract = parse_contract();
    assert!(
        !contract.operator_verification.is_empty(),
        "operator_verification must not be empty"
    );
}

// ── Top-level command / fragment list assertions ────────────────────

#[test]
fn supported_top_level_commands_is_non_empty() {
    let contract = parse_contract();
    assert!(
        !contract.supported_top_level_commands.is_empty(),
        "supported_top_level_commands must not be empty"
    );
}

#[test]
fn required_help_fragments_is_non_empty() {
    let contract = parse_contract();
    assert!(
        !contract.required_help_fragments.is_empty(),
        "required_help_fragments must not be empty"
    );
}

#[test]
fn banned_help_fragments_is_non_empty() {
    let contract = parse_contract();
    assert!(
        !contract.banned_help_fragments.is_empty(),
        "banned_help_fragments must not be empty"
    );
}

#[test]
fn required_readme_fragments_is_non_empty() {
    let contract = parse_contract();
    assert!(
        !contract.required_readme_fragments.is_empty(),
        "required_readme_fragments must not be empty"
    );
}

#[test]
fn banned_readme_fragments_is_non_empty() {
    let contract = parse_contract();
    assert!(
        !contract.banned_readme_fragments.is_empty(),
        "banned_readme_fragments must not be empty"
    );
}
