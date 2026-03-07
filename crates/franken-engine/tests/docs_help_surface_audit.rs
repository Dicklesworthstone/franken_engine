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
