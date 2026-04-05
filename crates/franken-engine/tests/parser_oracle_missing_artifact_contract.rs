#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, path::PathBuf};

use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.parser-oracle-missing-artifact-contract.v1";
const CONTRACT_POLICY_ID: &str = "policy-parser-oracle-missing-artifact-contract-v1";
const CONTRACT_JSON: &str =
    include_str!("../../../docs/parser_oracle_missing_artifact_contract_v1.json");

#[derive(Debug, Clone, Deserialize)]
struct ParserOracleMissingArtifactContract {
    schema_version: String,
    bead_id: String,
    policy_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: ContractTrack,
    source_inputs: Vec<String>,
    required_structured_log_fields: Vec<String>,
    generated_artifacts: Vec<String>,
    artifact_contract: ArtifactContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ContractTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct ArtifactContract {
    receipt_path: String,
    covered_artifacts: Vec<String>,
    required_receipt_fields: Vec<String>,
    reason_matrix: Vec<ReasonCodeEntry>,
    rejected_anonymous_backfills: Vec<RejectedBackfill>,
    consumer_fail_closed_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReasonCodeEntry {
    code: String,
    reason_id: String,
    stage: String,
    consumer_action: String,
    allowed_artifact_roles: Vec<String>,
    placeholder_rejected: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RejectedBackfill {
    artifact_path: String,
    signature_type: String,
    signature_value: String,
    classification: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> ParserOracleMissingArtifactContract {
    serde_json::from_str(CONTRACT_JSON).expect("parser oracle missing-artifact contract must parse")
}

fn contract_doc() -> String {
    let path = repo_root().join("docs/PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_V1.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn readme() -> String {
    let path = repo_root().join("README.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn gate_doc() -> String {
    let path = repo_root().join("docs/PARSER_ORACLE_GATE.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn gate_script() -> String {
    let path = repo_root().join("scripts/run_parser_oracle_gate.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn validation_script() -> String {
    let path = repo_root().join("scripts/run_parser_oracle_missing_artifact_contract.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn replay_script() -> String {
    let path = repo_root().join("scripts/e2e/parser_oracle_missing_artifact_contract_replay.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn validate_contract(contract: &ParserOracleMissingArtifactContract) -> Result<(), String> {
    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err("schema_version mismatch".to_string());
    }
    if contract.artifact_contract.receipt_path != "parser_oracle_missing_artifact_receipt.json" {
        return Err("receipt_path must be parser_oracle_missing_artifact_receipt.json".to_string());
    }

    let allowed_stages = [
        "mode_selection",
        "gate_condition",
        "execution",
        "post_run_validation",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let allowed_actions = ["record_and_continue", "surface_degraded", "fail_closed"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let allowed_signature_types = ["literal_json", "zero_bytes"]
        .into_iter()
        .collect::<BTreeSet<_>>();

    let covered = contract
        .artifact_contract
        .covered_artifacts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if covered.len() != contract.artifact_contract.covered_artifacts.len() {
        return Err("covered_artifacts must be unique".to_string());
    }

    let mut reason_ids = BTreeSet::<&str>::new();
    let mut reason_codes = BTreeSet::<&str>::new();
    for entry in &contract.artifact_contract.reason_matrix {
        if !allowed_stages.contains(entry.stage.as_str()) {
            return Err(format!("unknown stage {}", entry.stage));
        }
        if !allowed_actions.contains(entry.consumer_action.as_str()) {
            return Err(format!("unknown consumer_action {}", entry.consumer_action));
        }
        if !entry.placeholder_rejected {
            return Err(format!(
                "reason {} must reject anonymous placeholders",
                entry.reason_id
            ));
        }
        if !reason_ids.insert(entry.reason_id.as_str()) {
            return Err(format!("duplicate reason_id {}", entry.reason_id));
        }
        if !reason_codes.insert(entry.code.as_str()) {
            return Err(format!("duplicate reason code {}", entry.code));
        }
        if entry.allowed_artifact_roles.is_empty() {
            return Err(format!(
                "reason {} must list at least one artifact role",
                entry.reason_id
            ));
        }
    }

    let mut rejected_paths = BTreeSet::<&str>::new();
    for backfill in &contract.artifact_contract.rejected_anonymous_backfills {
        if !covered.contains(backfill.artifact_path.as_str()) {
            return Err(format!(
                "rejected backfill path {} must be covered",
                backfill.artifact_path
            ));
        }
        if !allowed_signature_types.contains(backfill.signature_type.as_str()) {
            return Err(format!(
                "unknown signature_type {}",
                backfill.signature_type
            ));
        }
        if !rejected_paths.insert(backfill.artifact_path.as_str()) {
            return Err(format!(
                "duplicate rejected backfill path {}",
                backfill.artifact_path
            ));
        }
    }

    Ok(())
}

#[test]
fn parser_oracle_missing_artifact_doc_contains_required_sections() {
    let doc = contract_doc();
    for section in [
        "# Parser Oracle Missing-Artifact Contract V1",
        "## Purpose",
        "## Covered Artifacts",
        "## Explicit Missing States",
        "## Rejected Anonymous Backfills",
        "## Structured Logging and Artifact Contract",
        "## Operator Verification",
    ] {
        assert!(doc.contains(section), "missing required section: {section}");
    }
}

#[test]
fn parser_oracle_missing_artifact_readme_section_is_present() {
    let readme = readme();
    assert!(readme.contains("## Parser Oracle Missing-Artifact Contract"));
    assert!(readme.contains("./scripts/run_parser_oracle_missing_artifact_contract.sh ci"));
    assert!(readme.contains("./scripts/e2e/parser_oracle_missing_artifact_contract_replay.sh ci"));
}

#[test]
fn parser_oracle_gate_doc_mentions_contract() {
    let doc = gate_doc();
    assert!(doc.contains("## Missing-Artifact Contract"));
    assert!(doc.contains("docs/PARSER_ORACLE_MISSING_ARTIFACT_CONTRACT_V1.md"));
    assert!(doc.contains("parser_oracle_missing_artifact_receipt.json"));
}

#[test]
fn parser_oracle_missing_artifact_contract_is_versioned_and_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-2muur.7.1");
    assert_eq!(contract.policy_id, CONTRACT_POLICY_ID);
    assert_eq!(contract.generated_by, "bd-2muur.7.1");
    assert_eq!(contract.track.id, "RGC-920G.1");
    assert_eq!(
        contract.track.name,
        "Parser Oracle Missing Artifact Contract"
    );
    assert!(contract.generated_at_utc.ends_with('Z'));
    assert!(
        contract
            .source_inputs
            .iter()
            .any(|path| path == "README.md")
    );
    assert!(
        contract
            .source_inputs
            .iter()
            .any(|path| path == "scripts/run_parser_oracle_gate.sh")
    );
}

#[test]
fn parser_oracle_missing_artifact_contract_declares_required_generated_artifacts() {
    let contract = parse_contract();
    for artifact in [
        "artifacts/parser_oracle_missing_artifact_contract/<timestamp>/run_manifest.json",
        "artifacts/parser_oracle_missing_artifact_contract/<timestamp>/trace_ids.json",
        "artifacts/parser_oracle_missing_artifact_contract/<timestamp>/events.jsonl",
        "artifacts/parser_oracle_missing_artifact_contract/<timestamp>/commands.txt",
        "artifacts/parser_oracle_missing_artifact_contract/<timestamp>/step_logs/step_000.log",
        "artifacts/parser_oracle_missing_artifact_contract/<timestamp>/parser_oracle_missing_artifact_contract.json",
        "artifacts/parser_oracle_missing_artifact_contract/<timestamp>/parser_oracle_missing_artifact_contract_validation_report.json",
    ] {
        assert!(
            contract
                .generated_artifacts
                .iter()
                .any(|entry| entry == artifact),
            "missing generated artifact contract entry: {artifact}"
        );
    }
}

#[test]
fn parser_oracle_missing_artifact_contract_declares_required_structured_log_fields() {
    let contract = parse_contract();
    for field in [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "artifact_path",
        "artifact_role",
        "stage",
        "reason_code",
        "consumer_action",
    ] {
        assert!(
            contract
                .required_structured_log_fields
                .iter()
                .any(|entry| entry == field),
            "missing required structured log field: {field}"
        );
    }
}

#[test]
fn parser_oracle_missing_artifact_contract_has_required_reason_matrix() {
    let contract = parse_contract();
    let reasons = contract
        .artifact_contract
        .reason_matrix
        .iter()
        .map(|entry| {
            (
                entry.code.as_str(),
                entry.reason_id.as_str(),
                entry.stage.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        vec![
            ("FE-PO-MISSING-0001", "not_run_by_design", "mode_selection"),
            (
                "FE-PO-MISSING-0002",
                "skipped_by_gate_condition",
                "gate_condition"
            ),
            (
                "FE-PO-MISSING-0003",
                "failed_before_artifact_creation",
                "execution"
            ),
            (
                "FE-PO-MISSING-0004",
                "missing_unexpected_absence",
                "post_run_validation"
            ),
        ]
    );
}

#[test]
fn parser_oracle_missing_artifact_contract_rejects_legacy_placeholder_backfills() {
    let script = gate_script();
    let contract = parse_contract();

    assert!(script.contains("parser_oracle_missing_artifact_receipt.json"));
    assert!(script.contains("write_missing_artifact_receipt"));
    assert!(!script.contains("echo \"{}\" >\"$baseline_path\""));
    assert!(
        !script.contains("echo \"{\\\"status\\\":\\\"not_run\\\"}\" >\"$relation_report_path\"")
    );
    assert!(!script.contains(": >\"$relation_events_path\""));
    assert!(!script.contains(": >\"$evidence_path\""));
    assert!(!script.contains(": >\"$drift_digest_path\""));

    let rejected = contract
        .artifact_contract
        .rejected_anonymous_backfills
        .iter()
        .map(|entry| (entry.artifact_path.as_str(), entry.signature_type.as_str()))
        .collect::<BTreeSet<_>>();
    for expected in [
        ("baseline.json", "literal_json"),
        ("relation_report.json", "literal_json"),
        ("relation_events.jsonl", "zero_bytes"),
        ("metamorphic_evidence.jsonl", "zero_bytes"),
        ("drift_digest.md", "zero_bytes"),
    ] {
        assert!(
            rejected.contains(&expected),
            "missing rejected backfill entry for {:?}",
            expected
        );
    }
}

#[test]
fn parser_oracle_missing_artifact_contract_validation_is_green() {
    let contract = parse_contract();
    validate_contract(&contract).expect("contract should validate");
}

#[test]
fn parser_oracle_missing_artifact_contract_validation_rejects_duplicate_reason_ids() {
    let mut contract = parse_contract();
    contract.artifact_contract.reason_matrix[1].reason_id = "not_run_by_design".to_string();
    let error = validate_contract(&contract).expect_err("duplicate reason_id must fail");
    assert!(error.contains("duplicate reason_id"));
}

#[test]
fn parser_oracle_missing_artifact_contract_validation_rejects_unknown_stage() {
    let mut contract = parse_contract();
    contract.artifact_contract.reason_matrix[0].stage = "mystery_stage".to_string();
    let error = validate_contract(&contract).expect_err("unknown stage must fail");
    assert!(error.contains("unknown stage"));
}

#[test]
fn parser_oracle_missing_artifact_contract_validation_rejects_unknown_signature_type() {
    let mut contract = parse_contract();
    contract.artifact_contract.rejected_anonymous_backfills[0].signature_type =
        "opaque_blob".to_string();
    let error = validate_contract(&contract).expect_err("unknown signature type must fail");
    assert!(error.contains("unknown signature_type"));
}

#[test]
fn parser_oracle_missing_artifact_contract_validation_rejects_uncovered_artifact_path() {
    let mut contract = parse_contract();
    contract.artifact_contract.rejected_anonymous_backfills[0].artifact_path =
        "unknown.json".to_string();
    let error = validate_contract(&contract).expect_err("uncovered path must fail");
    assert!(error.contains("must be covered"));
}

#[test]
fn parser_oracle_missing_artifact_contract_operator_verification_is_complete() {
    let contract = parse_contract();
    assert!(contract.operator_verification.iter().any(|entry| {
        entry.contains("jq empty docs/parser_oracle_missing_artifact_contract_v1.json")
    }));
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains(
                "cargo test -p frankenengine-engine --test parser_oracle_missing_artifact_contract"
            ))
    );
    assert!(contract.operator_verification.iter().any(|entry| {
        entry.contains("./scripts/run_parser_oracle_missing_artifact_contract.sh ci")
    }));
}

#[test]
fn parser_oracle_missing_artifact_validation_script_uses_rch_and_expected_artifacts() {
    let script = validation_script();
    assert!(script.contains("rch exec -- env"));
    assert!(script.contains(
        "cargo check -p frankenengine-engine --test parser_oracle_missing_artifact_contract"
    ));
    assert!(script.contains(
        "cargo test -p frankenengine-engine --test parser_oracle_missing_artifact_contract"
    ));
    assert!(script.contains("cargo clippy -p frankenengine-engine --test parser_oracle_missing_artifact_contract -- -D warnings"));
    assert!(script.contains("parser_oracle_missing_artifact_contract_validation_report.json"));
    assert!(script.contains("trace_ids.json"));
}

#[test]
fn parser_oracle_missing_artifact_replay_wrapper_requires_complete_bundle() {
    let script = replay_script();
    for required in [
        "run_manifest.json",
        "trace_ids.json",
        "events.jsonl",
        "commands.txt",
        "parser_oracle_missing_artifact_contract.json",
        "parser_oracle_missing_artifact_contract_validation_report.json",
        "step_logs/step_000.log",
    ] {
        assert!(
            script.contains(required),
            "replay wrapper missing completeness requirement: {required}"
        );
    }
}

#[test]
fn parser_oracle_missing_artifact_backfill_entries_have_nonempty_classifications() {
    let contract = parse_contract();
    for entry in &contract.artifact_contract.rejected_anonymous_backfills {
        assert!(
            !entry.classification.trim().is_empty(),
            "classification must not be empty for {}",
            entry.artifact_path
        );
        if entry.signature_type == "literal_json" {
            assert!(
                !entry.signature_value.is_empty(),
                "literal_json backfills must capture the rejected value"
            );
        }
    }
}
