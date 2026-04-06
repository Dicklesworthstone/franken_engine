#![forbid(unsafe_code)]

use std::{fs, path::PathBuf};

use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.parser-phase0-artifact-contract.v1";
const CONTRACT_POLICY_ID: &str = "policy-parser-phase0-artifact-contract-v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/parser_phase0_artifact_contract_v1.json");

#[derive(Debug, Deserialize)]
struct Phase0ArtifactContract {
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

#[derive(Debug, Deserialize)]
struct ContractTrack {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct ArtifactContract {
    baseline_artifacts: Vec<String>,
    performance_artifact_receipt_path: String,
    accepted_real_artifact_shapes: Vec<RealArtifactShape>,
    accepted_degraded_receipt_shape: DegradedReceiptShape,
    rejected_placeholder_signatures: Vec<String>,
    consumer_fail_closed_reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RealArtifactShape {
    shape_id: String,
    artifact_path: String,
    mode: String,
    required_receipt_fields: Vec<String>,
    allowed_capture_sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DegradedReceiptShape {
    shape_id: String,
    artifact_path: String,
    mode: String,
    required_receipt_fields: Vec<String>,
    allowed_reason_codes: Vec<DegradedReasonCode>,
}

#[derive(Debug, Deserialize)]
struct DegradedReasonCode {
    code: String,
    reason_id: String,
    stage: String,
    consumer_action: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> Phase0ArtifactContract {
    serde_json::from_str(CONTRACT_JSON).expect("parser phase0 artifact contract must parse")
}

fn contract_doc() -> String {
    let path = repo_root().join("docs/PARSER_PHASE0_ARTIFACT_CONTRACT_V1.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn readme() -> String {
    let path = repo_root().join("README.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn gate_script() -> String {
    let path = repo_root().join("scripts/run_parser_phase0_artifact_contract.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn replay_script() -> String {
    let path = repo_root().join("scripts/e2e/parser_phase0_artifact_contract_replay.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn placeholder_rejected(signatures: &[String], content: &str) -> bool {
    signatures
        .iter()
        .any(|signature| content.contains(signature))
}

#[test]
fn parser_phase0_artifact_doc_contains_required_sections() {
    let doc = contract_doc();
    for section in [
        "# Parser Phase0 Artifact Contract V1",
        "## Purpose",
        "## Accepted Artifact Modes",
        "## Rejected Placeholder Content",
        "## Degraded-Mode Receipts",
        "## Structured Logging and Artifact Contract",
        "## Operator Verification",
    ] {
        assert!(doc.contains(section), "missing required section: {section}");
    }
}

#[test]
fn parser_phase0_artifact_readme_section_is_present() {
    let readme = readme();
    assert!(readme.contains("## Parser Phase0 Artifact Contract"));
    assert!(readme.contains("./scripts/run_parser_phase0_artifact_contract.sh ci"));
    assert!(readme.contains("./scripts/e2e/parser_phase0_artifact_contract_replay.sh ci"));
}

#[test]
fn parser_phase0_artifact_contract_is_versioned_and_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-2muur.6.1");
    assert_eq!(contract.policy_id, CONTRACT_POLICY_ID);
    assert_eq!(contract.generated_by, "bd-2muur.6.1");
    assert_eq!(contract.track.id, "RGC-920F.1");
    assert_eq!(contract.track.name, "Parser Phase0 Artifact Contract");
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
            .any(|path| path == "scripts/generate_parser_phase0_artifacts.sh")
    );
}

#[test]
fn parser_phase0_artifact_contract_declares_required_generated_artifacts() {
    let contract = parse_contract();
    for artifact in [
        "artifacts/parser_phase0_artifact_contract/<timestamp>/run_manifest.json",
        "artifacts/parser_phase0_artifact_contract/<timestamp>/trace_ids.json",
        "artifacts/parser_phase0_artifact_contract/<timestamp>/events.jsonl",
        "artifacts/parser_phase0_artifact_contract/<timestamp>/commands.txt",
        "artifacts/parser_phase0_artifact_contract/<timestamp>/step_logs/step_000.log",
        "artifacts/parser_phase0_artifact_contract/<timestamp>/parser_phase0_artifact_contract.json",
        "artifacts/parser_phase0_artifact_contract/<timestamp>/parser_phase0_artifact_contract_validation_report.json",
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
fn parser_phase0_artifact_contract_declares_structured_log_fields() {
    let contract = parse_contract();
    for field in [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "artifact_mode",
        "receipt_reason_code",
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
fn parser_phase0_artifact_contract_covers_real_and_degraded_modes() {
    let contract = parse_contract();
    assert_eq!(
        contract.artifact_contract.performance_artifact_receipt_path,
        "parser_phase0_performance_artifact_receipt.json"
    );
    assert_eq!(contract.artifact_contract.baseline_artifacts.len(), 6);

    let shape_ids = contract
        .artifact_contract
        .accepted_real_artifact_shapes
        .iter()
        .map(|shape| shape.shape_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        shape_ids,
        vec!["real_flamegraph_svg", "profile_summary_only"]
    );

    for shape in &contract.artifact_contract.accepted_real_artifact_shapes {
        assert_eq!(shape.mode, "real_capture");
        assert!(
            shape
                .required_receipt_fields
                .iter()
                .any(|field| field == "placeholder_rejected")
        );
        assert!(!shape.allowed_capture_sources.is_empty());
        assert!(!shape.artifact_path.trim().is_empty());
    }

    let degraded = &contract.artifact_contract.accepted_degraded_receipt_shape;
    assert_eq!(degraded.shape_id, "degraded_receipt_only");
    assert_eq!(degraded.mode, "degraded_receipt");
    assert_eq!(
        degraded.artifact_path,
        "parser_phase0_performance_artifact_receipt.json"
    );
    assert!(
        degraded
            .required_receipt_fields
            .iter()
            .any(|field| field == "reason_code")
    );
}

#[test]
fn parser_phase0_artifact_contract_has_typed_degraded_reason_matrix() {
    let contract = parse_contract();
    let reasons = &contract
        .artifact_contract
        .accepted_degraded_receipt_shape
        .allowed_reason_codes;

    assert_eq!(reasons.len(), 6);

    for (code, reason_id, stage) in [
        (
            "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0001",
            "profiler_unavailable",
            "capture_preflight",
        ),
        (
            "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0002",
            "capture_disabled_by_policy",
            "policy_block",
        ),
        (
            "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0003",
            "platform_unsupported",
            "capture_preflight",
        ),
        (
            "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0004",
            "permission_denied",
            "capture_execution",
        ),
        (
            "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0005",
            "preflight_failed",
            "capture_preflight",
        ),
        (
            "FE-PARSER-PHASE0-ARTIFACT-RECEIPT-0006",
            "upstream_command_failed",
            "artifact_materialization",
        ),
    ] {
        let reason = reasons
            .iter()
            .find(|entry| entry.code == code)
            .unwrap_or_else(|| panic!("missing degraded reason code: {code}"));
        assert_eq!(reason.reason_id, reason_id);
        assert_eq!(reason.stage, stage);
        assert!(!reason.consumer_action.trim().is_empty());
    }
}

#[test]
fn parser_phase0_artifact_contract_rejects_current_placeholder_signatures() {
    let contract = parse_contract();
    let sample_placeholder = r##"
<svg xmlns="http://www.w3.org/2000/svg" aria-label="parser phase0 flamegraph placeholder">
  <rect x="40" y="72" width="1200" height="24" fill="#22c55e" />
  <text>parser_phase0 scalar_reference baseline lane (placeholder flamegraph artifact)</text>
</svg>
"##;

    assert!(
        placeholder_rejected(
            &contract.artifact_contract.rejected_placeholder_signatures,
            sample_placeholder
        ),
        "placeholder sample should be rejected by contract signatures"
    );
}

#[test]
fn parser_phase0_artifact_contract_declares_fail_closed_consumer_reasons() {
    let contract = parse_contract();
    for reason in [
        "missing performance artifact receipt",
        "unknown degraded reason code",
        "placeholder signature match",
        "real_capture receipt with empty artifact_sha256",
        "artifact path mismatch between receipt and emitted files",
    ] {
        assert!(
            contract
                .artifact_contract
                .consumer_fail_closed_reasons
                .iter()
                .any(|entry| entry == reason),
            "missing fail-closed consumer reason: {reason}"
        );
    }
}

#[test]
fn parser_phase0_artifact_operator_verification_is_rch_backed() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty docs/parser_phase0_artifact_contract_v1.json"))
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("target_rch_parser_phase0_artifact_contract_verify"))
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/run_parser_phase0_artifact_contract.sh ci"))
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/e2e/parser_phase0_artifact_contract_replay.sh ci"))
    );
}

#[test]
fn parser_phase0_artifact_gate_script_emits_required_artifacts() {
    let script = gate_script();
    assert!(script.contains("rch is required"));
    assert!(script.contains("step_logs"));
    assert!(script.contains("trace_ids.json"));
    assert!(script.contains("parser_phase0_artifact_contract_validation_report.json"));
    assert!(script.contains("parser_phase0_artifact_contract.json"));
    assert!(
        script
            .contains("cargo check -p frankenengine-engine --test parser_phase0_artifact_contract")
    );
    assert!(
        script
            .contains("cargo test -p frankenengine-engine --test parser_phase0_artifact_contract")
    );
    assert!(script.contains(
        "cargo clippy -p frankenengine-engine --test parser_phase0_artifact_contract -- -D warnings"
    ));
}

#[test]
fn parser_phase0_artifact_replay_script_requires_complete_bundle() {
    let script = replay_script();
    assert!(script.contains("run_manifest.json"));
    assert!(script.contains("trace_ids.json"));
    assert!(script.contains("events.jsonl"));
    assert!(script.contains("commands.txt"));
    assert!(script.contains("parser_phase0_artifact_contract.json"));
    assert!(script.contains("parser_phase0_artifact_contract_validation_report.json"));
    assert!(script.contains("step_logs/step_000.log"));
    assert!(script.contains("PARSER_PHASE0_ARTIFACT_CONTRACT_REPLAY_RUN_DIR"));
}
