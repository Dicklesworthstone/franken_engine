#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, path::PathBuf};

use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.lowering-gap-truth-invariant.v1";
const CONTRACT_POLICY_ID: &str = "policy-lowering-gap-truth-invariant-v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/lowering_gap_truth_invariant_v1.json");

#[derive(Debug, Clone, Deserialize)]
struct LoweringGapTruthInvariantContract {
    schema_version: String,
    bead_id: String,
    policy_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: ContractTrack,
    source_inputs: Vec<String>,
    required_structured_log_fields: Vec<String>,
    generated_artifacts: Vec<String>,
    invariant_contract: InvariantContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ContractTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct InvariantContract {
    rule_set_id: String,
    scope: String,
    deferred_application_bead: String,
    consumer_alignment_bead: String,
    allowed_status_matrix: Vec<AllowedStateRule>,
    disallowed_state_examples: Vec<DisallowedStateExample>,
    consumer_fail_closed_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AllowedStateRule {
    rule_id: String,
    status: String,
    parser_ready_syntax: bool,
    execution_ready_semantics: bool,
    execution_consequence_prefix: String,
    user_visible_divergence_prefix: String,
    consumer_interpretation: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DisallowedStateExample {
    example_id: String,
    status: String,
    parser_ready_syntax: bool,
    execution_ready_semantics: bool,
    execution_consequence: String,
    user_visible_divergence: String,
    expected_violation: String,
}

#[derive(Debug, Clone)]
struct DescriptorState<'a> {
    status: &'a str,
    parser_ready_syntax: bool,
    execution_ready_semantics: bool,
    execution_consequence: &'a str,
    user_visible_divergence: &'a str,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> LoweringGapTruthInvariantContract {
    serde_json::from_str(CONTRACT_JSON).expect("lowering gap truth invariant contract must parse")
}

fn contract_doc() -> String {
    let path = repo_root().join("docs/LOWERING_GAP_TRUTH_INVARIANT_V1.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn readme() -> String {
    let path = repo_root().join("README.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn gate_script() -> String {
    let path = repo_root().join("scripts/run_lowering_gap_truth_invariant.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn replay_script() -> String {
    let path = repo_root().join("scripts/e2e/lowering_gap_truth_invariant_replay.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn validate_contract(contract: &LoweringGapTruthInvariantContract) -> Result<(), String> {
    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err("schema_version mismatch".to_string());
    }
    if contract.policy_id != CONTRACT_POLICY_ID {
        return Err("policy_id mismatch".to_string());
    }
    if contract.invariant_contract.rule_set_id != "lowering_gap_truth_rules_v1" {
        return Err("unexpected rule_set_id".to_string());
    }
    if contract.invariant_contract.scope
        != "lowering_gap_inventory_only_tracks_parser_accepted_syntax_families"
    {
        return Err("unexpected invariant scope".to_string());
    }

    let allowed_statuses = ["resolved", "open_placeholder", "fail_closed"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut rule_ids = BTreeSet::<&str>::new();
    let mut statuses = BTreeSet::<&str>::new();

    for rule in &contract.invariant_contract.allowed_status_matrix {
        if !rule_ids.insert(rule.rule_id.as_str()) {
            return Err(format!("duplicate rule_id {}", rule.rule_id));
        }
        if !allowed_statuses.contains(rule.status.as_str()) {
            return Err(format!("unknown status {}", rule.status));
        }
        if !statuses.insert(rule.status.as_str()) {
            return Err(format!("duplicate status rule {}", rule.status));
        }
        if !rule.parser_ready_syntax {
            return Err(format!(
                "lowering-gap rule {} must keep parser_ready_syntax=true",
                rule.rule_id
            ));
        }
        if rule.status == "resolved" && !rule.execution_ready_semantics {
            return Err("resolved rule must require execution-ready semantics".to_string());
        }
        if rule.status != "resolved" && rule.execution_ready_semantics {
            return Err(format!(
                "non-resolved rule {} cannot claim execution-ready semantics",
                rule.rule_id
            ));
        }
        if rule.execution_consequence_prefix.is_empty()
            || rule.user_visible_divergence_prefix.is_empty()
            || rule.consumer_interpretation.is_empty()
        {
            return Err(format!("rule {} has empty required fields", rule.rule_id));
        }
    }

    if statuses != allowed_statuses {
        return Err(
            "allowed status matrix must cover resolved/open_placeholder/fail_closed".to_string(),
        );
    }

    let mut example_ids = BTreeSet::<&str>::new();
    for example in &contract.invariant_contract.disallowed_state_examples {
        if !example_ids.insert(example.example_id.as_str()) {
            return Err(format!("duplicate example_id {}", example.example_id));
        }
        if !allowed_statuses.contains(example.status.as_str()) {
            return Err(format!("unknown example status {}", example.status));
        }
        if example.expected_violation.is_empty() {
            return Err(format!(
                "example {} must include an expected_violation",
                example.example_id
            ));
        }
    }

    Ok(())
}

fn validate_state_against_contract<'a>(
    contract: &'a LoweringGapTruthInvariantContract,
    state: DescriptorState<'_>,
) -> Result<&'a str, String> {
    if !state.parser_ready_syntax {
        return Err("lowering_gap_sites_require_parser_ready_syntax".to_string());
    }

    let rule = contract
        .invariant_contract
        .allowed_status_matrix
        .iter()
        .find(|rule| rule.status == state.status)
        .ok_or_else(|| "unknown_status".to_string())?;

    if state.execution_ready_semantics != rule.execution_ready_semantics {
        return Err(match state.status {
            "resolved" => "resolved_requires_execution_ready".to_string(),
            "open_placeholder" => "open_placeholder_forbids_execution_ready".to_string(),
            "fail_closed" => "fail_closed_forbids_execution_ready".to_string(),
            _ => "unknown_status".to_string(),
        });
    }

    if !state
        .execution_consequence
        .starts_with(&rule.execution_consequence_prefix)
        || !state
            .user_visible_divergence
            .starts_with(&rule.user_visible_divergence_prefix)
    {
        return Err(match state.status {
            "resolved" => "resolved_requires_resolved_prefixes".to_string(),
            "open_placeholder" => "open_placeholder_requires_open_prefixes".to_string(),
            "fail_closed" => "fail_closed_requires_fail_closed_prefixes".to_string(),
            _ => "unknown_status".to_string(),
        });
    }

    Ok(rule.rule_id.as_str())
}

#[test]
fn lowering_gap_truth_invariant_doc_contains_required_sections() {
    let doc = contract_doc();
    for section in [
        "# Lowering Gap Truth Invariant V1",
        "## Purpose",
        "## Scope",
        "## Allowed State Matrix",
        "## Disallowed State Patterns",
        "## Structured Logging and Artifact Contract",
        "## Operator Verification",
    ] {
        assert!(doc.contains(section), "missing required section: {section}");
    }
}

#[test]
fn lowering_gap_truth_invariant_readme_section_is_present() {
    let readme = readme();
    assert!(readme.contains("## Lowering Gap Truth Invariant"));
    assert!(readme.contains("./scripts/run_lowering_gap_truth_invariant.sh ci"));
    assert!(readme.contains("./scripts/e2e/lowering_gap_truth_invariant_replay.sh ci"));
}

#[test]
fn lowering_gap_truth_invariant_contract_is_versioned_and_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-2muur.4.1");
    assert_eq!(contract.policy_id, CONTRACT_POLICY_ID);
    assert_eq!(contract.generated_by, "bd-2muur.4.1");
    assert_eq!(contract.track.id, "RGC-920D.1");
    assert_eq!(contract.track.name, "Lowering Gap Truth Invariant");
    assert!(contract.generated_at_utc.ends_with('Z'));
    assert!(
        contract
            .source_inputs
            .iter()
            .any(|path| path == "crates/franken-engine/src/lowering_gap_inventory.rs")
    );
    assert_eq!(
        contract.invariant_contract.deferred_application_bead,
        "bd-2muur.4.2"
    );
    assert_eq!(
        contract.invariant_contract.consumer_alignment_bead,
        "bd-2muur.4.3"
    );
}

#[test]
fn lowering_gap_truth_invariant_contract_declares_required_generated_artifacts() {
    let contract = parse_contract();
    for artifact in [
        "artifacts/lowering_gap_truth_invariant/<timestamp>/run_manifest.json",
        "artifacts/lowering_gap_truth_invariant/<timestamp>/trace_ids.json",
        "artifacts/lowering_gap_truth_invariant/<timestamp>/events.jsonl",
        "artifacts/lowering_gap_truth_invariant/<timestamp>/commands.txt",
        "artifacts/lowering_gap_truth_invariant/<timestamp>/step_logs/step_000.log",
        "artifacts/lowering_gap_truth_invariant/<timestamp>/lowering_gap_truth_invariant.json",
        "artifacts/lowering_gap_truth_invariant/<timestamp>/lowering_gap_truth_invariant_validation_report.json",
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
fn lowering_gap_truth_invariant_contract_declares_structured_log_fields() {
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
        "rule_id",
        "site_id",
        "status",
        "parser_ready_syntax",
        "execution_ready_semantics",
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
fn lowering_gap_truth_invariant_contract_matrix_is_valid() {
    let contract = parse_contract();
    validate_contract(&contract).expect("contract should validate");

    let rule_ids = contract
        .invariant_contract
        .allowed_status_matrix
        .iter()
        .map(|rule| rule.rule_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        rule_ids,
        vec![
            "resolved_exec_ready",
            "open_placeholder_parser_ready",
            "fail_closed_parser_ready"
        ]
    );
}

#[test]
fn lowering_gap_truth_invariant_accepts_all_allowed_rule_shapes() {
    let contract = parse_contract();

    for rule in &contract.invariant_contract.allowed_status_matrix {
        let execution_consequence =
            format!("{} example consequence", rule.execution_consequence_prefix);
        let user_visible_divergence =
            format!("{} example divergence", rule.user_visible_divergence_prefix);
        let state = DescriptorState {
            status: rule.status.as_str(),
            parser_ready_syntax: rule.parser_ready_syntax,
            execution_ready_semantics: rule.execution_ready_semantics,
            execution_consequence: execution_consequence.as_str(),
            user_visible_divergence: user_visible_divergence.as_str(),
        };
        let matched = validate_state_against_contract(&contract, state)
            .expect("allowed state should validate");
        assert_eq!(matched, rule.rule_id);
    }
}

#[test]
fn lowering_gap_truth_invariant_rejects_disallowed_examples() {
    let contract = parse_contract();

    for example in &contract.invariant_contract.disallowed_state_examples {
        let state = DescriptorState {
            status: example.status.as_str(),
            parser_ready_syntax: example.parser_ready_syntax,
            execution_ready_semantics: example.execution_ready_semantics,
            execution_consequence: example.execution_consequence.as_str(),
            user_visible_divergence: example.user_visible_divergence.as_str(),
        };
        let violation =
            validate_state_against_contract(&contract, state).expect_err("example must fail");
        assert_eq!(violation, example.expected_violation);
    }
}

#[test]
fn lowering_gap_truth_invariant_rejects_invalid_contract_encodings() {
    let contract = parse_contract();

    let mut duplicate_rule = contract.clone();
    duplicate_rule
        .invariant_contract
        .allowed_status_matrix
        .push(duplicate_rule.invariant_contract.allowed_status_matrix[0].clone());
    assert!(validate_contract(&duplicate_rule).is_err());

    let mut unknown_status = contract.clone();
    unknown_status.invariant_contract.allowed_status_matrix[0].status =
        "partially_ready".to_string();
    assert!(validate_contract(&unknown_status).is_err());

    let mut invalid_resolved = contract.clone();
    invalid_resolved.invariant_contract.allowed_status_matrix[0].execution_ready_semantics = false;
    assert!(validate_contract(&invalid_resolved).is_err());
}

#[test]
fn lowering_gap_truth_invariant_scripts_reference_rch_backed_validation() {
    let gate = gate_script();
    let replay = replay_script();

    assert!(
        gate.contains("cargo test -p frankenengine-engine --test lowering_gap_truth_invariant")
    );
    assert!(gate.contains("rch exec"));
    assert!(replay.contains("./scripts/run_lowering_gap_truth_invariant.sh"));
    assert!(replay.contains("lowering_gap_truth_invariant_validation_report.json"));
}

#[test]
fn lowering_gap_truth_invariant_operator_verification_mentions_required_commands() {
    let contract = parse_contract();
    for expected in [
        "jq empty docs/lowering_gap_truth_invariant_v1.json",
        "cargo test -p frankenengine-engine --test lowering_gap_truth_invariant",
        "./scripts/run_lowering_gap_truth_invariant.sh ci",
        "./scripts/e2e/lowering_gap_truth_invariant_replay.sh ci",
    ] {
        assert!(
            contract
                .operator_verification
                .iter()
                .any(|entry| entry.contains(expected)),
            "missing operator verification entry: {expected}"
        );
    }
}

#[test]
fn lowering_gap_truth_invariant_fail_closed_reasons_are_nonempty_and_unique() {
    let contract = parse_contract();
    let reasons = &contract.invariant_contract.consumer_fail_closed_reasons;
    assert_eq!(
        reasons.len(),
        reasons.iter().collect::<BTreeSet<_>>().len(),
        "consumer_fail_closed_reasons must be unique"
    );
    assert!(reasons.iter().all(|reason| !reason.trim().is_empty()));
}
