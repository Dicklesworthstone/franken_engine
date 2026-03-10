//! Comprehensive integration tests for `wave_handoff_contract` module.
//!
//! Covers: WaveId, RequiredBeadStatus, WaveCriterion, WaveTransitionContract,
//! CriterionAttestation, HandoffPackage, validation logic (happy/failure paths),
//! simulate_wave_transition, serde round-trips, edge cases, multi-wave scenarios,
//! and deterministic behavior.

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

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[path = "../src/wave_handoff_contract.rs"]
mod wave_handoff_contract;

use wave_handoff_contract::{
    CriterionAttestation, HandoffEvent, HandoffPackage, HandoffValidationErrorCode,
    HandoffValidationFailure, HandoffValidationReport, RequiredBeadStatus, WAVE_HANDOFF_COMPONENT,
    WAVE_HANDOFF_CONTRACT_VERSION, WAVE_HANDOFF_FAILURE_CODE, WAVE_HANDOFF_PACKET_SCHEMA_VERSION,
    WaveCriterion, WaveId, WaveTransitionContract, simulate_wave_transition, validate_handoff,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = read_to_string(path);
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as json: {err}", path.display()))
}

#[derive(Debug, Deserialize)]
struct HandoffSchemaContract {
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    properties: std::collections::BTreeMap<String, serde_json::Value>,
}

// ─── Fixture / doc validation (preserved from original) ───

#[test]
fn rgc_015_doc_contains_wave_entry_exit_and_handoff_sections() {
    let path = repo_root().join("docs/FRX_CROSS_TRACK_HANDOFF_PROTOCOL_V1.md");
    let doc = read_to_string(&path);

    let required_sections = [
        "# FRX Cross-Track Handoff Protocol v1",
        "## Wave Model",
        "## Wave Entry Criteria",
        "## Wave Exit Criteria",
        "## Mandatory Handoff Package",
        "## Automated Validation and Failure Policy",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }

    for phrase in [
        "wave_0",
        "wave_1",
        "wave_2",
        "wave_3",
        "entry",
        "exit",
        "handoff package",
        "artifact",
        "open risks",
        "next-step recommendations",
        "fe-rgc-015-handoff-0001",
    ] {
        assert!(
            doc.to_ascii_lowercase().contains(phrase),
            "expected phrase not found in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn rgc_015_schema_includes_wave_and_handoff_package_requirements() {
    let path = repo_root().join("docs/frx_handoff_packet_schema_v1.json");
    let schema: HandoffSchemaContract = load_json(&path);
    let required = schema.required;

    for field in [
        "wave_id",
        "producer_owner",
        "consumer_owner",
        "entry_criteria",
        "exit_criteria",
        "criteria_attestations",
        "handoff_package",
    ] {
        assert!(
            required
                .iter()
                .any(|required_field| required_field == field),
            "required field missing from schema: {field}"
        );
    }

    for field in [
        "wave_id",
        "producer_owner",
        "consumer_owner",
        "entry_criteria",
        "exit_criteria",
        "criteria_attestations",
        "handoff_package",
    ] {
        assert!(
            schema.properties.contains_key(field),
            "properties missing expected key: {field}"
        );
    }
}

// ─── Validation: happy path ───

#[test]
fn rgc_015_validation_accepts_complete_handoff_package() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let package = HandoffPackage::baseline();

    let report = validate_handoff(
        "trace-rgc-015-pass",
        "decision-rgc-015-pass",
        "policy-rgc-015-v1",
        &contract,
        &package,
    );
    assert!(report.valid);
    assert_eq!(report.outcome, "pass");
    assert_eq!(report.error_code, "none");
}

#[test]
fn validation_pass_report_has_correct_metadata() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let package = HandoffPackage::baseline();

    let report = validate_handoff(
        "trace-meta",
        "decision-meta",
        "policy-meta",
        &contract,
        &package,
    );
    assert!(report.valid);
    assert_eq!(report.trace_id, "trace-meta");
    assert_eq!(report.decision_id, "decision-meta");
    assert_eq!(report.policy_id, "policy-meta");
    assert_eq!(report.component, WAVE_HANDOFF_COMPONENT);
    assert_eq!(report.contract_version, WAVE_HANDOFF_CONTRACT_VERSION);
    assert_eq!(report.event, "validate_handoff");
    assert!(report.failures.is_empty());
}

// ─── Validation: weak/missing field failures ───

#[test]
fn rgc_015_validation_rejects_weak_or_missing_handoff_contents() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut package = HandoffPackage::baseline();
    package.next_step_recommendations.clear();
    package.completeness_score_milli = 100;
    package.criteria_attestations.pop();

    let report = validate_handoff(
        "trace-rgc-015-fail",
        "decision-rgc-015-fail",
        "policy-rgc-015-v1",
        &contract,
        &package,
    );
    assert!(!report.valid);
    assert_eq!(report.outcome, "fail");
    assert_eq!(report.error_code, WAVE_HANDOFF_FAILURE_CODE);
    assert!(report.failures.iter().any(|failure| {
        failure.code == HandoffValidationErrorCode::MissingRequiredField
            && failure.message.contains("next_step_recommendations")
    }));
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.code == HandoffValidationErrorCode::WeakHandoffPackage)
    );
    assert!(report.failures.iter().any(|failure| {
        failure.code == HandoffValidationErrorCode::MissingCriterionAttestation
            && failure.message.contains("exit-handoff-schema")
    }));
}

#[test]
fn validation_rejects_empty_packet_id() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = String::new();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingRequiredField
            && f.message.contains("packet_id")
    }));
}

#[test]
fn validation_rejects_whitespace_only_packet_id() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = "   \t  ".to_string();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingRequiredField
            && f.message.contains("packet_id")
    }));
}

#[test]
fn validation_rejects_empty_producer_owner() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.producer_owner = String::new();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingRequiredField
            && f.message.contains("producer_owner")
    }));
}

#[test]
fn validation_rejects_empty_consumer_owner() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.consumer_owner = String::new();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingRequiredField
            && f.message.contains("consumer_owner")
    }));
}

#[test]
fn validation_rejects_empty_changed_beads() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.changed_beads.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingRequiredField
            && f.message.contains("changed_beads")
    }));
}

#[test]
fn validation_rejects_empty_artifact_links() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.artifact_links.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingRequiredField
            && f.message.contains("artifact_links")
    }));
}

#[test]
fn validation_rejects_empty_next_step_recommendations() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.next_step_recommendations.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingRequiredField
            && f.message.contains("next_step_recommendations")
    }));
}

// ─── Validation: weak completeness score ───

#[test]
fn validation_rejects_weak_completeness_score() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = 100;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(
        report
            .failures
            .iter()
            .any(|f| { f.code == HandoffValidationErrorCode::WeakHandoffPackage })
    );
}

#[test]
fn validation_accepts_score_at_exact_threshold() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = contract.minimum_handoff_score_milli;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        !report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage),
        "score at exact threshold should not trigger weak package error"
    );
}

#[test]
fn validation_rejects_score_one_below_threshold() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = contract.minimum_handoff_score_milli - 1;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report
            .failures
            .iter()
            .any(|f| { f.code == HandoffValidationErrorCode::WeakHandoffPackage })
    );
}

#[test]
fn validation_accepts_score_one_above_threshold() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = contract.minimum_handoff_score_milli + 1;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        !report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage),
        "score above threshold should not trigger weak package error"
    );
}

// ─── Validation: criterion attestation missing ───

#[test]
fn validation_rejects_missing_entry_criterion_attestation() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.criteria_attestations
        .retain(|a| a.criterion_id != "entry-ready-deps");
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingCriterionAttestation
            && f.message.contains("entry-ready-deps")
    }));
}

#[test]
fn validation_rejects_missing_exit_criterion_attestation() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.criteria_attestations
        .retain(|a| a.criterion_id != "exit-handoff-doc");
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingCriterionAttestation
            && f.message.contains("exit-handoff-doc")
    }));
}

#[test]
fn validation_rejects_all_attestations_missing() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.criteria_attestations.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    let missing_count = report
        .failures
        .iter()
        .filter(|f| f.code == HandoffValidationErrorCode::MissingCriterionAttestation)
        .count();
    assert!(
        missing_count >= 3,
        "should report missing attestation for each mandatory criterion, found {missing_count}"
    );
}

// ─── Validation: criterion status mismatch ───

#[test]
fn validation_rejects_wrong_bead_status() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    for att in &mut pkg.criteria_attestations {
        if att.criterion_id == "entry-ready-deps" {
            att.bead_status = RequiredBeadStatus::Closed;
        }
    }
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::CriterionStatusMismatch
            && f.message.contains("entry-ready-deps")
    }));
}

// ─── Validation: criterion bead mismatch ───

#[test]
fn validation_rejects_wrong_bead_id_in_attestation() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    for att in &mut pkg.criteria_attestations {
        if att.criterion_id == "entry-ready-deps" {
            att.bead_id = "bd-wrong".to_string();
        }
    }
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::CriterionBeadMissing
            && f.message.contains("entry-ready-deps")
    }));
}

#[test]
fn validation_rejects_bead_not_in_changed_beads() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.changed_beads.retain(|b| b != "bd-1lsy.1");
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::CriterionBeadMissing
            && f.message.contains("changed_beads")
    }));
}

// ─── Validation: criterion artifact mismatch ───

#[test]
fn validation_rejects_wrong_artifact_ref_in_attestation() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    for att in &mut pkg.criteria_attestations {
        if att.criterion_id == "exit-handoff-doc" {
            att.artifact_ref = "wrong/path.md".to_string();
        }
    }
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::CriterionArtifactMissing
            && f.message.contains("exit-handoff-doc")
    }));
}

#[test]
fn validation_rejects_artifact_not_in_artifact_links() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.artifact_links
        .retain(|a| a != "docs/FRX_CROSS_TRACK_HANDOFF_PROTOCOL_V1.md");
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::CriterionArtifactMissing
            && f.message.contains("artifact_links")
    }));
}

// ─── Validation: multiple simultaneous failures ───

#[test]
fn validation_accumulates_multiple_failures() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = String::new();
    pkg.producer_owner = String::new();
    pkg.completeness_score_milli = 0;
    pkg.next_step_recommendations.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(
        report.failures.len() >= 4,
        "expected at least 4 failures, got {}",
        report.failures.len()
    );
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::MissingRequiredField)
    );
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage)
    );
}

// ─── Validation: optional criteria skipped ───

#[test]
fn validation_skips_non_mandatory_criteria() {
    let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
    contract.entry_criteria.push(WaveCriterion {
        criterion_id: "optional-thing".to_string(),
        bead_id: "bd-opt".to_string(),
        required_status: RequiredBeadStatus::Closed,
        required_artifact: "artifacts/opt.json".to_string(),
        mandatory: false,
    });
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report.valid,
        "optional criterion should not cause failure: {:?}",
        report.failures
    );
}

// ─── Validation: empty contract criteria ───

#[test]
fn validation_passes_with_empty_contract_criteria() {
    let contract = WaveTransitionContract {
        contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
        packet_schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        wave_id: WaveId::Wave0,
        minimum_handoff_score_milli: 0,
        entry_criteria: Vec::new(),
        exit_criteria: Vec::new(),
    };
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report.valid,
        "empty criteria contract should pass: {:?}",
        report.failures
    );
}

// ─── simulate_wave_transition: happy path ───

#[test]
fn rgc_015_e2e_transition_emits_deterministic_structured_events() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let package = HandoffPackage::baseline();

    let (report, events) = simulate_wave_transition(
        "trace-rgc-015-e2e",
        "decision-rgc-015-e2e",
        "policy-rgc-015-v1",
        &contract,
        &package,
    );

    assert!(report.valid);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event, "handoff_received");
    assert_eq!(events[1].event, "criteria_validated");
    assert_eq!(events[2].event, "ownership_transition_committed");

    for event in events {
        assert_eq!(event.schema_version, WAVE_HANDOFF_PACKET_SCHEMA_VERSION);
        assert_eq!(event.trace_id, "trace-rgc-015-e2e");
        assert_eq!(event.decision_id, "decision-rgc-015-e2e");
        assert_eq!(event.policy_id, "policy-rgc-015-v1");
        assert_eq!(event.component, WAVE_HANDOFF_COMPONENT);
        assert_eq!(event.wave_id, "wave_1");
        assert_eq!(event.packet_id, "pkt-rgc-wave-1-demo");
    }
}

#[test]
fn simulation_happy_path_first_event_has_no_error_code() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let package = HandoffPackage::baseline();
    let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &package);
    assert!(events[0].error_code.is_none());
    assert!(events[1].error_code.is_none());
    assert!(events[2].error_code.is_none());
}

// ─── simulate_wave_transition: failure path ───

#[test]
fn simulation_failure_emits_rejected_transition() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = String::new();

    let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event, "handoff_received");
    assert_eq!(events[0].outcome, "ok");
    assert!(events[0].error_code.is_none());

    assert_eq!(events[1].event, "criteria_validated");
    assert_eq!(events[1].outcome, "fail");
    assert_eq!(
        events[1].error_code.as_deref(),
        Some(WAVE_HANDOFF_FAILURE_CODE)
    );

    assert_eq!(events[2].event, "ownership_transition_rejected");
    assert_eq!(events[2].outcome, "fail");
    assert_eq!(
        events[2].error_code.as_deref(),
        Some(WAVE_HANDOFF_FAILURE_CODE)
    );
}

#[test]
fn simulation_failure_events_carry_correct_wave_and_packet() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = 0;

    let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    for event in &events {
        assert_eq!(event.wave_id, "wave_1");
        assert_eq!(event.packet_id, "pkt-rgc-wave-1-demo");
    }
}

// ─── Multi-wave contracts ───

#[test]
fn baseline_contract_works_for_all_wave_ids() {
    for wave in [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3] {
        let contract = WaveTransitionContract::baseline(wave);
        assert_eq!(contract.wave_id, wave);
        let pkg = HandoffPackage::baseline();
        let report = validate_handoff("t", "d", "p", &contract, &pkg);
        assert!(
            report.valid,
            "baseline package should pass for {wave:?}: {:?}",
            report.failures
        );
    }
}

#[test]
fn simulation_uses_package_wave_id_string() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave0);
    let mut pkg = HandoffPackage::baseline();
    pkg.wave_id = WaveId::Wave3;
    let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    for event in &events {
        assert_eq!(event.wave_id, "wave_3");
    }
}

// ─── Custom contract with multiple mandatory criteria ───

#[test]
fn custom_contract_with_strict_entry_and_exit_criteria() {
    let contract = WaveTransitionContract {
        contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
        packet_schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        wave_id: WaveId::Wave2,
        minimum_handoff_score_milli: 900,
        entry_criteria: vec![
            WaveCriterion {
                criterion_id: "entry-a".to_string(),
                bead_id: "bd-ea".to_string(),
                required_status: RequiredBeadStatus::Closed,
                required_artifact: "artifacts/ea.json".to_string(),
                mandatory: true,
            },
            WaveCriterion {
                criterion_id: "entry-b".to_string(),
                bead_id: "bd-eb".to_string(),
                required_status: RequiredBeadStatus::InProgress,
                required_artifact: "artifacts/eb.json".to_string(),
                mandatory: true,
            },
        ],
        exit_criteria: vec![WaveCriterion {
            criterion_id: "exit-x".to_string(),
            bead_id: "bd-ex".to_string(),
            required_status: RequiredBeadStatus::Closed,
            required_artifact: "artifacts/ex.json".to_string(),
            mandatory: true,
        }],
    };

    let pkg = HandoffPackage {
        packet_id: "pkt-custom".to_string(),
        wave_id: WaveId::Wave2,
        producer_owner: "alpha".to_string(),
        consumer_owner: "beta".to_string(),
        changed_beads: vec![
            "bd-ea".to_string(),
            "bd-eb".to_string(),
            "bd-ex".to_string(),
        ],
        artifact_links: vec![
            "artifacts/ea.json".to_string(),
            "artifacts/eb.json".to_string(),
            "artifacts/ex.json".to_string(),
        ],
        open_risks: vec!["risk-1".to_string()],
        next_step_recommendations: vec!["proceed".to_string()],
        criteria_attestations: vec![
            CriterionAttestation {
                criterion_id: "entry-a".to_string(),
                bead_id: "bd-ea".to_string(),
                bead_status: RequiredBeadStatus::Closed,
                artifact_ref: "artifacts/ea.json".to_string(),
            },
            CriterionAttestation {
                criterion_id: "entry-b".to_string(),
                bead_id: "bd-eb".to_string(),
                bead_status: RequiredBeadStatus::InProgress,
                artifact_ref: "artifacts/eb.json".to_string(),
            },
            CriterionAttestation {
                criterion_id: "exit-x".to_string(),
                bead_id: "bd-ex".to_string(),
                bead_status: RequiredBeadStatus::Closed,
                artifact_ref: "artifacts/ex.json".to_string(),
            },
        ],
        completeness_score_milli: 950,
    };

    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report.valid,
        "custom package should pass: {:?}",
        report.failures
    );
}

#[test]
fn custom_contract_rejects_partial_attestations() {
    let contract = WaveTransitionContract {
        contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
        packet_schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        wave_id: WaveId::Wave2,
        minimum_handoff_score_milli: 500,
        entry_criteria: vec![
            WaveCriterion {
                criterion_id: "entry-a".to_string(),
                bead_id: "bd-ea".to_string(),
                required_status: RequiredBeadStatus::Closed,
                required_artifact: "artifacts/ea.json".to_string(),
                mandatory: true,
            },
            WaveCriterion {
                criterion_id: "entry-b".to_string(),
                bead_id: "bd-eb".to_string(),
                required_status: RequiredBeadStatus::InProgress,
                required_artifact: "artifacts/eb.json".to_string(),
                mandatory: true,
            },
        ],
        exit_criteria: Vec::new(),
    };

    let pkg = HandoffPackage {
        packet_id: "pkt-partial".to_string(),
        wave_id: WaveId::Wave2,
        producer_owner: "alpha".to_string(),
        consumer_owner: "beta".to_string(),
        changed_beads: vec!["bd-ea".to_string()],
        artifact_links: vec!["artifacts/ea.json".to_string()],
        open_risks: vec!["none".to_string()],
        next_step_recommendations: vec!["fix missing".to_string()],
        criteria_attestations: vec![CriterionAttestation {
            criterion_id: "entry-a".to_string(),
            bead_id: "bd-ea".to_string(),
            bead_status: RequiredBeadStatus::Closed,
            artifact_ref: "artifacts/ea.json".to_string(),
        }],
        completeness_score_milli: 800,
    };

    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| {
        f.code == HandoffValidationErrorCode::MissingCriterionAttestation
            && f.message.contains("entry-b")
    }));
}

// ─── WaveId: as_str, ordering, serde ───

#[test]
fn wave_id_as_str_covers_all_variants() {
    assert_eq!(WaveId::Wave0.as_str(), "wave_0");
    assert_eq!(WaveId::Wave1.as_str(), "wave_1");
    assert_eq!(WaveId::Wave2.as_str(), "wave_2");
    assert_eq!(WaveId::Wave3.as_str(), "wave_3");
}

#[test]
fn wave_id_ordering_is_sequential() {
    assert!(WaveId::Wave0 < WaveId::Wave1);
    assert!(WaveId::Wave1 < WaveId::Wave2);
    assert!(WaveId::Wave2 < WaveId::Wave3);
}

#[test]
fn wave_id_serde_roundtrip_all_variants() {
    for wave in [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3] {
        let json = serde_json::to_string(&wave).unwrap();
        let back: WaveId = serde_json::from_str(&json).unwrap();
        assert_eq!(wave, back);
    }
}

#[test]
fn wave_id_clone_and_copy() {
    let w = WaveId::Wave2;
    let copied1 = w;
    let copied2 = w;
    assert_eq!(w, copied1);
    assert_eq!(w, copied2);
}

// ─── RequiredBeadStatus ───

#[test]
fn required_bead_status_serde_roundtrip_all() {
    for status in [
        RequiredBeadStatus::Open,
        RequiredBeadStatus::InProgress,
        RequiredBeadStatus::Closed,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: RequiredBeadStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn required_bead_status_ordering() {
    assert!(RequiredBeadStatus::Open < RequiredBeadStatus::InProgress);
    assert!(RequiredBeadStatus::InProgress < RequiredBeadStatus::Closed);
}

// ─── WaveTransitionContract serde ───

#[test]
fn wave_transition_contract_serde_roundtrip() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave3);
    let json = serde_json::to_string(&contract).unwrap();
    let back: WaveTransitionContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

#[test]
fn baseline_contract_minimum_score_is_reasonable() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave0);
    assert!(contract.minimum_handoff_score_milli > 0);
    assert!(contract.minimum_handoff_score_milli <= 1000);
}

// ─── HandoffPackage serde ───

#[test]
fn handoff_package_serde_roundtrip() {
    let pkg = HandoffPackage::baseline();
    let json = serde_json::to_string(&pkg).unwrap();
    let back: HandoffPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, back);
}

#[test]
fn handoff_package_json_is_valid_json() {
    let pkg = HandoffPackage::baseline();
    let json = serde_json::to_string_pretty(&pkg).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.is_object());
    assert!(parsed.get("packet_id").is_some());
    assert!(parsed.get("wave_id").is_some());
}

// ─── CriterionAttestation serde ───

#[test]
fn criterion_attestation_serde_roundtrip() {
    let att = CriterionAttestation {
        criterion_id: "c1".to_string(),
        bead_id: "bd-1".to_string(),
        bead_status: RequiredBeadStatus::InProgress,
        artifact_ref: "artifacts/a.json".to_string(),
    };
    let json = serde_json::to_string(&att).unwrap();
    let back: CriterionAttestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att, back);
}

// ─── HandoffValidationErrorCode serde ───

#[test]
fn validation_error_code_serde_roundtrip_all_variants() {
    let codes = [
        HandoffValidationErrorCode::MissingRequiredField,
        HandoffValidationErrorCode::WeakHandoffPackage,
        HandoffValidationErrorCode::MissingCriterionAttestation,
        HandoffValidationErrorCode::CriterionStatusMismatch,
        HandoffValidationErrorCode::CriterionArtifactMissing,
        HandoffValidationErrorCode::CriterionBeadMissing,
    ];
    for code in codes {
        let json = serde_json::to_string(&code).unwrap();
        let back: HandoffValidationErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}

// ─── HandoffValidationReport serde ───

#[test]
fn validation_report_serde_roundtrip() {
    let report = HandoffValidationReport {
        contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: WAVE_HANDOFF_COMPONENT.to_string(),
        event: "validate_handoff".to_string(),
        outcome: "pass".to_string(),
        error_code: "none".to_string(),
        valid: true,
        failures: Vec::new(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: HandoffValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn validation_report_with_failures_serde_roundtrip() {
    let report = HandoffValidationReport {
        contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: WAVE_HANDOFF_COMPONENT.to_string(),
        event: "validate_handoff".to_string(),
        outcome: "fail".to_string(),
        error_code: WAVE_HANDOFF_FAILURE_CODE.to_string(),
        valid: false,
        failures: vec![
            HandoffValidationFailure {
                code: HandoffValidationErrorCode::MissingRequiredField,
                message: "test error 1".to_string(),
            },
            HandoffValidationFailure {
                code: HandoffValidationErrorCode::WeakHandoffPackage,
                message: "test error 2".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: HandoffValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ─── HandoffEvent serde ───

#[test]
fn handoff_event_serde_roundtrip_without_error_code() {
    let event = HandoffEvent {
        schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: WAVE_HANDOFF_COMPONENT.to_string(),
        event: "handoff_received".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        wave_id: "wave_1".to_string(),
        packet_id: "pkt-1".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: HandoffEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn handoff_event_serde_roundtrip_with_error_code() {
    let event = HandoffEvent {
        schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        trace_id: "t2".to_string(),
        decision_id: "d2".to_string(),
        policy_id: "p2".to_string(),
        component: WAVE_HANDOFF_COMPONENT.to_string(),
        event: "criteria_validated".to_string(),
        outcome: "fail".to_string(),
        error_code: Some(WAVE_HANDOFF_FAILURE_CODE.to_string()),
        wave_id: "wave_0".to_string(),
        packet_id: "pkt-2".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: HandoffEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ─── Deterministic behavior ───

#[test]
fn validation_is_deterministic_across_multiple_calls() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let r1 = validate_handoff("t", "d", "p", &contract, &pkg);
    let r2 = validate_handoff("t", "d", "p", &contract, &pkg);
    assert_eq!(
        serde_json::to_string(&r1).unwrap(),
        serde_json::to_string(&r2).unwrap()
    );
}

#[test]
fn simulation_is_deterministic_across_multiple_calls() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let (r1, e1) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    let (r2, e2) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert_eq!(
        serde_json::to_string(&r1).unwrap(),
        serde_json::to_string(&r2).unwrap()
    );
    assert_eq!(
        serde_json::to_string(&e1).unwrap(),
        serde_json::to_string(&e2).unwrap()
    );
}

#[test]
fn different_trace_ids_produce_different_reports() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let r1 = validate_handoff("trace-a", "d", "p", &contract, &pkg);
    let r2 = validate_handoff("trace-b", "d", "p", &contract, &pkg);
    assert_ne!(r1.trace_id, r2.trace_id);
    assert_eq!(r1.valid, r2.valid);
}

// ─── Constants ───

#[test]
fn constants_are_non_empty() {
    assert!(!WAVE_HANDOFF_CONTRACT_VERSION.is_empty());
    assert!(!WAVE_HANDOFF_PACKET_SCHEMA_VERSION.is_empty());
    assert!(!WAVE_HANDOFF_COMPONENT.is_empty());
    assert!(!WAVE_HANDOFF_FAILURE_CODE.is_empty());
}

#[test]
fn failure_code_starts_with_fe_prefix() {
    assert!(
        WAVE_HANDOFF_FAILURE_CODE.starts_with("FE-"),
        "failure code should start with FE- prefix"
    );
}

// ─── WaveCriterion serde ───

#[test]
fn wave_criterion_serde_roundtrip() {
    let c = WaveCriterion {
        criterion_id: "test-crit".to_string(),
        bead_id: "bd-test".to_string(),
        required_status: RequiredBeadStatus::Closed,
        required_artifact: "artifacts/test.json".to_string(),
        mandatory: true,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: WaveCriterion = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ─── HandoffValidationFailure serde ───

#[test]
fn validation_failure_serde_roundtrip() {
    let f = HandoffValidationFailure {
        code: HandoffValidationErrorCode::WeakHandoffPackage,
        message: "score too low".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: HandoffValidationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ─── Edge case: zero-score threshold ───

#[test]
fn validation_zero_threshold_accepts_zero_score() {
    let contract = WaveTransitionContract {
        contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
        packet_schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        wave_id: WaveId::Wave0,
        minimum_handoff_score_milli: 0,
        entry_criteria: Vec::new(),
        exit_criteria: Vec::new(),
    };
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = 0;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        !report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage),
        "zero threshold should accept zero score"
    );
}

// ─── Edge case: max score threshold ───

#[test]
fn validation_max_threshold_rejects_lower_score() {
    let contract = WaveTransitionContract {
        contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
        packet_schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        wave_id: WaveId::Wave3,
        minimum_handoff_score_milli: 1000,
        entry_criteria: Vec::new(),
        exit_criteria: Vec::new(),
    };
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = 999;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report
            .failures
            .iter()
            .any(|f| { f.code == HandoffValidationErrorCode::WeakHandoffPackage })
    );
}

#[test]
fn validation_max_threshold_accepts_max_score() {
    let contract = WaveTransitionContract {
        contract_version: WAVE_HANDOFF_CONTRACT_VERSION.to_string(),
        packet_schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.to_string(),
        wave_id: WaveId::Wave3,
        minimum_handoff_score_milli: 1000,
        entry_criteria: Vec::new(),
        exit_criteria: Vec::new(),
    };
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = 1000;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        !report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage),
        "max score should satisfy max threshold"
    );
}

// ─── Simulation: event count is always 3 ───

#[test]
fn simulation_always_emits_exactly_three_events_on_pass() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave0);
    let pkg = HandoffPackage::baseline();
    let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert_eq!(events.len(), 3);
}

#[test]
fn simulation_always_emits_exactly_three_events_on_fail() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = String::new();
    let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert_eq!(events.len(), 3);
}

// ─── Baseline package attestation coverage ───

#[test]
fn baseline_package_has_attestations_for_all_baseline_criteria() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();

    let attested_ids: Vec<_> = pkg
        .criteria_attestations
        .iter()
        .map(|a| a.criterion_id.as_str())
        .collect();

    for criterion in contract
        .entry_criteria
        .iter()
        .chain(contract.exit_criteria.iter())
        .filter(|c| c.mandatory)
    {
        assert!(
            attested_ids.contains(&criterion.criterion_id.as_str()),
            "baseline package missing attestation for criterion: {}",
            criterion.criterion_id
        );
    }
}

// ─── Display / Debug coverage ───

#[test]
fn wave_id_debug_output_is_readable() {
    let s = format!("{:?}", WaveId::Wave2);
    assert!(s.contains("Wave2"));
}

#[test]
fn handoff_validation_error_code_debug_output() {
    let s = format!("{:?}", HandoffValidationErrorCode::CriterionStatusMismatch);
    assert!(s.contains("CriterionStatusMismatch"));
}

#[test]
fn handoff_package_debug_contains_packet_id() {
    let pkg = HandoffPackage::baseline();
    let s = format!("{:?}", pkg);
    assert!(s.contains("pkt-rgc-wave-1-demo"));
}
