#![forbid(unsafe_code)]
//! Enrichment integration tests for `wave_handoff_contract`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, validation edge cases, factory defaults, and event
//! sequencing beyond the existing 5 integration tests.

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

use frankenengine_engine::wave_handoff_contract::{
    CriterionAttestation, HandoffPackage, HandoffValidationErrorCode, HandoffValidationFailure,
    HandoffValidationReport, RequiredBeadStatus, WAVE_HANDOFF_COMPONENT,
    WAVE_HANDOFF_CONTRACT_VERSION, WAVE_HANDOFF_FAILURE_CODE, WAVE_HANDOFF_PACKET_SCHEMA_VERSION,
    WaveCriterion, WaveId, WaveTransitionContract, simulate_wave_transition, validate_handoff,
};

// ===========================================================================
// 1) WaveId — exact as_str / ordering
// ===========================================================================

#[test]
fn wave_id_as_str_exact() {
    assert_eq!(WaveId::Wave0.as_str(), "wave_0");
    assert_eq!(WaveId::Wave1.as_str(), "wave_1");
    assert_eq!(WaveId::Wave2.as_str(), "wave_2");
    assert_eq!(WaveId::Wave3.as_str(), "wave_3");
}

#[test]
fn wave_id_ordering_stable() {
    let mut waves = vec![WaveId::Wave3, WaveId::Wave0, WaveId::Wave2, WaveId::Wave1];
    waves.sort();
    assert_eq!(
        waves,
        [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3]
    );
}

// ===========================================================================
// 2) RequiredBeadStatus — ordering
// ===========================================================================

#[test]
fn required_bead_status_ordering() {
    assert!(RequiredBeadStatus::Open < RequiredBeadStatus::InProgress);
    assert!(RequiredBeadStatus::InProgress < RequiredBeadStatus::Closed);
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_wave_id() {
    let variants: Vec<String> = [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3]
        .iter()
        .map(|w| format!("{w:?}"))
        .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_required_bead_status() {
    let variants = [
        format!("{:?}", RequiredBeadStatus::Open),
        format!("{:?}", RequiredBeadStatus::InProgress),
        format!("{:?}", RequiredBeadStatus::Closed),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_handoff_validation_error_code() {
    let variants = [
        format!("{:?}", HandoffValidationErrorCode::MissingRequiredField),
        format!("{:?}", HandoffValidationErrorCode::WeakHandoffPackage),
        format!(
            "{:?}",
            HandoffValidationErrorCode::MissingCriterionAttestation
        ),
        format!("{:?}", HandoffValidationErrorCode::CriterionStatusMismatch),
        format!("{:?}", HandoffValidationErrorCode::CriterionArtifactMissing),
        format!("{:?}", HandoffValidationErrorCode::CriterionBeadMissing),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 4) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_wave_id_tags() {
    let waves = [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3];
    let expected = ["\"wave0\"", "\"wave1\"", "\"wave2\"", "\"wave3\""];
    for (w, exp) in waves.iter().zip(expected.iter()) {
        let json = serde_json::to_string(w).unwrap();
        assert_eq!(json, *exp, "WaveId serde tag mismatch for {w:?}");
    }
}

#[test]
fn serde_exact_required_bead_status_tags() {
    let statuses = [
        RequiredBeadStatus::Open,
        RequiredBeadStatus::InProgress,
        RequiredBeadStatus::Closed,
    ];
    let expected = ["\"open\"", "\"in_progress\"", "\"closed\""];
    for (s, exp) in statuses.iter().zip(expected.iter()) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(
            json, *exp,
            "RequiredBeadStatus serde tag mismatch for {s:?}"
        );
    }
}

#[test]
fn serde_exact_handoff_validation_error_code_tags() {
    let codes = [
        HandoffValidationErrorCode::MissingRequiredField,
        HandoffValidationErrorCode::WeakHandoffPackage,
        HandoffValidationErrorCode::MissingCriterionAttestation,
        HandoffValidationErrorCode::CriterionStatusMismatch,
        HandoffValidationErrorCode::CriterionArtifactMissing,
        HandoffValidationErrorCode::CriterionBeadMissing,
    ];
    let expected = [
        "\"missing_required_field\"",
        "\"weak_handoff_package\"",
        "\"missing_criterion_attestation\"",
        "\"criterion_status_mismatch\"",
        "\"criterion_artifact_missing\"",
        "\"criterion_bead_missing\"",
    ];
    for (c, exp) in codes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(c).unwrap();
        assert_eq!(
            json, *exp,
            "HandoffValidationErrorCode serde tag mismatch for {c:?}"
        );
    }
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_wave_criterion() {
    let wc = WaveCriterion {
        criterion_id: "c1".into(),
        bead_id: "b1".into(),
        required_status: RequiredBeadStatus::InProgress,
        required_artifact: "art1".into(),
        mandatory: true,
    };
    let v: serde_json::Value = serde_json::to_value(&wc).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "criterion_id",
        "bead_id",
        "required_status",
        "required_artifact",
        "mandatory",
    ] {
        assert!(obj.contains_key(key), "WaveCriterion missing field: {key}");
    }
}

#[test]
fn json_fields_wave_transition_contract() {
    let wtc = WaveTransitionContract::baseline(WaveId::Wave0);
    let v: serde_json::Value = serde_json::to_value(&wtc).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "contract_version",
        "packet_schema_version",
        "wave_id",
        "minimum_handoff_score_milli",
        "entry_criteria",
        "exit_criteria",
    ] {
        assert!(
            obj.contains_key(key),
            "WaveTransitionContract missing field: {key}"
        );
    }
}

#[test]
fn json_fields_criterion_attestation() {
    let ca = CriterionAttestation {
        criterion_id: "c1".into(),
        bead_id: "b1".into(),
        bead_status: RequiredBeadStatus::Closed,
        artifact_ref: "art1".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&ca).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["criterion_id", "bead_id", "bead_status", "artifact_ref"] {
        assert!(
            obj.contains_key(key),
            "CriterionAttestation missing field: {key}"
        );
    }
}

#[test]
fn json_fields_handoff_package() {
    let hp = HandoffPackage::baseline();
    let v: serde_json::Value = serde_json::to_value(&hp).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "packet_id",
        "wave_id",
        "producer_owner",
        "consumer_owner",
        "changed_beads",
        "artifact_links",
        "open_risks",
        "next_step_recommendations",
        "criteria_attestations",
        "completeness_score_milli",
    ] {
        assert!(obj.contains_key(key), "HandoffPackage missing field: {key}");
    }
}

#[test]
fn json_fields_handoff_validation_failure() {
    let hvf = HandoffValidationFailure {
        code: HandoffValidationErrorCode::MissingRequiredField,
        message: "test".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&hvf).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["code", "message"] {
        assert!(
            obj.contains_key(key),
            "HandoffValidationFailure missing field: {key}"
        );
    }
}

#[test]
fn json_fields_handoff_validation_report() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    let v: serde_json::Value = serde_json::to_value(&report).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "contract_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "valid",
        "failures",
    ] {
        assert!(
            obj.contains_key(key),
            "HandoffValidationReport missing field: {key}"
        );
    }
}

#[test]
fn json_fields_handoff_event() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert!(!events.is_empty());
    let v: serde_json::Value = serde_json::to_value(&events[0]).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "wave_id",
        "packet_id",
    ] {
        assert!(obj.contains_key(key), "HandoffEvent missing field: {key}");
    }
}

// ===========================================================================
// 6) Constants stability
// ===========================================================================

#[test]
fn constants_stable() {
    assert_eq!(
        WAVE_HANDOFF_CONTRACT_VERSION,
        "franken-engine.rgc-wave-handoff.contract.v1"
    );
    assert_eq!(WAVE_HANDOFF_PACKET_SCHEMA_VERSION, "frx.handoff.packet.v1");
    assert_eq!(WAVE_HANDOFF_COMPONENT, "rgc_wave_handoff_contract");
    assert_eq!(WAVE_HANDOFF_FAILURE_CODE, "FE-RGC-015-HANDOFF-0001");
}

// ===========================================================================
// 7) Baseline factories
// ===========================================================================

#[test]
fn baseline_contract_has_criteria() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave0);
    assert_eq!(contract.wave_id, WaveId::Wave0);
    assert_eq!(contract.minimum_handoff_score_milli, 850);
    assert!(!contract.entry_criteria.is_empty());
    assert!(!contract.exit_criteria.is_empty());
    assert_eq!(contract.contract_version, WAVE_HANDOFF_CONTRACT_VERSION);
    assert_eq!(
        contract.packet_schema_version,
        WAVE_HANDOFF_PACKET_SCHEMA_VERSION
    );
}

#[test]
fn baseline_contract_all_waves() {
    for wave in [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3] {
        let contract = WaveTransitionContract::baseline(wave);
        assert_eq!(contract.wave_id, wave);
    }
}

#[test]
fn baseline_package_fields() {
    let pkg = HandoffPackage::baseline();
    assert_eq!(pkg.wave_id, WaveId::Wave1);
    assert_eq!(pkg.completeness_score_milli, 920);
    assert!(!pkg.changed_beads.is_empty());
    assert!(!pkg.artifact_links.is_empty());
    assert!(!pkg.criteria_attestations.is_empty());
}

// ===========================================================================
// 8) validate_handoff — pass case
// ===========================================================================

#[test]
fn validate_handoff_baseline_passes() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(report.valid);
    assert!(report.failures.is_empty());
    assert_eq!(report.outcome, "pass");
    assert_eq!(report.component, WAVE_HANDOFF_COMPONENT);
    assert_eq!(report.event, "validate_handoff");
}

// ===========================================================================
// 9) validate_handoff — failure cases
// ===========================================================================

#[test]
fn validate_handoff_empty_packet_id() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = "".into();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::MissingRequiredField)
    );
}

#[test]
fn validate_handoff_weak_score() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = 100; // well below 850
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage)
    );
}

#[test]
fn validate_handoff_empty_changed_beads() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.changed_beads.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
}

#[test]
fn validate_handoff_preserves_trace_ids() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("my-trace", "my-dec", "my-pol", &contract, &pkg);
    assert_eq!(report.trace_id, "my-trace");
    assert_eq!(report.decision_id, "my-dec");
    assert_eq!(report.policy_id, "my-pol");
}

// ===========================================================================
// 10) simulate_wave_transition — event sequencing
// ===========================================================================

#[test]
fn simulate_wave_transition_3_events_on_pass() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert!(report.valid);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event, "handoff_received");
    assert_eq!(events[1].event, "criteria_validated");
    assert_eq!(events[2].event, "ownership_transition_committed");
}

#[test]
fn simulate_wave_transition_events_share_metadata() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let (_, events) = simulate_wave_transition("trace-x", "dec-y", "pol-z", &contract, &pkg);
    for ev in &events {
        assert_eq!(ev.trace_id, "trace-x");
        assert_eq!(ev.decision_id, "dec-y");
        assert_eq!(ev.policy_id, "pol-z");
        assert_eq!(ev.component, WAVE_HANDOFF_COMPONENT);
    }
}

#[test]
fn simulate_wave_transition_rejected_on_failure() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = "".into();
    let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].event, "ownership_transition_rejected");
    assert_eq!(events[2].outcome, "fail");
    assert!(events[2].error_code.is_some());
}

// ===========================================================================
// 11) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_wave_id() {
    for w in [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3] {
        let json = serde_json::to_string(&w).unwrap();
        let rt: WaveId = serde_json::from_str(&json).unwrap();
        assert_eq!(w, rt);
    }
}

#[test]
fn serde_roundtrip_required_bead_status() {
    for s in [
        RequiredBeadStatus::Open,
        RequiredBeadStatus::InProgress,
        RequiredBeadStatus::Closed,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: RequiredBeadStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_handoff_validation_error_code() {
    let codes = [
        HandoffValidationErrorCode::MissingRequiredField,
        HandoffValidationErrorCode::WeakHandoffPackage,
        HandoffValidationErrorCode::MissingCriterionAttestation,
        HandoffValidationErrorCode::CriterionStatusMismatch,
        HandoffValidationErrorCode::CriterionArtifactMissing,
        HandoffValidationErrorCode::CriterionBeadMissing,
    ];
    for c in &codes {
        let json = serde_json::to_string(c).unwrap();
        let rt: HandoffValidationErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, rt);
    }
}

#[test]
fn serde_roundtrip_wave_transition_contract() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave2);
    let json = serde_json::to_string(&contract).unwrap();
    let rt: WaveTransitionContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, rt);
}

#[test]
fn serde_roundtrip_handoff_package() {
    let pkg = HandoffPackage::baseline();
    let json = serde_json::to_string(&pkg).unwrap();
    let rt: HandoffPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, rt);
}

#[test]
fn serde_roundtrip_handoff_validation_report() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    let json = serde_json::to_string(&report).unwrap();
    let rt: HandoffValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, rt);
}
