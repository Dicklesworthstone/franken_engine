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

// ===========================================================================
// 12) validate_handoff — empty producer_owner
// ===========================================================================

#[test]
fn validate_handoff_empty_producer_owner() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.producer_owner = "".into();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| f.code
        == HandoffValidationErrorCode::MissingRequiredField
        && f.message.contains("producer_owner")));
}

// ===========================================================================
// 13) validate_handoff — empty consumer_owner
// ===========================================================================

#[test]
fn validate_handoff_empty_consumer_owner() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.consumer_owner = "".into();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| f.code
        == HandoffValidationErrorCode::MissingRequiredField
        && f.message.contains("consumer_owner")));
}

// ===========================================================================
// 14) validate_handoff — empty artifact_links
// ===========================================================================

#[test]
fn validate_handoff_empty_artifact_links() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.artifact_links.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| f.code
        == HandoffValidationErrorCode::MissingRequiredField
        && f.message.contains("artifact_links")));
}

// ===========================================================================
// 15) validate_handoff — empty next_step_recommendations
// ===========================================================================

#[test]
fn validate_handoff_empty_next_step_recommendations() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.next_step_recommendations.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| f.code
        == HandoffValidationErrorCode::MissingRequiredField
        && f.message.contains("next_step_recommendations")));
}

// ===========================================================================
// 16) validate_handoff — whitespace-only packet_id treated as empty
// ===========================================================================

#[test]
fn validate_handoff_whitespace_only_packet_id() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = "   ".into();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(report.failures.iter().any(|f| f.code
        == HandoffValidationErrorCode::MissingRequiredField
        && f.message.contains("packet_id")));
}

// ===========================================================================
// 17) validate_handoff — missing criterion attestation
// ===========================================================================

#[test]
fn validate_handoff_missing_criterion_attestation() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.criteria_attestations.clear();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::MissingCriterionAttestation)
    );
}

// ===========================================================================
// 18) validate_handoff — criterion status mismatch
// ===========================================================================

#[test]
fn validate_handoff_criterion_status_mismatch() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    for att in &mut pkg.criteria_attestations {
        att.bead_status = RequiredBeadStatus::Closed;
    }
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::CriterionStatusMismatch)
    );
}

// ===========================================================================
// 19) validate_handoff — criterion bead_id mismatch
// ===========================================================================

#[test]
fn validate_handoff_criterion_bead_id_mismatch() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    for att in &mut pkg.criteria_attestations {
        att.bead_id = "bd-wrong".into();
    }
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::CriterionBeadMissing)
    );
}

// ===========================================================================
// 20) validate_handoff — criterion artifact mismatch
// ===========================================================================

#[test]
fn validate_handoff_criterion_artifact_mismatch() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    for att in &mut pkg.criteria_attestations {
        att.artifact_ref = "wrong/path.json".into();
    }
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == HandoffValidationErrorCode::CriterionArtifactMissing)
    );
}

// ===========================================================================
// 21) validate_handoff — multiple failures accumulate
// ===========================================================================

#[test]
fn validate_handoff_accumulates_multiple_failures() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = "".into();
    pkg.producer_owner = "".into();
    pkg.consumer_owner = "".into();
    pkg.completeness_score_milli = 0;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    assert!(
        report.failures.len() >= 4,
        "expected at least 4 failures, got {}",
        report.failures.len()
    );
    assert_eq!(report.outcome, "fail");
    assert_eq!(report.error_code, WAVE_HANDOFF_FAILURE_CODE);
}

// ===========================================================================
// 22) validate_handoff — optional criterion is ignored
// ===========================================================================

#[test]
fn validate_handoff_optional_criterion_ignored() {
    let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
    contract.entry_criteria.push(WaveCriterion {
        criterion_id: "opt-crit".into(),
        bead_id: "bd-opt".into(),
        required_status: RequiredBeadStatus::Closed,
        required_artifact: "none".into(),
        mandatory: false,
    });
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    // The optional criterion should NOT produce any failures
    let opt_failures: Vec<_> = report
        .failures
        .iter()
        .filter(|f| f.message.contains("opt-crit"))
        .collect();
    assert!(
        opt_failures.is_empty(),
        "optional criterion should not produce failures"
    );
}

// ===========================================================================
// 23) Clone semantics for non-Copy types
// ===========================================================================

#[test]
fn clone_wave_criterion() {
    let wc = WaveCriterion {
        criterion_id: "c1".into(),
        bead_id: "b1".into(),
        required_status: RequiredBeadStatus::InProgress,
        required_artifact: "art1".into(),
        mandatory: true,
    };
    let cloned = wc.clone();
    assert_eq!(wc, cloned);
}

#[test]
fn clone_handoff_package() {
    let pkg = HandoffPackage::baseline();
    let cloned = pkg.clone();
    assert_eq!(pkg, cloned);
}

#[test]
fn clone_handoff_validation_failure() {
    let f = HandoffValidationFailure {
        code: HandoffValidationErrorCode::WeakHandoffPackage,
        message: "score too low".into(),
    };
    let cloned = f.clone();
    assert_eq!(f, cloned);
}

#[test]
fn clone_handoff_validation_report() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = "".into();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    let cloned = report.clone();
    assert_eq!(report, cloned);
    assert!(!cloned.valid);
    assert!(!cloned.failures.is_empty());
}

// ===========================================================================
// 24) Serde roundtrips for WaveCriterion and HandoffEvent
// ===========================================================================

#[test]
fn serde_roundtrip_wave_criterion() {
    let wc = WaveCriterion {
        criterion_id: "c-test".into(),
        bead_id: "bd-test".into(),
        required_status: RequiredBeadStatus::Closed,
        required_artifact: "artifacts/test.json".into(),
        mandatory: false,
    };
    let json = serde_json::to_string(&wc).unwrap();
    let rt: WaveCriterion = serde_json::from_str(&json).unwrap();
    assert_eq!(wc, rt);
}

#[test]
fn serde_roundtrip_handoff_validation_failure() {
    let f = HandoffValidationFailure {
        code: HandoffValidationErrorCode::CriterionArtifactMissing,
        message: "artifact not found in links".into(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let rt: HandoffValidationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, rt);
}

// ===========================================================================
// 25) simulate_wave_transition — event wave_id and packet_id propagation
// ===========================================================================

#[test]
fn simulate_events_contain_wave_and_packet_id() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    for ev in &events {
        assert_eq!(ev.wave_id, pkg.wave_id.as_str());
        assert_eq!(ev.packet_id, pkg.packet_id);
    }
}

// ===========================================================================
// 26) validate_handoff — no criteria contract passes field checks
// ===========================================================================

#[test]
fn validate_handoff_no_criteria_passes_field_checks() {
    let mut contract = WaveTransitionContract::baseline(WaveId::Wave1);
    contract.entry_criteria.clear();
    contract.exit_criteria.clear();
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    // With no criteria, no criterion-related failures should appear
    let crit_failures: Vec<_> = report
        .failures
        .iter()
        .filter(|f| {
            matches!(
                f.code,
                HandoffValidationErrorCode::MissingCriterionAttestation
                    | HandoffValidationErrorCode::CriterionStatusMismatch
                    | HandoffValidationErrorCode::CriterionArtifactMissing
                    | HandoffValidationErrorCode::CriterionBeadMissing
            )
        })
        .collect();
    assert!(
        crit_failures.is_empty(),
        "no criteria means no criterion failures"
    );
}

// ===========================================================================
// 27) validate_handoff — score exactly at threshold passes score check
// ===========================================================================

#[test]
fn validate_handoff_score_at_threshold_no_weak_failure() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = contract.minimum_handoff_score_milli;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    let weak_failures: Vec<_> = report
        .failures
        .iter()
        .filter(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage)
        .collect();
    assert!(
        weak_failures.is_empty(),
        "score at threshold should not produce weak failure"
    );
}

// ===========================================================================
// 28) simulate_wave_transition — first event always ok, no error_code
// ===========================================================================

#[test]
fn simulate_first_event_always_ok() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let (_, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert_eq!(events[0].event, "handoff_received");
    assert_eq!(events[0].outcome, "ok");
    assert!(events[0].error_code.is_none());
}

#[test]
fn simulate_first_event_ok_even_on_failure() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = "".into();
    let (report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert!(!report.valid);
    // First event is always "handoff_received" with outcome "ok"
    assert_eq!(events[0].event, "handoff_received");
    assert_eq!(events[0].outcome, "ok");
    assert!(events[0].error_code.is_none());
}

// ===========================================================================
// 29) WaveId as_str determinism — calling multiple times yields same result
// ===========================================================================

#[test]
fn wave_id_as_str_deterministic() {
    for wave in [WaveId::Wave0, WaveId::Wave1, WaveId::Wave2, WaveId::Wave3] {
        let s1 = wave.as_str();
        let s2 = wave.as_str();
        assert_eq!(s1, s2, "as_str must be deterministic for {wave:?}");
    }
}

// ===========================================================================
// 30) Serde deserialization from explicit JSON strings
// ===========================================================================

#[test]
fn serde_deserialize_wave_id_from_known_json() {
    let w: WaveId = serde_json::from_str("\"wave0\"").unwrap();
    assert_eq!(w, WaveId::Wave0);
    let w: WaveId = serde_json::from_str("\"wave3\"").unwrap();
    assert_eq!(w, WaveId::Wave3);
}

#[test]
fn serde_deserialize_required_bead_status_from_known_json() {
    let s: RequiredBeadStatus = serde_json::from_str("\"open\"").unwrap();
    assert_eq!(s, RequiredBeadStatus::Open);
    let s: RequiredBeadStatus = serde_json::from_str("\"in_progress\"").unwrap();
    assert_eq!(s, RequiredBeadStatus::InProgress);
    let s: RequiredBeadStatus = serde_json::from_str("\"closed\"").unwrap();
    assert_eq!(s, RequiredBeadStatus::Closed);
}

#[test]
fn serde_deserialize_invalid_wave_id_fails() {
    let result = serde_json::from_str::<WaveId>("\"wave99\"");
    assert!(result.is_err());
}

#[test]
fn serde_deserialize_invalid_bead_status_fails() {
    let result = serde_json::from_str::<RequiredBeadStatus>("\"deleted\"");
    assert!(result.is_err());
}

// ===========================================================================
// 31) Serde roundtrip for HandoffEvent (with and without error_code)
// ===========================================================================

#[test]
fn serde_roundtrip_handoff_event_no_error() {
    use frankenengine_engine::wave_handoff_contract::HandoffEvent;
    let event = HandoffEvent {
        schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.into(),
        trace_id: "t-rt".into(),
        decision_id: "d-rt".into(),
        policy_id: "p-rt".into(),
        component: WAVE_HANDOFF_COMPONENT.into(),
        event: "handoff_received".into(),
        outcome: "ok".into(),
        error_code: None,
        wave_id: "wave_1".into(),
        packet_id: "pkt-rt".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: HandoffEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

#[test]
fn serde_roundtrip_handoff_event_with_error() {
    use frankenengine_engine::wave_handoff_contract::HandoffEvent;
    let event = HandoffEvent {
        schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.into(),
        trace_id: "t-err".into(),
        decision_id: "d-err".into(),
        policy_id: "p-err".into(),
        component: WAVE_HANDOFF_COMPONENT.into(),
        event: "criteria_validated".into(),
        outcome: "fail".into(),
        error_code: Some(WAVE_HANDOFF_FAILURE_CODE.into()),
        wave_id: "wave_0".into(),
        packet_id: "pkt-err".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: HandoffEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

// ===========================================================================
// 32) Serde pretty-print roundtrip — validates multi-line JSON survives
// ===========================================================================

#[test]
fn serde_pretty_roundtrip_handoff_package() {
    let pkg = HandoffPackage::baseline();
    let pretty = serde_json::to_string_pretty(&pkg).unwrap();
    let rt: HandoffPackage = serde_json::from_str(&pretty).unwrap();
    assert_eq!(pkg, rt);
}

#[test]
fn serde_pretty_roundtrip_wave_transition_contract() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave3);
    let pretty = serde_json::to_string_pretty(&contract).unwrap();
    let rt: WaveTransitionContract = serde_json::from_str(&pretty).unwrap();
    assert_eq!(contract, rt);
}

// ===========================================================================
// 33) JSON field count stability — no extra or missing fields
// ===========================================================================

#[test]
fn json_field_count_wave_criterion() {
    let wc = WaveCriterion {
        criterion_id: "c".into(),
        bead_id: "b".into(),
        required_status: RequiredBeadStatus::Open,
        required_artifact: "a".into(),
        mandatory: false,
    };
    let v: serde_json::Value = serde_json::to_value(&wc).unwrap();
    assert_eq!(
        v.as_object().unwrap().len(),
        5,
        "WaveCriterion should have exactly 5 fields"
    );
}

#[test]
fn json_field_count_criterion_attestation() {
    let ca = CriterionAttestation {
        criterion_id: "c".into(),
        bead_id: "b".into(),
        bead_status: RequiredBeadStatus::Closed,
        artifact_ref: "a".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&ca).unwrap();
    assert_eq!(
        v.as_object().unwrap().len(),
        4,
        "CriterionAttestation should have exactly 4 fields"
    );
}

#[test]
fn json_field_count_handoff_package() {
    let pkg = HandoffPackage::baseline();
    let v: serde_json::Value = serde_json::to_value(&pkg).unwrap();
    assert_eq!(
        v.as_object().unwrap().len(),
        10,
        "HandoffPackage should have exactly 10 fields"
    );
}

#[test]
fn json_field_count_handoff_validation_report() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    let v: serde_json::Value = serde_json::to_value(&report).unwrap();
    assert_eq!(
        v.as_object().unwrap().len(),
        10,
        "HandoffValidationReport should have exactly 10 fields"
    );
}

// ===========================================================================
// 34) Validation determinism — same inputs produce identical reports
// ===========================================================================

#[test]
fn validate_handoff_deterministic_output() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let r1 = validate_handoff("t", "d", "p", &contract, &pkg);
    let r2 = validate_handoff("t", "d", "p", &contract, &pkg);
    assert_eq!(r1, r2, "identical inputs must produce identical reports");
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2, "serialized JSON must be byte-identical");
}

#[test]
fn simulate_wave_transition_deterministic_output() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let pkg = HandoffPackage::baseline();
    let (r1, e1) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    let (r2, e2) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert_eq!(r1, r2);
    assert_eq!(e1, e2);
}

// ===========================================================================
// 35) Score boundary: one above threshold passes score check
// ===========================================================================

#[test]
fn validate_handoff_score_one_above_threshold_no_weak_failure() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = contract.minimum_handoff_score_milli + 1;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    let weak: Vec<_> = report
        .failures
        .iter()
        .filter(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage)
        .collect();
    assert!(
        weak.is_empty(),
        "score above threshold should not produce weak failure"
    );
}

// ===========================================================================
// 36) Entry vs exit criterion failure message distinguishes phase
// ===========================================================================

#[test]
fn validate_handoff_entry_criterion_failure_says_entry() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    // Remove only the entry attestation so an entry criterion fails
    pkg.criteria_attestations
        .retain(|a| a.criterion_id != "entry-ready-deps");
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report.failures.iter().any(|f| f.code
            == HandoffValidationErrorCode::MissingCriterionAttestation
            && f.message.contains("entry")),
        "entry criterion failure message should mention 'entry'"
    );
}

#[test]
fn validate_handoff_exit_criterion_failure_says_exit() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    // Remove only exit attestations so exit criteria fail
    pkg.criteria_attestations
        .retain(|a| a.criterion_id == "entry-ready-deps");
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report.failures.iter().any(|f| f.code
            == HandoffValidationErrorCode::MissingCriterionAttestation
            && f.message.contains("exit")),
        "exit criterion failure message should mention 'exit'"
    );
}

// ===========================================================================
// 37) HandoffEvent error_code serializes as null when None
// ===========================================================================

#[test]
fn handoff_event_error_code_null_in_json() {
    use frankenengine_engine::wave_handoff_contract::HandoffEvent;
    let event = HandoffEvent {
        schema_version: WAVE_HANDOFF_PACKET_SCHEMA_VERSION.into(),
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: WAVE_HANDOFF_COMPONENT.into(),
        event: "handoff_received".into(),
        outcome: "ok".into(),
        error_code: None,
        wave_id: "wave_0".into(),
        packet_id: "pkt".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&event).unwrap();
    assert!(
        v["error_code"].is_null(),
        "None error_code should serialize as null"
    );
}

// ===========================================================================
// 38) Bead attested but not in changed_beads triggers CriterionBeadMissing
// ===========================================================================

#[test]
fn validate_handoff_attested_bead_not_in_changed_beads() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    // Keep attestations correct but remove their beads from changed_beads
    pkg.changed_beads = vec!["bd-unrelated-only".into()];
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report.failures.iter().any(
            |f| f.code == HandoffValidationErrorCode::CriterionBeadMissing
                && f.message.contains("changed_beads")
        ),
        "attestation referencing bead not in changed_beads should fail"
    );
}

// ===========================================================================
// 39) Attested artifact not in artifact_links triggers CriterionArtifactMissing
// ===========================================================================

#[test]
fn validate_handoff_attested_artifact_not_in_artifact_links() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    // Keep attestations correct but remove their artifacts from artifact_links
    pkg.artifact_links = vec!["some/other/artifact.json".into()];
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    assert!(
        report.failures.iter().any(|f| f.code
            == HandoffValidationErrorCode::CriterionArtifactMissing
            && f.message.contains("artifact_links")),
        "attestation referencing artifact not in artifact_links should fail"
    );
}

// ===========================================================================
// 40) Simulate rejected: second event carries error_code
// ===========================================================================

#[test]
fn simulate_rejected_second_event_has_error_code() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.packet_id = "".into();
    let (_report, events) = simulate_wave_transition("t", "d", "p", &contract, &pkg);
    assert_eq!(events[1].event, "criteria_validated");
    assert_eq!(events[1].outcome, "fail");
    assert_eq!(
        events[1].error_code,
        Some(WAVE_HANDOFF_FAILURE_CODE.into()),
        "criteria_validated event on failure must carry the error code"
    );
}

// ===========================================================================
// 41) Serde roundtrip with unicode in string fields
// ===========================================================================

#[test]
fn serde_roundtrip_unicode_strings() {
    let mut pkg = HandoffPackage::baseline();
    pkg.producer_owner = "agent_\u{03B1}\u{03B2}".into();
    pkg.consumer_owner = "agent_\u{2603}".into();
    pkg.open_risks = vec!["risk with \u{1F525} emoji".into()];
    let json = serde_json::to_string(&pkg).unwrap();
    let rt: HandoffPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, rt);
    assert_eq!(rt.producer_owner, "agent_\u{03B1}\u{03B2}");
}

// ===========================================================================
// 42) validate_handoff: max u16 completeness score passes score check
// ===========================================================================

#[test]
fn validate_handoff_max_score_passes() {
    let contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let mut pkg = HandoffPackage::baseline();
    pkg.completeness_score_milli = u16::MAX;
    let report = validate_handoff("t", "d", "p", &contract, &pkg);
    let weak: Vec<_> = report
        .failures
        .iter()
        .filter(|f| f.code == HandoffValidationErrorCode::WeakHandoffPackage)
        .collect();
    assert!(
        weak.is_empty(),
        "max u16 score should always pass threshold"
    );
}
