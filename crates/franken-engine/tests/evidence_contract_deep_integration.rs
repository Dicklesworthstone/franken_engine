//! Deep integration tests for evidence_contract module.
//!
//! Covers: contract validation exhaustive paths, EV tier boundary values,
//! rollout stage ordering, serde roundtrips, Display impls, version
//! compatibility, and multi-error accumulation.

use frankenengine_engine::evidence_contract::{
    ContractValidationError, ContractVersion, EvTier, EvidenceContract, RolloutStage,
    validate_contract,
};

fn valid_contract() -> EvidenceContract {
    EvidenceContract {
        version: ContractVersion::CURRENT,
        change_summary: "Add deterministic GC".to_string(),
        hotspot_evidence: "GC pauses dominate p99".to_string(),
        ev_score: 3.5,
        ev_tier: EvTier::Positive,
        expected_loss_model: "deploy vs rollback cost".to_string(),
        fallback_trigger: "p99 exceeds threshold".to_string(),
        rollout_stages: vec![
            RolloutStage::Shadow,
            RolloutStage::Canary,
            RolloutStage::Ramp,
            RolloutStage::Default,
        ],
        rollback_command: "cargo run -- rollback".to_string(),
        benchmark_artifacts: "before/after data".to_string(),
    }
}

// ---------------------------------------------------------------------------
// ContractVersion
// ---------------------------------------------------------------------------

#[test]
fn deep_version_current() {
    let v = ContractVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
    assert!(v.is_compatible());
}

#[test]
fn deep_version_compatible_same_major() {
    let v = ContractVersion::new(1, 5);
    assert!(v.is_compatible());
}

#[test]
fn deep_version_incompatible_different_major() {
    let v = ContractVersion::new(2, 0);
    assert!(!v.is_compatible());
}

#[test]
fn deep_version_display() {
    let v = ContractVersion::new(1, 0);
    assert_eq!(format!("{v}"), "1.0");
    let v2 = ContractVersion::new(3, 7);
    assert_eq!(format!("{v2}"), "3.7");
}

#[test]
fn deep_version_serde_roundtrip() {
    let v = ContractVersion::new(1, 0);
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ContractVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// ---------------------------------------------------------------------------
// EvTier
// ---------------------------------------------------------------------------

#[test]
fn deep_ev_tier_from_score_boundaries() {
    assert_eq!(EvTier::from_score(-1.0), EvTier::Reject);
    assert_eq!(EvTier::from_score(0.0), EvTier::Reject);
    assert_eq!(EvTier::from_score(0.99), EvTier::Reject);
    assert_eq!(EvTier::from_score(1.0), EvTier::Marginal);
    assert_eq!(EvTier::from_score(1.99), EvTier::Marginal);
    assert_eq!(EvTier::from_score(2.0), EvTier::Positive);
    assert_eq!(EvTier::from_score(4.99), EvTier::Positive);
    assert_eq!(EvTier::from_score(5.0), EvTier::HighImpact);
    assert_eq!(EvTier::from_score(100.0), EvTier::HighImpact);
}

#[test]
fn deep_ev_tier_meets_threshold() {
    assert!(!EvTier::Reject.meets_threshold());
    assert!(!EvTier::Marginal.meets_threshold());
    assert!(EvTier::Positive.meets_threshold());
    assert!(EvTier::HighImpact.meets_threshold());
}

#[test]
fn deep_ev_tier_display() {
    assert!(format!("{}", EvTier::Reject).contains("reject"));
    assert!(format!("{}", EvTier::Marginal).contains("marginal"));
    assert!(format!("{}", EvTier::Positive).contains("positive"));
    assert!(format!("{}", EvTier::HighImpact).contains("high-impact"));
}

#[test]
fn deep_ev_tier_serde_roundtrip() {
    let tiers = [
        EvTier::Reject,
        EvTier::Marginal,
        EvTier::Positive,
        EvTier::HighImpact,
    ];
    for tier in tiers {
        let json = serde_json::to_string(&tier).unwrap();
        let decoded: EvTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, decoded);
    }
}

// ---------------------------------------------------------------------------
// RolloutStage
// ---------------------------------------------------------------------------

#[test]
fn deep_rollout_stage_display() {
    assert_eq!(format!("{}", RolloutStage::Shadow), "shadow");
    assert_eq!(format!("{}", RolloutStage::Canary), "canary");
    assert_eq!(format!("{}", RolloutStage::Ramp), "ramp");
    assert_eq!(format!("{}", RolloutStage::Default), "default");
}

#[test]
fn deep_rollout_stage_serde_roundtrip() {
    let stages = [
        RolloutStage::Shadow,
        RolloutStage::Canary,
        RolloutStage::Ramp,
        RolloutStage::Default,
    ];
    for stage in stages {
        let json = serde_json::to_string(&stage).unwrap();
        let decoded: RolloutStage = serde_json::from_str(&json).unwrap();
        assert_eq!(stage, decoded);
    }
}

// ---------------------------------------------------------------------------
// Validation — valid contract
// ---------------------------------------------------------------------------

#[test]
fn deep_valid_contract_passes() {
    assert!(valid_contract().validate().is_ok());
}

#[test]
fn deep_valid_contract_validate_fn_returns_empty() {
    let errors = validate_contract(&valid_contract());
    assert!(errors.is_empty());
}

// ---------------------------------------------------------------------------
// Validation — missing fields
// ---------------------------------------------------------------------------

#[test]
fn deep_missing_each_field() {
    let fields = [
        "change_summary",
        "hotspot_evidence",
        "expected_loss_model",
        "fallback_trigger",
        "rollback_command",
        "benchmark_artifacts",
    ];

    for field_name in fields {
        let mut contract = valid_contract();
        match field_name {
            "change_summary" => contract.change_summary = "".to_string(),
            "hotspot_evidence" => contract.hotspot_evidence = "".to_string(),
            "expected_loss_model" => contract.expected_loss_model = "".to_string(),
            "fallback_trigger" => contract.fallback_trigger = "".to_string(),
            "rollback_command" => contract.rollback_command = "".to_string(),
            "benchmark_artifacts" => contract.benchmark_artifacts = "".to_string(),
            _ => unreachable!(),
        }
        let errors = contract.validate().unwrap_err();
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ContractValidationError::MissingField { field } if field == field_name
            )),
            "Missing field {} should be detected",
            field_name
        );
    }
}

#[test]
fn deep_whitespace_only_fields_detected() {
    let mut contract = valid_contract();
    contract.change_summary = "   \t\n  ".to_string();
    let errors = contract.validate().unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ContractValidationError::MissingField { field } if field == "change_summary"
    )));
}

#[test]
fn deep_all_fields_empty_six_errors() {
    let contract = EvidenceContract {
        version: ContractVersion::CURRENT,
        change_summary: String::new(),
        hotspot_evidence: String::new(),
        ev_score: 3.0,
        ev_tier: EvTier::Positive,
        expected_loss_model: String::new(),
        fallback_trigger: String::new(),
        rollout_stages: vec![RolloutStage::Shadow],
        rollback_command: String::new(),
        benchmark_artifacts: String::new(),
    };
    let errors = contract.validate().unwrap_err();
    let missing = errors
        .iter()
        .filter(|e| matches!(e, ContractValidationError::MissingField { .. }))
        .count();
    assert_eq!(missing, 6);
}

// ---------------------------------------------------------------------------
// Validation — EV score
// ---------------------------------------------------------------------------

#[test]
fn deep_ev_nan_fails() {
    let mut contract = valid_contract();
    contract.ev_score = f64::NAN;
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
    );
}

#[test]
fn deep_ev_positive_infinity_fails() {
    let mut contract = valid_contract();
    contract.ev_score = f64::INFINITY;
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
    );
}

#[test]
fn deep_ev_negative_infinity_fails() {
    let mut contract = valid_contract();
    contract.ev_score = f64::NEG_INFINITY;
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
    );
}

#[test]
fn deep_ev_tier_mismatch_detected() {
    let mut contract = valid_contract();
    contract.ev_score = 3.0; // should be Positive
    contract.ev_tier = EvTier::HighImpact; // wrong
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvTierMismatch { .. }))
    );
}

#[test]
fn deep_ev_below_threshold_detected() {
    let mut contract = valid_contract();
    contract.ev_score = 1.5;
    contract.ev_tier = EvTier::Marginal;
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
    );
}

#[test]
fn deep_ev_reject_tier_below_threshold() {
    let mut contract = valid_contract();
    contract.ev_score = 0.5;
    contract.ev_tier = EvTier::Reject;
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
    );
}

#[test]
fn deep_ev_exactly_2_passes() {
    let mut contract = valid_contract();
    contract.ev_score = 2.0;
    contract.ev_tier = EvTier::Positive;
    assert!(contract.validate().is_ok());
}

#[test]
fn deep_ev_exactly_5_high_impact() {
    let mut contract = valid_contract();
    contract.ev_score = 5.0;
    contract.ev_tier = EvTier::HighImpact;
    assert!(contract.validate().is_ok());
}

// ---------------------------------------------------------------------------
// Validation — rollout stages
// ---------------------------------------------------------------------------

#[test]
fn deep_empty_rollout_fails() {
    let mut contract = valid_contract();
    contract.rollout_stages.clear();
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EmptyRolloutStages))
    );
}

#[test]
fn deep_single_stage_passes() {
    let mut contract = valid_contract();
    contract.rollout_stages = vec![RolloutStage::Shadow];
    assert!(contract.validate().is_ok());
}

#[test]
fn deep_correct_ordering_passes() {
    let mut contract = valid_contract();
    contract.rollout_stages = vec![
        RolloutStage::Shadow,
        RolloutStage::Canary,
        RolloutStage::Ramp,
        RolloutStage::Default,
    ];
    assert!(contract.validate().is_ok());
}

#[test]
fn deep_wrong_ordering_fails() {
    let mut contract = valid_contract();
    contract.rollout_stages = vec![
        RolloutStage::Canary,
        RolloutStage::Shadow, // wrong: shadow after canary
    ];
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidRolloutOrder { .. }))
    );
}

#[test]
fn deep_duplicate_stages_pass() {
    // Same stage repeated is fine (not going backward)
    let mut contract = valid_contract();
    contract.rollout_stages = vec![RolloutStage::Shadow, RolloutStage::Shadow];
    assert!(contract.validate().is_ok());
}

// ---------------------------------------------------------------------------
// Validation — version incompatibility
// ---------------------------------------------------------------------------

#[test]
fn deep_incompatible_version_detected() {
    let mut contract = valid_contract();
    contract.version = ContractVersion::new(2, 0);
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::IncompatibleVersion { .. }))
    );
}

#[test]
fn deep_compatible_minor_version_passes() {
    let mut contract = valid_contract();
    contract.version = ContractVersion::new(1, 5);
    assert!(contract.validate().is_ok());
}

// ---------------------------------------------------------------------------
// ContractValidationError Display
// ---------------------------------------------------------------------------

#[test]
fn deep_error_display_missing_field() {
    let e = ContractValidationError::MissingField {
        field: "change_summary".to_string(),
    };
    let display = format!("{e}");
    assert!(display.contains("change_summary"));
    assert!(display.contains("missing"));
}

#[test]
fn deep_error_display_ev_below() {
    let e = ContractValidationError::EvBelowThreshold {
        score_str: "1.50".to_string(),
        tier: "marginal".to_string(),
    };
    let display = format!("{e}");
    assert!(display.contains("1.50"));
    assert!(display.contains("below"));
}

#[test]
fn deep_error_display_ev_mismatch() {
    let e = ContractValidationError::EvTierMismatch {
        score_str: "3.00".to_string(),
        declared_tier: "high-impact".to_string(),
        expected_tier: "positive".to_string(),
    };
    let display = format!("{e}");
    assert!(display.contains("mismatch"));
}

#[test]
fn deep_error_display_invalid_order() {
    let e = ContractValidationError::InvalidRolloutOrder {
        stage: "shadow".to_string(),
        position: 1,
    };
    let display = format!("{e}");
    assert!(display.contains("shadow"));
    assert!(display.contains("position 1"));
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn deep_contract_serde_roundtrip() {
    let contract = valid_contract();
    let json = serde_json::to_string(&contract).unwrap();
    let decoded: EvidenceContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract.version, decoded.version);
    assert_eq!(contract.change_summary, decoded.change_summary);
    assert_eq!(contract.ev_score, decoded.ev_score);
    assert_eq!(contract.ev_tier, decoded.ev_tier);
    assert_eq!(contract.rollout_stages, decoded.rollout_stages);
}

#[test]
fn deep_validation_error_serde_roundtrip() {
    let errors = [
        ContractValidationError::MissingField {
            field: "test".to_string(),
        },
        ContractValidationError::EmptyRolloutStages,
        ContractValidationError::InvalidEvScore,
        ContractValidationError::IncompatibleVersion {
            version: "2.0".to_string(),
        },
    ];
    for error in &errors {
        let json = serde_json::to_string(error).unwrap();
        let decoded: ContractValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*error, decoded);
    }
}

// ---------------------------------------------------------------------------
// Multi-error accumulation
// ---------------------------------------------------------------------------

#[test]
fn deep_multiple_errors_accumulated() {
    let contract = EvidenceContract {
        version: ContractVersion::new(2, 0), // incompatible
        change_summary: String::new(),       // missing
        hotspot_evidence: "ok".to_string(),
        ev_score: 0.5, // below threshold
        ev_tier: EvTier::Reject,
        expected_loss_model: "ok".to_string(),
        fallback_trigger: "ok".to_string(),
        rollout_stages: vec![], // empty
        rollback_command: "ok".to_string(),
        benchmark_artifacts: "ok".to_string(),
    };
    let errors = contract.validate().unwrap_err();
    assert!(
        errors.len() >= 3,
        "Should have multiple errors: {:?}",
        errors
    );
    // Should include: IncompatibleVersion, MissingField, EvBelowThreshold, EmptyRolloutStages
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::IncompatibleVersion { .. }))
    );
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::MissingField { .. }))
    );
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EmptyRolloutStages))
    );
}
