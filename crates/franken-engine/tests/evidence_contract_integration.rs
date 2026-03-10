#![forbid(unsafe_code)]

//! Integration tests for the `evidence_contract` module.
//!
//! Covers construction and validation of `EvidenceContract`, `ContractVersion`,
//! `EvTier`, `RolloutStage`, `ContractValidationError`, and `validate_contract`.
//! Tests Display impls, serde roundtrips, boundary conditions, multi-error
//! accumulation, deterministic replay, and all public API surfaces.

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

use frankenengine_engine::evidence_contract::{
    ContractValidationError, ContractVersion, EvTier, EvidenceContract, RolloutStage,
    validate_contract,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn valid_contract() -> EvidenceContract {
    EvidenceContract {
        version: ContractVersion::CURRENT,
        change_summary: "Add deterministic GC with per-extension isolation".to_string(),
        hotspot_evidence: "Profile shows GC pauses dominate p99 latency at 15ms".to_string(),
        ev_score: 3.5,
        ev_tier: EvTier::Positive,
        expected_loss_model:
            "Action: deploy GC, Loss(no-deploy)=high latency, Loss(deploy-bad)=rollback cost ~2h"
                .to_string(),
        fallback_trigger: "p99 GC pause exceeds 10ms for 5 consecutive minutes".to_string(),
        rollout_stages: vec![
            RolloutStage::Shadow,
            RolloutStage::Canary,
            RolloutStage::Ramp,
            RolloutStage::Default,
        ],
        rollback_command: "cargo run -- rollback gc-v1".to_string(),
        benchmark_artifacts: "Before: p99=15ms, After: p99=3ms. Golden hash: abc123".to_string(),
    }
}

// ---------------------------------------------------------------------------
// ContractVersion
// ---------------------------------------------------------------------------

#[test]
fn contract_version_current_is_1_0() {
    let v = ContractVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
}

#[test]
fn contract_version_new_stores_fields() {
    let v = ContractVersion::new(5, 12);
    assert_eq!(v.major, 5);
    assert_eq!(v.minor, 12);
}

#[test]
fn contract_version_is_compatible_same_major() {
    assert!(ContractVersion::new(1, 0).is_compatible());
    assert!(ContractVersion::new(1, 99).is_compatible());
}

#[test]
fn contract_version_incompatible_different_major() {
    assert!(!ContractVersion::new(0, 0).is_compatible());
    assert!(!ContractVersion::new(2, 0).is_compatible());
    assert!(!ContractVersion::new(99, 1).is_compatible());
}

#[test]
fn contract_version_display() {
    assert_eq!(ContractVersion::CURRENT.to_string(), "1.0");
    assert_eq!(ContractVersion::new(3, 7).to_string(), "3.7");
    assert_eq!(ContractVersion::new(0, 0).to_string(), "0.0");
}

#[test]
fn contract_version_ordering() {
    let v1_0 = ContractVersion::new(1, 0);
    let v1_5 = ContractVersion::new(1, 5);
    let v2_0 = ContractVersion::new(2, 0);
    assert!(v1_0 < v1_5);
    assert!(v1_5 < v2_0);
    assert_eq!(v1_0, ContractVersion::new(1, 0));
}

#[test]
fn contract_version_serde_roundtrip() {
    let v = ContractVersion::new(3, 14);
    let json = serde_json::to_string(&v).expect("serialize");
    let restored: ContractVersion = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, restored);
}

// ---------------------------------------------------------------------------
// EvTier
// ---------------------------------------------------------------------------

#[test]
fn ev_tier_from_score_reject() {
    assert_eq!(EvTier::from_score(-100.0), EvTier::Reject);
    assert_eq!(EvTier::from_score(0.0), EvTier::Reject);
    assert_eq!(EvTier::from_score(0.999), EvTier::Reject);
}

#[test]
fn ev_tier_from_score_marginal() {
    assert_eq!(EvTier::from_score(1.0), EvTier::Marginal);
    assert_eq!(EvTier::from_score(1.5), EvTier::Marginal);
    assert_eq!(EvTier::from_score(1.999), EvTier::Marginal);
}

#[test]
fn ev_tier_from_score_positive() {
    assert_eq!(EvTier::from_score(2.0), EvTier::Positive);
    assert_eq!(EvTier::from_score(3.5), EvTier::Positive);
    assert_eq!(EvTier::from_score(4.999), EvTier::Positive);
}

#[test]
fn ev_tier_from_score_high_impact() {
    assert_eq!(EvTier::from_score(5.0), EvTier::HighImpact);
    assert_eq!(EvTier::from_score(100.0), EvTier::HighImpact);
    assert_eq!(EvTier::from_score(999_999.0), EvTier::HighImpact);
}

#[test]
fn ev_tier_meets_threshold() {
    assert!(!EvTier::Reject.meets_threshold());
    assert!(!EvTier::Marginal.meets_threshold());
    assert!(EvTier::Positive.meets_threshold());
    assert!(EvTier::HighImpact.meets_threshold());
}

#[test]
fn ev_tier_display_contains_range_info() {
    let d = EvTier::Reject.to_string();
    assert!(d.contains("reject") && d.contains("EV < 1.0"));

    let d = EvTier::Marginal.to_string();
    assert!(d.contains("marginal") && d.contains("1.0") && d.contains("2.0"));

    let d = EvTier::Positive.to_string();
    assert!(d.contains("positive") && d.contains("2.0") && d.contains("5.0"));

    let d = EvTier::HighImpact.to_string();
    assert!(d.contains("high-impact") && d.contains("EV >= 5.0"));
}

#[test]
fn ev_tier_serde_roundtrip() {
    let tiers = [
        EvTier::Reject,
        EvTier::Marginal,
        EvTier::Positive,
        EvTier::HighImpact,
    ];
    for tier in &tiers {
        let json = serde_json::to_string(tier).expect("serialize");
        let restored: EvTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*tier, restored);
    }
}

// ---------------------------------------------------------------------------
// RolloutStage
// ---------------------------------------------------------------------------

#[test]
fn rollout_stage_display() {
    assert_eq!(RolloutStage::Shadow.to_string(), "shadow");
    assert_eq!(RolloutStage::Canary.to_string(), "canary");
    assert_eq!(RolloutStage::Ramp.to_string(), "ramp");
    assert_eq!(RolloutStage::Default.to_string(), "default");
}

#[test]
fn rollout_stage_serde_roundtrip() {
    let stages = [
        RolloutStage::Shadow,
        RolloutStage::Canary,
        RolloutStage::Ramp,
        RolloutStage::Default,
    ];
    for stage in &stages {
        let json = serde_json::to_string(stage).expect("serialize");
        let restored: RolloutStage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*stage, restored);
    }
}

// ---------------------------------------------------------------------------
// EvidenceContract — valid contracts
// ---------------------------------------------------------------------------

#[test]
fn valid_contract_passes_validation() {
    let contract = valid_contract();
    assert!(contract.validate().is_ok());
}

#[test]
fn valid_contract_with_high_impact_passes() {
    let mut contract = valid_contract();
    contract.ev_score = 7.5;
    contract.ev_tier = EvTier::HighImpact;
    assert!(contract.validate().is_ok());
}

#[test]
fn valid_contract_with_single_rollout_stage() {
    let mut contract = valid_contract();
    contract.rollout_stages = vec![RolloutStage::Default];
    assert!(contract.validate().is_ok());
}

#[test]
fn valid_contract_with_compatible_minor_version() {
    let mut contract = valid_contract();
    contract.version = ContractVersion::new(1, 99);
    assert!(contract.validate().is_ok());
}

#[test]
fn valid_contract_with_duplicate_rollout_stages_passes() {
    let mut contract = valid_contract();
    contract.rollout_stages = vec![
        RolloutStage::Canary,
        RolloutStage::Canary,
        RolloutStage::Ramp,
    ];
    assert!(contract.validate().is_ok());
}

// ---------------------------------------------------------------------------
// EvidenceContract — missing required fields
// ---------------------------------------------------------------------------

#[test]
fn missing_change_summary_produces_error() {
    let mut contract = valid_contract();
    contract.change_summary = "   ".to_string();
    let errors = contract.validate().unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ContractValidationError::MissingField { field } if field == "change_summary"
    )));
}

#[test]
fn missing_hotspot_evidence_produces_error() {
    let mut contract = valid_contract();
    contract.hotspot_evidence = String::new();
    let errors = contract.validate().unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ContractValidationError::MissingField { field } if field == "hotspot_evidence"
    )));
}

#[test]
fn missing_expected_loss_model_produces_error() {
    let mut contract = valid_contract();
    contract.expected_loss_model = "\t\n".to_string();
    let errors = contract.validate().unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ContractValidationError::MissingField { field } if field == "expected_loss_model"
    )));
}

#[test]
fn missing_fallback_trigger_produces_error() {
    let mut contract = valid_contract();
    contract.fallback_trigger = String::new();
    let errors = contract.validate().unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ContractValidationError::MissingField { field } if field == "fallback_trigger"
    )));
}

#[test]
fn missing_rollback_command_produces_error() {
    let mut contract = valid_contract();
    contract.rollback_command = "  ".to_string();
    let errors = contract.validate().unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ContractValidationError::MissingField { field } if field == "rollback_command"
    )));
}

#[test]
fn missing_benchmark_artifacts_produces_error() {
    let mut contract = valid_contract();
    contract.benchmark_artifacts = String::new();
    let errors = contract.validate().unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ContractValidationError::MissingField { field } if field == "benchmark_artifacts"
    )));
}

#[test]
fn all_text_fields_empty_produces_six_missing_errors() {
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
    let missing_count = errors
        .iter()
        .filter(|e| matches!(e, ContractValidationError::MissingField { .. }))
        .count();
    assert_eq!(missing_count, 6);
}

// ---------------------------------------------------------------------------
// EvidenceContract — EV score and tier errors
// ---------------------------------------------------------------------------

#[test]
fn ev_tier_mismatch_detected() {
    let mut contract = valid_contract();
    contract.ev_score = 3.0;
    contract.ev_tier = EvTier::HighImpact; // should be Positive
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvTierMismatch { .. }))
    );
}

#[test]
fn ev_below_threshold_rejected() {
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
fn ev_marginal_tier_below_threshold() {
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
fn ev_nan_produces_invalid_score_error() {
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
fn ev_positive_infinity_produces_invalid_score_error() {
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
fn ev_negative_infinity_produces_invalid_score_error() {
    let mut contract = valid_contract();
    contract.ev_score = f64::NEG_INFINITY;
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
    );
}

// ---------------------------------------------------------------------------
// EvidenceContract — rollout stage errors
// ---------------------------------------------------------------------------

#[test]
fn empty_rollout_stages_produces_error() {
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
fn out_of_order_rollout_stages_detected() {
    let mut contract = valid_contract();
    contract.rollout_stages = vec![RolloutStage::Ramp, RolloutStage::Shadow];
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidRolloutOrder { .. }))
    );
}

#[test]
fn reverse_order_rollout_stages_detected() {
    let mut contract = valid_contract();
    contract.rollout_stages = vec![
        RolloutStage::Default,
        RolloutStage::Ramp,
        RolloutStage::Canary,
        RolloutStage::Shadow,
    ];
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidRolloutOrder { .. }))
    );
}

// ---------------------------------------------------------------------------
// EvidenceContract — version errors
// ---------------------------------------------------------------------------

#[test]
fn incompatible_major_version_produces_error() {
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
fn major_version_zero_incompatible() {
    let mut contract = valid_contract();
    contract.version = ContractVersion::new(0, 9);
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::IncompatibleVersion { .. }))
    );
}

// ---------------------------------------------------------------------------
// Multi-error accumulation
// ---------------------------------------------------------------------------

#[test]
fn multiple_simultaneous_errors_all_reported() {
    let contract = EvidenceContract {
        version: ContractVersion::new(2, 0), // incompatible
        change_summary: String::new(),       // missing
        hotspot_evidence: "evidence".to_string(),
        ev_score: f64::NAN,        // invalid
        ev_tier: EvTier::Positive, // mismatch (but NaN takes priority)
        expected_loss_model: "model".to_string(),
        fallback_trigger: "trigger".to_string(),
        rollout_stages: vec![], // empty
        rollback_command: "cmd".to_string(),
        benchmark_artifacts: "data".to_string(),
    };
    let errors = contract.validate().unwrap_err();
    // Should have at least: IncompatibleVersion, MissingField, InvalidEvScore, EmptyRolloutStages
    assert!(errors.len() >= 4);
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
            .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
    );
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EmptyRolloutStages))
    );
}

// ---------------------------------------------------------------------------
// validate_contract free function
// ---------------------------------------------------------------------------

#[test]
fn validate_contract_free_fn_returns_empty_vec_for_valid() {
    let contract = valid_contract();
    let errors = validate_contract(&contract);
    assert!(errors.is_empty());
}

#[test]
fn validate_contract_free_fn_returns_errors_for_invalid() {
    let mut contract = valid_contract();
    contract.change_summary = String::new();
    let errors = validate_contract(&contract);
    assert!(!errors.is_empty());
}

// ---------------------------------------------------------------------------
// ContractValidationError — Display
// ---------------------------------------------------------------------------

#[test]
fn error_display_missing_field() {
    let err = ContractValidationError::MissingField {
        field: "hotspot_evidence".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("hotspot_evidence"));
    assert!(display.contains("missing required field"));
}

#[test]
fn error_display_ev_below_threshold() {
    let err = ContractValidationError::EvBelowThreshold {
        score_str: "1.50".to_string(),
        tier: "marginal".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("1.50"));
    assert!(display.contains("marginal"));
    assert!(display.contains("2.0"));
}

#[test]
fn error_display_ev_tier_mismatch() {
    let err = ContractValidationError::EvTierMismatch {
        score_str: "3.00".to_string(),
        declared_tier: "high-impact".to_string(),
        expected_tier: "positive".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("3.00"));
    assert!(display.contains("high-impact"));
    assert!(display.contains("positive"));
}

#[test]
fn error_display_empty_rollout_stages() {
    let err = ContractValidationError::EmptyRolloutStages;
    assert!(err.to_string().contains("at least one rollout stage"));
}

#[test]
fn error_display_invalid_rollout_order() {
    let err = ContractValidationError::InvalidRolloutOrder {
        stage: "shadow".to_string(),
        position: 1,
    };
    let display = err.to_string();
    assert!(display.contains("shadow"));
    assert!(display.contains("position 1"));
}

#[test]
fn error_display_incompatible_version() {
    let err = ContractValidationError::IncompatibleVersion {
        version: "2.0".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("2.0"));
    assert!(display.contains("incompatible"));
}

#[test]
fn error_display_invalid_ev_score() {
    let err = ContractValidationError::InvalidEvScore;
    assert!(err.to_string().contains("finite number"));
}

// ---------------------------------------------------------------------------
// ContractValidationError — serde
// ---------------------------------------------------------------------------

#[test]
fn contract_validation_error_serde_all_variants() {
    let errors = vec![
        ContractValidationError::MissingField {
            field: "change_summary".to_string(),
        },
        ContractValidationError::EvBelowThreshold {
            score_str: "0.50".to_string(),
            tier: "reject".to_string(),
        },
        ContractValidationError::EvTierMismatch {
            score_str: "3.00".to_string(),
            declared_tier: "high-impact".to_string(),
            expected_tier: "positive".to_string(),
        },
        ContractValidationError::EmptyRolloutStages,
        ContractValidationError::InvalidRolloutOrder {
            stage: "shadow".to_string(),
            position: 2,
        },
        ContractValidationError::IncompatibleVersion {
            version: "2.0".to_string(),
        },
        ContractValidationError::InvalidEvScore,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: ContractValidationError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ---------------------------------------------------------------------------
// EvidenceContract — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn evidence_contract_serde_roundtrip() {
    let contract = valid_contract();
    let json = serde_json::to_string(&contract).expect("serialize");
    let restored: EvidenceContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(contract, restored);
}

#[test]
fn evidence_contract_deterministic_serialization() {
    let contract = valid_contract();
    let json1 = serde_json::to_string(&contract).expect("serialize");
    let json2 = serde_json::to_string(&contract).expect("serialize");
    assert_eq!(json1, json2, "serialization must be deterministic");
}

// ---------------------------------------------------------------------------
// Deterministic replay: same input always yields same validation result
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_valid_contract() {
    let contract = valid_contract();
    for _ in 0..10 {
        assert!(contract.validate().is_ok());
    }
}

#[test]
fn deterministic_replay_invalid_contract() {
    let mut contract = valid_contract();
    contract.change_summary = String::new();
    contract.ev_score = 0.5;
    contract.ev_tier = EvTier::Reject;
    let first_errors = contract.validate().unwrap_err();
    for _ in 0..10 {
        let errors = contract.validate().unwrap_err();
        assert_eq!(first_errors, errors, "validation must be deterministic");
    }
}

// ---------------------------------------------------------------------------
// Boundary: exact EV thresholds
// ---------------------------------------------------------------------------

#[test]
fn ev_score_exactly_at_boundary_1_0_is_marginal() {
    let mut contract = valid_contract();
    contract.ev_score = 1.0;
    contract.ev_tier = EvTier::Marginal;
    let errors = contract.validate().unwrap_err();
    // Marginal does not meet threshold
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
    );
}

#[test]
fn ev_score_exactly_at_boundary_2_0_is_positive() {
    let mut contract = valid_contract();
    contract.ev_score = 2.0;
    contract.ev_tier = EvTier::Positive;
    assert!(contract.validate().is_ok());
}

#[test]
fn ev_score_exactly_at_boundary_5_0_is_high_impact() {
    let mut contract = valid_contract();
    contract.ev_score = 5.0;
    contract.ev_tier = EvTier::HighImpact;
    assert!(contract.validate().is_ok());
}
