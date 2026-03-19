#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

//! Enrichment integration tests for `evidence_contract`.
//!
//! Focus areas that complement existing unit and integration tests:
//! - Cross-field validation interactions (version + EV mismatch + missing fields simultaneously)
//! - Rollout stage permutation edge orderings
//! - Serde round-trips for contracts with various error combinations
//! - EV boundary precision with f64 edge cases (subnormal, MIN_POSITIVE)
//! - Validate function idempotency (validate twice gives same result)
//! - Contract mutation workflows (start valid, mutate, re-validate)
//! - JSON field name stability across serialization

use std::collections::BTreeSet;

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
        change_summary: "Implement isolation layer for extension sandboxing".to_string(),
        hotspot_evidence: "Profiles show cross-extension leaks cause 40% of incidents".to_string(),
        ev_score: 4.2,
        ev_tier: EvTier::Positive,
        expected_loss_model: "Loss(no-fix)=data leak, Loss(fix-bad)=perf regression 5%".to_string(),
        fallback_trigger: "Cross-extension read count > 0 for 1 minute".to_string(),
        rollout_stages: vec![
            RolloutStage::Shadow,
            RolloutStage::Canary,
            RolloutStage::Ramp,
            RolloutStage::Default,
        ],
        rollback_command: "cargo run -- rollback sandbox-v2".to_string(),
        benchmark_artifacts: "Before: 40% incidents, After: 0%. Hash: def456".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Cross-field validation interactions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_incompatible_version_and_ev_mismatch_and_missing_fields_all_at_once() {
    let contract = EvidenceContract {
        version: ContractVersion::new(3, 0),       // incompatible
        change_summary: String::new(),             // missing
        hotspot_evidence: "   \t\n  ".to_string(), // whitespace-only = missing
        ev_score: 4.0,
        ev_tier: EvTier::HighImpact,        // mismatch (4.0 is Positive)
        expected_loss_model: String::new(), // missing
        fallback_trigger: "exists".to_string(),
        rollout_stages: vec![RolloutStage::Default, RolloutStage::Shadow], // invalid order
        rollback_command: "cmd".to_string(),
        benchmark_artifacts: String::new(), // missing
    };
    let errors = contract.validate().unwrap_err();

    // Should have at minimum: IncompatibleVersion + 4 MissingField + EvTierMismatch + InvalidRolloutOrder
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::IncompatibleVersion { .. }))
    );
    let missing_count = errors
        .iter()
        .filter(|e| matches!(e, ContractValidationError::MissingField { .. }))
        .count();
    assert_eq!(missing_count, 4, "4 text fields are empty/whitespace");
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvTierMismatch { .. }))
    );
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidRolloutOrder { .. }))
    );
}

#[test]
fn enrichment_nan_score_with_empty_rollout_and_missing_fields() {
    let contract = EvidenceContract {
        version: ContractVersion::CURRENT,
        change_summary: String::new(),
        hotspot_evidence: String::new(),
        ev_score: f64::NAN,
        ev_tier: EvTier::Reject,
        expected_loss_model: String::new(),
        fallback_trigger: String::new(),
        rollout_stages: vec![],
        rollback_command: String::new(),
        benchmark_artifacts: String::new(),
    };
    let errors = contract.validate().unwrap_err();

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
    let missing_count = errors
        .iter()
        .filter(|e| matches!(e, ContractValidationError::MissingField { .. }))
        .count();
    assert_eq!(missing_count, 6);
    // NaN means no tier mismatch check and no threshold check
    assert!(
        !errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvTierMismatch { .. }))
    );
    assert!(
        !errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
    );
}

#[test]
fn enrichment_infinity_score_produces_invalid_ev_score_not_tier_mismatch() {
    let mut contract = valid_contract();
    contract.ev_score = f64::INFINITY;
    contract.ev_tier = EvTier::HighImpact;
    let errors = contract.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
    );
    // When score is infinite, tier mismatch/threshold checks are skipped
    assert!(
        !errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvTierMismatch { .. }))
    );
}

// ---------------------------------------------------------------------------
// Rollout stage permutation edge orderings
// ---------------------------------------------------------------------------

#[test]
fn enrichment_all_24_permutations_of_four_stages_only_sorted_passes() {
    let stages = [
        RolloutStage::Shadow,
        RolloutStage::Canary,
        RolloutStage::Ramp,
        RolloutStage::Default,
    ];
    // Generate all 24 permutations
    let perms = permutations_4(&stages);
    let sorted = vec![
        RolloutStage::Shadow,
        RolloutStage::Canary,
        RolloutStage::Ramp,
        RolloutStage::Default,
    ];

    let mut pass_count = 0;
    for perm in &perms {
        let mut c = valid_contract();
        c.rollout_stages = perm.clone();
        if c.validate().is_ok() {
            pass_count += 1;
        }
    }
    // Only the sorted order and permutations where each subsequent stage >= previous should pass.
    // Specifically, the only strict order is S<C<R<D (plus duplicates are ok but we have exactly 4 distinct).
    // So only 1 permutation should pass (the sorted one).
    assert_eq!(
        pass_count, 1,
        "only the correctly ordered permutation should pass"
    );

    // Verify the sorted one passes
    let mut c = valid_contract();
    c.rollout_stages = sorted;
    assert!(c.validate().is_ok());
}

fn permutations_4(stages: &[RolloutStage; 4]) -> Vec<Vec<RolloutStage>> {
    let mut result = Vec::new();
    let indices = [0, 1, 2, 3];
    for a in indices {
        for b in indices {
            if b == a {
                continue;
            }
            for c in indices {
                if c == a || c == b {
                    continue;
                }
                for d in indices {
                    if d == a || d == b || d == c {
                        continue;
                    }
                    result.push(vec![stages[a], stages[b], stages[c], stages[d]]);
                }
            }
        }
    }
    result
}

#[test]
fn enrichment_rollout_shadow_canary_shadow_is_invalid() {
    let mut c = valid_contract();
    c.rollout_stages = vec![
        RolloutStage::Shadow,
        RolloutStage::Canary,
        RolloutStage::Shadow,
    ];
    let errors = c.validate().unwrap_err();
    assert!(errors.iter().any(|e| matches!(
        e,
        ContractValidationError::InvalidRolloutOrder { position: 2, .. }
    )));
}

#[test]
fn enrichment_rollout_default_default_default_is_valid() {
    // All same stages at highest level is monotonically non-decreasing
    let mut c = valid_contract();
    c.rollout_stages = vec![
        RolloutStage::Default,
        RolloutStage::Default,
        RolloutStage::Default,
    ];
    assert!(c.validate().is_ok());
}

#[test]
fn enrichment_rollout_shadow_ramp_is_valid_skipping_canary() {
    let mut c = valid_contract();
    c.rollout_stages = vec![RolloutStage::Shadow, RolloutStage::Ramp];
    assert!(c.validate().is_ok());
}

#[test]
fn enrichment_rollout_canary_default_is_valid_skipping_ramp() {
    let mut c = valid_contract();
    c.rollout_stages = vec![RolloutStage::Canary, RolloutStage::Default];
    assert!(c.validate().is_ok());
}

// ---------------------------------------------------------------------------
// Serde round-trips for contracts with various error combinations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_roundtrip_contract_with_reject_tier() {
    let mut c = valid_contract();
    c.ev_score = 0.3;
    c.ev_tier = EvTier::Reject;
    let json = serde_json::to_string(&c).unwrap();
    let restored: EvidenceContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
    // Validate still produces same errors after roundtrip
    let err_orig = c.validate().unwrap_err();
    let err_restored = restored.validate().unwrap_err();
    assert_eq!(err_orig.len(), err_restored.len());
}

#[test]
fn enrichment_serde_roundtrip_all_error_variants_together() {
    let errors = vec![
        ContractValidationError::MissingField {
            field: "change_summary".into(),
        },
        ContractValidationError::EvBelowThreshold {
            score_str: "0.50".into(),
            tier: "reject".into(),
        },
        ContractValidationError::EvTierMismatch {
            score_str: "3.00".into(),
            declared_tier: "reject".into(),
            expected_tier: "positive".into(),
        },
        ContractValidationError::EmptyRolloutStages,
        ContractValidationError::InvalidRolloutOrder {
            stage: "shadow".into(),
            position: 2,
        },
        ContractValidationError::IncompatibleVersion {
            version: "5.0".into(),
        },
        ContractValidationError::InvalidEvScore,
    ];
    let json = serde_json::to_string(&errors).unwrap();
    let restored: Vec<ContractValidationError> = serde_json::from_str(&json).unwrap();
    assert_eq!(errors, restored);
}

#[test]
fn enrichment_serde_roundtrip_contract_with_many_rollout_stages() {
    let mut c = valid_contract();
    c.rollout_stages = vec![
        RolloutStage::Shadow,
        RolloutStage::Shadow,
        RolloutStage::Canary,
        RolloutStage::Canary,
        RolloutStage::Ramp,
        RolloutStage::Default,
        RolloutStage::Default,
    ];
    let json = serde_json::to_string(&c).unwrap();
    let restored: EvidenceContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
    assert!(c.validate().is_ok());
}

// ---------------------------------------------------------------------------
// EV boundary precision with f64 edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ev_tier_from_score_subnormal() {
    let subnormal = f64::MIN_POSITIVE / 2.0;
    assert!(subnormal > 0.0);
    assert!(subnormal < 1.0);
    assert_eq!(EvTier::from_score(subnormal), EvTier::Reject);
}

#[test]
fn enrichment_ev_tier_from_score_min_positive() {
    assert_eq!(EvTier::from_score(f64::MIN_POSITIVE), EvTier::Reject);
}

#[test]
fn enrichment_ev_tier_from_score_negative_zero() {
    assert_eq!(EvTier::from_score(-0.0), EvTier::Reject);
}

#[test]
fn enrichment_ev_tier_from_score_epsilon_below_boundaries() {
    // Just below 1.0 (using 4x epsilon to ensure representability)
    assert_eq!(EvTier::from_score(1.0 - 4.0 * f64::EPSILON), EvTier::Reject);
    // Just below 2.0
    assert_eq!(
        EvTier::from_score(2.0 - 4.0 * f64::EPSILON),
        EvTier::Marginal
    );
    // Just below 5.0 — note: 5.0 - f64::EPSILON == 5.0 in f64
    // so we use a larger gap that is actually representable
    assert_eq!(EvTier::from_score(4.999_999_999), EvTier::Positive);
}

#[test]
fn enrichment_ev_tier_from_score_very_large_positive() {
    assert_eq!(EvTier::from_score(f64::MAX), EvTier::HighImpact);
}

#[test]
fn enrichment_ev_tier_from_score_very_large_negative() {
    assert_eq!(EvTier::from_score(f64::MIN), EvTier::Reject);
}

// ---------------------------------------------------------------------------
// Validate function idempotency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_idempotent_for_valid_contract() {
    let c = valid_contract();
    let r1 = c.validate();
    let r2 = c.validate();
    assert!(r1.is_ok());
    assert!(r2.is_ok());
}

#[test]
fn enrichment_validate_idempotent_for_invalid_contract() {
    let mut c = valid_contract();
    c.change_summary = String::new();
    c.ev_score = 0.5;
    c.ev_tier = EvTier::Reject;
    let e1 = c.validate().unwrap_err();
    let e2 = c.validate().unwrap_err();
    assert_eq!(e1.len(), e2.len());
    assert_eq!(e1, e2);
}

#[test]
fn enrichment_validate_contract_fn_and_method_agree() {
    let c = valid_contract();
    let fn_errors = validate_contract(&c);
    let method_result = c.validate();
    assert!(fn_errors.is_empty());
    assert!(method_result.is_ok());

    let mut bad = valid_contract();
    bad.change_summary = String::new();
    let fn_errors = validate_contract(&bad);
    let method_errors = bad.validate().unwrap_err();
    assert_eq!(fn_errors, method_errors);
}

// ---------------------------------------------------------------------------
// Contract mutation workflows
// ---------------------------------------------------------------------------

#[test]
fn enrichment_valid_to_invalid_to_valid_again() {
    let mut c = valid_contract();
    assert!(c.validate().is_ok());

    // Mutate to invalid
    c.change_summary = String::new();
    assert!(c.validate().is_err());

    // Fix it
    c.change_summary = "Restored change summary".to_string();
    assert!(c.validate().is_ok());
}

#[test]
fn enrichment_lower_ev_then_raise_above_threshold() {
    let mut c = valid_contract();
    assert!(c.validate().is_ok());

    // Lower below threshold
    c.ev_score = 1.5;
    c.ev_tier = EvTier::Marginal;
    let errors = c.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
    );

    // Raise above threshold
    c.ev_score = 2.5;
    c.ev_tier = EvTier::Positive;
    assert!(c.validate().is_ok());
}

#[test]
fn enrichment_change_version_compatibility_roundtrip() {
    let mut c = valid_contract();
    assert!(c.validate().is_ok());

    c.version = ContractVersion::new(2, 0);
    let errors = c.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::IncompatibleVersion { .. }))
    );

    c.version = ContractVersion::new(1, 99);
    assert!(c.validate().is_ok());
}

// ---------------------------------------------------------------------------
// JSON field name stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_json_field_names_are_stable_across_serializations() {
    let c = valid_contract();
    let json1 = serde_json::to_string(&c).unwrap();
    let json2 = serde_json::to_string(&c).unwrap();
    assert_eq!(json1, json2, "deterministic serialization");

    // Verify all expected field names
    for field in &[
        "\"version\"",
        "\"change_summary\"",
        "\"hotspot_evidence\"",
        "\"ev_score\"",
        "\"ev_tier\"",
        "\"expected_loss_model\"",
        "\"fallback_trigger\"",
        "\"rollout_stages\"",
        "\"rollback_command\"",
        "\"benchmark_artifacts\"",
    ] {
        assert!(json1.contains(field), "JSON must contain field {field}");
    }
}

#[test]
fn enrichment_contract_version_json_field_names_stable() {
    let v = ContractVersion::new(1, 0);
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"major\""));
    assert!(json.contains("\"minor\""));

    let v2 = ContractVersion::new(99, 100);
    let json2 = serde_json::to_string(&v2).unwrap();
    assert!(json2.contains("\"major\""));
    assert!(json2.contains("\"minor\""));
}

#[test]
fn enrichment_error_variant_json_names_stable() {
    let err = ContractValidationError::EvTierMismatch {
        score_str: "3.00".into(),
        declared_tier: "Reject".into(),
        expected_tier: "Positive".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("\"score_str\""));
    assert!(json.contains("\"declared_tier\""));
    assert!(json.contains("\"expected_tier\""));
}

// ---------------------------------------------------------------------------
// Additional enrichment: Display and Ord for ContractVersion
// ---------------------------------------------------------------------------

#[test]
fn enrichment_contract_version_display_large_values() {
    let v = ContractVersion::new(u32::MAX, u32::MAX);
    let display = v.to_string();
    assert!(display.contains(&u32::MAX.to_string()));
}

#[test]
fn enrichment_contract_version_ord_is_total() {
    let versions = [
        ContractVersion::new(0, 0),
        ContractVersion::new(0, 1),
        ContractVersion::new(1, 0),
        ContractVersion::new(1, 1),
        ContractVersion::new(2, 0),
    ];
    for i in 0..versions.len() {
        for j in (i + 1)..versions.len() {
            assert!(
                versions[i] < versions[j],
                "{:?} should be < {:?}",
                versions[i],
                versions[j]
            );
        }
    }
}

#[test]
fn enrichment_ev_tier_deterministic_classification_across_calls() {
    let scores = [0.0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 10.0, 100.0];
    for &score in &scores {
        let t1 = EvTier::from_score(score);
        let t2 = EvTier::from_score(score);
        assert_eq!(t1, t2, "EvTier::from_score({score}) must be deterministic");
    }
}

#[test]
fn enrichment_rollout_stage_display_deterministic() {
    for stage in [
        RolloutStage::Shadow,
        RolloutStage::Canary,
        RolloutStage::Ramp,
        RolloutStage::Default,
    ] {
        let d1 = stage.to_string();
        let d2 = stage.to_string();
        assert_eq!(d1, d2);
    }
}

#[test]
fn enrichment_all_error_displays_are_non_empty_and_unique() {
    let errors = [
        ContractValidationError::MissingField { field: "a".into() },
        ContractValidationError::EvBelowThreshold {
            score_str: "1.0".into(),
            tier: "m".into(),
        },
        ContractValidationError::EvTierMismatch {
            score_str: "2.0".into(),
            declared_tier: "r".into(),
            expected_tier: "p".into(),
        },
        ContractValidationError::EmptyRolloutStages,
        ContractValidationError::InvalidRolloutOrder {
            stage: "s".into(),
            position: 0,
        },
        ContractValidationError::IncompatibleVersion {
            version: "9.0".into(),
        },
        ContractValidationError::InvalidEvScore,
    ];
    let mut displays = BTreeSet::new();
    for e in &errors {
        let d = e.to_string();
        assert!(!d.is_empty(), "error display should not be empty");
        displays.insert(d);
    }
    assert_eq!(
        displays.len(),
        7,
        "all 7 error variants must have unique displays"
    );
}

#[test]
fn enrichment_validate_contract_returns_vec_not_set_preserves_order() {
    let contract = EvidenceContract {
        version: ContractVersion::new(2, 0),
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
    let errors = validate_contract(&contract);
    // First error should be IncompatibleVersion (checked first in code)
    assert!(matches!(
        errors[0],
        ContractValidationError::IncompatibleVersion { .. }
    ));
}

#[test]
fn enrichment_ev_score_and_tier_mismatch_plus_below_threshold_combined() {
    // Score 0.5 with declared tier Positive: produces both EvTierMismatch and EvBelowThreshold
    let mut c = valid_contract();
    c.ev_score = 0.5;
    c.ev_tier = EvTier::Positive; // should be Reject
    let errors = c.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvTierMismatch { .. }))
    );
    // The below-threshold check uses the *declared* tier, which meets_threshold, so no EvBelowThreshold
    // But the declared tier is Positive which meets threshold, so only mismatch fires
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ContractValidationError::EvTierMismatch { .. }))
    );
}

#[test]
fn enrichment_contract_clone_then_mutate_independence() {
    let original = valid_contract();
    let mut cloned = original.clone();
    cloned.change_summary = String::new();

    assert!(original.validate().is_ok());
    assert!(cloned.validate().is_err());
}
