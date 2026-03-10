#![forbid(unsafe_code)]
//! Enrichment integration tests for `privacy_learning_contract`.
//!
//! Adds JSON field-name stability, serde exact enum values, Debug
//! distinctness, error Display exact messages, Display format checks,
//! validation edge cases, DP budget max_epochs computation, shadow
//! evaluation gate E2E (pass/reject/override/rollback), transcript
//! snapshots, and additional serde roundtrips beyond the existing 46
//! integration tests.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::privacy_learning_contract::{
    ClippingMethod, ClippingStrategy, CompositionMethod, ContractError, ContractRegistry,
    CoordinatorTrustModel, CreateContractInput, DataRetentionPolicy, DeterministicPrng,
    DpBudgetSemantics, FeatureField, FeatureFieldType, FeatureSchema, HumanOverrideRequest,
    PrivacyLearningContract, PrngAlgorithm, RandomnessTranscript, SafetyMetric,
    SafetyMetricSnapshot, SecretSharingScheme, SecureAggregationRequirements, SeedEscrowRecord,
    ShadowBurnInThresholdProfile, ShadowEvaluationCandidate, ShadowEvaluationGate,
    ShadowEvaluationGateConfig, ShadowExtensionClass, ShadowPromotionVerdict,
    ShadowReplayReference, ShadowRollbackReadinessArtifacts, UpdatePolicy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ===========================================================================
// Helpers
// ===========================================================================

fn sk() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn field(name: &str, ft: FeatureFieldType, prior: bool) -> (String, FeatureField) {
    (
        name.to_string(),
        FeatureField {
            name: name.to_string(),
            field_type: ft,
            description: format!("{name} field"),
            existed_in_prior_version: prior,
        },
    )
}

fn valid_schema() -> FeatureSchema {
    let mut fields = BTreeMap::new();
    fields.insert(
        "loss".to_string(),
        FeatureField {
            name: "loss".to_string(),
            field_type: FeatureFieldType::FixedPoint,
            description: "loss value".to_string(),
            existed_in_prior_version: false,
        },
    );
    fields.insert(
        "count".to_string(),
        FeatureField {
            name: "count".to_string(),
            field_type: FeatureFieldType::Counter,
            description: "sample count".to_string(),
            existed_in_prior_version: false,
        },
    );
    FeatureSchema {
        version: 1,
        fields,
        prior_version: None,
    }
}

fn valid_update_policy() -> UpdatePolicy {
    UpdatePolicy {
        min_local_samples: 100,
        min_submission_interval: 3600,
        max_data_age: 86400,
        allow_skip: true,
        max_consecutive_skips: 3,
    }
}

fn valid_clipping(schema: &FeatureSchema) -> ClippingStrategy {
    let per_field: BTreeMap<String, i64> = schema
        .fields
        .keys()
        .map(|k| (k.clone(), 1_000_000))
        .collect();
    ClippingStrategy {
        method: ClippingMethod::PerCoordinate,
        global_bound_millionths: 1_000_000,
        per_field_bounds: per_field,
    }
}

fn valid_dp_budget() -> DpBudgetSemantics {
    DpBudgetSemantics {
        epsilon_per_epoch_millionths: 100_000,
        delta_per_epoch_millionths: 1_000,
        composition_method: CompositionMethod::Advanced,
        lifetime_epsilon_budget_millionths: 1_000_000,
        lifetime_delta_budget_millionths: 10_000,
        fail_closed_on_exhaustion: true,
    }
}

fn valid_aggregation() -> SecureAggregationRequirements {
    SecureAggregationRequirements {
        min_participants: 10,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Additive,
        sharing_threshold: None,
        coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
    }
}

fn valid_retention() -> DataRetentionPolicy {
    DataRetentionPolicy {
        max_intermediate_retention: 86400,
        max_snapshot_retention: 604800,
        delete_local_after_submission: true,
        delete_shares_after_aggregation: true,
    }
}

fn participant_id() -> EngineObjectId {
    EngineObjectId::from_hex("aa00000000000000000000000000000000000000000000000000000000000001")
        .unwrap()
}

fn create_contract() -> PrivacyLearningContract {
    let schema = valid_schema();
    PrivacyLearningContract::create_signed(
        &sk(),
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(1),
            zone: "us-east-1",
            feature_schema: schema.clone(),
            update_policy: valid_update_policy(),
            clipping_strategy: valid_clipping(&schema),
            dp_budget: valid_dp_budget(),
            aggregation: valid_aggregation(),
            retention: valid_retention(),
            authorized_participants: [participant_id()].into_iter().collect(),
        },
    )
    .unwrap()
}

fn baseline_metrics() -> SafetyMetricSnapshot {
    SafetyMetricSnapshot {
        values_millionths: BTreeMap::from([
            (SafetyMetric::FalsePositiveRate, 120_000),
            (SafetyMetric::FalseNegativeRate, 90_000),
            (SafetyMetric::CalibrationError, 70_000),
            (SafetyMetric::DriftDetectionAccuracy, 760_000),
            (SafetyMetric::ContainmentTime, 500_000),
        ]),
    }
}

fn improved_metrics() -> SafetyMetricSnapshot {
    SafetyMetricSnapshot {
        values_millionths: BTreeMap::from([
            (SafetyMetric::FalsePositiveRate, 115_000),
            (SafetyMetric::FalseNegativeRate, 88_000),
            (SafetyMetric::CalibrationError, 68_000),
            (SafetyMetric::DriftDetectionAccuracy, 780_000),
            (SafetyMetric::ContainmentTime, 495_000),
        ]),
    }
}

fn regressed_metrics() -> SafetyMetricSnapshot {
    SafetyMetricSnapshot {
        values_millionths: BTreeMap::from([
            (SafetyMetric::FalsePositiveRate, 145_000),
            (SafetyMetric::FalseNegativeRate, 95_000),
            (SafetyMetric::CalibrationError, 75_000),
            (SafetyMetric::DriftDetectionAccuracy, 740_000),
            (SafetyMetric::ContainmentTime, 520_000),
        ]),
    }
}

fn replay_ref() -> ShadowReplayReference {
    ShadowReplayReference {
        replay_corpus_id: "corpus-2026".to_string(),
        randomness_snapshot_id: "rng-snap-7".to_string(),
        replay_seed_hash: [0x5A; 32],
        replay_seed_counter: 42,
    }
}

fn rollback_ready() -> ShadowRollbackReadinessArtifacts {
    ShadowRollbackReadinessArtifacts {
        rollback_command_tested: true,
        previous_policy_snapshot_id: "snap-2026".to_string(),
        transition_receipt_signed: true,
        rollback_playbook_ref: "playbook://rollback-v1".to_string(),
    }
}

fn gate_config() -> ShadowEvaluationGateConfig {
    ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 5_000,
        min_required_improvement_millionths: 2_500,
        default_burn_in_profile: ShadowBurnInThresholdProfile {
            min_shadow_success_rate_millionths: 995_000,
            max_false_deny_rate_millionths: 5_000,
            min_burn_in_duration_ns: 100,
            require_verified_rollback_artifacts: true,
        },
        burn_in_profiles_by_extension_class: BTreeMap::new(),
    }
}

fn passing_candidate(eps: i64, delta: i64) -> ShadowEvaluationCandidate {
    ShadowEvaluationCandidate {
        trace_id: "trace-e1".to_string(),
        decision_id: "dec-e1".to_string(),
        policy_id: "policy-e1".to_string(),
        extension_class: ShadowExtensionClass::Standard,
        candidate_version: "v2026.02.27".to_string(),
        baseline_snapshot_id: "snap-2026".to_string(),
        rollback_token: "rollback-tok-1".to_string(),
        epoch_id: SecurityEpoch::from_raw(1),
        shadow_started_at_ns: 1_000_000_000,
        evaluation_completed_at_ns: 1_000_000_200,
        shadow_success_rate_millionths: 997_000,
        false_deny_rate_millionths: 4_000,
        rollback_readiness: rollback_ready(),
        baseline_metrics: baseline_metrics(),
        candidate_metrics: improved_metrics(),
        replay_reference: replay_ref(),
        epsilon_spent_millionths: eps,
        delta_spent_millionths: delta,
    }
}

// ===========================================================================
// 1. Display exact for enums
// ===========================================================================

#[test]
fn feature_field_type_display_exact() {
    assert_eq!(format!("{}", FeatureFieldType::FixedPoint), "fixed_point");
    assert_eq!(format!("{}", FeatureFieldType::Counter), "counter");
    assert_eq!(format!("{}", FeatureFieldType::Boolean), "boolean");
    assert_eq!(format!("{}", FeatureFieldType::Categorical), "categorical");
}

#[test]
fn clipping_method_display_exact() {
    assert_eq!(format!("{}", ClippingMethod::L2Norm), "l2_norm");
    assert_eq!(
        format!("{}", ClippingMethod::PerCoordinate),
        "per_coordinate"
    );
    assert_eq!(format!("{}", ClippingMethod::Adaptive), "adaptive");
}

#[test]
fn composition_method_display_exact() {
    assert_eq!(format!("{}", CompositionMethod::Basic), "basic");
    assert_eq!(format!("{}", CompositionMethod::Advanced), "advanced");
    assert_eq!(format!("{}", CompositionMethod::Renyi), "renyi");
    assert_eq!(format!("{}", CompositionMethod::ZeroCdp), "zcdp");
}

#[test]
fn coordinator_trust_model_display_exact() {
    assert_eq!(
        format!("{}", CoordinatorTrustModel::HonestButCurious),
        "honest_but_curious"
    );
    assert_eq!(format!("{}", CoordinatorTrustModel::Malicious), "malicious");
}

#[test]
fn secret_sharing_scheme_display_exact() {
    assert_eq!(format!("{}", SecretSharingScheme::Additive), "additive");
    assert_eq!(format!("{}", SecretSharingScheme::Shamir), "shamir");
}

#[test]
fn prng_algorithm_display_exact() {
    assert_eq!(
        format!("{}", PrngAlgorithm::ChaCha20LikeCounter),
        "chacha20_like_counter"
    );
}

#[test]
fn safety_metric_display_exact() {
    assert_eq!(
        format!("{}", SafetyMetric::FalsePositiveRate),
        "false_positive_rate"
    );
    assert_eq!(
        format!("{}", SafetyMetric::FalseNegativeRate),
        "false_negative_rate"
    );
    assert_eq!(
        format!("{}", SafetyMetric::CalibrationError),
        "calibration_error"
    );
    assert_eq!(
        format!("{}", SafetyMetric::DriftDetectionAccuracy),
        "drift_detection_accuracy"
    );
    assert_eq!(
        format!("{}", SafetyMetric::ContainmentTime),
        "containment_time"
    );
}

#[test]
fn shadow_extension_class_display_exact() {
    assert_eq!(format!("{}", ShadowExtensionClass::LowRisk), "low_risk");
    assert_eq!(format!("{}", ShadowExtensionClass::Standard), "standard");
    assert_eq!(format!("{}", ShadowExtensionClass::HighRisk), "high_risk");
    assert_eq!(format!("{}", ShadowExtensionClass::Critical), "critical");
}

#[test]
fn shadow_promotion_verdict_display_exact() {
    assert_eq!(format!("{}", ShadowPromotionVerdict::Pass), "pass");
    assert_eq!(format!("{}", ShadowPromotionVerdict::Reject), "reject");
    assert_eq!(
        format!("{}", ShadowPromotionVerdict::OverrideApproved),
        "override_approved"
    );
}

// ===========================================================================
// 2. Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_feature_field_type() {
    let debugs: Vec<String> = [
        FeatureFieldType::FixedPoint,
        FeatureFieldType::Counter,
        FeatureFieldType::Boolean,
        FeatureFieldType::Categorical,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

#[test]
fn debug_distinct_clipping_method() {
    let debugs: Vec<String> = [
        ClippingMethod::L2Norm,
        ClippingMethod::PerCoordinate,
        ClippingMethod::Adaptive,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

#[test]
fn debug_distinct_composition_method() {
    let debugs: Vec<String> = [
        CompositionMethod::Basic,
        CompositionMethod::Advanced,
        CompositionMethod::Renyi,
        CompositionMethod::ZeroCdp,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

#[test]
fn debug_distinct_safety_metric() {
    let debugs: Vec<String> = SafetyMetric::ALL.iter().map(|v| format!("{v:?}")).collect();
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

#[test]
fn debug_distinct_shadow_extension_class() {
    let debugs: Vec<String> = [
        ShadowExtensionClass::LowRisk,
        ShadowExtensionClass::Standard,
        ShadowExtensionClass::HighRisk,
        ShadowExtensionClass::Critical,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    for i in 0..debugs.len() {
        for j in (i + 1)..debugs.len() {
            assert_ne!(debugs[i], debugs[j]);
        }
    }
}

// ===========================================================================
// 3. Error Display exact messages
// ===========================================================================

#[test]
fn error_display_empty_feature_schema() {
    assert_eq!(
        format!("{}", ContractError::EmptyFeatureSchema),
        "feature schema has no fields"
    );
}

#[test]
fn error_display_invalid_version() {
    let e = ContractError::InvalidVersion {
        detail: "must be > 0".to_string(),
    };
    assert_eq!(format!("{e}"), "invalid version: must be > 0");
}

#[test]
fn error_display_field_name_mismatch() {
    let e = ContractError::FieldNameMismatch {
        key: "key_a".to_string(),
        field_name: "key_b".to_string(),
    };
    assert_eq!(
        format!("{e}"),
        "field name mismatch: key=key_a, field.name=key_b"
    );
}

#[test]
fn error_display_backward_compat() {
    let e = ContractError::BackwardCompatibilityViolation {
        detail: "no prior fields".to_string(),
    };
    assert_eq!(
        format!("{e}"),
        "backward compatibility violation: no prior fields"
    );
}

#[test]
fn error_display_invalid_update_policy() {
    let e = ContractError::InvalidUpdatePolicy {
        detail: "min_local_samples must be > 0".to_string(),
    };
    assert_eq!(
        format!("{e}"),
        "invalid update policy: min_local_samples must be > 0"
    );
}

#[test]
fn error_display_invalid_clipping_strategy() {
    let e = ContractError::InvalidClippingStrategy {
        detail: "bound must be > 0".to_string(),
    };
    assert_eq!(
        format!("{e}"),
        "invalid clipping strategy: bound must be > 0"
    );
}

#[test]
fn error_display_invalid_dp_budget() {
    let e = ContractError::InvalidDpBudget {
        detail: "epsilon must be > 0".to_string(),
    };
    assert_eq!(format!("{e}"), "invalid DP budget: epsilon must be > 0");
}

#[test]
fn error_display_invalid_aggregation() {
    let e = ContractError::InvalidAggregation {
        detail: "min_participants must be >= 2".to_string(),
    };
    assert_eq!(
        format!("{e}"),
        "invalid aggregation: min_participants must be >= 2"
    );
}

#[test]
fn error_display_invalid_retention() {
    let e = ContractError::InvalidRetention {
        detail: "must be > 0".to_string(),
    };
    assert_eq!(format!("{e}"), "invalid retention: must be > 0");
}

#[test]
fn error_display_invalid_randomness_transcript() {
    let e = ContractError::InvalidRandomnessTranscript {
        detail: "bad".to_string(),
    };
    assert_eq!(format!("{e}"), "invalid randomness transcript: bad");
}

#[test]
fn error_display_no_authorized_participants() {
    assert_eq!(
        format!("{}", ContractError::NoAuthorizedParticipants),
        "no authorized participants"
    );
}

#[test]
fn error_display_signature_failed() {
    let e = ContractError::SignatureFailed {
        detail: "oops".to_string(),
    };
    assert_eq!(format!("{e}"), "signature failed: oops");
}

#[test]
fn error_display_signature_invalid() {
    let e = ContractError::SignatureInvalid {
        detail: "bad sig".to_string(),
    };
    assert_eq!(format!("{e}"), "signature invalid: bad sig");
}

#[test]
fn error_display_seed_escrow_access_denied() {
    let e = ContractError::SeedEscrowAccessDenied {
        principal: "bob".to_string(),
        phase_id: "phase_1".to_string(),
    };
    assert_eq!(
        format!("{e}"),
        "seed escrow access denied for principal bob on phase phase_1"
    );
}

#[test]
fn error_display_seed_hash_mismatch() {
    let e = ContractError::SeedHashMismatch {
        phase_id: "p1".to_string(),
    };
    assert_eq!(format!("{e}"), "seed hash mismatch for phase p1");
}

#[test]
fn error_display_invalid_shadow_evaluation() {
    let e = ContractError::InvalidShadowEvaluation {
        detail: "bad eval".to_string(),
    };
    assert_eq!(format!("{e}"), "invalid shadow evaluation: bad eval");
}

#[test]
fn error_display_invalid_shadow_override() {
    let e = ContractError::InvalidShadowOverride {
        detail: "bad override".to_string(),
    };
    assert_eq!(format!("{e}"), "invalid shadow override: bad override");
}

// ===========================================================================
// 4. std::error::Error impl
// ===========================================================================

#[test]
fn contract_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(ContractError::EmptyFeatureSchema);
    assert!(!e.to_string().is_empty());
}

// ===========================================================================
// 5. Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_feature_field_type() {
    for (ft, tag) in [
        (FeatureFieldType::FixedPoint, "FixedPoint"),
        (FeatureFieldType::Counter, "Counter"),
        (FeatureFieldType::Boolean, "Boolean"),
        (FeatureFieldType::Categorical, "Categorical"),
    ] {
        let json = serde_json::to_string(&ft).unwrap();
        assert!(json.contains(tag), "missing tag {tag} in {json}");
    }
}

#[test]
fn serde_exact_clipping_method() {
    for (m, tag) in [
        (ClippingMethod::L2Norm, "L2Norm"),
        (ClippingMethod::PerCoordinate, "PerCoordinate"),
        (ClippingMethod::Adaptive, "Adaptive"),
    ] {
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains(tag), "missing tag {tag} in {json}");
    }
}

#[test]
fn serde_exact_composition_method() {
    for (m, tag) in [
        (CompositionMethod::Basic, "Basic"),
        (CompositionMethod::Advanced, "Advanced"),
        (CompositionMethod::Renyi, "Renyi"),
        (CompositionMethod::ZeroCdp, "ZeroCdp"),
    ] {
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains(tag), "missing tag {tag} in {json}");
    }
}

#[test]
fn serde_exact_shadow_extension_class_rename_all() {
    // ShadowExtensionClass uses #[serde(rename_all = "snake_case")]
    for (c, expected) in [
        (ShadowExtensionClass::LowRisk, "\"low_risk\""),
        (ShadowExtensionClass::Standard, "\"standard\""),
        (ShadowExtensionClass::HighRisk, "\"high_risk\""),
        (ShadowExtensionClass::Critical, "\"critical\""),
    ] {
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, expected, "unexpected for {c:?}");
    }
}

#[test]
fn serde_exact_shadow_promotion_verdict() {
    for (v, tag) in [
        (ShadowPromotionVerdict::Pass, "Pass"),
        (ShadowPromotionVerdict::Reject, "Reject"),
        (ShadowPromotionVerdict::OverrideApproved, "OverrideApproved"),
    ] {
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains(tag), "missing tag {tag} in {json}");
    }
}

// ===========================================================================
// 6. Serde roundtrip all error variants
// ===========================================================================

#[test]
fn serde_roundtrip_all_contract_error_variants() {
    let errors: Vec<ContractError> = vec![
        ContractError::EmptyFeatureSchema,
        ContractError::InvalidVersion {
            detail: "v0".to_string(),
        },
        ContractError::FieldNameMismatch {
            key: "a".to_string(),
            field_name: "b".to_string(),
        },
        ContractError::BackwardCompatibilityViolation {
            detail: "bc".to_string(),
        },
        ContractError::InvalidUpdatePolicy {
            detail: "up".to_string(),
        },
        ContractError::InvalidClippingStrategy {
            detail: "cs".to_string(),
        },
        ContractError::InvalidDpBudget {
            detail: "dp".to_string(),
        },
        ContractError::InvalidAggregation {
            detail: "ag".to_string(),
        },
        ContractError::InvalidRetention {
            detail: "rt".to_string(),
        },
        ContractError::InvalidRandomnessTranscript {
            detail: "rng".to_string(),
        },
        ContractError::MissingSeedEscrow {
            phase_id: "p".to_string(),
            epoch_id: SecurityEpoch::from_raw(1),
        },
        ContractError::SeedEscrowAccessDenied {
            principal: "bob".to_string(),
            phase_id: "p".to_string(),
        },
        ContractError::SeedHashMismatch {
            phase_id: "p".to_string(),
        },
        ContractError::NoAuthorizedParticipants,
        ContractError::IdDerivationFailed {
            detail: "id".to_string(),
        },
        ContractError::SignatureFailed {
            detail: "sig".to_string(),
        },
        ContractError::SignatureInvalid {
            detail: "inv".to_string(),
        },
        ContractError::DuplicateContract {
            contract_id: participant_id(),
        },
        ContractError::NotFound {
            contract_id: participant_id(),
        },
        ContractError::EpochNotAdvanced {
            zone: "z".to_string(),
            existing_epoch: SecurityEpoch::from_raw(1),
            new_epoch: SecurityEpoch::from_raw(1),
        },
        ContractError::InvalidShadowEvaluation {
            detail: "se".to_string(),
        },
        ContractError::InvalidShadowOverride {
            detail: "so".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ContractError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back, "roundtrip failed for {err:?}");
    }
}

// ===========================================================================
// 7. JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_feature_field() {
    let (_, ff) = field("loss", FeatureFieldType::FixedPoint, false);
    let json = serde_json::to_string(&ff).unwrap();
    for f in [
        "name",
        "field_type",
        "description",
        "existed_in_prior_version",
    ] {
        assert!(json.contains(f), "missing field: {f}");
    }
}

#[test]
fn json_fields_feature_schema() {
    let schema = valid_schema();
    let json = serde_json::to_string(&schema).unwrap();
    for f in ["version", "fields", "prior_version"] {
        assert!(json.contains(f), "missing field: {f}");
    }
}

#[test]
fn json_fields_update_policy() {
    let up = valid_update_policy();
    let json = serde_json::to_string(&up).unwrap();
    for f in [
        "min_local_samples",
        "min_submission_interval",
        "max_data_age",
        "allow_skip",
        "max_consecutive_skips",
    ] {
        assert!(json.contains(f), "missing field: {f}");
    }
}

#[test]
fn json_fields_clipping_strategy() {
    let cs = ClippingStrategy {
        method: ClippingMethod::L2Norm,
        global_bound_millionths: 1_000_000,
        per_field_bounds: BTreeMap::new(),
    };
    let json = serde_json::to_string(&cs).unwrap();
    for f in ["method", "global_bound_millionths", "per_field_bounds"] {
        assert!(json.contains(f), "missing field: {f}");
    }
}

#[test]
fn json_fields_dp_budget_semantics() {
    let dp = valid_dp_budget();
    let json = serde_json::to_string(&dp).unwrap();
    for f in [
        "epsilon_per_epoch_millionths",
        "delta_per_epoch_millionths",
        "composition_method",
        "lifetime_epsilon_budget_millionths",
        "lifetime_delta_budget_millionths",
        "fail_closed_on_exhaustion",
    ] {
        assert!(json.contains(f), "missing field: {f}");
    }
}

#[test]
fn json_fields_secure_aggregation_requirements() {
    let agg = valid_aggregation();
    let json = serde_json::to_string(&agg).unwrap();
    for f in [
        "min_participants",
        "dropout_tolerance_millionths",
        "secret_sharing_scheme",
        "sharing_threshold",
        "coordinator_trust_model",
    ] {
        assert!(json.contains(f), "missing field: {f}");
    }
}

#[test]
fn json_fields_data_retention_policy() {
    let ret = valid_retention();
    let json = serde_json::to_string(&ret).unwrap();
    for f in [
        "max_intermediate_retention",
        "max_snapshot_retention",
        "delete_local_after_submission",
        "delete_shares_after_aggregation",
    ] {
        assert!(json.contains(f), "missing field: {f}");
    }
}

#[test]
fn json_fields_privacy_learning_contract() {
    let contract = create_contract();
    let json = serde_json::to_string(&contract).unwrap();
    for f in [
        "contract_id",
        "epoch",
        "zone",
        "feature_schema",
        "update_policy",
        "clipping_strategy",
        "dp_budget",
        "aggregation",
        "retention",
        "governance_signature",
        "authorized_participants",
    ] {
        assert!(json.contains(f), "missing field: {f}");
    }
}

// ===========================================================================
// 8. Validation edge cases
// ===========================================================================

#[test]
fn schema_version_zero_rejected() {
    let mut schema = valid_schema();
    schema.version = 0;
    assert!(matches!(
        schema.validate(),
        Err(ContractError::InvalidVersion { .. })
    ));
}

#[test]
fn schema_prior_version_must_have_old_fields() {
    // All fields marked as not-prior = backward compatibility violation
    let mut fields = BTreeMap::new();
    fields.insert(
        "new_field".to_string(),
        FeatureField {
            name: "new_field".to_string(),
            field_type: FeatureFieldType::FixedPoint,
            description: "new".to_string(),
            existed_in_prior_version: false,
        },
    );
    let schema = FeatureSchema {
        version: 2,
        fields,
        prior_version: Some(1),
    };
    assert!(matches!(
        schema.validate(),
        Err(ContractError::BackwardCompatibilityViolation { .. })
    ));
}

#[test]
fn schema_prior_version_must_be_strictly_less() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "a".to_string(),
        FeatureField {
            name: "a".to_string(),
            field_type: FeatureFieldType::Counter,
            description: "a".to_string(),
            existed_in_prior_version: true,
        },
    );
    let schema = FeatureSchema {
        version: 1,
        fields,
        prior_version: Some(1),
    };
    assert!(matches!(
        schema.validate(),
        Err(ContractError::InvalidVersion { .. })
    ));
}

#[test]
fn update_policy_min_samples_zero_rejected() {
    let mut up = valid_update_policy();
    up.min_local_samples = 0;
    assert!(matches!(
        up.validate(),
        Err(ContractError::InvalidUpdatePolicy { .. })
    ));
}

#[test]
fn update_policy_skip_with_zero_max_consecutive() {
    let mut up = valid_update_policy();
    up.allow_skip = true;
    up.max_consecutive_skips = 0;
    assert!(matches!(
        up.validate(),
        Err(ContractError::InvalidUpdatePolicy { .. })
    ));
}

#[test]
fn update_policy_no_skip_with_zero_max_consecutive_ok() {
    let mut up = valid_update_policy();
    up.allow_skip = false;
    up.max_consecutive_skips = 0;
    assert!(up.validate().is_ok());
}

#[test]
fn clipping_per_field_bounds_invalid_with_l2norm() {
    let schema = valid_schema();
    let mut cs = ClippingStrategy {
        method: ClippingMethod::L2Norm,
        global_bound_millionths: 1_000_000,
        per_field_bounds: BTreeMap::new(),
    };
    cs.per_field_bounds.insert("loss".to_string(), 500_000);
    assert!(matches!(
        cs.validate(&schema),
        Err(ContractError::InvalidClippingStrategy { .. })
    ));
}

#[test]
fn clipping_per_field_bounds_unknown_field() {
    let schema = valid_schema();
    let mut cs = valid_clipping(&schema);
    cs.per_field_bounds
        .insert("nonexistent".to_string(), 1_000_000);
    assert!(matches!(
        cs.validate(&schema),
        Err(ContractError::InvalidClippingStrategy { .. })
    ));
}

#[test]
fn clipping_per_field_bound_negative_rejected() {
    let schema = valid_schema();
    let mut cs = valid_clipping(&schema);
    cs.per_field_bounds.insert("loss".to_string(), -1);
    assert!(matches!(
        cs.validate(&schema),
        Err(ContractError::InvalidClippingStrategy { .. })
    ));
}

#[test]
fn dp_budget_fail_closed_must_be_true() {
    let mut dp = valid_dp_budget();
    dp.fail_closed_on_exhaustion = false;
    assert!(matches!(
        dp.validate(),
        Err(ContractError::InvalidDpBudget { .. })
    ));
}

#[test]
fn dp_budget_epsilon_exceeds_lifetime_rejected() {
    let mut dp = valid_dp_budget();
    dp.epsilon_per_epoch_millionths = 2_000_000;
    assert!(matches!(
        dp.validate(),
        Err(ContractError::InvalidDpBudget { .. })
    ));
}

#[test]
fn aggregation_min_participants_one_rejected() {
    let mut agg = valid_aggregation();
    agg.min_participants = 1;
    assert!(matches!(
        agg.validate(),
        Err(ContractError::InvalidAggregation { .. })
    ));
}

#[test]
fn aggregation_shamir_without_threshold_rejected() {
    let mut agg = valid_aggregation();
    agg.secret_sharing_scheme = SecretSharingScheme::Shamir;
    agg.sharing_threshold = None;
    assert!(matches!(
        agg.validate(),
        Err(ContractError::InvalidAggregation { .. })
    ));
}

#[test]
fn aggregation_shamir_threshold_above_participants_rejected() {
    let mut agg = valid_aggregation();
    agg.secret_sharing_scheme = SecretSharingScheme::Shamir;
    agg.sharing_threshold = Some(20); // > min_participants(10)
    assert!(matches!(
        agg.validate(),
        Err(ContractError::InvalidAggregation { .. })
    ));
}

#[test]
fn aggregation_additive_with_threshold_rejected() {
    let mut agg = valid_aggregation();
    agg.sharing_threshold = Some(5);
    assert!(matches!(
        agg.validate(),
        Err(ContractError::InvalidAggregation { .. })
    ));
}

#[test]
fn retention_snapshot_less_than_intermediate_rejected() {
    let mut ret = valid_retention();
    ret.max_snapshot_retention = 100;
    ret.max_intermediate_retention = 200;
    assert!(matches!(
        ret.validate(),
        Err(ContractError::InvalidRetention { .. })
    ));
}

// ===========================================================================
// 9. DP budget max_epochs computation
// ===========================================================================

#[test]
fn dp_budget_max_epochs_basic_composition() {
    let dp = DpBudgetSemantics {
        epsilon_per_epoch_millionths: 100_000,
        delta_per_epoch_millionths: 1_000,
        composition_method: CompositionMethod::Basic,
        lifetime_epsilon_budget_millionths: 1_000_000,
        lifetime_delta_budget_millionths: 10_000,
        fail_closed_on_exhaustion: true,
    };
    // Basic: linear. epsilon epochs = 1M / 100K = 10. delta epochs = 10K / 1K = 10.
    assert_eq!(dp.max_epochs(), 10);
}

#[test]
fn dp_budget_max_epochs_advanced_composition() {
    let dp = DpBudgetSemantics {
        epsilon_per_epoch_millionths: 100_000,
        delta_per_epoch_millionths: 1_000,
        composition_method: CompositionMethod::Advanced,
        lifetime_epsilon_budget_millionths: 1_000_000,
        lifetime_delta_budget_millionths: 100_000,
        fail_closed_on_exhaustion: true,
    };
    // Advanced: O(sqrt(k)). ratio = 1M/100K = 10. k = 10^2 = 100.
    // delta epochs = 100K / 1K = 100. min(100, 100) = 100.
    assert_eq!(dp.max_epochs(), 100);
}

#[test]
fn dp_budget_max_epochs_delta_limited() {
    let dp = DpBudgetSemantics {
        epsilon_per_epoch_millionths: 100_000,
        delta_per_epoch_millionths: 10_000,
        composition_method: CompositionMethod::Basic,
        lifetime_epsilon_budget_millionths: 10_000_000,
        lifetime_delta_budget_millionths: 50_000,
        fail_closed_on_exhaustion: true,
    };
    // Basic epsilon: 10M/100K = 100. delta: 50K/10K = 5. min(100,5) = 5.
    assert_eq!(dp.max_epochs(), 5);
}

// ===========================================================================
// 10. Backward compatibility check
// ===========================================================================

#[test]
fn backward_compat_type_change_fails() {
    let prior = valid_schema();
    let mut next_fields = prior.fields.clone();
    // Change "loss" from FixedPoint to Counter
    next_fields.get_mut("loss").unwrap().field_type = FeatureFieldType::Counter;
    let next = FeatureSchema {
        version: 2,
        fields: next_fields,
        prior_version: Some(1),
    };
    assert!(!next.is_backward_compatible_with(&prior));
}

#[test]
fn backward_compat_removed_field_fails() {
    let prior = valid_schema();
    let mut next_fields = BTreeMap::new();
    // Only keep "loss", not "count"
    next_fields.insert("loss".to_string(), prior.fields["loss"].clone());
    let next = FeatureSchema {
        version: 2,
        fields: next_fields,
        prior_version: Some(1),
    };
    assert!(!next.is_backward_compatible_with(&prior));
}

// ===========================================================================
// 11. Contract Display format
// ===========================================================================

#[test]
fn contract_display_format() {
    let contract = create_contract();
    let display = format!("{contract}");
    assert!(display.contains("PrivacyLearningContract"));
    assert!(display.contains("us-east-1"));
    assert!(display.contains("schema_v=1"));
}

// ===========================================================================
// 12. PRNG edge cases
// ===========================================================================

#[test]
fn prng_empty_phase_id_rejected() {
    let result = DeterministicPrng::new("", PrngAlgorithm::ChaCha20LikeCounter, b"seed");
    assert!(result.is_err());
}

#[test]
fn prng_empty_seed_rejected() {
    let result = DeterministicPrng::new("phase", PrngAlgorithm::ChaCha20LikeCounter, b"");
    assert!(result.is_err());
}

#[test]
fn prng_different_phases_different_output() {
    let mut p1 =
        DeterministicPrng::new("phase_A", PrngAlgorithm::ChaCha20LikeCounter, b"seed").unwrap();
    let mut p2 =
        DeterministicPrng::new("phase_B", PrngAlgorithm::ChaCha20LikeCounter, b"seed").unwrap();
    assert_ne!(p1.next_u64(), p2.next_u64());
}

// ===========================================================================
// 13. Transcript snapshot summary
// ===========================================================================

#[test]
fn transcript_emit_and_verify_snapshot_summary() {
    let signing = sk();
    let vk = signing.verification_key();
    let eid = EngineObjectId::from_hex(
        "ee00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let mut transcript = RandomnessTranscript::new();
    transcript
        .commit_seed(
            &signing,
            "phase_1",
            b"seed_1",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            eid,
        )
        .unwrap();
    let summary = transcript
        .emit_snapshot_summary(&signing, "model-snap-1", "policy-snap-1")
        .unwrap();
    assert_eq!(summary.commitment_count, 1);
    assert_eq!(summary.start_sequence_counter, 1);
    assert_eq!(summary.end_sequence_counter, 1);
    assert!(transcript.verify_snapshot_summaries(&vk).is_ok());
}

#[test]
fn transcript_empty_cannot_emit_snapshot() {
    let signing = sk();
    let mut transcript = RandomnessTranscript::new();
    let result = transcript.emit_snapshot_summary(&signing, "m", "p");
    assert!(result.is_err());
}

// ===========================================================================
// 14. Seed escrow edge cases
// ===========================================================================

#[test]
fn seed_escrow_empty_phase_rejected() {
    let auditors: BTreeSet<String> = ["a".to_string()].into_iter().collect();
    let result = SeedEscrowRecord::create("", SecurityEpoch::from_raw(1), b"seed", auditors);
    assert!(result.is_err());
}

#[test]
fn seed_escrow_empty_seed_rejected() {
    let auditors: BTreeSet<String> = ["a".to_string()].into_iter().collect();
    let result = SeedEscrowRecord::create("phase", SecurityEpoch::from_raw(1), b"", auditors);
    assert!(result.is_err());
}

#[test]
fn seed_escrow_access_log_tracks_attempts() {
    let auditors: BTreeSet<String> = ["alice".to_string()].into_iter().collect();
    let mut escrow =
        SeedEscrowRecord::create("phase_1", SecurityEpoch::from_raw(1), b"secret", auditors)
            .unwrap();
    let _ = escrow.open_for_audit("bob", "unauthorized");
    let _ = escrow.open_for_audit("alice", "audit");
    assert_eq!(escrow.access_log.len(), 2);
    assert!(!escrow.access_log[0].approved);
    assert!(escrow.access_log[1].approved);
}

// ===========================================================================
// 15. SafetyMetricSnapshot edge cases
// ===========================================================================

#[test]
fn safety_metric_snapshot_missing_metric_fails() {
    let snap = SafetyMetricSnapshot {
        values_millionths: BTreeMap::from([
            (SafetyMetric::FalsePositiveRate, 100_000),
            // Missing other 4 metrics
        ]),
    };
    assert!(snap.validate().is_err());
}

#[test]
fn safety_metric_snapshot_value_missing_returns_zero() {
    let snap = SafetyMetricSnapshot {
        values_millionths: BTreeMap::new(),
    };
    assert_eq!(snap.metric_value(SafetyMetric::CalibrationError), 0);
}

// ===========================================================================
// 16. Shadow evaluation gate — pass E2E
// ===========================================================================

#[test]
fn shadow_gate_pass_e2e() {
    let contract = create_contract();
    let mut gate = ShadowEvaluationGate::new(gate_config()).unwrap();
    let candidate = passing_candidate(50_000, 500);
    let artifact = gate
        .evaluate_candidate(&contract, candidate, &sk())
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
    assert!(artifact.failure_reasons.is_empty());
    assert!(artifact.significant_improvement_count > 0);
    assert!(artifact.deterministic_replay_ok);
    assert!(artifact.privacy_budget_status.within_budget);
    // Should be promoted
    assert!(gate.active_artifact("policy-e1").is_some());
    // Events should include start, evaluation, promotion_gate, auto_enforcement
    assert!(gate.events().len() >= 4);
}

// ===========================================================================
// 17. Shadow evaluation gate — reject (regression)
// ===========================================================================

#[test]
fn shadow_gate_reject_regression() {
    let contract = create_contract();
    let mut gate = ShadowEvaluationGate::new(gate_config()).unwrap();
    let mut candidate = passing_candidate(50_000, 500);
    candidate.candidate_metrics = regressed_metrics();
    let artifact = gate
        .evaluate_candidate(&contract, candidate, &sk())
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(!artifact.failure_reasons.is_empty());
    // Should NOT be promoted
    assert!(gate.active_artifact("policy-e1").is_none());
}

// ===========================================================================
// 18. Shadow evaluation gate — reject (budget exceeded)
// ===========================================================================

#[test]
fn shadow_gate_reject_budget_exceeded() {
    let contract = create_contract();
    let mut gate = ShadowEvaluationGate::new(gate_config()).unwrap();
    // Spend more than the per-epoch budget (100_000 epsilon)
    let candidate = passing_candidate(200_000, 500);
    let artifact = gate
        .evaluate_candidate(&contract, candidate, &sk())
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(!artifact.privacy_budget_status.within_budget);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|r| r.contains("privacy budget"))
    );
}

// ===========================================================================
// 19. Shadow evaluation gate — human override
// ===========================================================================

#[test]
fn shadow_gate_human_override_after_rejection() {
    let contract = create_contract();
    let mut gate = ShadowEvaluationGate::new(gate_config()).unwrap();
    let mut candidate = passing_candidate(50_000, 500);
    candidate.candidate_metrics = regressed_metrics();
    let rejected = gate
        .evaluate_candidate(&contract, candidate, &sk())
        .unwrap();
    assert_eq!(rejected.verdict, ShadowPromotionVerdict::Reject);

    let override_req = HumanOverrideRequest {
        operator_id: "admin-1".to_string(),
        summary: "Approved despite regression due to urgent fix".to_string(),
        bypassed_risk_criteria: vec!["regression_tolerance".to_string()],
        acknowledged_bypass: true,
    };
    let overridden = gate
        .apply_human_override(&rejected, override_req, &sk())
        .unwrap();
    assert_eq!(overridden.verdict, ShadowPromotionVerdict::OverrideApproved);
    assert!(overridden.human_override.is_some());
    assert!(gate.active_artifact("policy-e1").is_some());
}

// ===========================================================================
// 20. Shadow evaluation gate — post-deployment rollback
// ===========================================================================

#[test]
fn shadow_gate_post_deployment_rollback() {
    let contract = create_contract();
    let mut gate = ShadowEvaluationGate::new(gate_config()).unwrap();
    let candidate = passing_candidate(50_000, 500);
    let promoted = gate
        .evaluate_candidate(&contract, candidate, &sk())
        .unwrap();
    assert_eq!(promoted.verdict, ShadowPromotionVerdict::Pass);

    let receipt = gate
        .evaluate_post_deployment_metrics(&promoted, regressed_metrics(), &sk())
        .unwrap();
    assert!(receipt.is_some(), "should trigger rollback");
    let receipt = receipt.unwrap();
    assert!(!receipt.triggered_regressions.is_empty());
    assert!(receipt.reason.contains("automatic rollback"));
    // Should be un-promoted
    assert!(gate.active_artifact("policy-e1").is_none());
}

// ===========================================================================
// 21. Shadow evaluation gate — post-deployment pass
// ===========================================================================

#[test]
fn shadow_gate_post_deployment_pass() {
    let contract = create_contract();
    let mut gate = ShadowEvaluationGate::new(gate_config()).unwrap();
    let candidate = passing_candidate(50_000, 500);
    let promoted = gate
        .evaluate_candidate(&contract, candidate, &sk())
        .unwrap();
    let receipt = gate
        .evaluate_post_deployment_metrics(&promoted, improved_metrics(), &sk())
        .unwrap();
    assert!(receipt.is_none(), "no rollback needed");
    // Still promoted
    assert!(gate.active_artifact("policy-e1").is_some());
}

// ===========================================================================
// 22. Shadow gate scorecard entries
// ===========================================================================

#[test]
fn shadow_gate_scorecard_entries() {
    let contract = create_contract();
    let mut gate = ShadowEvaluationGate::new(gate_config()).unwrap();
    let candidate = passing_candidate(50_000, 500);
    gate.evaluate_candidate(&contract, candidate, &sk())
        .unwrap();
    let entries = gate.scorecard_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].verdict, ShadowPromotionVerdict::Pass);
    assert_eq!(entries[0].policy_id, "policy-e1");
    assert_eq!(entries[0].extension_class, ShadowExtensionClass::Standard);
}

// ===========================================================================
// 23. Serde roundtrips for additional types
// ===========================================================================

#[test]
fn serde_roundtrip_update_policy() {
    let up = valid_update_policy();
    let json = serde_json::to_string(&up).unwrap();
    let back: UpdatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(up, back);
}

#[test]
fn serde_roundtrip_clipping_strategy() {
    let schema = valid_schema();
    let cs = valid_clipping(&schema);
    let json = serde_json::to_string(&cs).unwrap();
    let back: ClippingStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(cs, back);
}

#[test]
fn serde_roundtrip_dp_budget() {
    let dp = valid_dp_budget();
    let json = serde_json::to_string(&dp).unwrap();
    let back: DpBudgetSemantics = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, back);
}

#[test]
fn serde_roundtrip_aggregation() {
    let agg = valid_aggregation();
    let json = serde_json::to_string(&agg).unwrap();
    let back: SecureAggregationRequirements = serde_json::from_str(&json).unwrap();
    assert_eq!(agg, back);
}

#[test]
fn serde_roundtrip_retention() {
    let ret = valid_retention();
    let json = serde_json::to_string(&ret).unwrap();
    let back: DataRetentionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(ret, back);
}

#[test]
fn serde_roundtrip_shadow_gate_config() {
    let cfg = gate_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ShadowEvaluationGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// 24. Contract registry epoch ordering
// ===========================================================================

#[test]
fn registry_rejects_same_epoch_for_zone() {
    let signing = sk();
    let vk = signing.verification_key();
    let schema = valid_schema();
    let make = |epoch: u64| {
        PrivacyLearningContract::create_signed(
            &signing,
            CreateContractInput {
                epoch: SecurityEpoch::from_raw(epoch),
                zone: "us-east-1",
                feature_schema: schema.clone(),
                update_policy: valid_update_policy(),
                clipping_strategy: valid_clipping(&schema),
                dp_budget: valid_dp_budget(),
                aggregation: valid_aggregation(),
                retention: valid_retention(),
                authorized_participants: [participant_id()].into_iter().collect(),
            },
        )
        .unwrap()
    };
    let c1 = make(1);
    let c2 = make(1); // same epoch
    let mut reg = ContractRegistry::new();
    reg.register(c1, &vk, "t1").unwrap();
    // c2 has same epoch → should fail (or same ID → duplicate)
    let result = reg.register(c2, &vk, "t2");
    assert!(result.is_err());
}

#[test]
fn registry_accepts_higher_epoch_for_zone() {
    let signing = sk();
    let vk = signing.verification_key();
    let schema = valid_schema();
    let make = |epoch: u64| {
        PrivacyLearningContract::create_signed(
            &signing,
            CreateContractInput {
                epoch: SecurityEpoch::from_raw(epoch),
                zone: "us-east-1",
                feature_schema: schema.clone(),
                update_policy: valid_update_policy(),
                clipping_strategy: valid_clipping(&schema),
                dp_budget: valid_dp_budget(),
                aggregation: valid_aggregation(),
                retention: valid_retention(),
                authorized_participants: [participant_id()].into_iter().collect(),
            },
        )
        .unwrap()
    };
    let c1 = make(1);
    let c2 = make(2);
    let mut reg = ContractRegistry::new();
    reg.register(c1, &vk, "t1").unwrap();
    reg.register(c2, &vk, "t2").unwrap();
    assert_eq!(reg.total_count(), 2);
    // Active should be epoch 2
    let active = reg.active_for_zone("us-east-1").unwrap();
    assert_eq!(active.epoch, SecurityEpoch::from_raw(2));
}

// ===========================================================================
// 25. ShadowBurnInThresholdProfile default
// ===========================================================================

#[test]
fn shadow_burn_in_threshold_profile_default() {
    let profile = ShadowBurnInThresholdProfile::default();
    assert_eq!(profile.min_shadow_success_rate_millionths, 995_000);
    assert_eq!(profile.max_false_deny_rate_millionths, 5_000);
    assert!(profile.min_burn_in_duration_ns > 0);
    assert!(profile.require_verified_rollback_artifacts);
}

// ===========================================================================
// 26. ShadowEvaluationGateConfig default
// ===========================================================================

#[test]
fn shadow_evaluation_gate_config_default() {
    let cfg = ShadowEvaluationGateConfig::default();
    assert_eq!(cfg.regression_tolerance_millionths, 5_000);
    assert_eq!(cfg.min_required_improvement_millionths, 2_500);
    // Should have burn-in profiles for LowRisk, HighRisk, Critical
    assert!(
        cfg.burn_in_profiles_by_extension_class
            .contains_key(&ShadowExtensionClass::LowRisk)
    );
    assert!(
        cfg.burn_in_profiles_by_extension_class
            .contains_key(&ShadowExtensionClass::HighRisk)
    );
    assert!(
        cfg.burn_in_profiles_by_extension_class
            .contains_key(&ShadowExtensionClass::Critical)
    );
}

// ===========================================================================
// 27. Contract creation with no participants fails
// ===========================================================================

#[test]
fn contract_no_participants_rejected() {
    let schema = valid_schema();
    let result = PrivacyLearningContract::create_signed(
        &sk(),
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(1),
            zone: "zone-1",
            feature_schema: schema.clone(),
            update_policy: valid_update_policy(),
            clipping_strategy: valid_clipping(&schema),
            dp_budget: valid_dp_budget(),
            aggregation: valid_aggregation(),
            retention: valid_retention(),
            authorized_participants: BTreeSet::new(),
        },
    );
    assert!(matches!(
        result,
        Err(ContractError::NoAuthorizedParticipants)
    ));
}

// ===========================================================================
// 28. ShadowExtensionClass default
// ===========================================================================

#[test]
fn shadow_extension_class_default_is_standard() {
    assert_eq!(
        ShadowExtensionClass::default(),
        ShadowExtensionClass::Standard
    );
}
