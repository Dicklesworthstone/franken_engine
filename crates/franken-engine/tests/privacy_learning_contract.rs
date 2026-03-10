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
    ClippingMethod, ClippingStrategy, CompositionMethod, ContractError, ContractEvent,
    ContractEventType, ContractRegistry, CoordinatorTrustModel, CreateContractInput,
    DataRetentionPolicy, DeterministicPrng, DpBudgetSemantics, FeatureField, FeatureFieldType,
    FeatureSchema, HumanOverrideRequest, PrivacyLearningContract, PrngAlgorithm, ReplayOutput,
    SafetyMetric, SafetyMetricSnapshot, SecretSharingScheme, SecureAggregationRequirements,
    SeedEscrowAccessEvent, SeedEscrowRecord, ShadowBurnInScorecardEntry,
    ShadowBurnInThresholdProfile, ShadowEvaluationCandidate, ShadowEvaluationGate,
    ShadowEvaluationGateConfig, ShadowExtensionClass, ShadowGateEvent, ShadowMetricAssessment,
    ShadowPrivacyBudgetStatus, ShadowPromotionVerdict, ShadowReplayReference,
    ShadowRollbackIncidentReceipt, ShadowRollbackReadinessArtifacts, UpdatePolicy, contract_schema,
    contract_schema_id,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x01; 32])
}

fn test_vk() -> frankenengine_engine::signature_preimage::VerificationKey {
    test_signing_key().verification_key()
}

fn test_participants() -> BTreeSet<EngineObjectId> {
    let mut set = BTreeSet::new();
    set.insert(EngineObjectId([0xAA; 32]));
    set.insert(EngineObjectId([0xBB; 32]));
    set
}

fn test_feature_schema() -> FeatureSchema {
    let mut fields = BTreeMap::new();
    fields.insert(
        "residual".to_string(),
        FeatureField {
            name: "residual".to_string(),
            field_type: FeatureFieldType::FixedPoint,
            description: "Calibration residual".to_string(),
            existed_in_prior_version: false,
        },
    );
    fields.insert(
        "drift_flag".to_string(),
        FeatureField {
            name: "drift_flag".to_string(),
            field_type: FeatureFieldType::Boolean,
            description: "Drift detected".to_string(),
            existed_in_prior_version: false,
        },
    );
    FeatureSchema {
        version: 1,
        fields,
        prior_version: None,
    }
}

fn test_update_policy() -> UpdatePolicy {
    UpdatePolicy {
        min_local_samples: 50,
        min_submission_interval: 3600,
        max_data_age: 86400,
        allow_skip: true,
        max_consecutive_skips: 2,
    }
}

fn test_clipping() -> ClippingStrategy {
    ClippingStrategy {
        method: ClippingMethod::L2Norm,
        global_bound_millionths: 1_000_000,
        per_field_bounds: BTreeMap::new(),
    }
}

fn test_dp_budget() -> DpBudgetSemantics {
    DpBudgetSemantics {
        epsilon_per_epoch_millionths: 100_000,
        delta_per_epoch_millionths: 1_000,
        composition_method: CompositionMethod::Renyi,
        lifetime_epsilon_budget_millionths: 10_000_000,
        lifetime_delta_budget_millionths: 100_000,
        fail_closed_on_exhaustion: true,
    }
}

fn test_aggregation() -> SecureAggregationRequirements {
    SecureAggregationRequirements {
        min_participants: 5,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Additive,
        sharing_threshold: None,
        coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
    }
}

fn test_retention() -> DataRetentionPolicy {
    DataRetentionPolicy {
        max_intermediate_retention: 86400,
        max_snapshot_retention: 604800,
        delete_local_after_submission: true,
        delete_shares_after_aggregation: true,
    }
}

fn test_contract_input() -> CreateContractInput<'static> {
    CreateContractInput {
        epoch: SecurityEpoch::from_raw(1),
        zone: "integration-zone",
        feature_schema: test_feature_schema(),
        update_policy: test_update_policy(),
        clipping_strategy: test_clipping(),
        dp_budget: test_dp_budget(),
        aggregation: test_aggregation(),
        retention: test_retention(),
        authorized_participants: test_participants(),
    }
}

fn create_contract() -> PrivacyLearningContract {
    PrivacyLearningContract::create_signed(&test_signing_key(), test_contract_input())
        .expect("contract creation")
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

fn test_replay_ref() -> ShadowReplayReference {
    ShadowReplayReference {
        replay_corpus_id: "corpus-integration".to_string(),
        randomness_snapshot_id: "rng-snap-1".to_string(),
        replay_seed_hash: [0x5A; 32],
        replay_seed_counter: 7,
    }
}

fn test_rollback_readiness() -> ShadowRollbackReadinessArtifacts {
    ShadowRollbackReadinessArtifacts {
        rollback_command_tested: true,
        previous_policy_snapshot_id: "snap-prev".to_string(),
        transition_receipt_signed: true,
        rollback_playbook_ref: "playbook://rollback-v1".to_string(),
    }
}

fn test_candidate(
    metrics: SafetyMetricSnapshot,
    epsilon: i64,
    delta: i64,
) -> ShadowEvaluationCandidate {
    ShadowEvaluationCandidate {
        trace_id: "trace-int-1".to_string(),
        decision_id: "decision-int-1".to_string(),
        policy_id: "policy-int-1".to_string(),
        extension_class: ShadowExtensionClass::Standard,
        candidate_version: "v2026.03.04".to_string(),
        baseline_snapshot_id: "snap-prev".to_string(),
        rollback_token: "rollback-tok-1".to_string(),
        epoch_id: SecurityEpoch::from_raw(5),
        shadow_started_at_ns: 1_000_000_000,
        evaluation_completed_at_ns: 1_000_000_200,
        shadow_success_rate_millionths: 997_000,
        false_deny_rate_millionths: 4_000,
        rollback_readiness: test_rollback_readiness(),
        baseline_metrics: baseline_metrics(),
        candidate_metrics: metrics,
        replay_reference: test_replay_ref(),
        epsilon_spent_millionths: epsilon,
        delta_spent_millionths: delta,
    }
}

fn test_gate() -> ShadowEvaluationGate {
    ShadowEvaluationGate::new(ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 5_000,
        min_required_improvement_millionths: 2_500,
        default_burn_in_profile: ShadowBurnInThresholdProfile {
            min_shadow_success_rate_millionths: 995_000,
            max_false_deny_rate_millionths: 5_000,
            min_burn_in_duration_ns: 100,
            require_verified_rollback_artifacts: true,
        },
        burn_in_profiles_by_extension_class: BTreeMap::new(),
    })
    .expect("gate creation")
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn feature_field_type_serde_roundtrip() {
    for v in [
        FeatureFieldType::FixedPoint,
        FeatureFieldType::Counter,
        FeatureFieldType::Boolean,
        FeatureFieldType::Categorical,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let r: FeatureFieldType = serde_json::from_str(&json).unwrap();
        assert_eq!(v, r);
    }
}

#[test]
fn clipping_method_serde_roundtrip() {
    for v in [
        ClippingMethod::L2Norm,
        ClippingMethod::PerCoordinate,
        ClippingMethod::Adaptive,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let r: ClippingMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(v, r);
    }
}

#[test]
fn composition_method_serde_roundtrip() {
    for v in [
        CompositionMethod::Basic,
        CompositionMethod::Advanced,
        CompositionMethod::Renyi,
        CompositionMethod::ZeroCdp,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let r: CompositionMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(v, r);
    }
}

#[test]
fn coordinator_trust_model_serde_roundtrip() {
    for v in [
        CoordinatorTrustModel::HonestButCurious,
        CoordinatorTrustModel::Malicious,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let r: CoordinatorTrustModel = serde_json::from_str(&json).unwrap();
        assert_eq!(v, r);
    }
}

#[test]
fn secret_sharing_scheme_serde_roundtrip() {
    for v in [SecretSharingScheme::Additive, SecretSharingScheme::Shamir] {
        let json = serde_json::to_string(&v).unwrap();
        let r: SecretSharingScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(v, r);
    }
}

#[test]
fn prng_algorithm_serde_roundtrip() {
    let v = PrngAlgorithm::ChaCha20LikeCounter;
    let json = serde_json::to_string(&v).unwrap();
    let r: PrngAlgorithm = serde_json::from_str(&json).unwrap();
    assert_eq!(v, r);
}

#[test]
fn safety_metric_serde_roundtrip() {
    for v in SafetyMetric::ALL {
        let json = serde_json::to_string(v).unwrap();
        let r: SafetyMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, r);
    }
}

#[test]
fn shadow_extension_class_serde_roundtrip() {
    for v in [
        ShadowExtensionClass::LowRisk,
        ShadowExtensionClass::Standard,
        ShadowExtensionClass::HighRisk,
        ShadowExtensionClass::Critical,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let r: ShadowExtensionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(v, r);
    }
}

#[test]
fn shadow_promotion_verdict_serde_roundtrip() {
    for v in [
        ShadowPromotionVerdict::Pass,
        ShadowPromotionVerdict::Reject,
        ShadowPromotionVerdict::OverrideApproved,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let r: ShadowPromotionVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, r);
    }
}

#[test]
fn contract_error_serde_roundtrip_all_variants() {
    let errors: Vec<ContractError> = vec![
        ContractError::EmptyFeatureSchema,
        ContractError::InvalidVersion {
            detail: "v0".into(),
        },
        ContractError::FieldNameMismatch {
            key: "k".into(),
            field_name: "f".into(),
        },
        ContractError::BackwardCompatibilityViolation {
            detail: "bc".into(),
        },
        ContractError::InvalidUpdatePolicy {
            detail: "up".into(),
        },
        ContractError::InvalidClippingStrategy {
            detail: "cs".into(),
        },
        ContractError::InvalidDpBudget {
            detail: "dp".into(),
        },
        ContractError::InvalidAggregation {
            detail: "ag".into(),
        },
        ContractError::InvalidRetention {
            detail: "rt".into(),
        },
        ContractError::InvalidRandomnessTranscript {
            detail: "rn".into(),
        },
        ContractError::MissingSeedEscrow {
            phase_id: "p".into(),
            epoch_id: SecurityEpoch::from_raw(1),
        },
        ContractError::SeedEscrowAccessDenied {
            principal: "pr".into(),
            phase_id: "ph".into(),
        },
        ContractError::SeedHashMismatch {
            phase_id: "p".into(),
        },
        ContractError::NoAuthorizedParticipants,
        ContractError::IdDerivationFailed {
            detail: "id".into(),
        },
        ContractError::SignatureFailed {
            detail: "sf".into(),
        },
        ContractError::SignatureInvalid {
            detail: "si".into(),
        },
        ContractError::DuplicateContract {
            contract_id: EngineObjectId([0xAA; 32]),
        },
        ContractError::NotFound {
            contract_id: EngineObjectId([0xBB; 32]),
        },
        ContractError::EpochNotAdvanced {
            zone: "z".into(),
            existing_epoch: SecurityEpoch::from_raw(1),
            new_epoch: SecurityEpoch::from_raw(1),
        },
        ContractError::InvalidShadowEvaluation {
            detail: "se".into(),
        },
        ContractError::InvalidShadowOverride {
            detail: "so".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let r: ContractError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, r);
    }
}

#[test]
fn contract_event_type_serde_roundtrip() {
    let variants = vec![
        ContractEventType::Registered {
            contract_id: EngineObjectId([0xAA; 32]),
            zone: "z".into(),
            epoch: SecurityEpoch::from_raw(3),
        },
        ContractEventType::Revoked {
            contract_id: EngineObjectId([0xBB; 32]),
            zone: "z".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let r: ContractEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, r);
    }
}

// ---------------------------------------------------------------------------
// Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn feature_field_type_display_all_unique() {
    let displays: BTreeSet<String> = [
        FeatureFieldType::FixedPoint,
        FeatureFieldType::Counter,
        FeatureFieldType::Boolean,
        FeatureFieldType::Categorical,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn clipping_method_display_all_unique() {
    let displays: BTreeSet<String> = [
        ClippingMethod::L2Norm,
        ClippingMethod::PerCoordinate,
        ClippingMethod::Adaptive,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn composition_method_display_all_unique() {
    let displays: BTreeSet<String> = [
        CompositionMethod::Basic,
        CompositionMethod::Advanced,
        CompositionMethod::Renyi,
        CompositionMethod::ZeroCdp,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn safety_metric_display_all_unique() {
    let displays: BTreeSet<String> = SafetyMetric::ALL.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn contract_error_display_all_nonempty() {
    let errors = vec![
        ContractError::EmptyFeatureSchema,
        ContractError::InvalidVersion { detail: "x".into() },
        ContractError::NoAuthorizedParticipants,
        ContractError::InvalidShadowEvaluation { detail: "y".into() },
    ];
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty(), "empty display for {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Schema functions
// ---------------------------------------------------------------------------

#[test]
fn contract_schema_deterministic() {
    let s1 = contract_schema();
    let s2 = contract_schema();
    assert_eq!(s1, s2);
}

#[test]
fn contract_schema_id_deterministic() {
    let s1 = contract_schema_id();
    let s2 = contract_schema_id();
    assert_eq!(s1, s2);
}

// ---------------------------------------------------------------------------
// FeatureSchema validation
// ---------------------------------------------------------------------------

#[test]
fn feature_schema_validates_successfully() {
    test_feature_schema().validate().unwrap();
}

#[test]
fn feature_schema_empty_fields_rejected() {
    let schema = FeatureSchema {
        version: 1,
        fields: BTreeMap::new(),
        prior_version: None,
    };
    assert!(matches!(
        schema.validate(),
        Err(ContractError::EmptyFeatureSchema)
    ));
}

#[test]
fn feature_schema_version_zero_rejected() {
    let mut schema = test_feature_schema();
    schema.version = 0;
    assert!(matches!(
        schema.validate(),
        Err(ContractError::InvalidVersion { .. })
    ));
}

#[test]
fn feature_schema_backward_compatibility_check() {
    let v1 = test_feature_schema();
    let mut v2_fields = v1.fields.clone();
    for field in v2_fields.values_mut() {
        field.existed_in_prior_version = true;
    }
    v2_fields.insert(
        "new_counter".to_string(),
        FeatureField {
            name: "new_counter".to_string(),
            field_type: FeatureFieldType::Counter,
            description: "New counter".to_string(),
            existed_in_prior_version: false,
        },
    );
    let v2 = FeatureSchema {
        version: 2,
        fields: v2_fields,
        prior_version: Some(1),
    };
    v2.validate().unwrap();
    assert!(v2.is_backward_compatible_with(&v1));
}

#[test]
fn feature_schema_type_change_breaks_compatibility() {
    let v1 = test_feature_schema();
    let mut v2_fields = v1.fields.clone();
    if let Some(f) = v2_fields.get_mut("residual") {
        f.field_type = FeatureFieldType::Counter;
        f.existed_in_prior_version = true;
    }
    let v2 = FeatureSchema {
        version: 2,
        fields: v2_fields,
        prior_version: Some(1),
    };
    assert!(!v2.is_backward_compatible_with(&v1));
}

#[test]
fn feature_schema_serde_roundtrip() {
    let schema = test_feature_schema();
    let json = serde_json::to_string(&schema).unwrap();
    let r: FeatureSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, r);
}

// ---------------------------------------------------------------------------
// UpdatePolicy validation
// ---------------------------------------------------------------------------

#[test]
fn update_policy_valid() {
    test_update_policy().validate().unwrap();
}

#[test]
fn update_policy_zero_samples_rejected() {
    let mut p = test_update_policy();
    p.min_local_samples = 0;
    assert!(matches!(
        p.validate(),
        Err(ContractError::InvalidUpdatePolicy { .. })
    ));
}

#[test]
fn update_policy_serde_roundtrip() {
    let p = test_update_policy();
    let json = serde_json::to_string(&p).unwrap();
    let r: UpdatePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, r);
}

// ---------------------------------------------------------------------------
// ClippingStrategy validation
// ---------------------------------------------------------------------------

#[test]
fn clipping_strategy_valid() {
    test_clipping().validate(&test_feature_schema()).unwrap();
}

#[test]
fn clipping_per_field_with_l2_rejected() {
    let mut c = test_clipping();
    c.per_field_bounds.insert("residual".to_string(), 500_000);
    assert!(matches!(
        c.validate(&test_feature_schema()),
        Err(ContractError::InvalidClippingStrategy { .. })
    ));
}

#[test]
fn clipping_per_coordinate_with_valid_field() {
    let mut c = test_clipping();
    c.method = ClippingMethod::PerCoordinate;
    c.per_field_bounds.insert("residual".to_string(), 500_000);
    c.validate(&test_feature_schema()).unwrap();
}

#[test]
fn clipping_strategy_serde_roundtrip() {
    let c = test_clipping();
    let json = serde_json::to_string(&c).unwrap();
    let r: ClippingStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(c, r);
}

// ---------------------------------------------------------------------------
// DpBudgetSemantics
// ---------------------------------------------------------------------------

#[test]
fn dp_budget_valid() {
    test_dp_budget().validate().unwrap();
}

#[test]
fn dp_budget_fail_open_rejected() {
    let mut b = test_dp_budget();
    b.fail_closed_on_exhaustion = false;
    assert!(matches!(
        b.validate(),
        Err(ContractError::InvalidDpBudget { .. })
    ));
}

#[test]
fn dp_budget_max_epochs_basic() {
    let mut b = test_dp_budget();
    b.composition_method = CompositionMethod::Basic;
    b.epsilon_per_epoch_millionths = 1_000_000;
    b.lifetime_epsilon_budget_millionths = 10_000_000;
    assert_eq!(b.max_epochs(), 10);
}

#[test]
fn dp_budget_max_epochs_renyi_sqrt() {
    let mut b = test_dp_budget();
    b.composition_method = CompositionMethod::Renyi;
    b.epsilon_per_epoch_millionths = 1_000_000;
    b.lifetime_epsilon_budget_millionths = 10_000_000;
    // sqrt composition: (10)^2 = 100
    assert_eq!(b.max_epochs(), 100);
}

#[test]
fn dp_budget_serde_roundtrip() {
    let b = test_dp_budget();
    let json = serde_json::to_string(&b).unwrap();
    let r: DpBudgetSemantics = serde_json::from_str(&json).unwrap();
    assert_eq!(b, r);
}

// ---------------------------------------------------------------------------
// SecureAggregationRequirements
// ---------------------------------------------------------------------------

#[test]
fn aggregation_additive_valid() {
    test_aggregation().validate().unwrap();
}

#[test]
fn aggregation_shamir_valid() {
    let agg = SecureAggregationRequirements {
        min_participants: 10,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Shamir,
        sharing_threshold: Some(7),
        coordinator_trust_model: CoordinatorTrustModel::Malicious,
    };
    agg.validate().unwrap();
}

#[test]
fn aggregation_shamir_no_threshold_rejected() {
    let agg = SecureAggregationRequirements {
        min_participants: 10,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Shamir,
        sharing_threshold: None,
        coordinator_trust_model: CoordinatorTrustModel::Malicious,
    };
    assert!(matches!(
        agg.validate(),
        Err(ContractError::InvalidAggregation { .. })
    ));
}

#[test]
fn aggregation_serde_roundtrip() {
    let a = test_aggregation();
    let json = serde_json::to_string(&a).unwrap();
    let r: SecureAggregationRequirements = serde_json::from_str(&json).unwrap();
    assert_eq!(a, r);
}

// ---------------------------------------------------------------------------
// DataRetentionPolicy
// ---------------------------------------------------------------------------

#[test]
fn retention_valid() {
    test_retention().validate().unwrap();
}

#[test]
fn retention_snapshot_less_than_intermediate_rejected() {
    let mut r = test_retention();
    r.max_intermediate_retention = 1000;
    r.max_snapshot_retention = 500;
    assert!(matches!(
        r.validate(),
        Err(ContractError::InvalidRetention { .. })
    ));
}

#[test]
fn retention_serde_roundtrip() {
    let r = test_retention();
    let json = serde_json::to_string(&r).unwrap();
    let restored: DataRetentionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(r, restored);
}

// ---------------------------------------------------------------------------
// PrivacyLearningContract creation and verification
// ---------------------------------------------------------------------------

#[test]
fn contract_creation_and_signature_verification() {
    let contract = create_contract();
    assert_eq!(contract.zone, "integration-zone");
    assert_eq!(contract.epoch, SecurityEpoch::from_raw(1));
    contract.verify_governance_signature(&test_vk()).unwrap();
}

#[test]
fn contract_creation_deterministic() {
    let c1 = create_contract();
    let c2 = create_contract();
    assert_eq!(c1.contract_id, c2.contract_id);
    assert_eq!(c1.governance_signature, c2.governance_signature);
}

#[test]
fn contract_wrong_key_fails_verification() {
    let contract = create_contract();
    let wrong = SigningKey::from_bytes([0xFF; 32]).verification_key();
    assert!(matches!(
        contract.verify_governance_signature(&wrong),
        Err(ContractError::SignatureInvalid { .. })
    ));
}

#[test]
fn contract_no_participants_rejected() {
    let mut input = test_contract_input();
    input.authorized_participants = BTreeSet::new();
    assert!(matches!(
        PrivacyLearningContract::create_signed(&test_signing_key(), input),
        Err(ContractError::NoAuthorizedParticipants)
    ));
}

#[test]
fn contract_is_authorized() {
    let contract = create_contract();
    assert!(contract.is_authorized(&EngineObjectId([0xAA; 32])));
    assert!(!contract.is_authorized(&EngineObjectId([0xFF; 32])));
}

#[test]
fn contract_display_contains_zone() {
    let contract = create_contract();
    let s = contract.to_string();
    assert!(s.contains("integration-zone"));
    assert!(s.contains("PrivacyLearningContract"));
}

#[test]
fn contract_serde_roundtrip() {
    let c = create_contract();
    let json = serde_json::to_string(&c).unwrap();
    let r: PrivacyLearningContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, r);
}

#[test]
fn contract_clone_independence() {
    let c1 = create_contract();
    let mut c2 = c1.clone();
    c2.zone = "mutated-zone".to_string();
    assert_ne!(c1.zone, c2.zone);
}

// ---------------------------------------------------------------------------
// ContractRegistry
// ---------------------------------------------------------------------------

#[test]
fn registry_starts_empty() {
    let r = ContractRegistry::new();
    assert_eq!(r.total_count(), 0);
    assert_eq!(r.zone_count(), 0);
    assert!(r.active_for_zone("integration-zone").is_none());
}

#[test]
fn registry_default_same_as_new() {
    let r1 = ContractRegistry::new();
    let r2 = ContractRegistry::default();
    assert_eq!(r1.total_count(), r2.total_count());
}

#[test]
fn registry_register_and_lookup() {
    let mut reg = ContractRegistry::new();
    let contract = create_contract();
    let id = reg
        .register(contract.clone(), &test_vk(), "trace-reg")
        .unwrap();
    assert_eq!(reg.total_count(), 1);
    assert_eq!(reg.zone_count(), 1);
    assert!(reg.get(&id).is_some());
    let active = reg.active_for_zone("integration-zone").unwrap();
    assert_eq!(active.contract_id, id);
}

#[test]
fn registry_duplicate_rejected() {
    let mut reg = ContractRegistry::new();
    let c = create_contract();
    reg.register(c.clone(), &test_vk(), "t1").unwrap();
    assert!(matches!(
        reg.register(c, &test_vk(), "t2"),
        Err(ContractError::DuplicateContract { .. })
    ));
}

#[test]
fn registry_epoch_advance_required() {
    let mut reg = ContractRegistry::new();
    reg.register(create_contract(), &test_vk(), "t1").unwrap();

    let mut input2 = test_contract_input();
    input2.feature_schema.version = 2;
    let c2 = PrivacyLearningContract::create_signed(&test_signing_key(), input2).unwrap();
    assert!(matches!(
        reg.register(c2, &test_vk(), "t2"),
        Err(ContractError::EpochNotAdvanced { .. })
    ));
}

#[test]
fn registry_epoch_upgrade_succeeds() {
    let mut reg = ContractRegistry::new();
    reg.register(create_contract(), &test_vk(), "t1").unwrap();

    let mut input2 = test_contract_input();
    input2.epoch = SecurityEpoch::from_raw(2);
    let c2 = PrivacyLearningContract::create_signed(&test_signing_key(), input2).unwrap();
    let id2 = reg.register(c2, &test_vk(), "t2").unwrap();
    let active = reg.active_for_zone("integration-zone").unwrap();
    assert_eq!(active.contract_id, id2);
    assert_eq!(active.epoch, SecurityEpoch::from_raw(2));
}

#[test]
fn registry_revoke() {
    let mut reg = ContractRegistry::new();
    let c = create_contract();
    let id = reg.register(c, &test_vk(), "t1").unwrap();
    reg.revoke(&id, "t-revoke").unwrap();
    assert_eq!(reg.total_count(), 0);
    assert!(reg.active_for_zone("integration-zone").is_none());
}

#[test]
fn registry_revoke_not_found() {
    let mut reg = ContractRegistry::new();
    assert!(matches!(
        reg.revoke(&EngineObjectId([0xFF; 32]), "t"),
        Err(ContractError::NotFound { .. })
    ));
}

#[test]
fn registry_events_on_register_and_revoke() {
    let mut reg = ContractRegistry::new();
    let c = create_contract();
    let id = reg.register(c, &test_vk(), "t1").unwrap();
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        ContractEventType::Registered { .. }
    ));
    assert_eq!(events[0].trace_id, "t1");

    reg.revoke(&id, "t-revoke").unwrap();
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        ContractEventType::Revoked { .. }
    ));
}

#[test]
fn registry_serde_roundtrip() {
    let reg = ContractRegistry::new();
    let json = serde_json::to_string(&reg).unwrap();
    let r: ContractRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg.total_count(), r.total_count());
}

// ---------------------------------------------------------------------------
// DeterministicPrng
// ---------------------------------------------------------------------------

#[test]
fn prng_reproducibility() {
    let mut p1 = DeterministicPrng::new(
        "phase-test",
        PrngAlgorithm::ChaCha20LikeCounter,
        b"seed-data",
    )
    .unwrap();
    let mut p2 = DeterministicPrng::new(
        "phase-test",
        PrngAlgorithm::ChaCha20LikeCounter,
        b"seed-data",
    )
    .unwrap();
    let s1: Vec<u64> = (0..10).map(|_| p1.next_u64()).collect();
    let s2: Vec<u64> = (0..10).map(|_| p2.next_u64()).collect();
    assert_eq!(s1, s2);
}

#[test]
fn prng_draw_counter_increments() {
    let mut p =
        DeterministicPrng::new("phase-cnt", PrngAlgorithm::ChaCha20LikeCounter, b"s").unwrap();
    assert_eq!(p.draw_counter(), 0);
    p.next_u64();
    assert_eq!(p.draw_counter(), 1);
    p.next_u64();
    p.next_u64();
    assert_eq!(p.draw_counter(), 3);
}

#[test]
fn prng_empty_phase_rejected() {
    assert!(matches!(
        DeterministicPrng::new("  ", PrngAlgorithm::ChaCha20LikeCounter, b"s"),
        Err(ContractError::InvalidRandomnessTranscript { .. })
    ));
}

#[test]
fn prng_empty_seed_rejected() {
    assert!(matches!(
        DeterministicPrng::new("phase", PrngAlgorithm::ChaCha20LikeCounter, b""),
        Err(ContractError::InvalidRandomnessTranscript { .. })
    ));
}

#[test]
fn prng_different_seeds_produce_different_outputs() {
    let mut p1 =
        DeterministicPrng::new("phase", PrngAlgorithm::ChaCha20LikeCounter, b"seed-a").unwrap();
    let mut p2 =
        DeterministicPrng::new("phase", PrngAlgorithm::ChaCha20LikeCounter, b"seed-b").unwrap();
    let s1: Vec<u64> = (0..5).map(|_| p1.next_u64()).collect();
    let s2: Vec<u64> = (0..5).map(|_| p2.next_u64()).collect();
    assert_ne!(s1, s2);
}

// ---------------------------------------------------------------------------
// Randomness transcript
// ---------------------------------------------------------------------------

#[test]
fn randomness_transcript_commit_and_verify_chain() {
    let mut transcript =
        frankenengine_engine::privacy_learning_contract::RandomnessTranscript::new();
    let sk = test_signing_key();
    let epoch = SecurityEpoch::from_raw(7);

    let c1 = transcript
        .commit_seed(
            &sk,
            "noise-phase",
            b"seed-noise",
            PrngAlgorithm::ChaCha20LikeCounter,
            epoch,
            EngineObjectId([0x11; 32]),
        )
        .unwrap()
        .clone();
    let c2 = transcript
        .commit_seed(
            &sk,
            "dropout-phase",
            b"seed-dropout",
            PrngAlgorithm::ChaCha20LikeCounter,
            epoch,
            EngineObjectId([0x12; 32]),
        )
        .unwrap()
        .clone();

    assert_eq!(c1.sequence_counter, 1);
    assert_eq!(c2.sequence_counter, 2);
    assert_eq!(c2.previous_commitment_hash, Some(c1.commitment_hash));
    transcript.verify_chain(&test_vk()).unwrap();
}

#[test]
fn randomness_transcript_snapshot_summary_verifies() {
    let mut transcript =
        frankenengine_engine::privacy_learning_contract::RandomnessTranscript::new();
    let sk = test_signing_key();
    let epoch = SecurityEpoch::from_raw(3);

    transcript
        .commit_seed(
            &sk,
            "p-a",
            b"s-a",
            PrngAlgorithm::ChaCha20LikeCounter,
            epoch,
            EngineObjectId([0x21; 32]),
        )
        .unwrap();
    transcript
        .emit_snapshot_summary(&sk, "model-1", "policy-1")
        .unwrap();
    transcript.verify_snapshot_summaries(&test_vk()).unwrap();
}

#[test]
fn randomness_transcript_tamper_detected() {
    let mut transcript =
        frankenengine_engine::privacy_learning_contract::RandomnessTranscript::new();
    let sk = test_signing_key();
    let epoch = SecurityEpoch::from_raw(5);

    transcript
        .commit_seed(
            &sk,
            "p1",
            b"s1",
            PrngAlgorithm::ChaCha20LikeCounter,
            epoch,
            EngineObjectId([0x31; 32]),
        )
        .unwrap();
    transcript
        .commit_seed(
            &sk,
            "p2",
            b"s2",
            PrngAlgorithm::ChaCha20LikeCounter,
            epoch,
            EngineObjectId([0x32; 32]),
        )
        .unwrap();
    // Tamper
    transcript.commitments[1].previous_commitment_hash = None;
    assert!(matches!(
        transcript.verify_chain(&test_vk()),
        Err(ContractError::InvalidRandomnessTranscript { .. })
    ));
}

#[test]
fn randomness_transcript_serde_roundtrip() {
    let mut transcript =
        frankenengine_engine::privacy_learning_contract::RandomnessTranscript::new();
    let sk = test_signing_key();
    transcript
        .commit_seed(
            &sk,
            "p",
            b"s",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            EngineObjectId([0x41; 32]),
        )
        .unwrap();
    let json = serde_json::to_string(&transcript).unwrap();
    let r: frankenengine_engine::privacy_learning_contract::RandomnessTranscript =
        serde_json::from_str(&json).unwrap();
    assert_eq!(transcript, r);
}

// ---------------------------------------------------------------------------
// SeedEscrowRecord
// ---------------------------------------------------------------------------

#[test]
fn seed_escrow_create_and_open_for_audit() {
    let mut auditors = BTreeSet::new();
    auditors.insert("trusted-auditor".to_string());
    let mut escrow = SeedEscrowRecord::create(
        "test-phase",
        SecurityEpoch::from_raw(1),
        b"secret",
        auditors,
    )
    .unwrap();
    let seed = escrow.open_for_audit("trusted-auditor", "check").unwrap();
    assert_eq!(seed.as_slice(), b"secret");
    assert_eq!(escrow.access_log.len(), 1);
    assert!(escrow.access_log[0].approved);
}

#[test]
fn seed_escrow_denies_unauthorized() {
    let mut auditors = BTreeSet::new();
    auditors.insert("allowed".to_string());
    let mut escrow =
        SeedEscrowRecord::create("phase", SecurityEpoch::from_raw(1), b"seed", auditors).unwrap();
    assert!(matches!(
        escrow.open_for_audit("intruder", "reason"),
        Err(ContractError::SeedEscrowAccessDenied { .. })
    ));
    assert_eq!(escrow.access_log.len(), 1);
    assert!(!escrow.access_log[0].approved);
}

#[test]
fn seed_escrow_serde_roundtrip() {
    let mut auditors = BTreeSet::new();
    auditors.insert("a".to_string());
    let escrow =
        SeedEscrowRecord::create("ph", SecurityEpoch::from_raw(2), b"s", auditors).unwrap();
    let json = serde_json::to_string(&escrow).unwrap();
    let r: SeedEscrowRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(escrow, r);
}

// ---------------------------------------------------------------------------
// Replay with escrowed seeds
// ---------------------------------------------------------------------------

#[test]
fn replay_with_escrowed_seeds_deterministic() {
    let mut transcript =
        frankenengine_engine::privacy_learning_contract::RandomnessTranscript::new();
    let sk = test_signing_key();
    let epoch = SecurityEpoch::from_raw(9);
    transcript
        .commit_seed(
            &sk,
            "noise",
            b"noise-seed",
            PrngAlgorithm::ChaCha20LikeCounter,
            epoch,
            EngineObjectId([0x51; 32]),
        )
        .unwrap();
    transcript
        .emit_snapshot_summary(&sk, "model", "policy")
        .unwrap();

    let mut auditors = BTreeSet::new();
    auditors.insert("bot".to_string());
    let e1 = SeedEscrowRecord::create("noise", epoch, b"noise-seed", auditors.clone()).unwrap();
    let e2 = SeedEscrowRecord::create("noise", epoch, b"noise-seed", auditors).unwrap();

    let mut r1 = vec![e1];
    let mut r2 = vec![e2];
    let o1 = transcript
        .replay_with_escrowed_seeds(&test_vk(), &mut r1, "bot", 5)
        .unwrap();
    let o2 = transcript
        .replay_with_escrowed_seeds(&test_vk(), &mut r2, "bot", 5)
        .unwrap();
    assert_eq!(o1, o2);
    assert_eq!(o1.len(), 1);
    assert_eq!(o1[0].outputs.len(), 5);
}

#[test]
fn replay_rejects_seed_hash_mismatch() {
    let mut transcript =
        frankenengine_engine::privacy_learning_contract::RandomnessTranscript::new();
    let sk = test_signing_key();
    let epoch = SecurityEpoch::from_raw(11);
    transcript
        .commit_seed(
            &sk,
            "sampling",
            b"correct-seed",
            PrngAlgorithm::ChaCha20LikeCounter,
            epoch,
            EngineObjectId([0x61; 32]),
        )
        .unwrap();
    transcript.emit_snapshot_summary(&sk, "m", "p").unwrap();

    let mut auditors = BTreeSet::new();
    auditors.insert("bot".to_string());
    let escrow = SeedEscrowRecord::create("sampling", epoch, b"wrong-seed", auditors).unwrap();
    let mut records = vec![escrow];
    assert!(matches!(
        transcript.replay_with_escrowed_seeds(&test_vk(), &mut records, "bot", 3),
        Err(ContractError::SeedHashMismatch { .. })
    ));
}

// ---------------------------------------------------------------------------
// ShadowEvaluationGate — pass
// ---------------------------------------------------------------------------

#[test]
fn shadow_gate_passes_improved_candidate() {
    let contract = create_contract();
    let mut gate = test_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            test_candidate(improved_metrics(), 90_000, 900),
            &test_signing_key(),
        )
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
    assert!(artifact.privacy_budget_status.within_budget);
    assert!(artifact.significant_improvement_count > 0);
    assert!(artifact.failure_reasons.is_empty());
}

#[test]
fn shadow_gate_events_on_pass() {
    let contract = create_contract();
    let mut gate = test_gate();
    gate.evaluate_candidate(
        &contract,
        test_candidate(improved_metrics(), 90_000, 900),
        &test_signing_key(),
    )
    .unwrap();
    let events = gate.events();
    assert!(events.len() >= 3);
    assert_eq!(events[0].event, "shadow_start");
    assert!(
        events
            .iter()
            .any(|e| e.event == "promotion_gate" && e.outcome == "pass")
    );
    assert!(events.iter().any(|e| e.event == "auto_enforcement"));
}

// ---------------------------------------------------------------------------
// ShadowEvaluationGate — reject on budget
// ---------------------------------------------------------------------------

#[test]
fn shadow_gate_rejects_budget_exhaustion() {
    let contract = create_contract();
    let mut gate = test_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            test_candidate(
                improved_metrics(),
                contract.dp_budget.epsilon_per_epoch_millionths + 1,
                contract.dp_budget.delta_per_epoch_millionths + 1,
            ),
            &test_signing_key(),
        )
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(!artifact.privacy_budget_status.within_budget);
}

// ---------------------------------------------------------------------------
// ShadowEvaluationGate — reject on regression
// ---------------------------------------------------------------------------

#[test]
fn shadow_gate_rejects_regression() {
    let contract = create_contract();
    let mut gate = test_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            test_candidate(regressed_metrics(), 90_000, 900),
            &test_signing_key(),
        )
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|r| r.contains("regression"))
    );
}

// ---------------------------------------------------------------------------
// ShadowEvaluationGate — human override
// ---------------------------------------------------------------------------

#[test]
fn shadow_gate_human_override() {
    let contract = create_contract();
    let mut gate = test_gate();
    let rejected = gate
        .evaluate_candidate(
            &contract,
            test_candidate(regressed_metrics(), 90_000, 900),
            &test_signing_key(),
        )
        .unwrap();
    assert_eq!(rejected.verdict, ShadowPromotionVerdict::Reject);

    let overridden = gate
        .apply_human_override(
            &rejected,
            HumanOverrideRequest {
                operator_id: "governor-7".to_string(),
                summary: "SLA preservation".to_string(),
                bypassed_risk_criteria: vec!["fpr <= baseline+5000".to_string()],
                acknowledged_bypass: true,
            },
            &test_signing_key(),
        )
        .unwrap();
    assert_eq!(overridden.verdict, ShadowPromotionVerdict::OverrideApproved);
    assert!(overridden.human_override.is_some());
}

// ---------------------------------------------------------------------------
// ShadowEvaluationGate — post-deployment rollback
// ---------------------------------------------------------------------------

#[test]
fn shadow_gate_post_deployment_rollback() {
    let contract = create_contract();
    let mut gate = test_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            test_candidate(improved_metrics(), 90_000, 900),
            &test_signing_key(),
        )
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);

    let receipt = gate
        .evaluate_post_deployment_metrics(&artifact, regressed_metrics(), &test_signing_key())
        .unwrap()
        .expect("rollback must trigger");
    assert_eq!(receipt.policy_id, artifact.policy_id);
    assert!(!receipt.triggered_regressions.is_empty());
    assert!(gate.active_artifact(&artifact.policy_id).is_none());
}

#[test]
fn shadow_gate_post_deployment_pass_no_regression() {
    let contract = create_contract();
    let mut gate = test_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            test_candidate(improved_metrics(), 90_000, 900),
            &test_signing_key(),
        )
        .unwrap();
    let receipt = gate
        .evaluate_post_deployment_metrics(&artifact, improved_metrics(), &test_signing_key())
        .unwrap();
    assert!(receipt.is_none());
    assert!(gate.active_artifact("policy-int-1").is_some());
}

// ---------------------------------------------------------------------------
// ShadowEvaluationGate — scorecard
// ---------------------------------------------------------------------------

#[test]
fn shadow_gate_scorecard_populated() {
    let contract = create_contract();
    let mut gate = test_gate();
    gate.evaluate_candidate(
        &contract,
        test_candidate(improved_metrics(), 90_000, 900),
        &test_signing_key(),
    )
    .unwrap();
    let sc = gate.scorecard_entries();
    assert_eq!(sc.len(), 1);
    assert_eq!(sc[0].policy_id, "policy-int-1");
    assert_eq!(sc[0].verdict, ShadowPromotionVerdict::Pass);
}

#[test]
fn shadow_gate_drain_events_clears() {
    let contract = create_contract();
    let mut gate = test_gate();
    gate.evaluate_candidate(
        &contract,
        test_candidate(improved_metrics(), 90_000, 900),
        &test_signing_key(),
    )
    .unwrap();
    let drained = gate.drain_events();
    assert!(!drained.is_empty());
    assert!(gate.events().is_empty());
}

// ---------------------------------------------------------------------------
// Shadow gate — specific failure paths
// ---------------------------------------------------------------------------

#[test]
fn shadow_gate_rejects_low_success_rate() {
    let contract = create_contract();
    let mut gate = test_gate();
    let mut c = test_candidate(improved_metrics(), 90_000, 900);
    c.shadow_success_rate_millionths = 990_000;
    let artifact = gate
        .evaluate_candidate(&contract, c, &test_signing_key())
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|r| r.contains("shadow success rate"))
    );
}

#[test]
fn shadow_gate_rejects_high_false_deny_rate() {
    let contract = create_contract();
    let mut gate = test_gate();
    let mut c = test_candidate(improved_metrics(), 90_000, 900);
    c.false_deny_rate_millionths = 6_000;
    let artifact = gate
        .evaluate_candidate(&contract, c, &test_signing_key())
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(artifact.burn_in_early_terminated);
}

#[test]
fn shadow_gate_rejects_short_burn_in() {
    let contract = create_contract();
    let mut gate = test_gate();
    let mut c = test_candidate(improved_metrics(), 90_000, 900);
    c.shadow_started_at_ns = 1_000_000_000;
    c.evaluation_completed_at_ns = 1_000_000_050; // 50ns < 100ns
    let artifact = gate
        .evaluate_candidate(&contract, c, &test_signing_key())
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|r| r.contains("burn-in duration"))
    );
}

#[test]
fn shadow_gate_rejects_unverified_rollback() {
    let contract = create_contract();
    let mut gate = test_gate();
    let mut c = test_candidate(improved_metrics(), 90_000, 900);
    c.rollback_readiness.rollback_command_tested = false;
    c.rollback_readiness.transition_receipt_signed = false;
    let artifact = gate
        .evaluate_candidate(&contract, c, &test_signing_key())
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|r| r.contains("rollback readiness"))
    );
}

// ---------------------------------------------------------------------------
// Shadow gate — extension class override
// ---------------------------------------------------------------------------

#[test]
fn shadow_gate_uses_extension_class_profile() {
    let mut profiles = BTreeMap::new();
    profiles.insert(
        ShadowExtensionClass::Critical,
        ShadowBurnInThresholdProfile {
            min_shadow_success_rate_millionths: 999_000,
            max_false_deny_rate_millionths: 500,
            min_burn_in_duration_ns: 50,
            require_verified_rollback_artifacts: true,
        },
    );
    let config = ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 5_000,
        min_required_improvement_millionths: 2_500,
        default_burn_in_profile: ShadowBurnInThresholdProfile {
            min_shadow_success_rate_millionths: 995_000,
            max_false_deny_rate_millionths: 5_000,
            min_burn_in_duration_ns: 100,
            require_verified_rollback_artifacts: true,
        },
        burn_in_profiles_by_extension_class: profiles,
    };
    let mut gate = ShadowEvaluationGate::new(config).unwrap();
    let contract = create_contract();
    let mut c = test_candidate(improved_metrics(), 90_000, 900);
    c.extension_class = ShadowExtensionClass::Critical;
    c.shadow_success_rate_millionths = 998_000; // below 999_000 critical threshold
    let artifact = gate
        .evaluate_candidate(&contract, c, &test_signing_key())
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert_eq!(
        artifact.burn_in_profile.min_shadow_success_rate_millionths,
        999_000
    );
}

// ---------------------------------------------------------------------------
// Default trait values
// ---------------------------------------------------------------------------

#[test]
fn shadow_burn_in_profile_default() {
    let d = ShadowBurnInThresholdProfile::default();
    assert_eq!(d.min_shadow_success_rate_millionths, 995_000);
    assert_eq!(d.max_false_deny_rate_millionths, 5_000);
    assert!(d.require_verified_rollback_artifacts);
}

#[test]
fn shadow_gate_config_default() {
    let d = ShadowEvaluationGateConfig::default();
    assert_eq!(d.regression_tolerance_millionths, 5_000);
    assert_eq!(d.min_required_improvement_millionths, 2_500);
    assert_eq!(d.burn_in_profiles_by_extension_class.len(), 3);
}

#[test]
fn shadow_extension_class_default_is_standard() {
    assert_eq!(
        ShadowExtensionClass::default(),
        ShadowExtensionClass::Standard
    );
}

#[test]
fn shadow_rollback_readiness_default() {
    let d = ShadowRollbackReadinessArtifacts::default();
    assert!(!d.rollback_command_tested);
    assert!(d.previous_policy_snapshot_id.is_empty());
    assert!(!d.transition_receipt_signed);
}

// ---------------------------------------------------------------------------
// Struct serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn safety_metric_snapshot_serde_roundtrip() {
    let s = baseline_metrics();
    let json = serde_json::to_string(&s).unwrap();
    let r: SafetyMetricSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(s, r);
}

#[test]
fn shadow_replay_reference_serde_roundtrip() {
    let rr = test_replay_ref();
    let json = serde_json::to_string(&rr).unwrap();
    let r: ShadowReplayReference = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, r);
}

#[test]
fn shadow_gate_event_serde_roundtrip() {
    let e = ShadowGateEvent {
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        component: "shadow_evaluation_gate".into(),
        event: "shadow_start".into(),
        outcome: "started".into(),
        error_code: Some("FE-PLC-SHADOW-0001".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let r: ShadowGateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, r);
}

#[test]
fn shadow_metric_assessment_serde_roundtrip() {
    let a = ShadowMetricAssessment {
        baseline_value_millionths: 100_000,
        candidate_value_millionths: 95_000,
        improvement_millionths: 5_000,
        regressed: false,
        significant_improvement: true,
    };
    let json = serde_json::to_string(&a).unwrap();
    let r: ShadowMetricAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(a, r);
}

#[test]
fn shadow_privacy_budget_status_serde_roundtrip() {
    let s = ShadowPrivacyBudgetStatus {
        epsilon_spent_millionths: 50_000,
        epsilon_limit_millionths: 100_000,
        delta_spent_millionths: 500,
        delta_limit_millionths: 1_000,
        within_budget: true,
    };
    let json = serde_json::to_string(&s).unwrap();
    let r: ShadowPrivacyBudgetStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(s, r);
}

#[test]
fn shadow_burn_in_scorecard_entry_serde_roundtrip() {
    let e = ShadowBurnInScorecardEntry {
        policy_id: "p1".into(),
        candidate_version: "v1".into(),
        extension_class: ShadowExtensionClass::HighRisk,
        verdict: ShadowPromotionVerdict::Pass,
        shadow_success_rate_millionths: 998_000,
        false_deny_rate_millionths: 2_000,
        burn_in_duration_ns: 7_200_000_000_000,
        rollback_ready: true,
        burn_in_early_terminated: false,
    };
    let json = serde_json::to_string(&e).unwrap();
    let r: ShadowBurnInScorecardEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, r);
}

#[test]
fn replay_output_serde_roundtrip() {
    let o = ReplayOutput {
        phase_id: "p".into(),
        sequence_counter: 3,
        outputs: vec![100, 200, 300],
    };
    let json = serde_json::to_string(&o).unwrap();
    let r: ReplayOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(o, r);
}

#[test]
fn seed_escrow_access_event_serde_roundtrip() {
    let e = SeedEscrowAccessEvent {
        principal: "auditor".into(),
        reason: "check".into(),
        approved: true,
    };
    let json = serde_json::to_string(&e).unwrap();
    let r: SeedEscrowAccessEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, r);
}

#[test]
fn human_override_request_serde_roundtrip() {
    let h = HumanOverrideRequest {
        operator_id: "op".into(),
        summary: "reason".into(),
        bypassed_risk_criteria: vec!["cr".into()],
        acknowledged_bypass: true,
    };
    let json = serde_json::to_string(&h).unwrap();
    let r: HumanOverrideRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(h, r);
}

#[test]
fn shadow_evaluation_candidate_serde_roundtrip() {
    let c = test_candidate(improved_metrics(), 90_000, 900);
    let json = serde_json::to_string(&c).unwrap();
    let r: ShadowEvaluationCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, r);
}

#[test]
fn shadow_rollback_readiness_serde_roundtrip() {
    let rr = test_rollback_readiness();
    let json = serde_json::to_string(&rr).unwrap();
    let r: ShadowRollbackReadinessArtifacts = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, r);
}

#[test]
fn shadow_burn_in_profile_serde_roundtrip() {
    let p = ShadowBurnInThresholdProfile::default();
    let json = serde_json::to_string(&p).unwrap();
    let r: ShadowBurnInThresholdProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, r);
}

#[test]
fn contract_event_serde_roundtrip() {
    let e = ContractEvent {
        event_type: ContractEventType::Registered {
            contract_id: EngineObjectId([0xCC; 32]),
            zone: "z".into(),
            epoch: SecurityEpoch::from_raw(3),
        },
        trace_id: "trace".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let r: ContractEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, r);
}

// ---------------------------------------------------------------------------
// Artifact serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn shadow_promotion_decision_artifact_serde_roundtrip() {
    let contract = create_contract();
    let mut gate = test_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            test_candidate(improved_metrics(), 90_000, 900),
            &test_signing_key(),
        )
        .unwrap();
    let json = serde_json::to_string(&artifact).unwrap();
    let r: frankenengine_engine::privacy_learning_contract::ShadowPromotionDecisionArtifact =
        serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, r);
}

#[test]
fn shadow_rollback_incident_receipt_serde_roundtrip() {
    let contract = create_contract();
    let mut gate = test_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            test_candidate(improved_metrics(), 90_000, 900),
            &test_signing_key(),
        )
        .unwrap();
    let receipt = gate
        .evaluate_post_deployment_metrics(&artifact, regressed_metrics(), &test_signing_key())
        .unwrap()
        .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let r: ShadowRollbackIncidentReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, r);
}

// ---------------------------------------------------------------------------
// JSON field name stability
// ---------------------------------------------------------------------------

#[test]
fn contract_json_field_names_stable() {
    let c = create_contract();
    let json = serde_json::to_string(&c).unwrap();
    for field in [
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
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}

#[test]
fn shadow_candidate_json_field_names_stable() {
    let c = test_candidate(improved_metrics(), 90_000, 900);
    let json = serde_json::to_string(&c).unwrap();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_class",
        "candidate_version",
        "baseline_snapshot_id",
        "rollback_token",
        "epoch_id",
        "shadow_success_rate_millionths",
        "false_deny_rate_millionths",
        "epsilon_spent_millionths",
        "delta_spent_millionths",
    ] {
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}

// ---------------------------------------------------------------------------
// End-to-end: contract lifecycle through registry + shadow gate
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_contract_lifecycle_with_shadow_gate() {
    // 1. Create and register contract
    let sk = test_signing_key();
    let vk = test_vk();
    let contract = create_contract();
    let mut registry = ContractRegistry::new();
    let cid = registry
        .register(contract.clone(), &vk, "e2e-trace")
        .unwrap();
    assert_eq!(registry.total_count(), 1);

    // 2. Verify signature on retrieved contract
    let retrieved = registry.get(&cid).unwrap();
    retrieved.verify_governance_signature(&vk).unwrap();

    // 3. Shadow evaluation — pass
    let mut gate = test_gate();
    let artifact = gate
        .evaluate_candidate(
            retrieved,
            test_candidate(improved_metrics(), 90_000, 900),
            &sk,
        )
        .unwrap();
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);

    // 4. Active artifact confirmed
    assert!(gate.active_artifact("policy-int-1").is_some());

    // 5. Post-deployment check — no regression
    let receipt = gate
        .evaluate_post_deployment_metrics(&artifact, improved_metrics(), &sk)
        .unwrap();
    assert!(receipt.is_none());

    // 6. Epoch upgrade
    let mut input2 = test_contract_input();
    input2.epoch = SecurityEpoch::from_raw(2);
    let c2 = PrivacyLearningContract::create_signed(&sk, input2).unwrap();
    registry.register(c2, &vk, "e2e-upgrade").unwrap();
    assert_eq!(registry.total_count(), 2);
    let active = registry.active_for_zone("integration-zone").unwrap();
    assert_eq!(active.epoch, SecurityEpoch::from_raw(2));
}

// ---------------------------------------------------------------------------
// End-to-end: randomness transcript with escrow + replay
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_randomness_transcript_escrow_replay() {
    let sk = test_signing_key();
    let vk = test_vk();
    let epoch = SecurityEpoch::from_raw(20);

    // 1. Build transcript with 3 commitments
    let mut transcript =
        frankenengine_engine::privacy_learning_contract::RandomnessTranscript::new();
    for i in 0..3 {
        transcript
            .commit_seed(
                &sk,
                &format!("phase-{i}"),
                format!("seed-{i}").as_bytes(),
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                EngineObjectId([0x70 + i as u8; 32]),
            )
            .unwrap();
    }
    assert_eq!(transcript.commitments.len(), 3);

    // 2. Emit snapshot summary
    transcript
        .emit_snapshot_summary(&sk, "model-e2e", "policy-e2e")
        .unwrap();

    // 3. Verify chain and snapshots
    transcript.verify_chain(&vk).unwrap();
    transcript.verify_snapshot_summaries(&vk).unwrap();

    // 4. Create escrow records
    let mut auditors = BTreeSet::new();
    auditors.insert("replay-bot".to_string());
    let mut escrows: Vec<SeedEscrowRecord> = (0..3)
        .map(|i| {
            SeedEscrowRecord::create(
                &format!("phase-{i}"),
                epoch,
                format!("seed-{i}").as_bytes(),
                auditors.clone(),
            )
            .unwrap()
        })
        .collect();

    // 5. Replay and verify determinism
    let outputs = transcript
        .replay_with_escrowed_seeds(&vk, &mut escrows, "replay-bot", 4)
        .unwrap();
    assert_eq!(outputs.len(), 3);
    for output in &outputs {
        assert_eq!(output.outputs.len(), 4);
    }
}

// ---------------------------------------------------------------------------
// Safety
// ---------------------------------------------------------------------------

#[test]
fn safety_metric_all_has_five_variants() {
    assert_eq!(SafetyMetric::ALL.len(), 5);
}

#[test]
fn safety_metric_snapshot_validate_rejects_missing() {
    let mut snap = baseline_metrics();
    snap.values_millionths
        .remove(&SafetyMetric::CalibrationError);
    assert!(matches!(
        snap.validate(),
        Err(ContractError::InvalidShadowEvaluation { .. })
    ));
}

#[test]
fn safety_metric_snapshot_metric_value_missing_returns_zero() {
    let snap = SafetyMetricSnapshot {
        values_millionths: BTreeMap::new(),
    };
    assert_eq!(snap.metric_value(SafetyMetric::FalsePositiveRate), 0);
}
