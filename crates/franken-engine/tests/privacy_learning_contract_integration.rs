#![forbid(unsafe_code)]
//! Integration tests for the `privacy_learning_contract` module.
//!
//! Exercises the privacy learning contract API from outside the crate
//! boundary: feature schema validation, update policy, clipping strategy,
//! DP budgets, aggregation, retention, contract lifecycle, randomness
//! transcripts, shadow evaluation gate, and promotion decisions.

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
    FeatureSchema, PrivacyLearningContract, PrngAlgorithm, RandomnessTranscript, ReplayOutput,
    SafetyMetric, SafetyMetricSnapshot, SecretSharingScheme, SecureAggregationRequirements,
    SeedEscrowAccessEvent, SeedEscrowRecord, ShadowExtensionClass, ShadowPromotionVerdict,
    UpdatePolicy, contract_schema, contract_schema_id,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ===========================================================================
// Helpers
// ===========================================================================

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
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

fn create_contract(sk: &SigningKey) -> PrivacyLearningContract {
    let schema = valid_schema();
    let participant = EngineObjectId::from_hex(
        "aa00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    PrivacyLearningContract::create_signed(
        sk,
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(1),
            zone: "us-east-1",
            feature_schema: schema.clone(),
            update_policy: valid_update_policy(),
            clipping_strategy: valid_clipping(&schema),
            dp_budget: valid_dp_budget(),
            aggregation: valid_aggregation(),
            retention: valid_retention(),
            authorized_participants: [participant].into_iter().collect(),
        },
    )
    .unwrap()
}

// ===========================================================================
// 1. Schema constants
// ===========================================================================

#[test]
fn contract_schema_nonempty() {
    let s = contract_schema();
    assert!(!s.as_bytes().is_empty());
}

#[test]
fn contract_schema_id_nonempty() {
    let id = contract_schema_id();
    let _ = format!("{id:?}"); // Just verify it exists and can be formatted
}

// ===========================================================================
// 2. FeatureFieldType serde
// ===========================================================================

#[test]
fn feature_field_type_serde_round_trip() {
    for ft in [
        FeatureFieldType::FixedPoint,
        FeatureFieldType::Counter,
        FeatureFieldType::Boolean,
        FeatureFieldType::Categorical,
    ] {
        let json = serde_json::to_string(&ft).unwrap();
        let back: FeatureFieldType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ft);
    }
}

// ===========================================================================
// 3. FeatureSchema validation
// ===========================================================================

#[test]
fn valid_schema_passes() {
    let schema = valid_schema();
    assert!(schema.validate().is_ok());
}

#[test]
fn empty_schema_fails() {
    let schema = FeatureSchema {
        version: 1,
        fields: BTreeMap::new(),
        prior_version: None,
    };
    assert!(schema.validate().is_err());
}

#[test]
fn schema_field_name_mismatch_fails() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "key_a".to_string(),
        FeatureField {
            name: "key_b".to_string(), // mismatch
            field_type: FeatureFieldType::FixedPoint,
            description: "mismatch".to_string(),
            existed_in_prior_version: false,
        },
    );
    let schema = FeatureSchema {
        version: 1,
        fields,
        prior_version: None,
    };
    assert!(schema.validate().is_err());
}

#[test]
fn schema_backward_compatibility() {
    let prior = valid_schema();
    let mut next_fields = prior.fields.clone();
    next_fields.insert(
        "accuracy".to_string(),
        FeatureField {
            name: "accuracy".to_string(),
            field_type: FeatureFieldType::FixedPoint,
            description: "accuracy metric".to_string(),
            existed_in_prior_version: false,
        },
    );
    let next = FeatureSchema {
        version: 2,
        fields: next_fields,
        prior_version: Some(1),
    };
    assert!(next.is_backward_compatible_with(&prior));
}

// ===========================================================================
// 4. UpdatePolicy validation
// ===========================================================================

#[test]
fn valid_update_policy_passes() {
    assert!(valid_update_policy().validate().is_ok());
}

// ===========================================================================
// 5. ClippingStrategy validation
// ===========================================================================

#[test]
fn valid_clipping_passes() {
    let schema = valid_schema();
    assert!(valid_clipping(&schema).validate(&schema).is_ok());
}

#[test]
fn clipping_method_serde_round_trip() {
    for m in [
        ClippingMethod::L2Norm,
        ClippingMethod::PerCoordinate,
        ClippingMethod::Adaptive,
    ] {
        let json = serde_json::to_string(&m).unwrap();
        let back: ClippingMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}

// ===========================================================================
// 6. DpBudgetSemantics
// ===========================================================================

#[test]
fn valid_dp_budget_passes() {
    assert!(valid_dp_budget().validate().is_ok());
}

#[test]
fn dp_budget_max_epochs() {
    let b = valid_dp_budget();
    let max = b.max_epochs();
    assert!(max > 0);
}

#[test]
fn composition_method_serde_round_trip() {
    for m in [
        CompositionMethod::Basic,
        CompositionMethod::Advanced,
        CompositionMethod::Renyi,
        CompositionMethod::ZeroCdp,
    ] {
        let json = serde_json::to_string(&m).unwrap();
        let back: CompositionMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}

// ===========================================================================
// 7. SecureAggregationRequirements
// ===========================================================================

#[test]
fn valid_aggregation_passes() {
    assert!(valid_aggregation().validate().is_ok());
}

#[test]
fn coordinator_trust_model_serde() {
    for m in [
        CoordinatorTrustModel::HonestButCurious,
        CoordinatorTrustModel::Malicious,
    ] {
        let json = serde_json::to_string(&m).unwrap();
        let back: CoordinatorTrustModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}

#[test]
fn secret_sharing_scheme_serde() {
    for s in [SecretSharingScheme::Additive, SecretSharingScheme::Shamir] {
        let json = serde_json::to_string(&s).unwrap();
        let back: SecretSharingScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 8. DataRetentionPolicy
// ===========================================================================

#[test]
fn valid_retention_passes() {
    assert!(valid_retention().validate().is_ok());
}

// ===========================================================================
// 9. Contract creation and signature
// ===========================================================================

#[test]
fn create_signed_contract() {
    let sk = test_signing_key();
    let contract = create_contract(&sk);
    assert_eq!(contract.zone, "us-east-1");
    assert_eq!(contract.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn verify_governance_signature() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract = create_contract(&sk);
    assert!(contract.verify_governance_signature(&vk).is_ok());
}

#[test]
fn verify_signature_wrong_key_fails() {
    let sk1 = test_signing_key();
    let sk2 = SigningKey::from_bytes([43u8; 32]);
    let vk2 = sk2.verification_key();
    let contract = create_contract(&sk1);
    assert!(contract.verify_governance_signature(&vk2).is_err());
}

#[test]
fn contract_participant_authorization() {
    let sk = test_signing_key();
    let contract = create_contract(&sk);
    let authorized = EngineObjectId::from_hex(
        "aa00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let unauthorized = EngineObjectId::from_hex(
        "ff00000000000000000000000000000000000000000000000000000000000099",
    )
    .unwrap();
    assert!(contract.is_authorized(&authorized));
    assert!(!contract.is_authorized(&unauthorized));
}

// ===========================================================================
// 10. Contract registry
// ===========================================================================

#[test]
fn registry_register_and_lookup() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract = create_contract(&sk);
    let cid = contract.contract_id.clone();
    let mut reg = ContractRegistry::new();
    reg.register(contract, &vk, "trace-1").unwrap();
    assert_eq!(reg.total_count(), 1);
    assert!(reg.get(&cid).is_some());
}

#[test]
fn registry_active_for_zone() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract = create_contract(&sk);
    let mut reg = ContractRegistry::new();
    reg.register(contract, &vk, "trace-2").unwrap();
    let active = reg.active_for_zone("us-east-1");
    assert!(active.is_some());
}

#[test]
fn registry_revoke() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract = create_contract(&sk);
    let cid = contract.contract_id.clone();
    let mut reg = ContractRegistry::new();
    reg.register(contract, &vk, "trace-3").unwrap();
    reg.revoke(&cid, "trace-4").unwrap();
    assert!(reg.active_for_zone("us-east-1").is_none());
}

#[test]
fn registry_zone_count() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract = create_contract(&sk);
    let mut reg = ContractRegistry::new();
    reg.register(contract, &vk, "trace-5").unwrap();
    assert_eq!(reg.zone_count(), 1);
}

#[test]
fn registry_drain_events() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract = create_contract(&sk);
    let mut reg = ContractRegistry::new();
    reg.register(contract, &vk, "trace-6").unwrap();
    let events = reg.drain_events();
    assert!(!events.is_empty());
    // After drain, no more events
    let events2 = reg.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn registry_duplicate_contract_error() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract = create_contract(&sk);
    let contract2 = contract.clone();
    let mut reg = ContractRegistry::new();
    reg.register(contract, &vk, "trace-7").unwrap();
    let result = reg.register(contract2, &vk, "trace-8");
    assert!(result.is_err());
}

// ===========================================================================
// 11. DeterministicPrng
// ===========================================================================

#[test]
fn prng_deterministic() {
    let mut p1 =
        DeterministicPrng::new("phase_1", PrngAlgorithm::ChaCha20LikeCounter, b"seed123").unwrap();
    let mut p2 =
        DeterministicPrng::new("phase_1", PrngAlgorithm::ChaCha20LikeCounter, b"seed123").unwrap();
    let v1: Vec<u64> = (0..10).map(|_| p1.next_u64()).collect();
    let v2: Vec<u64> = (0..10).map(|_| p2.next_u64()).collect();
    assert_eq!(v1, v2);
}

#[test]
fn prng_different_seeds_different_output() {
    let mut p1 =
        DeterministicPrng::new("phase_1", PrngAlgorithm::ChaCha20LikeCounter, b"seedA").unwrap();
    let mut p2 =
        DeterministicPrng::new("phase_1", PrngAlgorithm::ChaCha20LikeCounter, b"seedB").unwrap();
    let v1 = p1.next_u64();
    let v2 = p2.next_u64();
    assert_ne!(v1, v2);
}

#[test]
fn prng_draw_counter_increments() {
    let mut prng =
        DeterministicPrng::new("phase_1", PrngAlgorithm::ChaCha20LikeCounter, b"seed").unwrap();
    assert_eq!(prng.draw_counter(), 0);
    prng.next_u64();
    assert_eq!(prng.draw_counter(), 1);
    prng.next_u64();
    assert_eq!(prng.draw_counter(), 2);
}

// ===========================================================================
// 12. Randomness transcript
// ===========================================================================

#[test]
fn randomness_transcript_commit_and_verify() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let evidence_id = EngineObjectId::from_hex(
        "ee00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let mut transcript = RandomnessTranscript::new();
    transcript
        .commit_seed(
            &sk,
            "phase_1",
            b"random_seed_bytes",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            evidence_id,
        )
        .unwrap();
    assert!(transcript.verify_chain(&vk).is_ok());
}

#[test]
fn randomness_transcript_multiple_commits() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let eid1 = EngineObjectId::from_hex(
        "ee00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let eid2 = EngineObjectId::from_hex(
        "ee00000000000000000000000000000000000000000000000000000000000002",
    )
    .unwrap();
    let mut transcript = RandomnessTranscript::new();
    transcript
        .commit_seed(
            &sk,
            "phase_1",
            b"seed_1",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            eid1,
        )
        .unwrap();
    transcript
        .commit_seed(
            &sk,
            "phase_2",
            b"seed_2",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            eid2,
        )
        .unwrap();
    assert!(transcript.verify_chain(&vk).is_ok());
}

// ===========================================================================
// 13. Seed escrow
// ===========================================================================

#[test]
fn seed_escrow_create_and_open() {
    let auditors: BTreeSet<String> = ["alice".to_string()].into_iter().collect();
    let mut escrow = SeedEscrowRecord::create(
        "phase_1",
        SecurityEpoch::from_raw(1),
        b"secret_seed",
        auditors,
    )
    .unwrap();
    let opened = escrow.open_for_audit("alice", "compliance review").unwrap();
    assert!(!opened.is_empty());
}

#[test]
fn seed_escrow_unauthorized_access() {
    let auditors: BTreeSet<String> = ["alice".to_string()].into_iter().collect();
    let mut escrow = SeedEscrowRecord::create(
        "phase_1",
        SecurityEpoch::from_raw(1),
        b"secret_seed",
        auditors,
    )
    .unwrap();
    let result = escrow.open_for_audit("bob", "unauthorized");
    assert!(result.is_err());
}

// ===========================================================================
// 14. SafetyMetric
// ===========================================================================

#[test]
fn safety_metric_all_variants() {
    let all = SafetyMetric::ALL;
    assert_eq!(all.len(), 5);
    let unique: BTreeSet<_> = all.iter().collect();
    assert_eq!(unique.len(), all.len());
}

#[test]
fn safety_metric_serde_round_trip() {
    for m in SafetyMetric::ALL {
        let json = serde_json::to_string(m).unwrap();
        let back: SafetyMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, m);
    }
}

// ===========================================================================
// 15. ShadowExtensionClass serde
// ===========================================================================

#[test]
fn shadow_extension_class_serde() {
    for c in [
        ShadowExtensionClass::LowRisk,
        ShadowExtensionClass::Standard,
        ShadowExtensionClass::HighRisk,
        ShadowExtensionClass::Critical,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: ShadowExtensionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }
}

// ===========================================================================
// 16. ShadowPromotionVerdict serde
// ===========================================================================

#[test]
fn shadow_promotion_verdict_serde() {
    for v in [
        ShadowPromotionVerdict::Pass,
        ShadowPromotionVerdict::Reject,
        ShadowPromotionVerdict::OverrideApproved,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ShadowPromotionVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ===========================================================================
// 17. SafetyMetricSnapshot
// ===========================================================================

#[test]
fn safety_metric_snapshot_validate() {
    let mut values = BTreeMap::new();
    for m in SafetyMetric::ALL {
        values.insert(*m, 500_000i64);
    }
    let snap = SafetyMetricSnapshot {
        values_millionths: values,
    };
    assert!(snap.validate().is_ok());
}

#[test]
fn safety_metric_snapshot_value_lookup() {
    let mut values = BTreeMap::new();
    values.insert(SafetyMetric::CalibrationError, 123_456i64);
    let snap = SafetyMetricSnapshot {
        values_millionths: values,
    };
    assert_eq!(snap.metric_value(SafetyMetric::CalibrationError), 123_456);
}

// ===========================================================================
// 18. ContractError display
// ===========================================================================

#[test]
fn contract_error_display() {
    let errors = [
        ContractError::EmptyFeatureSchema,
        ContractError::NoAuthorizedParticipants,
        ContractError::InvalidVersion {
            detail: "bad version".to_string(),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

// ===========================================================================
// 19. PrngAlgorithm serde
// ===========================================================================

#[test]
fn prng_algorithm_serde() {
    let a = PrngAlgorithm::ChaCha20LikeCounter;
    let json = serde_json::to_string(&a).unwrap();
    let back: PrngAlgorithm = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}

// ===========================================================================
// 20. Contract serde round-trip
// ===========================================================================

#[test]
fn contract_serde_round_trip() {
    let sk = test_signing_key();
    let contract = create_contract(&sk);
    let json = serde_json::to_string(&contract).unwrap();
    let back: PrivacyLearningContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back.contract_id, contract.contract_id);
    assert_eq!(back.zone, contract.zone);
    assert_eq!(back.epoch, contract.epoch);
}

// ===========================================================================
// 21. Feature schema serde round-trip
// ===========================================================================

#[test]
fn feature_schema_serde_round_trip() {
    let schema = valid_schema();
    let json = serde_json::to_string(&schema).unwrap();
    let back: FeatureSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(back, schema);
}

// ===========================================================================
// 22. Multiple contracts in registry
// ===========================================================================

#[test]
fn multiple_contracts_different_zones() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let schema = valid_schema();
    let participant = EngineObjectId::from_hex(
        "aa00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();

    let c1 = PrivacyLearningContract::create_signed(
        &sk,
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(1),
            zone: "us-east-1",
            feature_schema: schema.clone(),
            update_policy: valid_update_policy(),
            clipping_strategy: valid_clipping(&schema),
            dp_budget: valid_dp_budget(),
            aggregation: valid_aggregation(),
            retention: valid_retention(),
            authorized_participants: [participant.clone()].into_iter().collect(),
        },
    )
    .unwrap();

    let c2 = PrivacyLearningContract::create_signed(
        &sk,
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(1),
            zone: "eu-west-1",
            feature_schema: schema.clone(),
            update_policy: valid_update_policy(),
            clipping_strategy: valid_clipping(&schema),
            dp_budget: valid_dp_budget(),
            aggregation: valid_aggregation(),
            retention: valid_retention(),
            authorized_participants: [participant].into_iter().collect(),
        },
    )
    .unwrap();

    let mut reg = ContractRegistry::new();
    reg.register(c1, &vk, "t1").unwrap();
    reg.register(c2, &vk, "t2").unwrap();
    assert_eq!(reg.total_count(), 2);
    assert_eq!(reg.zone_count(), 2);
    assert!(reg.active_for_zone("us-east-1").is_some());
    assert!(reg.active_for_zone("eu-west-1").is_some());
}

// ===========================================================================
// 23. Empty registry
// ===========================================================================

#[test]
fn empty_registry() {
    let reg = ContractRegistry::new();
    assert_eq!(reg.total_count(), 0);
    assert_eq!(reg.zone_count(), 0);
    assert!(reg.active_for_zone("us-east-1").is_none());
}

// ===========================================================================
// 24. FeatureFieldType display
// ===========================================================================

#[test]
fn feature_field_type_display_all() {
    let expected = ["fixed_point", "counter", "boolean", "categorical"];
    for (ft, exp) in [
        FeatureFieldType::FixedPoint,
        FeatureFieldType::Counter,
        FeatureFieldType::Boolean,
        FeatureFieldType::Categorical,
    ]
    .iter()
    .zip(expected.iter())
    {
        assert_eq!(ft.to_string(), *exp);
    }
}

// ===========================================================================
// 25. Schema version zero fails
// ===========================================================================

#[test]
fn schema_version_zero_fails() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "f".to_string(),
        FeatureField {
            name: "f".to_string(),
            field_type: FeatureFieldType::Boolean,
            description: "flag".to_string(),
            existed_in_prior_version: false,
        },
    );
    let schema = FeatureSchema {
        version: 0,
        fields,
        prior_version: None,
    };
    let err = schema.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidVersion { .. }));
}

// ===========================================================================
// 26. Schema backward compatibility violation: no prior fields
// ===========================================================================

#[test]
fn schema_backward_compat_no_prior_fields_fails() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "new_field".to_string(),
        FeatureField {
            name: "new_field".to_string(),
            field_type: FeatureFieldType::Counter,
            description: "new".to_string(),
            existed_in_prior_version: false, // all new, none from prior
        },
    );
    let schema = FeatureSchema {
        version: 2,
        fields,
        prior_version: Some(1),
    };
    let err = schema.validate().unwrap_err();
    assert!(matches!(
        err,
        ContractError::BackwardCompatibilityViolation { .. }
    ));
}

// ===========================================================================
// 27. Schema version not greater than prior
// ===========================================================================

#[test]
fn schema_version_not_greater_than_prior_fails() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "old_field".to_string(),
        FeatureField {
            name: "old_field".to_string(),
            field_type: FeatureFieldType::FixedPoint,
            description: "old".to_string(),
            existed_in_prior_version: true,
        },
    );
    let schema = FeatureSchema {
        version: 1, // not > prior_version 1
        fields,
        prior_version: Some(1),
    };
    let err = schema.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidVersion { .. }));
}

// ===========================================================================
// 28. Schema backward compatibility type change fails
// ===========================================================================

#[test]
fn schema_type_change_not_backward_compatible() {
    let prior = valid_schema();
    let mut next_fields = prior.fields.clone();
    // Change "loss" from FixedPoint to Counter
    next_fields.insert(
        "loss".to_string(),
        FeatureField {
            name: "loss".to_string(),
            field_type: FeatureFieldType::Counter, // was FixedPoint
            description: "loss value".to_string(),
            existed_in_prior_version: true,
        },
    );
    let next = FeatureSchema {
        version: 2,
        fields: next_fields,
        prior_version: Some(1),
    };
    assert!(!next.is_backward_compatible_with(&prior));
}

// ===========================================================================
// 29. Schema backward compatibility field removal fails
// ===========================================================================

#[test]
fn schema_field_removal_not_backward_compatible() {
    let prior = valid_schema();
    let mut next_fields = BTreeMap::new();
    // Only keep "loss", remove "count"
    next_fields.insert(
        "loss".to_string(),
        FeatureField {
            name: "loss".to_string(),
            field_type: FeatureFieldType::FixedPoint,
            description: "loss".to_string(),
            existed_in_prior_version: true,
        },
    );
    let next = FeatureSchema {
        version: 2,
        fields: next_fields,
        prior_version: Some(1),
    };
    assert!(!next.is_backward_compatible_with(&prior));
}

// ===========================================================================
// 30. UpdatePolicy validation edge cases
// ===========================================================================

#[test]
fn update_policy_zero_samples_fails() {
    let mut p = valid_update_policy();
    p.min_local_samples = 0;
    assert!(p.validate().is_err());
}

#[test]
fn update_policy_zero_interval_fails() {
    let mut p = valid_update_policy();
    p.min_submission_interval = 0;
    assert!(p.validate().is_err());
}

#[test]
fn update_policy_zero_data_age_fails() {
    let mut p = valid_update_policy();
    p.max_data_age = 0;
    assert!(p.validate().is_err());
}

#[test]
fn update_policy_skip_allowed_zero_max_skips_fails() {
    let mut p = valid_update_policy();
    p.allow_skip = true;
    p.max_consecutive_skips = 0;
    assert!(p.validate().is_err());
}

#[test]
fn update_policy_skip_not_allowed_zero_max_skips_ok() {
    let mut p = valid_update_policy();
    p.allow_skip = false;
    p.max_consecutive_skips = 0;
    assert!(p.validate().is_ok());
}

// ===========================================================================
// 31. ClippingStrategy validation edge cases
// ===========================================================================

#[test]
fn clipping_zero_global_bound_fails() {
    let schema = valid_schema();
    let clip = ClippingStrategy {
        method: ClippingMethod::L2Norm,
        global_bound_millionths: 0,
        per_field_bounds: BTreeMap::new(),
    };
    assert!(clip.validate(&schema).is_err());
}

#[test]
fn clipping_per_field_with_l2_norm_fails() {
    let schema = valid_schema();
    let mut bounds = BTreeMap::new();
    bounds.insert("loss".to_string(), 500_000i64);
    let clip = ClippingStrategy {
        method: ClippingMethod::L2Norm,
        global_bound_millionths: 1_000_000,
        per_field_bounds: bounds,
    };
    assert!(clip.validate(&schema).is_err());
}

#[test]
fn clipping_per_field_unknown_field_fails() {
    let schema = valid_schema();
    let mut bounds = BTreeMap::new();
    bounds.insert("nonexistent".to_string(), 500_000i64);
    let clip = ClippingStrategy {
        method: ClippingMethod::PerCoordinate,
        global_bound_millionths: 1_000_000,
        per_field_bounds: bounds,
    };
    assert!(clip.validate(&schema).is_err());
}

#[test]
fn clipping_per_field_negative_bound_fails() {
    let schema = valid_schema();
    let mut bounds = BTreeMap::new();
    bounds.insert("loss".to_string(), -1i64);
    let clip = ClippingStrategy {
        method: ClippingMethod::PerCoordinate,
        global_bound_millionths: 1_000_000,
        per_field_bounds: bounds,
    };
    assert!(clip.validate(&schema).is_err());
}

// ===========================================================================
// 32. DpBudget validation edge cases
// ===========================================================================

#[test]
fn dp_budget_fail_closed_false_fails() {
    let mut b = valid_dp_budget();
    b.fail_closed_on_exhaustion = false;
    assert!(b.validate().is_err());
}

#[test]
fn dp_budget_zero_epsilon_fails() {
    let mut b = valid_dp_budget();
    b.epsilon_per_epoch_millionths = 0;
    assert!(b.validate().is_err());
}

#[test]
fn dp_budget_epoch_exceeds_lifetime_fails() {
    let mut b = valid_dp_budget();
    b.epsilon_per_epoch_millionths = b.lifetime_epsilon_budget_millionths + 1;
    assert!(b.validate().is_err());
}

// ===========================================================================
// 33. DpBudget max_epochs computation
// ===========================================================================

#[test]
fn dp_budget_max_epochs_basic_composition() {
    let b = DpBudgetSemantics {
        epsilon_per_epoch_millionths: 100_000,
        delta_per_epoch_millionths: 1_000,
        composition_method: CompositionMethod::Basic,
        lifetime_epsilon_budget_millionths: 1_000_000,
        lifetime_delta_budget_millionths: 10_000,
        fail_closed_on_exhaustion: true,
    };
    let max = b.max_epochs();
    // Basic: lifetime/per_epoch = 10 for both epsilon and delta
    assert_eq!(max, 10);
}

#[test]
fn dp_budget_max_epochs_advanced_composition() {
    let b = DpBudgetSemantics {
        epsilon_per_epoch_millionths: 100_000,
        delta_per_epoch_millionths: 100,
        composition_method: CompositionMethod::Advanced,
        lifetime_epsilon_budget_millionths: 1_000_000,
        lifetime_delta_budget_millionths: 100_000,
        fail_closed_on_exhaustion: true,
    };
    let max = b.max_epochs();
    // Advanced: (lifetime/per_epoch)^2 = 100, but min with delta = 1000
    assert_eq!(max, 100);
}

// ===========================================================================
// 34. Aggregation validation edge cases
// ===========================================================================

#[test]
fn aggregation_one_participant_fails() {
    let mut a = valid_aggregation();
    a.min_participants = 1;
    assert!(a.validate().is_err());
}

#[test]
fn aggregation_shamir_no_threshold_fails() {
    let a = SecureAggregationRequirements {
        min_participants: 10,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Shamir,
        sharing_threshold: None,
        coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
    };
    assert!(a.validate().is_err());
}

#[test]
fn aggregation_shamir_threshold_one_fails() {
    let a = SecureAggregationRequirements {
        min_participants: 10,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Shamir,
        sharing_threshold: Some(1),
        coordinator_trust_model: CoordinatorTrustModel::Malicious,
    };
    assert!(a.validate().is_err());
}

#[test]
fn aggregation_shamir_threshold_exceeds_participants_fails() {
    let a = SecureAggregationRequirements {
        min_participants: 5,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Shamir,
        sharing_threshold: Some(10),
        coordinator_trust_model: CoordinatorTrustModel::Malicious,
    };
    assert!(a.validate().is_err());
}

#[test]
fn aggregation_additive_with_threshold_fails() {
    let a = SecureAggregationRequirements {
        min_participants: 10,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Additive,
        sharing_threshold: Some(5),
        coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
    };
    assert!(a.validate().is_err());
}

#[test]
fn aggregation_valid_shamir_passes() {
    let a = SecureAggregationRequirements {
        min_participants: 10,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Shamir,
        sharing_threshold: Some(5),
        coordinator_trust_model: CoordinatorTrustModel::Malicious,
    };
    assert!(a.validate().is_ok());
}

// ===========================================================================
// 35. Retention validation edge cases
// ===========================================================================

#[test]
fn retention_zero_intermediate_fails() {
    let mut r = valid_retention();
    r.max_intermediate_retention = 0;
    assert!(r.validate().is_err());
}

#[test]
fn retention_snapshot_less_than_intermediate_fails() {
    let r = DataRetentionPolicy {
        max_intermediate_retention: 100,
        max_snapshot_retention: 50,
        delete_local_after_submission: true,
        delete_shares_after_aggregation: true,
    };
    assert!(r.validate().is_err());
}

// ===========================================================================
// 36. PRNG edge cases
// ===========================================================================

#[test]
fn prng_empty_phase_id_fails() {
    let result = DeterministicPrng::new("", PrngAlgorithm::ChaCha20LikeCounter, b"seed");
    assert!(result.is_err());
}

#[test]
fn prng_empty_seed_fails() {
    let result = DeterministicPrng::new("phase", PrngAlgorithm::ChaCha20LikeCounter, b"");
    assert!(result.is_err());
}

#[test]
fn prng_different_phases_different_output() {
    let mut p1 =
        DeterministicPrng::new("phase_a", PrngAlgorithm::ChaCha20LikeCounter, b"seed").unwrap();
    let mut p2 =
        DeterministicPrng::new("phase_b", PrngAlgorithm::ChaCha20LikeCounter, b"seed").unwrap();
    assert_ne!(p1.next_u64(), p2.next_u64());
}

// ===========================================================================
// 37. Snapshot summary
// ===========================================================================

#[test]
fn snapshot_summary_emit_and_verify() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let eid = EngineObjectId::from_hex(
        "ee00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let mut transcript = RandomnessTranscript::new();
    transcript
        .commit_seed(
            &sk,
            "phase_1",
            b"seed_1",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            eid,
        )
        .unwrap();
    transcript
        .emit_snapshot_summary(&sk, "model-snap-1", "policy-snap-1")
        .unwrap();
    assert_eq!(transcript.snapshot_summaries.len(), 1);
    assert!(transcript.verify_snapshot_summaries(&vk).is_ok());
}

#[test]
fn snapshot_empty_transcript_fails() {
    let sk = test_signing_key();
    let mut transcript = RandomnessTranscript::new();
    let result = transcript.emit_snapshot_summary(&sk, "model", "policy");
    assert!(result.is_err());
}

// ===========================================================================
// 38. Seed escrow access log
// ===========================================================================

#[test]
fn seed_escrow_access_log_records_attempts() {
    let auditors: BTreeSet<String> = ["alice".to_string(), "bob".to_string()]
        .into_iter()
        .collect();
    let mut escrow =
        SeedEscrowRecord::create("phase_1", SecurityEpoch::from_raw(1), b"the_seed", auditors)
            .unwrap();
    // Successful access
    let _ = escrow.open_for_audit("alice", "review");
    // Failed access
    let _ = escrow.open_for_audit("charlie", "hack");
    assert_eq!(escrow.access_log.len(), 2);
    assert!(escrow.access_log[0].approved);
    assert!(!escrow.access_log[1].approved);
}

// ===========================================================================
// 39. Replay with escrowed seeds
// ===========================================================================

#[test]
fn replay_deterministic_with_escrow() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let auditors: BTreeSet<String> = ["auditor".to_string()].into_iter().collect();

    let eid = EngineObjectId::from_hex(
        "ee00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let mut transcript = RandomnessTranscript::new();
    transcript
        .commit_seed(
            &sk,
            "phase_1",
            b"replay_seed",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            eid,
        )
        .unwrap();
    transcript
        .emit_snapshot_summary(&sk, "model-1", "policy-1")
        .unwrap();

    let mut escrow_records = vec![
        SeedEscrowRecord::create(
            "phase_1",
            SecurityEpoch::from_raw(1),
            b"replay_seed",
            auditors,
        )
        .unwrap(),
    ];

    let outputs = transcript
        .replay_with_escrowed_seeds(&vk, &mut escrow_records, "auditor", 5)
        .unwrap();
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].outputs.len(), 5);
    assert_eq!(outputs[0].phase_id, "phase_1");
}

// ===========================================================================
// 40. Contract display
// ===========================================================================

#[test]
fn contract_display_contains_zone() {
    let sk = test_signing_key();
    let contract = create_contract(&sk);
    let display = format!("{contract}");
    assert!(display.contains("us-east-1"));
    assert!(display.contains("PrivacyLearningContract"));
}

// ===========================================================================
// 41. ContractError all variants display
// ===========================================================================

#[test]
fn contract_error_all_variants_display() {
    let dummy_id = EngineObjectId::from_hex(
        "ff00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let errors: Vec<ContractError> = vec![
        ContractError::EmptyFeatureSchema,
        ContractError::InvalidVersion { detail: "v".into() },
        ContractError::FieldNameMismatch {
            key: "k".into(),
            field_name: "f".into(),
        },
        ContractError::BackwardCompatibilityViolation { detail: "b".into() },
        ContractError::InvalidUpdatePolicy { detail: "u".into() },
        ContractError::InvalidClippingStrategy { detail: "c".into() },
        ContractError::InvalidDpBudget { detail: "d".into() },
        ContractError::InvalidAggregation { detail: "a".into() },
        ContractError::InvalidRetention { detail: "r".into() },
        ContractError::InvalidRandomnessTranscript { detail: "t".into() },
        ContractError::MissingSeedEscrow {
            phase_id: "p".into(),
            epoch_id: SecurityEpoch::from_raw(1),
        },
        ContractError::SeedEscrowAccessDenied {
            principal: "bob".into(),
            phase_id: "p".into(),
        },
        ContractError::SeedHashMismatch {
            phase_id: "p".into(),
        },
        ContractError::NoAuthorizedParticipants,
        ContractError::IdDerivationFailed { detail: "i".into() },
        ContractError::SignatureFailed { detail: "s".into() },
        ContractError::SignatureInvalid { detail: "s".into() },
        ContractError::DuplicateContract {
            contract_id: dummy_id.clone(),
        },
        ContractError::NotFound {
            contract_id: dummy_id.clone(),
        },
        ContractError::EpochNotAdvanced {
            zone: "z".into(),
            existing_epoch: SecurityEpoch::from_raw(1),
            new_epoch: SecurityEpoch::from_raw(1),
        },
        ContractError::InvalidShadowEvaluation { detail: "e".into() },
        ContractError::InvalidShadowOverride { detail: "o".into() },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty(), "empty display for {e:?}");
    }
}

// ===========================================================================
// 42. ContractError serde roundtrip
// ===========================================================================

#[test]
fn contract_error_serde_roundtrip() {
    let errors = vec![
        ContractError::EmptyFeatureSchema,
        ContractError::NoAuthorizedParticipants,
        ContractError::InvalidDpBudget {
            detail: "test".into(),
        },
        ContractError::SeedHashMismatch {
            phase_id: "p1".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: ContractError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// 43. ContractEventType serde
// ===========================================================================

#[test]
fn contract_event_type_serde_roundtrip() {
    let dummy_id = EngineObjectId::from_hex(
        "ff00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let events = vec![
        ContractEventType::Registered {
            contract_id: dummy_id.clone(),
            zone: "us-east-1".into(),
            epoch: SecurityEpoch::from_raw(1),
        },
        ContractEventType::Revoked {
            contract_id: dummy_id,
            zone: "us-east-1".into(),
        },
    ];
    for e in &events {
        let json = serde_json::to_string(e).unwrap();
        let back: ContractEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// 44. ContractEvent serde
// ===========================================================================

#[test]
fn contract_event_serde_roundtrip() {
    let dummy_id = EngineObjectId::from_hex(
        "ff00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let event = ContractEvent {
        event_type: ContractEventType::Registered {
            contract_id: dummy_id,
            zone: "eu-west-1".into(),
            epoch: SecurityEpoch::from_raw(5),
        },
        trace_id: "trace-44".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ContractEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// 45. Registry epoch not advanced
// ===========================================================================

#[test]
fn registry_epoch_not_advanced_fails() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract1 = create_contract(&sk);
    // Create another contract for the same zone with same epoch
    let contract2 = create_contract(&sk);
    let mut reg = ContractRegistry::new();
    reg.register(contract1, &vk, "t1").unwrap();
    let result = reg.register(contract2, &vk, "t2");
    assert!(result.is_err());
}

// ===========================================================================
// 46. Registry revoke nonexistent fails
// ===========================================================================

#[test]
fn registry_revoke_nonexistent_fails() {
    let dummy_id = EngineObjectId::from_hex(
        "ff00000000000000000000000000000000000000000000000000000000000099",
    )
    .unwrap();
    let mut reg = ContractRegistry::new();
    let result = reg.revoke(&dummy_id, "t");
    assert!(result.is_err());
}

// ===========================================================================
// 47. Contract no participants fails
// ===========================================================================

#[test]
fn create_contract_no_participants_fails() {
    let sk = test_signing_key();
    let schema = valid_schema();
    let result = PrivacyLearningContract::create_signed(
        &sk,
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(1),
            zone: "us-east-1",
            feature_schema: schema.clone(),
            update_policy: valid_update_policy(),
            clipping_strategy: valid_clipping(&schema),
            dp_budget: valid_dp_budget(),
            aggregation: valid_aggregation(),
            retention: valid_retention(),
            authorized_participants: BTreeSet::new(), // empty
        },
    );
    assert!(result.is_err());
}

// ===========================================================================
// 48. ClippingMethod display
// ===========================================================================

#[test]
fn clipping_method_display_all() {
    assert_eq!(ClippingMethod::L2Norm.to_string(), "l2_norm");
    assert_eq!(ClippingMethod::PerCoordinate.to_string(), "per_coordinate");
    assert_eq!(ClippingMethod::Adaptive.to_string(), "adaptive");
}

// ===========================================================================
// 49. CompositionMethod display
// ===========================================================================

#[test]
fn composition_method_display_all() {
    assert_eq!(CompositionMethod::Basic.to_string(), "basic");
    assert_eq!(CompositionMethod::Advanced.to_string(), "advanced");
    assert_eq!(CompositionMethod::Renyi.to_string(), "renyi");
    assert_eq!(CompositionMethod::ZeroCdp.to_string(), "zcdp");
}

// ===========================================================================
// 50. CoordinatorTrustModel display
// ===========================================================================

#[test]
fn coordinator_trust_model_display_all() {
    assert_eq!(
        CoordinatorTrustModel::HonestButCurious.to_string(),
        "honest_but_curious"
    );
    assert_eq!(CoordinatorTrustModel::Malicious.to_string(), "malicious");
}

// ===========================================================================
// 51. SecretSharingScheme display
// ===========================================================================

#[test]
fn secret_sharing_scheme_display_all() {
    assert_eq!(SecretSharingScheme::Additive.to_string(), "additive");
    assert_eq!(SecretSharingScheme::Shamir.to_string(), "shamir");
}

// ===========================================================================
// 52. PrngAlgorithm display
// ===========================================================================

#[test]
fn prng_algorithm_display() {
    assert_eq!(
        PrngAlgorithm::ChaCha20LikeCounter.to_string(),
        "chacha20_like_counter"
    );
}

// ===========================================================================
// 53. SeedEscrowAccessEvent serde
// ===========================================================================

#[test]
fn seed_escrow_access_event_serde() {
    let event = SeedEscrowAccessEvent {
        principal: "alice".into(),
        reason: "audit".into(),
        approved: true,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SeedEscrowAccessEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// 54. ReplayOutput serde
// ===========================================================================

#[test]
fn replay_output_serde_roundtrip() {
    let output = ReplayOutput {
        phase_id: "phase_1".into(),
        sequence_counter: 1,
        outputs: vec![123, 456, 789],
    };
    let json = serde_json::to_string(&output).unwrap();
    let back: ReplayOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

// ===========================================================================
// 55. SafetyMetric display
// ===========================================================================

#[test]
fn safety_metric_display_all() {
    for m in SafetyMetric::ALL {
        assert!(!m.to_string().is_empty());
    }
}

// ===========================================================================
// 56. SafetyMetricSnapshot missing metric returns zero
// ===========================================================================

#[test]
fn safety_metric_snapshot_missing_returns_zero() {
    let snap = SafetyMetricSnapshot {
        values_millionths: BTreeMap::new(),
    };
    assert_eq!(snap.metric_value(SafetyMetric::CalibrationError), 0);
}

// ===========================================================================
// 57. SafetyMetricSnapshot empty validates
// ===========================================================================

#[test]
fn safety_metric_snapshot_empty_validates() {
    let snap = SafetyMetricSnapshot {
        values_millionths: BTreeMap::new(),
    };
    // Empty is valid — no invariant requires all metrics present
    assert!(snap.validate().is_ok());
}

// ===========================================================================
// 58. RandomnessTranscript default
// ===========================================================================

#[test]
fn randomness_transcript_default_is_empty() {
    let t = RandomnessTranscript::default();
    assert!(t.commitments.is_empty());
    assert!(t.snapshot_summaries.is_empty());
}

// ===========================================================================
// 59. Registry serde roundtrip
// ===========================================================================

#[test]
fn registry_serde_roundtrip() {
    let sk = test_signing_key();
    let vk = sk.verification_key();
    let contract = create_contract(&sk);
    let mut reg = ContractRegistry::new();
    reg.register(contract, &vk, "trace-serde").unwrap();
    let json = serde_json::to_string(&reg).unwrap();
    let back: ContractRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_count(), 1);
    assert_eq!(back.zone_count(), 1);
}

// ===========================================================================
// 60. ShadowExtensionClass display
// ===========================================================================

#[test]
fn shadow_extension_class_display_all() {
    for c in [
        ShadowExtensionClass::LowRisk,
        ShadowExtensionClass::Standard,
        ShadowExtensionClass::HighRisk,
        ShadowExtensionClass::Critical,
    ] {
        assert!(!c.to_string().is_empty());
    }
}

// ===========================================================================
// 61. ShadowPromotionVerdict display
// ===========================================================================

#[test]
fn shadow_promotion_verdict_display_all() {
    for v in [
        ShadowPromotionVerdict::Pass,
        ShadowPromotionVerdict::Reject,
        ShadowPromotionVerdict::OverrideApproved,
    ] {
        assert!(!v.to_string().is_empty());
    }
}
