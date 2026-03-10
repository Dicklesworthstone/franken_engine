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
    ShadowReplayReference, ShadowRollbackReadinessArtifacts, UpdatePolicy, contract_schema,
    contract_schema_id,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_ZONE: &str = "integration-test-zone";

fn governance_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x01; 32])
}

fn governance_vk() -> frankenengine_engine::signature_preimage::VerificationKey {
    governance_signing_key().verification_key()
}

fn test_participant_ids() -> BTreeSet<EngineObjectId> {
    let mut set = BTreeSet::new();
    set.insert(EngineObjectId([0xAA; 32]));
    set.insert(EngineObjectId([0xBB; 32]));
    set.insert(EngineObjectId([0xCC; 32]));
    set
}

fn test_feature_schema() -> FeatureSchema {
    let mut fields = BTreeMap::new();
    fields.insert(
        "calibration_residual".to_string(),
        FeatureField {
            name: "calibration_residual".to_string(),
            field_type: FeatureFieldType::FixedPoint,
            description: "Residual between predicted and observed calibration".to_string(),
            existed_in_prior_version: false,
        },
    );
    fields.insert(
        "false_positive_count".to_string(),
        FeatureField {
            name: "false_positive_count".to_string(),
            field_type: FeatureFieldType::Counter,
            description: "Number of false positive detections".to_string(),
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
        min_local_samples: 100,
        min_submission_interval: 3600,
        max_data_age: 86400,
        allow_skip: true,
        max_consecutive_skips: 3,
    }
}

fn test_clipping_strategy() -> ClippingStrategy {
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
        min_participants: 10,
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
        zone: TEST_ZONE,
        feature_schema: test_feature_schema(),
        update_policy: test_update_policy(),
        clipping_strategy: test_clipping_strategy(),
        dp_budget: test_dp_budget(),
        aggregation: test_aggregation(),
        retention: test_retention(),
        authorized_participants: test_participant_ids(),
    }
}

fn create_test_contract() -> PrivacyLearningContract {
    PrivacyLearningContract::create_signed(&governance_signing_key(), test_contract_input())
        .expect("create test contract")
}

fn evidence_id(byte: u8) -> EngineObjectId {
    EngineObjectId([byte; 32])
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

fn replay_reference() -> ShadowReplayReference {
    ShadowReplayReference {
        replay_corpus_id: "corpus-2026-02".to_string(),
        randomness_snapshot_id: "rng-snapshot-7".to_string(),
        replay_seed_hash: [0x5A; 32],
        replay_seed_counter: 42,
    }
}

fn rollback_readiness() -> ShadowRollbackReadinessArtifacts {
    ShadowRollbackReadinessArtifacts {
        rollback_command_tested: true,
        previous_policy_snapshot_id: "snapshot-2026-02-19".to_string(),
        transition_receipt_signed: true,
        rollback_playbook_ref: "playbook://shadow-gate/rollback-v1".to_string(),
    }
}

fn candidate_with_metrics(
    candidate_metrics: SafetyMetricSnapshot,
    epsilon_spent_millionths: i64,
    delta_spent_millionths: i64,
) -> ShadowEvaluationCandidate {
    ShadowEvaluationCandidate {
        trace_id: "trace-shadow-1".to_string(),
        decision_id: "decision-shadow-1".to_string(),
        policy_id: "policy-shadow-1".to_string(),
        extension_class: ShadowExtensionClass::Standard,
        candidate_version: "v2026.02.20".to_string(),
        baseline_snapshot_id: "snapshot-2026-02-19".to_string(),
        rollback_token: "rollback-token-shadow-1".to_string(),
        epoch_id: SecurityEpoch::from_raw(9),
        shadow_started_at_ns: 1_000_000_000,
        evaluation_completed_at_ns: 1_000_000_120,
        shadow_success_rate_millionths: 997_000,
        false_deny_rate_millionths: 4_000,
        rollback_readiness: rollback_readiness(),
        baseline_metrics: baseline_metrics(),
        candidate_metrics,
        replay_reference: replay_reference(),
        epsilon_spent_millionths,
        delta_spent_millionths,
    }
}

fn shadow_gate() -> ShadowEvaluationGate {
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
    .expect("shadow gate")
}

// ===================================================================
// ContractError Display — exhaustive verification
// ===================================================================

#[test]
fn error_display_empty_feature_schema() {
    let e = ContractError::EmptyFeatureSchema;
    assert_eq!(e.to_string(), "feature schema has no fields");
}

#[test]
fn error_display_invalid_version() {
    let e = ContractError::InvalidVersion {
        detail: "must be > 0".to_string(),
    };
    assert!(e.to_string().contains("invalid version"));
    assert!(e.to_string().contains("must be > 0"));
}

#[test]
fn error_display_field_name_mismatch() {
    let e = ContractError::FieldNameMismatch {
        key: "k".to_string(),
        field_name: "f".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("field name mismatch"));
    assert!(s.contains("k"));
    assert!(s.contains("f"));
}

#[test]
fn error_display_backward_compatibility_violation() {
    let e = ContractError::BackwardCompatibilityViolation {
        detail: "missing field".to_string(),
    };
    assert!(e.to_string().contains("backward compatibility violation"));
}

#[test]
fn error_display_invalid_update_policy() {
    let e = ContractError::InvalidUpdatePolicy {
        detail: "reason".to_string(),
    };
    assert!(e.to_string().contains("invalid update policy"));
}

#[test]
fn error_display_invalid_clipping_strategy() {
    let e = ContractError::InvalidClippingStrategy {
        detail: "reason".to_string(),
    };
    assert!(e.to_string().contains("invalid clipping strategy"));
}

#[test]
fn error_display_invalid_dp_budget() {
    let e = ContractError::InvalidDpBudget {
        detail: "bad epsilon".to_string(),
    };
    assert!(e.to_string().contains("invalid DP budget"));
}

#[test]
fn error_display_invalid_aggregation() {
    let e = ContractError::InvalidAggregation {
        detail: "too few".to_string(),
    };
    assert!(e.to_string().contains("invalid aggregation"));
}

#[test]
fn error_display_invalid_retention() {
    let e = ContractError::InvalidRetention {
        detail: "reason".to_string(),
    };
    assert!(e.to_string().contains("invalid retention"));
}

#[test]
fn error_display_invalid_randomness_transcript() {
    let e = ContractError::InvalidRandomnessTranscript {
        detail: "broken chain".to_string(),
    };
    assert!(e.to_string().contains("invalid randomness transcript"));
}

#[test]
fn error_display_missing_seed_escrow() {
    let e = ContractError::MissingSeedEscrow {
        phase_id: "noise".to_string(),
        epoch_id: SecurityEpoch::from_raw(5),
    };
    let s = e.to_string();
    assert!(s.contains("missing seed escrow"));
    assert!(s.contains("noise"));
}

#[test]
fn error_display_seed_escrow_access_denied() {
    let e = ContractError::SeedEscrowAccessDenied {
        principal: "bad-actor".to_string(),
        phase_id: "noise".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("seed escrow access denied"));
    assert!(s.contains("bad-actor"));
}

#[test]
fn error_display_seed_hash_mismatch() {
    let e = ContractError::SeedHashMismatch {
        phase_id: "phase-x".to_string(),
    };
    assert!(e.to_string().contains("seed hash mismatch"));
}

#[test]
fn error_display_no_authorized_participants() {
    let e = ContractError::NoAuthorizedParticipants;
    assert_eq!(e.to_string(), "no authorized participants");
}

#[test]
fn error_display_id_derivation_failed() {
    let e = ContractError::IdDerivationFailed {
        detail: "reason".to_string(),
    };
    assert!(e.to_string().contains("id derivation failed"));
}

#[test]
fn error_display_signature_failed() {
    let e = ContractError::SignatureFailed {
        detail: "reason".to_string(),
    };
    assert!(e.to_string().contains("signature failed"));
}

#[test]
fn error_display_signature_invalid() {
    let e = ContractError::SignatureInvalid {
        detail: "reason".to_string(),
    };
    assert!(e.to_string().contains("signature invalid"));
}

#[test]
fn error_display_duplicate_contract() {
    let e = ContractError::DuplicateContract {
        contract_id: EngineObjectId([0xAA; 32]),
    };
    assert!(e.to_string().contains("duplicate contract"));
}

#[test]
fn error_display_not_found() {
    let e = ContractError::NotFound {
        contract_id: EngineObjectId([0xBB; 32]),
    };
    assert!(e.to_string().contains("contract not found"));
}

#[test]
fn error_display_epoch_not_advanced() {
    let e = ContractError::EpochNotAdvanced {
        zone: "z".to_string(),
        existing_epoch: SecurityEpoch::from_raw(1),
        new_epoch: SecurityEpoch::from_raw(1),
    };
    let s = e.to_string();
    assert!(s.contains("epoch not advanced"));
    assert!(s.contains("zone z"));
}

#[test]
fn error_display_invalid_shadow_evaluation() {
    let e = ContractError::InvalidShadowEvaluation {
        detail: "reason".to_string(),
    };
    assert!(e.to_string().contains("invalid shadow evaluation"));
}

#[test]
fn error_display_invalid_shadow_override() {
    let e = ContractError::InvalidShadowOverride {
        detail: "reason".to_string(),
    };
    assert!(e.to_string().contains("invalid shadow override"));
}

// ===================================================================
// ContractError std::error::Error
// ===================================================================

#[test]
fn contract_error_implements_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(ContractError::EmptyFeatureSchema);
    assert!(e.source().is_none());
    assert!(!e.to_string().is_empty());
}

#[test]
fn contract_error_implements_std_error_with_detail() {
    let e: Box<dyn std::error::Error> = Box::new(ContractError::InvalidDpBudget {
        detail: "test".to_string(),
    });
    assert!(e.source().is_none());
    assert!(e.to_string().contains("test"));
}

// ===================================================================
// SafetyMetric Display
// ===================================================================

#[test]
fn safety_metric_display_all_variants() {
    assert_eq!(
        SafetyMetric::FalsePositiveRate.to_string(),
        "false_positive_rate"
    );
    assert_eq!(
        SafetyMetric::FalseNegativeRate.to_string(),
        "false_negative_rate"
    );
    assert_eq!(
        SafetyMetric::CalibrationError.to_string(),
        "calibration_error"
    );
    assert_eq!(
        SafetyMetric::DriftDetectionAccuracy.to_string(),
        "drift_detection_accuracy"
    );
    assert_eq!(
        SafetyMetric::ContainmentTime.to_string(),
        "containment_time"
    );
}

#[test]
fn safety_metric_all_constant_has_five_entries() {
    assert_eq!(SafetyMetric::ALL.len(), 5);
}

// ===================================================================
// ShadowPromotionVerdict Display
// ===================================================================

#[test]
fn shadow_promotion_verdict_display() {
    assert_eq!(ShadowPromotionVerdict::Pass.to_string(), "pass");
    assert_eq!(ShadowPromotionVerdict::Reject.to_string(), "reject");
    assert_eq!(
        ShadowPromotionVerdict::OverrideApproved.to_string(),
        "override_approved"
    );
}

// ===================================================================
// PrngAlgorithm Display
// ===================================================================

#[test]
fn prng_algorithm_display() {
    assert_eq!(
        PrngAlgorithm::ChaCha20LikeCounter.to_string(),
        "chacha20_like_counter"
    );
}

// ===================================================================
// CompositionMethod Display — Advanced variant untested inline
// ===================================================================

#[test]
fn composition_method_display_advanced() {
    assert_eq!(CompositionMethod::Advanced.to_string(), "advanced");
}

// ===================================================================
// SafetyMetricSnapshot edge cases
// ===================================================================

#[test]
fn safety_metric_snapshot_validate_missing_metric() {
    let mut snap = baseline_metrics();
    snap.values_millionths
        .remove(&SafetyMetric::ContainmentTime);
    let err = snap.validate().unwrap_err();
    assert!(matches!(err, ContractError::InvalidShadowEvaluation { .. }));
}

#[test]
fn safety_metric_snapshot_metric_value_missing_returns_zero() {
    let snap = SafetyMetricSnapshot {
        values_millionths: BTreeMap::new(),
    };
    assert_eq!(snap.metric_value(SafetyMetric::FalsePositiveRate), 0);
}

// ===================================================================
// ShadowEvaluationGateConfig
// ===================================================================

#[test]
fn shadow_gate_config_default_is_valid() {
    let config = ShadowEvaluationGateConfig::default();
    assert!(config.regression_tolerance_millionths > 0);
    assert!(config.min_required_improvement_millionths > 0);
    let gate = ShadowEvaluationGate::new(config);
    assert!(gate.is_ok());
}

#[test]
fn shadow_gate_config_zero_improvement_rejected() {
    let config = ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 5_000,
        min_required_improvement_millionths: 0,
        ..ShadowEvaluationGateConfig::default()
    };
    let result = ShadowEvaluationGate::new(config);
    assert!(result.is_err());
}

#[test]
fn shadow_gate_config_zero_regression_tolerance_allowed() {
    let config = ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 0,
        min_required_improvement_millionths: 1_000,
        ..ShadowEvaluationGateConfig::default()
    };
    assert!(ShadowEvaluationGate::new(config).is_ok());
}

// ===================================================================
// DP budget — Advanced composition
// ===================================================================

#[test]
fn dp_budget_max_epochs_advanced() {
    let mut budget = test_dp_budget();
    budget.composition_method = CompositionMethod::Advanced;
    budget.epsilon_per_epoch_millionths = 500_000; // 0.5
    budget.lifetime_epsilon_budget_millionths = 5_000_000; // 5.0
    // sqrt composition: (5_000_000 / 500_000)^2 = 100
    assert_eq!(budget.max_epochs(), 100);
}

// ===================================================================
// DP budget — delta epoch exceeds delta lifetime
// ===================================================================

#[test]
fn dp_budget_delta_epoch_exceeds_lifetime_rejected() {
    let mut budget = test_dp_budget();
    budget.delta_per_epoch_millionths = budget.lifetime_delta_budget_millionths + 1;
    assert!(matches!(
        budget.validate(),
        Err(ContractError::InvalidDpBudget { .. })
    ));
}

// ===================================================================
// Clipping — Adaptive method
// ===================================================================

#[test]
fn clipping_strategy_adaptive_valid() {
    let clipping = ClippingStrategy {
        method: ClippingMethod::Adaptive,
        global_bound_millionths: 500_000,
        per_field_bounds: BTreeMap::new(),
    };
    clipping
        .validate(&test_feature_schema())
        .expect("adaptive valid");
}

// ===================================================================
// Shadow gate: candidate validation failures
// ===================================================================

#[test]
fn shadow_gate_rejects_empty_trace_id() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.trace_id.clear();
    let result = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    assert!(result.is_err());
}

#[test]
fn shadow_gate_rejects_empty_decision_id() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.decision_id.clear();
    let result = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    assert!(result.is_err());
}

#[test]
fn shadow_gate_rejects_empty_policy_id() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.policy_id.clear();
    let result = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    assert!(result.is_err());
}

#[test]
fn shadow_gate_rejects_empty_candidate_version() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.candidate_version.clear();
    let result = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    assert!(result.is_err());
}

#[test]
fn shadow_gate_rejects_empty_rollback_token() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.rollback_token.clear();
    let result = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    assert!(result.is_err());
}

#[test]
fn shadow_gate_rejects_negative_epsilon_spent() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let candidate = candidate_with_metrics(improved_metrics(), -1, 900);
    let result = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    assert!(result.is_err());
}

#[test]
fn shadow_gate_rejects_negative_delta_spent() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let candidate = candidate_with_metrics(improved_metrics(), 90_000, -1);
    let result = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    assert!(result.is_err());
}

#[test]
fn shadow_gate_rejects_when_burn_in_duration_below_threshold() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.evaluation_completed_at_ns = candidate.shadow_started_at_ns + 10;

    let artifact = gate
        .evaluate_candidate(&contract, candidate, &governance_signing_key())
        .expect("shadow evaluation");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("burn-in duration"))
    );
    assert!(gate.events().iter().any(|event| {
        event.error_code.as_deref() == Some("FE-PLC-SHADOW-0008")
            && event.event == "shadow_evaluation"
    }));
}

#[test]
fn shadow_gate_rejects_when_rollback_artifacts_not_verified() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.rollback_readiness.rollback_command_tested = false;

    let artifact = gate
        .evaluate_candidate(&contract, candidate, &governance_signing_key())
        .expect("shadow evaluation");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(artifact.failure_reasons.iter().any(|reason| {
        reason.contains("rollback readiness artifacts are incomplete or unverified")
    }));
    assert!(gate.events().iter().any(|event| {
        event.error_code.as_deref() == Some("FE-PLC-SHADOW-0011")
            && event.event == "shadow_evaluation"
    }));
}

#[test]
fn shadow_gate_emits_error_event_on_invalid_candidate() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.trace_id.clear();
    let _ = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    let events = gate.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].error_code.as_deref(), Some("FE-PLC-SHADOW-0001"));
}

// ===================================================================
// Shadow gate: override validation failures
// ===================================================================

#[test]
fn shadow_gate_override_rejects_empty_operator_id() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(regressed_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("evaluate");
    let result = gate.apply_human_override(
        &artifact,
        HumanOverrideRequest {
            operator_id: "".to_string(),
            summary: "reason".to_string(),
            bypassed_risk_criteria: vec!["criterion".to_string()],
            acknowledged_bypass: true,
        },
        &governance_signing_key(),
    );
    assert!(result.is_err());
}

#[test]
fn shadow_gate_override_rejects_empty_summary() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(regressed_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("evaluate");
    let result = gate.apply_human_override(
        &artifact,
        HumanOverrideRequest {
            operator_id: "operator".to_string(),
            summary: "".to_string(),
            bypassed_risk_criteria: vec!["criterion".to_string()],
            acknowledged_bypass: true,
        },
        &governance_signing_key(),
    );
    assert!(result.is_err());
}

#[test]
fn shadow_gate_override_rejects_empty_criteria() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(regressed_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("evaluate");
    let result = gate.apply_human_override(
        &artifact,
        HumanOverrideRequest {
            operator_id: "operator".to_string(),
            summary: "reason".to_string(),
            bypassed_risk_criteria: vec![],
            acknowledged_bypass: true,
        },
        &governance_signing_key(),
    );
    assert!(result.is_err());
}

#[test]
fn shadow_gate_override_rejects_unacknowledged_bypass() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(regressed_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("evaluate");
    let result = gate.apply_human_override(
        &artifact,
        HumanOverrideRequest {
            operator_id: "operator".to_string(),
            summary: "reason".to_string(),
            bypassed_risk_criteria: vec!["criterion".to_string()],
            acknowledged_bypass: false,
        },
        &governance_signing_key(),
    );
    assert!(result.is_err());
}

#[test]
fn shadow_gate_override_failure_emits_reject_event() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(regressed_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("evaluate");
    let _ = gate.apply_human_override(
        &artifact,
        HumanOverrideRequest {
            operator_id: "".to_string(),
            summary: "reason".to_string(),
            bypassed_risk_criteria: vec!["criterion".to_string()],
            acknowledged_bypass: true,
        },
        &governance_signing_key(),
    );
    let last = gate.events().last().expect("event");
    assert_eq!(last.event, "human_override");
    assert_eq!(last.outcome, "reject");
    assert_eq!(last.error_code.as_deref(), Some("FE-PLC-SHADOW-0006"));
}

// ===================================================================
// Shadow gate: post-deployment metrics — no regression → None
// ===================================================================

#[test]
fn shadow_gate_post_deployment_no_regression_returns_none() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(improved_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("pass");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);

    let result = gate
        .evaluate_post_deployment_metrics(&artifact, improved_metrics(), &governance_signing_key())
        .expect("post deployment check");
    assert!(result.is_none());
    let last = gate.events().last().expect("event");
    assert_eq!(last.event, "post_deployment_guard");
    assert_eq!(last.outcome, "pass");
}

// ===================================================================
// Shadow gate: drain_events clears events
// ===================================================================

#[test]
fn shadow_gate_drain_events_clears() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    gate.evaluate_candidate(
        &contract,
        candidate_with_metrics(improved_metrics(), 90_000, 900),
        &governance_signing_key(),
    )
    .expect("pass");
    assert!(!gate.events().is_empty());
    let drained = gate.drain_events();
    assert!(!drained.is_empty());
    assert!(gate.events().is_empty());
}

// ===================================================================
// Shadow gate: active_artifact lifecycle
// ===================================================================

#[test]
fn shadow_gate_active_artifact_after_pass() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(improved_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("pass");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
    let active = gate.active_artifact(&artifact.policy_id);
    assert!(active.is_some());
    assert_eq!(active.unwrap().verdict, ShadowPromotionVerdict::Pass);
}

#[test]
fn shadow_gate_active_artifact_not_stored_on_reject() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(regressed_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("reject");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(gate.active_artifact(&artifact.policy_id).is_none());
}

#[test]
fn shadow_gate_active_artifact_after_override() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(regressed_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("reject");
    let overridden = gate
        .apply_human_override(
            &artifact,
            HumanOverrideRequest {
                operator_id: "governor".to_string(),
                summary: "manual promotion".to_string(),
                bypassed_risk_criteria: vec!["criterion".to_string()],
                acknowledged_bypass: true,
            },
            &governance_signing_key(),
        )
        .expect("override");
    assert_eq!(overridden.verdict, ShadowPromotionVerdict::OverrideApproved);
    let active = gate.active_artifact(&overridden.policy_id);
    assert!(active.is_some());
    assert_eq!(
        active.unwrap().verdict,
        ShadowPromotionVerdict::OverrideApproved
    );
}

// ===================================================================
// Shadow gate: no significant improvement → reject
// ===================================================================

#[test]
fn shadow_gate_rejects_when_no_significant_improvement() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    // Metrics identical to baseline — no improvement at all.
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(baseline_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("no improvement");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert_eq!(artifact.significant_improvement_count, 0);
}

// ===================================================================
// Shadow gate: deterministic replay check
// ===================================================================

#[test]
fn shadow_gate_rejects_zero_seed_hash() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let mut candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
    candidate.replay_reference.replay_seed_hash = [0u8; 32];
    // Validation will catch this via ShadowReplayReference::validate
    let result = gate.evaluate_candidate(&contract, candidate, &governance_signing_key());
    assert!(result.is_err());
}

// ===================================================================
// Randomness transcript edge cases
// ===================================================================

#[test]
fn randomness_empty_transcript_chain_verifies() {
    let transcript = RandomnessTranscript::new();
    transcript
        .verify_chain(&governance_vk())
        .expect("empty chain is vacuously valid");
}

#[test]
fn randomness_single_commitment_chain() {
    let mut transcript = RandomnessTranscript::new();
    let sk = governance_signing_key();
    let vk = governance_vk();
    let epoch = SecurityEpoch::from_raw(1);

    let commitment = transcript
        .commit_seed(
            &sk,
            "only-phase",
            b"only-seed",
            PrngAlgorithm::ChaCha20LikeCounter,
            epoch,
            evidence_id(0x01),
        )
        .expect("single commitment");
    assert_eq!(commitment.sequence_counter, 1);
    assert!(commitment.previous_commitment_hash.is_none());

    transcript
        .verify_chain(&vk)
        .expect("single-entry chain valid");
}

// ===================================================================
// PRNG: different seeds produce different output
// ===================================================================

#[test]
fn prng_different_seeds_produce_different_output() {
    let mut p1 = DeterministicPrng::new(
        "same-phase",
        PrngAlgorithm::ChaCha20LikeCounter,
        b"seed-alpha",
    )
    .expect("prng1");
    let mut p2 = DeterministicPrng::new(
        "same-phase",
        PrngAlgorithm::ChaCha20LikeCounter,
        b"seed-beta",
    )
    .expect("prng2");

    let seq1: Vec<u64> = (0..5).map(|_| p1.next_u64()).collect();
    let seq2: Vec<u64> = (0..5).map(|_| p2.next_u64()).collect();
    assert_ne!(seq1, seq2);
}

#[test]
fn prng_draw_counter_increments() {
    let mut prng = DeterministicPrng::new(
        "counter-test",
        PrngAlgorithm::ChaCha20LikeCounter,
        b"test-seed",
    )
    .expect("prng");
    assert_eq!(prng.draw_counter(), 0);
    prng.next_u64();
    assert_eq!(prng.draw_counter(), 1);
    prng.next_u64();
    prng.next_u64();
    assert_eq!(prng.draw_counter(), 3);
}

// ===================================================================
// Seed escrow: authorized auditor can open
// ===================================================================

#[test]
fn seed_escrow_authorized_auditor_can_open() {
    let mut auditors = BTreeSet::new();
    auditors.insert("allowed-auditor".to_string());
    let mut escrow = SeedEscrowRecord::create(
        "dropout-phase",
        SecurityEpoch::from_raw(1),
        b"dropout-seed",
        auditors,
    )
    .expect("escrow");
    let seed = escrow.open_for_audit("allowed-auditor", "investigation");
    assert!(seed.is_ok());
}

#[test]
fn seed_escrow_is_deterministic() {
    let mut auditors = BTreeSet::new();
    auditors.insert("auditor".to_string());
    let escrow_a = SeedEscrowRecord::create(
        "phase-a",
        SecurityEpoch::from_raw(1),
        b"the-seed",
        auditors.clone(),
    )
    .expect("a");
    let escrow_b =
        SeedEscrowRecord::create("phase-a", SecurityEpoch::from_raw(1), b"the-seed", auditors)
            .expect("b");
    assert_eq!(escrow_a.encrypted_seed, escrow_b.encrypted_seed);
    assert_eq!(escrow_a.seed_hash, escrow_b.seed_hash);
}

// ===================================================================
// Contract creation: compound validation — first failure wins
// ===================================================================

#[test]
fn create_contract_invalid_update_policy_rejected() {
    let mut input = test_contract_input();
    input.update_policy.min_local_samples = 0;
    let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
    assert!(matches!(
        result,
        Err(ContractError::InvalidUpdatePolicy { .. })
    ));
}

#[test]
fn create_contract_invalid_clipping_rejected() {
    let mut input = test_contract_input();
    input.clipping_strategy.global_bound_millionths = 0;
    let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
    assert!(matches!(
        result,
        Err(ContractError::InvalidClippingStrategy { .. })
    ));
}

#[test]
fn create_contract_invalid_aggregation_rejected() {
    let mut input = test_contract_input();
    input.aggregation.min_participants = 1;
    let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
    assert!(matches!(
        result,
        Err(ContractError::InvalidAggregation { .. })
    ));
}

#[test]
fn create_contract_invalid_retention_rejected() {
    let mut input = test_contract_input();
    input.retention.max_intermediate_retention = 0;
    let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
    assert!(matches!(
        result,
        Err(ContractError::InvalidRetention { .. })
    ));
}

// ===================================================================
// Registry: zone_count tracks through operations
// ===================================================================

#[test]
fn registry_zone_count_tracks_add_and_revoke() {
    let mut registry = ContractRegistry::new();
    assert_eq!(registry.zone_count(), 0);

    let contract = create_test_contract();
    let id = registry
        .register(contract, &governance_vk(), "t-1")
        .expect("register");
    assert_eq!(registry.zone_count(), 1);

    registry.revoke(&id, "t-revoke").expect("revoke");
    assert_eq!(registry.zone_count(), 0);
}

#[test]
fn registry_drain_events_empties_queue() {
    let mut registry = ContractRegistry::new();
    let contract = create_test_contract();
    registry
        .register(contract, &governance_vk(), "t-reg")
        .expect("register");
    let events = registry.drain_events();
    assert_eq!(events.len(), 1);
    assert!(registry.drain_events().is_empty());
}

// ===================================================================
// Serde roundtrips for additional types
// ===================================================================

#[test]
fn update_policy_serde_roundtrip() {
    let policy = test_update_policy();
    let json = serde_json::to_string(&policy).expect("serialize");
    let restored: UpdatePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, restored);
}

#[test]
fn clipping_strategy_serde_roundtrip() {
    let clipping = test_clipping_strategy();
    let json = serde_json::to_string(&clipping).expect("serialize");
    let restored: ClippingStrategy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(clipping, restored);
}

#[test]
fn aggregation_serde_roundtrip() {
    let agg = test_aggregation();
    let json = serde_json::to_string(&agg).expect("serialize");
    let restored: SecureAggregationRequirements = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(agg, restored);
}

#[test]
fn retention_serde_roundtrip() {
    let ret = test_retention();
    let json = serde_json::to_string(&ret).expect("serialize");
    let restored: DataRetentionPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ret, restored);
}

#[test]
fn shadow_gate_config_serde_roundtrip() {
    let config = ShadowEvaluationGateConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: ShadowEvaluationGateConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, restored);
}

#[test]
fn shadow_replay_reference_serde_roundtrip() {
    let rr = replay_reference();
    let json = serde_json::to_string(&rr).expect("serialize");
    let restored: ShadowReplayReference = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(rr, restored);
}

#[test]
fn safety_metric_snapshot_serde_roundtrip() {
    let snap = baseline_metrics();
    let json = serde_json::to_string(&snap).expect("serialize");
    let restored: SafetyMetricSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snap, restored);
}

#[test]
fn shadow_promotion_verdict_serde_roundtrip() {
    for verdict in [
        ShadowPromotionVerdict::Pass,
        ShadowPromotionVerdict::Reject,
        ShadowPromotionVerdict::OverrideApproved,
    ] {
        let json = serde_json::to_string(&verdict).expect("serialize");
        let restored: ShadowPromotionVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(verdict, restored);
    }
}

#[test]
fn safety_metric_serde_roundtrip() {
    for metric in SafetyMetric::ALL {
        let json = serde_json::to_string(metric).expect("serialize");
        let restored: SafetyMetric = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*metric, restored);
    }
}

#[test]
fn clipping_method_serde_roundtrip() {
    for method in [
        ClippingMethod::L2Norm,
        ClippingMethod::PerCoordinate,
        ClippingMethod::Adaptive,
    ] {
        let json = serde_json::to_string(&method).expect("serialize");
        let restored: ClippingMethod = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(method, restored);
    }
}

#[test]
fn composition_method_serde_roundtrip() {
    for method in [
        CompositionMethod::Basic,
        CompositionMethod::Advanced,
        CompositionMethod::Renyi,
        CompositionMethod::ZeroCdp,
    ] {
        let json = serde_json::to_string(&method).expect("serialize");
        let restored: CompositionMethod = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(method, restored);
    }
}

#[test]
fn coordinator_trust_model_serde_roundtrip() {
    for model in [
        CoordinatorTrustModel::HonestButCurious,
        CoordinatorTrustModel::Malicious,
    ] {
        let json = serde_json::to_string(&model).expect("serialize");
        let restored: CoordinatorTrustModel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(model, restored);
    }
}

#[test]
fn secret_sharing_scheme_serde_roundtrip() {
    for scheme in [SecretSharingScheme::Additive, SecretSharingScheme::Shamir] {
        let json = serde_json::to_string(&scheme).expect("serialize");
        let restored: SecretSharingScheme = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(scheme, restored);
    }
}

#[test]
fn prng_algorithm_serde_roundtrip() {
    let algo = PrngAlgorithm::ChaCha20LikeCounter;
    let json = serde_json::to_string(&algo).expect("serialize");
    let restored: PrngAlgorithm = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(algo, restored);
}

#[test]
fn human_override_request_serde_roundtrip() {
    let req = HumanOverrideRequest {
        operator_id: "op-1".to_string(),
        summary: "manual promotion".to_string(),
        bypassed_risk_criteria: vec!["crit-1".to_string()],
        acknowledged_bypass: true,
    };
    let json = serde_json::to_string(&req).expect("serialize");
    let restored: HumanOverrideRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, restored);
}

// ===================================================================
// Shadow promotion decision artifact serde
// ===================================================================

#[test]
fn shadow_promotion_artifact_serde_roundtrip() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(improved_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("pass");
    let json = serde_json::to_string(&artifact).expect("serialize");
    let restored = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, restored);
}

// ===================================================================
// Shadow gate event serde
// ===================================================================

#[test]
fn shadow_gate_events_serde_roundtrip() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    gate.evaluate_candidate(
        &contract,
        candidate_with_metrics(improved_metrics(), 90_000, 900),
        &governance_signing_key(),
    )
    .expect("pass");
    let events = gate.drain_events();
    let json = serde_json::to_string(&events).expect("serialize");
    let restored: Vec<frankenengine_engine::privacy_learning_contract::ShadowGateEvent> =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(events, restored);
}

// ===================================================================
// Rollback incident receipt serde
// ===================================================================

#[test]
fn rollback_receipt_serde_roundtrip() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(improved_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("pass");
    let receipt = gate
        .evaluate_post_deployment_metrics(&artifact, regressed_metrics(), &governance_signing_key())
        .expect("post deployment check")
        .expect("rollback");
    let json = serde_json::to_string(&receipt).expect("serialize");
    let restored: frankenengine_engine::privacy_learning_contract::ShadowRollbackIncidentReceipt =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, restored);
}

// ===================================================================
// Contract event serde
// ===================================================================

#[test]
fn contract_event_type_serde_roundtrip() {
    let mut registry = ContractRegistry::new();
    let contract = create_test_contract();
    registry
        .register(contract, &governance_vk(), "trace-1")
        .expect("register");
    let events = registry.drain_events();
    let json = serde_json::to_string(&events).expect("serialize");
    let restored: Vec<frankenengine_engine::privacy_learning_contract::ContractEvent> =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(events, restored);
}

// ===================================================================
// Schema functions determinism
// ===================================================================

#[test]
fn contract_schema_and_id_are_deterministic() {
    let s1 = contract_schema();
    let s2 = contract_schema();
    assert_eq!(s1, s2);

    let id1 = contract_schema_id();
    let id2 = contract_schema_id();
    assert_eq!(id1, id2);
}

// ===================================================================
// Contract preimage_bytes determinism
// ===================================================================

#[test]
fn contract_display_contains_key_fields() {
    let contract = create_test_contract();
    let display = contract.to_string();
    assert!(display.contains("PrivacyLearningContract"));
    assert!(display.contains(TEST_ZONE));
}

#[test]
fn contract_id_is_deterministic_across_identical_inputs() {
    let c1 = create_test_contract();
    let c2 = create_test_contract();
    assert_eq!(c1.contract_id, c2.contract_id);
    assert_eq!(c1.governance_signature, c2.governance_signature);
}

// ===================================================================
// Feature schema: backward compatibility edge cases
// ===================================================================

#[test]
fn feature_schema_backward_compatible_with_identical_schema() {
    let v1 = test_feature_schema();
    // A schema is trivially backward compatible with itself.
    assert!(v1.is_backward_compatible_with(&v1));
}

#[test]
fn feature_schema_version_3_without_prior_version_ok() {
    // Version 3 with no prior_version (initial contract at v3) is valid.
    let mut schema = test_feature_schema();
    schema.version = 3;
    schema.prior_version = None;
    schema.validate().expect("valid v3 without prior");
}

// ===================================================================
// Update policy: skip disabled with nonzero max_consecutive_skips
// ===================================================================

#[test]
fn update_policy_no_skip_nonzero_limit_ok() {
    let mut policy = test_update_policy();
    policy.allow_skip = false;
    policy.max_consecutive_skips = 5;
    policy
        .validate()
        .expect("valid when skips disabled regardless of limit");
}

// ===================================================================
// Clipping: per-coordinate requires per_field_bounds if provided
// ===================================================================

#[test]
fn clipping_strategy_per_coordinate_no_bounds_valid() {
    let clipping = ClippingStrategy {
        method: ClippingMethod::PerCoordinate,
        global_bound_millionths: 500_000,
        per_field_bounds: BTreeMap::new(),
    };
    clipping
        .validate(&test_feature_schema())
        .expect("valid without per-field");
}

// ===================================================================
// Aggregation: Shamir with valid threshold
// ===================================================================

#[test]
fn aggregation_shamir_threshold_equals_participants_ok() {
    let agg = SecureAggregationRequirements {
        min_participants: 5,
        dropout_tolerance_millionths: 200_000,
        secret_sharing_scheme: SecretSharingScheme::Shamir,
        sharing_threshold: Some(5),
        coordinator_trust_model: CoordinatorTrustModel::Malicious,
    };
    agg.validate().expect("threshold == participants ok");
}

// ===================================================================
// Randomness: snapshot on empty transcript
// ===================================================================

#[test]
fn randomness_empty_transcript_snapshot_summary_fails() {
    let mut transcript = RandomnessTranscript::new();
    let sk = governance_signing_key();
    let result = transcript.emit_snapshot_summary(&sk, "model-snap", "policy-snap");
    // Empty transcript has no commitments to snapshot — should fail.
    assert!(result.is_err());
}

#[test]
fn randomness_verify_snapshot_on_empty_transcript() {
    let transcript = RandomnessTranscript::new();
    let vk = governance_vk();
    // No summaries to verify — vacuously valid.
    transcript
        .verify_snapshot_summaries(&vk)
        .expect("empty transcript snapshot verification");
}

// ===================================================================
// Randomness: multi-commitment snapshot
// ===================================================================

#[test]
fn randomness_three_commitments_snapshot_verified() {
    let mut transcript = RandomnessTranscript::new();
    let sk = governance_signing_key();
    let vk = governance_vk();
    let epoch = SecurityEpoch::from_raw(20);

    for i in 0..3 {
        transcript
            .commit_seed(
                &sk,
                &format!("phase-{i}"),
                format!("seed-{i}").as_bytes(),
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(i as u8 + 0x60),
            )
            .expect("commitment");
    }

    transcript
        .emit_snapshot_summary(&sk, "model-3", "policy-3")
        .expect("snapshot");
    transcript.verify_chain(&vk).expect("chain valid");
    transcript
        .verify_snapshot_summaries(&vk)
        .expect("snapshot summary valid");
}

// ===================================================================
// Randomness replay: deterministic output across multiple phases
// ===================================================================

#[test]
fn randomness_replay_multiple_phases_deterministic() {
    let mut transcript = RandomnessTranscript::new();
    let sk = governance_signing_key();
    let vk = governance_vk();
    let epoch = SecurityEpoch::from_raw(25);

    let phases = ["noise-phase", "dropout-phase"];
    let seeds: [&[u8]; 2] = [b"noise-seed-data", b"dropout-seed-data"];

    for (phase, seed) in phases.iter().zip(seeds.iter()) {
        transcript
            .commit_seed(
                &sk,
                phase,
                seed,
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x70),
            )
            .expect("commit");
    }
    transcript
        .emit_snapshot_summary(&sk, "model-multi", "policy-multi")
        .expect("snapshot");

    let mut auditors = BTreeSet::new();
    auditors.insert("audit-bot".to_string());

    let mut records_a: Vec<_> = phases
        .iter()
        .zip(seeds.iter())
        .map(|(phase, seed)| {
            SeedEscrowRecord::create(phase, epoch, seed, auditors.clone()).expect("escrow")
        })
        .collect();
    let mut records_b: Vec<_> = phases
        .iter()
        .zip(seeds.iter())
        .map(|(phase, seed)| {
            SeedEscrowRecord::create(phase, epoch, seed, auditors.clone()).expect("escrow")
        })
        .collect();

    let out_a = transcript
        .replay_with_escrowed_seeds(&vk, &mut records_a, "audit-bot", 8)
        .expect("replay A");
    let out_b = transcript
        .replay_with_escrowed_seeds(&vk, &mut records_b, "audit-bot", 8)
        .expect("replay B");

    assert_eq!(out_a, out_b);
    assert_eq!(out_a.len(), 2);
    for output in &out_a {
        assert_eq!(output.outputs.len(), 8);
    }
}

// ===================================================================
// Registry: multi-zone with epoch upgrades
// ===================================================================

#[test]
fn registry_multi_zone_independent_epoch_tracking() {
    let mut registry = ContractRegistry::new();

    // Zone 1 at epoch 1.
    let contract1 = create_test_contract();
    registry
        .register(contract1, &governance_vk(), "t-1")
        .expect("zone1 epoch1");

    // Zone 2 at epoch 1.
    let mut input2 = test_contract_input();
    input2.zone = "zone-two";
    let contract2 =
        PrivacyLearningContract::create_signed(&governance_signing_key(), input2).unwrap();
    registry
        .register(contract2, &governance_vk(), "t-2")
        .expect("zone2 epoch1");

    assert_eq!(registry.zone_count(), 2);

    // Upgrade zone 1 to epoch 2 — should not affect zone 2.
    let mut input1_v2 = test_contract_input();
    input1_v2.epoch = SecurityEpoch::from_raw(2);
    let contract1_v2 =
        PrivacyLearningContract::create_signed(&governance_signing_key(), input1_v2).unwrap();
    registry
        .register(contract1_v2, &governance_vk(), "t-3")
        .expect("zone1 epoch2");

    assert_eq!(registry.zone_count(), 2);
    // total_count includes both old and new contracts (register does not
    // remove superseded contracts from the map).
    assert_eq!(registry.total_count(), 3);

    let z1 = registry.active_for_zone(TEST_ZONE).unwrap();
    assert_eq!(z1.epoch, SecurityEpoch::from_raw(2));

    let z2 = registry.active_for_zone("zone-two").unwrap();
    assert_eq!(z2.epoch, SecurityEpoch::from_raw(1));
}

// ===================================================================
// Shadow gate: metric assessments are populated for all metrics
// ===================================================================

#[test]
fn shadow_gate_populates_all_metric_assessments() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(improved_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("pass");

    assert_eq!(artifact.metric_assessments.len(), SafetyMetric::ALL.len());
    for metric in SafetyMetric::ALL {
        let assessment = artifact.metric_assessments.get(metric).expect("present");
        // Improved metrics should show positive improvement.
        assert!(assessment.improvement_millionths > 0);
        assert!(assessment.significant_improvement || assessment.improvement_millionths > 0);
        assert!(!assessment.regressed);
    }
}

// ===================================================================
// Shadow rollback incident receipt: reason contains metric names
// ===================================================================

#[test]
fn rollback_receipt_reason_contains_regressed_metric_names() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(improved_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("pass");
    let receipt = gate
        .evaluate_post_deployment_metrics(&artifact, regressed_metrics(), &governance_signing_key())
        .expect("check")
        .expect("rollback");

    assert!(receipt.reason.contains("automatic rollback"));
    for metric in &receipt.triggered_regressions {
        assert!(receipt.reason.contains(&metric.to_string()));
    }
}

// ===================================================================
// Contract: authorized_participants boundary checks
// ===================================================================

#[test]
fn contract_is_authorized_boundary() {
    let contract = create_test_contract();
    // Known participants.
    assert!(contract.is_authorized(&EngineObjectId([0xAA; 32])));
    assert!(contract.is_authorized(&EngineObjectId([0xBB; 32])));
    assert!(contract.is_authorized(&EngineObjectId([0xCC; 32])));
    // Unknown.
    assert!(!contract.is_authorized(&EngineObjectId([0x00; 32])));
    assert!(!contract.is_authorized(&EngineObjectId([0xFF; 32])));
}

// ===================================================================
// Shadow gate: budget exactly at limit passes
// ===================================================================

#[test]
fn shadow_gate_budget_exactly_at_limit_passes() {
    let contract = create_test_contract();
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(
                improved_metrics(),
                contract.dp_budget.epsilon_per_epoch_millionths,
                contract.dp_budget.delta_per_epoch_millionths,
            ),
            &governance_signing_key(),
        )
        .expect("evaluate");
    // Budget at exact limit should be within budget.
    assert!(artifact.privacy_budget_status.within_budget);
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
}

// ===================================================================
// Feature field type display
// ===================================================================

#[test]
fn feature_field_type_serde_roundtrip() {
    for fft in [
        FeatureFieldType::FixedPoint,
        FeatureFieldType::Counter,
        FeatureFieldType::Boolean,
        FeatureFieldType::Categorical,
    ] {
        let json = serde_json::to_string(&fft).expect("serialize");
        let restored: FeatureFieldType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(fft, restored);
    }
}

// ===================================================================
// Full end-to-end: create → register → evaluate → promote → rollback
// ===================================================================

#[test]
fn end_to_end_contract_lifecycle() {
    // 1. Create and register contract.
    let mut registry = ContractRegistry::new();
    let contract = create_test_contract();
    let contract_id = registry
        .register(contract.clone(), &governance_vk(), "trace-e2e")
        .expect("register");
    assert!(registry.get(&contract_id).is_some());

    // 2. Shadow gate: evaluate improved candidate → pass.
    let mut gate = shadow_gate();
    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate_with_metrics(improved_metrics(), 90_000, 900),
            &governance_signing_key(),
        )
        .expect("evaluate");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
    assert!(gate.active_artifact(&artifact.policy_id).is_some());

    // 3. Post-deployment: no regression.
    let no_rollback = gate
        .evaluate_post_deployment_metrics(&artifact, improved_metrics(), &governance_signing_key())
        .expect("post-deploy check");
    assert!(no_rollback.is_none());

    // 4. Post-deployment: regression triggers rollback.
    let rollback = gate
        .evaluate_post_deployment_metrics(&artifact, regressed_metrics(), &governance_signing_key())
        .expect("post-deploy regression check")
        .expect("rollback");
    assert_eq!(rollback.policy_id, artifact.policy_id);
    assert!(gate.active_artifact(&artifact.policy_id).is_none());

    // 5. Registry: revoke contract.
    registry
        .revoke(&contract_id, "trace-revoke")
        .expect("revoke");
    assert!(registry.active_for_zone(TEST_ZONE).is_none());

    // 6. Verify all events recorded.
    let registry_events = registry.drain_events();
    assert!(registry_events.len() >= 2); // register + revoke
    let gate_events = gate.drain_events();
    assert!(gate_events.len() >= 3); // evaluate + post-deploy pass + rollback
}
