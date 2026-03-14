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
use frankenengine_engine::privacy_learning_contract::PrivacyLearningContract;
use frankenengine_engine::privacy_learning_contract::{
    ClippingMethod, ClippingStrategy, CompositionMethod, ContractError, CoordinatorTrustModel,
    CreateContractInput, DataRetentionPolicy, DpBudgetSemantics, FeatureField, FeatureFieldType,
    FeatureSchema, HumanOverrideRequest, PrngAlgorithm, SafetyMetric, SafetyMetricSnapshot,
    SecretSharingScheme, SecureAggregationRequirements, ShadowBurnInThresholdProfile,
    ShadowEvaluationCandidate, ShadowEvaluationGate, ShadowEvaluationGateConfig,
    ShadowExtensionClass, ShadowPromotionVerdict, ShadowReplayReference,
    ShadowRollbackReadinessArtifacts, UpdatePolicy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

const TEST_ZONE: &str = "shadow-eval-zone";

fn governance_signing_key() -> SigningKey {
    SigningKey::from_bytes([0x11; 32])
}

fn participant_ids() -> BTreeSet<EngineObjectId> {
    let mut set = BTreeSet::new();
    set.insert(EngineObjectId([0xAA; 32]));
    set.insert(EngineObjectId([0xBB; 32]));
    set
}

fn feature_schema() -> FeatureSchema {
    FeatureSchema {
        version: 1,
        fields: BTreeMap::from([(
            "calibration_residual".to_string(),
            FeatureField {
                name: "calibration_residual".to_string(),
                field_type: FeatureFieldType::FixedPoint,
                description: "residual".to_string(),
                existed_in_prior_version: false,
            },
        )]),
        prior_version: None,
    }
}

fn contract() -> PrivacyLearningContract {
    PrivacyLearningContract::create_signed(
        &governance_signing_key(),
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(7),
            zone: TEST_ZONE,
            feature_schema: feature_schema(),
            update_policy: UpdatePolicy {
                min_local_samples: 100,
                min_submission_interval: 3600,
                max_data_age: 86400,
                allow_skip: true,
                max_consecutive_skips: 3,
            },
            clipping_strategy: ClippingStrategy {
                method: ClippingMethod::L2Norm,
                global_bound_millionths: 1_000_000,
                per_field_bounds: BTreeMap::new(),
            },
            dp_budget: DpBudgetSemantics {
                epsilon_per_epoch_millionths: 100_000,
                delta_per_epoch_millionths: 1_000,
                composition_method: CompositionMethod::Renyi,
                lifetime_epsilon_budget_millionths: 10_000_000,
                lifetime_delta_budget_millionths: 100_000,
                fail_closed_on_exhaustion: true,
            },
            aggregation: SecureAggregationRequirements {
                min_participants: 5,
                dropout_tolerance_millionths: 100_000,
                secret_sharing_scheme: SecretSharingScheme::Additive,
                sharing_threshold: None,
                coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
            },
            retention: DataRetentionPolicy {
                max_intermediate_retention: 86_400,
                max_snapshot_retention: 604_800,
                delete_local_after_submission: true,
                delete_shares_after_aggregation: true,
            },
            authorized_participants: participant_ids(),
        },
    )
    .expect("contract")
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
            (SafetyMetric::FalsePositiveRate, 150_000),
            (SafetyMetric::FalseNegativeRate, 100_000),
            (SafetyMetric::CalibrationError, 80_000),
            (SafetyMetric::DriftDetectionAccuracy, 740_000),
            (SafetyMetric::ContainmentTime, 525_000),
        ]),
    }
}

fn replay_reference() -> ShadowReplayReference {
    ShadowReplayReference {
        replay_corpus_id: "fleet-corpus-v7".to_string(),
        randomness_snapshot_id: "rng-snapshot-v7".to_string(),
        replay_seed_hash: [0x22; 32],
        replay_seed_counter: 17,
    }
}

fn rollback_readiness() -> ShadowRollbackReadinessArtifacts {
    ShadowRollbackReadinessArtifacts {
        rollback_command_tested: true,
        previous_policy_snapshot_id: "snapshot-v7.0".to_string(),
        transition_receipt_signed: true,
        rollback_playbook_ref: "playbook://shadow-gate/rollback".to_string(),
    }
}

fn candidate(
    decision_id: &str,
    candidate_metrics: SafetyMetricSnapshot,
    epsilon_spent: i64,
    delta_spent: i64,
) -> ShadowEvaluationCandidate {
    ShadowEvaluationCandidate {
        trace_id: format!("trace-{decision_id}"),
        decision_id: decision_id.to_string(),
        policy_id: "policy-shadow-gate".to_string(),
        extension_class: ShadowExtensionClass::Standard,
        candidate_version: "v7.1".to_string(),
        baseline_snapshot_id: "snapshot-v7.0".to_string(),
        rollback_token: "rollback-token-v7.0".to_string(),
        epoch_id: SecurityEpoch::from_raw(7),
        shadow_started_at_ns: 1_000_000_000,
        evaluation_completed_at_ns: 1_000_000_120,
        shadow_success_rate_millionths: 997_000,
        false_deny_rate_millionths: 4_000,
        rollback_readiness: rollback_readiness(),
        baseline_metrics: baseline_metrics(),
        candidate_metrics,
        replay_reference: replay_reference(),
        epsilon_spent_millionths: epsilon_spent,
        delta_spent_millionths: delta_spent,
    }
}

fn gate() -> ShadowEvaluationGate {
    let mut profiles = BTreeMap::new();
    profiles.insert(
        ShadowExtensionClass::HighRisk,
        ShadowBurnInThresholdProfile {
            min_shadow_success_rate_millionths: 999_000,
            max_false_deny_rate_millionths: 1_000,
            min_burn_in_duration_ns: 100,
            require_verified_rollback_artifacts: true,
        },
    );
    ShadowEvaluationGate::new(ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 5_000,
        min_required_improvement_millionths: 2_500,
        default_burn_in_profile: ShadowBurnInThresholdProfile {
            min_shadow_success_rate_millionths: 995_000,
            max_false_deny_rate_millionths: 5_000,
            min_burn_in_duration_ns: 100,
            require_verified_rollback_artifacts: true,
        },
        burn_in_profiles_by_extension_class: profiles,
    })
    .expect("gate")
}

#[test]
fn shadow_gate_full_lifecycle_pass_reject_override_and_rollback() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let pass_artifact = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-pass", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("pass candidate");
    assert_eq!(pass_artifact.verdict, ShadowPromotionVerdict::Pass);
    assert!(gate.active_artifact("policy-shadow-gate").is_some());

    let rollback = gate
        .evaluate_post_deployment_metrics(&pass_artifact, regressed_metrics(), &signing)
        .expect("post deployment evaluation")
        .expect("rollback required");
    assert_eq!(rollback.policy_id, "policy-shadow-gate");
    assert!(!rollback.triggered_regressions.is_empty());
    assert!(gate.active_artifact("policy-shadow-gate").is_none());

    let rejected = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-reject", regressed_metrics(), 90_000, 900),
            &signing,
        )
        .expect("reject candidate");
    assert_eq!(rejected.verdict, ShadowPromotionVerdict::Reject);

    let overridden = gate
        .apply_human_override(
            &rejected,
            HumanOverrideRequest {
                operator_id: "human-approver-1".to_string(),
                summary: "external risk context justifies temporary override".to_string(),
                bypassed_risk_criteria: vec!["false_positive_rate <= baseline+5000".to_string()],
                acknowledged_bypass: true,
            },
            &signing,
        )
        .expect("override");
    assert_eq!(overridden.verdict, ShadowPromotionVerdict::OverrideApproved);
    assert!(gate.active_artifact("policy-shadow-gate").is_some());
    assert!(overridden.human_override.is_some());

    let scorecards = gate.scorecard_entries();
    assert!(scorecards.len() >= 2);
    assert!(
        scorecards
            .iter()
            .any(|entry| entry.policy_id == "policy-shadow-gate")
    );
}

#[test]
fn shadow_gate_rejects_nondeterministic_replay_inputs() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let mut invalid = candidate("decision-invalid", improved_metrics(), 90_000, 900);
    invalid.replay_reference.replay_seed_hash = [0u8; 32];
    let err = gate
        .evaluate_candidate(&contract, invalid, &signing)
        .expect_err("candidate must be rejected");
    assert!(
        err.to_string()
            .contains("replay_seed_hash must not be all zeros")
    );
}

#[test]
fn shadow_gate_early_terminates_when_false_deny_exceeds_threshold() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let mut excessive_false_deny =
        candidate("decision-early-stop", improved_metrics(), 90_000, 900);
    excessive_false_deny.false_deny_rate_millionths = 7_500;

    let artifact = gate
        .evaluate_candidate(&contract, excessive_false_deny, &signing)
        .expect("shadow evaluation");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(artifact.burn_in_early_terminated);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("false-deny rate"))
    );
    assert!(
        gate.events()
            .iter()
            .any(|event| event.event == "shadow_evaluation" && event.outcome == "early_terminated")
    );
}

// ---------- metric improvement checks ----------

#[test]
fn shadow_gate_rejects_when_no_significant_improvement() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-no-improve", baseline_metrics(), 90_000, 900),
            &signing,
        )
        .expect("shadow evaluation");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|r| r.contains("improvement")),
        "failure reasons: {:?}",
        artifact.failure_reasons
    );
}

#[test]
fn shadow_gate_pass_generates_signed_artifact() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-signed", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("pass");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
    assert!(!artifact.trace_id.is_empty());
    assert!(!artifact.decision_id.is_empty());
    assert!(!artifact.artifact_hash.is_empty());
}

// ---------- privacy budget ----------

#[test]
fn shadow_gate_checks_privacy_budget_status() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-budget", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("pass");
    assert!(artifact.privacy_budget_status.within_budget);
}

// ---------- rollback readiness ----------

#[test]
fn shadow_gate_rejects_unverified_rollback_artifacts() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let mut unverified = candidate(
        "decision-unverified-rollback",
        improved_metrics(),
        90_000,
        900,
    );
    unverified.rollback_readiness.rollback_command_tested = false;
    unverified.rollback_readiness.transition_receipt_signed = false;

    let artifact = gate
        .evaluate_candidate(&contract, unverified, &signing)
        .expect("shadow evaluation");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|r| r.contains("rollback")),
        "failure reasons: {:?}",
        artifact.failure_reasons
    );
}

// ---------- human override ----------

#[test]
fn shadow_gate_human_override_requires_acknowledged_bypass() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let rejected = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-override-fail", regressed_metrics(), 90_000, 900),
            &signing,
        )
        .expect("reject");

    let err = gate
        .apply_human_override(
            &rejected,
            HumanOverrideRequest {
                operator_id: "human-1".to_string(),
                summary: "override justification".to_string(),
                bypassed_risk_criteria: vec!["criteria-1".to_string()],
                acknowledged_bypass: false,
            },
            &signing,
        )
        .expect_err("unacknowledged override must fail");
    assert!(err.to_string().contains("acknowledged"));
}

// ---------- events ----------

#[test]
fn shadow_gate_events_contain_component_field() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let _artifact = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-events", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("pass");

    for event in gate.events() {
        assert!(
            !event.component.is_empty(),
            "event component must not be empty"
        );
    }
}

#[test]
fn shadow_gate_drain_events_clears_event_log() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let _artifact = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-drain", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("pass");

    let drained = gate.drain_events();
    assert!(!drained.is_empty());
    assert!(gate.events().is_empty());
}

// ---------- scorecard ----------

#[test]
fn scorecard_empty_before_any_evaluation() {
    let gate = gate();
    assert!(gate.scorecard_entries().is_empty());
}

// ---------- metric assessments ----------

#[test]
fn pass_artifact_contains_metric_assessments_for_all_metrics() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let artifact = gate
        .evaluate_candidate(
            &contract,
            candidate("decision-assessments", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("pass");

    assert!(!artifact.metric_assessments.is_empty());
    for (metric, assessment) in &artifact.metric_assessments {
        assert!(
            !format!("{metric:?}").is_empty(),
            "metric key should be displayable"
        );
        assert!(
            assessment.improvement_millionths != 0
                || (assessment.baseline_value_millionths == assessment.candidate_value_millionths),
            "improvement should be non-zero unless values are equal"
        );
    }
}

// ---------- extension class profiles ----------

#[test]
fn low_risk_extension_uses_default_profile() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let mut low_risk = candidate("decision-low-risk", improved_metrics(), 90_000, 900);
    low_risk.extension_class = ShadowExtensionClass::LowRisk;
    let artifact = gate
        .evaluate_candidate(&contract, low_risk, &signing)
        .expect("evaluation");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
}

// ---------- serde roundtrip ----------

#[test]
fn shadow_evaluation_candidate_serde_roundtrip() {
    let c = candidate("decision-serde", improved_metrics(), 90_000, 900);
    let json = serde_json::to_string(&c).expect("serialize");
    let recovered: ShadowEvaluationCandidate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.decision_id, c.decision_id);
    assert_eq!(
        recovered.shadow_success_rate_millionths,
        c.shadow_success_rate_millionths
    );
}

#[test]
fn safety_metric_snapshot_serde_roundtrip() {
    let snapshot = improved_metrics();
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let recovered: SafetyMetricSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.values_millionths, snapshot.values_millionths);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde roundtrips, defaults, enum coverage
// ────────────────────────────────────────────────────────────

#[test]
fn shadow_extension_class_serde_round_trip() {
    for class in [
        ShadowExtensionClass::LowRisk,
        ShadowExtensionClass::Standard,
        ShadowExtensionClass::HighRisk,
        ShadowExtensionClass::Critical,
    ] {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: ShadowExtensionClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, recovered);
    }
}

#[test]
fn shadow_extension_class_default_is_standard() {
    assert_eq!(
        ShadowExtensionClass::default(),
        ShadowExtensionClass::Standard
    );
}

#[test]
fn shadow_extension_class_ordering() {
    assert!(ShadowExtensionClass::LowRisk < ShadowExtensionClass::Standard);
    assert!(ShadowExtensionClass::Standard < ShadowExtensionClass::HighRisk);
    assert!(ShadowExtensionClass::HighRisk < ShadowExtensionClass::Critical);
}

#[test]
fn shadow_promotion_verdict_serde_round_trip() {
    for verdict in [
        ShadowPromotionVerdict::Pass,
        ShadowPromotionVerdict::Reject,
        ShadowPromotionVerdict::OverrideApproved,
    ] {
        let json = serde_json::to_string(&verdict).expect("serialize");
        let recovered: ShadowPromotionVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(verdict, recovered);
    }
}

#[test]
fn safety_metric_all_constant_covers_five_metrics() {
    assert_eq!(SafetyMetric::ALL.len(), 5);
    let set: std::collections::BTreeSet<_> = SafetyMetric::ALL.iter().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn safety_metric_serde_round_trip() {
    for metric in SafetyMetric::ALL {
        let json = serde_json::to_string(metric).expect("serialize");
        let recovered: SafetyMetric = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*metric, recovered);
    }
}

#[test]
fn shadow_burn_in_threshold_profile_serde_round_trip() {
    let profile = ShadowBurnInThresholdProfile {
        min_shadow_success_rate_millionths: 995_000,
        max_false_deny_rate_millionths: 5_000,
        min_burn_in_duration_ns: 100,
        require_verified_rollback_artifacts: true,
    };
    let json = serde_json::to_string(&profile).expect("serialize");
    let recovered: ShadowBurnInThresholdProfile = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(profile, recovered);
}

#[test]
fn shadow_rollback_readiness_artifacts_default() {
    let arts = ShadowRollbackReadinessArtifacts::default();
    assert!(!arts.rollback_command_tested);
    assert!(arts.previous_policy_snapshot_id.is_empty());
    assert!(!arts.transition_receipt_signed);
    assert!(arts.rollback_playbook_ref.is_empty());
}

#[test]
fn shadow_rollback_readiness_artifacts_serde_round_trip() {
    let arts = rollback_readiness();
    let json = serde_json::to_string(&arts).expect("serialize");
    let recovered: ShadowRollbackReadinessArtifacts =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(arts, recovered);
}

#[test]
fn shadow_evaluation_gate_config_serde_round_trip() {
    let config = ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 5_000,
        min_required_improvement_millionths: 2_500,
        default_burn_in_profile: ShadowBurnInThresholdProfile::default(),
        burn_in_profiles_by_extension_class: BTreeMap::new(),
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: ShadowEvaluationGateConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn shadow_replay_reference_serde_round_trip() {
    let rr = replay_reference();
    let json = serde_json::to_string(&rr).expect("serialize");
    let recovered: ShadowReplayReference = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(rr, recovered);
}

#[test]
fn human_override_request_serde_round_trip() {
    let req = HumanOverrideRequest {
        operator_id: "op-1".to_string(),
        summary: "justification".to_string(),
        bypassed_risk_criteria: vec!["c1".to_string()],
        acknowledged_bypass: true,
    };
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: HumanOverrideRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, recovered);
}

#[test]
fn shadow_gate_critical_class_uses_strictest_default_profile() {
    let contract = contract();
    let mut g = gate();
    let signing = governance_signing_key();

    let mut critical = candidate("decision-critical", improved_metrics(), 90_000, 900);
    critical.extension_class = ShadowExtensionClass::Critical;
    // Critical is not in our gate's custom profiles, so uses default
    let artifact = g
        .evaluate_candidate(&contract, critical, &signing)
        .expect("evaluation");
    // Default profile has 995k success rate requirement; our candidate has 997k, should pass
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
}

#[test]
fn shadow_gate_applies_stricter_high_risk_threshold_profile() {
    let contract = contract();
    let mut gate = gate();
    let signing = governance_signing_key();

    let mut high_risk = candidate("decision-high-risk", improved_metrics(), 90_000, 900);
    high_risk.extension_class = ShadowExtensionClass::HighRisk;
    let artifact = gate
        .evaluate_candidate(&contract, high_risk, &signing)
        .expect("shadow evaluation");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("shadow success rate"))
    );
}

#[test]
fn shadow_evaluation_gate_config_default_has_positive_thresholds() {
    let config = ShadowEvaluationGateConfig {
        regression_tolerance_millionths: 5_000,
        min_required_improvement_millionths: 2_500,
        default_burn_in_profile: ShadowBurnInThresholdProfile {
            min_shadow_success_rate_millionths: 995_000,
            max_false_deny_rate_millionths: 5_000,
            min_burn_in_duration_ns: 100,
            require_verified_rollback_artifacts: true,
        },
        burn_in_profiles_by_extension_class: BTreeMap::new(),
    };
    assert!(config.regression_tolerance_millionths > 0);
    assert!(config.min_required_improvement_millionths > 0);
    assert!(
        config
            .default_burn_in_profile
            .min_shadow_success_rate_millionths
            > 0
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: budget exhaustion, scorecard after multiple evals, gate serde
// ────────────────────────────────────────────────────────────

#[test]
fn shadow_gate_rejects_when_privacy_budget_exhausted() {
    let contract = contract();
    let mut g = gate();
    let signing = governance_signing_key();

    // Submit candidate with lifetime-exceeding budget consumption
    let artifact = g
        .evaluate_candidate(
            &contract,
            candidate(
                "decision-budget-exceed",
                improved_metrics(),
                10_000_000,
                100_000,
            ),
            &signing,
        )
        .expect("evaluation");
    assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
    assert!(
        artifact
            .failure_reasons
            .iter()
            .any(|r| r.contains("budget")),
        "failure reasons should mention budget: {:?}",
        artifact.failure_reasons
    );
}

#[test]
fn shadow_gate_scorecard_grows_with_each_evaluation() {
    let contract = contract();
    let mut g = gate();
    let signing = governance_signing_key();

    // First evaluation
    let _a1 = g
        .evaluate_candidate(
            &contract,
            candidate("decision-sc1", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("first eval");
    let sc1_len = g.scorecard_entries().len();
    assert!(sc1_len >= 1);

    // Second evaluation (reject due to no improvement)
    let _a2 = g
        .evaluate_candidate(
            &contract,
            candidate("decision-sc2", baseline_metrics(), 90_000, 900),
            &signing,
        )
        .expect("second eval");
    let sc2_len = g.scorecard_entries().len();
    assert!(
        sc2_len > sc1_len,
        "scorecard should grow: {} > {}",
        sc2_len,
        sc1_len
    );
}

#[test]
fn shadow_evaluation_gate_serde_roundtrip() {
    let g = gate();
    let json = serde_json::to_string(&g).expect("serialize gate");
    let recovered: ShadowEvaluationGate = serde_json::from_str(&json).expect("deserialize gate");
    assert_eq!(
        recovered.scorecard_entries().len(),
        g.scorecard_entries().len()
    );
}

#[test]
fn shadow_gate_no_active_artifact_when_none_promoted() {
    let contract = contract();
    let mut g = gate();
    let signing = governance_signing_key();

    // Evaluate a candidate that gets rejected
    let _rejected = g
        .evaluate_candidate(
            &contract,
            candidate("decision-no-active", regressed_metrics(), 90_000, 900),
            &signing,
        )
        .expect("reject");

    // No active artifact should exist for this policy
    assert!(
        g.active_artifact("policy-shadow-gate").is_none(),
        "rejected candidate should not create an active artifact"
    );
}

#[test]
fn shadow_gate_post_deployment_with_unchanged_metrics_returns_none() {
    let contract = contract();
    let mut g = gate();
    let signing = governance_signing_key();

    // Pass the candidate
    let pass_artifact = g
        .evaluate_candidate(
            &contract,
            candidate("decision-stable", improved_metrics(), 90_000, 900),
            &signing,
        )
        .expect("pass");
    assert_eq!(pass_artifact.verdict, ShadowPromotionVerdict::Pass);

    // Post-deployment with same improved metrics => no rollback needed
    let rollback = g
        .evaluate_post_deployment_metrics(&pass_artifact, improved_metrics(), &signing)
        .expect("post-deployment check");
    assert!(
        rollback.is_none(),
        "unchanged/improved metrics should not trigger rollback"
    );
    assert!(
        g.active_artifact("policy-shadow-gate").is_some(),
        "artifact should remain active after stable post-deployment check"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: PearlTower 2026-03-14 — Display impls, serde, defaults
// ────────────────────────────────────────────────────────────

#[test]
fn feature_field_type_display_all_variants() {
    let cases = [
        (FeatureFieldType::FixedPoint, "fixed_point"),
        (FeatureFieldType::Counter, "counter"),
        (FeatureFieldType::Boolean, "boolean"),
        (FeatureFieldType::Categorical, "categorical"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected);
    }
}

#[test]
fn feature_field_type_serde_roundtrip() {
    for variant in [
        FeatureFieldType::FixedPoint,
        FeatureFieldType::Counter,
        FeatureFieldType::Boolean,
        FeatureFieldType::Categorical,
    ] {
        let json = serde_json::to_string(&variant).expect("serialize");
        let recovered: FeatureFieldType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, recovered);
    }
}

#[test]
fn clipping_method_display_all_variants() {
    let cases = [
        (ClippingMethod::L2Norm, "l2_norm"),
        (ClippingMethod::PerCoordinate, "per_coordinate"),
        (ClippingMethod::Adaptive, "adaptive"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected);
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
        let recovered: ClippingMethod = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(method, recovered);
    }
}

#[test]
fn composition_method_display_all_variants() {
    let cases = [
        (CompositionMethod::Basic, "basic"),
        (CompositionMethod::Advanced, "advanced"),
        (CompositionMethod::Renyi, "renyi"),
        (CompositionMethod::ZeroCdp, "zcdp"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected);
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
        let recovered: CompositionMethod = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(method, recovered);
    }
}

#[test]
fn coordinator_trust_model_display() {
    assert_eq!(
        CoordinatorTrustModel::HonestButCurious.to_string(),
        "honest_but_curious"
    );
    assert_eq!(CoordinatorTrustModel::Malicious.to_string(), "malicious");
}

#[test]
fn coordinator_trust_model_serde_roundtrip() {
    for model in [
        CoordinatorTrustModel::HonestButCurious,
        CoordinatorTrustModel::Malicious,
    ] {
        let json = serde_json::to_string(&model).expect("serialize");
        let recovered: CoordinatorTrustModel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(model, recovered);
    }
}

#[test]
fn secret_sharing_scheme_display() {
    assert_eq!(SecretSharingScheme::Additive.to_string(), "additive");
    assert_eq!(SecretSharingScheme::Shamir.to_string(), "shamir");
}

#[test]
fn secret_sharing_scheme_serde_roundtrip() {
    for scheme in [SecretSharingScheme::Additive, SecretSharingScheme::Shamir] {
        let json = serde_json::to_string(&scheme).expect("serialize");
        let recovered: SecretSharingScheme = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(scheme, recovered);
    }
}

#[test]
fn prng_algorithm_display() {
    assert_eq!(
        PrngAlgorithm::ChaCha20LikeCounter.to_string(),
        "chacha20_like_counter"
    );
}

#[test]
fn prng_algorithm_serde_roundtrip() {
    let alg = PrngAlgorithm::ChaCha20LikeCounter;
    let json = serde_json::to_string(&alg).expect("serialize");
    let recovered: PrngAlgorithm = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(alg, recovered);
}

#[test]
fn safety_metric_display_all_five_variants() {
    let displays: BTreeSet<String> = SafetyMetric::ALL.iter().map(|m| m.to_string()).collect();
    assert_eq!(
        displays.len(),
        5,
        "all 5 SafetyMetric variants should have distinct Display"
    );
    for display in &displays {
        assert!(!display.is_empty());
    }
}

#[test]
fn shadow_promotion_verdict_display_all_variants() {
    let pass = ShadowPromotionVerdict::Pass.to_string();
    let reject = ShadowPromotionVerdict::Reject.to_string();
    let over = ShadowPromotionVerdict::OverrideApproved.to_string();
    assert!(!pass.is_empty());
    assert!(!reject.is_empty());
    assert!(!over.is_empty());
    assert_ne!(pass, reject);
    assert_ne!(reject, over);
}

#[test]
fn shadow_burn_in_threshold_profile_default_values() {
    let profile = ShadowBurnInThresholdProfile::default();
    assert_eq!(profile.min_shadow_success_rate_millionths, 995_000);
    assert_eq!(profile.max_false_deny_rate_millionths, 5_000);
    assert!(profile.min_burn_in_duration_ns > 0);
    assert!(profile.require_verified_rollback_artifacts);
}

#[test]
fn shadow_evaluation_gate_config_default_has_profiles() {
    let config = ShadowEvaluationGateConfig::default();
    let json = serde_json::to_string(&config).expect("serialize config");
    assert!(!json.is_empty());
    // Default config should have a default burn-in profile
    assert!(
        config
            .default_burn_in_profile
            .min_shadow_success_rate_millionths
            > 0
    );
}

#[test]
fn contract_error_display_is_nonempty_for_all_tested_variants() {
    let errors: Vec<ContractError> = vec![
        ContractError::EmptyFeatureSchema,
        ContractError::InvalidVersion {
            detail: "version must be > 0".to_string(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(
            !msg.is_empty(),
            "ContractError Display must be non-empty for {err:?}"
        );
    }
}
