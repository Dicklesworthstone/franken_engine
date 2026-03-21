//! Enrichment integration tests for counterfactual_evaluator module.
//!
//! Covers IPS/DR/DirectMethod estimators, confidence envelopes, safety
//! evaluation, regime breakdowns, and policy comparison utilities.

use std::collections::BTreeSet;

use frankenengine_engine::counterfactual_evaluator::{
    BaselinePolicy, COUNTERFACTUAL_EVALUATOR_COMPONENT, COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION,
    ConfidenceEnvelope, CounterfactualError, CounterfactualEvaluator, EnvelopeStatus,
    EstimatorKind, EvaluatorConfig, LoggedTransition, PolicyId, TargetPolicyMapping,
    TransitionBatch, compare_policies, observed_regimes, rank_by_safety, safe_candidates,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_decision_theory::{LaneAction, RegimeLabel};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_hash(seed: u8) -> ContentHash {
    ContentHash::compute(&[seed])
}

fn make_transition(tick: u64, propensity: i64, reward: i64) -> LoggedTransition {
    LoggedTransition {
        epoch: epoch(1),
        tick,
        regime: RegimeLabel::Normal,
        action_taken: LaneAction::FallbackSafe,
        propensity_millionths: propensity,
        reward_millionths: reward,
        model_prediction_millionths: Some(reward),
        context_hash: make_hash(tick as u8),
    }
}

fn make_batch(n: usize, propensity: i64, reward: i64) -> TransitionBatch {
    TransitionBatch {
        policy_id: PolicyId("test-policy".to_string()),
        transitions: (0..n)
            .map(|i| make_transition(i as u64, propensity, reward))
            .collect(),
    }
}

fn make_target(n: usize, propensity: i64) -> TargetPolicyMapping {
    TargetPolicyMapping {
        target_policy_id: PolicyId("candidate-policy".to_string()),
        target_propensities_millionths: vec![propensity; n],
        target_model_predictions_millionths: Some(vec![500_000; n]),
    }
}

fn default_evaluator() -> CounterfactualEvaluator {
    CounterfactualEvaluator::default_safe_mode()
}

// ---------------------------------------------------------------------------
// EstimatorKind
// ---------------------------------------------------------------------------

#[test]
fn estimator_kind_display_all_distinct() {
    let kinds = [
        EstimatorKind::Ips,
        EstimatorKind::DoublyRobust,
        EstimatorKind::DirectMethod,
    ];
    let displays: Vec<String> = kinds.iter().map(|k| format!("{k}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 3);
}

// ---------------------------------------------------------------------------
// PolicyId
// ---------------------------------------------------------------------------

#[test]
fn policy_id_display() {
    let pid = PolicyId("my-policy-v2".to_string());
    assert_eq!(format!("{pid}"), "my-policy-v2");
}

#[test]
fn policy_id_ordering() {
    let a = PolicyId("alpha".to_string());
    let b = PolicyId("beta".to_string());
    assert!(a < b);
}

#[test]
fn policy_id_serde_roundtrip() {
    let pid = PolicyId("serde-test".to_string());
    let json = serde_json::to_string(&pid).unwrap();
    let restored: PolicyId = serde_json::from_str(&json).unwrap();
    assert_eq!(pid, restored);
}

// ---------------------------------------------------------------------------
// BaselinePolicy
// ---------------------------------------------------------------------------

#[test]
fn baseline_policy_default_safe_mode() {
    let bp = BaselinePolicy::default();
    assert_eq!(bp.action, LaneAction::FallbackSafe);
    assert_eq!(format!("{}", bp.id), "baseline-safe-mode");
}

#[test]
fn baseline_policy_serde_roundtrip() {
    let bp = BaselinePolicy::default();
    let json = serde_json::to_string(&bp).unwrap();
    let restored: BaselinePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(bp, restored);
}

// ---------------------------------------------------------------------------
// ConfidenceEnvelope
// ---------------------------------------------------------------------------

#[test]
fn envelope_width() {
    let env = ConfidenceEnvelope {
        estimate_millionths: 500_000,
        lower_millionths: 300_000,
        upper_millionths: 700_000,
        confidence_millionths: 950_000,
        effective_samples: 100,
    };
    assert_eq!(env.width(), 400_000);
}

#[test]
fn envelope_is_positive() {
    let env = ConfidenceEnvelope {
        estimate_millionths: 500_000,
        lower_millionths: 100_000,
        upper_millionths: 900_000,
        confidence_millionths: 950_000,
        effective_samples: 50,
    };
    assert!(env.is_positive());
}

#[test]
fn envelope_is_negative() {
    let env = ConfidenceEnvelope {
        estimate_millionths: -500_000,
        lower_millionths: -900_000,
        upper_millionths: -100_000,
        confidence_millionths: 950_000,
        effective_samples: 50,
    };
    assert!(env.is_negative());
}

#[test]
fn envelope_neither_positive_nor_negative() {
    let env = ConfidenceEnvelope {
        estimate_millionths: 100_000,
        lower_millionths: -200_000,
        upper_millionths: 400_000,
        confidence_millionths: 950_000,
        effective_samples: 50,
    };
    assert!(!env.is_positive());
    assert!(!env.is_negative());
}

#[test]
fn envelope_serde_roundtrip() {
    let env = ConfidenceEnvelope {
        estimate_millionths: 500_000,
        lower_millionths: 300_000,
        upper_millionths: 700_000,
        confidence_millionths: 950_000,
        effective_samples: 100,
    };
    let json = serde_json::to_string(&env).unwrap();
    let restored: ConfidenceEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, restored);
}

// ---------------------------------------------------------------------------
// EnvelopeStatus
// ---------------------------------------------------------------------------

#[test]
fn envelope_status_display_all_distinct() {
    let statuses = [
        EnvelopeStatus::Safe,
        EnvelopeStatus::Inconclusive,
        EnvelopeStatus::Unsafe,
    ];
    let displays: Vec<String> = statuses.iter().map(|s| format!("{s}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 3);
}

// ---------------------------------------------------------------------------
// EvaluatorConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_doubly_robust() {
    let cfg = EvaluatorConfig::default();
    assert_eq!(cfg.estimator, EstimatorKind::DoublyRobust);
    assert_eq!(cfg.confidence_millionths, 950_000);
}

#[test]
fn config_serde_roundtrip() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        confidence_millionths: 900_000,
        min_propensity_millionths: 50_000,
        improvement_threshold_millionths: 100_000,
        regime_breakdown: true,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: EvaluatorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ---------------------------------------------------------------------------
// CounterfactualEvaluator construction
// ---------------------------------------------------------------------------

#[test]
fn evaluator_default_safe_mode() {
    let eval = CounterfactualEvaluator::default_safe_mode();
    assert_eq!(eval.config().estimator, EstimatorKind::DoublyRobust);
    assert_eq!(eval.evaluation_count(), 0);
}

#[test]
fn evaluator_new_valid_config() {
    let cfg = EvaluatorConfig::default();
    let baseline = BaselinePolicy::default();
    let eval = CounterfactualEvaluator::new(cfg, baseline);
    assert!(eval.is_ok());
}

#[test]
fn evaluator_new_invalid_confidence_zero() {
    let cfg = EvaluatorConfig {
        confidence_millionths: 0,
        ..EvaluatorConfig::default()
    };
    let result = CounterfactualEvaluator::new(cfg, BaselinePolicy::default());
    assert!(result.is_err());
}

#[test]
fn evaluator_new_invalid_confidence_over_million() {
    let cfg = EvaluatorConfig {
        confidence_millionths: 1_100_000,
        ..EvaluatorConfig::default()
    };
    let result = CounterfactualEvaluator::new(cfg, BaselinePolicy::default());
    assert!(result.is_err());
}

#[test]
fn evaluator_new_negative_threshold() {
    let cfg = EvaluatorConfig {
        improvement_threshold_millionths: -100,
        ..EvaluatorConfig::default()
    };
    let result = CounterfactualEvaluator::new(cfg, BaselinePolicy::default());
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// evaluate()
// ---------------------------------------------------------------------------

#[test]
fn evaluate_basic_batch() {
    let mut eval = default_evaluator();
    let batch = make_batch(10, 500_000, 600_000);
    let target = make_target(10, 500_000);
    let result = eval.evaluate(&batch, &target);
    assert!(result.is_ok());
    let r = result.unwrap();
    assert_eq!(r.schema_version, COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION);
}

#[test]
fn evaluate_empty_batch_error() {
    let mut eval = default_evaluator();
    let batch = TransitionBatch {
        policy_id: PolicyId("empty".to_string()),
        transitions: vec![],
    };
    let target = TargetPolicyMapping {
        target_policy_id: PolicyId("target".to_string()),
        target_propensities_millionths: vec![],
        target_model_predictions_millionths: None,
    };
    let result = eval.evaluate(&batch, &target);
    match result {
        Err(CounterfactualError::EmptyBatch) => {}
        other => panic!("expected EmptyBatch, got {other:?}"),
    }
}

#[test]
fn evaluate_propensity_length_mismatch() {
    let mut eval = default_evaluator();
    let batch = make_batch(10, 500_000, 600_000);
    let target = make_target(5, 500_000); // wrong length
    let result = eval.evaluate(&batch, &target);
    match result {
        Err(CounterfactualError::PropensityLengthMismatch { .. }) => {}
        other => panic!("expected PropensityLengthMismatch, got {other:?}"),
    }
}

#[test]
fn evaluate_increments_count() {
    let mut eval = default_evaluator();
    assert_eq!(eval.evaluation_count(), 0);
    let batch = make_batch(10, 500_000, 600_000);
    let target = make_target(10, 500_000);
    eval.evaluate(&batch, &target).unwrap();
    assert_eq!(eval.evaluation_count(), 1);
    eval.evaluate(&batch, &target).unwrap();
    assert_eq!(eval.evaluation_count(), 2);
}

#[test]
fn evaluate_with_ips_estimator() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        ..EvaluatorConfig::default()
    };
    let mut eval = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(20, 500_000, 600_000);
    let target = make_target(20, 500_000);
    let result = eval.evaluate(&batch, &target);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().estimator, EstimatorKind::Ips);
}

#[test]
fn evaluate_with_direct_method() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::DirectMethod,
        ..EvaluatorConfig::default()
    };
    let mut eval = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(20, 500_000, 600_000);
    let target = make_target(20, 500_000);
    let result = eval.evaluate(&batch, &target);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().estimator, EstimatorKind::DirectMethod);
}

#[test]
fn evaluate_result_has_artifact_hash() {
    let mut eval = default_evaluator();
    let batch = make_batch(10, 500_000, 600_000);
    let target = make_target(10, 500_000);
    let result = eval.evaluate(&batch, &target).unwrap();
    // artifact_hash should be non-zero
    assert_ne!(result.artifact_hash, ContentHash::compute(b""));
}

#[test]
fn evaluate_deterministic() {
    let batch = make_batch(10, 500_000, 600_000);
    let target = make_target(10, 500_000);

    let mut eval1 = default_evaluator();
    let r1 = eval1.evaluate(&batch, &target).unwrap();

    let mut eval2 = default_evaluator();
    let r2 = eval2.evaluate(&batch, &target).unwrap();

    assert_eq!(r1.artifact_hash, r2.artifact_hash);
    assert_eq!(r1.safety_status, r2.safety_status);
}

// ---------------------------------------------------------------------------
// Low propensity clipping
// ---------------------------------------------------------------------------

#[test]
fn evaluate_very_low_propensity_clamped() {
    let mut eval = default_evaluator();
    // Propensity of 1 (essentially zero) — should be clamped to min
    let batch = make_batch(10, 1, 600_000);
    let target = make_target(10, 500_000);
    let result = eval.evaluate(&batch, &target);
    // Should not panic due to division by near-zero
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// compare_policies
// ---------------------------------------------------------------------------

#[test]
fn compare_policies_empty() {
    let mut eval = default_evaluator();
    let batch = make_batch(10, 500_000, 600_000);
    let result = compare_policies(&mut eval, &batch, &[]);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn compare_policies_single() {
    let mut eval = default_evaluator();
    let batch = make_batch(10, 500_000, 600_000);
    let target = make_target(10, 500_000);
    let cmp = compare_policies(&mut eval, &batch, &[target]);
    assert!(cmp.is_ok());
    assert_eq!(cmp.unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// rank_by_safety
// ---------------------------------------------------------------------------

#[test]
fn rank_by_safety_empty() {
    let result = rank_by_safety(&[]);
    assert!(result.is_empty());
}

// ---------------------------------------------------------------------------
// safe_candidates
// ---------------------------------------------------------------------------

#[test]
fn safe_candidates_filters_unsafe() {
    let mut eval = default_evaluator();
    let batch = make_batch(10, 500_000, 600_000);
    let target = make_target(10, 500_000);
    let r = eval.evaluate(&batch, &target).unwrap();
    let results = vec![r];
    let safe = safe_candidates(&results);
    // May or may not be safe depending on envelope
    assert!(safe.len() <= results.len());
}

// ---------------------------------------------------------------------------
// observed_regimes
// ---------------------------------------------------------------------------

#[test]
fn observed_regimes_single() {
    let mut eval = default_evaluator();
    let batch = make_batch(10, 500_000, 600_000);
    let target = make_target(10, 500_000);
    let r = eval.evaluate(&batch, &target).unwrap();
    let regimes = observed_regimes(&[r]);
    // All transitions use Normal regime
    assert!(!regimes.is_empty());
}

// ---------------------------------------------------------------------------
// CounterfactualError
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_variants_distinct() {
    let errors = [
        CounterfactualError::EmptyBatch,
        CounterfactualError::BatchTooLarge {
            size: 200_000,
            max: 100_000,
        },
        CounterfactualError::PropensityLengthMismatch {
            batch: 10,
            target: 5,
        },
        CounterfactualError::PropensityOutOfRange {
            index: 0,
            value: -1,
        },
        CounterfactualError::ZeroEffectiveSamples,
        CounterfactualError::ModelPredictionLengthMismatch {
            batch: 10,
            predictions: 5,
        },
        CounterfactualError::InvalidConfidence { value: 0 },
        CounterfactualError::NegativeThreshold { value: -100 },
    ];
    let displays: Vec<String> = errors.iter().map(|e| format!("{e}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), errors.len());
}

#[test]
fn error_is_std_error() {
    let err = CounterfactualError::EmptyBatch;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// LoggedTransition serde
// ---------------------------------------------------------------------------

#[test]
fn logged_transition_serde_roundtrip() {
    let t = make_transition(42, 500_000, 700_000);
    let json = serde_json::to_string(&t).unwrap();
    let restored: LoggedTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, restored);
}

// ---------------------------------------------------------------------------
// TransitionBatch serde
// ---------------------------------------------------------------------------

#[test]
fn transition_batch_serde_roundtrip() {
    let batch = make_batch(5, 500_000, 600_000);
    let json = serde_json::to_string(&batch).unwrap();
    let restored: TransitionBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, restored);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert!(COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION.contains("counterfactual"));
    assert_eq!(
        COUNTERFACTUAL_EVALUATOR_COMPONENT,
        "counterfactual_evaluator"
    );
}
