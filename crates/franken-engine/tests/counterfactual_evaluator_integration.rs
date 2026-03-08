#![forbid(unsafe_code)]

//! Integration tests for the `counterfactual_evaluator` module.
//!
//! Exercises the full public API from outside the crate boundary:
//! - EstimatorKind, PolicyId, BaselinePolicy, LoggedTransition, TransitionBatch
//! - TargetPolicyMapping, ConfidenceEnvelope, EnvelopeStatus, EvaluationResult
//! - EvaluatorConfig, CounterfactualEvaluator, CounterfactualError
//! - compare_policies, rank_by_safety, safe_candidates, observed_regimes
//! - Constants: COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION, COUNTERFACTUAL_EVALUATOR_COMPONENT

use std::collections::BTreeMap;

use frankenengine_engine::counterfactual_evaluator::{
    BaselinePolicy, COUNTERFACTUAL_EVALUATOR_COMPONENT, COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION,
    ConfidenceEnvelope, CounterfactualError, CounterfactualEvaluator, EnvelopeStatus,
    EstimatorKind, EvaluationResult, EvaluatorConfig, LoggedTransition, PolicyId,
    TargetPolicyMapping, TransitionBatch, compare_policies, observed_regimes, rank_by_safety,
    safe_candidates,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_decision_theory::{LaneAction, LaneId, RegimeLabel};
use frankenengine_engine::security_epoch::SecurityEpoch;

const MILLION: i64 = 1_000_000;

// ── Helpers ──────────────────────────────────────────────────────────

fn make_hash(seed: u8) -> ContentHash {
    ContentHash::compute(&[seed; 32])
}

fn make_transition(
    epoch: u64,
    tick: u64,
    regime: RegimeLabel,
    reward: i64,
    propensity: i64,
) -> LoggedTransition {
    LoggedTransition {
        epoch: SecurityEpoch::from_raw(epoch),
        tick,
        regime,
        action_taken: LaneAction::FallbackSafe,
        propensity_millionths: propensity,
        reward_millionths: reward,
        model_prediction_millionths: None,
        context_hash: make_hash(tick as u8),
    }
}

fn make_batch(n: usize, reward: i64, propensity: i64) -> TransitionBatch {
    TransitionBatch {
        policy_id: PolicyId("logging-v1".to_string()),
        transitions: (0..n)
            .map(|i| make_transition(1, i as u64, RegimeLabel::Normal, reward, propensity))
            .collect(),
    }
}

fn make_target(n: usize, propensity: i64) -> TargetPolicyMapping {
    TargetPolicyMapping {
        target_policy_id: PolicyId("candidate-v1".to_string()),
        target_propensities_millionths: vec![propensity; n],
        target_model_predictions_millionths: None,
    }
}

fn make_envelope(est: i64, lo: i64, hi: i64, eff: u64) -> ConfidenceEnvelope {
    ConfidenceEnvelope {
        estimate_millionths: est,
        lower_millionths: lo,
        upper_millionths: hi,
        confidence_millionths: 950_000,
        effective_samples: eff,
    }
}

fn make_eval_result(
    candidate_id: &str,
    improvement_lo: i64,
    status: EnvelopeStatus,
    regimes: &[&str],
) -> EvaluationResult {
    let mut regime_breakdown = BTreeMap::new();
    for r in regimes {
        regime_breakdown.insert(r.to_string(), make_envelope(0, 0, 0, 5));
    }
    EvaluationResult {
        schema_version: COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION.to_string(),
        estimator: EstimatorKind::DoublyRobust,
        candidate_policy_id: PolicyId(candidate_id.to_string()),
        baseline_policy_id: PolicyId("baseline".to_string()),
        candidate_envelope: make_envelope(0, 0, 0, 10),
        baseline_envelope: make_envelope(0, 0, 0, 10),
        improvement_envelope: make_envelope(
            improvement_lo + 50_000,
            improvement_lo,
            improvement_lo + 100_000,
            10,
        ),
        safety_status: status,
        regime_breakdown,
        artifact_hash: make_hash(1),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Constants
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn constants_are_well_known_strings() {
    assert_eq!(
        COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION,
        "franken-engine.counterfactual-evaluator.v1"
    );
    assert_eq!(
        COUNTERFACTUAL_EVALUATOR_COMPONENT,
        "counterfactual_evaluator"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. EstimatorKind
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn estimator_kind_display_all_variants() {
    assert_eq!(EstimatorKind::Ips.to_string(), "ips");
    assert_eq!(EstimatorKind::DoublyRobust.to_string(), "doubly_robust");
    assert_eq!(EstimatorKind::DirectMethod.to_string(), "direct_method");
}

#[test]
fn estimator_kind_serde_roundtrip() {
    for kind in [
        EstimatorKind::Ips,
        EstimatorKind::DoublyRobust,
        EstimatorKind::DirectMethod,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: EstimatorKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn estimator_kind_clone_eq() {
    let a = EstimatorKind::DoublyRobust;
    let b = a;
    assert_eq!(a, b);
}

// ═══════════════════════════════════════════════════════════════════════
// 3. PolicyId and BaselinePolicy
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn policy_id_display() {
    let p = PolicyId("my-policy-v3".to_string());
    assert_eq!(p.to_string(), "my-policy-v3");
}

#[test]
fn policy_id_serde_roundtrip() {
    let p = PolicyId("policy-x".to_string());
    let json = serde_json::to_string(&p).unwrap();
    let back: PolicyId = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn policy_id_ordering() {
    let a = PolicyId("alpha".to_string());
    let b = PolicyId("beta".to_string());
    assert!(a < b);
}

#[test]
fn baseline_policy_default() {
    let bl = BaselinePolicy::default();
    assert_eq!(bl.id, PolicyId("baseline-safe-mode".to_string()));
    assert_eq!(bl.action, LaneAction::FallbackSafe);
}

#[test]
fn baseline_policy_custom() {
    let bl = BaselinePolicy {
        id: PolicyId("custom-baseline".to_string()),
        action: LaneAction::RouteTo(LaneId("fast-lane".to_string())),
    };
    assert_eq!(bl.id.to_string(), "custom-baseline");
}

#[test]
fn baseline_policy_serde_roundtrip() {
    let bl = BaselinePolicy::default();
    let json = serde_json::to_string(&bl).unwrap();
    let back: BaselinePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(bl, back);
}

// ═══════════════════════════════════════════════════════════════════════
// 4. LoggedTransition and TransitionBatch
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn logged_transition_serde_roundtrip() {
    let t = make_transition(5, 42, RegimeLabel::Attack, 750_000, 333_000);
    let json = serde_json::to_string(&t).unwrap();
    let back: LoggedTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn logged_transition_with_model_prediction() {
    let mut t = make_transition(1, 0, RegimeLabel::Normal, 500_000, 500_000);
    t.model_prediction_millionths = Some(600_000);
    let json = serde_json::to_string(&t).unwrap();
    let back: LoggedTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(back.model_prediction_millionths, Some(600_000));
}

#[test]
fn transition_batch_serde_roundtrip() {
    let batch = make_batch(5, 500_000, 400_000);
    let json = serde_json::to_string(&batch).unwrap();
    let back: TransitionBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

// ═══════════════════════════════════════════════════════════════════════
// 5. TargetPolicyMapping
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn target_policy_mapping_serde_roundtrip() {
    let t = make_target(10, 500_000);
    let json = serde_json::to_string(&t).unwrap();
    let back: TargetPolicyMapping = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn target_policy_mapping_with_model_predictions() {
    let mut t = make_target(3, 500_000);
    t.target_model_predictions_millionths = Some(vec![100_000, 200_000, 300_000]);
    let json = serde_json::to_string(&t).unwrap();
    let back: TargetPolicyMapping = serde_json::from_str(&json).unwrap();
    assert_eq!(
        back.target_model_predictions_millionths,
        Some(vec![100_000, 200_000, 300_000])
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 6. ConfidenceEnvelope
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn envelope_is_positive_when_lower_above_zero() {
    let env = make_envelope(500_000, 100_000, 900_000, 100);
    assert!(env.is_positive());
    assert!(!env.is_negative());
}

#[test]
fn envelope_is_negative_when_upper_below_zero() {
    let env = make_envelope(-500_000, -900_000, -100_000, 50);
    assert!(!env.is_positive());
    assert!(env.is_negative());
}

#[test]
fn envelope_spanning_zero_is_neither() {
    let env = make_envelope(10_000, -50_000, 70_000, 20);
    assert!(!env.is_positive());
    assert!(!env.is_negative());
}

#[test]
fn envelope_width() {
    let env = make_envelope(500_000, 300_000, 700_000, 10);
    assert_eq!(env.width(), 400_000);
}

#[test]
fn envelope_zero_width() {
    let env = make_envelope(500_000, 500_000, 500_000, 10);
    assert_eq!(env.width(), 0);
}

#[test]
fn envelope_serde_roundtrip() {
    let env = make_envelope(123_456, -100_000, 500_000, 42);
    let json = serde_json::to_string(&env).unwrap();
    let back: ConfidenceEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

// ═══════════════════════════════════════════════════════════════════════
// 7. EnvelopeStatus
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn envelope_status_display() {
    assert_eq!(EnvelopeStatus::Safe.to_string(), "safe");
    assert_eq!(EnvelopeStatus::Inconclusive.to_string(), "inconclusive");
    assert_eq!(EnvelopeStatus::Unsafe.to_string(), "unsafe");
}

#[test]
fn envelope_status_serde_roundtrip() {
    for s in [
        EnvelopeStatus::Safe,
        EnvelopeStatus::Inconclusive,
        EnvelopeStatus::Unsafe,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: EnvelopeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 8. EvaluatorConfig
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn evaluator_config_default_values() {
    let cfg = EvaluatorConfig::default();
    assert_eq!(cfg.estimator, EstimatorKind::DoublyRobust);
    assert_eq!(cfg.confidence_millionths, 950_000);
    assert_eq!(cfg.min_propensity_millionths, 10_000);
    assert_eq!(cfg.improvement_threshold_millionths, 0);
    assert!(cfg.regime_breakdown);
}

#[test]
fn evaluator_config_serde_roundtrip() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        confidence_millionths: 900_000,
        min_propensity_millionths: 50_000,
        improvement_threshold_millionths: 100_000,
        regime_breakdown: false,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: EvaluatorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ═══════════════════════════════════════════════════════════════════════
// 9. CounterfactualError
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn error_display_all_variants() {
    let cases: Vec<(CounterfactualError, &str)> = vec![
        (CounterfactualError::EmptyBatch, "empty transition batch"),
        (
            CounterfactualError::BatchTooLarge {
                size: 200_000,
                max: 100_000,
            },
            "batch size 200000 exceeds maximum 100000",
        ),
        (
            CounterfactualError::PropensityLengthMismatch {
                batch: 10,
                target: 5,
            },
            "propensity vector length 5 != batch length 10",
        ),
        (
            CounterfactualError::PropensityOutOfRange {
                index: 3,
                value: -5,
            },
            "propensity at index 3 out of range: -5",
        ),
        (
            CounterfactualError::ZeroEffectiveSamples,
            "zero effective samples after propensity clipping",
        ),
        (
            CounterfactualError::ModelPredictionLengthMismatch {
                batch: 10,
                predictions: 7,
            },
            "model prediction length 7 != batch length 10",
        ),
        (
            CounterfactualError::InvalidConfidence { value: -1 },
            "confidence level out of range: -1",
        ),
        (
            CounterfactualError::NegativeThreshold { value: -10 },
            "improvement threshold must be non-negative: -10",
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(err.to_string(), expected);
    }
}

#[test]
fn error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CounterfactualError::EmptyBatch);
    assert_eq!(err.to_string(), "empty transition batch");
}

#[test]
fn error_serde_roundtrip() {
    let errs = vec![
        CounterfactualError::EmptyBatch,
        CounterfactualError::BatchTooLarge {
            size: 200_000,
            max: 100_000,
        },
        CounterfactualError::ZeroEffectiveSamples,
        CounterfactualError::PropensityLengthMismatch {
            batch: 5,
            target: 3,
        },
        CounterfactualError::PropensityOutOfRange {
            index: 0,
            value: -99,
        },
        CounterfactualError::ModelPredictionLengthMismatch {
            batch: 10,
            predictions: 2,
        },
        CounterfactualError::InvalidConfidence { value: 0 },
        CounterfactualError::NegativeThreshold { value: -1 },
    ];
    for e in errs {
        let json = serde_json::to_string(&e).unwrap();
        let back: CounterfactualError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 10. CounterfactualEvaluator — Construction
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_safe_mode_creates_evaluator() {
    let e = CounterfactualEvaluator::default_safe_mode();
    assert_eq!(e.evaluation_count(), 0);
    assert_eq!(e.config().estimator, EstimatorKind::DoublyRobust);
    assert_eq!(e.baseline().id, PolicyId("baseline-safe-mode".to_string()));
}

#[test]
fn new_with_valid_config() {
    let cfg = EvaluatorConfig::default();
    let base = BaselinePolicy::default();
    assert!(CounterfactualEvaluator::new(cfg, base).is_ok());
}

#[test]
fn new_rejects_zero_confidence() {
    let cfg = EvaluatorConfig {
        confidence_millionths: 0,
        ..EvaluatorConfig::default()
    };
    let err = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap_err();
    assert_eq!(err, CounterfactualError::InvalidConfidence { value: 0 });
}

#[test]
fn new_rejects_negative_confidence() {
    let cfg = EvaluatorConfig {
        confidence_millionths: -100,
        ..EvaluatorConfig::default()
    };
    let err = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap_err();
    assert_eq!(err, CounterfactualError::InvalidConfidence { value: -100 });
}

#[test]
fn new_rejects_million_confidence() {
    let cfg = EvaluatorConfig {
        confidence_millionths: MILLION,
        ..EvaluatorConfig::default()
    };
    let err = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap_err();
    assert_eq!(
        err,
        CounterfactualError::InvalidConfidence { value: MILLION }
    );
}

#[test]
fn new_rejects_negative_threshold() {
    let cfg = EvaluatorConfig {
        improvement_threshold_millionths: -1,
        ..EvaluatorConfig::default()
    };
    let err = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap_err();
    assert_eq!(err, CounterfactualError::NegativeThreshold { value: -1 });
}

#[test]
fn new_accepts_zero_threshold() {
    let cfg = EvaluatorConfig {
        improvement_threshold_millionths: 0,
        ..EvaluatorConfig::default()
    };
    assert!(CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).is_ok());
}

#[test]
fn new_accepts_edge_confidence() {
    // Just above 0
    let cfg = EvaluatorConfig {
        confidence_millionths: 1,
        ..EvaluatorConfig::default()
    };
    assert!(CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).is_ok());

    // Just below 1M
    let cfg = EvaluatorConfig {
        confidence_millionths: MILLION - 1,
        ..EvaluatorConfig::default()
    };
    assert!(CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// 11. CounterfactualEvaluator — Validation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn evaluate_empty_batch_error() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = TransitionBatch {
        policy_id: PolicyId("p".to_string()),
        transitions: vec![],
    };
    let target = make_target(0, 500_000);
    assert_eq!(
        e.evaluate(&batch, &target).unwrap_err(),
        CounterfactualError::EmptyBatch
    );
}

#[test]
fn evaluate_propensity_length_mismatch() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(5, 500_000, 500_000);
    let target = make_target(3, 500_000);
    let err = e.evaluate(&batch, &target).unwrap_err();
    assert!(matches!(
        err,
        CounterfactualError::PropensityLengthMismatch {
            batch: 5,
            target: 3
        }
    ));
}

#[test]
fn evaluate_negative_logging_propensity() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let mut batch = make_batch(3, 500_000, 500_000);
    batch.transitions[1].propensity_millionths = -1;
    let target = make_target(3, 500_000);
    let err = e.evaluate(&batch, &target).unwrap_err();
    assert!(matches!(
        err,
        CounterfactualError::PropensityOutOfRange {
            index: 1,
            value: -1
        }
    ));
}

#[test]
fn evaluate_too_large_logging_propensity() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let mut batch = make_batch(3, 500_000, 500_000);
    batch.transitions[0].propensity_millionths = MILLION + 1;
    let target = make_target(3, 500_000);
    let err = e.evaluate(&batch, &target).unwrap_err();
    assert!(matches!(
        err,
        CounterfactualError::PropensityOutOfRange { index: 0, .. }
    ));
}

#[test]
fn evaluate_target_propensity_out_of_range() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(3, 500_000, 500_000);
    let mut target = make_target(3, 500_000);
    target.target_propensities_millionths[2] = MILLION + 1;
    let err = e.evaluate(&batch, &target).unwrap_err();
    assert!(matches!(
        err,
        CounterfactualError::PropensityOutOfRange { index: 2, .. }
    ));
}

#[test]
fn evaluate_model_prediction_length_mismatch() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(3, 500_000, 500_000);
    let mut target = make_target(3, 500_000);
    target.target_model_predictions_millionths = Some(vec![500_000; 2]);
    let err = e.evaluate(&batch, &target).unwrap_err();
    assert!(matches!(
        err,
        CounterfactualError::ModelPredictionLengthMismatch {
            batch: 3,
            predictions: 2
        }
    ));
}

#[test]
fn evaluate_zero_target_propensity_yields_zero_effective_samples() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(10, 500_000, 500_000);
    let target = make_target(10, 0);
    let err = e.evaluate(&batch, &target).unwrap_err();
    assert_eq!(err, CounterfactualError::ZeroEffectiveSamples);
}

// ═══════════════════════════════════════════════════════════════════════
// 12. IPS Estimator
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ips_equal_propensities_yields_mean_reward() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(100, 600_000, 500_000);
    let target = make_target(100, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert!(
        (result.candidate_envelope.estimate_millionths - 600_000).abs() < 10_000,
        "got {}",
        result.candidate_envelope.estimate_millionths
    );
}

#[test]
fn ips_double_propensity_doubles_weight() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    // logging propensity=250k, target=500k => weight ~2x
    let batch = make_batch(100, 300_000, 250_000);
    let target = make_target(100, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    // Expected: 300k * 2 = 600k
    assert!(
        (result.candidate_envelope.estimate_millionths - 600_000).abs() < 10_000,
        "got {}",
        result.candidate_envelope.estimate_millionths
    );
}

#[test]
fn ips_half_propensity_halves_weight() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    // logging=500k, target=250k => weight ~0.5
    let batch = make_batch(100, 800_000, 500_000);
    let target = make_target(100, 250_000);
    let result = e.evaluate(&batch, &target).unwrap();
    // Expected: 800k * 0.5 = 400k
    assert!(
        (result.candidate_envelope.estimate_millionths - 400_000).abs() < 10_000,
        "got {}",
        result.candidate_envelope.estimate_millionths
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 13. DR Estimator
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn dr_with_perfect_model() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(50, 400_000, 500_000);
    let mut target = make_target(50, 500_000);
    target.target_model_predictions_millionths = Some(vec![400_000; 50]);
    let result = e.evaluate(&batch, &target).unwrap();
    // DR with perfect model => close to reward mean
    assert!(
        (result.candidate_envelope.estimate_millionths - 400_000).abs() < 20_000,
        "got {}",
        result.candidate_envelope.estimate_millionths
    );
}

#[test]
fn dr_without_model_falls_back_to_rewards() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(50, 700_000, 500_000);
    let target = make_target(50, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    // No model => residual is 0 => DR ~ mean(reward)
    assert!(
        (result.candidate_envelope.estimate_millionths - 700_000).abs() < 20_000,
        "got {}",
        result.candidate_envelope.estimate_millionths
    );
}

#[test]
fn dr_biased_model_corrected_by_weights() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    // Rewards are all 500k but model predicts 300k; DR corrects via IPS term
    let batch = make_batch(50, 500_000, 500_000);
    let mut target = make_target(50, 500_000);
    target.target_model_predictions_millionths = Some(vec![300_000; 50]);
    let result = e.evaluate(&batch, &target).unwrap();
    // With equal propensities, weight=1, DR = m_hat + 1*(r - m_hat) = r = 500k
    assert!(
        (result.candidate_envelope.estimate_millionths - 500_000).abs() < 20_000,
        "got {}",
        result.candidate_envelope.estimate_millionths
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 14. Direct Method
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn direct_method_averages_model_predictions() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::DirectMethod,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(10, 100_000, 500_000);
    let mut target = make_target(10, 500_000);
    target.target_model_predictions_millionths = Some(vec![800_000; 10]);
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(result.candidate_envelope.estimate_millionths, 800_000);
}

#[test]
fn direct_method_no_model_returns_zero() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::DirectMethod,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(10, 500_000, 500_000);
    let target = make_target(10, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(result.candidate_envelope.estimate_millionths, 0);
}

#[test]
fn direct_method_varied_predictions() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::DirectMethod,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(4, 100_000, 500_000);
    let mut target = make_target(4, 500_000);
    // average of [200k, 400k, 600k, 800k] = 500k
    target.target_model_predictions_millionths = Some(vec![200_000, 400_000, 600_000, 800_000]);
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(result.candidate_envelope.estimate_millionths, 500_000);
}

// ═══════════════════════════════════════════════════════════════════════
// 15. Safety Status
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn safety_status_unsafe_when_threshold_high() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        improvement_threshold_millionths: 500_000,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    // Equal propensities => improvement ~ 0 << 500k threshold
    let batch = make_batch(100, 500_000, 500_000);
    let target = make_target(100, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(result.safety_status, EnvelopeStatus::Unsafe);
}

#[test]
fn safety_status_safe_when_large_improvement() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        improvement_threshold_millionths: 0,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    // target 2x logging => candidate estimate ~2*300k = 600k, baseline=300k
    // improvement ~300k with tight CI on uniform data
    let batch = make_batch(1000, 300_000, 250_000);
    let target = make_target(1000, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert!(
        result.safety_status == EnvelopeStatus::Safe
            || result.safety_status == EnvelopeStatus::Inconclusive,
        "status: {:?}",
        result.safety_status
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 16. Evaluation Count
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn evaluation_count_increments() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    assert_eq!(e.evaluation_count(), 0);
    let batch = make_batch(5, 500_000, 500_000);
    let target = make_target(5, 500_000);
    let _ = e.evaluate(&batch, &target).unwrap();
    assert_eq!(e.evaluation_count(), 1);
    let _ = e.evaluate(&batch, &target).unwrap();
    assert_eq!(e.evaluation_count(), 2);
}

#[test]
fn evaluation_count_does_not_increment_on_error() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = TransitionBatch {
        policy_id: PolicyId("p".to_string()),
        transitions: vec![],
    };
    let target = make_target(0, 500_000);
    let _ = e.evaluate(&batch, &target);
    assert_eq!(e.evaluation_count(), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// 17. Schema Version and Artifact Hash
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn result_includes_schema_version() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(5, 500_000, 500_000);
    let target = make_target(5, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(
        result.schema_version,
        COUNTERFACTUAL_EVALUATOR_SCHEMA_VERSION
    );
}

#[test]
fn artifact_hash_is_deterministic() {
    let mut e1 = CounterfactualEvaluator::default_safe_mode();
    let mut e2 = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(20, 500_000, 500_000);
    let target = make_target(20, 500_000);
    let r1 = e1.evaluate(&batch, &target).unwrap();
    let r2 = e2.evaluate(&batch, &target).unwrap();
    assert_eq!(r1.artifact_hash, r2.artifact_hash);
}

#[test]
fn artifact_hash_changes_with_different_data() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch1 = make_batch(20, 500_000, 500_000);
    let batch2 = make_batch(20, 600_000, 500_000);
    let target = make_target(20, 500_000);
    let r1 = e.evaluate(&batch1, &target).unwrap();
    let r2 = e.evaluate(&batch2, &target).unwrap();
    assert_ne!(r1.artifact_hash, r2.artifact_hash);
}

// ═══════════════════════════════════════════════════════════════════════
// 18. Regime Breakdown
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn regime_breakdown_groups_by_regime() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let mut batch = make_batch(6, 500_000, 500_000);
    batch.transitions[0].regime = RegimeLabel::Normal;
    batch.transitions[1].regime = RegimeLabel::Normal;
    batch.transitions[2].regime = RegimeLabel::Normal;
    batch.transitions[3].regime = RegimeLabel::Elevated;
    batch.transitions[4].regime = RegimeLabel::Elevated;
    batch.transitions[5].regime = RegimeLabel::Elevated;
    let target = make_target(6, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert!(result.regime_breakdown.contains_key("normal"));
    assert!(result.regime_breakdown.contains_key("elevated"));
    assert_eq!(result.regime_breakdown.len(), 2);
}

#[test]
fn regime_breakdown_disabled_yields_empty_map() {
    let cfg = EvaluatorConfig {
        regime_breakdown: false,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(10, 500_000, 500_000);
    let target = make_target(10, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert!(result.regime_breakdown.is_empty());
}

#[test]
fn regime_breakdown_all_five_regimes() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let regimes = [
        RegimeLabel::Normal,
        RegimeLabel::Elevated,
        RegimeLabel::Attack,
        RegimeLabel::Degraded,
        RegimeLabel::Recovery,
    ];
    let mut transitions = Vec::new();
    for (i, &regime) in regimes.iter().enumerate() {
        transitions.push(LoggedTransition {
            epoch: SecurityEpoch::from_raw(1),
            tick: i as u64,
            regime,
            action_taken: LaneAction::FallbackSafe,
            propensity_millionths: 500_000,
            reward_millionths: (i as i64 + 1) * 100_000,
            model_prediction_millionths: None,
            context_hash: make_hash(i as u8),
        });
    }
    let batch = TransitionBatch {
        policy_id: PolicyId("log".to_string()),
        transitions,
    };
    let target = make_target(5, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(result.regime_breakdown.len(), 5);
    assert!(result.regime_breakdown.contains_key("normal"));
    assert!(result.regime_breakdown.contains_key("elevated"));
    assert!(result.regime_breakdown.contains_key("attack"));
    assert!(result.regime_breakdown.contains_key("degraded"));
    assert!(result.regime_breakdown.contains_key("recovery"));
}

#[test]
fn regime_breakdown_higher_reward_regime_has_higher_estimate() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let mut transitions = Vec::new();
    for i in 0..20u64 {
        let (regime, reward) = if i < 10 {
            (RegimeLabel::Normal, 800_000)
        } else {
            (RegimeLabel::Degraded, 200_000)
        };
        transitions.push(LoggedTransition {
            epoch: SecurityEpoch::from_raw(1),
            tick: i,
            regime,
            action_taken: LaneAction::FallbackSafe,
            propensity_millionths: 500_000,
            reward_millionths: reward,
            model_prediction_millionths: None,
            context_hash: make_hash(i as u8),
        });
    }
    let batch = TransitionBatch {
        policy_id: PolicyId("log".to_string()),
        transitions,
    };
    let target = make_target(20, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    let normal_est = result.regime_breakdown["normal"].estimate_millionths;
    let degraded_est = result.regime_breakdown["degraded"].estimate_millionths;
    assert!(
        normal_est > degraded_est,
        "normal={normal_est}, degraded={degraded_est}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 19. Single Transition Edge Case
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn single_transition_evaluates_successfully() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(1, 500_000, 500_000);
    let target = make_target(1, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert!(result.candidate_envelope.effective_samples >= 1);
}

// ═══════════════════════════════════════════════════════════════════════
// 20. Confidence Envelope Width from Evaluation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn more_samples_tighter_envelope() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        regime_breakdown: false,
        ..EvaluatorConfig::default()
    };

    let mut e_small = CounterfactualEvaluator::new(cfg.clone(), BaselinePolicy::default()).unwrap();
    let mut e_large = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();

    let batch_small = make_batch(10, 500_000, 500_000);
    let target_small = make_target(10, 500_000);
    let r_small = e_small.evaluate(&batch_small, &target_small).unwrap();

    let batch_large = make_batch(1000, 500_000, 500_000);
    let target_large = make_target(1000, 500_000);
    let r_large = e_large.evaluate(&batch_large, &target_large).unwrap();

    // Uniform data => zero variance => both should have width 0 or very small
    // But at least the large batch should not be wider
    assert!(
        r_large.candidate_envelope.width() <= r_small.candidate_envelope.width(),
        "large={}, small={}",
        r_large.candidate_envelope.width(),
        r_small.candidate_envelope.width()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 21. compare_policies
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn compare_policies_returns_all() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(20, 500_000, 500_000);
    let candidates = vec![make_target(20, 300_000), make_target(20, 700_000)];
    let results = compare_policies(&mut e, &batch, &candidates).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(e.evaluation_count(), 2);
}

#[test]
fn compare_policies_empty_candidates() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(10, 500_000, 500_000);
    let results = compare_policies(&mut e, &batch, &[]).unwrap();
    assert!(results.is_empty());
}

#[test]
fn compare_policies_propagates_first_error() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(5, 500_000, 500_000);
    // Second candidate has wrong length
    let candidates = vec![make_target(5, 500_000), make_target(3, 500_000)];
    let err = compare_policies(&mut e, &batch, &candidates).unwrap_err();
    assert!(matches!(
        err,
        CounterfactualError::PropensityLengthMismatch { .. }
    ));
}

// ═══════════════════════════════════════════════════════════════════════
// 22. rank_by_safety
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn rank_by_safety_orders_descending() {
    let results = vec![
        make_eval_result("a", 10_000, EnvelopeStatus::Safe, &["normal"]),
        make_eval_result("b", 100_000, EnvelopeStatus::Safe, &["normal"]),
        make_eval_result("c", -50_000, EnvelopeStatus::Unsafe, &["normal"]),
    ];
    let ranked = rank_by_safety(&results);
    assert_eq!(ranked.len(), 3);
    assert_eq!(ranked[0].0, 1); // b has highest lower bound
    assert_eq!(ranked[1].0, 0); // a second
    assert_eq!(ranked[2].0, 2); // c worst
}

#[test]
fn rank_by_safety_empty_input() {
    let ranked = rank_by_safety(&[]);
    assert!(ranked.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// 23. safe_candidates
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn safe_candidates_filters_correctly() {
    let results = vec![
        make_eval_result("safe1", 10_000, EnvelopeStatus::Safe, &[]),
        make_eval_result("unsafe1", -10_000, EnvelopeStatus::Unsafe, &[]),
        make_eval_result("safe2", 20_000, EnvelopeStatus::Safe, &[]),
        make_eval_result("inconclusive1", 0, EnvelopeStatus::Inconclusive, &[]),
    ];
    let safe = safe_candidates(&results);
    assert_eq!(safe.len(), 2);
    assert_eq!(safe[0].candidate_policy_id, PolicyId("safe1".to_string()));
    assert_eq!(safe[1].candidate_policy_id, PolicyId("safe2".to_string()));
}

#[test]
fn safe_candidates_empty_when_none_safe() {
    let results = vec![
        make_eval_result("u1", -10_000, EnvelopeStatus::Unsafe, &[]),
        make_eval_result("i1", 0, EnvelopeStatus::Inconclusive, &[]),
    ];
    let safe = safe_candidates(&results);
    assert!(safe.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// 24. observed_regimes
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn observed_regimes_collects_all() {
    let results = vec![
        make_eval_result("a", 0, EnvelopeStatus::Safe, &["normal", "attack"]),
        make_eval_result("b", 0, EnvelopeStatus::Safe, &["attack", "degraded"]),
    ];
    let regimes = observed_regimes(&results);
    assert_eq!(regimes.len(), 3);
    assert!(regimes.contains("normal"));
    assert!(regimes.contains("attack"));
    assert!(regimes.contains("degraded"));
}

#[test]
fn observed_regimes_empty_when_no_breakdown() {
    let results = vec![make_eval_result("a", 0, EnvelopeStatus::Safe, &[])];
    let regimes = observed_regimes(&results);
    assert!(regimes.is_empty());
}

#[test]
fn observed_regimes_deduplicates() {
    let results = vec![
        make_eval_result("a", 0, EnvelopeStatus::Safe, &["normal"]),
        make_eval_result("b", 0, EnvelopeStatus::Safe, &["normal"]),
    ];
    let regimes = observed_regimes(&results);
    assert_eq!(regimes.len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════
// 25. EvaluationResult Serde
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn evaluation_result_serde_roundtrip() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(10, 500_000, 500_000);
    let target = make_target(10, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: EvaluationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ═══════════════════════════════════════════════════════════════════════
// 26. CounterfactualEvaluator Serde
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn evaluator_serde_roundtrip() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(5, 500_000, 500_000);
    let target = make_target(5, 500_000);
    let _ = e.evaluate(&batch, &target).unwrap();

    let json = serde_json::to_string(&e).unwrap();
    let back: CounterfactualEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evaluation_count(), 1);
    assert_eq!(back.config().estimator, EstimatorKind::DoublyRobust);
}

// ═══════════════════════════════════════════════════════════════════════
// 27. Different LaneAction variants in transitions
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn transitions_with_route_to_action() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let mut batch = make_batch(3, 500_000, 500_000);
    batch.transitions[0].action_taken = LaneAction::RouteTo(LaneId("fast".to_string()));
    batch.transitions[1].action_taken = LaneAction::SuspendAdaptive;
    let target = make_target(3, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(result.estimator, EstimatorKind::DoublyRobust);
}

// ═══════════════════════════════════════════════════════════════════════
// 28. Boundary propensity values
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn propensity_at_zero_and_million_boundary() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    // logging propensity at exactly 0 is valid but target at 0 yields zero weights
    let batch = make_batch(5, 500_000, 0);
    let target = make_target(5, MILLION);
    // logging propensity=0 is allowed; clamped to min_propensity internally
    let result = e.evaluate(&batch, &target);
    // Should succeed since target propensity is nonzero
    assert!(result.is_ok());
}

#[test]
fn propensity_at_exactly_million() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(5, 500_000, MILLION);
    let target = make_target(5, MILLION);
    let result = e.evaluate(&batch, &target).unwrap();
    // Weight = 1M/1M = 1.0 => estimate ~ reward
    assert!(
        (result.candidate_envelope.estimate_millionths - 500_000).abs() < 20_000,
        "got {}",
        result.candidate_envelope.estimate_millionths
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 29. Improvement envelope and baseline envelope
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn improvement_envelope_is_candidate_minus_baseline() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        regime_breakdown: false,
        ..EvaluatorConfig::default()
    };
    let mut e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    let batch = make_batch(100, 500_000, 500_000);
    let target = make_target(100, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    let expected_improvement = result.candidate_envelope.estimate_millionths
        - result.baseline_envelope.estimate_millionths;
    assert_eq!(
        result.improvement_envelope.estimate_millionths,
        expected_improvement
    );
}

#[test]
fn baseline_envelope_effective_samples_equals_batch_size() {
    let mut e = CounterfactualEvaluator::default_safe_mode();
    let batch = make_batch(42, 500_000, 500_000);
    let target = make_target(42, 500_000);
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(result.baseline_envelope.effective_samples, 42);
}

// ═══════════════════════════════════════════════════════════════════════
// 30. Policy IDs in result
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn result_carries_correct_policy_ids() {
    let baseline = BaselinePolicy {
        id: PolicyId("my-baseline".to_string()),
        action: LaneAction::FallbackSafe,
    };
    let mut e = CounterfactualEvaluator::new(EvaluatorConfig::default(), baseline).unwrap();
    let batch = make_batch(5, 500_000, 500_000);
    let mut target = make_target(5, 500_000);
    target.target_policy_id = PolicyId("candidate-xyz".to_string());
    let result = e.evaluate(&batch, &target).unwrap();
    assert_eq!(
        result.candidate_policy_id,
        PolicyId("candidate-xyz".to_string())
    );
    assert_eq!(
        result.baseline_policy_id,
        PolicyId("my-baseline".to_string())
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 31. Evaluator accessors
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn config_accessor_returns_correct_estimator() {
    let cfg = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        ..EvaluatorConfig::default()
    };
    let e = CounterfactualEvaluator::new(cfg, BaselinePolicy::default()).unwrap();
    assert_eq!(e.config().estimator, EstimatorKind::Ips);
    assert_eq!(e.config().confidence_millionths, 950_000);
}

#[test]
fn baseline_accessor_returns_custom_baseline() {
    let bl = BaselinePolicy {
        id: PolicyId("custom".to_string()),
        action: LaneAction::SuspendAdaptive,
    };
    let e = CounterfactualEvaluator::new(EvaluatorConfig::default(), bl.clone()).unwrap();
    assert_eq!(e.baseline().id, PolicyId("custom".to_string()));
    assert_eq!(e.baseline().action, LaneAction::SuspendAdaptive);
}
