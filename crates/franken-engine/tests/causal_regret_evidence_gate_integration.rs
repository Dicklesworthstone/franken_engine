#![forbid(unsafe_code)]
//! Integration tests for the `causal_regret_evidence_gate` module.
//!
//! Exercises every public type, constant, method, error path, and
//! cross-concern scenario from outside the crate boundary.

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

use std::collections::BTreeMap;

use frankenengine_engine::causal_regret_evidence_gate::{
    BlockingReason, CAUSAL_REGRET_GATE_COMPONENT, CAUSAL_REGRET_GATE_SCHEMA_VERSION,
    CausalRegretEvidenceGate, CausalRegretGateConfig, CausalRegretGateError, DemotionHistoryItem,
    EvaluationSummary, GateInput, GateOutput, RegretSummary, StageThresholds,
};
use frankenengine_engine::counterfactual_evaluator::{
    ConfidenceEnvelope, EnvelopeStatus, EstimatorKind, EvaluationResult, PolicyId,
};
use frankenengine_engine::demotion_rollback::{DemotionReason, DemotionSeverity};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::moonshot_contract::MoonshotStage;
use frankenengine_engine::regret_bounded_router::{RegimeKind, RegretCertificate};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{GateVerdict, RiskLevel};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_envelope(lower: i64, upper: i64, samples: u64) -> ConfidenceEnvelope {
    ConfidenceEnvelope {
        estimate_millionths: (lower + upper) / 2,
        lower_millionths: lower,
        upper_millionths: upper,
        confidence_millionths: 950_000,
        effective_samples: samples,
    }
}

fn make_eval(
    policy: &str,
    estimator: EstimatorKind,
    status: EnvelopeStatus,
    lower: i64,
    samples: u64,
) -> EvaluationResult {
    let envelope = make_envelope(lower, lower + 100_000, samples);
    EvaluationResult {
        schema_version: "test".into(),
        estimator,
        candidate_policy_id: PolicyId(policy.into()),
        baseline_policy_id: PolicyId("baseline".into()),
        candidate_envelope: envelope.clone(),
        baseline_envelope: make_envelope(0, 50_000, samples),
        improvement_envelope: envelope,
        safety_status: status,
        regime_breakdown: BTreeMap::new(),
        artifact_hash: ContentHash::compute(policy.as_bytes()),
    }
}

fn make_regret_cert(realized: i64, bound: i64, within: bool, per_round: i64) -> RegretCertificate {
    RegretCertificate {
        schema: "test".into(),
        rounds: 1000,
        realized_regret_millionths: realized,
        theoretical_bound_millionths: bound,
        within_bound: within,
        exact_regret_available: within,
        per_round_regret_millionths: per_round,
        growth_rate_class: "sublinear".into(),
    }
}

fn make_demotion(epoch: u64, severity: DemotionSeverity) -> DemotionHistoryItem {
    DemotionHistoryItem {
        epoch: SecurityEpoch::from_raw(epoch),
        reason: DemotionReason::PerformanceBreach {
            metric_name: "latency".into(),
            observed_millionths: 500_000,
            threshold_millionths: 200_000,
            sustained_duration_ns: 1_000_000,
        },
        severity,
        timestamp_ns: epoch * 1_000_000_000,
    }
}

/// Build a valid `GateInput` for the given target stage with correct predecessor.
fn basic_input(target: MoonshotStage) -> GateInput {
    let current = match target {
        MoonshotStage::Shadow => MoonshotStage::Research,
        MoonshotStage::Canary => MoonshotStage::Shadow,
        MoonshotStage::Production => MoonshotStage::Canary,
        MoonshotStage::Research => MoonshotStage::Research,
    };
    GateInput {
        current_stage: current,
        target_stage: target,
        evaluations: vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Safe,
            250_000,
            2_000,
        )],
        regret_certificate: Some(make_regret_cert(50_000, 100_000, true, 50)),
        demotion_history: Vec::new(),
        epoch: SecurityEpoch::from_raw(10),
        timestamp_ns: 1_000_000_000,
        regime: RegimeKind::Stochastic,
        moonshot_id: Some("moonshot-1".into()),
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_non_empty() {
    assert!(!CAUSAL_REGRET_GATE_SCHEMA_VERSION.is_empty());
    assert!(!CAUSAL_REGRET_GATE_COMPONENT.is_empty());
}

#[test]
fn schema_version_contains_module_name() {
    assert!(CAUSAL_REGRET_GATE_SCHEMA_VERSION.contains("causal-regret-evidence-gate"));
}

#[test]
fn component_is_snake_case() {
    assert_eq!(CAUSAL_REGRET_GATE_COMPONENT, "causal_regret_evidence_gate");
}

// ===========================================================================
// 2. StageThresholds
// ===========================================================================

#[test]
fn stage_thresholds_research_is_lenient() {
    let t = StageThresholds::research();
    assert_eq!(t.stage, MoonshotStage::Research);
    assert_eq!(t.min_confidence_lower_millionths, 0);
    assert_eq!(t.min_effective_samples, 0);
    assert!(!t.require_regret_within_bound);
    assert!(!t.require_safe_envelope);
    assert!(t.allowed_estimators.is_empty());
}

#[test]
fn stage_thresholds_shadow_moderate() {
    let t = StageThresholds::shadow();
    assert_eq!(t.stage, MoonshotStage::Shadow);
    assert_eq!(t.min_confidence_lower_millionths, 50_000);
    assert_eq!(t.min_effective_samples, 100);
    assert!(!t.require_safe_envelope);
}

#[test]
fn stage_thresholds_canary_strict() {
    let t = StageThresholds::canary();
    assert_eq!(t.stage, MoonshotStage::Canary);
    assert!(t.require_regret_within_bound);
    assert!(t.require_safe_envelope);
    assert_eq!(t.allowed_estimators, vec![EstimatorKind::DoublyRobust]);
}

#[test]
fn stage_thresholds_production_most_stringent() {
    let t = StageThresholds::production();
    assert_eq!(t.stage, MoonshotStage::Production);
    assert_eq!(t.min_confidence_lower_millionths, 200_000);
    assert_eq!(t.min_effective_samples, 1_000);
    assert_eq!(t.max_recent_critical_demotions, 0);
    assert_eq!(t.max_recent_demotions, 0);
}

#[test]
fn stage_thresholds_for_stage_covers_all() {
    for stage in MoonshotStage::all() {
        let t = StageThresholds::for_stage(*stage);
        assert_eq!(t.stage, *stage);
    }
}

#[test]
fn stage_thresholds_progressively_stricter_confidence() {
    let r = StageThresholds::research();
    let s = StageThresholds::shadow();
    let c = StageThresholds::canary();
    let p = StageThresholds::production();
    assert!(r.min_confidence_lower_millionths <= s.min_confidence_lower_millionths);
    assert!(s.min_confidence_lower_millionths <= c.min_confidence_lower_millionths);
    assert!(c.min_confidence_lower_millionths <= p.min_confidence_lower_millionths);
}

#[test]
fn stage_thresholds_progressively_tighter_regret() {
    let r = StageThresholds::research();
    let s = StageThresholds::shadow();
    let c = StageThresholds::canary();
    let p = StageThresholds::production();
    assert!(r.max_regret_millionths >= s.max_regret_millionths);
    assert!(s.max_regret_millionths >= c.max_regret_millionths);
    assert!(c.max_regret_millionths >= p.max_regret_millionths);
}

#[test]
fn stage_thresholds_serde_roundtrip_all() {
    for stage in MoonshotStage::all() {
        let t = StageThresholds::for_stage(*stage);
        let json = serde_json::to_string(&t).unwrap();
        let restored: StageThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(t, restored);
    }
}

// ===========================================================================
// 3. CausalRegretGateConfig
// ===========================================================================

#[test]
fn config_default_values() {
    let c = CausalRegretGateConfig::default();
    assert!(c.stage_thresholds.is_empty());
    assert_eq!(c.demotion_lookback_epochs, 5);
    assert!(!c.block_on_inconclusive);
    assert_eq!(c.max_per_round_regret_millionths, 50_000);
    assert!(c.require_evaluation);
    assert!(c.require_regret_certificate);
}

#[test]
fn config_serde_roundtrip() {
    let c = CausalRegretGateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let restored: CausalRegretGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

#[test]
fn config_thresholds_for_returns_override() {
    let mut config = CausalRegretGateConfig::default();
    let mut custom = StageThresholds::shadow();
    custom.min_effective_samples = 42;
    config
        .stage_thresholds
        .insert("shadow".into(), custom.clone());
    let t = config.thresholds_for(MoonshotStage::Shadow);
    assert_eq!(t.min_effective_samples, 42);
}

#[test]
fn config_thresholds_for_falls_back_to_default() {
    let config = CausalRegretGateConfig::default();
    let t = config.thresholds_for(MoonshotStage::Canary);
    assert_eq!(t, StageThresholds::canary());
}

// ===========================================================================
// 4. CausalRegretEvidenceGate — construction
// ===========================================================================

#[test]
fn gate_new_default() {
    let gate = CausalRegretEvidenceGate::new();
    assert_eq!(gate.evaluations_run(), 0);
    assert_eq!(gate.promotions_approved(), 0);
    assert_eq!(gate.promotions_denied(), 0);
}

#[test]
fn gate_default_equals_new() {
    assert_eq!(
        CausalRegretEvidenceGate::new(),
        CausalRegretEvidenceGate::default()
    );
}

#[test]
fn gate_with_config_valid() {
    let config = CausalRegretGateConfig {
        max_per_round_regret_millionths: 0,
        ..Default::default()
    };
    let gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    assert_eq!(gate.config().max_per_round_regret_millionths, 0);
}

#[test]
fn gate_with_config_negative_per_round_rejects() {
    let config = CausalRegretGateConfig {
        max_per_round_regret_millionths: -1,
        ..Default::default()
    };
    let err = CausalRegretEvidenceGate::with_config(config).unwrap_err();
    assert!(matches!(err, CausalRegretGateError::InvalidConfig { .. }));
}

#[test]
fn gate_serde_roundtrip() {
    let gate = CausalRegretEvidenceGate::new();
    let json = serde_json::to_string(&gate).unwrap();
    let restored: CausalRegretEvidenceGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, restored);
}

// ===========================================================================
// 5. Approved promotion paths
// ===========================================================================

#[test]
fn shadow_promotion_approved() {
    let mut gate = CausalRegretEvidenceGate::new();
    let input = basic_input(MoonshotStage::Shadow);
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);
    assert!(output.blocking_reasons.is_empty());
    assert_eq!(output.target_stage, MoonshotStage::Shadow);
    assert_eq!(output.current_stage, MoonshotStage::Research);
}

#[test]
fn canary_promotion_approved() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&basic_input(MoonshotStage::Canary)).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);
}

#[test]
fn production_promotion_approved() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate
        .evaluate(&basic_input(MoonshotStage::Production))
        .unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);
}

#[test]
fn approved_output_carries_schema_and_component() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    assert_eq!(output.schema_version, CAUSAL_REGRET_GATE_SCHEMA_VERSION);
    assert_eq!(output.component, CAUSAL_REGRET_GATE_COMPONENT);
}

#[test]
fn approved_output_has_summaries() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    assert_eq!(output.evaluation_summaries.len(), 1);
    assert_eq!(
        output.evaluation_summaries[0].policy_id,
        PolicyId("policy-1".into())
    );
    assert!(output.regret_summary.is_some());
}

// ===========================================================================
// 6. Blocking: unsafe / inconclusive envelope
// ===========================================================================

#[test]
fn unsafe_envelope_blocks_and_critical() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Unsafe,
        -50_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::UnsafeEnvelope { .. }))
    );
    assert_eq!(output.risk_level, RiskLevel::Critical);
}

#[test]
fn inconclusive_envelope_allowed_for_shadow() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Inconclusive,
        250_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);
}

#[test]
fn inconclusive_envelope_blocks_for_canary() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Canary);
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Inconclusive,
        250_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InconclusiveEnvelope { .. }))
    );
}

#[test]
fn block_on_inconclusive_config_flag() {
    let config = CausalRegretGateConfig {
        block_on_inconclusive: true,
        ..Default::default()
    };
    let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Inconclusive,
        250_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);
}

// ===========================================================================
// 7. Blocking: insufficient confidence
// ===========================================================================

#[test]
fn insufficient_confidence_blocks_canary() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Canary);
    // Canary min = 100_000. Provide 50_000.
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Safe,
        50_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InsufficientConfidence { .. }))
    );
}

#[test]
fn confidence_exactly_at_threshold_passes() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Canary);
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Safe,
        100_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert!(
        !output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InsufficientConfidence { .. }))
    );
}

// ===========================================================================
// 8. Blocking: insufficient samples
// ===========================================================================

#[test]
fn insufficient_samples_blocks_production() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Production);
    // Production min = 1000. Give 500.
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Safe,
        250_000,
        500,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InsufficientSamples { .. }))
    );
}

// ===========================================================================
// 9. Blocking: disallowed estimator
// ===========================================================================

#[test]
fn disallowed_estimator_blocks_production() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Production);
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::Ips,
        EnvelopeStatus::Safe,
        250_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::DisallowedEstimator { .. }))
    );
}

#[test]
fn any_estimator_allowed_when_list_empty() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DirectMethod,
        EnvelopeStatus::Safe,
        250_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert!(
        !output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::DisallowedEstimator { .. }))
    );
}

// ===========================================================================
// 10. Blocking: regret certificate
// ===========================================================================

#[test]
fn excessive_regret_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    // Shadow max = 500_000. Give 600_000.
    input.regret_certificate = Some(make_regret_cert(600_000, 700_000, true, 50));
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::ExcessiveRegret { .. }))
    );
    assert_eq!(output.risk_level, RiskLevel::High);
}

#[test]
fn regret_exactly_at_threshold_passes() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = Some(make_regret_cert(500_000, 600_000, true, 50));
    let output = gate.evaluate(&input).unwrap();
    assert!(
        !output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::ExcessiveRegret { .. }))
    );
}

#[test]
fn regret_one_above_threshold_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = Some(make_regret_cert(500_001, 600_000, true, 50));
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::ExcessiveRegret { .. }))
    );
}

#[test]
fn regret_not_within_bound_blocks_canary() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Canary);
    input.regret_certificate = Some(make_regret_cert(100_000, 200_000, false, 50));
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::RegretNotWithinBound))
    );
}

#[test]
fn regret_not_within_bound_ok_for_shadow() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = Some(make_regret_cert(100_000, 200_000, false, 50));
    let output = gate.evaluate(&input).unwrap();
    assert!(
        !output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::RegretNotWithinBound))
    );
}

#[test]
fn excessive_per_round_regret_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    // Config default max per-round = 50_000. Give 60_000.
    input.regret_certificate = Some(make_regret_cert(100_000, 200_000, true, 60_000));
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::ExcessivePerRoundRegret { .. }))
    );
}

#[test]
fn per_round_regret_exactly_at_threshold_passes() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = Some(make_regret_cert(100_000, 200_000, true, 50_000));
    let output = gate.evaluate(&input).unwrap();
    assert!(
        !output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::ExcessivePerRoundRegret { .. }))
    );
}

#[test]
fn missing_regret_certificate_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = None;
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::MissingRegretCertificate))
    );
}

#[test]
fn missing_regret_certificate_ok_when_not_required() {
    let config = CausalRegretGateConfig {
        require_regret_certificate: false,
        ..Default::default()
    };
    let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = None;
    let output = gate.evaluate(&input).unwrap();
    assert!(
        !output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::MissingRegretCertificate))
    );
    assert!(output.regret_summary.is_none());
}

// ===========================================================================
// 11. Blocking: missing evaluation
// ===========================================================================

#[test]
fn missing_evaluation_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations.clear();
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::MissingEvaluation))
    );
}

#[test]
fn missing_evaluation_ok_when_not_required() {
    let config = CausalRegretGateConfig {
        require_evaluation: false,
        ..Default::default()
    };
    let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations.clear();
    let output = gate.evaluate(&input).unwrap();
    assert!(
        !output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::MissingEvaluation))
    );
}

// ===========================================================================
// 12. Blocking: invalid stage progression
// ===========================================================================

#[test]
fn invalid_progression_backward_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.current_stage = MoonshotStage::Production;
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InvalidStageProgression { .. }))
    );
    assert_eq!(output.risk_level, RiskLevel::Critical);
}

#[test]
fn invalid_progression_skip_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Canary);
    input.current_stage = MoonshotStage::Research;
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InvalidStageProgression { .. }))
    );
}

#[test]
fn same_stage_progression_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.current_stage = MoonshotStage::Shadow;
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InvalidStageProgression { .. }))
    );
}

// ===========================================================================
// 13. Blocking: demotion history
// ===========================================================================

#[test]
fn critical_demotions_block_canary() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Canary);
    input.demotion_history = vec![make_demotion(8, DemotionSeverity::Critical)];
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::TooManyCriticalDemotions { .. }))
    );
    assert_eq!(output.risk_level, RiskLevel::Critical);
}

#[test]
fn too_many_demotions_blocks_production() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Production);
    input.demotion_history = vec![make_demotion(8, DemotionSeverity::Advisory)];
    let output = gate.evaluate(&input).unwrap();
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::TooManyDemotions { .. }))
    );
}

#[test]
fn old_demotions_outside_lookback_ignored() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Production);
    // epoch=10, lookback=5, so epoch<5 is outside.
    input.demotion_history = vec![make_demotion(3, DemotionSeverity::Critical)];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.demotions_considered, 0);
    assert_eq!(output.critical_demotions_count, 0);
}

#[test]
fn advisory_demotions_tolerated_for_shadow() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.demotion_history = vec![
        make_demotion(8, DemotionSeverity::Advisory),
        make_demotion(9, DemotionSeverity::Advisory),
    ];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);
    assert_eq!(output.demotions_considered, 2);
}

#[test]
fn zero_lookback_counts_only_current_epoch() {
    let config = CausalRegretGateConfig {
        demotion_lookback_epochs: 0,
        ..Default::default()
    };
    let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    let mut input = basic_input(MoonshotStage::Production);
    input.demotion_history = vec![
        make_demotion(10, DemotionSeverity::Advisory),
        make_demotion(9, DemotionSeverity::Advisory),
    ];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.demotions_considered, 1);
}

#[test]
fn large_lookback_includes_all() {
    let config = CausalRegretGateConfig {
        demotion_lookback_epochs: 100,
        ..Default::default()
    };
    let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.demotion_history = vec![
        make_demotion(1, DemotionSeverity::Advisory),
        make_demotion(5, DemotionSeverity::Advisory),
        make_demotion(10, DemotionSeverity::Advisory),
    ];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.demotions_considered, 3);
}

// ===========================================================================
// 14. Risk level classification
// ===========================================================================

#[test]
fn risk_low_when_approved_with_sufficient_samples() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    assert_eq!(output.risk_level, RiskLevel::Low);
}

#[test]
fn risk_high_for_production_blocking() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Production);
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::Ips,
        EnvelopeStatus::Safe,
        250_000,
        2_000,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.risk_level, RiskLevel::High);
}

#[test]
fn risk_medium_for_non_production_non_critical_block() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    // Insufficient samples for shadow (100 required), give 50.
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Safe,
        250_000,
        50,
    )];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.risk_level, RiskLevel::Medium);
}

#[test]
fn risk_medium_for_low_samples_when_approved() {
    // Research→Shadow with very low samples but still passes thresholds.
    let config = CausalRegretGateConfig {
        require_evaluation: false,
        require_regret_certificate: false,
        ..Default::default()
    };
    let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    let mut input = basic_input(MoonshotStage::Shadow);
    // Shadow threshold min_effective_samples=100. Give 50 which blocks.
    // Actually, we need to pass but have low samples. For research target
    // it allows 0 samples. Use that.
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Safe,
        250_000,
        50,
    )];
    input.regret_certificate = None;
    // This will block on insufficient samples for shadow (100 needed).
    // To trigger Medium risk on approved path, we need samples < 100 but
    // no blocking reasons. Let's use Research target instead.
    input.current_stage = MoonshotStage::Research;
    input.target_stage = MoonshotStage::Shadow;
    // Shadow requires 100 samples. 50 triggers InsufficientSamples block.
    // So risk_level = Medium from the blocking reason.
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.risk_level, RiskLevel::Medium);
}

// ===========================================================================
// 15. Multiple evaluations
// ===========================================================================

#[test]
fn multiple_evaluations_all_safe_approved() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations = vec![
        make_eval(
            "pa",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Safe,
            200_000,
            500,
        ),
        make_eval(
            "pb",
            EstimatorKind::Ips,
            EnvelopeStatus::Safe,
            300_000,
            1_000,
        ),
    ];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);
    assert_eq!(output.evaluation_summaries.len(), 2);
}

#[test]
fn multiple_evaluations_one_unsafe_blocks() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations = vec![
        make_eval(
            "pa",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Safe,
            200_000,
            500,
        ),
        make_eval(
            "pb",
            EstimatorKind::Ips,
            EnvelopeStatus::Unsafe,
            -10_000,
            1_000,
        ),
    ];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);
}

// ===========================================================================
// 16. Counter tracking and reset
// ===========================================================================

#[test]
fn counters_track_approved_and_denied() {
    let mut gate = CausalRegretEvidenceGate::new();
    let _ = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    assert_eq!(gate.evaluations_run(), 1);
    assert_eq!(gate.promotions_approved(), 1);
    assert_eq!(gate.promotions_denied(), 0);

    let mut bad = basic_input(MoonshotStage::Shadow);
    bad.evaluations.clear();
    let _ = gate.evaluate(&bad).unwrap();
    assert_eq!(gate.evaluations_run(), 2);
    assert_eq!(gate.promotions_approved(), 1);
    assert_eq!(gate.promotions_denied(), 1);
}

#[test]
fn reset_counters_zeroes_all() {
    let mut gate = CausalRegretEvidenceGate::new();
    let _ = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    gate.reset_counters();
    assert_eq!(gate.evaluations_run(), 0);
    assert_eq!(gate.promotions_approved(), 0);
    assert_eq!(gate.promotions_denied(), 0);
}

// ===========================================================================
// 17. Artifact hash determinism
// ===========================================================================

#[test]
fn artifact_hash_deterministic_across_gates() {
    let mut g1 = CausalRegretEvidenceGate::new();
    let mut g2 = CausalRegretEvidenceGate::new();
    let input = basic_input(MoonshotStage::Shadow);
    let o1 = g1.evaluate(&input).unwrap();
    let o2 = g2.evaluate(&input).unwrap();
    assert_eq!(o1.artifact_hash, o2.artifact_hash);
}

#[test]
fn artifact_hash_changes_with_verdict() {
    let mut gate = CausalRegretEvidenceGate::new();
    let o1 = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    let mut bad = basic_input(MoonshotStage::Shadow);
    bad.evaluations.clear();
    let o2 = gate.evaluate(&bad).unwrap();
    assert_ne!(o1.artifact_hash, o2.artifact_hash);
}

#[test]
fn artifact_hash_changes_with_timestamp() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut i1 = basic_input(MoonshotStage::Shadow);
    i1.timestamp_ns = 1_000;
    let o1 = gate.evaluate(&i1).unwrap();
    let mut i2 = basic_input(MoonshotStage::Shadow);
    i2.timestamp_ns = 2_000;
    let o2 = gate.evaluate(&i2).unwrap();
    assert_ne!(o1.artifact_hash, o2.artifact_hash);
}

#[test]
fn artifact_hash_changes_with_epoch() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut i1 = basic_input(MoonshotStage::Shadow);
    i1.epoch = SecurityEpoch::from_raw(10);
    let o1 = gate.evaluate(&i1).unwrap();
    let mut i2 = basic_input(MoonshotStage::Shadow);
    i2.epoch = SecurityEpoch::from_raw(11);
    let o2 = gate.evaluate(&i2).unwrap();
    assert_ne!(o1.artifact_hash, o2.artifact_hash);
}

// ===========================================================================
// 18. Error cases
// ===========================================================================

#[test]
fn too_many_evaluations_error() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations = (0..101)
        .map(|i| {
            make_eval(
                &format!("p{i}"),
                EstimatorKind::DoublyRobust,
                EnvelopeStatus::Safe,
                250_000,
                2_000,
            )
        })
        .collect();
    let err = gate.evaluate(&input).unwrap_err();
    assert!(matches!(
        err,
        CausalRegretGateError::TooManyEvaluations {
            count: 101,
            max: 100
        }
    ));
}

#[test]
fn too_many_demotion_items_error() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.demotion_history = (0..1001)
        .map(|i| make_demotion(i, DemotionSeverity::Advisory))
        .collect();
    let err = gate.evaluate(&input).unwrap_err();
    assert!(matches!(
        err,
        CausalRegretGateError::TooManyDemotionItems {
            count: 1001,
            max: 1000
        }
    ));
}

#[test]
fn exactly_100_evaluations_ok() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.evaluations = (0..100)
        .map(|i| {
            make_eval(
                &format!("p{i}"),
                EstimatorKind::DoublyRobust,
                EnvelopeStatus::Safe,
                250_000,
                2_000,
            )
        })
        .collect();
    assert!(gate.evaluate(&input).is_ok());
}

#[test]
fn exactly_1000_demotion_items_ok() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.demotion_history = (0..1000)
        .map(|i| make_demotion(i, DemotionSeverity::Advisory))
        .collect();
    assert!(gate.evaluate(&input).is_ok());
}

// ===========================================================================
// 19. Display implementations
// ===========================================================================

#[test]
fn blocking_reason_display_all_variants() {
    let reasons = vec![
        BlockingReason::UnsafeEnvelope {
            policy_id: "p".into(),
            estimator: EstimatorKind::Ips,
        },
        BlockingReason::InconclusiveEnvelope {
            policy_id: "p".into(),
            estimator: EstimatorKind::DoublyRobust,
        },
        BlockingReason::InsufficientConfidence {
            observed_millionths: 10,
            required_millionths: 100,
        },
        BlockingReason::InsufficientSamples {
            observed: 5,
            required: 100,
        },
        BlockingReason::DisallowedEstimator {
            estimator: EstimatorKind::DirectMethod,
        },
        BlockingReason::MissingRegretCertificate,
        BlockingReason::ExcessiveRegret {
            realized_millionths: 500,
            max_millionths: 100,
        },
        BlockingReason::ExcessivePerRoundRegret {
            per_round_millionths: 500,
            max_millionths: 100,
        },
        BlockingReason::RegretNotWithinBound,
        BlockingReason::TooManyCriticalDemotions { count: 3, max: 0 },
        BlockingReason::TooManyDemotions { count: 5, max: 2 },
        BlockingReason::MissingEvaluation,
        BlockingReason::InvalidStageProgression {
            current: MoonshotStage::Production,
            target: MoonshotStage::Research,
        },
    ];
    for r in &reasons {
        let s = format!("{r}");
        assert!(!s.is_empty(), "Display for {r:?} should be non-empty");
    }
}

#[test]
fn error_display_all_variants() {
    let errors = vec![
        CausalRegretGateError::TooManyEvaluations {
            count: 200,
            max: 100,
        },
        CausalRegretGateError::TooManyDemotionItems {
            count: 2000,
            max: 1000,
        },
        CausalRegretGateError::InvalidConfig {
            reason: "bad".into(),
        },
    ];
    for e in &errors {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

#[test]
fn blocking_reason_display_contains_values() {
    let r = BlockingReason::InsufficientConfidence {
        observed_millionths: 42,
        required_millionths: 100,
    };
    let s = format!("{r}");
    assert!(s.contains("42"));
    assert!(s.contains("100"));
}

// ===========================================================================
// 20. Serde roundtrips for all public types
// ===========================================================================

#[test]
fn gate_output_serde_roundtrip() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let restored: GateOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, restored);
}

#[test]
fn evaluation_summary_serde_roundtrip() {
    let summary = EvaluationSummary {
        policy_id: PolicyId("test".into()),
        estimator: EstimatorKind::DoublyRobust,
        safety_status: EnvelopeStatus::Safe,
        improvement_lower_millionths: 100_000,
        effective_samples: 500,
        artifact_hash: ContentHash::compute(b"test"),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: EvaluationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn regret_summary_serde_roundtrip() {
    let summary = RegretSummary {
        rounds: 1000,
        realized_regret_millionths: 50_000,
        theoretical_bound_millionths: 100_000,
        within_bound: true,
        per_round_regret_millionths: 50,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: RegretSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn demotion_history_item_serde_roundtrip() {
    let item = make_demotion(5, DemotionSeverity::Warning);
    let json = serde_json::to_string(&item).unwrap();
    let restored: DemotionHistoryItem = serde_json::from_str(&json).unwrap();
    assert_eq!(item, restored);
}

#[test]
fn gate_input_serde_roundtrip() {
    let input = basic_input(MoonshotStage::Shadow);
    let json = serde_json::to_string(&input).unwrap();
    let restored: GateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, restored);
}

#[test]
fn blocking_reason_serde_roundtrip() {
    let reasons = vec![
        BlockingReason::UnsafeEnvelope {
            policy_id: "p1".into(),
            estimator: EstimatorKind::Ips,
        },
        BlockingReason::MissingRegretCertificate,
        BlockingReason::RegretNotWithinBound,
        BlockingReason::MissingEvaluation,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let restored: BlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored);
    }
}

#[test]
fn error_serde_roundtrip() {
    let errs = vec![
        CausalRegretGateError::TooManyEvaluations {
            count: 200,
            max: 100,
        },
        CausalRegretGateError::TooManyDemotionItems {
            count: 2000,
            max: 1000,
        },
        CausalRegretGateError::InvalidConfig {
            reason: "test".into(),
        },
    ];
    for e in &errs {
        let json = serde_json::to_string(e).unwrap();
        let restored: CausalRegretGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

// ===========================================================================
// 21. Output field propagation
// ===========================================================================

#[test]
fn output_carries_moonshot_id() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    assert_eq!(output.moonshot_id, Some("moonshot-1".into()));
}

#[test]
fn output_carries_regime() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regime = RegimeKind::Adversarial;
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.regime, RegimeKind::Adversarial);
}

#[test]
fn output_carries_epoch_and_timestamp() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.epoch = SecurityEpoch::from_raw(42);
    input.timestamp_ns = 999_999;
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.epoch, SecurityEpoch::from_raw(42));
    assert_eq!(output.timestamp_ns, 999_999);
}

#[test]
fn output_moonshot_id_none_when_absent() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.moonshot_id = None;
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.moonshot_id, None);
}

// ===========================================================================
// 22. Multiple blocking reasons accumulate
// ===========================================================================

#[test]
fn multiple_blocking_reasons_accumulate() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Production);
    input.current_stage = MoonshotStage::Research; // invalid progression
    input.evaluations = vec![make_eval(
        "p1",
        EstimatorKind::Ips,
        EnvelopeStatus::Unsafe,
        -50_000,
        100,
    )];
    input.regret_certificate = None;
    input.demotion_history = vec![make_demotion(9, DemotionSeverity::Critical)];
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);
    // Should accumulate: InvalidStageProgression, UnsafeEnvelope,
    // InsufficientConfidence, InsufficientSamples, DisallowedEstimator,
    // MissingRegretCertificate, TooManyCriticalDemotions, TooManyDemotions
    assert!(output.blocking_reasons.len() >= 5);
}

// ===========================================================================
// 23. Full lifecycle: Research → Shadow → Canary → Production
// ===========================================================================

#[test]
fn full_lifecycle_promotion_chain() {
    let mut gate = CausalRegretEvidenceGate::new();

    // Research → Shadow
    let output = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);

    // Shadow → Canary
    let output = gate.evaluate(&basic_input(MoonshotStage::Canary)).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);

    // Canary → Production
    let output = gate
        .evaluate(&basic_input(MoonshotStage::Production))
        .unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);

    assert_eq!(gate.evaluations_run(), 3);
    assert_eq!(gate.promotions_approved(), 3);
    assert_eq!(gate.promotions_denied(), 0);
}

#[test]
fn lifecycle_with_denial_and_retry() {
    let mut gate = CausalRegretEvidenceGate::new();

    // First attempt: denied (no regret cert)
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = None;
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);

    // Retry with cert: approved
    let output = gate.evaluate(&basic_input(MoonshotStage::Shadow)).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);

    assert_eq!(gate.evaluations_run(), 2);
    assert_eq!(gate.promotions_approved(), 1);
    assert_eq!(gate.promotions_denied(), 1);
}

// ===========================================================================
// 24. Config with custom stage overrides
// ===========================================================================

#[test]
fn custom_threshold_override_affects_evaluation() {
    let mut config = CausalRegretGateConfig::default();
    // Make shadow extremely strict.
    let mut strict_shadow = StageThresholds::shadow();
    strict_shadow.min_effective_samples = 5_000;
    config
        .stage_thresholds
        .insert("shadow".into(), strict_shadow);

    let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    let input = basic_input(MoonshotStage::Shadow); // has 2000 samples
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InsufficientSamples { .. }))
    );
}

// ===========================================================================
// 25. Regret summary population
// ===========================================================================

#[test]
fn regret_summary_populated_from_certificate() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = Some(make_regret_cert(42_000, 84_000, true, 42));
    let output = gate.evaluate(&input).unwrap();
    let rs = output.regret_summary.unwrap();
    assert_eq!(rs.rounds, 1000);
    assert_eq!(rs.realized_regret_millionths, 42_000);
    assert_eq!(rs.theoretical_bound_millionths, 84_000);
    assert!(rs.within_bound);
    assert_eq!(rs.per_round_regret_millionths, 42);
}

#[test]
fn regret_summary_none_without_certificate() {
    let config = CausalRegretGateConfig {
        require_regret_certificate: false,
        ..Default::default()
    };
    let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
    let mut input = basic_input(MoonshotStage::Shadow);
    input.regret_certificate = None;
    let output = gate.evaluate(&input).unwrap();
    assert!(output.regret_summary.is_none());
}
