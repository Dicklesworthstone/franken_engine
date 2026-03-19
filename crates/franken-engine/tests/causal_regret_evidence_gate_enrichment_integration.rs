//! Enrichment integration tests for `causal_regret_evidence_gate` module.
//!
//! Deep coverage of serde roundtrips, Display distinctness, configuration,
//! blocking reason coverage, and evaluation lifecycle.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
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
// Helpers — match existing test patterns exactly
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

fn make_demotion(epoch_val: u64, severity: DemotionSeverity) -> DemotionHistoryItem {
    DemotionHistoryItem {
        epoch: SecurityEpoch::from_raw(epoch_val),
        reason: DemotionReason::PerformanceBreach {
            metric_name: "latency".into(),
            observed_millionths: 500_000,
            threshold_millionths: 200_000,
            sustained_duration_ns: 1_000_000,
        },
        severity,
        timestamp_ns: epoch_val * 1_000_000_000,
    }
}

fn safe_research_input() -> GateInput {
    let current = MoonshotStage::Research;
    let target = MoonshotStage::Shadow;
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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrich_constants_nonempty() {
    assert!(!CAUSAL_REGRET_GATE_SCHEMA_VERSION.is_empty());
    assert!(!CAUSAL_REGRET_GATE_COMPONENT.is_empty());
}

#[test]
fn enrich_schema_version_format() {
    assert!(CAUSAL_REGRET_GATE_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ---------------------------------------------------------------------------
// StageThresholds — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_stage_thresholds_research_permissive() {
    let t = StageThresholds::research();
    assert_eq!(t.stage, MoonshotStage::Research);
    assert_eq!(t.min_confidence_lower_millionths, 0);
    assert_eq!(t.min_effective_samples, 0);
    assert!(!t.require_regret_within_bound);
    assert!(!t.require_safe_envelope);
}

#[test]
fn enrich_stage_thresholds_production_strict() {
    let t = StageThresholds::production();
    assert_eq!(t.stage, MoonshotStage::Production);
    assert!(t.min_confidence_lower_millionths > 0);
    assert!(t.min_effective_samples > 0);
    assert!(t.require_regret_within_bound);
    assert!(t.require_safe_envelope);
    assert_eq!(t.max_recent_demotions, 0);
    assert_eq!(t.max_recent_critical_demotions, 0);
}

#[test]
fn enrich_stage_thresholds_shadow_moderate() {
    let t = StageThresholds::shadow();
    assert_eq!(t.stage, MoonshotStage::Shadow);
    assert!(t.min_confidence_lower_millionths > 0);
    assert!(t.max_recent_demotions > 0);
}

#[test]
fn enrich_stage_thresholds_canary_strict() {
    let t = StageThresholds::canary();
    assert_eq!(t.stage, MoonshotStage::Canary);
    assert!(t.require_regret_within_bound);
    assert!(t.require_safe_envelope);
}

#[test]
fn enrich_stage_thresholds_for_stage_all() {
    let stages = [
        MoonshotStage::Research,
        MoonshotStage::Shadow,
        MoonshotStage::Canary,
        MoonshotStage::Production,
    ];
    for stage in &stages {
        let t = StageThresholds::for_stage(*stage);
        assert_eq!(t.stage, *stage);
    }
}

#[test]
fn enrich_stage_thresholds_serde_roundtrip() {
    let t = StageThresholds::canary();
    let json = serde_json::to_string(&t).unwrap();
    let back: StageThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrich_stage_thresholds_progressive_strictness() {
    let research = StageThresholds::research();
    let shadow = StageThresholds::shadow();
    let canary = StageThresholds::canary();
    let production = StageThresholds::production();
    assert!(research.min_confidence_lower_millionths <= shadow.min_confidence_lower_millionths);
    assert!(shadow.min_confidence_lower_millionths <= canary.min_confidence_lower_millionths);
    assert!(canary.min_confidence_lower_millionths <= production.min_confidence_lower_millionths);
}

// ---------------------------------------------------------------------------
// CausalRegretGateConfig — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_config_default_values() {
    let c = CausalRegretGateConfig::default();
    assert!(c.require_evaluation);
    assert!(c.require_regret_certificate);
    assert!(!c.block_on_inconclusive);
    assert!(c.demotion_lookback_epochs > 0);
}

#[test]
fn enrich_config_serde_roundtrip() {
    let c = CausalRegretGateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: CausalRegretGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrich_config_thresholds_for_default_stage() {
    let c = CausalRegretGateConfig::default();
    let t = c.thresholds_for(MoonshotStage::Shadow);
    assert_eq!(t.stage, MoonshotStage::Shadow);
}

// ---------------------------------------------------------------------------
// DemotionHistoryItem — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_demotion_history_item_serde_roundtrip() {
    let item = make_demotion(10, DemotionSeverity::Critical);
    let json = serde_json::to_string(&item).unwrap();
    let back: DemotionHistoryItem = serde_json::from_str(&json).unwrap();
    assert_eq!(item, back);
}

#[test]
fn enrich_demotion_history_item_warning_severity() {
    let item = make_demotion(20, DemotionSeverity::Warning);
    assert_eq!(item.severity, DemotionSeverity::Warning);
}

// ---------------------------------------------------------------------------
// BlockingReason — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_blocking_reason_display_distinct() {
    let reasons: Vec<BlockingReason> = vec![
        BlockingReason::UnsafeEnvelope {
            policy_id: "p".to_string(),
            estimator: EstimatorKind::DoublyRobust,
        },
        BlockingReason::InconclusiveEnvelope {
            policy_id: "p".to_string(),
            estimator: EstimatorKind::Ips,
        },
        BlockingReason::InsufficientConfidence {
            observed_millionths: 1,
            required_millionths: 2,
        },
        BlockingReason::InsufficientSamples {
            observed: 1,
            required: 2,
        },
        BlockingReason::DisallowedEstimator {
            estimator: EstimatorKind::Ips,
        },
        BlockingReason::MissingRegretCertificate,
        BlockingReason::ExcessiveRegret {
            realized_millionths: 1,
            max_millionths: 0,
        },
        BlockingReason::ExcessivePerRoundRegret {
            per_round_millionths: 1,
            max_millionths: 0,
        },
        BlockingReason::RegretNotWithinBound,
        BlockingReason::TooManyCriticalDemotions { count: 5, max: 3 },
        BlockingReason::TooManyDemotions { count: 10, max: 5 },
        BlockingReason::MissingEvaluation,
        BlockingReason::InvalidStageProgression {
            current: MoonshotStage::Production,
            target: MoonshotStage::Research,
        },
    ];
    let displays: std::collections::BTreeSet<String> =
        reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), reasons.len());
}

#[test]
fn enrich_blocking_reason_serde_all_variants() {
    let reasons: Vec<BlockingReason> = vec![
        BlockingReason::UnsafeEnvelope {
            policy_id: "pol".to_string(),
            estimator: EstimatorKind::DoublyRobust,
        },
        BlockingReason::MissingRegretCertificate,
        BlockingReason::RegretNotWithinBound,
        BlockingReason::MissingEvaluation,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: BlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// EvaluationSummary — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_evaluation_summary_serde_roundtrip() {
    let s = EvaluationSummary {
        policy_id: PolicyId("test-pol".to_string()),
        estimator: EstimatorKind::DoublyRobust,
        safety_status: EnvelopeStatus::Safe,
        improvement_lower_millionths: 50_000,
        effective_samples: 500,
        artifact_hash: ContentHash::compute(b"art"),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: EvaluationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// RegretSummary — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_regret_summary_serde_roundtrip() {
    let s = RegretSummary {
        rounds: 100,
        realized_regret_millionths: 10_000,
        theoretical_bound_millionths: 50_000,
        within_bound: true,
        per_round_regret_millionths: 100,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: RegretSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// CausalRegretGateError — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_error_display_too_many_evaluations() {
    let e = CausalRegretGateError::TooManyEvaluations {
        count: 200,
        max: 100,
    };
    let s = e.to_string();
    assert!(s.contains("200"));
    assert!(s.contains("100"));
}

#[test]
fn enrich_gate_error_display_too_many_demotions() {
    let e = CausalRegretGateError::TooManyDemotionItems {
        count: 2000,
        max: 1000,
    };
    let s = e.to_string();
    assert!(s.contains("2000"));
}

#[test]
fn enrich_gate_error_display_invalid_config() {
    let e = CausalRegretGateError::InvalidConfig {
        reason: "bad value".to_string(),
    };
    assert!(e.to_string().contains("bad value"));
}

#[test]
fn enrich_gate_error_serde_roundtrip() {
    let errors = vec![
        CausalRegretGateError::TooManyEvaluations { count: 1, max: 0 },
        CausalRegretGateError::TooManyDemotionItems { count: 2, max: 1 },
        CausalRegretGateError::InvalidConfig {
            reason: "test".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: CausalRegretGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// CausalRegretEvidenceGate — construction
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_new_zero_counters() {
    let gate = CausalRegretEvidenceGate::new();
    assert_eq!(gate.evaluations_run(), 0);
    assert_eq!(gate.promotions_approved(), 0);
    assert_eq!(gate.promotions_denied(), 0);
}

#[test]
fn enrich_gate_with_config_valid() {
    let config = CausalRegretGateConfig::default();
    let gate = CausalRegretEvidenceGate::with_config(config.clone()).unwrap();
    assert_eq!(*gate.config(), config);
}

#[test]
fn enrich_gate_with_config_negative_regret_rejected() {
    let mut config = CausalRegretGateConfig::default();
    config.max_per_round_regret_millionths = -1;
    let err = CausalRegretEvidenceGate::with_config(config).unwrap_err();
    assert!(matches!(err, CausalRegretGateError::InvalidConfig { .. }));
}

#[test]
fn enrich_gate_serde_roundtrip() {
    let gate = CausalRegretEvidenceGate::new();
    let json = serde_json::to_string(&gate).unwrap();
    let back: CausalRegretEvidenceGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}

// ---------------------------------------------------------------------------
// CausalRegretEvidenceGate — evaluate
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_evaluate_research_to_shadow_approved() {
    let mut gate = CausalRegretEvidenceGate::new();
    let input = safe_research_input();
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Approved);
    assert!(output.blocking_reasons.is_empty());
    assert_eq!(output.target_stage, MoonshotStage::Shadow);
    assert_eq!(output.current_stage, MoonshotStage::Research);
    assert_eq!(gate.evaluations_run(), 1);
    assert_eq!(gate.promotions_approved(), 1);
}

#[test]
fn enrich_gate_evaluate_missing_evaluation_blocked() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = safe_research_input();
    input.evaluations.clear();
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::MissingEvaluation))
    );
}

#[test]
fn enrich_gate_evaluate_unsafe_envelope_blocked() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = safe_research_input();
    input.evaluations = vec![make_eval(
        "pol-unsafe",
        EstimatorKind::DoublyRobust,
        EnvelopeStatus::Unsafe,
        250_000,
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
}

#[test]
fn enrich_gate_evaluate_counters_increment() {
    let mut gate = CausalRegretEvidenceGate::new();

    // Approved
    let output1 = gate.evaluate(&safe_research_input()).unwrap();
    assert_eq!(output1.verdict, GateVerdict::Approved);
    assert_eq!(gate.evaluations_run(), 1);
    assert_eq!(gate.promotions_approved(), 1);

    // Denied (missing evaluation)
    let mut denied_input = safe_research_input();
    denied_input.evaluations.clear();
    let output2 = gate.evaluate(&denied_input).unwrap();
    assert_eq!(output2.verdict, GateVerdict::Denied);
    assert_eq!(gate.evaluations_run(), 2);
    assert_eq!(gate.promotions_denied(), 1);
}

#[test]
fn enrich_gate_evaluate_output_schema_version() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&safe_research_input()).unwrap();
    assert_eq!(output.schema_version, CAUSAL_REGRET_GATE_SCHEMA_VERSION);
    assert_eq!(output.component, CAUSAL_REGRET_GATE_COMPONENT);
}

#[test]
fn enrich_gate_evaluate_output_serde_roundtrip() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&safe_research_input()).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let back: GateOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn enrich_gate_evaluate_output_has_evaluation_summaries() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&safe_research_input()).unwrap();
    assert_eq!(output.evaluation_summaries.len(), 1);
    assert_eq!(
        output.evaluation_summaries[0].estimator,
        EstimatorKind::DoublyRobust
    );
}

#[test]
fn enrich_gate_evaluate_output_has_regret_summary() {
    let mut gate = CausalRegretEvidenceGate::new();
    let output = gate.evaluate(&safe_research_input()).unwrap();
    assert!(output.regret_summary.is_some());
    let rs = output.regret_summary.unwrap();
    assert!(rs.within_bound);
}

#[test]
fn enrich_gate_evaluate_invalid_progression() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = safe_research_input();
    input.current_stage = MoonshotStage::Production;
    input.target_stage = MoonshotStage::Research;
    let output = gate.evaluate(&input).unwrap();
    assert_eq!(output.verdict, GateVerdict::Denied);
    assert!(
        output
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, BlockingReason::InvalidStageProgression { .. }))
    );
}

// ---------------------------------------------------------------------------
// GateInput — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_input_serde_roundtrip() {
    let input = safe_research_input();
    let json = serde_json::to_string(&input).unwrap();
    let back: GateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn enrich_gate_input_with_demotion_history() {
    let mut input = safe_research_input();
    input.demotion_history = vec![make_demotion(5, DemotionSeverity::Warning)];
    let json = serde_json::to_string(&input).unwrap();
    let back: GateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.demotion_history.len(), 1);
}

#[test]
fn enrich_gate_evaluate_with_demotion_history() {
    let mut gate = CausalRegretEvidenceGate::new();
    let mut input = safe_research_input();
    input.demotion_history = vec![
        make_demotion(8, DemotionSeverity::Warning),
        make_demotion(9, DemotionSeverity::Warning),
    ];
    let output = gate.evaluate(&input).unwrap();
    // Research -> Shadow is permissive, so should still approve
    assert_eq!(output.verdict, GateVerdict::Approved);
    assert_eq!(output.demotions_considered, 2);
}
