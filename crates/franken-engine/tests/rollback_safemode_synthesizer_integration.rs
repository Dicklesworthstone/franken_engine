use frankenengine_engine::bifurcation_boundary_scanner::{
    EarlyWarningIndicator, PreemptiveAction, ScanResult,
};
use frankenengine_engine::counterfactual_evaluator::{EnvelopeStatus, PolicyId};
use frankenengine_engine::counterfactual_replay_engine::{
    Recommendation, ReplayComparisonResult, ReplayScope,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::rollback_safemode_synthesizer::*;
use frankenengine_engine::runtime_decision_theory::{LaneAction, LaneId};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeMap;

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_config() -> SynthesizerConfig {
    SynthesizerConfig::default()
}

fn make_rule(id: &str, trigger: EvidenceTrigger, output_kind: BundleKind) -> SynthesisRule {
    SynthesisRule {
        rule_id: id.to_string(),
        description: format!("Rule {}", id),
        trigger,
        min_confidence_millionths: 700_000,
        priority: 1,
        output_kind,
        enabled: true,
    }
}

fn make_replay_result(
    improvement: i64,
    confidence: i64,
    safety: EnvelopeStatus,
) -> ReplayComparisonResult {
    ReplayComparisonResult {
        schema_version: "v1".to_string(),
        trace_count: 10,
        total_decisions: 1000,
        scope: ReplayScope::default(),
        policy_reports: vec![],
        ranked_recommendations: vec![Recommendation {
            rank: 1,
            policy_id: PolicyId("policy-A".to_string()),
            expected_improvement_millionths: improvement,
            confidence_millionths: confidence,
            safety_status: safety,
            rationale: "test".to_string(),
        }],
        global_assumptions: vec![],
        causal_effects: vec![],
        artifact_hash: ContentHash::compute(b"replay"),
    }
}

fn make_scan_result(stability: i64) -> ScanResult {
    ScanResult {
        schema_version: "v1".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        parameters_scanned: 5,
        bifurcation_points: vec![],
        warnings: vec![],
        preemptive_actions: vec![],
        stability_score_millionths: stability,
        regime_summary: BTreeMap::new(),
        artifact_hash: ContentHash::compute(b"scan"),
    }
}

fn make_scan_result_with_warning(stability: i64, active: bool, risk: i64) -> ScanResult {
    let mut scan = make_scan_result(stability);
    scan.warnings.push(EarlyWarningIndicator {
        indicator_id: "ew-1".to_string(),
        parameter_id: "p-1".to_string(),
        risk_value_millionths: risk,
        threshold_millionths: 500_000,
        active,
        trend_millionths: 50_000,
        observation_count: 100,
    });
    scan
}

fn make_scan_result_with_preemptive(stability: i64) -> ScanResult {
    let mut scan = make_scan_result(stability);
    scan.preemptive_actions.push(PreemptiveAction {
        action_id: "act-1".to_string(),
        trigger_indicator_id: "ew-1".to_string(),
        parameter_id: "p-1".to_string(),
        lane_action: LaneAction::FallbackSafe,
        epoch: SecurityEpoch::from_raw(1),
        trigger_risk_millionths: 300_000,
        rationale: "high risk".to_string(),
    });
    scan
}

fn make_simple_synthesizer() -> RollbackSafemodeSynthesizer {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap()
}

// ── SynthesisRule display ────────────────────────────────────────────────

#[test]
fn synthesis_rule_display() {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::Rollback,
    );
    let s = rule.to_string();
    assert!(s.contains("r1"));
    assert!(s.contains("Rollback") || s.contains("rollback"));
}

#[test]
fn evidence_trigger_display_counterfactual() {
    let t = EvidenceTrigger::CounterfactualImprovement {
        min_improvement_millionths: 100_000,
    };
    let s = t.to_string();
    assert!(s.contains("cf-improvement"));
    assert!(s.contains("100000"));
}

#[test]
fn evidence_trigger_display_bifurcation() {
    let t = EvidenceTrigger::BifurcationInstability {
        min_risk_millionths: 200_000,
    };
    let s = t.to_string();
    assert!(s.contains("bifurcation-instability"));
    assert!(s.contains("200000"));
}

#[test]
fn evidence_trigger_display_early_warning() {
    let t = EvidenceTrigger::EarlyWarningActive {
        min_active_count: 3,
    };
    let s = t.to_string();
    assert!(s.contains("early-warning"));
    assert!(s.contains("3"));
}

#[test]
fn evidence_trigger_display_preemptive() {
    let t = EvidenceTrigger::PreemptiveActionRecommended;
    let s = t.to_string();
    assert!(s.contains("preemptive-action"));
}

#[test]
fn evidence_trigger_display_combined() {
    let t = EvidenceTrigger::CombinedEvidence {
        min_replay_improvement_millionths: 150_000,
        min_bifurcation_risk_millionths: 200_000,
    };
    let s = t.to_string();
    assert!(s.contains("combined"));
    assert!(s.contains("150000"));
    assert!(s.contains("200000"));
}

// ── BundleKind display ───────────────────────────────────────────────────

#[test]
fn bundle_kind_display_rollback() {
    assert_eq!(BundleKind::Rollback.to_string(), "rollback");
}

#[test]
fn bundle_kind_display_safe_mode() {
    assert_eq!(BundleKind::SafeMode.to_string(), "safe-mode");
}

#[test]
fn bundle_kind_display_adaptive() {
    assert_eq!(BundleKind::Adaptive.to_string(), "adaptive");
}

// ── VerificationKind display ─────────────────────────────────────────────

#[test]
fn verification_kind_display_improvement_replay() {
    assert_eq!(
        VerificationKind::ImprovementReplay.to_string(),
        "improvement-replay"
    );
}

#[test]
fn verification_kind_display_non_regression() {
    assert_eq!(
        VerificationKind::NonRegressionReplay.to_string(),
        "non-regression-replay"
    );
}

#[test]
fn verification_kind_display_stability() {
    assert_eq!(
        VerificationKind::StabilityReplay.to_string(),
        "stability-replay"
    );
}

#[test]
fn verification_kind_display_safe_mode() {
    assert_eq!(
        VerificationKind::SafeModeReplay.to_string(),
        "safe-mode-replay"
    );
}

// ── EvidenceSource display ───────────────────────────────────────────────

#[test]
fn evidence_source_display_counterfactual() {
    assert_eq!(
        EvidenceSource::CounterfactualReplay.to_string(),
        "counterfactual-replay"
    );
}

#[test]
fn evidence_source_display_bifurcation() {
    assert_eq!(
        EvidenceSource::BifurcationScan.to_string(),
        "bifurcation-scan"
    );
}

#[test]
fn evidence_source_display_combined() {
    assert_eq!(EvidenceSource::Combined.to_string(), "combined");
}

// ── ConstraintCategory display ───────────────────────────────────────────

#[test]
fn constraint_category_display_safety() {
    assert_eq!(ConstraintCategory::Safety.to_string(), "safety");
}

#[test]
fn constraint_category_display_performance() {
    assert_eq!(ConstraintCategory::Performance.to_string(), "performance");
}

#[test]
fn constraint_category_display_correctness() {
    assert_eq!(ConstraintCategory::Correctness.to_string(), "correctness");
}

#[test]
fn constraint_category_display_stability() {
    assert_eq!(ConstraintCategory::Stability.to_string(), "stability");
}

#[test]
fn constraint_category_display_compatibility() {
    assert_eq!(
        ConstraintCategory::Compatibility.to_string(),
        "compatibility"
    );
}

// ── SynthesizerError display ─────────────────────────────────────────────

#[test]
fn synthesizer_error_display_no_rules() {
    let e = SynthesizerError::NoRules;
    assert!(e.to_string().contains("no synthesis rules"));
}

#[test]
fn synthesizer_error_display_too_many_rules() {
    let e = SynthesizerError::TooManyRules {
        count: 300,
        max: 256,
    };
    let s = e.to_string();
    assert!(s.contains("300"));
    assert!(s.contains("256"));
}

#[test]
fn synthesizer_error_display_no_evidence() {
    let e = SynthesizerError::NoEvidence;
    assert!(e.to_string().contains("no evidence"));
}

#[test]
fn synthesizer_error_display_too_many_deltas() {
    let e = SynthesizerError::TooManyDeltas {
        count: 200,
        max: 128,
    };
    assert!(e.to_string().contains("200"));
}

#[test]
fn synthesizer_error_display_too_many_constraints() {
    let e = SynthesizerError::TooManyConstraints {
        count: 200,
        max: 128,
    };
    assert!(e.to_string().contains("200"));
}

#[test]
fn synthesizer_error_display_duplicate_rule() {
    let e = SynthesizerError::DuplicateRule {
        rule_id: "r1".to_string(),
    };
    assert!(e.to_string().contains("r1"));
}

#[test]
fn synthesizer_error_display_duplicate_constraint() {
    let e = SynthesizerError::DuplicateConstraint {
        constraint_id: "c1".to_string(),
    };
    assert!(e.to_string().contains("c1"));
}

#[test]
fn synthesizer_error_display_invalid_config() {
    let e = SynthesizerError::InvalidConfig {
        detail: "bad value".to_string(),
    };
    assert!(e.to_string().contains("bad value"));
}

// ── Constructor validation ───────────────────────────────────────────────

#[test]
fn new_returns_error_if_no_rules() {
    let err = RollbackSafemodeSynthesizer::new(make_config(), vec![], vec![]);
    assert_eq!(err.unwrap_err(), SynthesizerError::NoRules);
}

#[test]
fn new_returns_error_on_duplicate_rule_id() {
    let rule1 = make_rule(
        "dup",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::Rollback,
    );
    let rule2 = make_rule(
        "dup",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    );
    let err = RollbackSafemodeSynthesizer::new(make_config(), vec![rule1, rule2], vec![]);
    assert_eq!(
        err.unwrap_err(),
        SynthesizerError::DuplicateRule {
            rule_id: "dup".to_string()
        }
    );
}

#[test]
fn new_returns_error_on_duplicate_constraint_id() {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::Rollback,
    );
    let constraint = NonRegressionConstraint {
        constraint_id: "c1".to_string(),
        description: "test".to_string(),
        category: ConstraintCategory::Safety,
        max_regression_millionths: 50_000,
        hard: true,
    };
    let err = RollbackSafemodeSynthesizer::new(
        make_config(),
        vec![rule],
        vec![constraint.clone(), constraint],
    );
    assert_eq!(
        err.unwrap_err(),
        SynthesizerError::DuplicateConstraint {
            constraint_id: "c1".to_string()
        }
    );
}

#[test]
fn new_returns_error_for_invalid_confidence() {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::Rollback,
    );
    let mut config = make_config();
    config.min_confidence_millionths = -1;
    let err = RollbackSafemodeSynthesizer::new(config, vec![rule], vec![]);
    assert!(matches!(
        err.unwrap_err(),
        SynthesizerError::InvalidConfig { .. }
    ));
}

#[test]
fn new_returns_error_for_confidence_above_million() {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::Rollback,
    );
    let mut config = make_config();
    config.min_confidence_millionths = 2_000_000;
    let err = RollbackSafemodeSynthesizer::new(config, vec![rule], vec![]);
    assert!(matches!(
        err.unwrap_err(),
        SynthesizerError::InvalidConfig { .. }
    ));
}

#[test]
fn new_succeeds_with_valid_inputs() {
    let synth = make_simple_synthesizer();
    assert_eq!(synth.rule_count(), 1);
    assert_eq!(synth.constraint_count(), 0);
    assert_eq!(synth.synthesis_count(), 0);
}

// ── Config defaults ───────────────────────────────────────────────────────

#[test]
fn config_default_values() {
    let cfg = SynthesizerConfig::default();
    assert_eq!(cfg.min_confidence_millionths, 900_000);
    assert_eq!(cfg.max_regression_millionths, 50_000);
    assert_eq!(cfg.improvement_threshold_millionths, 100_000);
    assert!(cfg.generate_verification_hooks);
    assert_eq!(cfg.safe_mode_lane, LaneId("safe".to_string()));
    assert_eq!(cfg.rollback_lane, LaneId("baseline".to_string()));
}

// ── SynthesisInput ────────────────────────────────────────────────────────

#[test]
fn synthesis_input_has_evidence_with_replay() {
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    assert!(input.has_evidence());
}

#[test]
fn synthesis_input_has_evidence_with_scan() {
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result(800_000)),
    };
    assert!(input.has_evidence());
}

#[test]
fn synthesis_input_no_evidence() {
    let input = SynthesisInput {
        replay_result: None,
        scan_result: None,
    };
    assert!(!input.has_evidence());
}

// ── synthesize: error cases ──────────────────────────────────────────────

#[test]
fn synthesize_returns_error_if_no_evidence() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: None,
        scan_result: None,
    };
    let err = synth.synthesize(&input).unwrap_err();
    assert_eq!(err, SynthesizerError::NoEvidence);
}

// ── synthesize: counterfactual improvement trigger ────────────────────────

#[test]
fn synthesize_fires_counterfactual_rule_with_sufficient_improvement() {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.rules_fired.contains(&"r1".to_string()));
    assert_eq!(result.approved_count, 1);
    assert_eq!(synth.synthesis_count(), 1);
}

#[test]
fn synthesize_skips_rule_when_improvement_too_low() {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 500_000,
        },
        BundleKind::Rollback,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(100_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.rules_fired.contains(&"r1".to_string()));
}

#[test]
fn synthesize_skips_unsafe_recommendations() {
    let rule = SynthesisRule {
        rule_id: "r1".to_string(),
        description: "test".to_string(),
        trigger: EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        min_confidence_millionths: 700_000,
        priority: 1,
        output_kind: BundleKind::Rollback,
        enabled: true,
    };
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Unsafe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    // Unsafe recommendation should be skipped, so no bundles
    assert!(result.bundles.is_empty());
}

#[test]
fn synthesize_skips_low_confidence_recommendations() {
    let rule = SynthesisRule {
        rule_id: "r1".to_string(),
        description: "test".to_string(),
        trigger: EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        min_confidence_millionths: 900_000,
        priority: 1,
        output_kind: BundleKind::Rollback,
        enabled: true,
    };
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 500_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.bundles.is_empty());
}

// ── synthesize: bifurcation instability trigger ──────────────────────────

#[test]
fn synthesize_fires_bifurcation_rule_with_high_risk() {
    let rule = make_rule(
        "r-bif",
        EvidenceTrigger::BifurcationInstability {
            min_risk_millionths: 100_000,
        },
        BundleKind::SafeMode,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    // stability=500_000 means risk=500_000, which exceeds min_risk=100_000
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result(500_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.rules_fired.contains(&"r-bif".to_string()));
}

#[test]
fn synthesize_skips_bifurcation_rule_when_risk_low() {
    let rule = make_rule(
        "r-bif",
        EvidenceTrigger::BifurcationInstability {
            min_risk_millionths: 500_000,
        },
        BundleKind::SafeMode,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    // stability=900_000 means risk=100_000, below threshold=500_000
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result(900_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.rules_fired.contains(&"r-bif".to_string()));
}

// ── synthesize: early warning trigger ───────────────────────────────────

#[test]
fn synthesize_fires_early_warning_rule() {
    let rule = make_rule(
        "r-ew",
        EvidenceTrigger::EarlyWarningActive {
            min_active_count: 1,
        },
        BundleKind::SafeMode,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result_with_warning(800_000, true, 600_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.rules_fired.contains(&"r-ew".to_string()));
}

#[test]
fn synthesize_skips_early_warning_rule_when_no_active_warnings() {
    let rule = make_rule(
        "r-ew",
        EvidenceTrigger::EarlyWarningActive {
            min_active_count: 1,
        },
        BundleKind::SafeMode,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result_with_warning(800_000, false, 600_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.rules_fired.contains(&"r-ew".to_string()));
}

// ── synthesize: preemptive action trigger ───────────────────────────────

#[test]
fn synthesize_fires_preemptive_rule() {
    let rule = make_rule(
        "r-preempt",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result_with_preemptive(600_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.rules_fired.contains(&"r-preempt".to_string()));
    assert!(!result.bundles.is_empty());
}

#[test]
fn synthesize_skips_preemptive_rule_with_no_actions() {
    let rule = make_rule(
        "r-preempt",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result(800_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.rules_fired.contains(&"r-preempt".to_string()));
}

// ── synthesize: combined trigger ─────────────────────────────────────────

#[test]
fn synthesize_fires_combined_rule_with_both_sources() {
    let rule = make_rule(
        "r-comb",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    let mut config = make_config();
    config.min_confidence_millionths = 500_000;
    let mut synth = RollbackSafemodeSynthesizer::new(config, vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 800_000, EnvelopeStatus::Safe)),
        // stability=600_000 means risk=400_000 > 100_000
        scan_result: Some(make_scan_result(600_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.rules_fired.contains(&"r-comb".to_string()));
}

#[test]
fn synthesize_skips_combined_rule_missing_scan() {
    let rule = make_rule(
        "r-comb",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.rules_fired.contains(&"r-comb".to_string()));
}

// ── Disabled rules ────────────────────────────────────────────────────────

#[test]
fn synthesize_skips_disabled_rule() {
    let mut rule = make_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::Rollback,
    );
    rule.enabled = false;
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result_with_preemptive(600_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.rules_fired.is_empty());
    assert!(result.rules_skipped.contains(&"r1".to_string()));
}

// ── SynthesisResult helpers ───────────────────────────────────────────────

#[test]
fn synthesis_result_has_bundles_true_when_bundles_present() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.has_bundles());
}

#[test]
fn synthesis_result_schema_version() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.schema_version, SYNTHESIZER_SCHEMA_VERSION);
}

#[test]
fn synthesis_result_display() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let s = result.to_string();
    assert!(s.contains("synthesis"));
    assert!(s.contains("approved"));
}

#[test]
fn synthesis_result_best_approved_returns_bundle() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.best_approved().is_some());
}

#[test]
fn synthesis_result_approved_bundles_count() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(
        result.approved_bundles().len(),
        result.approved_count as usize
    );
}

// ── SynthesizedBundle helpers ─────────────────────────────────────────────

#[test]
fn bundle_is_approved_with_no_hard_constraint_violations() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = result.bundles.first().unwrap();
    assert!(bundle.is_approved());
    assert!(bundle.all_hard_constraints_passed);
}

#[test]
fn bundle_delta_count() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = result.bundles.first().unwrap();
    assert_eq!(bundle.delta_count(), bundle.deltas.len());
    assert!(bundle.delta_count() > 0);
}

#[test]
fn bundle_display() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = result.bundles.first().unwrap();
    let s = bundle.to_string();
    assert!(s.contains("bundle"));
    assert!(s.contains("approved") || s.contains("rejected"));
}

#[test]
fn bundle_schema_version() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = result.bundles.first().unwrap();
    assert_eq!(bundle.schema_version, SYNTHESIZER_SCHEMA_VERSION);
}

// ── Verification hooks ─────────────────────────────────────────────────────

#[test]
fn bundle_has_verification_hooks_when_enabled() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = result.bundles.first().unwrap();
    assert!(!bundle.verification_hooks.is_empty());
}

#[test]
fn bundle_has_no_hooks_when_disabled() {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    let mut config = make_config();
    config.generate_verification_hooks = false;
    let mut synth = RollbackSafemodeSynthesizer::new(config, vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = result.bundles.first().unwrap();
    assert!(bundle.verification_hooks.is_empty());
}

// ── Serde roundtrip ─────────────────────────────────────────────────────

#[test]
fn synthesis_rule_serde_roundtrip() {
    let rule = make_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::Rollback,
    );
    let json = serde_json::to_string(&rule).unwrap();
    let decoded: SynthesisRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, decoded);
}

#[test]
fn bundle_kind_serde_roundtrip() {
    for kind in [
        BundleKind::Rollback,
        BundleKind::SafeMode,
        BundleKind::Adaptive,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: BundleKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

#[test]
fn constraint_category_serde_roundtrip() {
    for cat in [
        ConstraintCategory::Safety,
        ConstraintCategory::Performance,
        ConstraintCategory::Correctness,
        ConstraintCategory::Stability,
        ConstraintCategory::Compatibility,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let decoded: ConstraintCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, decoded);
    }
}

#[test]
fn synthesizer_error_serde_roundtrip() {
    let e = SynthesizerError::DuplicateRule {
        rule_id: "r1".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let decoded: SynthesizerError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, decoded);
}

// ── Multiple rules, priority ordering ────────────────────────────────────

#[test]
fn synthesize_handles_multiple_rules() {
    let rule1 = SynthesisRule {
        rule_id: "r1".to_string(),
        description: "first".to_string(),
        trigger: EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        min_confidence_millionths: 700_000,
        priority: 2,
        output_kind: BundleKind::Rollback,
        enabled: true,
    };
    let rule2 = SynthesisRule {
        rule_id: "r2".to_string(),
        description: "second".to_string(),
        trigger: EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        min_confidence_millionths: 700_000,
        priority: 1,
        output_kind: BundleKind::SafeMode,
        enabled: true,
    };
    let mut synth =
        RollbackSafemodeSynthesizer::new(make_config(), vec![rule1, rule2], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.approved_count, 2);
}

// ── NonRegressionConstraint display ──────────────────────────────────────

#[test]
fn non_regression_constraint_display_hard() {
    let c = NonRegressionConstraint {
        constraint_id: "c1".to_string(),
        description: "hard safety".to_string(),
        category: ConstraintCategory::Safety,
        max_regression_millionths: 0,
        hard: true,
    };
    let s = c.to_string();
    assert!(s.contains("c1"));
    assert!(s.contains("safety"));
    assert!(s.contains("hard"));
}

#[test]
fn non_regression_constraint_display_soft() {
    let c = NonRegressionConstraint {
        constraint_id: "c2".to_string(),
        description: "soft perf".to_string(),
        category: ConstraintCategory::Performance,
        max_regression_millionths: 50_000,
        hard: false,
    };
    let s = c.to_string();
    assert!(s.contains("soft"));
}

// ── PolicyDelta display ───────────────────────────────────────────────────

#[test]
fn policy_delta_display() {
    let delta = PolicyDelta {
        delta_id: "d-1".to_string(),
        source_rule_id: "r1".to_string(),
        action: LaneAction::FallbackSafe,
        effective_epoch: SecurityEpoch::from_raw(1),
        expected_improvement_millionths: 200_000,
        confidence_millionths: 950_000,
        rationale: "test delta".to_string(),
    };
    let s = delta.to_string();
    assert!(s.contains("d-1"));
    assert!(s.contains("200000"));
}

// ── Synthesis count increments ────────────────────────────────────────────

#[test]
fn synthesis_count_increments_per_call() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    synth.synthesize(&input).unwrap();
    assert_eq!(synth.synthesis_count(), 1);
    synth.synthesize(&input).unwrap();
    assert_eq!(synth.synthesis_count(), 2);
}

// ── Evidence refs ─────────────────────────────────────────────────────────

#[test]
fn bundle_evidence_refs_from_replay() {
    let mut synth = make_simple_synthesizer();
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000, EnvelopeStatus::Safe)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = result.bundles.first().unwrap();
    assert!(!bundle.evidence_refs.is_empty());
    assert!(
        bundle
            .evidence_refs
            .iter()
            .any(|r| r.source == EvidenceSource::CounterfactualReplay)
    );
}

#[test]
fn bundle_evidence_refs_from_scan() {
    let rule = make_rule(
        "r-bif",
        EvidenceTrigger::BifurcationInstability {
            min_risk_millionths: 100_000,
        },
        BundleKind::SafeMode,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(make_config(), vec![rule], vec![]).unwrap();
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(make_scan_result(500_000)),
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = result.bundles.first().unwrap();
    assert!(
        bundle
            .evidence_refs
            .iter()
            .any(|r| r.source == EvidenceSource::BifurcationScan)
    );
}
