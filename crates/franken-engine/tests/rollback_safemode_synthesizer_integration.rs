#![forbid(unsafe_code)]
//! Integration tests for the `rollback_safemode_synthesizer` module.
//!
//! Exercises synthesis rules, policy deltas, non-regression constraints,
//! synthesized bundles, evidence triggers, the synthesizer lifecycle,
//! and serde round-trips from outside the crate boundary.

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

use frankenengine_engine::bifurcation_boundary_scanner::ScanResult;
use frankenengine_engine::counterfactual_evaluator::{EnvelopeStatus, PolicyId};
use frankenengine_engine::counterfactual_replay_engine::{
    Recommendation, ReplayComparisonResult, ReplayScope,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::rollback_safemode_synthesizer::{
    BundleKind, ConstraintCategory, EvidenceSource, EvidenceTrigger, NonRegressionConstraint,
    ReplayVerificationHook, RollbackSafemodeSynthesizer, SYNTHESIZER_SCHEMA_VERSION,
    SynthesisInput, SynthesisResult, SynthesisRule, SynthesizerConfig, SynthesizerError,
    VerificationKind,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(5)
}

fn default_config() -> SynthesizerConfig {
    SynthesizerConfig {
        epoch: test_epoch(),
        ..SynthesizerConfig::default()
    }
}

fn basic_rule(id: &str, trigger: EvidenceTrigger, kind: BundleKind) -> SynthesisRule {
    SynthesisRule {
        rule_id: id.into(),
        description: format!("Rule {id}"),
        trigger,
        min_confidence_millionths: 900_000,
        priority: 1,
        output_kind: kind,
        enabled: true,
    }
}

fn basic_constraint(id: &str, category: ConstraintCategory) -> NonRegressionConstraint {
    NonRegressionConstraint {
        constraint_id: id.into(),
        description: format!("Constraint {id}"),
        category,
        max_regression_millionths: 50_000,
        hard: true,
    }
}

fn make_replay_result(improvement: i64, confidence: i64) -> ReplayComparisonResult {
    ReplayComparisonResult {
        schema_version: "test-v1".into(),
        trace_count: 10,
        total_decisions: 100,
        scope: ReplayScope::default(),
        policy_reports: vec![],
        ranked_recommendations: vec![Recommendation {
            rank: 1,
            policy_id: PolicyId("alt-policy-1".into()),
            expected_improvement_millionths: improvement,
            confidence_millionths: confidence,
            safety_status: EnvelopeStatus::Safe,
            rationale: "Looks better".into(),
        }],
        global_assumptions: vec![],
        causal_effects: vec![],
        artifact_hash: ContentHash::compute(b"replay-result"),
    }
}

fn make_scan_result(stability: i64) -> ScanResult {
    ScanResult {
        schema_version: "test-v1".into(),
        epoch: test_epoch(),
        parameters_scanned: 20,
        bifurcation_points: vec![],
        warnings: vec![],
        preemptive_actions: vec![],
        stability_score_millionths: stability,
        regime_summary: BTreeMap::from([("stable".into(), 18), ("unstable".into(), 2)]),
        artifact_hash: ContentHash::compute(b"scan-result"),
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!SYNTHESIZER_SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// 2. BundleKind
// ===========================================================================

#[test]
fn bundle_kind_display_and_serde() {
    for k in [
        BundleKind::Rollback,
        BundleKind::SafeMode,
        BundleKind::Adaptive,
    ] {
        let s = k.to_string();
        assert!(!s.is_empty());
        let json = serde_json::to_string(&k).unwrap();
        let back: BundleKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

// ===========================================================================
// 3. ConstraintCategory
// ===========================================================================

#[test]
fn constraint_category_display_and_serde() {
    for c in [
        ConstraintCategory::Safety,
        ConstraintCategory::Performance,
        ConstraintCategory::Correctness,
        ConstraintCategory::Stability,
        ConstraintCategory::Compatibility,
    ] {
        let s = c.to_string();
        assert!(!s.is_empty());
        let json = serde_json::to_string(&c).unwrap();
        let back: ConstraintCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }
}

// ===========================================================================
// 4. VerificationKind
// ===========================================================================

#[test]
fn verification_kind_display_and_serde() {
    for v in [
        VerificationKind::ImprovementReplay,
        VerificationKind::NonRegressionReplay,
        VerificationKind::StabilityReplay,
        VerificationKind::SafeModeReplay,
    ] {
        let s = v.to_string();
        assert!(!s.is_empty());
        let json = serde_json::to_string(&v).unwrap();
        let back: VerificationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ===========================================================================
// 5. EvidenceSource
// ===========================================================================

#[test]
fn evidence_source_display_and_serde() {
    for e in [
        EvidenceSource::CounterfactualReplay,
        EvidenceSource::BifurcationScan,
        EvidenceSource::Combined,
    ] {
        let s = e.to_string();
        assert!(!s.is_empty());
        let json = serde_json::to_string(&e).unwrap();
        let back: EvidenceSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

// ===========================================================================
// 6. EvidenceTrigger
// ===========================================================================

#[test]
fn evidence_trigger_serde_round_trip() {
    let triggers = vec![
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        EvidenceTrigger::BifurcationInstability {
            min_risk_millionths: 200_000,
        },
        EvidenceTrigger::EarlyWarningActive {
            min_active_count: 3,
        },
        EvidenceTrigger::PreemptiveActionRecommended,
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 50_000,
            min_bifurcation_risk_millionths: 30_000,
        },
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let back: EvidenceTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, t);
    }
}

// ===========================================================================
// 7. SynthesisRule serde
// ===========================================================================

#[test]
fn synthesis_rule_serde_round_trip() {
    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    let json = serde_json::to_string(&rule).unwrap();
    let back: SynthesisRule = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rule);
}

// ===========================================================================
// 8. NonRegressionConstraint serde
// ===========================================================================

#[test]
fn non_regression_constraint_serde_round_trip() {
    let c = basic_constraint("c-1", ConstraintCategory::Safety);
    let json = serde_json::to_string(&c).unwrap();
    let back: NonRegressionConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 9. SynthesizerConfig
// ===========================================================================

#[test]
fn synthesizer_config_default() {
    let config = SynthesizerConfig::default();
    assert!(config.min_confidence_millionths > 0);
    assert!(config.max_regression_millionths > 0);
}

#[test]
fn synthesizer_config_serde_round_trip() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: SynthesizerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// 10. SynthesizerError
// ===========================================================================

#[test]
fn synthesizer_error_no_rules() {
    let result = RollbackSafemodeSynthesizer::new(default_config(), vec![], vec![]);
    match result {
        Err(SynthesizerError::NoRules) => {}
        other => panic!("expected NoRules, got {other:?}"),
    }
}

#[test]
fn synthesizer_error_duplicate_rule() {
    let rule = basic_rule(
        "dup",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    );
    let result =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule.clone(), rule], vec![]);
    match result {
        Err(SynthesizerError::DuplicateRule { rule_id }) => {
            assert_eq!(rule_id, "dup");
        }
        other => panic!("expected DuplicateRule, got {other:?}"),
    }
}

#[test]
fn synthesizer_error_duplicate_constraint() {
    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::Rollback,
    );
    let c = basic_constraint("dup-c", ConstraintCategory::Safety);
    let result = RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![c.clone(), c]);
    match result {
        Err(SynthesizerError::DuplicateConstraint { constraint_id }) => {
            assert_eq!(constraint_id, "dup-c");
        }
        other => panic!("expected DuplicateConstraint, got {other:?}"),
    }
}

#[test]
fn synthesizer_error_serde_round_trip() {
    let errors = vec![
        SynthesizerError::NoRules,
        SynthesizerError::NoEvidence,
        SynthesizerError::TooManyRules {
            count: 300,
            max: 256,
        },
        SynthesizerError::DuplicateRule {
            rule_id: "x".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SynthesizerError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 11. SynthesisInput
// ===========================================================================

#[test]
fn synthesis_input_no_evidence() {
    let input = SynthesisInput {
        replay_result: None,
        scan_result: None,
    };
    assert!(!input.has_evidence());
}

#[test]
fn synthesis_input_with_replay() {
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000)),
        scan_result: None,
    };
    assert!(input.has_evidence());
}

#[test]
fn synthesis_input_serde_round_trip() {
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(100_000, 900_000)),
        scan_result: Some(make_scan_result(800_000)),
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: SynthesisInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, input);
}

// ===========================================================================
// 12. Synthesizer — no evidence error
// ===========================================================================

#[test]
fn synthesize_no_evidence_returns_error() {
    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![]).unwrap();

    let input = SynthesisInput {
        replay_result: None,
        scan_result: None,
    };

    match synth.synthesize(&input) {
        Err(SynthesizerError::NoEvidence) => {}
        other => panic!("expected NoEvidence, got {other:?}"),
    }
}

// ===========================================================================
// 13. Synthesizer — basic synthesis with replay evidence
// ===========================================================================

#[test]
fn synthesize_with_replay_improvement() {
    let rule = basic_rule(
        "rollback-on-improvement",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    let constraint = basic_constraint("safety-floor", ConstraintCategory::Safety);
    let mut synth =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![constraint]).unwrap();

    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000)),
        scan_result: None,
    };

    let result = synth.synthesize(&input).unwrap();
    assert!(result.has_bundles());
    assert!(!result.rules_fired.is_empty());
}

// ===========================================================================
// 14. Synthesizer — disabled rule skipped
// ===========================================================================

#[test]
fn synthesize_disabled_rule_skipped() {
    let mut rule = basic_rule(
        "disabled-rule",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    rule.enabled = false;

    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![]).unwrap();

    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000)),
        scan_result: None,
    };

    let result = synth.synthesize(&input).unwrap();
    assert!(result.rules_skipped.contains(&"disabled-rule".to_string()));
}

// ===========================================================================
// 15. Synthesizer — accessors
// ===========================================================================

#[test]
fn synthesizer_accessors() {
    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    );
    let constraint = basic_constraint("c-1", ConstraintCategory::Performance);
    let synth =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![constraint]).unwrap();

    assert_eq!(synth.rule_count(), 1);
    assert_eq!(synth.constraint_count(), 1);
    assert_eq!(synth.synthesis_count(), 0);
    assert_eq!(synth.config().epoch, test_epoch());
}

// ===========================================================================
// 16. SynthesisResult
// ===========================================================================

#[test]
fn synthesis_result_best_approved() {
    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 50_000,
        },
        BundleKind::Rollback,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![]).unwrap();

    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000)),
        scan_result: None,
    };

    let result = synth.synthesize(&input).unwrap();
    if let Some(best) = result.best_approved() {
        assert!(best.is_approved());
        assert!(best.total_improvement_millionths > 0);
    }
}

#[test]
fn synthesis_result_serde_round_trip() {
    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 50_000,
        },
        BundleKind::Adaptive,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![]).unwrap();

    let input = SynthesisInput {
        replay_result: Some(make_replay_result(150_000, 950_000)),
        scan_result: None,
    };

    let result = synth.synthesize(&input).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: SynthesisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

// ===========================================================================
// 17. SynthesizedBundle
// ===========================================================================

#[test]
fn bundle_is_approved_logic() {
    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 50_000,
        },
        BundleKind::Rollback,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![]).unwrap();

    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000)),
        scan_result: None,
    };

    let result = synth.synthesize(&input).unwrap();
    for bundle in &result.bundles {
        if bundle.all_hard_constraints_passed && bundle.delta_count() > 0 {
            assert!(bundle.is_approved());
        }
    }
}

// ===========================================================================
// 18. Verification hooks
// ===========================================================================

#[test]
fn synthesis_generates_verification_hooks() {
    let mut config = default_config();
    config.generate_verification_hooks = true;

    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 50_000,
        },
        BundleKind::Rollback,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(config, vec![rule], vec![]).unwrap();

    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000)),
        scan_result: None,
    };

    let result = synth.synthesize(&input).unwrap();
    if let Some(bundle) = result.bundles.first() {
        // When generate_verification_hooks is true, expect hooks
        if bundle.delta_count() > 0 {
            assert!(
                !bundle.verification_hooks.is_empty(),
                "expected verification hooks when generate_verification_hooks=true"
            );
        }
    }
}

#[test]
fn replay_verification_hook_serde_round_trip() {
    let hook = ReplayVerificationHook {
        hook_id: "hook-1".into(),
        description: "Verify improvement replays correctly".into(),
        verification_kind: VerificationKind::ImprovementReplay,
        expected_outcome_millionths: 200_000,
        tolerance_millionths: 10_000,
    };
    let json = serde_json::to_string(&hook).unwrap();
    let back: ReplayVerificationHook = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hook);
}

// ===========================================================================
// 19. Synthesis count increments
// ===========================================================================

#[test]
fn synthesis_count_increments() {
    let rule = basic_rule(
        "r-1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 50_000,
        },
        BundleKind::Rollback,
    );
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![]).unwrap();

    assert_eq!(synth.synthesis_count(), 0);

    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000)),
        scan_result: None,
    };

    synth.synthesize(&input).unwrap();
    assert_eq!(synth.synthesis_count(), 1);

    synth.synthesize(&input).unwrap();
    assert_eq!(synth.synthesis_count(), 2);
}

// ===========================================================================
// 20. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_synthesizer() {
    // 1. Build config
    let mut config = default_config();
    config.generate_verification_hooks = true;

    // 2. Build rules
    let rules = vec![
        basic_rule(
            "replay-improvement",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        ),
        basic_rule(
            "safe-mode-instability",
            EvidenceTrigger::BifurcationInstability {
                min_risk_millionths: 200_000,
            },
            BundleKind::SafeMode,
        ),
    ];

    // 3. Build constraints
    let constraints = vec![
        basic_constraint("safety", ConstraintCategory::Safety),
        basic_constraint("performance", ConstraintCategory::Performance),
    ];

    // 4. Create synthesizer
    let mut synth = RollbackSafemodeSynthesizer::new(config, rules, constraints).unwrap();
    assert_eq!(synth.rule_count(), 2);
    assert_eq!(synth.constraint_count(), 2);

    // 5. Synthesize with both replay and scan evidence
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(300_000, 960_000)),
        scan_result: Some(make_scan_result(700_000)),
    };

    let result = synth.synthesize(&input).unwrap();

    // 6. Inspect results
    assert_eq!(result.schema_version, SYNTHESIZER_SCHEMA_VERSION);
    assert_eq!(result.epoch, test_epoch());
    assert!(result.has_bundles());
    assert_eq!(synth.synthesis_count(), 1);

    // 7. Check approved bundles
    let approved = result.approved_bundles();
    for bundle in &approved {
        assert!(bundle.is_approved());
        assert!(bundle.delta_count() > 0);
    }

    // 8. Serde round-trip
    let json = serde_json::to_string(&result).unwrap();
    let back: SynthesisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

// ===========================================================================
// 21. Too many rules returns error
// ===========================================================================

#[test]
fn synthesizer_error_too_many_rules() {
    let rules: Vec<SynthesisRule> = (0..257)
        .map(|i| {
            basic_rule(
                &format!("r-{i}"),
                EvidenceTrigger::PreemptiveActionRecommended,
                BundleKind::SafeMode,
            )
        })
        .collect();
    let result = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]);
    match result {
        Err(SynthesizerError::TooManyRules { count, max }) => {
            assert_eq!(count, 257);
            assert!(max < 257);
        }
        other => panic!("expected TooManyRules, got {other:?}"),
    }
}

// ===========================================================================
// 22. Synthesizer determinism — same input produces identical result
// ===========================================================================

#[test]
fn synthesizer_determinism_same_input_same_result() {
    let rule = basic_rule(
        "r-det",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 50_000,
        },
        BundleKind::Rollback,
    );
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(200_000, 950_000)),
        scan_result: None,
    };

    let mut synth1 =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule.clone()], vec![]).unwrap();
    let mut synth2 =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![]).unwrap();

    let r1 = synth1.synthesize(&input).unwrap();
    let r2 = synth2.synthesize(&input).unwrap();

    let json1 = serde_json::to_string(&r1).unwrap();
    let json2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(
        json1, json2,
        "identical inputs must produce identical serialized results"
    );
}
