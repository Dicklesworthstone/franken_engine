#![forbid(unsafe_code)]
//! Enrichment integration tests for the `rollback_safemode_synthesizer` module.
//!
//! Supplements the existing 28 integration tests with deeper coverage of:
//! - Display exact-value assertions for all enums/structs
//! - Serde roundtrips for types not yet exercised from outside (PolicyDelta,
//!   ConstraintCheckResult, EvidenceRef, SynthesizedBundle)
//! - All 5 trigger types exercised from integration boundary
//! - Hard/soft constraint interplay, adaptive resolution, priority ordering
//! - JSON field-name stability, Debug distinctness, artifact hash determinism
//! - E2E multi-rule synthesis workflows

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

use frankenengine_engine::bifurcation_boundary_scanner::{
    EarlyWarningIndicator, PreemptiveAction, ScanResult,
};
use frankenengine_engine::counterfactual_evaluator::{EnvelopeStatus, PolicyId};
use frankenengine_engine::counterfactual_replay_engine::{
    Recommendation, ReplayComparisonResult, ReplayScope,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::rollback_safemode_synthesizer::{
    BundleKind, ConstraintCategory, ConstraintCheckResult, EvidenceRef, EvidenceSource,
    EvidenceTrigger, NonRegressionConstraint, PolicyDelta, RollbackSafemodeSynthesizer,
    SYNTHESIZER_SCHEMA_VERSION, SynthesisInput, SynthesisResult, SynthesisRule, SynthesizedBundle,
    SynthesizerConfig, SynthesizerError, VerificationKind,
};
use frankenengine_engine::runtime_decision_theory::{LaneAction, LaneId};
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

fn basic_constraint(id: &str, category: ConstraintCategory, hard: bool) -> NonRegressionConstraint {
    NonRegressionConstraint {
        constraint_id: id.into(),
        description: format!("Constraint {id}"),
        category,
        max_regression_millionths: 50_000,
        hard,
    }
}

fn make_recommendation(policy_id: &str, improvement: i64, confidence: i64) -> Recommendation {
    Recommendation {
        rank: 1,
        policy_id: PolicyId(policy_id.into()),
        expected_improvement_millionths: improvement,
        confidence_millionths: confidence,
        safety_status: EnvelopeStatus::Safe,
        rationale: format!("Recommend {policy_id}"),
    }
}

fn make_replay_result(recs: Vec<Recommendation>) -> ReplayComparisonResult {
    ReplayComparisonResult {
        schema_version: "test-v1".into(),
        trace_count: 10,
        total_decisions: 100,
        scope: ReplayScope::default(),
        policy_reports: vec![],
        ranked_recommendations: recs,
        global_assumptions: vec![],
        causal_effects: vec![],
        artifact_hash: ContentHash::compute(b"replay-result"),
    }
}

fn make_scan_result(
    stability: i64,
    warnings: Vec<EarlyWarningIndicator>,
    preemptive: Vec<PreemptiveAction>,
) -> ScanResult {
    ScanResult {
        schema_version: "test-v1".into(),
        epoch: test_epoch(),
        parameters_scanned: 20,
        bifurcation_points: vec![],
        warnings,
        preemptive_actions: preemptive,
        stability_score_millionths: stability,
        regime_summary: BTreeMap::from([("stable".into(), 18), ("unstable".into(), 2)]),
        artifact_hash: ContentHash::compute(b"scan-result"),
    }
}

fn make_warning(id: &str, risk: i64, active: bool) -> EarlyWarningIndicator {
    EarlyWarningIndicator {
        indicator_id: id.into(),
        parameter_id: format!("param-{id}"),
        risk_value_millionths: risk,
        threshold_millionths: 750_000,
        active,
        trend_millionths: 0,
        observation_count: 10,
    }
}

fn make_preemptive_action(id: &str, risk: i64) -> PreemptiveAction {
    PreemptiveAction {
        action_id: id.into(),
        trigger_indicator_id: format!("ew-{id}"),
        parameter_id: format!("param-{id}"),
        lane_action: LaneAction::FallbackSafe,
        epoch: test_epoch(),
        trigger_risk_millionths: risk,
        rationale: format!("Preemptive action {id}"),
    }
}

fn default_synthesizer() -> RollbackSafemodeSynthesizer {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    )];
    let constraints = vec![basic_constraint("c1", ConstraintCategory::Safety, true)];
    RollbackSafemodeSynthesizer::new(default_config(), rules, constraints).unwrap()
}

// ===========================================================================
// 1. EvidenceTrigger Display — exact values
// ===========================================================================

#[test]
fn evidence_trigger_display_exact_counterfactual() {
    let t = EvidenceTrigger::CounterfactualImprovement {
        min_improvement_millionths: 100_000,
    };
    assert_eq!(t.to_string(), "cf-improvement(min=100000)");
}

#[test]
fn evidence_trigger_display_exact_bifurcation() {
    let t = EvidenceTrigger::BifurcationInstability {
        min_risk_millionths: 200_000,
    };
    assert_eq!(t.to_string(), "bifurcation-instability(min=200000)");
}

#[test]
fn evidence_trigger_display_exact_early_warning() {
    let t = EvidenceTrigger::EarlyWarningActive {
        min_active_count: 3,
    };
    assert_eq!(t.to_string(), "early-warning(min=3)");
}

#[test]
fn evidence_trigger_display_exact_preemptive() {
    assert_eq!(
        EvidenceTrigger::PreemptiveActionRecommended.to_string(),
        "preemptive-action"
    );
}

#[test]
fn evidence_trigger_display_exact_combined() {
    let t = EvidenceTrigger::CombinedEvidence {
        min_replay_improvement_millionths: 50_000,
        min_bifurcation_risk_millionths: 30_000,
    };
    assert_eq!(t.to_string(), "combined(replay=50000, bifurcation=30000)");
}

// ===========================================================================
// 2. SynthesisRule Display
// ===========================================================================

#[test]
fn synthesis_rule_display_contains_id_kind_priority() {
    let rule = basic_rule(
        "my-rule",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    );
    let s = rule.to_string();
    assert!(s.contains("my-rule"), "should contain rule_id");
    assert!(s.contains("SafeMode"), "should contain output_kind debug");
    assert!(s.contains("pri=1"), "should contain priority");
}

// ===========================================================================
// 3. PolicyDelta serde + Display (not in existing integration tests)
// ===========================================================================

#[test]
fn policy_delta_serde_roundtrip() {
    let delta = PolicyDelta {
        delta_id: "d-r1-alt1".into(),
        source_rule_id: "r1".into(),
        action: LaneAction::FallbackSafe,
        effective_epoch: test_epoch(),
        expected_improvement_millionths: 200_000,
        confidence_millionths: 950_000,
        rationale: "Counterfactual replay recommends alt1".into(),
    };
    let json = serde_json::to_string(&delta).unwrap();
    let back: PolicyDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(back, delta);
}

#[test]
fn policy_delta_serde_with_route_to_action() {
    let delta = PolicyDelta {
        delta_id: "d-r2-default".into(),
        source_rule_id: "r2".into(),
        action: LaneAction::RouteTo(LaneId("baseline".into())),
        effective_epoch: SecurityEpoch::from_raw(10),
        expected_improvement_millionths: 400_000,
        confidence_millionths: 300_000,
        rationale: "Bifurcation risk 400000 exceeds threshold 200000".into(),
    };
    let json = serde_json::to_string(&delta).unwrap();
    let back: PolicyDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(back, delta);
}

#[test]
fn policy_delta_display_content() {
    let delta = PolicyDelta {
        delta_id: "d-r1-alt1".into(),
        source_rule_id: "r1".into(),
        action: LaneAction::FallbackSafe,
        effective_epoch: test_epoch(),
        expected_improvement_millionths: 200_000,
        confidence_millionths: 950_000,
        rationale: "test".into(),
    };
    let s = delta.to_string();
    assert!(s.contains("d-r1-alt1"), "should contain delta_id");
    assert!(s.contains("200000"), "should contain improvement");
}

// ===========================================================================
// 4. ConstraintCheckResult serde (not in existing integration tests)
// ===========================================================================

#[test]
fn constraint_check_result_serde_passed() {
    let check = ConstraintCheckResult {
        constraint_id: "c-safety".into(),
        passed: true,
        regression_millionths: 10_000,
        detail: "regression 10000 within limit 50000".into(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: ConstraintCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, check);
}

#[test]
fn constraint_check_result_serde_failed() {
    let check = ConstraintCheckResult {
        constraint_id: "c-perf".into(),
        passed: false,
        regression_millionths: 60_000,
        detail: "regression 60000 exceeds limit 50000".into(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: ConstraintCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, check);
    assert!(!back.passed);
}

#[test]
fn constraint_check_result_serde_negative_regression() {
    let check = ConstraintCheckResult {
        constraint_id: "c-perf".into(),
        passed: true,
        regression_millionths: -5_000,
        detail: "improved by 5000".into(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: ConstraintCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, check);
}

// ===========================================================================
// 5. EvidenceRef serde (not in existing integration tests)
// ===========================================================================

#[test]
fn evidence_ref_serde_counterfactual() {
    let eref = EvidenceRef {
        source: EvidenceSource::CounterfactualReplay,
        artifact_hash: ContentHash::compute(b"replay-evidence"),
        summary: "10 traces, 100 decisions, 1 recommendations".into(),
    };
    let json = serde_json::to_string(&eref).unwrap();
    let back: EvidenceRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, eref);
}

#[test]
fn evidence_ref_serde_bifurcation() {
    let eref = EvidenceRef {
        source: EvidenceSource::BifurcationScan,
        artifact_hash: ContentHash::compute(b"scan-evidence"),
        summary: "20 params, 0 bifurcations, 2 warnings, stability=700000".into(),
    };
    let json = serde_json::to_string(&eref).unwrap();
    let back: EvidenceRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, eref);
}

// ===========================================================================
// 6. SynthesizedBundle serde + Display (from integration boundary)
// ===========================================================================

#[test]
fn synthesized_bundle_serde_roundtrip_from_synthesis() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let bundle = &result.bundles[0];
    let json = serde_json::to_string(bundle).unwrap();
    let back: SynthesizedBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, bundle);
}

#[test]
fn synthesized_bundle_display_approved() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let s = result.bundles[0].to_string();
    assert!(
        s.contains("approved"),
        "approved bundle should say approved"
    );
    assert!(s.contains("rollback"), "should contain kind");
    assert!(s.contains("deltas="), "should contain delta count");
}

#[test]
fn synthesized_bundle_display_rejected() {
    let mut rule = basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    rule.min_confidence_millionths = 400_000; // lower so 500_000 confidence passes
    let mut constraint = basic_constraint("c1", ConstraintCategory::Safety, true);
    constraint.max_regression_millionths = 0;
    let mut synth =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![constraint]).unwrap();
    let rec = make_recommendation("alt1", 500_000, 500_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let s = result.bundles[0].to_string();
    assert!(
        s.contains("rejected"),
        "rejected bundle should say rejected"
    );
}

#[test]
fn synthesized_bundle_is_approved_empty_deltas() {
    let bundle = SynthesizedBundle {
        bundle_id: "b-empty".into(),
        schema_version: SYNTHESIZER_SCHEMA_VERSION.into(),
        kind: BundleKind::Rollback,
        synthesis_epoch: test_epoch(),
        deltas: vec![],
        constraint_checks: vec![],
        all_hard_constraints_passed: true,
        soft_violations: 0,
        total_improvement_millionths: 0,
        min_confidence_millionths: 0,
        verification_hooks: vec![],
        evidence_refs: vec![],
        artifact_hash: ContentHash::compute(b"empty"),
    };
    assert!(!bundle.is_approved(), "empty deltas → not approved");
    assert_eq!(bundle.delta_count(), 0);
    assert_eq!(bundle.violation_count(), 0);
}

// ===========================================================================
// 7. SynthesisResult Display
// ===========================================================================

#[test]
fn synthesis_result_display_content() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let s = result.to_string();
    assert!(s.contains("synthesis("), "should start with synthesis(");
    assert!(s.contains("epoch="), "should contain epoch");
    assert!(s.contains("approved="), "should contain approved count");
    assert!(s.contains("rejected="), "should contain rejected count");
}

// ===========================================================================
// 8. NonRegressionConstraint Display
// ===========================================================================

#[test]
fn non_regression_constraint_display_hard() {
    let c = basic_constraint("safety-floor", ConstraintCategory::Safety, true);
    let s = c.to_string();
    assert!(s.contains("safety-floor"));
    assert!(s.contains("safety"));
    assert!(s.contains("hard"));
}

#[test]
fn non_regression_constraint_display_soft() {
    let c = basic_constraint("perf-advisory", ConstraintCategory::Performance, false);
    let s = c.to_string();
    assert!(s.contains("perf-advisory"));
    assert!(s.contains("performance"));
    assert!(s.contains("soft"));
}

// ===========================================================================
// 9. SynthesizerError — all 8 variants Display + serde
// ===========================================================================

#[test]
fn synthesizer_error_all_variants_display_exact() {
    let cases: Vec<(SynthesizerError, &str)> = vec![
        (SynthesizerError::NoRules, "no synthesis rules configured"),
        (
            SynthesizerError::TooManyRules {
                count: 300,
                max: 256,
            },
            "too many rules: 300 exceeds max 256",
        ),
        (
            SynthesizerError::NoEvidence,
            "no evidence provided for synthesis",
        ),
        (
            SynthesizerError::TooManyDeltas {
                count: 200,
                max: 128,
            },
            "too many deltas: 200 exceeds max 128",
        ),
        (
            SynthesizerError::TooManyConstraints {
                count: 150,
                max: 128,
            },
            "too many constraints: 150 exceeds max 128",
        ),
        (
            SynthesizerError::DuplicateRule {
                rule_id: "dup-rule".into(),
            },
            "duplicate rule ID: dup-rule",
        ),
        (
            SynthesizerError::DuplicateConstraint {
                constraint_id: "dup-c".into(),
            },
            "duplicate constraint ID: dup-c",
        ),
        (
            SynthesizerError::InvalidConfig {
                detail: "confidence out of range".into(),
            },
            "invalid config: confidence out of range",
        ),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (err, expected) in &cases {
        let s = err.to_string();
        assert_eq!(&s, expected, "Display mismatch for {:?}", err);
        assert!(seen.insert(s), "Duplicate Display for {:?}", err);
    }
    assert_eq!(seen.len(), 8);
}

#[test]
fn synthesizer_error_all_variants_serde() {
    let errors = vec![
        SynthesizerError::NoRules,
        SynthesizerError::TooManyRules {
            count: 300,
            max: 256,
        },
        SynthesizerError::NoEvidence,
        SynthesizerError::TooManyDeltas {
            count: 200,
            max: 128,
        },
        SynthesizerError::TooManyConstraints {
            count: 150,
            max: 128,
        },
        SynthesizerError::DuplicateRule {
            rule_id: "x".into(),
        },
        SynthesizerError::DuplicateConstraint {
            constraint_id: "y".into(),
        },
        SynthesizerError::InvalidConfig {
            detail: "bad".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SynthesizerError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 10. SynthesizerError std::error::Error trait
// ===========================================================================

#[test]
fn synthesizer_error_implements_std_error() {
    let err = SynthesizerError::NoRules;
    let _dyn_err: &dyn std::error::Error = &err;
}

// ===========================================================================
// 11. Synthesizer serde roundtrip
// ===========================================================================

#[test]
fn synthesizer_serde_roundtrip() {
    let synth = default_synthesizer();
    let json = serde_json::to_string(&synth).unwrap();
    let back: RollbackSafemodeSynthesizer = serde_json::from_str(&json).unwrap();
    assert_eq!(back.rule_count(), synth.rule_count());
    assert_eq!(back.constraint_count(), synth.constraint_count());
    assert_eq!(back.synthesis_count(), synth.synthesis_count());
}

// ===========================================================================
// 12. Bifurcation instability trigger
// ===========================================================================

#[test]
fn bifurcation_instability_fires_when_risk_exceeds_threshold() {
    let rules = vec![basic_rule(
        "bifurcation-check",
        EvidenceTrigger::BifurcationInstability {
            min_risk_millionths: 200_000,
        },
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    // stability=600_000 → risk=400_000 ≥ 200_000 threshold
    let scan = make_scan_result(600_000, vec![], vec![]);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.has_bundles());
    assert_eq!(result.bundles[0].kind, BundleKind::SafeMode);
    assert_eq!(result.rules_fired, vec!["bifurcation-check"]);
}

#[test]
fn bifurcation_instability_skips_when_stable() {
    let rules = vec![basic_rule(
        "r-bif",
        EvidenceTrigger::BifurcationInstability {
            min_risk_millionths: 200_000,
        },
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    // stability=900_000 → risk=100_000 < 200_000 threshold
    let scan = make_scan_result(900_000, vec![], vec![]);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.has_bundles());
}

#[test]
fn bifurcation_with_preemptive_actions_uses_them() {
    let rules = vec![basic_rule(
        "r-bif",
        EvidenceTrigger::BifurcationInstability {
            min_risk_millionths: 200_000,
        },
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let actions = vec![make_preemptive_action("pa1", 400_000)];
    let scan = make_scan_result(500_000, vec![], actions); // risk=500_000
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.has_bundles());
    assert_eq!(result.bundles[0].deltas.len(), 1);
    assert!(result.bundles[0].deltas[0].delta_id.contains("pa1"));
}

// ===========================================================================
// 13. Early warning trigger
// ===========================================================================

#[test]
fn early_warning_fires_when_enough_active() {
    let rules = vec![basic_rule(
        "r-ew",
        EvidenceTrigger::EarlyWarningActive {
            min_active_count: 2,
        },
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let warnings = vec![
        make_warning("w1", 800_000, true),
        make_warning("w2", 700_000, true),
        make_warning("w3", 300_000, false), // inactive
    ];
    let scan = make_scan_result(700_000, warnings, vec![]);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.has_bundles());
    // Uses max risk of active warnings
    assert_eq!(
        result.bundles[0].deltas[0].expected_improvement_millionths,
        800_000
    );
}

#[test]
fn early_warning_skips_insufficient_active() {
    let rules = vec![basic_rule(
        "r-ew",
        EvidenceTrigger::EarlyWarningActive {
            min_active_count: 3,
        },
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let warnings = vec![
        make_warning("w1", 800_000, true),
        make_warning("w2", 700_000, true), // only 2 active, need 3
    ];
    let scan = make_scan_result(700_000, warnings, vec![]);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.has_bundles());
}

// ===========================================================================
// 14. Preemptive action trigger
// ===========================================================================

#[test]
fn preemptive_action_trigger_produces_deltas() {
    let rules = vec![basic_rule(
        "r-pre",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let actions = vec![
        make_preemptive_action("pa1", 300_000),
        make_preemptive_action("pa2", 500_000),
    ];
    let scan = make_scan_result(700_000, vec![], actions);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.has_bundles());
    assert_eq!(result.bundles[0].deltas.len(), 2);
}

#[test]
fn preemptive_action_trigger_skips_when_empty() {
    let rules = vec![basic_rule(
        "r-pre",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let scan = make_scan_result(900_000, vec![], vec![]);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.has_bundles());
}

// ===========================================================================
// 15. Combined evidence trigger
// ===========================================================================

#[test]
fn combined_trigger_fires_when_both_thresholds_met() {
    let rules = vec![basic_rule(
        "r-combined",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 200_000,
        },
        BundleKind::Adaptive,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    let scan = make_scan_result(600_000, vec![], vec![]); // risk=400_000
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.has_bundles());
}

#[test]
fn combined_trigger_needs_both_thresholds() {
    let rules = vec![basic_rule(
        "r-combined",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 200_000,
        },
        BundleKind::Adaptive,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    // Good replay but stable scan (risk=100_000 < 200_000)
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let scan = make_scan_result(900_000, vec![], vec![]);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.has_bundles());
}

#[test]
fn combined_trigger_needs_replay_too() {
    let rules = vec![basic_rule(
        "r-combined",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 200_000,
        },
        BundleKind::Adaptive,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    // No replay evidence
    let scan = make_scan_result(600_000, vec![], vec![]);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.has_bundles());
}

// ===========================================================================
// 16. Multiple rules → multiple bundles
// ===========================================================================

#[test]
fn multiple_rules_produce_multiple_bundles() {
    let rules = vec![
        basic_rule(
            "r-replay",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        ),
        basic_rule(
            "r-preemptive",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        ),
    ];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    let actions = vec![make_preemptive_action("pa1", 300_000)];
    let scan = make_scan_result(700_000, vec![], actions);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.bundles.len(), 2);
    assert_eq!(result.rules_fired.len(), 2);
}

// ===========================================================================
// 17. Rule priority ordering
// ===========================================================================

#[test]
fn rules_fire_by_priority_order() {
    let mut r1 = basic_rule(
        "r-low-pri",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    r1.priority = 10;
    let mut r2 = basic_rule(
        "r-high-pri",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::SafeMode,
    );
    r2.priority = 1;
    let rules = vec![r1, r2]; // r-low-pri first in vec but r-high-pri has lower priority value
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    // r-high-pri fires first (priority 1 < 10)
    assert_eq!(result.rules_fired, vec!["r-high-pri", "r-low-pri"]);
}

// ===========================================================================
// 18. Soft constraint doesn't block approval
// ===========================================================================

#[test]
fn soft_constraint_violation_allows_approval() {
    let mut rule = basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    rule.min_confidence_millionths = 400_000; // lower so 500_000 confidence passes
    let mut constraint = basic_constraint("perf-soft", ConstraintCategory::Performance, false);
    constraint.max_regression_millionths = 0; // will fail
    let mut synth =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![constraint]).unwrap();

    let rec = make_recommendation("alt1", 500_000, 500_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(
        result.bundles[0].is_approved(),
        "soft constraint shouldn't block"
    );
    assert!(result.bundles[0].soft_violations > 0);
}

// ===========================================================================
// 19. Hard constraint blocks approval
// ===========================================================================

#[test]
fn hard_constraint_violation_blocks_approval() {
    let mut rule = basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    rule.min_confidence_millionths = 400_000; // lower so 500_000 confidence passes
    let mut constraint = basic_constraint("safety-hard", ConstraintCategory::Safety, true);
    constraint.max_regression_millionths = 0;
    let mut synth =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![constraint]).unwrap();

    // Low confidence → high uncertainty → regression estimate exceeds 0
    let rec = make_recommendation("alt1", 500_000, 500_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.bundles[0].is_approved());
    assert_eq!(result.rejected_count, 1);
}

// ===========================================================================
// 20. Adaptive bundle kind resolution
// ===========================================================================

#[test]
fn adaptive_resolves_to_safemode_with_critical_warnings() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 200_000,
        },
        BundleKind::Adaptive,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    // Critical warning: risk > threshold (900_000 > 750_000)
    let warnings = vec![make_warning("w1", 900_000, true)];
    let scan = make_scan_result(600_000, warnings, vec![]);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.bundles[0].kind, BundleKind::SafeMode);
}

#[test]
fn adaptive_resolves_to_rollback_without_critical() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 200_000,
        },
        BundleKind::Adaptive,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    // No warnings, no preemptive actions
    let scan = make_scan_result(600_000, vec![], vec![]);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.bundles[0].kind, BundleKind::Rollback);
}

#[test]
fn adaptive_resolves_to_safemode_with_preemptive_actions() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 200_000,
        },
        BundleKind::Adaptive,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    let actions = vec![make_preemptive_action("pa1", 400_000)];
    let scan = make_scan_result(600_000, vec![], actions);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.bundles[0].kind, BundleKind::SafeMode);
}

// ===========================================================================
// 21. Delta sorting within bundles
// ===========================================================================

#[test]
fn deltas_sorted_by_improvement_descending() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    )];
    let config = SynthesizerConfig {
        epoch: test_epoch(),
        min_confidence_millionths: 500_000,
        ..SynthesizerConfig::default()
    };
    let mut synth = RollbackSafemodeSynthesizer::new(config, rules, vec![]).unwrap();

    let recs = vec![
        make_recommendation("alt1", 150_000, 950_000),
        make_recommendation("alt2", 300_000, 950_000),
        make_recommendation("alt3", 200_000, 950_000),
    ];
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(recs)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let improvements: Vec<i64> = result.bundles[0]
        .deltas
        .iter()
        .map(|d| d.expected_improvement_millionths)
        .collect();
    assert_eq!(improvements, vec![300_000, 200_000, 150_000]);
}

// ===========================================================================
// 22. Bundle sorting by total improvement
// ===========================================================================

#[test]
fn bundles_sorted_by_total_improvement_descending() {
    let rules = vec![
        basic_rule(
            "r-replay",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        ),
        basic_rule(
            "r-preemptive",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        ),
    ];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    let actions = vec![make_preemptive_action("pa1", 600_000)]; // Higher improvement
    let scan = make_scan_result(700_000, vec![], actions);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(
        result.bundles[0].total_improvement_millionths
            >= result.bundles[1].total_improvement_millionths,
        "bundles should be sorted by improvement descending"
    );
}

// ===========================================================================
// 23. SafeMode verification hook
// ===========================================================================

#[test]
fn safemode_bundle_gets_safemode_hook() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let actions = vec![make_preemptive_action("pa1", 300_000)];
    let scan = make_scan_result(700_000, vec![], actions);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(
        result.bundles[0]
            .verification_hooks
            .iter()
            .any(|h| h.verification_kind == VerificationKind::SafeModeReplay)
    );
}

// ===========================================================================
// 24. Stability hook for multi-delta
// ===========================================================================

#[test]
fn stability_hook_added_for_multiple_deltas() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    )];
    let config = SynthesizerConfig {
        epoch: test_epoch(),
        min_confidence_millionths: 500_000,
        ..SynthesizerConfig::default()
    };
    let mut synth = RollbackSafemodeSynthesizer::new(config, rules, vec![]).unwrap();

    let recs = vec![
        make_recommendation("alt1", 200_000, 950_000),
        make_recommendation("alt2", 300_000, 950_000),
    ];
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(recs)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(
        result.bundles[0]
            .verification_hooks
            .iter()
            .any(|h| h.verification_kind == VerificationKind::StabilityReplay)
    );
}

#[test]
fn no_stability_hook_for_single_delta() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(
        !result.bundles[0]
            .verification_hooks
            .iter()
            .any(|h| h.verification_kind == VerificationKind::StabilityReplay)
    );
}

// ===========================================================================
// 25. No hooks when disabled
// ===========================================================================

#[test]
fn no_verification_hooks_when_disabled() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    )];
    let config = SynthesizerConfig {
        epoch: test_epoch(),
        generate_verification_hooks: false,
        ..SynthesizerConfig::default()
    };
    let mut synth = RollbackSafemodeSynthesizer::new(config, rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.bundles[0].verification_hooks.is_empty());
}

// ===========================================================================
// 26. Both evidence sources in refs
// ===========================================================================

#[test]
fn evidence_refs_contain_both_sources() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 100_000,
            min_bifurcation_risk_millionths: 200_000,
        },
        BundleKind::Adaptive,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    let scan = make_scan_result(600_000, vec![], vec![]);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.bundles[0].evidence_refs.len(), 2);
    let sources: Vec<_> = result.bundles[0]
        .evidence_refs
        .iter()
        .map(|r| r.source)
        .collect();
    assert!(sources.contains(&EvidenceSource::CounterfactualReplay));
    assert!(sources.contains(&EvidenceSource::BifurcationScan));
}

#[test]
fn evidence_refs_replay_only() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.bundles[0].evidence_refs.len(), 1);
    assert_eq!(
        result.bundles[0].evidence_refs[0].source,
        EvidenceSource::CounterfactualReplay
    );
}

// ===========================================================================
// 27. Zero confidence skipped
// ===========================================================================

#[test]
fn zero_confidence_recommendation_skipped() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 0);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.has_bundles());
}

// ===========================================================================
// 28. Multiple recommendations filtered
// ===========================================================================

#[test]
fn recommendations_filtered_by_improvement_and_confidence() {
    let mut synth = default_synthesizer();
    let recs = vec![
        make_recommendation("alt1", 50_000, 950_000), // Too low improvement (< 100_000)
        make_recommendation("alt2", 200_000, 100_000), // Too low confidence (< 900_000)
        make_recommendation("alt3", 200_000, 950_000), // Good
    ];
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(recs)),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.bundles[0].deltas.len(), 1);
    assert!(result.bundles[0].deltas[0].delta_id.contains("alt3"));
}

// ===========================================================================
// 29. Unsafe recommendation skipped
// ===========================================================================

#[test]
fn unsafe_recommendation_skipped() {
    let mut synth = default_synthesizer();
    let rec = Recommendation {
        rank: 1,
        policy_id: PolicyId("alt1".into()),
        expected_improvement_millionths: 200_000,
        confidence_millionths: 950_000,
        safety_status: EnvelopeStatus::Unsafe,
        rationale: "looks risky".into(),
    };
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.has_bundles());
}

// ===========================================================================
// 30. Violation count
// ===========================================================================

#[test]
fn bundle_violation_count_correct() {
    let bundle = SynthesizedBundle {
        bundle_id: "b1".into(),
        schema_version: SYNTHESIZER_SCHEMA_VERSION.into(),
        kind: BundleKind::SafeMode,
        synthesis_epoch: test_epoch(),
        deltas: vec![PolicyDelta {
            delta_id: "d1".into(),
            source_rule_id: "r1".into(),
            action: LaneAction::FallbackSafe,
            effective_epoch: test_epoch(),
            expected_improvement_millionths: 100_000,
            confidence_millionths: 950_000,
            rationale: "test".into(),
        }],
        constraint_checks: vec![
            ConstraintCheckResult {
                constraint_id: "c1".into(),
                passed: true,
                regression_millionths: 0,
                detail: "ok".into(),
            },
            ConstraintCheckResult {
                constraint_id: "c2".into(),
                passed: false,
                regression_millionths: 60_000,
                detail: "exceeded".into(),
            },
            ConstraintCheckResult {
                constraint_id: "c3".into(),
                passed: false,
                regression_millionths: 30_000,
                detail: "borderline".into(),
            },
        ],
        all_hard_constraints_passed: false,
        soft_violations: 2,
        total_improvement_millionths: 100_000,
        min_confidence_millionths: 950_000,
        verification_hooks: vec![],
        evidence_refs: vec![],
        artifact_hash: ContentHash::compute(b"mixed"),
    };
    assert_eq!(bundle.violation_count(), 2);
    assert!(!bundle.is_approved());
}

// ===========================================================================
// 31. High confidence yields zero regression
// ===========================================================================

#[test]
fn high_confidence_yields_zero_regression() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    )];
    let constraints = vec![basic_constraint(
        "perf",
        ConstraintCategory::Performance,
        true,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, constraints).unwrap();

    // Perfect confidence → uncertainty=0 → regression=0
    let rec = make_recommendation("alt1", 200_000, 1_000_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let check = &result.bundles[0].constraint_checks[0];
    assert_eq!(check.regression_millionths, 0);
    assert!(check.passed);
}

// ===========================================================================
// 32. Safety constraint more conservative than performance
// ===========================================================================

#[test]
fn safety_constraint_more_conservative_than_performance() {
    let mut rule = basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    rule.min_confidence_millionths = 500_000; // lower so 800_000 confidence passes
    let constraints = vec![
        basic_constraint("safety", ConstraintCategory::Safety, true),
        basic_constraint("perf", ConstraintCategory::Performance, true),
    ];
    let mut synth =
        RollbackSafemodeSynthesizer::new(default_config(), vec![rule], constraints).unwrap();

    let rec = make_recommendation("alt1", 200_000, 800_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let safety_reg = result.bundles[0]
        .constraint_checks
        .iter()
        .find(|c| c.constraint_id == "safety")
        .unwrap()
        .regression_millionths;
    let perf_reg = result.bundles[0]
        .constraint_checks
        .iter()
        .find(|c| c.constraint_id == "perf")
        .unwrap()
        .regression_millionths;
    // Safety has higher category factor (3 vs 1), so lower regression estimate
    assert!(safety_reg <= perf_reg);
}

// ===========================================================================
// 33. Artifact hash determinism
// ===========================================================================

#[test]
fn artifact_hash_deterministic_across_instances() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    )];
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };

    let mut s1 = RollbackSafemodeSynthesizer::new(default_config(), rules.clone(), vec![]).unwrap();
    let r1 = s1.synthesize(&input).unwrap();

    let mut s2 = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();
    let r2 = s2.synthesize(&input).unwrap();

    assert_eq!(r1.artifact_hash, r2.artifact_hash);
    assert_eq!(r1.bundles[0].artifact_hash, r2.bundles[0].artifact_hash);
}

// ===========================================================================
// 34. SynthesisInput edge cases
// ===========================================================================

#[test]
fn synthesis_input_has_evidence_scan_only() {
    let scan = make_scan_result(900_000, vec![], vec![]);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    assert!(input.has_evidence());
}

#[test]
fn synthesis_input_serde_both_none() {
    let input = SynthesisInput {
        replay_result: None,
        scan_result: None,
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: SynthesisInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, input);
    assert!(!back.has_evidence());
}

// ===========================================================================
// 35. Disabled rule skipped
// ===========================================================================

#[test]
fn disabled_rule_appears_in_rules_skipped() {
    let mut rule = basic_rule(
        "disabled-rule",
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 100_000,
        },
        BundleKind::Rollback,
    );
    rule.enabled = false;
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), vec![rule], vec![]).unwrap();

    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(!result.has_bundles());
    assert!(result.rules_skipped.contains(&"disabled-rule".to_string()));
}

// ===========================================================================
// 36. Constructor validation edge cases
// ===========================================================================

#[test]
fn constructor_rejects_too_many_constraints() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    )];
    let constraints: Vec<_> = (0..129)
        .map(|i| basic_constraint(&format!("c{i}"), ConstraintCategory::Safety, true))
        .collect();
    let result = RollbackSafemodeSynthesizer::new(default_config(), rules, constraints);
    assert!(matches!(
        result,
        Err(SynthesizerError::TooManyConstraints {
            count: 129,
            max: 128
        })
    ));
}

#[test]
fn constructor_rejects_negative_confidence() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    )];
    let config = SynthesizerConfig {
        epoch: test_epoch(),
        min_confidence_millionths: -1,
        ..SynthesizerConfig::default()
    };
    let result = RollbackSafemodeSynthesizer::new(config, rules, vec![]);
    assert!(matches!(
        result,
        Err(SynthesizerError::InvalidConfig { .. })
    ));
}

#[test]
fn constructor_rejects_over_million_confidence() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    )];
    let config = SynthesizerConfig {
        epoch: test_epoch(),
        min_confidence_millionths: 1_000_001,
        ..SynthesizerConfig::default()
    };
    let result = RollbackSafemodeSynthesizer::new(config, rules, vec![]);
    assert!(matches!(
        result,
        Err(SynthesizerError::InvalidConfig { .. })
    ));
}

// ===========================================================================
// 37. JSON field-name stability
// ===========================================================================

#[test]
fn json_field_names_stable_synthesis_rule() {
    let rule = basic_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    );
    let json = serde_json::to_string(&rule).unwrap();
    for field in [
        "rule_id",
        "description",
        "trigger",
        "min_confidence_millionths",
        "priority",
        "output_kind",
        "enabled",
    ] {
        assert!(json.contains(field), "missing field {field} in {json}");
    }
}

#[test]
fn json_field_names_stable_policy_delta() {
    let delta = PolicyDelta {
        delta_id: "d1".into(),
        source_rule_id: "r1".into(),
        action: LaneAction::FallbackSafe,
        effective_epoch: test_epoch(),
        expected_improvement_millionths: 200_000,
        confidence_millionths: 950_000,
        rationale: "test".into(),
    };
    let json = serde_json::to_string(&delta).unwrap();
    for field in [
        "delta_id",
        "source_rule_id",
        "action",
        "effective_epoch",
        "expected_improvement_millionths",
        "confidence_millionths",
        "rationale",
    ] {
        assert!(json.contains(field), "missing field {field} in {json}");
    }
}

#[test]
fn json_field_names_stable_synthesized_bundle() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let json = serde_json::to_string(&result.bundles[0]).unwrap();
    for field in [
        "bundle_id",
        "schema_version",
        "kind",
        "synthesis_epoch",
        "deltas",
        "constraint_checks",
        "all_hard_constraints_passed",
        "soft_violations",
        "total_improvement_millionths",
        "min_confidence_millionths",
        "verification_hooks",
        "evidence_refs",
        "artifact_hash",
    ] {
        assert!(json.contains(field), "missing field {field} in {json}");
    }
}

#[test]
fn json_field_names_stable_synthesis_result() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    for field in [
        "schema_version",
        "epoch",
        "rules_fired",
        "rules_skipped",
        "bundles",
        "approved_count",
        "rejected_count",
        "artifact_hash",
    ] {
        assert!(json.contains(field), "missing field {field} in {json}");
    }
}

// ===========================================================================
// 38. Debug distinctness
// ===========================================================================

#[test]
fn debug_distinctness_bundle_kind() {
    let mut seen = std::collections::BTreeSet::new();
    for kind in [
        BundleKind::Rollback,
        BundleKind::SafeMode,
        BundleKind::Adaptive,
    ] {
        assert!(seen.insert(format!("{kind:?}")));
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn debug_distinctness_constraint_category() {
    let mut seen = std::collections::BTreeSet::new();
    for cat in [
        ConstraintCategory::Safety,
        ConstraintCategory::Performance,
        ConstraintCategory::Correctness,
        ConstraintCategory::Stability,
        ConstraintCategory::Compatibility,
    ] {
        assert!(seen.insert(format!("{cat:?}")));
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn debug_distinctness_verification_kind() {
    let mut seen = std::collections::BTreeSet::new();
    for vk in [
        VerificationKind::ImprovementReplay,
        VerificationKind::NonRegressionReplay,
        VerificationKind::StabilityReplay,
        VerificationKind::SafeModeReplay,
    ] {
        assert!(seen.insert(format!("{vk:?}")));
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn debug_distinctness_evidence_source() {
    let mut seen = std::collections::BTreeSet::new();
    for src in [
        EvidenceSource::CounterfactualReplay,
        EvidenceSource::BifurcationScan,
        EvidenceSource::Combined,
    ] {
        assert!(seen.insert(format!("{src:?}")));
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn debug_distinctness_evidence_trigger() {
    let mut seen = std::collections::BTreeSet::new();
    for trigger in [
        EvidenceTrigger::CounterfactualImprovement {
            min_improvement_millionths: 0,
        },
        EvidenceTrigger::BifurcationInstability {
            min_risk_millionths: 0,
        },
        EvidenceTrigger::EarlyWarningActive {
            min_active_count: 0,
        },
        EvidenceTrigger::PreemptiveActionRecommended,
        EvidenceTrigger::CombinedEvidence {
            min_replay_improvement_millionths: 0,
            min_bifurcation_risk_millionths: 0,
        },
    ] {
        assert!(seen.insert(format!("{trigger:?}")));
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn debug_distinctness_synthesizer_error() {
    let mut seen = std::collections::BTreeSet::new();
    for err in [
        SynthesizerError::NoRules,
        SynthesizerError::TooManyRules { count: 0, max: 0 },
        SynthesizerError::NoEvidence,
        SynthesizerError::TooManyDeltas { count: 0, max: 0 },
        SynthesizerError::TooManyConstraints { count: 0, max: 0 },
        SynthesizerError::DuplicateRule {
            rule_id: String::new(),
        },
        SynthesizerError::DuplicateConstraint {
            constraint_id: String::new(),
        },
        SynthesizerError::InvalidConfig {
            detail: String::new(),
        },
    ] {
        assert!(seen.insert(format!("{err:?}")));
    }
    assert_eq!(seen.len(), 8);
}

// ===========================================================================
// 39. E2E multi-rule synthesis with constraints
// ===========================================================================

#[test]
fn e2e_multi_rule_with_mixed_constraints() {
    let config = SynthesizerConfig {
        epoch: SecurityEpoch::from_raw(42),
        generate_verification_hooks: true,
        ..SynthesizerConfig::default()
    };

    let rules = vec![
        {
            let mut r = basic_rule(
                "replay-rollback",
                EvidenceTrigger::CounterfactualImprovement {
                    min_improvement_millionths: 100_000,
                },
                BundleKind::Rollback,
            );
            r.priority = 1;
            r
        },
        {
            let mut r = basic_rule(
                "safemode-instability",
                EvidenceTrigger::BifurcationInstability {
                    min_risk_millionths: 200_000,
                },
                BundleKind::SafeMode,
            );
            r.priority = 2;
            r
        },
    ];

    let constraints = vec![
        basic_constraint("safety", ConstraintCategory::Safety, true),
        basic_constraint("perf", ConstraintCategory::Performance, false),
    ];

    let mut synth = RollbackSafemodeSynthesizer::new(config, rules, constraints).unwrap();
    assert_eq!(synth.rule_count(), 2);
    assert_eq!(synth.constraint_count(), 2);
    assert_eq!(synth.synthesis_count(), 0);

    let rec = make_recommendation("alt-policy", 300_000, 960_000);
    let scan = make_scan_result(600_000, vec![], vec![]); // risk=400_000
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: Some(scan),
    };

    let result = synth.synthesize(&input).unwrap();
    assert_eq!(synth.synthesis_count(), 1);
    assert_eq!(result.schema_version, SYNTHESIZER_SCHEMA_VERSION);
    assert_eq!(result.epoch, SecurityEpoch::from_raw(42));
    assert!(result.has_bundles());
    assert_eq!(result.rules_fired.len(), 2);

    // Bundles sorted by total improvement
    for i in 0..result.bundles.len().saturating_sub(1) {
        assert!(
            result.bundles[i].total_improvement_millionths
                >= result.bundles[i + 1].total_improvement_millionths
        );
    }

    // Approved count + rejected count = total bundles
    assert_eq!(
        result.approved_count + result.rejected_count,
        result.bundles.len() as u64
    );

    // Every approved bundle has non-empty deltas
    for bundle in result.approved_bundles() {
        assert!(bundle.is_approved());
        assert!(bundle.delta_count() > 0);
        assert!(!bundle.verification_hooks.is_empty());
    }

    // Evidence refs present on each bundle
    for bundle in &result.bundles {
        assert!(
            !bundle.evidence_refs.is_empty(),
            "each bundle should have evidence refs"
        );
    }

    // Serde roundtrip of full result
    let json = serde_json::to_string(&result).unwrap();
    let back: SynthesisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

// ===========================================================================
// 40. E2E: second synthesis increments count and is independent
// ===========================================================================

#[test]
fn e2e_second_synthesis_independent() {
    let mut synth = default_synthesizer();

    let rec1 = make_recommendation("alt1", 200_000, 950_000);
    let input1 = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec1])),
        scan_result: None,
    };
    let result1 = synth.synthesize(&input1).unwrap();
    assert_eq!(synth.synthesis_count(), 1);

    let rec2 = make_recommendation("alt2", 400_000, 980_000);
    let input2 = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec2])),
        scan_result: None,
    };
    let result2 = synth.synthesize(&input2).unwrap();
    assert_eq!(synth.synthesis_count(), 2);

    // Different improvements → different artifact hashes
    assert_ne!(result1.artifact_hash, result2.artifact_hash);
    assert!(
        result2.bundles[0].total_improvement_millionths
            > result1.bundles[0].total_improvement_millionths
    );
}

// ===========================================================================
// 41. Scan-only evidence with preemptive trigger
// ===========================================================================

#[test]
fn scan_only_evidence_produces_scan_ref_only() {
    let rules = vec![basic_rule(
        "r1",
        EvidenceTrigger::PreemptiveActionRecommended,
        BundleKind::SafeMode,
    )];
    let mut synth = RollbackSafemodeSynthesizer::new(default_config(), rules, vec![]).unwrap();

    let actions = vec![make_preemptive_action("pa1", 300_000)];
    let scan = make_scan_result(700_000, vec![], actions);
    let input = SynthesisInput {
        replay_result: None,
        scan_result: Some(scan),
    };
    let result = synth.synthesize(&input).unwrap();
    assert!(result.has_bundles());
    assert_eq!(result.bundles[0].evidence_refs.len(), 1);
    assert_eq!(
        result.bundles[0].evidence_refs[0].source,
        EvidenceSource::BifurcationScan
    );
}

// ===========================================================================
// 42. Schema version propagation
// ===========================================================================

#[test]
fn schema_version_propagates_to_bundles_and_result() {
    let mut synth = default_synthesizer();
    let rec = make_recommendation("alt1", 200_000, 950_000);
    let input = SynthesisInput {
        replay_result: Some(make_replay_result(vec![rec])),
        scan_result: None,
    };
    let result = synth.synthesize(&input).unwrap();
    assert_eq!(result.schema_version, SYNTHESIZER_SCHEMA_VERSION);
    for bundle in &result.bundles {
        assert_eq!(bundle.schema_version, SYNTHESIZER_SCHEMA_VERSION);
    }
}
