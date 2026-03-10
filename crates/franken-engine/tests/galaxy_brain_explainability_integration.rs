#![forbid(unsafe_code)]

//! Integration tests for the `galaxy_brain_explainability` module.
//!
//! Covers: VerbosityLevel, DecisionDomain, GoverningEquation, RejectionReason,
//! ExplainedAlternative, ConstraintInteraction, RiskBreakdown,
//! CounterfactualOutcome, DecisionExplanation, ExplanationBuilder,
//! ExplanationIndex, ExplainabilityReport, generate_report,
//! explain_lane_routing, explain_fallback, and serde round-trips for all types.

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

use frankenengine_engine::galaxy_brain_explainability::*;
use frankenengine_engine::runtime_decision_theory::{
    DemotionReason, LaneAction, LaneId, RegimeLabel,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

const MILLION: i64 = 1_000_000;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn lane(name: &str) -> LaneId {
    LaneId(name.to_string())
}

/// Build a minimal valid explanation via the builder.
fn minimal_expl(
    decision_id: &str,
    ep: SecurityEpoch,
    domain: DecisionDomain,
) -> DecisionExplanation {
    ExplanationBuilder::new(decision_id.to_string(), ep, domain)
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("auto".to_string())
        .build()
        .unwrap()
}

// =========================================================================
// Section 1: VerbosityLevel
// =========================================================================

#[test]
fn verbosity_default_is_standard() {
    assert_eq!(VerbosityLevel::default(), VerbosityLevel::Standard);
}

#[test]
fn verbosity_display_all_variants() {
    assert_eq!(VerbosityLevel::Minimal.to_string(), "minimal");
    assert_eq!(VerbosityLevel::Standard.to_string(), "standard");
    assert_eq!(VerbosityLevel::GalaxyBrain.to_string(), "galaxy_brain");
}

#[test]
fn verbosity_ordering() {
    assert!(VerbosityLevel::Minimal < VerbosityLevel::Standard);
    assert!(VerbosityLevel::Standard < VerbosityLevel::GalaxyBrain);
    assert!(VerbosityLevel::Minimal < VerbosityLevel::GalaxyBrain);
}

#[test]
fn verbosity_serde_roundtrip_all_variants() {
    for v in [
        VerbosityLevel::Minimal,
        VerbosityLevel::Standard,
        VerbosityLevel::GalaxyBrain,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: VerbosityLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn verbosity_serde_snake_case_names() {
    assert_eq!(
        serde_json::to_string(&VerbosityLevel::GalaxyBrain).unwrap(),
        "\"galaxy_brain\""
    );
    assert_eq!(
        serde_json::to_string(&VerbosityLevel::Minimal).unwrap(),
        "\"minimal\""
    );
}

#[test]
fn verbosity_clone_and_copy() {
    let v = VerbosityLevel::GalaxyBrain;
    let v2 = v;
    let v3 = v;
    assert_eq!(v, v2);
    assert_eq!(v, v3);
}

// =========================================================================
// Section 2: DecisionDomain
// =========================================================================

#[test]
fn domain_display_all_five() {
    let expected = [
        (DecisionDomain::LaneRouting, "lane_routing"),
        (DecisionDomain::Fallback, "fallback"),
        (DecisionDomain::Optimization, "optimization"),
        (DecisionDomain::Security, "security"),
        (DecisionDomain::Governance, "governance"),
    ];
    for (d, name) in &expected {
        assert_eq!(d.to_string(), *name);
    }
}

#[test]
fn domain_serde_roundtrip_all_variants() {
    for d in [
        DecisionDomain::LaneRouting,
        DecisionDomain::Fallback,
        DecisionDomain::Optimization,
        DecisionDomain::Security,
        DecisionDomain::Governance,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: DecisionDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

#[test]
fn domain_display_uniqueness() {
    let domains = [
        DecisionDomain::LaneRouting,
        DecisionDomain::Fallback,
        DecisionDomain::Optimization,
        DecisionDomain::Security,
        DecisionDomain::Governance,
    ];
    let mut set = std::collections::BTreeSet::new();
    for d in &domains {
        set.insert(d.to_string());
    }
    assert_eq!(set.len(), 5);
}

// =========================================================================
// Section 3: GoverningEquation
// =========================================================================

#[test]
fn equation_plain_language_threshold_exceeded() {
    let eq = GoverningEquation {
        name: "CVaR check".to_string(),
        formula: "CVaR(alpha) = E[L | L > VaR(alpha)]".to_string(),
        parameters: BTreeMap::from([("alpha".to_string(), 50_000)]),
        result_millionths: 800_000,
        threshold_millionths: Some(500_000),
        threshold_exceeded: true,
    };
    let text = eq.plain_language();
    assert!(text.contains("exceeded"));
    assert!(text.contains("CVaR check"));
    assert!(text.contains("0.800000"));
    assert!(text.contains("0.500000"));
}

#[test]
fn equation_plain_language_within_threshold() {
    let eq = GoverningEquation {
        name: "budget".to_string(),
        formula: "remaining >= min".to_string(),
        parameters: BTreeMap::new(),
        result_millionths: 300_000,
        threshold_millionths: Some(500_000),
        threshold_exceeded: false,
    };
    let text = eq.plain_language();
    assert!(text.contains("within"));
    assert!(text.contains("budget"));
}

#[test]
fn equation_plain_language_no_threshold() {
    let eq = GoverningEquation {
        name: "expected_loss".to_string(),
        formula: "E[L]".to_string(),
        parameters: BTreeMap::new(),
        result_millionths: 123_456,
        threshold_millionths: None,
        threshold_exceeded: false,
    };
    let text = eq.plain_language();
    assert!(text.contains("expected_loss"));
    assert!(text.contains("computed"));
    assert!(!text.contains("threshold"));
}

#[test]
fn equation_serde_roundtrip() {
    let eq = GoverningEquation {
        name: "test".to_string(),
        formula: "x + y".to_string(),
        parameters: BTreeMap::from([("x".to_string(), 100), ("y".to_string(), 200)]),
        result_millionths: 300,
        threshold_millionths: Some(500),
        threshold_exceeded: false,
    };
    let json = serde_json::to_string(&eq).unwrap();
    let back: GoverningEquation = serde_json::from_str(&json).unwrap();
    assert_eq!(eq, back);
}

#[test]
fn equation_with_many_parameters() {
    let mut params = BTreeMap::new();
    for i in 0..20 {
        params.insert(format!("param_{i}"), i * 100_000);
    }
    let eq = GoverningEquation {
        name: "multi-param".to_string(),
        formula: "sum(params)".to_string(),
        parameters: params.clone(),
        result_millionths: 19_000_000,
        threshold_millionths: None,
        threshold_exceeded: false,
    };
    let json = serde_json::to_string(&eq).unwrap();
    let back: GoverningEquation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.parameters.len(), 20);
}

// =========================================================================
// Section 4: RejectionReason
// =========================================================================

#[test]
fn rejection_reason_display_all() {
    let expected = [
        (RejectionReason::HigherLoss, "higher_loss"),
        (RejectionReason::GuardrailViolation, "guardrail_violation"),
        (RejectionReason::BudgetInsufficient, "budget_insufficient"),
        (
            RejectionReason::CalibrationInsufficient,
            "calibration_insufficient",
        ),
        (RejectionReason::RegimeRestriction, "regime_restriction"),
        (RejectionReason::PolicyForbidden, "policy_forbidden"),
    ];
    for (r, s) in &expected {
        assert_eq!(r.to_string(), *s);
    }
}

#[test]
fn rejection_reason_serde_roundtrip_all() {
    for r in [
        RejectionReason::HigherLoss,
        RejectionReason::GuardrailViolation,
        RejectionReason::BudgetInsufficient,
        RejectionReason::CalibrationInsufficient,
        RejectionReason::RegimeRestriction,
        RejectionReason::PolicyForbidden,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn rejection_reason_ord() {
    // Just verify ordering is implemented and consistent.
    let a = RejectionReason::HigherLoss;
    let b = RejectionReason::PolicyForbidden;
    assert!(a <= b || a >= b);
}

// =========================================================================
// Section 5: ExplainedAlternative
// =========================================================================

#[test]
fn explained_alternative_serde_roundtrip() {
    let alt = ExplainedAlternative {
        action: LaneAction::RouteTo(lane("wasm")),
        expected_loss_millionths: 500_000,
        rejection_reason: RejectionReason::HigherLoss,
        detail: "wasm lane has higher loss".to_string(),
    };
    let json = serde_json::to_string(&alt).unwrap();
    let back: ExplainedAlternative = serde_json::from_str(&json).unwrap();
    assert_eq!(alt, back);
}

#[test]
fn explained_alternative_with_demote_action() {
    let alt = ExplainedAlternative {
        action: LaneAction::Demote {
            from_lane: lane("fast"),
            reason: DemotionReason::DriftDetected,
        },
        expected_loss_millionths: 0,
        rejection_reason: RejectionReason::RegimeRestriction,
        detail: "not in degraded regime".to_string(),
    };
    let json = serde_json::to_string(&alt).unwrap();
    let back: ExplainedAlternative = serde_json::from_str(&json).unwrap();
    assert_eq!(alt, back);
}

// =========================================================================
// Section 6: ConstraintInteraction
// =========================================================================

#[test]
fn constraint_serde_roundtrip() {
    let c = ConstraintInteraction {
        constraint_id: "budget-floor".to_string(),
        description: "minimum budget".to_string(),
        binding: true,
        slack_millionths: 0,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: ConstraintInteraction = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn constraint_non_binding_has_slack() {
    let c = ConstraintInteraction {
        constraint_id: "latency-cap".to_string(),
        description: "p99 latency cap".to_string(),
        binding: false,
        slack_millionths: 250_000,
    };
    assert!(!c.binding);
    assert!(c.slack_millionths > 0);
}

// =========================================================================
// Section 7: RiskBreakdown
// =========================================================================

#[test]
fn risk_breakdown_serde_roundtrip() {
    let r = RiskBreakdown {
        factor: "latency".to_string(),
        weight_millionths: 300_000,
        belief_millionths: 700_000,
        contribution_millionths: 210_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: RiskBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// =========================================================================
// Section 8: CounterfactualOutcome
// =========================================================================

#[test]
fn counterfactual_serde_roundtrip() {
    let cf = CounterfactualOutcome {
        action: LaneAction::FallbackSafe,
        predicted_loss_millionths: 0,
        loss_delta_millionths: -100_000,
        would_trigger_guardrail: false,
        narrative: "safe mode avoids all risk".to_string(),
    };
    let json = serde_json::to_string(&cf).unwrap();
    let back: CounterfactualOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(cf, back);
}

#[test]
fn counterfactual_positive_delta_means_worse() {
    let cf = CounterfactualOutcome {
        action: LaneAction::RouteTo(lane("expensive")),
        predicted_loss_millionths: 900_000,
        loss_delta_millionths: 400_000,
        would_trigger_guardrail: true,
        narrative: "expensive lane triggers guardrail".to_string(),
    };
    assert!(cf.loss_delta_millionths > 0);
    assert!(cf.would_trigger_guardrail);
}

// =========================================================================
// Section 9: SCHEMA_VERSION constant
// =========================================================================

#[test]
fn schema_version_is_expected() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.galaxy-brain-explainability.v1"
    );
}

// =========================================================================
// Section 10: DecisionExplanation::compute_id
// =========================================================================

#[test]
fn compute_id_deterministic() {
    let id1 = DecisionExplanation::compute_id("d-1", &epoch(42), &DecisionDomain::Fallback);
    let id2 = DecisionExplanation::compute_id("d-1", &epoch(42), &DecisionDomain::Fallback);
    assert_eq!(id1, id2);
}

#[test]
fn compute_id_starts_with_expl_prefix() {
    let id = DecisionExplanation::compute_id("d-1", &epoch(1), &DecisionDomain::Security);
    assert!(id.starts_with("expl-"));
}

#[test]
fn compute_id_differs_by_decision_id() {
    let id1 = DecisionExplanation::compute_id("d-1", &epoch(1), &DecisionDomain::Fallback);
    let id2 = DecisionExplanation::compute_id("d-2", &epoch(1), &DecisionDomain::Fallback);
    assert_ne!(id1, id2);
}

#[test]
fn compute_id_differs_by_epoch() {
    let id1 = DecisionExplanation::compute_id("d-1", &epoch(1), &DecisionDomain::Fallback);
    let id2 = DecisionExplanation::compute_id("d-1", &epoch(2), &DecisionDomain::Fallback);
    assert_ne!(id1, id2);
}

#[test]
fn compute_id_differs_by_domain() {
    let id1 = DecisionExplanation::compute_id("d-1", &epoch(1), &DecisionDomain::LaneRouting);
    let id2 = DecisionExplanation::compute_id("d-1", &epoch(1), &DecisionDomain::Fallback);
    assert_ne!(id1, id2);
}

// =========================================================================
// Section 11: DecisionExplanation methods
// =========================================================================

#[test]
fn one_line_summary_contains_key_fields() {
    let expl = ExplanationBuilder::new("d-10".to_string(), epoch(42), DecisionDomain::LaneRouting)
        .chosen(LaneAction::RouteTo(lane("js")), 100_000)
        .rationale("lowest loss lane".to_string())
        .build()
        .unwrap();

    let summary = expl.one_line_summary();
    assert!(summary.contains("d-10"));
    assert!(summary.contains("lane_routing"));
    assert!(summary.contains("lowest loss lane"));
    assert!(summary.contains("100000"));
}

#[test]
fn candidates_considered_with_no_alternatives() {
    let expl = minimal_expl("d-cc0", epoch(1), DecisionDomain::Fallback);
    assert_eq!(expl.candidates_considered(), 1);
}

#[test]
fn candidates_considered_with_many_alternatives() {
    let mut builder =
        ExplanationBuilder::new("d-cc1".to_string(), epoch(1), DecisionDomain::LaneRouting)
            .chosen(LaneAction::RouteTo(lane("js")), 100_000)
            .rationale("best".to_string());

    for i in 0..7 {
        builder = builder.alternative(ExplainedAlternative {
            action: LaneAction::RouteTo(lane(&format!("alt-{i}"))),
            expected_loss_millionths: (i as i64 + 2) * 100_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: format!("alt-{i} rejected"),
        });
    }

    let expl = builder.build().unwrap();
    assert_eq!(expl.candidates_considered(), 8);
}

#[test]
fn has_binding_constraint_false_when_empty() {
    let expl = minimal_expl("d-bc0", epoch(1), DecisionDomain::Security);
    assert!(!expl.has_binding_constraint());
}

#[test]
fn has_binding_constraint_true_when_present() {
    let expl = ExplanationBuilder::new("d-bc1".to_string(), epoch(1), DecisionDomain::Fallback)
        .chosen(LaneAction::FallbackSafe, 0)
        .constraint(ConstraintInteraction {
            constraint_id: "c1".to_string(),
            description: "binding constraint".to_string(),
            binding: true,
            slack_millionths: 0,
        })
        .rationale("bound".to_string())
        .build()
        .unwrap();

    assert!(expl.has_binding_constraint());
}

#[test]
fn has_binding_constraint_false_when_all_non_binding() {
    let expl = ExplanationBuilder::new("d-bc2".to_string(), epoch(1), DecisionDomain::Fallback)
        .chosen(LaneAction::FallbackSafe, 0)
        .constraint(ConstraintInteraction {
            constraint_id: "c1".to_string(),
            description: "loose".to_string(),
            binding: false,
            slack_millionths: 500_000,
        })
        .rationale("free".to_string())
        .build()
        .unwrap();

    assert!(!expl.has_binding_constraint());
}

#[test]
fn total_risk_millionths_empty() {
    let expl = minimal_expl("d-tr0", epoch(1), DecisionDomain::Optimization);
    assert_eq!(expl.total_risk_millionths(), 0);
}

#[test]
fn total_risk_millionths_sums_contributions() {
    let expl = ExplanationBuilder::new("d-tr1".to_string(), epoch(1), DecisionDomain::Security)
        .chosen(LaneAction::FallbackSafe, 0)
        .risk(RiskBreakdown {
            factor: "a".to_string(),
            weight_millionths: 500_000,
            belief_millionths: 400_000,
            contribution_millionths: 200_000,
        })
        .risk(RiskBreakdown {
            factor: "b".to_string(),
            weight_millionths: 500_000,
            belief_millionths: 600_000,
            contribution_millionths: 300_000,
        })
        .rationale("assessment".to_string())
        .build()
        .unwrap();

    assert_eq!(expl.total_risk_millionths(), 500_000);
}

#[test]
fn explanation_serde_roundtrip_full() {
    let expl =
        ExplanationBuilder::new("d-sr1".to_string(), epoch(42), DecisionDomain::Optimization)
            .verbosity(VerbosityLevel::GalaxyBrain)
            .regime(RegimeLabel::Elevated)
            .chosen(LaneAction::RouteTo(lane("wasm")), 200_000)
            .rationale("wasm optimized path".to_string())
            .equation(GoverningEquation {
                name: "eq1".to_string(),
                formula: "a + b".to_string(),
                parameters: BTreeMap::from([("a".to_string(), 100_000)]),
                result_millionths: 100_000,
                threshold_millionths: Some(500_000),
                threshold_exceeded: false,
            })
            .alternative(ExplainedAlternative {
                action: LaneAction::FallbackSafe,
                expected_loss_millionths: 0,
                rejection_reason: RejectionReason::PolicyForbidden,
                detail: "forbidden".to_string(),
            })
            .constraint(ConstraintInteraction {
                constraint_id: "c1".to_string(),
                description: "budget floor".to_string(),
                binding: false,
                slack_millionths: 300_000,
            })
            .risk(RiskBreakdown {
                factor: "latency".to_string(),
                weight_millionths: 500_000,
                belief_millionths: 400_000,
                contribution_millionths: 200_000,
            })
            .counterfactual(CounterfactualOutcome {
                action: LaneAction::SuspendAdaptive,
                predicted_loss_millionths: 0,
                loss_delta_millionths: -200_000,
                would_trigger_guardrail: false,
                narrative: "no risk at all".to_string(),
            })
            .posterior("latency".to_string(), 600_000)
            .confidence(850_000)
            .build()
            .unwrap();

    let json = serde_json::to_string_pretty(&expl).unwrap();
    let back: DecisionExplanation = serde_json::from_str(&json).unwrap();
    assert_eq!(expl, back);
}

// =========================================================================
// Section 12: ExplanationBuilder
// =========================================================================

#[test]
fn builder_returns_none_without_chosen_action() {
    let builder =
        ExplanationBuilder::new("d-bn".to_string(), epoch(1), DecisionDomain::LaneRouting);
    assert!(builder.build().is_none());
}

#[test]
fn builder_default_verbosity_is_standard() {
    let expl = ExplanationBuilder::new("d-dv".to_string(), epoch(1), DecisionDomain::LaneRouting)
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("test".to_string())
        .build()
        .unwrap();
    assert_eq!(expl.verbosity, VerbosityLevel::Standard);
}

#[test]
fn builder_default_regime_is_normal() {
    let expl = ExplanationBuilder::new("d-dr".to_string(), epoch(1), DecisionDomain::LaneRouting)
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("test".to_string())
        .build()
        .unwrap();
    assert_eq!(expl.regime, RegimeLabel::Normal);
}

#[test]
fn builder_sets_regime() {
    let expl = ExplanationBuilder::new("d-reg".to_string(), epoch(1), DecisionDomain::Security)
        .regime(RegimeLabel::Attack)
        .chosen(LaneAction::SuspendAdaptive, 0)
        .rationale("attack".to_string())
        .build()
        .unwrap();
    assert_eq!(expl.regime, RegimeLabel::Attack);
}

#[test]
fn builder_sets_verbosity() {
    let expl = ExplanationBuilder::new("d-vb".to_string(), epoch(1), DecisionDomain::Governance)
        .verbosity(VerbosityLevel::Minimal)
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("minimal".to_string())
        .build()
        .unwrap();
    assert_eq!(expl.verbosity, VerbosityLevel::Minimal);
}

#[test]
fn builder_explanation_id_matches_compute_id() {
    let ep = epoch(99);
    let domain = DecisionDomain::Governance;
    let did = "d-eid";
    let expected_id = DecisionExplanation::compute_id(did, &ep, &domain);

    let expl = ExplanationBuilder::new(did.to_string(), ep, domain)
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("test".to_string())
        .build()
        .unwrap();

    assert_eq!(expl.explanation_id, expected_id);
}

#[test]
fn builder_multiple_equations() {
    let expl = ExplanationBuilder::new("d-meq".to_string(), epoch(1), DecisionDomain::Optimization)
        .chosen(LaneAction::RouteTo(lane("fast")), 50_000)
        .equation(GoverningEquation {
            name: "eq1".to_string(),
            formula: "x".to_string(),
            parameters: BTreeMap::new(),
            result_millionths: 100_000,
            threshold_millionths: None,
            threshold_exceeded: false,
        })
        .equation(GoverningEquation {
            name: "eq2".to_string(),
            formula: "y".to_string(),
            parameters: BTreeMap::new(),
            result_millionths: 200_000,
            threshold_millionths: None,
            threshold_exceeded: false,
        })
        .rationale("multi-eq".to_string())
        .build()
        .unwrap();

    assert_eq!(expl.equations.len(), 2);
}

#[test]
fn builder_posterior_overwrites_same_key() {
    let expl = ExplanationBuilder::new("d-post".to_string(), epoch(1), DecisionDomain::LaneRouting)
        .chosen(LaneAction::FallbackSafe, 0)
        .posterior("factor_a".to_string(), 100_000)
        .posterior("factor_a".to_string(), 200_000)
        .rationale("test".to_string())
        .build()
        .unwrap();

    assert_eq!(expl.posterior_millionths.len(), 1);
    assert_eq!(expl.posterior_millionths["factor_a"], 200_000);
}

#[test]
fn builder_serde_roundtrip() {
    let builder = ExplanationBuilder::new("d-bser".to_string(), epoch(5), DecisionDomain::Security);
    let json = serde_json::to_string(&builder).unwrap();
    let back: ExplanationBuilder = serde_json::from_str(&json).unwrap();
    // Builder without chosen action should still not build.
    assert!(back.build().is_none());
}

// =========================================================================
// Section 13: ExplanationIndex
// =========================================================================

#[test]
fn index_starts_empty() {
    let idx = ExplanationIndex::new();
    assert!(idx.is_empty());
    assert_eq!(idx.len(), 0);
}

#[test]
fn index_insert_and_get() {
    let mut idx = ExplanationIndex::new();
    let expl = minimal_expl("d-ig", epoch(42), DecisionDomain::LaneRouting);
    let eid = expl.explanation_id.clone();
    idx.insert(expl);
    assert_eq!(idx.len(), 1);
    assert!(!idx.is_empty());
    assert!(idx.get(&eid).is_some());
}

#[test]
fn index_get_by_decision() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl("d-gbd", epoch(42), DecisionDomain::Fallback));
    assert!(idx.get_by_decision("d-gbd").is_some());
    assert!(idx.get_by_decision("nonexistent").is_none());
}

#[test]
fn index_by_domain_filters_correctly() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl("d-bd1", epoch(1), DecisionDomain::LaneRouting));
    idx.insert(minimal_expl("d-bd2", epoch(1), DecisionDomain::LaneRouting));
    idx.insert(minimal_expl("d-bd3", epoch(1), DecisionDomain::Fallback));

    assert_eq!(idx.by_domain(DecisionDomain::LaneRouting).len(), 2);
    assert_eq!(idx.by_domain(DecisionDomain::Fallback).len(), 1);
    assert_eq!(idx.by_domain(DecisionDomain::Security).len(), 0);
}

#[test]
fn index_by_epoch_filters_correctly() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl(
        "d-be1",
        epoch(1),
        DecisionDomain::Optimization,
    ));
    idx.insert(minimal_expl(
        "d-be2",
        epoch(1),
        DecisionDomain::Optimization,
    ));
    idx.insert(minimal_expl(
        "d-be3",
        epoch(2),
        DecisionDomain::Optimization,
    ));

    assert_eq!(idx.by_epoch(&epoch(1)).len(), 2);
    assert_eq!(idx.by_epoch(&epoch(2)).len(), 1);
    assert_eq!(idx.by_epoch(&epoch(99)).len(), 0);
}

#[test]
fn index_with_binding_constraints() {
    let mut idx = ExplanationIndex::new();

    let expl_bound =
        ExplanationBuilder::new("d-wbc1".to_string(), epoch(1), DecisionDomain::Fallback)
            .chosen(LaneAction::FallbackSafe, 0)
            .constraint(ConstraintInteraction {
                constraint_id: "c1".to_string(),
                description: "binding".to_string(),
                binding: true,
                slack_millionths: 0,
            })
            .rationale("bound".to_string())
            .build()
            .unwrap();

    idx.insert(expl_bound);
    idx.insert(minimal_expl(
        "d-wbc2",
        epoch(1),
        DecisionDomain::LaneRouting,
    ));

    assert_eq!(idx.with_binding_constraints().len(), 1);
}

#[test]
fn index_in_regime_filters() {
    let mut idx = ExplanationIndex::new();

    let attack_expl =
        ExplanationBuilder::new("d-ir1".to_string(), epoch(1), DecisionDomain::Security)
            .regime(RegimeLabel::Attack)
            .chosen(LaneAction::SuspendAdaptive, 0)
            .rationale("attack".to_string())
            .build()
            .unwrap();

    idx.insert(attack_expl);
    idx.insert(minimal_expl("d-ir2", epoch(1), DecisionDomain::LaneRouting));

    assert_eq!(idx.in_regime(RegimeLabel::Attack).len(), 1);
    assert_eq!(idx.in_regime(RegimeLabel::Normal).len(), 1);
    assert_eq!(idx.in_regime(RegimeLabel::Degraded).len(), 0);
}

#[test]
fn index_serde_roundtrip() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl(
        "d-isr1",
        epoch(1),
        DecisionDomain::LaneRouting,
    ));
    idx.insert(minimal_expl("d-isr2", epoch(2), DecisionDomain::Fallback));

    let json = serde_json::to_string(&idx).unwrap();
    let back: ExplanationIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
    assert!(back.get_by_decision("d-isr1").is_some());
    assert!(back.get_by_decision("d-isr2").is_some());
}

#[test]
fn index_get_returns_none_for_unknown_id() {
    let idx = ExplanationIndex::new();
    assert!(idx.get("nonexistent").is_none());
}

// =========================================================================
// Section 14: generate_report
// =========================================================================

#[test]
fn report_empty_index() {
    let idx = ExplanationIndex::new();
    let report = generate_report(&idx, &epoch(42));
    assert_eq!(report.total_explained, 0);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.average_confidence_millionths, 0);
    assert_eq!(report.average_alternatives_millionths, 0);
    assert!(!report.content_hash.is_empty());
}

#[test]
fn report_counts_domains_correctly() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl(
        "d-rcd1",
        epoch(1),
        DecisionDomain::LaneRouting,
    ));
    idx.insert(minimal_expl(
        "d-rcd2",
        epoch(1),
        DecisionDomain::LaneRouting,
    ));
    idx.insert(minimal_expl("d-rcd3", epoch(1), DecisionDomain::Fallback));

    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.total_explained, 3);
    assert_eq!(report.domain_counts.get("lane_routing"), Some(&2));
    assert_eq!(report.domain_counts.get("fallback"), Some(&1));
}

#[test]
fn report_content_hash_deterministic() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl(
        "d-rch1",
        epoch(42),
        DecisionDomain::Governance,
    ));

    let r1 = generate_report(&idx, &epoch(42));
    let r2 = generate_report(&idx, &epoch(42));
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_content_hash_differs_by_epoch() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl("d-rch2", epoch(1), DecisionDomain::Governance));
    idx.insert(minimal_expl("d-rch3", epoch(2), DecisionDomain::Governance));

    let r1 = generate_report(&idx, &epoch(1));
    let r2 = generate_report(&idx, &epoch(2));
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_average_confidence() {
    let mut idx = ExplanationIndex::new();
    for (i, conf) in [800_000i64, 600_000].iter().enumerate() {
        let expl =
            ExplanationBuilder::new(format!("d-rac{i}"), epoch(1), DecisionDomain::LaneRouting)
                .chosen(LaneAction::FallbackSafe, 0)
                .confidence(*conf)
                .rationale("test".to_string())
                .build()
                .unwrap();
        idx.insert(expl);
    }
    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.average_confidence_millionths, 700_000);
}

#[test]
fn report_average_alternatives() {
    let mut idx = ExplanationIndex::new();

    // 2 alternatives.
    let expl1 =
        ExplanationBuilder::new("d-raa1".to_string(), epoch(1), DecisionDomain::LaneRouting)
            .chosen(LaneAction::RouteTo(lane("js")), 100_000)
            .alternative(ExplainedAlternative {
                action: LaneAction::RouteTo(lane("wasm")),
                expected_loss_millionths: 200_000,
                rejection_reason: RejectionReason::HigherLoss,
                detail: "higher".to_string(),
            })
            .alternative(ExplainedAlternative {
                action: LaneAction::FallbackSafe,
                expected_loss_millionths: 0,
                rejection_reason: RejectionReason::PolicyForbidden,
                detail: "forbidden".to_string(),
            })
            .rationale("test".to_string())
            .build()
            .unwrap();

    // 0 alternatives.
    let expl2 = minimal_expl("d-raa2", epoch(1), DecisionDomain::Fallback);

    idx.insert(expl1);
    idx.insert(expl2);

    let report = generate_report(&idx, &epoch(1));
    // (2 + 0) / 2 = 1.0 = 1_000_000 millionths
    assert_eq!(report.average_alternatives_millionths, MILLION);
}

#[test]
fn report_non_normal_regime_count() {
    let mut idx = ExplanationIndex::new();

    let attack_expl =
        ExplanationBuilder::new("d-rnr1".to_string(), epoch(1), DecisionDomain::Security)
            .regime(RegimeLabel::Attack)
            .chosen(LaneAction::SuspendAdaptive, 0)
            .rationale("attack".to_string())
            .build()
            .unwrap();

    idx.insert(attack_expl);
    idx.insert(minimal_expl(
        "d-rnr2",
        epoch(1),
        DecisionDomain::LaneRouting,
    ));

    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.non_normal_regime_count, 1);
}

#[test]
fn report_binding_constraint_count() {
    let mut idx = ExplanationIndex::new();

    let bound_expl =
        ExplanationBuilder::new("d-rbcc1".to_string(), epoch(1), DecisionDomain::Fallback)
            .chosen(LaneAction::FallbackSafe, 0)
            .constraint(ConstraintInteraction {
                constraint_id: "c1".to_string(),
                description: "bound".to_string(),
                binding: true,
                slack_millionths: 0,
            })
            .rationale("bound".to_string())
            .build()
            .unwrap();

    idx.insert(bound_expl);
    idx.insert(minimal_expl(
        "d-rbcc2",
        epoch(1),
        DecisionDomain::LaneRouting,
    ));

    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.binding_constraint_count, 1);
}

#[test]
fn report_serde_roundtrip() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl(
        "d-rsr1",
        epoch(42),
        DecisionDomain::Optimization,
    ));

    let report = generate_report(&idx, &epoch(42));
    let json = serde_json::to_string(&report).unwrap();
    let back: ExplainabilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn report_filters_by_epoch() {
    let mut idx = ExplanationIndex::new();
    idx.insert(minimal_expl(
        "d-rfe1",
        epoch(1),
        DecisionDomain::LaneRouting,
    ));
    idx.insert(minimal_expl(
        "d-rfe2",
        epoch(2),
        DecisionDomain::LaneRouting,
    ));

    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.total_explained, 1);
}

#[test]
fn report_verbosity_counts() {
    let mut idx = ExplanationIndex::new();

    let galaxy_expl =
        ExplanationBuilder::new("d-rvc1".to_string(), epoch(1), DecisionDomain::LaneRouting)
            .verbosity(VerbosityLevel::GalaxyBrain)
            .chosen(LaneAction::FallbackSafe, 0)
            .rationale("galaxy".to_string())
            .build()
            .unwrap();
    idx.insert(galaxy_expl);
    idx.insert(minimal_expl("d-rvc2", epoch(1), DecisionDomain::Fallback));

    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.verbosity_counts.get("galaxy_brain"), Some(&1));
    assert_eq!(report.verbosity_counts.get("standard"), Some(&1));
}

// =========================================================================
// Section 15: explain_lane_routing convenience function
// =========================================================================

#[test]
fn explain_lane_routing_basic() {
    let expl = explain_lane_routing(LaneRoutingExplanationInput {
        decision_id: "d-elr1".to_string(),
        epoch: epoch(42),
        regime: RegimeLabel::Normal,
        chosen_lane: lane("js"),
        chosen_loss_millionths: 100_000,
        alternatives: vec![],
        equations: vec![],
        verbosity: VerbosityLevel::Standard,
    })
    .unwrap();

    assert_eq!(expl.domain, DecisionDomain::LaneRouting);
    assert!(expl.rationale.contains("js"));
    assert!(expl.rationale.contains("100000"));
}

#[test]
fn explain_lane_routing_with_alternatives_and_equations() {
    let expl = explain_lane_routing(LaneRoutingExplanationInput {
        decision_id: "d-elr2".to_string(),
        epoch: epoch(42),
        regime: RegimeLabel::Normal,
        chosen_lane: lane("js"),
        chosen_loss_millionths: 100_000,
        alternatives: vec![ExplainedAlternative {
            action: LaneAction::RouteTo(lane("wasm")),
            expected_loss_millionths: 500_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "5x more expensive".to_string(),
        }],
        equations: vec![GoverningEquation {
            name: "loss".to_string(),
            formula: "E[L]".to_string(),
            parameters: BTreeMap::new(),
            result_millionths: 100_000,
            threshold_millionths: None,
            threshold_exceeded: false,
        }],
        verbosity: VerbosityLevel::GalaxyBrain,
    })
    .unwrap();

    assert_eq!(expl.alternatives.len(), 1);
    assert_eq!(expl.equations.len(), 1);
    assert_eq!(expl.verbosity, VerbosityLevel::GalaxyBrain);
}

// =========================================================================
// Section 16: explain_fallback convenience function
// =========================================================================

#[test]
fn explain_fallback_basic() {
    let expl = explain_fallback(FallbackExplanationInput {
        decision_id: "d-efb1".to_string(),
        epoch: epoch(42),
        regime: RegimeLabel::Degraded,
        from_lane: lane("wasm"),
        reason: DemotionReason::CvarExceeded,
        equations: vec![],
        constraints: vec![],
        verbosity: VerbosityLevel::Standard,
    })
    .unwrap();

    assert_eq!(expl.domain, DecisionDomain::Fallback);
    assert!(expl.rationale.contains("Demoted"));
    assert!(expl.rationale.contains("CvarExceeded"));
}

#[test]
fn explain_fallback_with_equations_and_constraints() {
    let expl = explain_fallback(FallbackExplanationInput {
        decision_id: "d-efb2".to_string(),
        epoch: epoch(42),
        regime: RegimeLabel::Degraded,
        from_lane: lane("wasm"),
        reason: DemotionReason::GuardrailTriggered,
        equations: vec![GoverningEquation {
            name: "guardrail".to_string(),
            formula: "E > threshold".to_string(),
            parameters: BTreeMap::from([("E".to_string(), 900_000)]),
            result_millionths: 900_000,
            threshold_millionths: Some(500_000),
            threshold_exceeded: true,
        }],
        constraints: vec![ConstraintInteraction {
            constraint_id: "guardrail-limit".to_string(),
            description: "e-process guardrail".to_string(),
            binding: true,
            slack_millionths: 0,
        }],
        verbosity: VerbosityLevel::GalaxyBrain,
    })
    .unwrap();

    assert!(expl.has_binding_constraint());
    assert_eq!(expl.equations.len(), 1);
    assert_eq!(expl.constraints.len(), 1);
}

// =========================================================================
// Section 17: End-to-end / integration scenarios
// =========================================================================

#[test]
fn end_to_end_build_index_and_report() {
    let mut idx = ExplanationIndex::new();
    let ep = epoch(10);

    // Insert lane routing explanation.
    let routing = explain_lane_routing(LaneRoutingExplanationInput {
        decision_id: "d-e2e-route".to_string(),
        epoch: ep,
        regime: RegimeLabel::Normal,
        chosen_lane: lane("js"),
        chosen_loss_millionths: 100_000,
        alternatives: vec![ExplainedAlternative {
            action: LaneAction::RouteTo(lane("wasm")),
            expected_loss_millionths: 500_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "higher cost".to_string(),
        }],
        equations: vec![],
        verbosity: VerbosityLevel::Standard,
    })
    .unwrap();
    idx.insert(routing);

    // Insert fallback explanation.
    let fallback = explain_fallback(FallbackExplanationInput {
        decision_id: "d-e2e-fallback".to_string(),
        epoch: ep,
        regime: RegimeLabel::Degraded,
        from_lane: lane("wasm"),
        reason: DemotionReason::BudgetExhausted,
        equations: vec![],
        constraints: vec![ConstraintInteraction {
            constraint_id: "budget".to_string(),
            description: "budget exhausted".to_string(),
            binding: true,
            slack_millionths: 0,
        }],
        verbosity: VerbosityLevel::Standard,
    })
    .unwrap();
    idx.insert(fallback);

    // Generate report.
    let report = generate_report(&idx, &ep);
    assert_eq!(report.total_explained, 2);
    assert_eq!(report.binding_constraint_count, 1);
    assert_eq!(report.non_normal_regime_count, 1);
    assert_eq!(report.domain_counts.get("lane_routing"), Some(&1));
    assert_eq!(report.domain_counts.get("fallback"), Some(&1));

    // Verify index queries.
    assert_eq!(idx.by_domain(DecisionDomain::LaneRouting).len(), 1);
    assert_eq!(idx.by_domain(DecisionDomain::Fallback).len(), 1);
    assert_eq!(idx.by_epoch(&ep).len(), 2);
    assert_eq!(idx.with_binding_constraints().len(), 1);
    assert_eq!(idx.in_regime(RegimeLabel::Normal).len(), 1);
    assert_eq!(idx.in_regime(RegimeLabel::Degraded).len(), 1);

    // Report serde round-trip.
    let json = serde_json::to_string(&report).unwrap();
    let back: ExplainabilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn end_to_end_large_index() {
    let mut idx = ExplanationIndex::new();
    let ep = epoch(50);
    let domains = [
        DecisionDomain::LaneRouting,
        DecisionDomain::Fallback,
        DecisionDomain::Optimization,
        DecisionDomain::Security,
        DecisionDomain::Governance,
    ];

    for i in 0..25 {
        let domain = domains[i % domains.len()];
        let expl = ExplanationBuilder::new(format!("d-large-{i}"), ep, domain)
            .chosen(LaneAction::FallbackSafe, (i as i64) * 10_000)
            .confidence((i as i64) * 40_000)
            .rationale(format!("decision {i}"))
            .build()
            .unwrap();
        idx.insert(expl);
    }

    assert_eq!(idx.len(), 25);
    assert_eq!(idx.by_domain(DecisionDomain::LaneRouting).len(), 5);
    assert_eq!(idx.by_epoch(&ep).len(), 25);

    let report = generate_report(&idx, &ep);
    assert_eq!(report.total_explained, 25);
    assert_eq!(report.domain_counts.len(), 5);
}
