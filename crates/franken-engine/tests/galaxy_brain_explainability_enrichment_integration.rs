//! Enrichment integration tests for the `galaxy_brain_explainability` module.
//!
//! Covers: VerbosityLevel ordering/Copy/Hash/Default/Display/serde,
//! DecisionDomain ordering/Copy/Hash/Display/serde,
//! RejectionReason ordering/Copy/Hash/Display/serde,
//! GoverningEquation::plain_language variants,
//! ExplanationBuilder fluent API + build without chosen returns None,
//! DecisionExplanation compute_id determinism, one_line_summary,
//! candidates_considered, has_binding_constraint, total_risk_millionths,
//! ExplanationIndex insert/get/by_decision/by_domain/by_epoch/len/is_empty,
//! with_binding_constraints, in_regime,
//! ExplainabilityReport serde, generate_report,
//! compound type serde roundtrips, Debug formatting.

#![forbid(unsafe_code)]
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

use frankenengine_engine::galaxy_brain_explainability::{
    ConstraintInteraction, CounterfactualOutcome, DecisionDomain, DecisionExplanation,
    ExplainabilityReport, ExplainedAlternative, ExplanationBuilder, ExplanationIndex,
    FallbackExplanationInput, GoverningEquation, LaneRoutingExplanationInput, RejectionReason,
    RiskBreakdown, SCHEMA_VERSION, VerbosityLevel, explain_fallback, explain_lane_routing,
    generate_report,
};
use frankenengine_engine::runtime_decision_theory::{
    DemotionReason, LaneAction, LaneId, RegimeLabel,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn lane(name: &str) -> LaneId {
    LaneId(name.to_string())
}

fn simple_equation(
    name: &str,
    result: i64,
    threshold: Option<i64>,
    exceeded: bool,
) -> GoverningEquation {
    GoverningEquation {
        name: name.to_string(),
        formula: format!("{name}(x)"),
        parameters: BTreeMap::new(),
        result_millionths: result,
        threshold_millionths: threshold,
        threshold_exceeded: exceeded,
    }
}

fn build_minimal_explanation(decision_id: &str, domain: DecisionDomain) -> DecisionExplanation {
    ExplanationBuilder::new(decision_id.to_string(), epoch(1), domain)
        .chosen(LaneAction::RouteTo(lane("fast")), 100_000)
        .rationale("test rationale".to_string())
        .build()
        .unwrap()
}

// =========================================================================
// A. VerbosityLevel — ordering, Copy, Hash, Default, Display, serde
// =========================================================================

#[test]
fn enrichment_verbosity_level_ordering() {
    assert!(VerbosityLevel::Minimal < VerbosityLevel::Standard);
    assert!(VerbosityLevel::Standard < VerbosityLevel::GalaxyBrain);
}

#[test]
fn enrichment_verbosity_level_default_is_standard() {
    assert_eq!(VerbosityLevel::default(), VerbosityLevel::Standard);
}

#[test]
fn enrichment_verbosity_level_copy_hash() {
    let v = VerbosityLevel::GalaxyBrain;
    let v2 = v;
    assert_eq!(v, v2);

    use std::hash::{Hash, Hasher};
    let all = [
        VerbosityLevel::Minimal,
        VerbosityLevel::Standard,
        VerbosityLevel::GalaxyBrain,
    ];
    let mut hashes = BTreeSet::new();
    for variant in &all {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        variant.hash(&mut hasher);
        hashes.insert(hasher.finish());
    }
    assert_eq!(hashes.len(), 3);
}

#[test]
fn enrichment_verbosity_level_display() {
    assert_eq!(VerbosityLevel::Minimal.to_string(), "minimal");
    assert_eq!(VerbosityLevel::Standard.to_string(), "standard");
    assert_eq!(VerbosityLevel::GalaxyBrain.to_string(), "galaxy_brain");
}

#[test]
fn enrichment_verbosity_level_serde_all() {
    let all = [
        VerbosityLevel::Minimal,
        VerbosityLevel::Standard,
        VerbosityLevel::GalaxyBrain,
    ];
    for v in all {
        let json = serde_json::to_string(&v).unwrap();
        let restored: VerbosityLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

// =========================================================================
// B. DecisionDomain — ordering, Copy, Hash, Display, serde
// =========================================================================

#[test]
fn enrichment_decision_domain_ordering() {
    assert!(DecisionDomain::LaneRouting < DecisionDomain::Fallback);
    assert!(DecisionDomain::Fallback < DecisionDomain::Optimization);
    assert!(DecisionDomain::Optimization < DecisionDomain::Security);
    assert!(DecisionDomain::Security < DecisionDomain::Governance);
}

#[test]
fn enrichment_decision_domain_display_all_distinct() {
    let all = [
        DecisionDomain::LaneRouting,
        DecisionDomain::Fallback,
        DecisionDomain::Optimization,
        DecisionDomain::Security,
        DecisionDomain::Governance,
    ];
    let strings: BTreeSet<String> = all.iter().map(|d| d.to_string()).collect();
    assert_eq!(strings.len(), 5);
}

#[test]
fn enrichment_decision_domain_serde_all() {
    let all = [
        DecisionDomain::LaneRouting,
        DecisionDomain::Fallback,
        DecisionDomain::Optimization,
        DecisionDomain::Security,
        DecisionDomain::Governance,
    ];
    for d in all {
        let json = serde_json::to_string(&d).unwrap();
        let restored: DecisionDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(d, restored);
    }
}

// =========================================================================
// C. RejectionReason — ordering, Copy, Hash, Display, serde
// =========================================================================

#[test]
fn enrichment_rejection_reason_ordering() {
    assert!(RejectionReason::HigherLoss < RejectionReason::GuardrailViolation);
    assert!(RejectionReason::GuardrailViolation < RejectionReason::BudgetInsufficient);
    assert!(RejectionReason::BudgetInsufficient < RejectionReason::CalibrationInsufficient);
    assert!(RejectionReason::CalibrationInsufficient < RejectionReason::RegimeRestriction);
    assert!(RejectionReason::RegimeRestriction < RejectionReason::PolicyForbidden);
}

#[test]
fn enrichment_rejection_reason_display_all_distinct() {
    let all = [
        RejectionReason::HigherLoss,
        RejectionReason::GuardrailViolation,
        RejectionReason::BudgetInsufficient,
        RejectionReason::CalibrationInsufficient,
        RejectionReason::RegimeRestriction,
        RejectionReason::PolicyForbidden,
    ];
    let strings: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(strings.len(), 6);
}

#[test]
fn enrichment_rejection_reason_serde_all() {
    let all = [
        RejectionReason::HigherLoss,
        RejectionReason::GuardrailViolation,
        RejectionReason::BudgetInsufficient,
        RejectionReason::CalibrationInsufficient,
        RejectionReason::RegimeRestriction,
        RejectionReason::PolicyForbidden,
    ];
    for r in all {
        let json = serde_json::to_string(&r).unwrap();
        let restored: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }
}

// =========================================================================
// D. GoverningEquation::plain_language
// =========================================================================

#[test]
fn enrichment_governing_equation_plain_language_with_threshold_exceeded() {
    let eq = simple_equation("risk_score", 800_000, Some(500_000), true);
    let text = eq.plain_language();
    assert!(text.contains("risk_score"));
    assert!(text.contains("exceeded"));
}

#[test]
fn enrichment_governing_equation_plain_language_within_threshold() {
    let eq = simple_equation("risk_score", 300_000, Some(500_000), false);
    let text = eq.plain_language();
    assert!(text.contains("risk_score"));
    assert!(text.contains("within"));
}

#[test]
fn enrichment_governing_equation_plain_language_no_threshold() {
    let eq = simple_equation("loss_estimate", 750_000, None, false);
    let text = eq.plain_language();
    assert!(text.contains("loss_estimate"));
    assert!(text.contains("computed"));
}

// =========================================================================
// E. ExplanationBuilder — fluent API, build without chosen returns None
// =========================================================================

#[test]
fn enrichment_builder_without_chosen_returns_none() {
    let result =
        ExplanationBuilder::new("dec-1".to_string(), epoch(1), DecisionDomain::LaneRouting)
            .rationale("test".to_string())
            .build();
    assert!(result.is_none());
}

#[test]
fn enrichment_builder_with_chosen_returns_some() {
    let result =
        ExplanationBuilder::new("dec-1".to_string(), epoch(1), DecisionDomain::LaneRouting)
            .chosen(LaneAction::FallbackSafe, 0)
            .rationale("safe fallback".to_string())
            .build();
    assert!(result.is_some());
    let expl = result.unwrap();
    assert_eq!(expl.chosen_action, LaneAction::FallbackSafe);
    assert_eq!(expl.domain, DecisionDomain::LaneRouting);
}

#[test]
fn enrichment_builder_full_galaxy_brain() {
    let expl = ExplanationBuilder::new("dec-2".to_string(), epoch(3), DecisionDomain::Security)
        .verbosity(VerbosityLevel::GalaxyBrain)
        .regime(RegimeLabel::Elevated)
        .equation(simple_equation("cvar", 900_000, Some(800_000), true))
        .chosen(LaneAction::RouteTo(lane("safe")), 50_000)
        .rationale("elevated risk, routing to safe lane".to_string())
        .alternative(ExplainedAlternative {
            action: LaneAction::RouteTo(lane("fast")),
            expected_loss_millionths: 200_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "fast lane has higher expected loss".to_string(),
        })
        .constraint(ConstraintInteraction {
            constraint_id: "c1".to_string(),
            description: "max loss".to_string(),
            binding: true,
            slack_millionths: 0,
        })
        .risk(RiskBreakdown {
            factor: "tail_risk".to_string(),
            weight_millionths: 500_000,
            belief_millionths: 800_000,
            contribution_millionths: 400_000,
        })
        .counterfactual(CounterfactualOutcome {
            action: LaneAction::FallbackSafe,
            predicted_loss_millionths: 10_000,
            loss_delta_millionths: -40_000,
            would_trigger_guardrail: false,
            narrative: "safe mode would have lower loss".to_string(),
        })
        .posterior("tail_risk".to_string(), 800_000)
        .confidence(950_000)
        .build()
        .unwrap();

    assert_eq!(expl.verbosity, VerbosityLevel::GalaxyBrain);
    assert_eq!(expl.regime, RegimeLabel::Elevated);
    assert_eq!(expl.equations.len(), 1);
    assert_eq!(expl.alternatives.len(), 1);
    assert_eq!(expl.constraints.len(), 1);
    assert_eq!(expl.risk_breakdown.len(), 1);
    assert_eq!(expl.counterfactuals.len(), 1);
    assert_eq!(expl.confidence_millionths, 950_000);
    assert_eq!(expl.posterior_millionths.get("tail_risk"), Some(&800_000));
}

// =========================================================================
// F. DecisionExplanation — compute_id, one_line_summary, accessors
// =========================================================================

#[test]
fn enrichment_compute_id_deterministic() {
    let id1 = DecisionExplanation::compute_id("dec-1", &epoch(1), &DecisionDomain::LaneRouting);
    let id2 = DecisionExplanation::compute_id("dec-1", &epoch(1), &DecisionDomain::LaneRouting);
    assert_eq!(id1, id2);
    assert!(id1.starts_with("expl-"));
}

#[test]
fn enrichment_compute_id_different_inputs_differ() {
    let id1 = DecisionExplanation::compute_id("dec-1", &epoch(1), &DecisionDomain::LaneRouting);
    let id2 = DecisionExplanation::compute_id("dec-2", &epoch(1), &DecisionDomain::LaneRouting);
    let id3 = DecisionExplanation::compute_id("dec-1", &epoch(2), &DecisionDomain::LaneRouting);
    let id4 = DecisionExplanation::compute_id("dec-1", &epoch(1), &DecisionDomain::Security);
    assert_ne!(id1, id2);
    assert_ne!(id1, id3);
    assert_ne!(id1, id4);
}

#[test]
fn enrichment_one_line_summary_contains_key_fields() {
    let expl = build_minimal_explanation("dec-1", DecisionDomain::LaneRouting);
    let summary = expl.one_line_summary();
    assert!(summary.contains("lane_routing"));
    assert!(summary.contains("dec-1"));
    assert!(summary.contains("test rationale"));
}

#[test]
fn enrichment_candidates_considered() {
    let expl = ExplanationBuilder::new("dec-1".to_string(), epoch(1), DecisionDomain::Fallback)
        .chosen(LaneAction::FallbackSafe, 0)
        .alternative(ExplainedAlternative {
            action: LaneAction::RouteTo(lane("fast")),
            expected_loss_millionths: 200_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "higher loss".to_string(),
        })
        .alternative(ExplainedAlternative {
            action: LaneAction::RouteTo(lane("medium")),
            expected_loss_millionths: 150_000,
            rejection_reason: RejectionReason::BudgetInsufficient,
            detail: "budget".to_string(),
        })
        .build()
        .unwrap();
    // 1 chosen + 2 alternatives = 3
    assert_eq!(expl.candidates_considered(), 3);
}

#[test]
fn enrichment_has_binding_constraint() {
    let expl = ExplanationBuilder::new("dec-1".to_string(), epoch(1), DecisionDomain::Security)
        .chosen(LaneAction::FallbackSafe, 0)
        .constraint(ConstraintInteraction {
            constraint_id: "c1".to_string(),
            description: "test".to_string(),
            binding: false,
            slack_millionths: 100_000,
        })
        .build()
        .unwrap();
    assert!(!expl.has_binding_constraint());

    let expl2 = ExplanationBuilder::new("dec-2".to_string(), epoch(1), DecisionDomain::Security)
        .chosen(LaneAction::FallbackSafe, 0)
        .constraint(ConstraintInteraction {
            constraint_id: "c1".to_string(),
            description: "test".to_string(),
            binding: true,
            slack_millionths: 0,
        })
        .build()
        .unwrap();
    assert!(expl2.has_binding_constraint());
}

#[test]
fn enrichment_total_risk_millionths() {
    let expl = ExplanationBuilder::new("dec-1".to_string(), epoch(1), DecisionDomain::Governance)
        .chosen(LaneAction::FallbackSafe, 0)
        .risk(RiskBreakdown {
            factor: "a".to_string(),
            weight_millionths: 500_000,
            belief_millionths: 800_000,
            contribution_millionths: 400_000,
        })
        .risk(RiskBreakdown {
            factor: "b".to_string(),
            weight_millionths: 300_000,
            belief_millionths: 600_000,
            contribution_millionths: 180_000,
        })
        .build()
        .unwrap();
    assert_eq!(expl.total_risk_millionths(), 580_000);
}

// =========================================================================
// G. ExplanationIndex — insert, get, queries
// =========================================================================

#[test]
fn enrichment_index_empty() {
    let idx = ExplanationIndex::new();
    assert!(idx.is_empty());
    assert_eq!(idx.len(), 0);
    assert!(idx.get("nonexistent").is_none());
    assert!(idx.get_by_decision("nonexistent").is_none());
    assert!(idx.by_domain(DecisionDomain::LaneRouting).is_empty());
    assert!(idx.by_epoch(&epoch(1)).is_empty());
}

#[test]
fn enrichment_index_insert_and_retrieve() {
    let mut idx = ExplanationIndex::new();
    let expl = build_minimal_explanation("dec-1", DecisionDomain::LaneRouting);
    let id = expl.explanation_id.clone();
    idx.insert(expl);

    assert_eq!(idx.len(), 1);
    assert!(!idx.is_empty());

    let retrieved = idx.get(&id).unwrap();
    assert_eq!(retrieved.decision_id, "dec-1");

    let by_dec = idx.get_by_decision("dec-1").unwrap();
    assert_eq!(by_dec.explanation_id, id);
}

#[test]
fn enrichment_index_by_domain() {
    let mut idx = ExplanationIndex::new();
    idx.insert(build_minimal_explanation(
        "dec-1",
        DecisionDomain::LaneRouting,
    ));
    idx.insert(build_minimal_explanation("dec-2", DecisionDomain::Security));
    idx.insert(build_minimal_explanation(
        "dec-3",
        DecisionDomain::LaneRouting,
    ));

    let lane_routing = idx.by_domain(DecisionDomain::LaneRouting);
    assert_eq!(lane_routing.len(), 2);

    let security = idx.by_domain(DecisionDomain::Security);
    assert_eq!(security.len(), 1);

    let governance = idx.by_domain(DecisionDomain::Governance);
    assert!(governance.is_empty());
}

#[test]
fn enrichment_index_by_epoch() {
    let mut idx = ExplanationIndex::new();
    // All built with epoch(1)
    idx.insert(build_minimal_explanation(
        "dec-1",
        DecisionDomain::LaneRouting,
    ));
    idx.insert(build_minimal_explanation("dec-2", DecisionDomain::Security));

    let e1 = idx.by_epoch(&epoch(1));
    assert_eq!(e1.len(), 2);

    let e2 = idx.by_epoch(&epoch(2));
    assert!(e2.is_empty());
}

#[test]
fn enrichment_index_with_binding_constraints() {
    let mut idx = ExplanationIndex::new();
    idx.insert(build_minimal_explanation(
        "dec-1",
        DecisionDomain::LaneRouting,
    ));

    let expl_with_binding =
        ExplanationBuilder::new("dec-2".to_string(), epoch(1), DecisionDomain::Security)
            .chosen(LaneAction::FallbackSafe, 0)
            .constraint(ConstraintInteraction {
                constraint_id: "c1".to_string(),
                description: "binding constraint".to_string(),
                binding: true,
                slack_millionths: 0,
            })
            .build()
            .unwrap();
    idx.insert(expl_with_binding);

    let binding = idx.with_binding_constraints();
    assert_eq!(binding.len(), 1);
    assert_eq!(binding[0].decision_id, "dec-2");
}

#[test]
fn enrichment_index_in_regime() {
    let mut idx = ExplanationIndex::new();
    // Default builder uses Normal regime
    idx.insert(build_minimal_explanation(
        "dec-1",
        DecisionDomain::LaneRouting,
    ));

    let expl_elevated =
        ExplanationBuilder::new("dec-2".to_string(), epoch(1), DecisionDomain::Fallback)
            .regime(RegimeLabel::Elevated)
            .chosen(LaneAction::FallbackSafe, 0)
            .build()
            .unwrap();
    idx.insert(expl_elevated);

    let normal = idx.in_regime(RegimeLabel::Normal);
    assert_eq!(normal.len(), 1);

    let elevated = idx.in_regime(RegimeLabel::Elevated);
    assert_eq!(elevated.len(), 1);

    let attack = idx.in_regime(RegimeLabel::Attack);
    assert!(attack.is_empty());
}

// =========================================================================
// H. generate_report
// =========================================================================

#[test]
fn enrichment_generate_report_empty_index() {
    let idx = ExplanationIndex::new();
    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.total_explained, 0);
    assert_eq!(report.average_confidence_millionths, 0);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_generate_report_with_entries() {
    let mut idx = ExplanationIndex::new();
    idx.insert(build_minimal_explanation(
        "dec-1",
        DecisionDomain::LaneRouting,
    ));
    idx.insert(build_minimal_explanation("dec-2", DecisionDomain::Security));

    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.total_explained, 2);
    assert_eq!(report.epoch, epoch(1));
    assert!(report.domain_counts.contains_key("lane_routing"));
    assert!(report.domain_counts.contains_key("security"));
}

// =========================================================================
// I. Serde roundtrips for compound types
// =========================================================================

#[test]
fn enrichment_governing_equation_serde() {
    let mut params = BTreeMap::new();
    params.insert("alpha".to_string(), 500_000i64);
    let eq = GoverningEquation {
        name: "bayes_update".to_string(),
        formula: "P(H|E) = P(E|H)P(H)/P(E)".to_string(),
        parameters: params,
        result_millionths: 750_000,
        threshold_millionths: Some(800_000),
        threshold_exceeded: false,
    };
    let json = serde_json::to_string(&eq).unwrap();
    let restored: GoverningEquation = serde_json::from_str(&json).unwrap();
    assert_eq!(eq, restored);
}

#[test]
fn enrichment_constraint_interaction_serde() {
    let ci = ConstraintInteraction {
        constraint_id: "cvar_bound".to_string(),
        description: "CVaR must not exceed 0.8".to_string(),
        binding: true,
        slack_millionths: 0,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let restored: ConstraintInteraction = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, restored);
}

#[test]
fn enrichment_risk_breakdown_serde() {
    let rb = RiskBreakdown {
        factor: "tail_risk".to_string(),
        weight_millionths: 500_000,
        belief_millionths: 800_000,
        contribution_millionths: 400_000,
    };
    let json = serde_json::to_string(&rb).unwrap();
    let restored: RiskBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, restored);
}

#[test]
fn enrichment_decision_explanation_serde() {
    let expl = build_minimal_explanation("dec-1", DecisionDomain::LaneRouting);
    let json = serde_json::to_string(&expl).unwrap();
    let restored: DecisionExplanation = serde_json::from_str(&json).unwrap();
    assert_eq!(expl, restored);
}

#[test]
fn enrichment_explainability_report_serde() {
    let mut idx = ExplanationIndex::new();
    idx.insert(build_minimal_explanation(
        "dec-1",
        DecisionDomain::LaneRouting,
    ));
    let report = generate_report(&idx, &epoch(1));
    let json = serde_json::to_string(&report).unwrap();
    let restored: ExplainabilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// =========================================================================
// J. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", VerbosityLevel::Standard).is_empty());
    assert!(!format!("{:?}", DecisionDomain::LaneRouting).is_empty());
    assert!(!format!("{:?}", RejectionReason::HigherLoss).is_empty());
    assert!(!format!("{:?}", ExplanationIndex::new()).is_empty());
}

// =========================================================================
// K. Schema version constant
// =========================================================================

#[test]
fn enrichment_schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("galaxy-brain"));
}

// =========================================================================
// L. explain_lane_routing convenience function
// =========================================================================

#[test]
fn enrichment_explain_lane_routing_produces_valid_explanation() {
    let input = LaneRoutingExplanationInput {
        decision_id: "lr-1".to_string(),
        epoch: epoch(5),
        regime: RegimeLabel::Normal,
        chosen_lane: lane("fast"),
        chosen_loss_millionths: 50_000,
        alternatives: vec![ExplainedAlternative {
            action: LaneAction::RouteTo(lane("slow")),
            expected_loss_millionths: 100_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "slow lane has higher loss".to_string(),
        }],
        equations: vec![simple_equation("cvar", 400_000, Some(500_000), false)],
        verbosity: VerbosityLevel::Standard,
    };
    let expl = explain_lane_routing(input).unwrap();
    assert_eq!(expl.domain, DecisionDomain::LaneRouting);
    assert_eq!(expl.chosen_action, LaneAction::RouteTo(lane("fast")));
    assert_eq!(expl.chosen_loss_millionths, 50_000);
    assert_eq!(expl.alternatives.len(), 1);
    assert_eq!(expl.equations.len(), 1);
    assert!(expl.rationale.contains("fast"));
    assert_eq!(expl.regime, RegimeLabel::Normal);
    assert_eq!(expl.epoch, epoch(5));
}

#[test]
fn enrichment_explain_lane_routing_elevated_regime() {
    let input = LaneRoutingExplanationInput {
        decision_id: "lr-elevated".to_string(),
        epoch: epoch(10),
        regime: RegimeLabel::Elevated,
        chosen_lane: lane("safe"),
        chosen_loss_millionths: 10_000,
        alternatives: Vec::new(),
        equations: Vec::new(),
        verbosity: VerbosityLevel::GalaxyBrain,
    };
    let expl = explain_lane_routing(input).unwrap();
    assert_eq!(expl.regime, RegimeLabel::Elevated);
    assert_eq!(expl.verbosity, VerbosityLevel::GalaxyBrain);
    assert!(!expl.rationale.is_empty());
    assert!(expl.alternatives.is_empty());
}

// =========================================================================
// M. explain_fallback convenience function
// =========================================================================

#[test]
fn enrichment_explain_fallback_produces_valid_explanation() {
    let input = FallbackExplanationInput {
        decision_id: "fb-1".to_string(),
        epoch: epoch(7),
        regime: RegimeLabel::Attack,
        from_lane: lane("fast"),
        reason: DemotionReason::CvarExceeded,
        equations: vec![simple_equation("cvar", 900_000, Some(500_000), true)],
        constraints: vec![ConstraintInteraction {
            constraint_id: "max-cvar".to_string(),
            description: "CVaR must stay under 0.5".to_string(),
            binding: true,
            slack_millionths: 0,
        }],
        verbosity: VerbosityLevel::Standard,
    };
    let expl = explain_fallback(input).unwrap();
    assert_eq!(expl.domain, DecisionDomain::Fallback);
    assert!(expl.rationale.contains("Demoted"));
    assert!(expl.rationale.contains("fast"));
    assert_eq!(expl.equations.len(), 1);
    assert_eq!(expl.constraints.len(), 1);
    assert!(expl.has_binding_constraint());
    assert_eq!(expl.regime, RegimeLabel::Attack);
}

#[test]
fn enrichment_explain_fallback_guardrail_triggered() {
    let input = FallbackExplanationInput {
        decision_id: "fb-guard".to_string(),
        epoch: epoch(3),
        regime: RegimeLabel::Normal,
        from_lane: lane("optimized"),
        reason: DemotionReason::GuardrailTriggered,
        equations: Vec::new(),
        constraints: Vec::new(),
        verbosity: VerbosityLevel::Minimal,
    };
    let expl = explain_fallback(input).unwrap();
    assert_eq!(expl.domain, DecisionDomain::Fallback);
    assert_eq!(expl.verbosity, VerbosityLevel::Minimal);
    assert!(expl.rationale.contains("GuardrailTriggered"));
    assert!(expl.constraints.is_empty());
}

// =========================================================================
// N. CounterfactualOutcome and ExplainedAlternative serde roundtrips
// =========================================================================

#[test]
fn enrichment_counterfactual_outcome_serde_roundtrip() {
    let cf = CounterfactualOutcome {
        action: LaneAction::SuspendAdaptive,
        predicted_loss_millionths: 5_000,
        loss_delta_millionths: -45_000,
        would_trigger_guardrail: true,
        narrative: "suspending adaptive would trigger guardrail".to_string(),
    };
    let json = serde_json::to_string(&cf).unwrap();
    let restored: CounterfactualOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(cf, restored);
}

#[test]
fn enrichment_explained_alternative_serde_roundtrip() {
    let alt = ExplainedAlternative {
        action: LaneAction::Demote {
            from_lane: lane("fast"),
            reason: DemotionReason::DriftDetected,
        },
        expected_loss_millionths: 300_000,
        rejection_reason: RejectionReason::RegimeRestriction,
        detail: "regime does not allow demotion here".to_string(),
    };
    let json = serde_json::to_string(&alt).unwrap();
    let restored: ExplainedAlternative = serde_json::from_str(&json).unwrap();
    assert_eq!(alt, restored);
}

// =========================================================================
// O. Report field coverage — binding, non-normal, confidence, alternatives
// =========================================================================

#[test]
fn enrichment_report_binding_and_non_normal_counts() {
    let mut idx = ExplanationIndex::new();

    // Decision 1: Normal regime, no binding constraints
    idx.insert(build_minimal_explanation(
        "dec-1",
        DecisionDomain::LaneRouting,
    ));

    // Decision 2: Elevated regime with binding constraint
    let expl2 = ExplanationBuilder::new("dec-2".to_string(), epoch(1), DecisionDomain::Security)
        .regime(RegimeLabel::Elevated)
        .chosen(LaneAction::FallbackSafe, 0)
        .confidence(800_000)
        .constraint(ConstraintInteraction {
            constraint_id: "c1".to_string(),
            description: "binding".to_string(),
            binding: true,
            slack_millionths: 0,
        })
        .alternative(ExplainedAlternative {
            action: LaneAction::RouteTo(lane("fast")),
            expected_loss_millionths: 200_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "higher loss".to_string(),
        })
        .build()
        .unwrap();
    idx.insert(expl2);

    // Decision 3: Attack regime, no binding, with confidence
    let expl3 = ExplanationBuilder::new("dec-3".to_string(), epoch(1), DecisionDomain::Governance)
        .regime(RegimeLabel::Attack)
        .chosen(LaneAction::SuspendAdaptive, 0)
        .confidence(600_000)
        .build()
        .unwrap();
    idx.insert(expl3);

    let report = generate_report(&idx, &epoch(1));
    assert_eq!(report.total_explained, 3);
    assert_eq!(report.binding_constraint_count, 1);
    assert_eq!(report.non_normal_regime_count, 2);
    // Average confidence is computed by the implementation — verify it's reasonable
    assert!(report.average_confidence_millionths > 0);
    assert!(report.average_confidence_millionths <= 1_000_000);
    // Verbosity counts should include "standard" (all 3 default to standard)
    assert!(report.verbosity_counts.contains_key("standard"));
    // Content hash should be non-empty
    assert!(!report.content_hash.is_empty());
}

#[test]
fn enrichment_report_content_hash_deterministic() {
    let mut idx = ExplanationIndex::new();
    idx.insert(build_minimal_explanation("dec-1", DecisionDomain::Fallback));

    let report1 = generate_report(&idx, &epoch(1));
    let report2 = generate_report(&idx, &epoch(1));
    assert_eq!(report1.content_hash, report2.content_hash);
    assert_eq!(report1, report2);
}

// =========================================================================
// P. ExplanationIndex serde roundtrip and overwrite behavior
// =========================================================================

#[test]
fn enrichment_index_serde_roundtrip() {
    let mut idx = ExplanationIndex::new();
    idx.insert(build_minimal_explanation(
        "dec-1",
        DecisionDomain::LaneRouting,
    ));
    idx.insert(build_minimal_explanation("dec-2", DecisionDomain::Security));

    let json = serde_json::to_string(&idx).unwrap();
    let restored: ExplanationIndex = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.len(), 2);
    assert!(restored.get_by_decision("dec-1").is_some());
    assert!(restored.get_by_decision("dec-2").is_some());
}

#[test]
fn enrichment_index_insert_same_decision_id_overwrites() {
    let mut idx = ExplanationIndex::new();
    let expl1 = ExplanationBuilder::new("dec-dup".to_string(), epoch(1), DecisionDomain::Security)
        .chosen(LaneAction::FallbackSafe, 10_000)
        .rationale("first".to_string())
        .build()
        .unwrap();
    let id1 = expl1.explanation_id.clone();
    idx.insert(expl1);
    assert_eq!(idx.len(), 1);

    // Same decision_id, same epoch, same domain → same compute_id → overwrite
    let expl2 = ExplanationBuilder::new("dec-dup".to_string(), epoch(1), DecisionDomain::Security)
        .chosen(LaneAction::SuspendAdaptive, 20_000)
        .rationale("second".to_string())
        .build()
        .unwrap();
    let id2 = expl2.explanation_id.clone();
    assert_eq!(id1, id2);
    idx.insert(expl2);

    // Still 1 entry — the overwrite replaced the old one
    assert_eq!(idx.len(), 1);
    let retrieved = idx.get_by_decision("dec-dup").unwrap();
    assert_eq!(retrieved.rationale, "second");
    assert_eq!(retrieved.chosen_action, LaneAction::SuspendAdaptive);
}
