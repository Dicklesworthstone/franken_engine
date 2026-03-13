//! Integration tests for the counterfactual intervention planner (RGC-615B).

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

use frankenengine_engine::counterfactual_intervention_planner::{
    self, BEAD_ID, COMPONENT, CounterfactualScenario, InterventionKind, MILLIONTHS,
    OptimizationPass, POLICY_ID, PlannerError, PlanningDecision, SCHEMA_VERSION, UpliftCertificate,
    WaveDefinition,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_pass(id: &str, uplift: u64, risk: u64, cost: u64) -> OptimizationPass {
    OptimizationPass {
        pass_id: id.to_string(),
        name: format!("Pass {id}"),
        estimated_uplift_millionths: uplift,
        estimated_risk_millionths: risk,
        cost_millionths: cost,
        prerequisites: vec![],
    }
}

fn make_pass_with_prereqs(
    id: &str,
    uplift: u64,
    risk: u64,
    cost: u64,
    prereqs: Vec<String>,
) -> OptimizationPass {
    OptimizationPass {
        pass_id: id.to_string(),
        name: format!("Pass {id}"),
        estimated_uplift_millionths: uplift,
        estimated_risk_millionths: risk,
        cost_millionths: cost,
        prerequisites: prereqs,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("counterfactual"));
}

#[test]
fn test_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-615B");
}

#[test]
fn test_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// PlannerError
// ---------------------------------------------------------------------------

#[test]
fn test_planner_error_display_no_viable() {
    let e = PlannerError::NoViablePasses;
    assert!(format!("{e}").contains("no viable"));
}

#[test]
fn test_planner_error_display_risk_exceeds() {
    let e = PlannerError::RiskExceedsBudget;
    assert!(format!("{e}").contains("risk"));
}

#[test]
fn test_planner_error_display_cyclic() {
    let e = PlannerError::CyclicDependency;
    assert!(format!("{e}").contains("cyclic"));
}

#[test]
fn test_planner_error_display_insufficient() {
    let e = PlannerError::InsufficientData;
    assert!(format!("{e}").contains("insufficient"));
}

#[test]
fn test_planner_error_serde_roundtrip() {
    let e = PlannerError::NoViablePasses;
    let json = serde_json::to_string(&e).unwrap();
    let back: PlannerError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// InterventionKind
// ---------------------------------------------------------------------------

#[test]
fn test_intervention_kind_all() {
    assert_eq!(InterventionKind::ALL.len(), 5);
}

#[test]
fn test_intervention_kind_as_str() {
    assert_eq!(InterventionKind::EnablePass.as_str(), "enable_pass");
    assert_eq!(InterventionKind::DisablePass.as_str(), "disable_pass");
    assert_eq!(InterventionKind::ReorderPasses.as_str(), "reorder_passes");
    assert_eq!(
        InterventionKind::AdjustParameter.as_str(),
        "adjust_parameter"
    );
    assert_eq!(
        InterventionKind::CompareVariants.as_str(),
        "compare_variants"
    );
}

#[test]
fn test_intervention_kind_display() {
    let s = format!("{}", InterventionKind::EnablePass);
    assert_eq!(s, "enable_pass");
}

#[test]
fn test_intervention_kind_serde_roundtrip() {
    for kind in InterventionKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: InterventionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// OptimizationPass
// ---------------------------------------------------------------------------

#[test]
fn test_optimization_pass_uplift_risk_ratio() {
    let pass = make_pass("p1", 500_000, 100_000, 50_000);
    let ratio = pass.uplift_risk_ratio();
    assert_eq!(ratio, 5_000_000); // 500k * 1M / 100k = 5M
}

#[test]
fn test_optimization_pass_uplift_risk_ratio_zero_risk() {
    let pass = make_pass("p2", 500_000, 0, 50_000);
    assert_eq!(pass.uplift_risk_ratio(), u64::MAX);
}

#[test]
fn test_optimization_pass_net_benefit() {
    let pass = make_pass("p3", 500_000, 100_000, 200_000);
    assert_eq!(pass.net_benefit(), 300_000);
}

#[test]
fn test_optimization_pass_net_benefit_cost_exceeds() {
    let pass = make_pass("p4", 100_000, 50_000, 200_000);
    assert_eq!(pass.net_benefit(), 0); // saturating sub
}

#[test]
fn test_optimization_pass_serde_roundtrip() {
    let pass = make_pass("p5", 500_000, 100_000, 50_000);
    let json = serde_json::to_string(&pass).unwrap();
    let back: OptimizationPass = serde_json::from_str(&json).unwrap();
    assert_eq!(pass, back);
}

// ---------------------------------------------------------------------------
// rank_passes
// ---------------------------------------------------------------------------

#[test]
fn test_rank_passes_ordering() {
    let passes = vec![
        make_pass("low", 100_000, 100_000, 50_000),
        make_pass("high", 900_000, 100_000, 50_000),
    ];
    let ranked = counterfactual_intervention_planner::rank_passes(&passes);
    assert_eq!(ranked.len(), 2);
    assert_eq!(ranked[0].0, "high");
    assert!(ranked[0].1 > ranked[1].1);
}

#[test]
fn test_rank_passes_empty() {
    let ranked = counterfactual_intervention_planner::rank_passes(&[]);
    assert!(ranked.is_empty());
}

// ---------------------------------------------------------------------------
// validate_pass_ordering
// ---------------------------------------------------------------------------

#[test]
fn test_validate_pass_ordering_simple() {
    let passes = vec![
        make_pass("a", 500_000, 100_000, 50_000),
        make_pass("b", 300_000, 100_000, 50_000),
    ];
    let order = counterfactual_intervention_planner::validate_pass_ordering(&passes).unwrap();
    assert_eq!(order.len(), 2);
}

#[test]
fn test_validate_pass_ordering_with_prereqs() {
    let passes = vec![
        make_pass("a", 500_000, 100_000, 50_000),
        make_pass_with_prereqs("b", 300_000, 100_000, 50_000, vec!["a".to_string()]),
    ];
    let order = counterfactual_intervention_planner::validate_pass_ordering(&passes).unwrap();
    assert_eq!(order.len(), 2);
    // "a" must come before "b"
    let pos_a = order.iter().position(|x| x == "a").unwrap();
    let pos_b = order.iter().position(|x| x == "b").unwrap();
    assert!(pos_a < pos_b);
}

#[test]
fn test_validate_pass_ordering_cyclic() {
    let passes = vec![
        make_pass_with_prereqs("a", 500_000, 100_000, 50_000, vec!["b".to_string()]),
        make_pass_with_prereqs("b", 300_000, 100_000, 50_000, vec!["a".to_string()]),
    ];
    let result = counterfactual_intervention_planner::validate_pass_ordering(&passes);
    assert!(matches!(result, Err(PlannerError::CyclicDependency)));
}

#[test]
fn test_validate_pass_ordering_empty() {
    let result = counterfactual_intervention_planner::validate_pass_ordering(&[]);
    assert!(matches!(result, Err(PlannerError::NoViablePasses)));
}

// ---------------------------------------------------------------------------
// plan_wave
// ---------------------------------------------------------------------------

#[test]
fn test_plan_wave_ok() {
    let passes = vec![
        make_pass("a", 500_000, 100_000, 50_000),
        make_pass("b", 300_000, 200_000, 80_000),
    ];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    assert!(!wave.passes.is_empty());
    assert!(wave.total_expected_uplift_millionths > 0);
    assert!(!wave.wave_id.is_empty());
}

#[test]
fn test_plan_wave_respects_risk_budget() {
    let passes = vec![
        make_pass("a", 500_000, 100_000, 50_000),
        make_pass("b", 300_000, 200_000, 80_000),
    ];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 150_000).unwrap();
    assert!(wave.total_risk_millionths <= 150_000);
}

#[test]
fn test_plan_wave_empty_error() {
    let result = counterfactual_intervention_planner::plan_wave(vec![], 500_000);
    assert!(matches!(result, Err(PlannerError::NoViablePasses)));
}

#[test]
fn test_plan_wave_budget_exceeded() {
    let passes = vec![make_pass("a", 500_000, 300_000, 50_000)];
    let result = counterfactual_intervention_planner::plan_wave(passes, 100_000);
    assert!(matches!(result, Err(PlannerError::RiskExceedsBudget)));
}

// ---------------------------------------------------------------------------
// WaveDefinition
// ---------------------------------------------------------------------------

#[test]
fn test_wave_recompute_aggregates() {
    let mut wave = WaveDefinition {
        wave_id: "w1".to_string(),
        passes: vec![
            make_pass("a", 500_000, 100_000, 50_000),
            make_pass("b", 300_000, 200_000, 80_000),
        ],
        total_expected_uplift_millionths: 0,
        total_risk_millionths: 0,
        priority_order: vec!["a".to_string(), "b".to_string()],
    };
    wave.recompute_aggregates();
    assert_eq!(wave.total_expected_uplift_millionths, 800_000);
    assert_eq!(wave.total_risk_millionths, 300_000);
}

#[test]
fn test_wave_pass_count() {
    let wave = WaveDefinition {
        wave_id: "w1".to_string(),
        passes: vec![make_pass("a", 100, 100, 100)],
        total_expected_uplift_millionths: 100,
        total_risk_millionths: 100,
        priority_order: vec!["a".to_string()],
    };
    assert_eq!(wave.pass_count(), 1);
}

#[test]
fn test_wave_total_cost() {
    let wave = WaveDefinition {
        wave_id: "w1".to_string(),
        passes: vec![
            make_pass("a", 100, 100, 50_000),
            make_pass("b", 100, 100, 30_000),
        ],
        total_expected_uplift_millionths: 200,
        total_risk_millionths: 200,
        priority_order: vec!["a".to_string(), "b".to_string()],
    };
    assert_eq!(wave.total_cost_millionths(), 80_000);
}

// ---------------------------------------------------------------------------
// CounterfactualScenario
// ---------------------------------------------------------------------------

#[test]
fn test_counterfactual_scenario_seal() {
    let mut scenario = CounterfactualScenario {
        scenario_id: "s1".to_string(),
        interventions: vec![(InterventionKind::EnablePass, "a".to_string())],
        expected_outcome_millionths: 500_000,
        confidence_millionths: 800_000,
        content_hash: ContentHash::compute(b""),
    };
    scenario.seal();
    assert_ne!(scenario.content_hash, ContentHash::compute(b""));
}

#[test]
fn test_counterfactual_scenario_serde_roundtrip() {
    let mut scenario = CounterfactualScenario {
        scenario_id: "s1".to_string(),
        interventions: vec![(InterventionKind::DisablePass, "b".to_string())],
        expected_outcome_millionths: -200_000,
        confidence_millionths: 700_000,
        content_hash: ContentHash::compute(b""),
    };
    scenario.seal();
    let json = serde_json::to_string(&scenario).unwrap();
    let back: CounterfactualScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, back);
}

// ---------------------------------------------------------------------------
// UpliftCertificate
// ---------------------------------------------------------------------------

#[test]
fn test_uplift_certificate_positive_effect() {
    let mut cert = UpliftCertificate {
        certificate_id: "uc1".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 500_000,
        counterfactual_baseline_millionths: 100_000,
        causal_effect_millionths: 400_000,
        confidence_interval_low_millionths: 100_000,
        confidence_interval_high_millionths: 700_000,
        content_hash: ContentHash::compute(b""),
    };
    cert.seal();
    assert!(cert.is_positive_effect());
    assert_eq!(cert.ci_width(), 600_000);
}

#[test]
fn test_uplift_certificate_not_positive() {
    let mut cert = UpliftCertificate {
        certificate_id: "uc2".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 100_000,
        counterfactual_baseline_millionths: 200_000,
        causal_effect_millionths: -100_000,
        confidence_interval_low_millionths: -200_000,
        confidence_interval_high_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    cert.seal();
    assert!(!cert.is_positive_effect());
}

// ---------------------------------------------------------------------------
// build_counterfactual
// ---------------------------------------------------------------------------

#[test]
fn test_build_counterfactual() {
    let passes = vec![
        make_pass("a", 500_000, 100_000, 50_000),
        make_pass("b", 300_000, 200_000, 80_000),
    ];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "a",
    );
    assert!(!scenario.scenario_id.is_empty());
    assert!(!scenario.interventions.is_empty());
}

// ---------------------------------------------------------------------------
// estimate_causal_effect
// ---------------------------------------------------------------------------

#[test]
fn test_estimate_causal_effect() {
    let passes = vec![make_pass("a", 500_000, 100_000, 50_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "a",
    );
    let cert =
        counterfactual_intervention_planner::estimate_causal_effect(&scenario, 100_000, 600_000);
    assert!(!cert.certificate_id.is_empty());
    assert_eq!(cert.observed_uplift_millionths, 600_000);
    assert_eq!(cert.counterfactual_baseline_millionths, 100_000);
    assert_eq!(cert.causal_effect_millionths, 500_000);
}

// ---------------------------------------------------------------------------
// select_best_wave
// ---------------------------------------------------------------------------

#[test]
fn test_select_best_wave() {
    let waves = vec![
        WaveDefinition {
            wave_id: "w1".to_string(),
            passes: vec![make_pass("a", 500_000, 100_000, 50_000)],
            total_expected_uplift_millionths: 500_000,
            total_risk_millionths: 100_000,
            priority_order: vec!["a".to_string()],
        },
        WaveDefinition {
            wave_id: "w2".to_string(),
            passes: vec![make_pass("b", 300_000, 200_000, 80_000)],
            total_expected_uplift_millionths: 300_000,
            total_risk_millionths: 200_000,
            priority_order: vec!["b".to_string()],
        },
    ];
    let decision = counterfactual_intervention_planner::select_best_wave(waves, 500_000).unwrap();
    assert!(!decision.decision_id.is_empty());
    assert!(decision.is_informative());
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest() {
    let decision = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    assert!(!decision.decision_id.is_empty());
    assert!(!decision.selected_wave.passes.is_empty());
}

#[test]
fn test_manifest_deterministic() {
    let a = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    let b = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    assert_eq!(a.decision_id, b.decision_id);
    assert_eq!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// Enrichment helpers
// ---------------------------------------------------------------------------

fn make_wave(id: &str, passes: Vec<OptimizationPass>) -> WaveDefinition {
    let priority_order: Vec<String> = passes.iter().map(|p| p.pass_id.clone()).collect();
    let mut wave = WaveDefinition {
        wave_id: id.to_string(),
        passes,
        total_expected_uplift_millionths: 0,
        total_risk_millionths: 0,
        priority_order,
    };
    wave.recompute_aggregates();
    wave
}

fn make_decision(wave: WaveDefinition) -> PlanningDecision {
    let mut d = PlanningDecision {
        decision_id: "test-decision".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        selected_wave: wave,
        alternatives_considered: 0,
        information_value_millionths: 100_000,
        downside_bound_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    d.seal();
    d
}

// ===========================================================================
// PlannerError enrichment
// ===========================================================================

#[test]
fn enrichment_planner_error_debug_no_viable() {
    let e = PlannerError::NoViablePasses;
    let dbg = format!("{e:?}");
    assert!(dbg.contains("NoViablePasses"));
}

#[test]
fn enrichment_planner_error_debug_risk_exceeds() {
    let e = PlannerError::RiskExceedsBudget;
    let dbg = format!("{e:?}");
    assert!(dbg.contains("RiskExceedsBudget"));
}

#[test]
fn enrichment_planner_error_debug_cyclic() {
    let e = PlannerError::CyclicDependency;
    let dbg = format!("{e:?}");
    assert!(dbg.contains("CyclicDependency"));
}

#[test]
fn enrichment_planner_error_debug_insufficient() {
    let e = PlannerError::InsufficientData;
    let dbg = format!("{e:?}");
    assert!(dbg.contains("InsufficientData"));
}

#[test]
fn enrichment_planner_error_debug_internal() {
    let e = PlannerError::InternalError("oops".to_string());
    let dbg = format!("{e:?}");
    assert!(dbg.contains("InternalError"));
    assert!(dbg.contains("oops"));
}

#[test]
fn enrichment_planner_error_display_internal() {
    let e = PlannerError::InternalError("unexpected".to_string());
    let s = format!("{e}");
    assert!(s.contains("internal error"));
    assert!(s.contains("unexpected"));
}

#[test]
fn enrichment_planner_error_clone_eq() {
    let e = PlannerError::InternalError("msg".to_string());
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn enrichment_planner_error_serde_all_variants() {
    let variants: Vec<PlannerError> = vec![
        PlannerError::NoViablePasses,
        PlannerError::RiskExceedsBudget,
        PlannerError::CyclicDependency,
        PlannerError::InsufficientData,
        PlannerError::InternalError("test-msg".to_string()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: PlannerError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_planner_error_internal_empty_msg() {
    let e = PlannerError::InternalError(String::new());
    let s = format!("{e}");
    assert!(s.contains("internal error:"));
}

#[test]
fn enrichment_planner_error_ne() {
    assert_ne!(PlannerError::NoViablePasses, PlannerError::CyclicDependency);
    assert_ne!(
        PlannerError::RiskExceedsBudget,
        PlannerError::InsufficientData
    );
}

// ===========================================================================
// InterventionKind enrichment
// ===========================================================================

#[test]
fn enrichment_intervention_kind_debug_all() {
    for k in InterventionKind::ALL {
        let dbg = format!("{k:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_intervention_kind_clone() {
    let k = InterventionKind::ReorderPasses;
    let k2 = k.clone();
    assert_eq!(k, k2);
}

#[test]
fn enrichment_intervention_kind_copy() {
    let k = InterventionKind::AdjustParameter;
    let k2 = k;
    assert_eq!(k, k2);
}

#[test]
fn enrichment_intervention_kind_ord() {
    // InterventionKind derives PartialOrd + Ord
    let mut kinds: Vec<InterventionKind> = InterventionKind::ALL.to_vec();
    kinds.reverse();
    kinds.sort();
    // After sort, should be in declaration order
    assert_eq!(kinds[0], InterventionKind::EnablePass);
    assert_eq!(kinds[4], InterventionKind::CompareVariants);
}

#[test]
fn enrichment_intervention_kind_btreeset() {
    let mut set = BTreeSet::new();
    for k in InterventionKind::ALL {
        set.insert(*k);
    }
    assert_eq!(set.len(), 5);
    // Inserting duplicates doesn't change the count
    set.insert(InterventionKind::EnablePass);
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_intervention_kind_display_roundtrip_each() {
    assert_eq!(format!("{}", InterventionKind::DisablePass), "disable_pass");
    assert_eq!(
        format!("{}", InterventionKind::ReorderPasses),
        "reorder_passes"
    );
    assert_eq!(
        format!("{}", InterventionKind::AdjustParameter),
        "adjust_parameter"
    );
    assert_eq!(
        format!("{}", InterventionKind::CompareVariants),
        "compare_variants"
    );
}

#[test]
fn enrichment_intervention_kind_json_field_names() {
    let json = serde_json::to_string(&InterventionKind::EnablePass).unwrap();
    // Should serialize as a string variant
    assert!(json.contains("EnablePass") || json.contains("enable"));
}

#[test]
fn enrichment_intervention_kind_as_str_unique() {
    let strs: BTreeSet<&str> = InterventionKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), 5);
}

// ===========================================================================
// OptimizationPass enrichment
// ===========================================================================

#[test]
fn enrichment_optimization_pass_debug() {
    let p = make_pass("dbg", 100, 50, 10);
    let dbg = format!("{p:?}");
    assert!(dbg.contains("OptimizationPass"));
    assert!(dbg.contains("dbg"));
}

#[test]
fn enrichment_optimization_pass_clone() {
    let p = make_pass("c1", 100_000, 50_000, 10_000);
    let p2 = p.clone();
    assert_eq!(p, p2);
}

#[test]
fn enrichment_optimization_pass_json_field_names() {
    let p = make_pass("field_check", 100_000, 50_000, 10_000);
    let json = serde_json::to_string(&p).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val.get("pass_id").is_some());
    assert!(val.get("name").is_some());
    assert!(val.get("estimated_uplift_millionths").is_some());
    assert!(val.get("estimated_risk_millionths").is_some());
    assert!(val.get("cost_millionths").is_some());
    assert!(val.get("prerequisites").is_some());
}

#[test]
fn enrichment_optimization_pass_uplift_risk_ratio_equal() {
    let p = make_pass("eq", 100_000, 100_000, 0);
    // 100_000 * 1_000_000 / 100_000 = 1_000_000
    assert_eq!(p.uplift_risk_ratio(), MILLIONTHS);
}

#[test]
fn enrichment_optimization_pass_uplift_risk_ratio_large_values() {
    let p = make_pass("big", u64::MAX / 2, 1, 0);
    // Saturating mul will cap at u64::MAX, then / 1 = u64::MAX
    let ratio = p.uplift_risk_ratio();
    assert!(ratio > 0);
}

#[test]
fn enrichment_optimization_pass_net_benefit_zero_cost() {
    let p = make_pass("zc", 500_000, 100_000, 0);
    assert_eq!(p.net_benefit(), 500_000);
}

#[test]
fn enrichment_optimization_pass_net_benefit_exact_cost() {
    let p = make_pass("exact", 500_000, 100_000, 500_000);
    assert_eq!(p.net_benefit(), 0);
}

#[test]
fn enrichment_optimization_pass_prerequisites_empty() {
    let p = make_pass("np", 100_000, 50_000, 10_000);
    assert!(p.prerequisites.is_empty());
}

#[test]
fn enrichment_optimization_pass_with_prereqs_serde() {
    let p = make_pass_with_prereqs(
        "dep",
        200_000,
        50_000,
        10_000,
        vec!["a".to_string(), "b".to_string()],
    );
    let json = serde_json::to_string(&p).unwrap();
    let back: OptimizationPass = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    assert_eq!(back.prerequisites.len(), 2);
}

// ===========================================================================
// CounterfactualScenario enrichment
// ===========================================================================

#[test]
fn enrichment_scenario_debug() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-dbg".to_string(),
        interventions: vec![(InterventionKind::EnablePass, "x".to_string())],
        expected_outcome_millionths: 100,
        confidence_millionths: 500_000,
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    let dbg = format!("{s:?}");
    assert!(dbg.contains("CounterfactualScenario"));
}

#[test]
fn enrichment_scenario_clone() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-clone".to_string(),
        interventions: vec![(InterventionKind::DisablePass, "y".to_string())],
        expected_outcome_millionths: -50_000,
        confidence_millionths: 700_000,
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn enrichment_scenario_json_field_names() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-fields".to_string(),
        interventions: vec![],
        expected_outcome_millionths: 0,
        confidence_millionths: 0,
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    let json = serde_json::to_string(&s).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val.get("scenario_id").is_some());
    assert!(val.get("interventions").is_some());
    assert!(val.get("expected_outcome_millionths").is_some());
    assert!(val.get("confidence_millionths").is_some());
    assert!(val.get("content_hash").is_some());
}

#[test]
fn enrichment_scenario_seal_changes_hash() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-seal".to_string(),
        interventions: vec![(InterventionKind::ReorderPasses, "z".to_string())],
        expected_outcome_millionths: 42,
        confidence_millionths: 600_000,
        content_hash: ContentHash::compute(b""),
    };
    let before = s.content_hash;
    s.seal();
    assert_ne!(s.content_hash, before);
}

#[test]
fn enrichment_scenario_seal_deterministic() {
    let make = || {
        let mut s = CounterfactualScenario {
            scenario_id: "s-det".to_string(),
            interventions: vec![(InterventionKind::AdjustParameter, "p".to_string())],
            expected_outcome_millionths: 100_000,
            confidence_millionths: 800_000,
            content_hash: ContentHash::compute(b""),
        };
        s.seal();
        s
    };
    assert_eq!(make().content_hash, make().content_hash);
}

#[test]
fn enrichment_scenario_empty_interventions() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-empty".to_string(),
        interventions: vec![],
        expected_outcome_millionths: 0,
        confidence_millionths: 0,
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    // Should still produce a valid hash
    assert_ne!(s.content_hash, ContentHash::compute(b""));
}

#[test]
fn enrichment_scenario_negative_outcome() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-neg".to_string(),
        interventions: vec![(InterventionKind::DisablePass, "t".to_string())],
        expected_outcome_millionths: -999_999,
        confidence_millionths: 100_000,
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    let json = serde_json::to_string(&s).unwrap();
    let back: CounterfactualScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(back.expected_outcome_millionths, -999_999);
}

#[test]
fn enrichment_scenario_multiple_interventions() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-multi".to_string(),
        interventions: vec![
            (InterventionKind::EnablePass, "a".to_string()),
            (InterventionKind::DisablePass, "b".to_string()),
            (InterventionKind::ReorderPasses, "c".to_string()),
        ],
        expected_outcome_millionths: 300_000,
        confidence_millionths: 500_000,
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    let json = serde_json::to_string(&s).unwrap();
    let back: CounterfactualScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(back.interventions.len(), 3);
}

// ===========================================================================
// WaveDefinition enrichment
// ===========================================================================

#[test]
fn enrichment_wave_debug() {
    let w = make_wave("w-dbg", vec![make_pass("p1", 100, 50, 10)]);
    let dbg = format!("{w:?}");
    assert!(dbg.contains("WaveDefinition"));
}

#[test]
fn enrichment_wave_clone() {
    let w = make_wave("w-clone", vec![make_pass("p1", 200_000, 50_000, 10_000)]);
    let w2 = w.clone();
    assert_eq!(w, w2);
}

#[test]
fn enrichment_wave_json_field_names() {
    let w = make_wave("w-fields", vec![make_pass("f1", 100_000, 50_000, 10_000)]);
    let json = serde_json::to_string(&w).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val.get("wave_id").is_some());
    assert!(val.get("passes").is_some());
    assert!(val.get("total_expected_uplift_millionths").is_some());
    assert!(val.get("total_risk_millionths").is_some());
    assert!(val.get("priority_order").is_some());
}

#[test]
fn enrichment_wave_recompute_aggregates_empty() {
    let mut w = WaveDefinition {
        wave_id: "w-empty".to_string(),
        passes: vec![],
        total_expected_uplift_millionths: 999,
        total_risk_millionths: 999,
        priority_order: vec![],
    };
    w.recompute_aggregates();
    assert_eq!(w.total_expected_uplift_millionths, 0);
    assert_eq!(w.total_risk_millionths, 0);
}

#[test]
fn enrichment_wave_pass_count_empty() {
    let w = WaveDefinition {
        wave_id: "w-empty2".to_string(),
        passes: vec![],
        total_expected_uplift_millionths: 0,
        total_risk_millionths: 0,
        priority_order: vec![],
    };
    assert_eq!(w.pass_count(), 0);
}

#[test]
fn enrichment_wave_total_cost_empty() {
    let w = WaveDefinition {
        wave_id: "w-tc-empty".to_string(),
        passes: vec![],
        total_expected_uplift_millionths: 0,
        total_risk_millionths: 0,
        priority_order: vec![],
    };
    assert_eq!(w.total_cost_millionths(), 0);
}

#[test]
fn enrichment_wave_serde_roundtrip() {
    let w = make_wave(
        "w-rt",
        vec![
            make_pass("x", 200_000, 40_000, 10_000),
            make_pass("y", 300_000, 60_000, 20_000),
        ],
    );
    let json = serde_json::to_string(&w).unwrap();
    let back: WaveDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn enrichment_wave_recompute_aggregates_saturating() {
    let mut w = WaveDefinition {
        wave_id: "w-sat".to_string(),
        passes: vec![
            make_pass("a", u64::MAX - 1, u64::MAX - 1, 0),
            make_pass("b", 10, 10, 0),
        ],
        total_expected_uplift_millionths: 0,
        total_risk_millionths: 0,
        priority_order: vec!["a".to_string(), "b".to_string()],
    };
    w.recompute_aggregates();
    // Saturating add should cap at u64::MAX
    assert_eq!(w.total_expected_uplift_millionths, u64::MAX);
    assert_eq!(w.total_risk_millionths, u64::MAX);
}

#[test]
fn enrichment_wave_total_cost_multi() {
    let w = make_wave(
        "w-cost",
        vec![
            make_pass("c1", 100_000, 50_000, 25_000),
            make_pass("c2", 200_000, 60_000, 35_000),
            make_pass("c3", 300_000, 70_000, 45_000),
        ],
    );
    assert_eq!(w.total_cost_millionths(), 105_000);
}

// ===========================================================================
// UpliftCertificate enrichment
// ===========================================================================

#[test]
fn enrichment_uplift_cert_debug() {
    let cert = UpliftCertificate {
        certificate_id: "uc-dbg".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 100_000,
        counterfactual_baseline_millionths: 50_000,
        causal_effect_millionths: 50_000,
        confidence_interval_low_millionths: 10_000,
        confidence_interval_high_millionths: 90_000,
        content_hash: ContentHash::compute(b""),
    };
    let dbg = format!("{cert:?}");
    assert!(dbg.contains("UpliftCertificate"));
}

#[test]
fn enrichment_uplift_cert_clone() {
    let mut cert = UpliftCertificate {
        certificate_id: "uc-cl".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 200_000,
        counterfactual_baseline_millionths: 100_000,
        causal_effect_millionths: 100_000,
        confidence_interval_low_millionths: 50_000,
        confidence_interval_high_millionths: 150_000,
        content_hash: ContentHash::compute(b""),
    };
    cert.seal();
    let cert2 = cert.clone();
    assert_eq!(cert, cert2);
}

#[test]
fn enrichment_uplift_cert_json_field_names() {
    let mut cert = UpliftCertificate {
        certificate_id: "uc-fields".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 100_000,
        counterfactual_baseline_millionths: 50_000,
        causal_effect_millionths: 50_000,
        confidence_interval_low_millionths: 10_000,
        confidence_interval_high_millionths: 90_000,
        content_hash: ContentHash::compute(b""),
    };
    cert.seal();
    let json = serde_json::to_string(&cert).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val.get("certificate_id").is_some());
    assert!(val.get("wave_id").is_some());
    assert!(val.get("observed_uplift_millionths").is_some());
    assert!(val.get("counterfactual_baseline_millionths").is_some());
    assert!(val.get("causal_effect_millionths").is_some());
    assert!(val.get("confidence_interval_low_millionths").is_some());
    assert!(val.get("confidence_interval_high_millionths").is_some());
    assert!(val.get("content_hash").is_some());
}

#[test]
fn enrichment_uplift_cert_ci_width_zero() {
    let cert = UpliftCertificate {
        certificate_id: "uc-cw0".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 0,
        counterfactual_baseline_millionths: 0,
        causal_effect_millionths: 0,
        confidence_interval_low_millionths: 100_000,
        confidence_interval_high_millionths: 100_000,
        content_hash: ContentHash::compute(b""),
    };
    assert_eq!(cert.ci_width(), 0);
}

#[test]
fn enrichment_uplift_cert_ci_width_negative_interval() {
    // CI low > CI high (unusual but the function uses saturating_sub)
    let cert = UpliftCertificate {
        certificate_id: "uc-neg-ci".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 0,
        counterfactual_baseline_millionths: 0,
        causal_effect_millionths: 0,
        confidence_interval_low_millionths: -200_000,
        confidence_interval_high_millionths: -300_000,
        content_hash: ContentHash::compute(b""),
    };
    // saturating_sub: -300_000 - (-200_000) = -100_000
    // i64 saturating_sub doesn't clamp to 0; it handles overflow
    assert_eq!(cert.ci_width(), -100_000);
}

#[test]
fn enrichment_uplift_cert_is_positive_effect_boundary_zero() {
    let cert = UpliftCertificate {
        certificate_id: "uc-bnd0".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 0,
        counterfactual_baseline_millionths: 0,
        causal_effect_millionths: 0,
        confidence_interval_low_millionths: 0,
        confidence_interval_high_millionths: 100_000,
        content_hash: ContentHash::compute(b""),
    };
    // CI low is exactly 0, not > 0
    assert!(!cert.is_positive_effect());
}

#[test]
fn enrichment_uplift_cert_is_positive_effect_boundary_one() {
    let cert = UpliftCertificate {
        certificate_id: "uc-bnd1".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 100,
        counterfactual_baseline_millionths: 0,
        causal_effect_millionths: 100,
        confidence_interval_low_millionths: 1,
        confidence_interval_high_millionths: 200,
        content_hash: ContentHash::compute(b""),
    };
    // CI low is 1 > 0
    assert!(cert.is_positive_effect());
}

#[test]
fn enrichment_uplift_cert_seal_deterministic() {
    let make = || {
        let mut c = UpliftCertificate {
            certificate_id: "uc-det".to_string(),
            wave_id: "w1".to_string(),
            observed_uplift_millionths: 500_000,
            counterfactual_baseline_millionths: 100_000,
            causal_effect_millionths: 400_000,
            confidence_interval_low_millionths: 200_000,
            confidence_interval_high_millionths: 600_000,
            content_hash: ContentHash::compute(b""),
        };
        c.seal();
        c
    };
    assert_eq!(make().content_hash, make().content_hash);
}

#[test]
fn enrichment_uplift_cert_seal_changes_hash() {
    let mut cert = UpliftCertificate {
        certificate_id: "uc-change".to_string(),
        wave_id: "w1".to_string(),
        observed_uplift_millionths: 100_000,
        counterfactual_baseline_millionths: 0,
        causal_effect_millionths: 100_000,
        confidence_interval_low_millionths: 50_000,
        confidence_interval_high_millionths: 150_000,
        content_hash: ContentHash::compute(b""),
    };
    let before = cert.content_hash;
    cert.seal();
    assert_ne!(cert.content_hash, before);
}

// ===========================================================================
// PlanningDecision enrichment
// ===========================================================================

#[test]
fn enrichment_planning_decision_debug() {
    let w = make_wave("w-d-dbg", vec![make_pass("p1", 100_000, 50_000, 10_000)]);
    let d = make_decision(w);
    let dbg = format!("{d:?}");
    assert!(dbg.contains("PlanningDecision"));
}

#[test]
fn enrichment_planning_decision_clone() {
    let w = make_wave("w-d-cl", vec![make_pass("p1", 100_000, 50_000, 10_000)]);
    let d = make_decision(w);
    let d2 = d.clone();
    assert_eq!(d, d2);
}

#[test]
fn enrichment_planning_decision_json_field_names() {
    let w = make_wave("w-d-fields", vec![make_pass("pf", 100_000, 50_000, 10_000)]);
    let d = make_decision(w);
    let json = serde_json::to_string(&d).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(val.get("decision_id").is_some());
    assert!(val.get("epoch").is_some());
    assert!(val.get("selected_wave").is_some());
    assert!(val.get("alternatives_considered").is_some());
    assert!(val.get("information_value_millionths").is_some());
    assert!(val.get("downside_bound_millionths").is_some());
    assert!(val.get("content_hash").is_some());
}

#[test]
fn enrichment_planning_decision_serde_roundtrip() {
    let w = make_wave("w-d-rt", vec![make_pass("px", 100_000, 50_000, 10_000)]);
    let d = make_decision(w);
    let json = serde_json::to_string(&d).unwrap();
    let back: PlanningDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_planning_decision_not_informative_zero() {
    let w = make_wave("w-ni", vec![make_pass("p1", 100_000, 50_000, 10_000)]);
    let d = PlanningDecision {
        decision_id: "d-not-inf".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        selected_wave: w,
        alternatives_considered: 0,
        information_value_millionths: 0,
        downside_bound_millionths: 0,
        content_hash: ContentHash::compute(b""),
    };
    assert!(!d.is_informative());
}

#[test]
fn enrichment_planning_decision_is_informative_positive() {
    let w = make_wave("w-inf", vec![make_pass("p1", 100_000, 50_000, 10_000)]);
    let d = PlanningDecision {
        decision_id: "d-inf".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        selected_wave: w,
        alternatives_considered: 3,
        information_value_millionths: 1,
        downside_bound_millionths: 0,
        content_hash: ContentHash::compute(b""),
    };
    assert!(d.is_informative());
}

#[test]
fn enrichment_planning_decision_seal_deterministic() {
    let make = || {
        let w = make_wave("w-sd", vec![make_pass("ps", 100_000, 50_000, 10_000)]);
        let mut d = PlanningDecision {
            decision_id: "d-seal-det".to_string(),
            epoch: SecurityEpoch::from_raw(42),
            selected_wave: w,
            alternatives_considered: 5,
            information_value_millionths: 200_000,
            downside_bound_millionths: 75_000,
            content_hash: ContentHash::compute(b""),
        };
        d.seal();
        d
    };
    assert_eq!(make().content_hash, make().content_hash);
}

#[test]
fn enrichment_planning_decision_seal_changes_hash() {
    let w = make_wave("w-sc", vec![make_pass("pc", 100_000, 50_000, 10_000)]);
    let mut d = PlanningDecision {
        decision_id: "d-sc".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        selected_wave: w,
        alternatives_considered: 0,
        information_value_millionths: 100_000,
        downside_bound_millionths: 50_000,
        content_hash: ContentHash::compute(b""),
    };
    let before = d.content_hash;
    d.seal();
    assert_ne!(d.content_hash, before);
}

// ===========================================================================
// rank_passes enrichment
// ===========================================================================

#[test]
fn enrichment_rank_passes_single() {
    let passes = vec![make_pass("only", 300_000, 100_000, 50_000)];
    let ranked = counterfactual_intervention_planner::rank_passes(&passes);
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].0, "only");
}

#[test]
fn enrichment_rank_passes_tiebreak_by_id() {
    // Two passes with same ratio should be sorted alphabetically by ID
    let passes = vec![
        make_pass("zzz", 100_000, 100_000, 0),
        make_pass("aaa", 100_000, 100_000, 0),
    ];
    let ranked = counterfactual_intervention_planner::rank_passes(&passes);
    assert_eq!(ranked.len(), 2);
    // Same ratio, so tiebreak by id ascending
    assert_eq!(ranked[0].0, "aaa");
    assert_eq!(ranked[1].0, "zzz");
}

#[test]
fn enrichment_rank_passes_deterministic() {
    let passes = vec![
        make_pass("a", 500_000, 100_000, 50_000),
        make_pass("b", 300_000, 100_000, 50_000),
        make_pass("c", 700_000, 100_000, 50_000),
    ];
    let r1 = counterfactual_intervention_planner::rank_passes(&passes);
    let r2 = counterfactual_intervention_planner::rank_passes(&passes);
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_rank_passes_all_zero_risk() {
    let passes = vec![
        make_pass("a", 500_000, 0, 50_000),
        make_pass("b", 300_000, 0, 50_000),
    ];
    let ranked = counterfactual_intervention_planner::rank_passes(&passes);
    // Both have u64::MAX ratio, tiebreak by id
    assert_eq!(ranked[0].1, u64::MAX);
    assert_eq!(ranked[1].1, u64::MAX);
    assert_eq!(ranked[0].0, "a");
    assert_eq!(ranked[1].0, "b");
}

// ===========================================================================
// validate_pass_ordering enrichment
// ===========================================================================

#[test]
fn enrichment_validate_ordering_single_pass() {
    let passes = vec![make_pass("solo", 100_000, 10_000, 5_000)];
    let order = counterfactual_intervention_planner::validate_pass_ordering(&passes).unwrap();
    assert_eq!(order, vec!["solo".to_string()]);
}

#[test]
fn enrichment_validate_ordering_diamond_dag() {
    // a -> b, a -> c, b -> d, c -> d
    let passes = vec![
        make_pass("a", 100_000, 10_000, 0),
        make_pass_with_prereqs("b", 200_000, 20_000, 0, vec!["a".to_string()]),
        make_pass_with_prereqs("c", 300_000, 30_000, 0, vec!["a".to_string()]),
        make_pass_with_prereqs(
            "d",
            400_000,
            40_000,
            0,
            vec!["b".to_string(), "c".to_string()],
        ),
    ];
    let order = counterfactual_intervention_planner::validate_pass_ordering(&passes).unwrap();
    assert_eq!(order.len(), 4);
    let pos_a = order.iter().position(|x| x == "a").unwrap();
    let pos_b = order.iter().position(|x| x == "b").unwrap();
    let pos_c = order.iter().position(|x| x == "c").unwrap();
    let pos_d = order.iter().position(|x| x == "d").unwrap();
    assert!(pos_a < pos_b);
    assert!(pos_a < pos_c);
    assert!(pos_b < pos_d);
    assert!(pos_c < pos_d);
}

#[test]
fn enrichment_validate_ordering_external_prereq_ignored() {
    // prereq "ext" is not in the passes list, so it should be ignored
    let passes = vec![make_pass_with_prereqs(
        "a",
        100_000,
        10_000,
        0,
        vec!["ext".to_string()],
    )];
    let order = counterfactual_intervention_planner::validate_pass_ordering(&passes).unwrap();
    assert_eq!(order, vec!["a".to_string()]);
}

#[test]
fn enrichment_validate_ordering_self_cycle() {
    let passes = vec![make_pass_with_prereqs(
        "loop",
        100_000,
        10_000,
        0,
        vec!["loop".to_string()],
    )];
    let result = counterfactual_intervention_planner::validate_pass_ordering(&passes);
    assert!(matches!(result, Err(PlannerError::CyclicDependency)));
}

#[test]
fn enrichment_validate_ordering_deterministic() {
    let passes = vec![
        make_pass("c", 300_000, 30_000, 0),
        make_pass("a", 100_000, 10_000, 0),
        make_pass("b", 200_000, 20_000, 0),
    ];
    let o1 = counterfactual_intervention_planner::validate_pass_ordering(&passes).unwrap();
    let o2 = counterfactual_intervention_planner::validate_pass_ordering(&passes).unwrap();
    assert_eq!(o1, o2);
}

// ===========================================================================
// plan_wave enrichment
// ===========================================================================

#[test]
fn enrichment_plan_wave_single_pass() {
    let passes = vec![make_pass("solo", 500_000, 50_000, 20_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 100_000).unwrap();
    assert_eq!(wave.pass_count(), 1);
    assert_eq!(wave.total_expected_uplift_millionths, 500_000);
    assert_eq!(wave.total_risk_millionths, 50_000);
}

#[test]
fn enrichment_plan_wave_deterministic() {
    let make_passes = || {
        vec![
            make_pass("a", 500_000, 100_000, 50_000),
            make_pass("b", 300_000, 80_000, 30_000),
            make_pass("c", 200_000, 60_000, 20_000),
        ]
    };
    let w1 = counterfactual_intervention_planner::plan_wave(make_passes(), 500_000).unwrap();
    let w2 = counterfactual_intervention_planner::plan_wave(make_passes(), 500_000).unwrap();
    assert_eq!(w1, w2);
}

#[test]
fn enrichment_plan_wave_wave_id_nonempty() {
    let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    assert!(!wave.wave_id.is_empty());
    assert!(wave.wave_id.starts_with("wave-"));
}

#[test]
fn enrichment_plan_wave_priority_order_matches_passes() {
    let passes = vec![
        make_pass("x", 200_000, 50_000, 10_000),
        make_pass("y", 300_000, 60_000, 20_000),
    ];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let pass_ids: BTreeSet<&str> = wave.passes.iter().map(|p| p.pass_id.as_str()).collect();
    let order_ids: BTreeSet<&str> = wave.priority_order.iter().map(|s| s.as_str()).collect();
    assert_eq!(pass_ids, order_ids);
}

#[test]
fn enrichment_plan_wave_budget_zero_all_rejected() {
    let passes = vec![make_pass("a", 200_000, 1, 10_000)];
    let result = counterfactual_intervention_planner::plan_wave(passes, 0);
    assert!(matches!(result, Err(PlannerError::RiskExceedsBudget)));
}

#[test]
fn enrichment_plan_wave_exact_budget() {
    let passes = vec![make_pass("a", 200_000, 100_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 100_000).unwrap();
    assert_eq!(wave.total_risk_millionths, 100_000);
}

#[test]
fn enrichment_plan_wave_with_prerequisites_chain() {
    let passes = vec![
        make_pass("base", 100_000, 20_000, 5_000),
        make_pass_with_prereqs("mid", 200_000, 30_000, 10_000, vec!["base".to_string()]),
        make_pass_with_prereqs("top", 300_000, 40_000, 15_000, vec!["mid".to_string()]),
    ];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    // Check topological order is respected
    if wave.passes.len() >= 2 {
        let has_base = wave.priority_order.iter().position(|x| x == "base");
        let has_mid = wave.priority_order.iter().position(|x| x == "mid");
        if let (Some(pb), Some(pm)) = (has_base, has_mid) {
            assert!(pb < pm);
        }
    }
}

// ===========================================================================
// build_counterfactual enrichment
// ===========================================================================

#[test]
fn enrichment_build_counterfactual_reorder_passes() {
    let passes = vec![make_pass("a", 500_000, 100_000, 50_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::ReorderPasses,
        "a",
    );
    // Reorder = 10% of uplift = 500_000 / 10 = 50_000
    assert_eq!(scenario.expected_outcome_millionths, 50_000);
    assert_eq!(scenario.confidence_millionths, 500_000);
}

#[test]
fn enrichment_build_counterfactual_adjust_parameter() {
    let passes = vec![make_pass("a", 500_000, 100_000, 50_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::AdjustParameter,
        "a",
    );
    // AdjustParameter = 20% of uplift = 500_000 / 5 = 100_000
    assert_eq!(scenario.expected_outcome_millionths, 100_000);
    assert_eq!(scenario.confidence_millionths, 600_000);
}

#[test]
fn enrichment_build_counterfactual_compare_variants_confidence() {
    let passes = vec![make_pass("a", 500_000, 100_000, 50_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::CompareVariants,
        "a",
    );
    assert_eq!(scenario.expected_outcome_millionths, 0);
    assert_eq!(scenario.confidence_millionths, 900_000);
}

#[test]
fn enrichment_build_counterfactual_disable_pass_negative() {
    let passes = vec![make_pass("a", 300_000, 100_000, 50_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::DisablePass,
        "a",
    );
    assert_eq!(scenario.expected_outcome_millionths, -300_000);
    assert_eq!(scenario.confidence_millionths, 800_000);
}

#[test]
fn enrichment_build_counterfactual_enable_pass_confidence() {
    let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "a",
    );
    assert_eq!(scenario.confidence_millionths, 800_000);
}

#[test]
fn enrichment_build_counterfactual_scenario_id_nonempty() {
    let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    for kind in InterventionKind::ALL {
        let scenario = counterfactual_intervention_planner::build_counterfactual(&wave, *kind, "a");
        assert!(!scenario.scenario_id.is_empty());
        assert!(scenario.scenario_id.starts_with("scenario-"));
    }
}

#[test]
fn enrichment_build_counterfactual_sealed() {
    let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "a",
    );
    assert_ne!(scenario.content_hash, ContentHash::compute(b""));
}

#[test]
fn enrichment_build_counterfactual_deterministic() {
    let make = || {
        let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
        let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
        counterfactual_intervention_planner::build_counterfactual(
            &wave,
            InterventionKind::EnablePass,
            "a",
        )
    };
    let s1 = make();
    let s2 = make();
    assert_eq!(s1, s2);
}

// ===========================================================================
// estimate_causal_effect enrichment
// ===========================================================================

#[test]
fn enrichment_estimate_causal_effect_zero_delta() {
    let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "a",
    );
    let cert =
        counterfactual_intervention_planner::estimate_causal_effect(&scenario, 100_000, 100_000);
    assert_eq!(cert.causal_effect_millionths, 0);
}

#[test]
fn enrichment_estimate_causal_effect_negative_baseline() {
    let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "a",
    );
    let cert =
        counterfactual_intervention_planner::estimate_causal_effect(&scenario, -100_000, 200_000);
    assert_eq!(cert.causal_effect_millionths, 300_000);
}

#[test]
fn enrichment_estimate_causal_effect_ci_contains_effect() {
    let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "a",
    );
    let cert =
        counterfactual_intervention_planner::estimate_causal_effect(&scenario, 50_000, 250_000);
    assert!(cert.confidence_interval_low_millionths <= cert.causal_effect_millionths);
    assert!(cert.confidence_interval_high_millionths >= cert.causal_effect_millionths);
}

#[test]
fn enrichment_estimate_causal_effect_high_confidence_narrow_ci() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-hc".to_string(),
        interventions: vec![(InterventionKind::CompareVariants, "x".to_string())],
        expected_outcome_millionths: 0,
        confidence_millionths: 900_000, // 90% confidence
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    let cert = counterfactual_intervention_planner::estimate_causal_effect(&s, 100_000, 200_000);
    // half_width = |100_000| * (1_000_000 - 900_000) / 1_000_000 = 100_000 * 100_000 / 1_000_000 = 10_000
    assert_eq!(cert.ci_width(), 20_000);
}

#[test]
fn enrichment_estimate_causal_effect_low_confidence_wide_ci() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-lc".to_string(),
        interventions: vec![(InterventionKind::ReorderPasses, "x".to_string())],
        expected_outcome_millionths: 0,
        confidence_millionths: 100_000, // 10% confidence
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    let cert = counterfactual_intervention_planner::estimate_causal_effect(&s, 100_000, 200_000);
    // half_width = |100_000| * (1_000_000 - 100_000) / 1_000_000 = 100_000 * 900_000 / 1_000_000 = 90_000
    assert_eq!(cert.ci_width(), 180_000);
}

#[test]
fn enrichment_estimate_causal_effect_wave_id_derived() {
    let passes = vec![make_pass("target_pass", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "target_pass",
    );
    let cert =
        counterfactual_intervention_planner::estimate_causal_effect(&scenario, 100_000, 300_000);
    assert!(cert.wave_id.contains("target_pass"));
}

#[test]
fn enrichment_estimate_causal_effect_cert_id_nonempty() {
    let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave,
        InterventionKind::EnablePass,
        "a",
    );
    let cert = counterfactual_intervention_planner::estimate_causal_effect(&scenario, 0, 100_000);
    assert!(!cert.certificate_id.is_empty());
    assert!(cert.certificate_id.starts_with("cert-"));
}

#[test]
fn enrichment_estimate_causal_effect_deterministic() {
    let make = || {
        let passes = vec![make_pass("a", 200_000, 50_000, 10_000)];
        let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
        let scenario = counterfactual_intervention_planner::build_counterfactual(
            &wave,
            InterventionKind::EnablePass,
            "a",
        );
        counterfactual_intervention_planner::estimate_causal_effect(&scenario, 100_000, 200_000)
    };
    let c1 = make();
    let c2 = make();
    assert_eq!(c1, c2);
}

#[test]
fn enrichment_estimate_causal_effect_empty_interventions_wave_id() {
    let mut s = CounterfactualScenario {
        scenario_id: "s-ei".to_string(),
        interventions: vec![],
        expected_outcome_millionths: 0,
        confidence_millionths: 500_000,
        content_hash: ContentHash::compute(b""),
    };
    s.seal();
    let cert = counterfactual_intervention_planner::estimate_causal_effect(&s, 0, 100_000);
    assert_eq!(cert.wave_id, "wave-unknown");
}

// ===========================================================================
// select_best_wave enrichment
// ===========================================================================

#[test]
fn enrichment_select_best_wave_single() {
    let w = make_wave("w-single", vec![make_pass("a", 200_000, 50_000, 10_000)]);
    let decision = counterfactual_intervention_planner::select_best_wave(vec![w], 500_000).unwrap();
    assert_eq!(decision.alternatives_considered, 0);
    // Single wave: info value = uplift of the single wave
    assert_eq!(decision.information_value_millionths, 200_000);
}

#[test]
fn enrichment_select_best_wave_filters_over_budget() {
    let w1 = make_wave("w-ok", vec![make_pass("a", 200_000, 50_000, 10_000)]);
    let w2 = make_wave("w-over", vec![make_pass("b", 900_000, 600_000, 10_000)]);
    let decision =
        counterfactual_intervention_planner::select_best_wave(vec![w1, w2], 100_000).unwrap();
    assert_eq!(decision.selected_wave.wave_id, "w-ok");
}

#[test]
fn enrichment_select_best_wave_downside_bound() {
    let w = make_wave("w-ds", vec![make_pass("a", 200_000, 75_000, 10_000)]);
    let decision = counterfactual_intervention_planner::select_best_wave(vec![w], 500_000).unwrap();
    assert_eq!(decision.downside_bound_millionths, 75_000);
}

#[test]
fn enrichment_select_best_wave_epoch_is_one() {
    let w = make_wave("w-ep", vec![make_pass("a", 200_000, 50_000, 10_000)]);
    let decision = counterfactual_intervention_planner::select_best_wave(vec![w], 500_000).unwrap();
    assert_eq!(decision.epoch.as_u64(), 1);
}

#[test]
fn enrichment_select_best_wave_decision_sealed() {
    let w = make_wave("w-sealed", vec![make_pass("a", 200_000, 50_000, 10_000)]);
    let decision = counterfactual_intervention_planner::select_best_wave(vec![w], 500_000).unwrap();
    assert_ne!(decision.content_hash, ContentHash::compute(b""));
}

#[test]
fn enrichment_select_best_wave_decision_id_nonempty() {
    let w = make_wave("w-did", vec![make_pass("a", 200_000, 50_000, 10_000)]);
    let decision = counterfactual_intervention_planner::select_best_wave(vec![w], 500_000).unwrap();
    assert!(!decision.decision_id.is_empty());
    assert!(decision.decision_id.starts_with("decision-"));
}

#[test]
fn enrichment_select_best_wave_info_value_two_waves() {
    let w1 = make_wave("w-iv1", vec![make_pass("a", 300_000, 50_000, 10_000)]);
    let w2 = make_wave("w-iv2", vec![make_pass("b", 500_000, 80_000, 20_000)]);
    let decision =
        counterfactual_intervention_planner::select_best_wave(vec![w1, w2], 500_000).unwrap();
    // Info value = 500_000 - 300_000 = 200_000
    assert_eq!(decision.information_value_millionths, 200_000);
    assert_eq!(decision.alternatives_considered, 1);
}

#[test]
fn enrichment_select_best_wave_deterministic() {
    let make = || {
        let w1 = make_wave("w-det1", vec![make_pass("a", 300_000, 50_000, 10_000)]);
        let w2 = make_wave("w-det2", vec![make_pass("b", 500_000, 80_000, 20_000)]);
        counterfactual_intervention_planner::select_best_wave(vec![w1, w2], 500_000).unwrap()
    };
    let d1 = make();
    let d2 = make();
    assert_eq!(d1, d2);
}

// ===========================================================================
// Manifest enrichment
// ===========================================================================

#[test]
fn enrichment_manifest_has_multiple_passes() {
    let d = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    assert!(d.selected_wave.pass_count() > 1);
}

#[test]
fn enrichment_manifest_wave_id_prefix() {
    let d = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    assert!(d.selected_wave.wave_id.starts_with("wave-"));
}

#[test]
fn enrichment_manifest_decision_id_format() {
    let d = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    assert!(d.decision_id.starts_with("manifest-"));
    assert!(d.decision_id.contains(BEAD_ID));
}

#[test]
fn enrichment_manifest_sealed() {
    let d = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    assert_ne!(d.content_hash, ContentHash::compute(b""));
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let d = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    let json = serde_json::to_string(&d).unwrap();
    let back: PlanningDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_manifest_aggregates_consistent() {
    let d = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    let sum_uplift: u64 = d
        .selected_wave
        .passes
        .iter()
        .map(|p| p.estimated_uplift_millionths)
        .sum();
    let sum_risk: u64 = d
        .selected_wave
        .passes
        .iter()
        .map(|p| p.estimated_risk_millionths)
        .sum();
    assert_eq!(d.selected_wave.total_expected_uplift_millionths, sum_uplift);
    assert_eq!(d.selected_wave.total_risk_millionths, sum_risk);
}

#[test]
fn enrichment_manifest_is_informative() {
    let d = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    assert!(d.is_informative());
}

#[test]
fn enrichment_manifest_passes_have_valid_ids() {
    let d = counterfactual_intervention_planner::franken_engine_intervention_manifest();
    for pass in &d.selected_wave.passes {
        assert!(!pass.pass_id.is_empty());
        assert!(pass.pass_id.starts_with("pass-"));
    }
}

// ===========================================================================
// Constants enrichment
// ===========================================================================

#[test]
fn enrichment_schema_version_contains_v1() {
    assert!(SCHEMA_VERSION.contains(".v1"));
}

#[test]
fn enrichment_component_lowercase() {
    assert_eq!(COMPONENT, COMPONENT.to_lowercase());
}

#[test]
fn enrichment_bead_id_format() {
    assert!(BEAD_ID.contains('.'));
    let parts: Vec<&str> = BEAD_ID.split('.').collect();
    assert!(parts.len() > 1);
}

#[test]
fn enrichment_millionths_is_10_pow_6() {
    assert_eq!(MILLIONTHS, 10u64.pow(6));
}
