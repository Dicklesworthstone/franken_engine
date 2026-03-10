//! Integration tests for the counterfactual intervention planner (RGC-615B).

use frankenengine_engine::counterfactual_intervention_planner::{
    self, CounterfactualScenario, InterventionKind, OptimizationPass,
    PlannerError, UpliftCertificate, WaveDefinition,
    SCHEMA_VERSION, BEAD_ID, COMPONENT, POLICY_ID, MILLIONTHS,
};
use frankenengine_engine::hash_tiers::ContentHash;

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
    id: &str, uplift: u64, risk: u64, cost: u64, prereqs: Vec<String>,
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
    assert_eq!(InterventionKind::AdjustParameter.as_str(), "adjust_parameter");
    assert_eq!(InterventionKind::CompareVariants.as_str(), "compare_variants");
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
    let passes = vec![
        make_pass("a", 500_000, 300_000, 50_000),
    ];
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
        interventions: vec![
            (InterventionKind::EnablePass, "a".to_string()),
        ],
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
        interventions: vec![
            (InterventionKind::DisablePass, "b".to_string()),
        ],
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
        &wave, InterventionKind::EnablePass, "a",
    );
    assert!(!scenario.scenario_id.is_empty());
    assert!(!scenario.interventions.is_empty());
}

// ---------------------------------------------------------------------------
// estimate_causal_effect
// ---------------------------------------------------------------------------

#[test]
fn test_estimate_causal_effect() {
    let passes = vec![
        make_pass("a", 500_000, 100_000, 50_000),
    ];
    let wave = counterfactual_intervention_planner::plan_wave(passes, 500_000).unwrap();
    let scenario = counterfactual_intervention_planner::build_counterfactual(
        &wave, InterventionKind::EnablePass, "a",
    );
    let cert = counterfactual_intervention_planner::estimate_causal_effect(
        &scenario, 100_000, 600_000,
    );
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
    let decision = counterfactual_intervention_planner::select_best_wave(
        waves, 500_000,
    ).unwrap();
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
