#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the counterfactual intervention planner.

use std::collections::BTreeSet;

use frankenengine_engine::counterfactual_intervention_planner::{
    BEAD_ID, COMPONENT, CounterfactualScenario, InterventionKind, MILLIONTHS, OptimizationPass,
    POLICY_ID, PlannerError, PlanningDecision, SCHEMA_VERSION, UpliftCertificate, WaveDefinition,
    build_counterfactual, estimate_causal_effect, franken_engine_intervention_manifest, plan_wave,
    rank_passes, select_best_wave, validate_pass_ordering,
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

fn sample_wave() -> WaveDefinition {
    let passes = vec![
        make_pass("alpha", 400_000, 50_000, 20_000),
        make_pass("beta", 200_000, 100_000, 30_000),
        make_pass("gamma", 300_000, 30_000, 10_000),
    ];
    plan_wave(passes, MILLIONTHS).unwrap()
}

// ---------------------------------------------------------------------------
// Serde round-trips (enrichment)
// ---------------------------------------------------------------------------

#[test]
fn optimization_pass_serde_roundtrip_with_prereqs() {
    let pass = make_pass_with_prereqs("p1", 100_000, 50_000, 10_000, vec!["p0".to_string()]);
    let json = serde_json::to_string(&pass).unwrap();
    let decoded: OptimizationPass = serde_json::from_str(&json).unwrap();
    assert_eq!(pass, decoded);
}

#[test]
fn wave_definition_serde_roundtrip() {
    let wave = sample_wave();
    let json = serde_json::to_string(&wave).unwrap();
    let decoded: WaveDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(wave, decoded);
}

#[test]
fn counterfactual_scenario_serde_roundtrip() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, "alpha");
    let json = serde_json::to_string(&scenario).unwrap();
    let decoded: CounterfactualScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, decoded);
}

#[test]
fn uplift_certificate_serde_roundtrip() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, "alpha");
    let cert = estimate_causal_effect(&scenario, 0, 100_000);
    let json = serde_json::to_string(&cert).unwrap();
    let decoded: UpliftCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, decoded);
}

#[test]
fn planning_decision_serde_roundtrip() {
    let decision = franken_engine_intervention_manifest();
    let json = serde_json::to_string(&decision).unwrap();
    let decoded: PlanningDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, decoded);
}

#[test]
fn planner_error_serde_all_variants() {
    let errors = vec![
        PlannerError::NoViablePasses,
        PlannerError::RiskExceedsBudget,
        PlannerError::CyclicDependency,
        PlannerError::InsufficientData,
        PlannerError::InternalError("detail".to_string()),
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let decoded: PlannerError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }
}

// ---------------------------------------------------------------------------
// Display distinctness
// ---------------------------------------------------------------------------

#[test]
fn intervention_kind_display_all_distinct() {
    let displays: BTreeSet<String> = InterventionKind::ALL
        .iter()
        .map(|k| k.to_string())
        .collect();
    assert_eq!(displays.len(), InterventionKind::ALL.len());
}

#[test]
fn planner_error_display_all_distinct() {
    let errors = vec![
        PlannerError::NoViablePasses,
        PlannerError::RiskExceedsBudget,
        PlannerError::CyclicDependency,
        PlannerError::InsufficientData,
        PlannerError::InternalError("x".to_string()),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

// ---------------------------------------------------------------------------
// Deterministic hashing
// ---------------------------------------------------------------------------

#[test]
fn scenario_seal_is_deterministic() {
    let wave = sample_wave();
    let s1 = build_counterfactual(&wave, InterventionKind::DisablePass, "alpha");
    let s2 = build_counterfactual(&wave, InterventionKind::DisablePass, "alpha");
    assert_eq!(s1.content_hash, s2.content_hash);
}

#[test]
fn certificate_seal_is_deterministic() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, "alpha");
    let c1 = estimate_causal_effect(&scenario, 0, 200_000);
    let c2 = estimate_causal_effect(&scenario, 0, 200_000);
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn decision_seal_is_deterministic() {
    let d1 = franken_engine_intervention_manifest();
    let d2 = franken_engine_intervention_manifest();
    assert_eq!(d1.content_hash, d2.content_hash);
}

#[test]
fn different_scenarios_produce_different_hashes() {
    let wave = sample_wave();
    let s1 = build_counterfactual(&wave, InterventionKind::EnablePass, "alpha");
    let s2 = build_counterfactual(&wave, InterventionKind::DisablePass, "alpha");
    assert_ne!(s1.content_hash, s2.content_hash);
}

// ---------------------------------------------------------------------------
// OptimizationPass enrichment
// ---------------------------------------------------------------------------

#[test]
fn pass_net_benefit_zero_when_cost_exceeds_uplift() {
    let pass = make_pass("expensive", 100, 50, 200);
    assert_eq!(pass.net_benefit(), 0);
}

#[test]
fn pass_uplift_risk_ratio_saturating_for_max_values() {
    let pass = make_pass("big", u64::MAX, 1, 0);
    // Should not panic, returns some value
    let ratio = pass.uplift_risk_ratio();
    assert!(ratio > 0);
}

#[test]
fn pass_net_benefit_positive() {
    let pass = make_pass("good", 500_000, 100_000, 200_000);
    assert_eq!(pass.net_benefit(), 300_000);
}

// ---------------------------------------------------------------------------
// WaveDefinition enrichment
// ---------------------------------------------------------------------------

#[test]
fn wave_recompute_aggregates_reflects_passes() {
    let mut wave = WaveDefinition {
        wave_id: "w1".to_string(),
        passes: vec![
            make_pass("a", 100_000, 10_000, 5_000),
            make_pass("b", 200_000, 20_000, 10_000),
        ],
        total_expected_uplift_millionths: 0,
        total_risk_millionths: 0,
        priority_order: vec!["a".to_string(), "b".to_string()],
    };
    wave.recompute_aggregates();
    assert_eq!(wave.total_expected_uplift_millionths, 300_000);
    assert_eq!(wave.total_risk_millionths, 30_000);
}

#[test]
fn wave_pass_count_matches() {
    let wave = sample_wave();
    assert_eq!(wave.pass_count(), wave.passes.len());
}

#[test]
fn wave_total_cost_is_sum_of_pass_costs() {
    let wave = sample_wave();
    let expected: u64 = wave.passes.iter().map(|p| p.cost_millionths).sum();
    assert_eq!(wave.total_cost_millionths(), expected);
}

// ---------------------------------------------------------------------------
// UpliftCertificate enrichment
// ---------------------------------------------------------------------------

#[test]
fn certificate_positive_effect_when_ci_above_zero() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, "alpha");
    let cert = estimate_causal_effect(&scenario, 0, 500_000);
    // causal_effect = 500_000, confidence = 800_000
    // half_width = 500_000 * 200_000 / 1_000_000 = 100_000
    // ci_low = 400_000 > 0 → positive
    assert!(cert.is_positive_effect());
}

#[test]
fn certificate_not_positive_when_baseline_equals_observed() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::CompareVariants, "alpha");
    let cert = estimate_causal_effect(&scenario, 100_000, 100_000);
    // causal_effect = 0, ci includes zero
    assert!(!cert.is_positive_effect());
}

#[test]
fn certificate_ci_width_non_negative() {
    let wave = sample_wave();
    for kind in InterventionKind::ALL {
        let scenario = build_counterfactual(&wave, *kind, "alpha");
        let cert = estimate_causal_effect(&scenario, 100, 500);
        assert!(cert.ci_width() >= 0);
    }
}

// ---------------------------------------------------------------------------
// PlanningDecision enrichment
// ---------------------------------------------------------------------------

#[test]
fn decision_is_informative_when_value_positive() {
    let decision = franken_engine_intervention_manifest();
    assert!(decision.is_informative());
}

#[test]
fn decision_epoch_is_set() {
    let decision = franken_engine_intervention_manifest();
    assert_eq!(decision.epoch.as_u64(), 1);
}

// ---------------------------------------------------------------------------
// rank_passes enrichment
// ---------------------------------------------------------------------------

#[test]
fn rank_passes_sorted_descending_by_ratio() {
    let passes = vec![
        make_pass("low", 100_000, 500_000, 0),
        make_pass("high", 900_000, 100_000, 0),
        make_pass("mid", 400_000, 200_000, 0),
    ];
    let ranked = rank_passes(&passes);
    for i in 1..ranked.len() {
        assert!(ranked[i - 1].1 >= ranked[i].1);
    }
}

#[test]
fn rank_passes_zero_risk_first() {
    let passes = vec![
        make_pass("risky", 100_000, 50_000, 0),
        make_pass("safe", 100_000, 0, 0),
    ];
    let ranked = rank_passes(&passes);
    assert_eq!(ranked[0].0, "safe");
    assert_eq!(ranked[0].1, u64::MAX);
}

// ---------------------------------------------------------------------------
// validate_pass_ordering enrichment
// ---------------------------------------------------------------------------

#[test]
fn validate_pass_ordering_empty_input() {
    let result = validate_pass_ordering(&[]);
    assert!(matches!(result, Err(PlannerError::NoViablePasses)));
}

#[test]
fn validate_pass_ordering_with_chain() {
    let passes = vec![
        make_pass_with_prereqs("c", 100, 10, 5, vec!["b".to_string()]),
        make_pass_with_prereqs("b", 100, 10, 5, vec!["a".to_string()]),
        make_pass("a", 100, 10, 5),
    ];
    let order = validate_pass_ordering(&passes).unwrap();
    let pos_a = order.iter().position(|x| x == "a").unwrap();
    let pos_b = order.iter().position(|x| x == "b").unwrap();
    let pos_c = order.iter().position(|x| x == "c").unwrap();
    assert!(pos_a < pos_b);
    assert!(pos_b < pos_c);
}

#[test]
fn validate_pass_ordering_detects_cycle() {
    let passes = vec![
        make_pass_with_prereqs("a", 100, 10, 5, vec!["b".to_string()]),
        make_pass_with_prereqs("b", 100, 10, 5, vec!["a".to_string()]),
    ];
    let result = validate_pass_ordering(&passes);
    assert!(matches!(result, Err(PlannerError::CyclicDependency)));
}

// ---------------------------------------------------------------------------
// plan_wave enrichment
// ---------------------------------------------------------------------------

#[test]
fn plan_wave_empty_input_returns_no_viable() {
    let result = plan_wave(vec![], 1_000_000);
    assert!(matches!(result, Err(PlannerError::NoViablePasses)));
}

#[test]
fn plan_wave_risk_budget_zero_returns_risk_exceeds() {
    let passes = vec![make_pass("x", 100_000, 1, 0)];
    let result = plan_wave(passes, 0);
    assert!(matches!(result, Err(PlannerError::RiskExceedsBudget)));
}

#[test]
fn plan_wave_respects_risk_budget() {
    let wave = plan_wave(
        vec![
            make_pass("a", 500_000, 300_000, 0),
            make_pass("b", 200_000, 100_000, 0),
        ],
        250_000,
    )
    .unwrap();
    assert!(wave.total_risk_millionths <= 250_000);
}

// ---------------------------------------------------------------------------
// select_best_wave enrichment
// ---------------------------------------------------------------------------

#[test]
fn select_best_wave_empty_returns_error() {
    let result = select_best_wave(vec![], 1_000_000);
    assert!(matches!(result, Err(PlannerError::NoViablePasses)));
}

#[test]
fn select_best_wave_picks_highest_uplift() {
    let w1 = {
        let mut w = WaveDefinition {
            wave_id: "w1".to_string(),
            passes: vec![make_pass("a", 100_000, 10_000, 0)],
            total_expected_uplift_millionths: 100_000,
            total_risk_millionths: 10_000,
            priority_order: vec!["a".to_string()],
        };
        w.recompute_aggregates();
        w
    };
    let w2 = {
        let mut w = WaveDefinition {
            wave_id: "w2".to_string(),
            passes: vec![make_pass("b", 500_000, 50_000, 0)],
            total_expected_uplift_millionths: 500_000,
            total_risk_millionths: 50_000,
            priority_order: vec!["b".to_string()],
        };
        w.recompute_aggregates();
        w
    };
    let decision = select_best_wave(vec![w1, w2], 1_000_000).unwrap();
    assert_eq!(decision.selected_wave.wave_id, "w2");
}

#[test]
fn select_best_wave_filters_over_budget() {
    let w_big = WaveDefinition {
        wave_id: "big".to_string(),
        passes: vec![make_pass("x", 900_000, 500_000, 0)],
        total_expected_uplift_millionths: 900_000,
        total_risk_millionths: 500_000,
        priority_order: vec!["x".to_string()],
    };
    let w_small = WaveDefinition {
        wave_id: "small".to_string(),
        passes: vec![make_pass("y", 100_000, 10_000, 0)],
        total_expected_uplift_millionths: 100_000,
        total_risk_millionths: 10_000,
        priority_order: vec!["y".to_string()],
    };
    let decision = select_best_wave(vec![w_big, w_small], 100_000).unwrap();
    assert_eq!(decision.selected_wave.wave_id, "small");
}

// ---------------------------------------------------------------------------
// build_counterfactual enrichment
// ---------------------------------------------------------------------------

#[test]
fn build_counterfactual_enable_pass_has_positive_outcome() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, "alpha");
    assert!(scenario.expected_outcome_millionths > 0);
}

#[test]
fn build_counterfactual_disable_pass_has_negative_outcome() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::DisablePass, "alpha");
    assert!(scenario.expected_outcome_millionths < 0);
}

#[test]
fn build_counterfactual_compare_variants_has_zero_outcome() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::CompareVariants, "alpha");
    assert_eq!(scenario.expected_outcome_millionths, 0);
}

#[test]
fn build_counterfactual_all_kinds_produce_sealed_hashes() {
    let wave = sample_wave();
    for kind in InterventionKind::ALL {
        let scenario = build_counterfactual(&wave, *kind, "alpha");
        assert_ne!(scenario.content_hash, ContentHash::compute(b""));
    }
}

#[test]
fn build_counterfactual_unknown_target_gives_zero_outcome_for_enable() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, "nonexistent");
    assert_eq!(scenario.expected_outcome_millionths, 0);
}

// ---------------------------------------------------------------------------
// estimate_causal_effect enrichment
// ---------------------------------------------------------------------------

#[test]
fn estimate_causal_effect_zero_difference() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::CompareVariants, "alpha");
    let cert = estimate_causal_effect(&scenario, 100, 100);
    assert_eq!(cert.causal_effect_millionths, 0);
}

#[test]
fn estimate_causal_effect_positive_difference() {
    let wave = sample_wave();
    let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, "alpha");
    let cert = estimate_causal_effect(&scenario, 0, 500_000);
    assert_eq!(cert.causal_effect_millionths, 500_000);
}

// ---------------------------------------------------------------------------
// Constants enrichment
// ---------------------------------------------------------------------------

#[test]
fn constants_values_are_stable() {
    assert_eq!(MILLIONTHS, 1_000_000);
    assert_eq!(BEAD_ID, "bd-1lsy.7.15.2");
    assert_eq!(POLICY_ID, "RGC-615B");
    assert!(SCHEMA_VERSION.contains("counterfactual"));
    assert!(COMPONENT.contains("counterfactual"));
}

// ---------------------------------------------------------------------------
// InterventionKind enrichment
// ---------------------------------------------------------------------------

#[test]
fn intervention_kind_all_has_five_variants() {
    assert_eq!(InterventionKind::ALL.len(), 5);
}

#[test]
fn intervention_kind_as_str_roundtrip() {
    for kind in InterventionKind::ALL {
        let s = kind.as_str();
        assert!(!s.is_empty());
        assert_eq!(kind.to_string(), s);
    }
}

#[test]
fn intervention_kind_serde_all_variants() {
    for kind in InterventionKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let decoded: InterventionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// Manifest enrichment
// ---------------------------------------------------------------------------

#[test]
fn manifest_decision_has_non_empty_wave() {
    let decision = franken_engine_intervention_manifest();
    assert!(decision.selected_wave.pass_count() > 0);
    assert!(decision.selected_wave.total_expected_uplift_millionths > 0);
}

#[test]
fn manifest_decision_sealed_hash_is_not_empty() {
    let decision = franken_engine_intervention_manifest();
    assert_ne!(decision.content_hash, ContentHash::compute(b""));
}

// ---------------------------------------------------------------------------
// Deterministic replay: 50 iterations
// ---------------------------------------------------------------------------

#[test]
fn plan_wave_deterministic_50_times() {
    let mut wave_ids = BTreeSet::new();
    for _ in 0..50 {
        let passes = vec![
            make_pass("a", 300_000, 50_000, 20_000),
            make_pass("b", 200_000, 30_000, 10_000),
        ];
        let wave = plan_wave(passes, 500_000).unwrap();
        wave_ids.insert(wave.wave_id.clone());
    }
    assert_eq!(wave_ids.len(), 1, "wave ID should be deterministic");
}

#[test]
fn select_best_wave_deterministic_50_times() {
    let mut decision_ids = BTreeSet::new();
    for _ in 0..50 {
        let w1 = WaveDefinition {
            wave_id: "w-a".to_string(),
            passes: vec![make_pass("p1", 400_000, 40_000, 10_000)],
            total_expected_uplift_millionths: 400_000,
            total_risk_millionths: 40_000,
            priority_order: vec!["p1".to_string()],
        };
        let decision = select_best_wave(vec![w1], 1_000_000).unwrap();
        decision_ids.insert(decision.decision_id.clone());
    }
    assert_eq!(decision_ids.len(), 1, "decision ID should be deterministic");
}
