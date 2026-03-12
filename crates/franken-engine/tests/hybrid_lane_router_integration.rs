//! Integration tests for the `hybrid_lane_router` module.
//!
//! Exercises the public API from outside the crate boundary:
//! LaneChoice, RoutingPolicy, DemotionReason, PolicyTransition,
//! LaneObservation, ConformalConfig/State, ChangePointConfig/Monitor,
//! RiskBudget, RiskAccumulator, AdaptiveWeights, compute_reward,
//! RoutingDecisionTrace, RouterConfig, HybridLaneRouter, RouterSummary.

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

use frankenengine_engine::hybrid_lane_router::{
    AdaptiveWeights, ChangePointConfig, ChangePointMonitor, ConformalConfig, ConformalState,
    DemotionReason, HybridLaneRouter, LaneChoice, LaneObservation, PolicyTransition,
    RiskAccumulator, RiskBudget, RouterConfig, RouterError, RouterSummary, RoutingDecisionTrace,
    RoutingPolicy, compute_reward,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ok_observation(lane: LaneChoice) -> LaneObservation {
    LaneObservation {
        lane,
        latency_us: 4_000,
        success: true,
        dom_ops: 100,
        signals_evaluated: 50,
        safe_mode_entered: false,
        compatibility_errors: 0,
    }
}

// =========================================================================
// LaneChoice
// =========================================================================

#[test]
fn lane_choice_as_str() {
    assert_eq!(LaneChoice::Js.as_str(), "js");
    assert_eq!(LaneChoice::Wasm.as_str(), "wasm");
}

#[test]
fn lane_choice_index_roundtrip() {
    for lane in &LaneChoice::ALL {
        assert_eq!(LaneChoice::from_index(lane.index()), Some(*lane));
    }
    assert_eq!(LaneChoice::from_index(99), None);
}

#[test]
fn lane_choice_ordering() {
    assert!(LaneChoice::Js < LaneChoice::Wasm);
}

#[test]
fn lane_choice_serde_roundtrip() {
    for lane in &LaneChoice::ALL {
        let json = serde_json::to_string(lane).unwrap();
        let restored: LaneChoice = serde_json::from_str(&json).unwrap();
        assert_eq!(*lane, restored);
    }
}

// =========================================================================
// RoutingPolicy
// =========================================================================

#[test]
fn routing_policy_serde_roundtrip() {
    for policy in &[RoutingPolicy::Conservative, RoutingPolicy::Adaptive] {
        let json = serde_json::to_string(policy).unwrap();
        let restored: RoutingPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*policy, restored);
    }
}

// =========================================================================
// DemotionReason
// =========================================================================

#[test]
fn demotion_reason_serde_roundtrip() {
    let reasons = vec![
        DemotionReason::ChangePointDetected {
            cusum_stat_millionths: 3_000_000,
            threshold_millionths: 2_000_000,
        },
        DemotionReason::ConformalViolation {
            coverage_millionths: 800_000,
            target_millionths: 900_000,
        },
        DemotionReason::RegretExceeded {
            realized_millionths: 600_000,
            bound_millionths: 500_000,
        },
        DemotionReason::TailLatencyBudgetExhausted {
            observed_p99_us: 20_000,
            budget_us: 16_000,
        },
        DemotionReason::CompatibilityBudgetExhausted {
            errors_observed: 10,
            budget: 5,
        },
        DemotionReason::ManualDemotion,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let restored: DemotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored);
    }
}

// =========================================================================
// PolicyTransition
// =========================================================================

#[test]
fn policy_transition_serde_roundtrip() {
    let pt = PolicyTransition {
        round: 42,
        from: RoutingPolicy::Adaptive,
        to: RoutingPolicy::Conservative,
        reason: Some(DemotionReason::ManualDemotion),
    };
    let json = serde_json::to_string(&pt).unwrap();
    let restored: PolicyTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(pt, restored);
}

// =========================================================================
// ConformalState
// =========================================================================

#[test]
fn conformal_initially_valid() {
    let state = ConformalState::new(ConformalConfig::default_config());
    assert!(state.is_valid());
    assert_eq!(state.coverage_millionths(), 1_000_000); // vacuously valid
    assert!(state.check().is_none());
}

#[test]
fn conformal_all_in_bounds() {
    let mut state = ConformalState::new(ConformalConfig::default_config());
    for _ in 0..30 {
        state.observe(true);
    }
    assert!(state.is_valid());
    assert_eq!(state.coverage_millionths(), 1_000_000);
}

#[test]
fn conformal_low_coverage_triggers() {
    let mut state = ConformalState::new(ConformalConfig {
        target_coverage_millionths: 900_000,
        min_observations: 10,
        window_size: 20,
    });
    // 8 in bounds, 12 out of bounds = 40% coverage
    for _ in 0..8 {
        state.observe(true);
    }
    for _ in 0..12 {
        state.observe(false);
    }
    assert!(!state.is_valid());
    let reason = state.check();
    assert!(matches!(
        reason,
        Some(DemotionReason::ConformalViolation { .. })
    ));
}

#[test]
fn conformal_serde_roundtrip() {
    let mut state = ConformalState::new(ConformalConfig::default_config());
    state.observe(true);
    state.observe(false);
    let json = serde_json::to_string(&state).unwrap();
    let restored: ConformalState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, restored);
}

// =========================================================================
// ChangePointMonitor
// =========================================================================

#[test]
fn change_point_initially_not_triggered() {
    let mon = ChangePointMonitor::new(ChangePointConfig::default_config());
    assert!(!mon.is_triggered());
    assert!(mon.check().is_none());
}

#[test]
fn change_point_stable_observations() {
    let mut mon = ChangePointMonitor::new(ChangePointConfig::default_config());
    for _ in 0..20 {
        mon.observe(500_000); // stable
    }
    assert!(!mon.is_triggered());
}

#[test]
fn change_point_reset() {
    let mut mon = ChangePointMonitor::new(ChangePointConfig::default_config());
    for _ in 0..20 {
        mon.observe(500_000);
    }
    mon.reset();
    assert_eq!(mon.cusum_upper_millionths, 0);
    assert_eq!(mon.cusum_lower_millionths, 0);
    // Running mean and count preserved
    assert!(mon.observation_count > 0);
}

#[test]
fn change_point_serde_roundtrip() {
    let mut mon = ChangePointMonitor::new(ChangePointConfig::default_config());
    mon.observe(500_000);
    let json = serde_json::to_string(&mon).unwrap();
    let restored: ChangePointMonitor = serde_json::from_str(&json).unwrap();
    assert_eq!(mon, restored);
}

// =========================================================================
// RiskBudget
// =========================================================================

#[test]
fn risk_budget_defaults() {
    let budget = RiskBudget::default_budget();
    assert_eq!(budget.tail_latency_budget_us, 16_000);
    assert_eq!(budget.compatibility_error_budget, 5);
    assert_eq!(budget.regret_budget_millionths, 500_000);
}

// =========================================================================
// RiskAccumulator
// =========================================================================

#[test]
fn risk_accumulator_empty() {
    let acc = RiskAccumulator::new();
    assert_eq!(acc.p99_latency_us(), 0);
    assert_eq!(acc.compatibility_errors, 0);
    assert!(acc.check_budgets(&RiskBudget::default_budget()).is_none());
}

#[test]
fn risk_accumulator_records_observations() {
    let mut acc = RiskAccumulator::new();
    let obs = ok_observation(LaneChoice::Js);
    acc.record(&obs, 800_000);
    assert_eq!(acc.latencies_us.len(), 1);
    assert_eq!(acc.p99_latency_us(), 4_000);
}

#[test]
fn risk_accumulator_compatibility_error_budget() {
    let mut acc = RiskAccumulator::new();
    let budget = RiskBudget {
        tail_latency_budget_us: 100_000,
        compatibility_error_budget: 2,
        regret_budget_millionths: 10_000_000,
    };
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 1_000,
        success: true,
        dom_ops: 10,
        signals_evaluated: 5,
        safe_mode_entered: false,
        compatibility_errors: 3,
    };
    acc.record(&obs, 500_000);
    let reason = acc.check_budgets(&budget);
    assert!(matches!(
        reason,
        Some(DemotionReason::CompatibilityBudgetExhausted { .. })
    ));
}

#[test]
fn risk_accumulator_serde_roundtrip() {
    let mut acc = RiskAccumulator::new();
    acc.record(&ok_observation(LaneChoice::Js), 800_000);
    let json = serde_json::to_string(&acc).unwrap();
    let restored: RiskAccumulator = serde_json::from_str(&json).unwrap();
    assert_eq!(acc, restored);
}

// =========================================================================
// AdaptiveWeights
// =========================================================================

#[test]
fn adaptive_weights_initial_uniform() {
    let w = AdaptiveWeights::new();
    let probs = w.probabilities_millionths();
    assert_eq!(probs.len(), 2);
    // With equal log-weights and gamma=0.1, probabilities should be roughly equal
    let diff = (probs[0] - probs[1]).abs();
    assert!(diff < 100_000, "diff = {diff}");
}

#[test]
fn adaptive_weights_select() {
    let w = AdaptiveWeights::new();
    let lane0 = w.select(0);
    assert_eq!(lane0, LaneChoice::Js);
    let lane1 = w.select(999_999);
    assert_eq!(lane1, LaneChoice::Wasm);
}

#[test]
fn adaptive_weights_update() {
    let mut w = AdaptiveWeights::new();
    w.update(LaneChoice::Js, 900_000);
    assert_eq!(w.rounds, 1);
    // After rewarding Js, its log weight should be higher
    assert!(w.log_weights_millionths[0] > w.log_weights_millionths[1]);
}

#[test]
fn adaptive_weights_serde_roundtrip() {
    let mut w = AdaptiveWeights::new();
    w.update(LaneChoice::Wasm, 500_000);
    let json = serde_json::to_string(&w).unwrap();
    let restored: AdaptiveWeights = serde_json::from_str(&json).unwrap();
    assert_eq!(w, restored);
}

// =========================================================================
// compute_reward
// =========================================================================

#[test]
fn reward_success_low_latency() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 0,
        success: true,
        dom_ops: 500,
        signals_evaluated: 100,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let reward = compute_reward(&obs, 8_000);
    assert!(reward > 800_000, "reward = {reward}"); // should be high
}

#[test]
fn reward_failure_zero() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 1_000,
        success: false,
        dom_ops: 0,
        signals_evaluated: 0,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    assert_eq!(compute_reward(&obs, 8_000), 0);
}

#[test]
fn reward_safe_mode_penalized() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 1_000,
        success: true,
        dom_ops: 100,
        signals_evaluated: 50,
        safe_mode_entered: true,
        compatibility_errors: 0,
    };
    assert_eq!(compute_reward(&obs, 8_000), 100_000);
}

#[test]
fn reward_compat_errors_penalized() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 1_000,
        success: true,
        dom_ops: 100,
        signals_evaluated: 50,
        safe_mode_entered: false,
        compatibility_errors: 1,
    };
    assert_eq!(compute_reward(&obs, 8_000), 200_000);
}

// =========================================================================
// RouterConfig
// =========================================================================

#[test]
fn router_config_defaults() {
    let cfg = RouterConfig::default_config();
    assert_eq!(cfg.baseline_lane, LaneChoice::Js);
    assert_eq!(cfg.latency_baseline_us, 8_000);
    assert_eq!(cfg.adaptive_horizon, 1000);
}

#[test]
fn router_config_serde_roundtrip() {
    let cfg = RouterConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: RouterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// HybridLaneRouter — construction
// =========================================================================

#[test]
fn router_new_starts_conservative() {
    let router = HybridLaneRouter::with_defaults();
    assert_eq!(router.policy, RoutingPolicy::Conservative);
    assert_eq!(router.round, 0);
    assert!(router.policy_transitions.is_empty());
}

#[test]
fn router_select_lane_conservative_returns_baseline() {
    let router = HybridLaneRouter::with_defaults();
    assert_eq!(router.select_lane(500_000), LaneChoice::Js);
}

// =========================================================================
// HybridLaneRouter — observe
// =========================================================================

#[test]
fn router_observe_increments_round() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = ok_observation(LaneChoice::Js);
    let trace = router.observe(LaneChoice::Js, &obs, None);
    assert_eq!(trace.round, 0);
    assert_eq!(router.round, 1);
    assert_eq!(router.total_js_routes, 1);
    assert_eq!(router.total_wasm_routes, 0);
}

#[test]
fn router_observe_returns_decision_trace() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = ok_observation(LaneChoice::Js);
    let trace = router.observe(LaneChoice::Js, &obs, Some(300_000));
    assert_eq!(trace.policy, RoutingPolicy::Conservative);
    assert_eq!(trace.chosen_lane, LaneChoice::Js);
    assert!(trace.reward_millionths.is_some());
    assert_eq!(trace.random_draw_millionths, Some(300_000));
}

// =========================================================================
// HybridLaneRouter — promote / demote
// =========================================================================

#[test]
fn router_promote_to_adaptive() {
    let mut router = HybridLaneRouter::with_defaults();
    router.promote_to_adaptive().unwrap();
    assert_eq!(router.policy, RoutingPolicy::Adaptive);
    assert_eq!(router.policy_transitions.len(), 1);
}

#[test]
fn router_manual_demote() {
    let mut router = HybridLaneRouter::with_defaults();
    router.promote_to_adaptive().unwrap();
    router.manual_demote().unwrap();
    assert_eq!(router.policy, RoutingPolicy::Conservative);
    assert_eq!(router.policy_transitions.len(), 2);
}

#[test]
fn router_manual_demote_when_conservative_errors() {
    let mut router = HybridLaneRouter::with_defaults();
    let result = router.manual_demote();
    assert!(matches!(result, Err(RouterError::AlreadyConservative)));
}

// =========================================================================
// HybridLaneRouter — lane probabilities
// =========================================================================

#[test]
fn router_lane_probabilities_conservative() {
    let router = HybridLaneRouter::with_defaults();
    let probs = router.lane_probabilities();
    assert_eq!(*probs.get(&LaneChoice::Js).unwrap(), 1_000_000);
    assert_eq!(*probs.get(&LaneChoice::Wasm).unwrap(), 0);
}

#[test]
fn router_lane_probabilities_adaptive() {
    let mut router = HybridLaneRouter::with_defaults();
    router.promote_to_adaptive().unwrap();
    let probs = router.lane_probabilities();
    // Both should be > 0 (exploration ensures non-zero probability)
    assert!(*probs.get(&LaneChoice::Js).unwrap() > 0);
    assert!(*probs.get(&LaneChoice::Wasm).unwrap() > 0);
}

// =========================================================================
// HybridLaneRouter — summary
// =========================================================================

#[test]
fn router_summary() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = ok_observation(LaneChoice::Js);
    router.observe(LaneChoice::Js, &obs, None);

    let summary = router.summary();
    assert_eq!(summary.round, 1);
    assert_eq!(summary.policy, RoutingPolicy::Conservative);
    assert_eq!(summary.total_js_routes, 1);
    assert_eq!(summary.total_wasm_routes, 0);
}

#[test]
fn router_summary_serde_roundtrip() {
    let mut router = HybridLaneRouter::with_defaults();
    router.observe(LaneChoice::Js, &ok_observation(LaneChoice::Js), None);
    let summary = router.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let restored: RouterSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// =========================================================================
// HybridLaneRouter — serde roundtrip
// =========================================================================

#[test]
fn router_serde_roundtrip() {
    let mut router = HybridLaneRouter::with_defaults();
    router.observe(LaneChoice::Js, &ok_observation(LaneChoice::Js), None);
    let json = serde_json::to_string(&router).unwrap();
    let restored: HybridLaneRouter = serde_json::from_str(&json).unwrap();
    assert_eq!(router, restored);
}

// =========================================================================
// Full lifecycle: conservative → adaptive → observe → demote
// =========================================================================

#[test]
fn full_lifecycle() {
    let mut router = HybridLaneRouter::with_defaults();

    // Start conservative, observe a few rounds
    for _ in 0..5 {
        router.observe(LaneChoice::Js, &ok_observation(LaneChoice::Js), None);
    }
    assert_eq!(router.round, 5);
    assert_eq!(router.total_js_routes, 5);

    // Promote to adaptive
    router.promote_to_adaptive().unwrap();
    assert_eq!(router.policy, RoutingPolicy::Adaptive);

    // Observe some adaptive rounds
    for i in 0..10 {
        let lane = if i % 2 == 0 {
            LaneChoice::Js
        } else {
            LaneChoice::Wasm
        };
        router.observe(lane, &ok_observation(lane), Some(i * 100_000));
    }

    assert_eq!(router.round, 15);
    assert!(router.total_wasm_routes > 0);

    // Summary should reflect state
    let summary = router.summary();
    assert_eq!(summary.round, 15);
    assert!(summary.policy_transitions >= 1);

    // Decision log should have entries
    assert!(!router.decision_log.is_empty());

    // Serde roundtrip
    let json = serde_json::to_string(&router).unwrap();
    let restored: HybridLaneRouter = serde_json::from_str(&json).unwrap();
    assert_eq!(router, restored);
}

// =========================================================================
// Enrichment: LaneChoice additional coverage
// =========================================================================

#[test]
fn lane_choice_all_contains_both_variants() {
    assert_eq!(LaneChoice::ALL.len(), 2);
    assert_eq!(LaneChoice::ALL[0], LaneChoice::Js);
    assert_eq!(LaneChoice::ALL[1], LaneChoice::Wasm);
}

#[test]
fn lane_choice_from_index_boundary_values() {
    assert_eq!(LaneChoice::from_index(0), Some(LaneChoice::Js));
    assert_eq!(LaneChoice::from_index(1), Some(LaneChoice::Wasm));
    assert_eq!(LaneChoice::from_index(2), None);
    assert_eq!(LaneChoice::from_index(usize::MAX), None);
}

#[test]
fn lane_choice_index_distinct() {
    assert_ne!(LaneChoice::Js.index(), LaneChoice::Wasm.index());
}

#[test]
fn lane_choice_as_str_distinct() {
    assert_ne!(LaneChoice::Js.as_str(), LaneChoice::Wasm.as_str());
}

#[test]
fn lane_choice_clone_equals_original() {
    let original = LaneChoice::Wasm;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn lane_choice_debug_non_empty() {
    let dbg = format!("{:?}", LaneChoice::Js);
    assert!(!dbg.is_empty());
    let dbg2 = format!("{:?}", LaneChoice::Wasm);
    assert!(!dbg2.is_empty());
    assert_ne!(dbg, dbg2);
}

#[test]
fn lane_choice_hash_consistent() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(LaneChoice::Js);
    set.insert(LaneChoice::Wasm);
    set.insert(LaneChoice::Js); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn lane_choice_serde_json_string_values() {
    let js_json = serde_json::to_string(&LaneChoice::Js).unwrap();
    let wasm_json = serde_json::to_string(&LaneChoice::Wasm).unwrap();
    assert!(js_json.contains("Js"));
    assert!(wasm_json.contains("Wasm"));
}

// =========================================================================
// Enrichment: RoutingPolicy additional coverage
// =========================================================================

#[test]
fn routing_policy_ordering() {
    assert!(RoutingPolicy::Conservative < RoutingPolicy::Adaptive);
}

#[test]
fn routing_policy_clone_eq() {
    let a = RoutingPolicy::Adaptive;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn routing_policy_debug_distinct() {
    let c_dbg = format!("{:?}", RoutingPolicy::Conservative);
    let a_dbg = format!("{:?}", RoutingPolicy::Adaptive);
    assert_ne!(c_dbg, a_dbg);
}

// =========================================================================
// Enrichment: DemotionReason additional coverage
// =========================================================================

#[test]
fn demotion_reason_ordering_manual_is_last() {
    let change = DemotionReason::ChangePointDetected {
        cusum_stat_millionths: 1,
        threshold_millionths: 1,
    };
    let manual = DemotionReason::ManualDemotion;
    // ManualDemotion should sort after struct variants due to enum ordering
    assert!(change < manual);
}

#[test]
fn demotion_reason_clone_preserves_fields() {
    let original = DemotionReason::TailLatencyBudgetExhausted {
        observed_p99_us: 25_000,
        budget_us: 16_000,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn demotion_reason_debug_contains_variant_name() {
    let r = DemotionReason::RegretExceeded {
        realized_millionths: 1_000_000,
        bound_millionths: 500_000,
    };
    let dbg = format!("{:?}", r);
    assert!(dbg.contains("RegretExceeded"));
}

#[test]
fn demotion_reason_serde_change_point_fields() {
    let reason = DemotionReason::ChangePointDetected {
        cusum_stat_millionths: 5_000_000,
        threshold_millionths: 2_000_000,
    };
    let json = serde_json::to_string(&reason).unwrap();
    let restored: DemotionReason = serde_json::from_str(&json).unwrap();
    if let DemotionReason::ChangePointDetected {
        cusum_stat_millionths,
        threshold_millionths,
    } = restored
    {
        assert_eq!(cusum_stat_millionths, 5_000_000);
        assert_eq!(threshold_millionths, 2_000_000);
    } else {
        panic!("unexpected variant");
    }
}

// =========================================================================
// Enrichment: PolicyTransition additional coverage
// =========================================================================

#[test]
fn policy_transition_no_reason() {
    let pt = PolicyTransition {
        round: 10,
        from: RoutingPolicy::Conservative,
        to: RoutingPolicy::Adaptive,
        reason: None,
    };
    let json = serde_json::to_string(&pt).unwrap();
    let restored: PolicyTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(pt, restored);
    assert!(restored.reason.is_none());
}

#[test]
fn policy_transition_debug_format() {
    let pt = PolicyTransition {
        round: 0,
        from: RoutingPolicy::Adaptive,
        to: RoutingPolicy::Conservative,
        reason: Some(DemotionReason::ManualDemotion),
    };
    let dbg = format!("{:?}", pt);
    assert!(dbg.contains("ManualDemotion"));
}

// =========================================================================
// Enrichment: LaneObservation additional coverage
// =========================================================================

#[test]
fn lane_observation_serde_roundtrip() {
    let obs = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 12_000,
        success: true,
        dom_ops: 500,
        signals_evaluated: 200,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let restored: LaneObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, restored);
}

#[test]
fn lane_observation_all_fields_failure() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 0,
        success: false,
        dom_ops: 0,
        signals_evaluated: 0,
        safe_mode_entered: true,
        compatibility_errors: 100,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let restored: LaneObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, restored);
}

#[test]
fn lane_observation_max_latency() {
    let obs = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: u64::MAX,
        success: true,
        dom_ops: 0,
        signals_evaluated: 0,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let restored: LaneObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, restored);
}

// =========================================================================
// Enrichment: ConformalConfig additional coverage
// =========================================================================

#[test]
fn conformal_config_default_values() {
    let cfg = ConformalConfig::default_config();
    assert_eq!(cfg.target_coverage_millionths, 900_000);
    assert_eq!(cfg.min_observations, 20);
    assert_eq!(cfg.window_size, 100);
}

#[test]
fn conformal_config_serde_roundtrip() {
    let cfg = ConformalConfig {
        target_coverage_millionths: 950_000,
        min_observations: 50,
        window_size: 200,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ConformalConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// Enrichment: ConformalState additional coverage
// =========================================================================

#[test]
fn conformal_valid_below_min_observations() {
    let mut state = ConformalState::new(ConformalConfig {
        target_coverage_millionths: 900_000,
        min_observations: 20,
        window_size: 100,
    });
    // All out of bounds, but below min_observations
    for _ in 0..19 {
        state.observe(false);
    }
    assert!(state.is_valid());
    assert!(state.check().is_none());
}

#[test]
fn conformal_window_eviction_behavior() {
    let mut state = ConformalState::new(ConformalConfig {
        target_coverage_millionths: 500_000,
        min_observations: 1,
        window_size: 3,
    });
    state.observe(false);
    state.observe(false);
    state.observe(false);
    assert_eq!(state.window.len(), 3);
    assert_eq!(state.coverage_millionths(), 0);

    // Now push in-bounds, evicting oldest out-of-bounds
    state.observe(true);
    assert_eq!(state.window.len(), 3);
    // Window is [false, false, true] -> 1/3 coverage
    assert!(state.coverage_millionths() > 0);
    assert!(state.coverage_millionths() < 500_000);
}

#[test]
fn conformal_coverage_100_percent() {
    let mut state = ConformalState::new(ConformalConfig {
        target_coverage_millionths: 900_000,
        min_observations: 5,
        window_size: 10,
    });
    for _ in 0..10 {
        state.observe(true);
    }
    assert_eq!(state.coverage_millionths(), 1_000_000);
    assert!(state.is_valid());
}

#[test]
fn conformal_coverage_0_percent() {
    let mut state = ConformalState::new(ConformalConfig {
        target_coverage_millionths: 100_000,
        min_observations: 5,
        window_size: 10,
    });
    for _ in 0..10 {
        state.observe(false);
    }
    assert_eq!(state.coverage_millionths(), 0);
    assert!(!state.is_valid());
}

#[test]
fn conformal_total_observations_tracks() {
    let mut state = ConformalState::new(ConformalConfig::default_config());
    for _ in 0..50 {
        state.observe(true);
    }
    assert_eq!(state.total_observations, 50);
    assert_eq!(state.total_in_bounds, 50);
}

#[test]
fn conformal_check_returns_reason_with_values() {
    let mut state = ConformalState::new(ConformalConfig {
        target_coverage_millionths: 900_000,
        min_observations: 5,
        window_size: 10,
    });
    for _ in 0..10 {
        state.observe(false);
    }
    let reason = state.check().unwrap();
    if let DemotionReason::ConformalViolation {
        coverage_millionths,
        target_millionths,
    } = reason
    {
        assert_eq!(coverage_millionths, 0);
        assert_eq!(target_millionths, 900_000);
    } else {
        panic!("expected ConformalViolation");
    }
}

// =========================================================================
// Enrichment: ChangePointConfig additional coverage
// =========================================================================

#[test]
fn change_point_config_default_values() {
    let cfg = ChangePointConfig::default_config();
    assert_eq!(cfg.threshold_millionths, 2_000_000);
    assert_eq!(cfg.drift_millionths, 50_000);
    assert_eq!(cfg.min_observations, 10);
}

#[test]
fn change_point_config_serde_roundtrip() {
    let cfg = ChangePointConfig {
        threshold_millionths: 1_000_000,
        drift_millionths: 100_000,
        min_observations: 5,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ChangePointConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// Enrichment: ChangePointMonitor additional coverage
// =========================================================================

#[test]
fn change_point_detects_upward_shift() {
    let mut mon = ChangePointMonitor::new(ChangePointConfig {
        threshold_millionths: 500_000,
        drift_millionths: 10_000,
        min_observations: 5,
    });
    // Stable period at low values
    for _ in 0..10 {
        mon.observe(100_000);
    }
    // Sudden upward shift
    for _ in 0..20 {
        mon.observe(900_000);
    }
    assert!(mon.is_triggered());
    let reason = mon.check().unwrap();
    assert!(matches!(reason, DemotionReason::ChangePointDetected { .. }));
}

#[test]
fn change_point_reset_preserves_count_and_mean() {
    let mut mon = ChangePointMonitor::new(ChangePointConfig::default_config());
    for _ in 0..15 {
        mon.observe(500_000);
    }
    let count_before = mon.observation_count;
    let mean_before = mon.running_mean_millionths;
    mon.reset();
    assert_eq!(mon.cusum_upper_millionths, 0);
    assert_eq!(mon.cusum_lower_millionths, 0);
    assert_eq!(mon.observation_count, count_before);
    assert_eq!(mon.running_mean_millionths, mean_before);
}

#[test]
fn change_point_zero_threshold_triggers_after_min_obs() {
    let mut mon = ChangePointMonitor::new(ChangePointConfig {
        threshold_millionths: 0,
        drift_millionths: 0,
        min_observations: 3,
    });
    mon.observe(500_000);
    mon.observe(500_000);
    assert!(!mon.is_triggered());
    mon.observe(500_000);
    assert!(mon.is_triggered());
}

#[test]
fn change_point_negative_threshold_triggers_after_min_obs() {
    let mut mon = ChangePointMonitor::new(ChangePointConfig {
        threshold_millionths: -100,
        drift_millionths: 0,
        min_observations: 2,
    });
    mon.observe(0);
    assert!(!mon.is_triggered());
    mon.observe(0);
    assert!(mon.is_triggered());
}

#[test]
fn change_point_running_mean_updates() {
    let mut mon = ChangePointMonitor::new(ChangePointConfig::default_config());
    mon.observe(1_000_000);
    assert_eq!(mon.running_mean_millionths, 1_000_000);
    mon.observe(0);
    // Mean after two observations of 1M and 0 should be 500k
    assert_eq!(mon.running_mean_millionths, 500_000);
}

#[test]
fn change_point_check_returns_none_when_not_triggered() {
    let mon = ChangePointMonitor::new(ChangePointConfig::default_config());
    assert!(mon.check().is_none());
}

// =========================================================================
// Enrichment: RiskBudget additional coverage
// =========================================================================

#[test]
fn risk_budget_serde_roundtrip() {
    let budget = RiskBudget {
        tail_latency_budget_us: 32_000,
        compatibility_error_budget: 10,
        regret_budget_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&budget).unwrap();
    let restored: RiskBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, restored);
}

#[test]
fn risk_budget_default_positive_values() {
    let budget = RiskBudget::default_budget();
    assert!(budget.tail_latency_budget_us > 0);
    assert!(budget.compatibility_error_budget > 0);
    assert!(budget.regret_budget_millionths > 0);
}

// =========================================================================
// Enrichment: RiskAccumulator additional coverage
// =========================================================================

#[test]
fn risk_accumulator_default_eq_new() {
    let a = RiskAccumulator::default();
    let b = RiskAccumulator::new();
    assert_eq!(a, b);
}

#[test]
fn risk_accumulator_p99_single_value() {
    let mut acc = RiskAccumulator::new();
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 7_500,
        success: true,
        dom_ops: 100,
        signals_evaluated: 50,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    acc.record(&obs, 800_000);
    assert_eq!(acc.p99_latency_us(), 7_500);
}

#[test]
fn risk_accumulator_p99_multiple_values() {
    let mut acc = RiskAccumulator::new();
    for i in 1..=100 {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: i * 100,
            success: true,
            dom_ops: 10,
            signals_evaluated: 5,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        acc.record(&obs, 500_000);
    }
    let p99 = acc.p99_latency_us();
    // p99 of 100..10000 step 100 should be near 10000
    assert!(p99 >= 9_900);
}

#[test]
fn risk_accumulator_tail_latency_budget_violation() {
    let mut acc = RiskAccumulator::new();
    let budget = RiskBudget {
        tail_latency_budget_us: 5_000,
        compatibility_error_budget: 100,
        regret_budget_millionths: 100_000_000,
    };
    for _ in 0..100 {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 10_000,
            success: true,
            dom_ops: 10,
            signals_evaluated: 5,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        acc.record(&obs, 500_000);
    }
    let reason = acc.check_budgets(&budget);
    assert!(matches!(
        reason,
        Some(DemotionReason::TailLatencyBudgetExhausted { .. })
    ));
}

#[test]
fn risk_accumulator_latency_window_capped() {
    let mut acc = RiskAccumulator::new();
    for _ in 0..1100 {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 1_000,
            success: true,
            dom_ops: 10,
            signals_evaluated: 5,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        acc.record(&obs, 500_000);
    }
    assert!(acc.latencies_us.len() <= 1000);
}

#[test]
fn risk_accumulator_tracks_per_lane_rewards() {
    let mut acc = RiskAccumulator::new();
    let obs_js = ok_observation(LaneChoice::Js);
    let obs_wasm = ok_observation(LaneChoice::Wasm);
    acc.record(&obs_js, 800_000);
    acc.record(&obs_wasm, 600_000);
    assert_eq!(
        *acc.cumulative_rewards.get(&LaneChoice::Js).unwrap(),
        800_000
    );
    assert_eq!(
        *acc.cumulative_rewards.get(&LaneChoice::Wasm).unwrap(),
        600_000
    );
}

#[test]
fn risk_accumulator_tracks_per_lane_pulls() {
    let mut acc = RiskAccumulator::new();
    let obs_js = ok_observation(LaneChoice::Js);
    acc.record(&obs_js, 500_000);
    acc.record(&obs_js, 500_000);
    acc.record(&obs_js, 500_000);
    assert_eq!(*acc.lane_pulls.get(&LaneChoice::Js).unwrap(), 3);
}

#[test]
fn risk_accumulator_no_budgets_violated_clean() {
    let mut acc = RiskAccumulator::new();
    let budget = RiskBudget::default_budget();
    for _ in 0..10 {
        acc.record(&ok_observation(LaneChoice::Js), 800_000);
    }
    assert!(acc.check_budgets(&budget).is_none());
}

// =========================================================================
// Enrichment: AdaptiveWeights additional coverage
// =========================================================================

#[test]
fn adaptive_weights_default_eq_new() {
    let a = AdaptiveWeights::default();
    let b = AdaptiveWeights::new();
    assert_eq!(a, b);
}

#[test]
fn adaptive_weights_probabilities_sum_approximately_million() {
    let w = AdaptiveWeights::new();
    let probs = w.probabilities_millionths();
    let total: i64 = probs.iter().sum();
    // Should sum close to 1_000_000 (may be off by rounding)
    assert!(
        (total - 1_000_000).abs() < 50_000,
        "probs sum = {total}, expected ~1_000_000"
    );
}

#[test]
fn adaptive_weights_after_many_updates_probs_still_bounded() {
    let mut w = AdaptiveWeights::new();
    for _ in 0..100 {
        w.update(LaneChoice::Wasm, 1_000_000);
    }
    let probs = w.probabilities_millionths();
    for p in &probs {
        assert!(*p >= 0, "probability should be non-negative, got {p}");
        assert!(*p <= 1_000_000, "probability should be <= MILLION, got {p}");
    }
}

#[test]
fn adaptive_weights_gamma_ensures_exploration() {
    let mut w = AdaptiveWeights::new();
    // Heavily reward Js
    for _ in 0..50 {
        w.update(LaneChoice::Js, 1_000_000);
    }
    let probs = w.probabilities_millionths();
    // Even after heavy rewarding, Wasm should still have nonzero probability due to exploration
    assert!(probs[1] > 0, "wasm prob should be > 0 due to exploration");
}

#[test]
fn adaptive_weights_zero_reward_no_change() {
    let mut w = AdaptiveWeights::new();
    let probs_before = w.probabilities_millionths();
    w.update(LaneChoice::Js, 0);
    let probs_after = w.probabilities_millionths();
    // With zero reward, log_weights should not shift much
    let diff = (probs_before[0] - probs_after[0]).abs();
    assert!(diff < 50_000, "zero reward should cause minimal shift");
}

#[test]
fn adaptive_weights_select_boundary() {
    let w = AdaptiveWeights::new();
    // At exact boundary of Js probability, should still select one
    let probs = w.probabilities_millionths();
    let boundary = probs[0];
    let lane = w.select(boundary);
    // At or above Js probability -> Wasm
    assert_eq!(lane, LaneChoice::Wasm);
}

#[test]
fn adaptive_weights_rounds_increment() {
    let mut w = AdaptiveWeights::new();
    assert_eq!(w.rounds, 0);
    w.update(LaneChoice::Js, 500_000);
    assert_eq!(w.rounds, 1);
    w.update(LaneChoice::Wasm, 500_000);
    assert_eq!(w.rounds, 2);
}

// =========================================================================
// Enrichment: compute_reward additional coverage
// =========================================================================

#[test]
fn reward_zero_baseline_no_panic() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 5_000,
        success: true,
        dom_ops: 100,
        signals_evaluated: 50,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let r = compute_reward(&obs, 0);
    assert!((0..=1_000_000).contains(&r));
}

#[test]
fn reward_high_latency_low_reward() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 16_000,
        success: true,
        dom_ops: 50,
        signals_evaluated: 25,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let r = compute_reward(&obs, 8_000);
    // At 2x baseline, latency reward should be near 0
    assert!(r < 500_000, "high latency should lower reward, got {r}");
}

#[test]
fn reward_max_dom_ops_throughput_bonus() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 0,
        success: true,
        dom_ops: 10_000,
        signals_evaluated: 100,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let r = compute_reward(&obs, 8_000);
    assert!(
        r > 800_000,
        "high throughput should give high reward, got {r}"
    );
}

#[test]
fn reward_always_in_0_million_range() {
    let cases = vec![
        (0_u64, true, 0_u32, false, 0_u32),
        (100_000, true, 10_000, false, 0),
        (0, true, 0, true, 0),
        (0, true, 0, false, 5),
        (0, false, 0, false, 0),
    ];
    for (lat, success, dom, safe, compat) in cases {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: lat,
            success,
            dom_ops: dom,
            signals_evaluated: 0,
            safe_mode_entered: safe,
            compatibility_errors: compat,
        };
        let r = compute_reward(&obs, 8_000);
        assert!(
            (0..=1_000_000).contains(&r),
            "reward out of range: {r} for case lat={lat} success={success}"
        );
    }
}

#[test]
fn reward_safe_mode_always_100k() {
    let obs = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 0,
        success: true,
        dom_ops: 10_000,
        signals_evaluated: 5_000,
        safe_mode_entered: true,
        compatibility_errors: 0,
    };
    assert_eq!(compute_reward(&obs, 8_000), 100_000);
}

#[test]
fn reward_compat_errors_always_200k() {
    let obs = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 0,
        success: true,
        dom_ops: 10_000,
        signals_evaluated: 5_000,
        safe_mode_entered: false,
        compatibility_errors: 50,
    };
    assert_eq!(compute_reward(&obs, 8_000), 200_000);
}

#[test]
fn reward_safe_mode_takes_priority_over_compat_errors() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 0,
        success: true,
        dom_ops: 100,
        signals_evaluated: 50,
        safe_mode_entered: true,
        compatibility_errors: 10,
    };
    // safe_mode check comes before compat_errors check
    assert_eq!(compute_reward(&obs, 8_000), 100_000);
}

// =========================================================================
// Enrichment: RoutingDecisionTrace additional coverage
// =========================================================================

fn sample_trace() -> RoutingDecisionTrace {
    RoutingDecisionTrace {
        round: 10,
        policy: RoutingPolicy::Adaptive,
        chosen_lane: LaneChoice::Wasm,
        rejected_lanes: vec![LaneChoice::Js],
        probabilities_millionths: vec![400_000, 600_000],
        random_draw_millionths: Some(550_000),
        reward_millionths: Some(800_000),
        cumulative_regret_millionths: 50_000,
        p99_latency_us: 3_000,
        compatibility_errors: 0,
        conformal_coverage_millionths: 980_000,
        cusum_stat_millionths: 100_000,
        demotion_reason: None,
    }
}

#[test]
fn routing_decision_trace_serde_roundtrip() {
    let trace = sample_trace();
    let json = serde_json::to_string(&trace).unwrap();
    let restored: RoutingDecisionTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, restored);
}

#[test]
fn routing_decision_trace_with_demotion_serde() {
    let mut trace = sample_trace();
    trace.demotion_reason = Some(DemotionReason::ManualDemotion);
    let json = serde_json::to_string(&trace).unwrap();
    let restored: RoutingDecisionTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, restored);
}

#[test]
fn routing_decision_trace_derive_id_stable() {
    let trace = sample_trace();
    let id1 = trace.derive_id();
    let id2 = trace.derive_id();
    assert_eq!(id1, id2);
}

#[test]
fn routing_decision_trace_derive_id_differs_by_round() {
    let mut trace1 = sample_trace();
    trace1.round = 1;
    let mut trace2 = sample_trace();
    trace2.round = 2;
    assert_ne!(trace1.derive_id(), trace2.derive_id());
}

#[test]
fn routing_decision_trace_derive_id_differs_by_lane() {
    let mut trace1 = sample_trace();
    trace1.chosen_lane = LaneChoice::Js;
    let mut trace2 = sample_trace();
    trace2.chosen_lane = LaneChoice::Wasm;
    // Same round but different lane should produce different IDs
    assert_ne!(trace1.derive_id(), trace2.derive_id());
}

#[test]
fn routing_decision_trace_conservative_policy() {
    let trace = RoutingDecisionTrace {
        round: 0,
        policy: RoutingPolicy::Conservative,
        chosen_lane: LaneChoice::Js,
        rejected_lanes: vec![LaneChoice::Wasm],
        probabilities_millionths: vec![1_000_000, 0],
        random_draw_millionths: None,
        reward_millionths: None,
        cumulative_regret_millionths: 0,
        p99_latency_us: 0,
        compatibility_errors: 0,
        conformal_coverage_millionths: 1_000_000,
        cusum_stat_millionths: 0,
        demotion_reason: None,
    };
    let json = serde_json::to_string(&trace).unwrap();
    let restored: RoutingDecisionTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, restored);
}

// =========================================================================
// Enrichment: RouterConfig additional coverage
// =========================================================================

#[test]
fn router_config_default_baseline_is_js() {
    let cfg = RouterConfig::default_config();
    assert_eq!(cfg.baseline_lane, LaneChoice::Js);
    assert_eq!(cfg.latency_baseline_us, 8_000);
    assert_eq!(cfg.adaptive_horizon, 1000);
}

#[test]
fn router_config_custom_serde_roundtrip() {
    let cfg = RouterConfig {
        baseline_lane: LaneChoice::Wasm,
        risk_budget: RiskBudget {
            tail_latency_budget_us: 32_000,
            compatibility_error_budget: 20,
            regret_budget_millionths: 2_000_000,
        },
        conformal: ConformalConfig {
            target_coverage_millionths: 950_000,
            min_observations: 30,
            window_size: 50,
        },
        change_point: ChangePointConfig {
            threshold_millionths: 3_000_000,
            drift_millionths: 100_000,
            min_observations: 15,
        },
        latency_baseline_us: 16_000,
        adaptive_horizon: 500,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: RouterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// Enrichment: RouterError additional coverage
// =========================================================================

#[test]
fn router_error_all_variants_serde() {
    let errors = vec![
        RouterError::AlreadyConservative,
        RouterError::InvalidRandomDraw { value: -1 },
        RouterError::InvalidRandomDraw { value: 2_000_000 },
        RouterError::InvalidConfig {
            reason: "threshold must be positive".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: RouterError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn router_error_debug_format() {
    let err = RouterError::AlreadyConservative;
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("AlreadyConservative"));
}

#[test]
fn router_error_invalid_config_preserves_reason() {
    let err = RouterError::InvalidConfig {
        reason: "test reason".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: RouterError = serde_json::from_str(&json).unwrap();
    if let RouterError::InvalidConfig { reason } = restored {
        assert_eq!(reason, "test reason");
    } else {
        panic!("expected InvalidConfig");
    }
}

// =========================================================================
// Enrichment: HybridLaneRouter additional coverage
// =========================================================================

#[test]
fn router_new_with_custom_config() {
    let cfg = RouterConfig {
        baseline_lane: LaneChoice::Wasm,
        ..RouterConfig::default_config()
    };
    let router = HybridLaneRouter::new(cfg);
    assert_eq!(router.config.baseline_lane, LaneChoice::Wasm);
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn router_conservative_always_returns_baseline_wasm() {
    let cfg = RouterConfig {
        baseline_lane: LaneChoice::Wasm,
        ..RouterConfig::default_config()
    };
    let router = HybridLaneRouter::new(cfg);
    for r in 0..100 {
        assert_eq!(router.select_lane(r * 10_000), LaneChoice::Wasm);
    }
}

#[test]
fn router_observe_wasm_increments_wasm_count() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = ok_observation(LaneChoice::Wasm);
    router.observe(LaneChoice::Wasm, &obs, None);
    assert_eq!(router.total_wasm_routes, 1);
    assert_eq!(router.total_js_routes, 0);
}

#[test]
fn router_observe_with_random_draw() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = ok_observation(LaneChoice::Js);
    let trace = router.observe(LaneChoice::Js, &obs, Some(750_000));
    assert_eq!(trace.random_draw_millionths, Some(750_000));
}

#[test]
fn router_promote_idempotent() {
    let mut router = HybridLaneRouter::with_defaults();
    router.promote_to_adaptive().unwrap();
    // Second promote is idempotent
    router.promote_to_adaptive().unwrap();
    assert_eq!(router.policy, RoutingPolicy::Adaptive);
    // Only one transition recorded
    assert_eq!(router.policy_transitions.len(), 1);
}

#[test]
fn router_promote_resets_consecutive_conservative() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = ok_observation(LaneChoice::Js);
    router.observe(LaneChoice::Js, &obs, None);
    router.observe(LaneChoice::Js, &obs, None);
    assert_eq!(router.consecutive_conservative_rounds, 2);

    router.promote_to_adaptive().unwrap();
    assert_eq!(router.consecutive_conservative_rounds, 0);
}

#[test]
fn router_consecutive_conservative_resets_on_adaptive() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = ok_observation(LaneChoice::Js);
    router.observe(LaneChoice::Js, &obs, None);
    router.observe(LaneChoice::Js, &obs, None);

    router.promote_to_adaptive().unwrap();
    router.observe(LaneChoice::Js, &obs, None);
    assert_eq!(router.consecutive_conservative_rounds, 0);
}

#[test]
fn router_decision_log_trims_at_1000() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = ok_observation(LaneChoice::Js);
    for _ in 0..1050 {
        router.observe(LaneChoice::Js, &obs, None);
    }
    assert!(router.decision_log.len() <= 1000);
}

#[test]
fn router_derive_id_stable() {
    let r1 = HybridLaneRouter::with_defaults();
    let r2 = HybridLaneRouter::with_defaults();
    assert_eq!(r1.derive_id(), r2.derive_id());
}

#[test]
fn router_derive_id_changes_after_observe() {
    let mut router = HybridLaneRouter::with_defaults();
    let id_before = router.derive_id();
    router.observe(LaneChoice::Js, &ok_observation(LaneChoice::Js), None);
    let id_after = router.derive_id();
    assert_ne!(id_before, id_after);
}

#[test]
fn router_demotes_on_tail_latency() {
    let mut router = HybridLaneRouter::new(RouterConfig {
        risk_budget: RiskBudget {
            tail_latency_budget_us: 5_000,
            compatibility_error_budget: 1000,
            regret_budget_millionths: 100_000_000,
        },
        change_point: ChangePointConfig {
            threshold_millionths: 100_000_000,
            ..ChangePointConfig::default_config()
        },
        conformal: ConformalConfig {
            target_coverage_millionths: 0,
            ..ConformalConfig::default_config()
        },
        ..RouterConfig::default_config()
    });
    router.promote_to_adaptive().unwrap();

    // Send many high-latency observations
    for _ in 0..100 {
        let obs = LaneObservation {
            lane: LaneChoice::Wasm,
            latency_us: 50_000,
            success: true,
            dom_ops: 10,
            signals_evaluated: 5,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        router.observe(LaneChoice::Wasm, &obs, None);
    }
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn router_demotes_on_conformal_violation() {
    let mut router = HybridLaneRouter::new(RouterConfig {
        conformal: ConformalConfig {
            target_coverage_millionths: 900_000,
            min_observations: 5,
            window_size: 10,
        },
        change_point: ChangePointConfig {
            threshold_millionths: 100_000_000,
            ..ChangePointConfig::default_config()
        },
        ..RouterConfig::default_config()
    });
    router.promote_to_adaptive().unwrap();

    // Failing observations -> conformal violation
    for _ in 0..10 {
        let obs = LaneObservation {
            lane: LaneChoice::Wasm,
            latency_us: 1_000,
            success: false,
            dom_ops: 0,
            signals_evaluated: 0,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        router.observe(LaneChoice::Wasm, &obs, None);
    }
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn router_no_demotion_in_conservative_mode() {
    let mut router = HybridLaneRouter::with_defaults();
    // Even with bad observations, no demotion occurs in conservative mode
    for _ in 0..20 {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 100_000,
            success: false,
            dom_ops: 0,
            signals_evaluated: 0,
            safe_mode_entered: true,
            compatibility_errors: 10,
        };
        let trace = router.observe(LaneChoice::Js, &obs, None);
        assert!(trace.demotion_reason.is_none());
    }
    assert_eq!(router.policy, RoutingPolicy::Conservative);
}

#[test]
fn router_promote_demote_promote_cycle() {
    let mut router = HybridLaneRouter::new(RouterConfig {
        risk_budget: RiskBudget {
            compatibility_error_budget: 0,
            ..RiskBudget::default_budget()
        },
        ..RouterConfig::default_config()
    });

    // First promote
    router.promote_to_adaptive().unwrap();
    assert_eq!(router.policy, RoutingPolicy::Adaptive);

    // Trigger demotion via compat errors
    let bad = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 1_000,
        success: true,
        dom_ops: 10,
        signals_evaluated: 5,
        safe_mode_entered: false,
        compatibility_errors: 1,
    };
    router.observe(LaneChoice::Wasm, &bad, None);
    assert_eq!(router.policy, RoutingPolicy::Conservative);

    // Re-promote
    router.promote_to_adaptive().unwrap();
    assert_eq!(router.policy, RoutingPolicy::Adaptive);
    assert_eq!(router.policy_transitions.len(), 3);
}

// =========================================================================
// Enrichment: RouterSummary additional coverage
// =========================================================================

#[test]
fn router_summary_fields_match_router() {
    let mut router = HybridLaneRouter::with_defaults();
    let js_obs = ok_observation(LaneChoice::Js);
    let wasm_obs = ok_observation(LaneChoice::Wasm);
    router.observe(LaneChoice::Js, &js_obs, None);
    router.observe(LaneChoice::Js, &js_obs, None);
    router.observe(LaneChoice::Wasm, &wasm_obs, None);

    let summary = router.summary();
    assert_eq!(summary.round, 3);
    assert_eq!(summary.total_js_routes, 2);
    assert_eq!(summary.total_wasm_routes, 1);
    assert_eq!(summary.policy, RoutingPolicy::Conservative);
    assert_eq!(summary.consecutive_conservative_rounds, 3);
}

#[test]
fn router_summary_derive_id_stable() {
    let summary = RouterSummary {
        round: 50,
        policy: RoutingPolicy::Adaptive,
        total_js_routes: 30,
        total_wasm_routes: 20,
        p99_latency_us: 4_000,
        cumulative_regret_millionths: 200_000,
        compatibility_errors: 1,
        conformal_coverage_millionths: 950_000,
        policy_transitions: 2,
        consecutive_conservative_rounds: 0,
    };
    let id1 = summary.derive_id();
    let id2 = summary.derive_id();
    assert_eq!(id1, id2);
}

#[test]
fn router_summary_derive_id_differs_by_round() {
    let s1 = RouterSummary {
        round: 1,
        policy: RoutingPolicy::Conservative,
        total_js_routes: 1,
        total_wasm_routes: 0,
        p99_latency_us: 0,
        cumulative_regret_millionths: 0,
        compatibility_errors: 0,
        conformal_coverage_millionths: 1_000_000,
        policy_transitions: 0,
        consecutive_conservative_rounds: 1,
    };
    let mut s2 = s1.clone();
    s2.round = 2;
    assert_ne!(s1.derive_id(), s2.derive_id());
}

#[test]
fn router_summary_serde_custom_values() {
    let summary = RouterSummary {
        round: 999,
        policy: RoutingPolicy::Adaptive,
        total_js_routes: 500,
        total_wasm_routes: 499,
        p99_latency_us: 12_345,
        cumulative_regret_millionths: 300_000,
        compatibility_errors: 3,
        conformal_coverage_millionths: 920_000,
        policy_transitions: 5,
        consecutive_conservative_rounds: 0,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: RouterSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// =========================================================================
// Enrichment: E2E scenarios
// =========================================================================

#[test]
fn e2e_adaptive_session_stays_adaptive_with_good_data() {
    let mut router = HybridLaneRouter::new(RouterConfig {
        change_point: ChangePointConfig {
            threshold_millionths: 50_000_000,
            ..ChangePointConfig::default_config()
        },
        risk_budget: RiskBudget {
            tail_latency_budget_us: 1_000_000,
            compatibility_error_budget: 100,
            regret_budget_millionths: 50_000_000,
        },
        ..RouterConfig::default_config()
    });
    router.promote_to_adaptive().unwrap();

    for i in 0..50 {
        let random = ((i as i64) * 20_000) % 1_000_000;
        let lane = router.select_lane(random);
        let obs = LaneObservation {
            lane,
            latency_us: 3_000,
            success: true,
            dom_ops: 150,
            signals_evaluated: 75,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        router.observe(lane, &obs, Some(random));
    }

    assert_eq!(router.policy, RoutingPolicy::Adaptive);
    assert_eq!(router.round, 50);
}

#[test]
fn e2e_regime_shift_causes_demotion() {
    let mut router = HybridLaneRouter::new(RouterConfig {
        change_point: ChangePointConfig {
            threshold_millionths: 500_000,
            drift_millionths: 10_000,
            min_observations: 5,
        },
        ..RouterConfig::default_config()
    });
    router.promote_to_adaptive().unwrap();

    // Good period
    for _ in 0..10 {
        let obs = ok_observation(LaneChoice::Js);
        router.observe(LaneChoice::Js, &obs, None);
    }
    assert_eq!(router.policy, RoutingPolicy::Adaptive);

    // Regime shift: all failures
    for _ in 0..20 {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 1_000,
            success: false,
            dom_ops: 0,
            signals_evaluated: 0,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        router.observe(LaneChoice::Js, &obs, None);
    }

    assert_eq!(router.policy, RoutingPolicy::Conservative);
    assert!(router.policy_transitions.len() >= 2);
}

#[test]
fn e2e_mixed_lane_routing_adaptive() {
    let mut router = HybridLaneRouter::new(RouterConfig {
        risk_budget: RiskBudget {
            tail_latency_budget_us: 100_000,
            compatibility_error_budget: 100,
            regret_budget_millionths: 100_000_000,
        },
        change_point: ChangePointConfig {
            threshold_millionths: 100_000_000,
            ..ChangePointConfig::default_config()
        },
        ..RouterConfig::default_config()
    });
    router.promote_to_adaptive().unwrap();

    // Alternate between lanes
    for i in 0..40 {
        let lane = if i % 2 == 0 {
            LaneChoice::Js
        } else {
            LaneChoice::Wasm
        };
        let obs = ok_observation(lane);
        router.observe(lane, &obs, Some((i * 25_000) % 1_000_000));
    }

    let summary = router.summary();
    assert_eq!(summary.total_js_routes + summary.total_wasm_routes, 40);
}

#[test]
fn e2e_decision_trace_captures_demotion_reason() {
    let mut router = HybridLaneRouter::new(RouterConfig {
        risk_budget: RiskBudget {
            compatibility_error_budget: 0,
            ..RiskBudget::default_budget()
        },
        ..RouterConfig::default_config()
    });
    router.promote_to_adaptive().unwrap();

    let bad = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 1_000,
        success: true,
        dom_ops: 10,
        signals_evaluated: 5,
        safe_mode_entered: false,
        compatibility_errors: 1,
    };
    let trace = router.observe(LaneChoice::Wasm, &bad, None);
    assert!(trace.demotion_reason.is_some());
    assert!(matches!(
        trace.demotion_reason,
        Some(DemotionReason::CompatibilityBudgetExhausted { .. })
    ));
}

#[test]
fn e2e_serde_roundtrip_after_transitions() {
    let mut router = HybridLaneRouter::with_defaults();
    for _ in 0..5 {
        router.observe(LaneChoice::Js, &ok_observation(LaneChoice::Js), None);
    }
    router.promote_to_adaptive().unwrap();
    for i in 0..10 {
        let lane = if i % 2 == 0 {
            LaneChoice::Js
        } else {
            LaneChoice::Wasm
        };
        router.observe(lane, &ok_observation(lane), Some(i * 100_000));
    }

    let json = serde_json::to_string(&router).unwrap();
    let restored: HybridLaneRouter = serde_json::from_str(&json).unwrap();
    assert_eq!(router, restored);
}

#[test]
fn e2e_lane_probabilities_shift_with_reward() {
    let mut router = HybridLaneRouter::with_defaults();
    router.promote_to_adaptive().unwrap();

    let probs_before = router.lane_probabilities();
    let js_before = *probs_before.get(&LaneChoice::Js).unwrap();

    // Heavily reward Wasm
    for _ in 0..20 {
        let obs = LaneObservation {
            lane: LaneChoice::Wasm,
            latency_us: 1_000,
            success: true,
            dom_ops: 500,
            signals_evaluated: 100,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        router.observe(LaneChoice::Wasm, &obs, None);
    }

    let probs_after = router.lane_probabilities();
    let js_after = *probs_after.get(&LaneChoice::Js).unwrap();
    let wasm_after = *probs_after.get(&LaneChoice::Wasm).unwrap();

    // Wasm probability should be higher than before
    assert!(
        wasm_after > js_after || js_after < js_before,
        "wasm should gain probability after consistent rewards"
    );
}
