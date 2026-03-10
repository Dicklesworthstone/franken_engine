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
    RiskAccumulator, RiskBudget, RouterConfig, RouterError, RouterSummary, RoutingPolicy,
    compute_reward,
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
