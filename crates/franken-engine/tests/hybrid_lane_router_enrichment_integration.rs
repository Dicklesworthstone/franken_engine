//! Enrichment integration tests for hybrid_lane_router.
//!
//! Covers: serde round-trips, boundary conditions, determinism,
//! risk budget checks, conformal validity, CUSUM change-point,
//! EXP3 adaptive weights, reward computation, and full router lifecycle.

use frankenengine_engine::hybrid_lane_router::*;

// ---------------------------------------------------------------------------
// Serde round-trip determinism
// ---------------------------------------------------------------------------

#[test]
fn serde_lane_choice_round_trip() {
    for lane in LaneChoice::ALL {
        let json = serde_json::to_string(&lane).unwrap();
        let back: LaneChoice = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, back);
    }
}

#[test]
fn serde_routing_policy_round_trip() {
    for policy in [RoutingPolicy::Conservative, RoutingPolicy::Adaptive] {
        let json = serde_json::to_string(&policy).unwrap();
        let back: RoutingPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }
}

#[test]
fn serde_demotion_reason_all_variants_round_trip() {
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
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: DemotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn serde_router_config_round_trip() {
    let config = RouterConfig::default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: RouterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn serde_hybrid_lane_router_round_trip() {
    let router = HybridLaneRouter::with_defaults();
    let json = serde_json::to_string(&router).unwrap();
    let back: HybridLaneRouter = serde_json::from_str(&json).unwrap();
    assert_eq!(router, back);
}

#[test]
fn serde_policy_transition_round_trip() {
    let transition = PolicyTransition {
        round: 42,
        from: RoutingPolicy::Adaptive,
        to: RoutingPolicy::Conservative,
        reason: Some(DemotionReason::ManualDemotion),
    };
    let json = serde_json::to_string(&transition).unwrap();
    let back: PolicyTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(transition, back);
}

#[test]
fn serde_lane_observation_round_trip() {
    let obs = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 5000,
        success: true,
        dom_ops: 42,
        signals_evaluated: 100,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: LaneObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

// ---------------------------------------------------------------------------
// LaneChoice basics
// ---------------------------------------------------------------------------

#[test]
fn lane_choice_as_str() {
    assert_eq!(LaneChoice::Js.as_str(), "js");
    assert_eq!(LaneChoice::Wasm.as_str(), "wasm");
}

#[test]
fn lane_choice_index_round_trip() {
    for lane in LaneChoice::ALL {
        let idx = lane.index();
        assert_eq!(LaneChoice::from_index(idx), Some(lane));
    }
}

#[test]
fn lane_choice_from_index_out_of_range() {
    assert_eq!(LaneChoice::from_index(2), None);
    assert_eq!(LaneChoice::from_index(usize::MAX), None);
}

// ---------------------------------------------------------------------------
// ConformalState
// ---------------------------------------------------------------------------

#[test]
fn conformal_vacuously_valid_when_empty() {
    let state = ConformalState::new(ConformalConfig::default_config());
    assert!(state.is_valid());
    assert_eq!(state.coverage_millionths(), 1_000_000);
    assert!(state.check().is_none());
}

#[test]
fn conformal_valid_with_insufficient_observations() {
    let config = ConformalConfig {
        target_coverage_millionths: 900_000,
        min_observations: 20,
        window_size: 100,
    };
    let mut state = ConformalState::new(config);
    // Add 10 out-of-bounds observations — still valid because < min_observations
    for _ in 0..10 {
        state.observe(false);
    }
    assert!(state.is_valid());
}

#[test]
fn conformal_detects_low_coverage() {
    let config = ConformalConfig {
        target_coverage_millionths: 900_000,
        min_observations: 5,
        window_size: 100,
    };
    let mut state = ConformalState::new(config);
    // 3 in-bounds, 7 out-of-bounds → 30% coverage
    for _ in 0..3 {
        state.observe(true);
    }
    for _ in 0..7 {
        state.observe(false);
    }
    assert!(!state.is_valid());
    let reason = state.check().unwrap();
    assert!(matches!(reason, DemotionReason::ConformalViolation { .. }));
}

#[test]
fn conformal_window_rolls_over() {
    let config = ConformalConfig {
        target_coverage_millionths: 500_000,
        min_observations: 1,
        window_size: 5,
    };
    let mut state = ConformalState::new(config);
    // Fill window with failures
    for _ in 0..5 {
        state.observe(false);
    }
    assert!(!state.is_valid());
    // Now push successes to fill the window
    for _ in 0..5 {
        state.observe(true);
    }
    assert!(state.is_valid());
    assert_eq!(state.coverage_millionths(), 1_000_000);
}

// ---------------------------------------------------------------------------
// ChangePointMonitor (CUSUM)
// ---------------------------------------------------------------------------

#[test]
fn cusum_not_triggered_below_threshold() {
    let mut monitor = ChangePointMonitor::new(ChangePointConfig::default_config());
    for i in 0..20 {
        monitor.observe(500_000 + (i * 1000));
    }
    assert!(!monitor.is_triggered());
    assert!(monitor.check().is_none());
}

#[test]
fn cusum_triggers_on_large_shift() {
    let config = ChangePointConfig {
        threshold_millionths: 1_000_000,
        drift_millionths: 10_000,
        min_observations: 5,
    };
    let mut monitor = ChangePointMonitor::new(config);
    // Baseline
    for _ in 0..5 {
        monitor.observe(100_000);
    }
    // Sharp upward shift
    for _ in 0..20 {
        monitor.observe(5_000_000);
    }
    assert!(monitor.is_triggered());
    let reason = monitor.check().unwrap();
    assert!(matches!(reason, DemotionReason::ChangePointDetected { .. }));
}

#[test]
fn cusum_not_triggered_with_insufficient_observations() {
    let config = ChangePointConfig {
        threshold_millionths: 0, // would normally trigger immediately
        drift_millionths: 0,
        min_observations: 100,
    };
    let mut monitor = ChangePointMonitor::new(config);
    for _ in 0..99 {
        monitor.observe(1_000_000);
    }
    assert!(!monitor.is_triggered());
}

#[test]
fn cusum_reset_clears_accumulators() {
    let mut monitor = ChangePointMonitor::new(ChangePointConfig::default_config());
    for _ in 0..15 {
        monitor.observe(5_000_000);
    }
    monitor.reset();
    assert_eq!(monitor.cusum_upper_millionths, 0);
    assert_eq!(monitor.cusum_lower_millionths, 0);
    // Count and mean preserved
    assert!(monitor.observation_count > 0);
}

#[test]
fn cusum_non_positive_threshold_forces_demotion() {
    let config = ChangePointConfig {
        threshold_millionths: 0,
        drift_millionths: 0,
        min_observations: 3,
    };
    let mut monitor = ChangePointMonitor::new(config);
    for _ in 0..3 {
        monitor.observe(0);
    }
    assert!(monitor.is_triggered());
}

// ---------------------------------------------------------------------------
// RiskBudget and RiskAccumulator
// ---------------------------------------------------------------------------

#[test]
fn risk_accumulator_starts_clean() {
    let acc = RiskAccumulator::new();
    assert_eq!(acc.p99_latency_us(), 0);
    assert_eq!(acc.compatibility_errors, 0);
    assert_eq!(acc.cumulative_regret_millionths, 0);
}

#[test]
fn risk_accumulator_tracks_latency_p99() {
    let mut acc = RiskAccumulator::new();
    for i in 0..100 {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: (i + 1) * 100,
            success: true,
            dom_ops: 10,
            signals_evaluated: 5,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        acc.record(&obs, 500_000);
    }
    let p99 = acc.p99_latency_us();
    assert!(p99 >= 9900, "p99 should be near 9900, got {p99}");
}

#[test]
fn risk_budget_tail_latency_violation() {
    let budget = RiskBudget {
        tail_latency_budget_us: 1000,
        compatibility_error_budget: 100,
        regret_budget_millionths: 10_000_000,
    };
    let mut acc = RiskAccumulator::new();
    for _ in 0..100 {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: 2000,
            success: true,
            dom_ops: 0,
            signals_evaluated: 0,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        acc.record(&obs, 500_000);
    }
    let violation = acc.check_budgets(&budget);
    assert!(violation.is_some());
    assert!(matches!(
        violation.unwrap(),
        DemotionReason::TailLatencyBudgetExhausted { .. }
    ));
}

#[test]
fn risk_budget_compatibility_error_violation() {
    let budget = RiskBudget {
        tail_latency_budget_us: 100_000,
        compatibility_error_budget: 3,
        regret_budget_millionths: 10_000_000,
    };
    let mut acc = RiskAccumulator::new();
    for _ in 0..5 {
        let obs = LaneObservation {
            lane: LaneChoice::Wasm,
            latency_us: 100,
            success: true,
            dom_ops: 0,
            signals_evaluated: 0,
            safe_mode_entered: false,
            compatibility_errors: 1,
        };
        acc.record(&obs, 200_000);
    }
    let violation = acc.check_budgets(&budget);
    assert!(violation.is_some());
    assert!(matches!(
        violation.unwrap(),
        DemotionReason::CompatibilityBudgetExhausted { .. }
    ));
}

// ---------------------------------------------------------------------------
// Reward computation
// ---------------------------------------------------------------------------

#[test]
fn reward_zero_on_failure() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 100,
        success: false,
        dom_ops: 50,
        signals_evaluated: 10,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    assert_eq!(compute_reward(&obs, 8000), 0);
}

#[test]
fn reward_penalized_on_safe_mode() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 100,
        success: true,
        dom_ops: 50,
        signals_evaluated: 10,
        safe_mode_entered: true,
        compatibility_errors: 0,
    };
    assert_eq!(compute_reward(&obs, 8000), 100_000);
}

#[test]
fn reward_penalized_on_compat_errors() {
    let obs = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 100,
        success: true,
        dom_ops: 50,
        signals_evaluated: 10,
        safe_mode_entered: false,
        compatibility_errors: 3,
    };
    assert_eq!(compute_reward(&obs, 8000), 200_000);
}

#[test]
fn reward_positive_on_good_observation() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 4000,
        success: true,
        dom_ops: 500,
        signals_evaluated: 100,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let reward = compute_reward(&obs, 8000);
    assert!(reward > 0);
    assert!(reward <= 1_000_000);
}

#[test]
fn reward_zero_baseline_latency_handled() {
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 1000,
        success: true,
        dom_ops: 10,
        signals_evaluated: 5,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    // Should not panic with zero baseline
    let reward = compute_reward(&obs, 0);
    assert!(reward >= 0);
}

// ---------------------------------------------------------------------------
// AdaptiveWeights (EXP3)
// ---------------------------------------------------------------------------

#[test]
fn adaptive_weights_default_uniform() {
    let weights = AdaptiveWeights::new();
    let probs = weights.probabilities_millionths();
    assert_eq!(probs.len(), 2);
    // With equal log-weights, probabilities should be near 50-50
    let diff = (probs[0] - probs[1]).abs();
    assert!(diff < 100_000, "expected near-uniform, got diff={diff}");
}

#[test]
fn adaptive_weights_select_deterministic() {
    let weights = AdaptiveWeights::new();
    let lane1 = weights.select(0);
    let lane2 = weights.select(0);
    assert_eq!(lane1, lane2);
}

#[test]
fn adaptive_weights_select_boundary() {
    let weights = AdaptiveWeights::new();
    let probs = weights.probabilities_millionths();
    // Just below the threshold → Js
    let lane_low = weights.select(probs[0] - 1);
    assert_eq!(lane_low, LaneChoice::Js);
    // At the threshold → Wasm
    let lane_high = weights.select(probs[0]);
    assert_eq!(lane_high, LaneChoice::Wasm);
}

#[test]
fn adaptive_weights_update_shifts_probabilities() {
    let mut weights = AdaptiveWeights::new();
    // Repeatedly reward Wasm
    for _ in 0..20 {
        weights.update(LaneChoice::Wasm, 800_000);
    }
    let probs = weights.probabilities_millionths();
    assert!(
        probs[1] > probs[0],
        "Wasm prob ({}) should exceed Js ({})",
        probs[1],
        probs[0]
    );
}

#[test]
fn adaptive_weights_clamp_prevents_overflow() {
    let mut weights = AdaptiveWeights::new();
    // Extreme rewards
    for _ in 0..100 {
        weights.update(LaneChoice::Js, 1_000_000);
    }
    for w in &weights.log_weights_millionths {
        assert!(*w <= 10_000_000);
        assert!(*w >= -10_000_000);
    }
}

// ---------------------------------------------------------------------------
// HybridLaneRouter lifecycle
// ---------------------------------------------------------------------------

#[test]
fn router_starts_conservative() {
    let router = HybridLaneRouter::with_defaults();
    assert_eq!(router.policy, RoutingPolicy::Conservative);
    assert_eq!(router.round, 0);
}

#[test]
fn router_conservative_always_baseline() {
    let router = HybridLaneRouter::with_defaults();
    for random in [0, 250_000, 500_000, 750_000, 999_999] {
        let lane = router.select_lane(random);
        assert_eq!(lane, LaneChoice::Js); // default baseline is Js
    }
}

#[test]
fn router_observe_increments_round() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 1000,
        success: true,
        dom_ops: 10,
        signals_evaluated: 5,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    router.observe(LaneChoice::Js, &obs, None);
    assert_eq!(router.round, 1);
    assert_eq!(router.total_js_routes, 1);
}

#[test]
fn router_tracks_per_lane_counts() {
    let mut router = HybridLaneRouter::with_defaults();
    let js_obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 1000,
        success: true,
        dom_ops: 10,
        signals_evaluated: 5,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let wasm_obs = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 2000,
        success: true,
        dom_ops: 20,
        signals_evaluated: 10,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    for _ in 0..3 {
        router.observe(LaneChoice::Js, &js_obs, None);
    }
    for _ in 0..2 {
        router.observe(LaneChoice::Wasm, &wasm_obs, None);
    }
    assert_eq!(router.total_js_routes, 3);
    assert_eq!(router.total_wasm_routes, 2);
    assert_eq!(router.round, 5);
}

#[test]
fn router_decision_trace_has_required_fields() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 5000,
        success: true,
        dom_ops: 50,
        signals_evaluated: 20,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let trace = router.observe(LaneChoice::Js, &obs, Some(250_000));
    assert_eq!(trace.round, 0); // round is 0-based, incremented after trace
    assert_eq!(trace.chosen_lane, LaneChoice::Js);
    assert!(!trace.probabilities_millionths.is_empty());
}

#[test]
fn router_serde_after_multiple_observations() {
    let mut router = HybridLaneRouter::with_defaults();
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 3000,
        success: true,
        dom_ops: 30,
        signals_evaluated: 15,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    for _ in 0..10 {
        router.observe(LaneChoice::Js, &obs, None);
    }
    let json = serde_json::to_string(&router).unwrap();
    let back: HybridLaneRouter = serde_json::from_str(&json).unwrap();
    assert_eq!(router.round, back.round);
    assert_eq!(router.total_js_routes, back.total_js_routes);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn deterministic_identical_observation_sequences() {
    let mut r1 = HybridLaneRouter::with_defaults();
    let mut r2 = HybridLaneRouter::with_defaults();
    let obs = LaneObservation {
        lane: LaneChoice::Js,
        latency_us: 4000,
        success: true,
        dom_ops: 40,
        signals_evaluated: 20,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    for _ in 0..50 {
        r1.observe(LaneChoice::Js, &obs, Some(500_000));
        r2.observe(LaneChoice::Js, &obs, Some(500_000));
    }
    assert_eq!(r1.round, r2.round);
    assert_eq!(
        r1.risk.cumulative_regret_millionths,
        r2.risk.cumulative_regret_millionths
    );
    assert_eq!(
        r1.conformal.total_observations,
        r2.conformal.total_observations
    );
}

#[test]
fn deterministic_reward_computation() {
    let obs = LaneObservation {
        lane: LaneChoice::Wasm,
        latency_us: 6000,
        success: true,
        dom_ops: 100,
        signals_evaluated: 50,
        safe_mode_entered: false,
        compatibility_errors: 0,
    };
    let r1 = compute_reward(&obs, 8000);
    let r2 = compute_reward(&obs, 8000);
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// RouterError serde
// ---------------------------------------------------------------------------

#[test]
fn serde_router_error_round_trip() {
    let errors = vec![
        RouterError::AlreadyConservative,
        RouterError::InvalidRandomDraw { value: -1 },
        RouterError::InvalidConfig {
            reason: "bad threshold".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: RouterError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn risk_accumulator_latency_buffer_bounded() {
    let mut acc = RiskAccumulator::new();
    for i in 0..2000 {
        let obs = LaneObservation {
            lane: LaneChoice::Js,
            latency_us: i,
            success: true,
            dom_ops: 0,
            signals_evaluated: 0,
            safe_mode_entered: false,
            compatibility_errors: 0,
        };
        acc.record(&obs, 0);
    }
    assert!(acc.latencies_us.len() <= 1000);
}

#[test]
fn routing_decision_trace_derive_id_deterministic() {
    let trace = RoutingDecisionTrace {
        round: 1,
        policy: RoutingPolicy::Conservative,
        chosen_lane: LaneChoice::Js,
        rejected_lanes: vec![LaneChoice::Wasm],
        probabilities_millionths: vec![500_000, 500_000],
        random_draw_millionths: None,
        reward_millionths: Some(700_000),
        cumulative_regret_millionths: 0,
        p99_latency_us: 1000,
        compatibility_errors: 0,
        conformal_coverage_millionths: 1_000_000,
        cusum_stat_millionths: 0,
        demotion_reason: None,
    };
    let id1 = trace.derive_id();
    let id2 = trace.derive_id();
    assert_eq!(id1, id2);
}
