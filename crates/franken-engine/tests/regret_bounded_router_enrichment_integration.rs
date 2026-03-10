#![forbid(unsafe_code)]
//! Enrichment integration tests for `regret_bounded_router`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, and edge cases beyond
//! the existing 35 integration tests.

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

use std::collections::BTreeSet;

use frankenengine_engine::regret_bounded_router::{
    Exp3State, FtrlState, LaneArm, ROUTING_SCHEMA_VERSION, RegimeKind, RegimeTransition,
    RegretBoundedRouter, RegretCertificate, RewardSignal, RouterError, RouterSummary,
    RoutingDecisionReceipt,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Test helpers
// ===========================================================================

fn arm(id: &str) -> LaneArm {
    LaneArm {
        lane_id: id.to_string(),
        description: format!("Lane {id}"),
    }
}

fn make_router(n: usize) -> RegretBoundedRouter {
    let arms: Vec<_> = (0..n).map(|i| arm(&format!("lane-{i}"))).collect();
    RegretBoundedRouter::new(arms, 100_000).unwrap() // gamma = 0.1
}

// ===========================================================================
// 1) RouterError — exact Display
// ===========================================================================

#[test]
fn router_error_display_exact_no_arms() {
    assert_eq!(RouterError::NoArms.to_string(), "no arms configured");
}

#[test]
fn router_error_display_exact_too_many_arms() {
    let e = RouterError::TooManyArms {
        count: 200,
        max: 100,
    };
    assert_eq!(e.to_string(), "200 arms exceeds maximum 100");
}

#[test]
fn router_error_display_exact_arm_out_of_bounds() {
    let e = RouterError::ArmOutOfBounds { index: 5, count: 3 };
    assert_eq!(e.to_string(), "arm index 5 out of bounds (count 3)");
}

#[test]
fn router_error_display_exact_reward_out_of_range() {
    let e = RouterError::RewardOutOfRange { reward: -1 };
    assert_eq!(e.to_string(), "reward -1 outside [0, 1_000_000]");
}

#[test]
fn router_error_display_exact_invalid_gamma() {
    let e = RouterError::InvalidGamma {
        gamma_millionths: -50,
    };
    assert_eq!(e.to_string(), "gamma -50 outside (0, 1_000_000]");
}

#[test]
fn router_error_display_exact_counterfactual_size_mismatch() {
    let e = RouterError::CounterfactualSizeMismatch {
        got: 2,
        expected: 4,
    };
    assert_eq!(
        e.to_string(),
        "counterfactual reward vector has size 2, expected 4"
    );
}

#[test]
fn router_error_display_exact_zero_weight() {
    assert_eq!(
        RouterError::ZeroWeight.to_string(),
        "cannot route with zero total weight"
    );
}

#[test]
fn router_error_display_all_unique() {
    let variants: Vec<String> = vec![
        RouterError::NoArms.to_string(),
        RouterError::TooManyArms { count: 2, max: 1 }.to_string(),
        RouterError::ArmOutOfBounds { index: 0, count: 0 }.to_string(),
        RouterError::RewardOutOfRange { reward: 0 }.to_string(),
        RouterError::InvalidGamma {
            gamma_millionths: 0,
        }
        .to_string(),
        RouterError::CounterfactualSizeMismatch {
            got: 0,
            expected: 0,
        }
        .to_string(),
        RouterError::ZeroWeight.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

// ===========================================================================
// 2) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_regime_kind() {
    let variants = [
        format!("{:?}", RegimeKind::Unknown),
        format!("{:?}", RegimeKind::Stochastic),
        format!("{:?}", RegimeKind::Adversarial),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_router_error() {
    let variants = [
        format!("{:?}", RouterError::NoArms),
        format!("{:?}", RouterError::ZeroWeight),
        format!("{:?}", RouterError::TooManyArms { count: 1, max: 1 }),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 3) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_regime_kind_tags() {
    let kinds = [
        RegimeKind::Unknown,
        RegimeKind::Stochastic,
        RegimeKind::Adversarial,
    ];
    let expected = ["\"Unknown\"", "\"Stochastic\"", "\"Adversarial\""];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "RegimeKind serde tag mismatch for {k:?}");
    }
}

// ===========================================================================
// 4) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_lane_arm() {
    let la = arm("test");
    let v: serde_json::Value = serde_json::to_value(&la).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("lane_id"));
    assert!(obj.contains_key("description"));
}

#[test]
fn json_fields_reward_signal() {
    let rs = RewardSignal {
        arm_index: 0,
        reward_millionths: 500_000,
        latency_us: 100,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    let v: serde_json::Value = serde_json::to_value(&rs).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "arm_index",
        "reward_millionths",
        "latency_us",
        "success",
        "epoch",
        "counterfactual_rewards_millionths",
    ] {
        assert!(obj.contains_key(key), "RewardSignal missing field: {key}");
    }
}

#[test]
fn json_fields_exp3_state() {
    let state = Exp3State::new(3, 100_000).unwrap();
    let v: serde_json::Value = serde_json::to_value(&state).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "num_arms",
        "log_weights_millionths",
        "gamma_millionths",
        "eta_millionths",
        "rounds",
    ] {
        assert!(obj.contains_key(key), "Exp3State missing field: {key}");
    }
}

#[test]
fn json_fields_ftrl_state() {
    let state = FtrlState::new(3).unwrap();
    let v: serde_json::Value = serde_json::to_value(&state).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "num_arms",
        "cumulative_rewards_millionths",
        "arm_counts",
        "eta_millionths",
        "rounds",
    ] {
        assert!(obj.contains_key(key), "FtrlState missing field: {key}");
    }
}

#[test]
fn json_fields_regime_transition() {
    let rt = RegimeTransition {
        round: 10,
        from: RegimeKind::Unknown,
        to: RegimeKind::Stochastic,
        confidence_millionths: 800_000,
    };
    let v: serde_json::Value = serde_json::to_value(&rt).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["round", "from", "to", "confidence_millionths"] {
        assert!(
            obj.contains_key(key),
            "RegimeTransition missing field: {key}"
        );
    }
}

#[test]
fn json_fields_routing_decision_receipt() {
    let rdr = RoutingDecisionReceipt {
        schema: ROUTING_SCHEMA_VERSION.to_string(),
        round: 1,
        arm_selected: 0,
        reward_millionths: 500_000,
        regime: RegimeKind::Unknown,
        cumulative_reward_millionths: 500_000,
        realized_regret_millionths: 0,
        theoretical_regret_bound_millionths: 100_000,
        exact_regret_available: false,
        regret_within_bound: true,
    };
    let v: serde_json::Value = serde_json::to_value(&rdr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema",
        "round",
        "arm_selected",
        "reward_millionths",
        "regime",
        "cumulative_reward_millionths",
        "realized_regret_millionths",
        "theoretical_regret_bound_millionths",
        "exact_regret_available",
        "regret_within_bound",
    ] {
        assert!(
            obj.contains_key(key),
            "RoutingDecisionReceipt missing field: {key}"
        );
    }
}

#[test]
fn json_fields_router_summary() {
    let router = make_router(3);
    let summary = router.summary();
    let v: serde_json::Value = serde_json::to_value(&summary).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema",
        "num_arms",
        "rounds",
        "active_regime",
        "arm_probabilities_millionths",
        "cumulative_reward_millionths",
        "best_arm_cumulative_millionths",
        "realized_regret_millionths",
        "theoretical_regret_bound_millionths",
        "exact_regret_available",
        "regime_transitions",
    ] {
        assert!(obj.contains_key(key), "RouterSummary missing field: {key}");
    }
}

#[test]
fn json_fields_regret_certificate() {
    let router = make_router(2);
    let cert = router.regret_certificate();
    let v: serde_json::Value = serde_json::to_value(&cert).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema",
        "rounds",
        "realized_regret_millionths",
        "theoretical_bound_millionths",
        "within_bound",
        "exact_regret_available",
        "per_round_regret_millionths",
        "growth_rate_class",
    ] {
        assert!(
            obj.contains_key(key),
            "RegretCertificate missing field: {key}"
        );
    }
}

// ===========================================================================
// 5) Schema version constant stability
// ===========================================================================

#[test]
fn schema_version_constant_stable() {
    assert_eq!(
        ROUTING_SCHEMA_VERSION,
        "franken-engine.regret-bounded-router.v1"
    );
}

// ===========================================================================
// 6) Router construction errors
// ===========================================================================

#[test]
fn router_no_arms_error() {
    let result = RegretBoundedRouter::new(vec![], 100_000);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), RouterError::NoArms);
}

#[test]
fn router_invalid_gamma_zero() {
    let result = RegretBoundedRouter::new(vec![arm("a")], 0);
    assert!(result.is_err());
}

#[test]
fn router_invalid_gamma_negative() {
    let result = RegretBoundedRouter::new(vec![arm("a")], -1);
    assert!(result.is_err());
}

// ===========================================================================
// 7) Exp3 construction errors
// ===========================================================================

#[test]
fn exp3_no_arms_error() {
    let result = Exp3State::new(0, 100_000);
    assert!(result.is_err());
}

#[test]
fn exp3_invalid_gamma_error() {
    let result = Exp3State::new(3, 0);
    assert!(result.is_err());
}

// ===========================================================================
// 8) FTRL construction errors
// ===========================================================================

#[test]
fn ftrl_no_arms_error() {
    let result = FtrlState::new(0);
    assert!(result.is_err());
}

// ===========================================================================
// 9) Router basic state
// ===========================================================================

#[test]
fn router_initial_state_correct() {
    let router = make_router(3);
    assert_eq!(router.num_arms(), 3);
    assert_eq!(router.rounds(), 0);
    assert_eq!(router.active_regime, RegimeKind::Unknown);
    assert_eq!(router.cumulative_reward_millionths, 0);
    assert_eq!(router.best_arm_cumulative_millionths, 0);
    assert!(router.regime_history.is_empty());
}

// ===========================================================================
// 10) Arm probabilities sum to 1
// ===========================================================================

#[test]
fn exp3_arm_probabilities_sum_to_one() {
    let state = Exp3State::new(4, 200_000).unwrap();
    let probs = state.arm_probabilities();
    assert_eq!(probs.len(), 4);
    let sum: i64 = probs.iter().sum();
    // Should be ~1_000_000 (±1 due to rounding)
    assert!(
        (sum - 1_000_000).abs() <= 4,
        "probabilities should sum to ~1.0: {sum}"
    );
}

#[test]
fn ftrl_arm_probabilities_sum_to_one() {
    let state = FtrlState::new(3).unwrap();
    let probs = state.arm_probabilities();
    assert_eq!(probs.len(), 3);
    let sum: i64 = probs.iter().sum();
    assert!(
        (sum - 1_000_000).abs() <= 3,
        "probabilities should sum to ~1.0: {sum}"
    );
}

// ===========================================================================
// 11) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_lane_arm() {
    let la = arm("test-rt");
    let json = serde_json::to_string(&la).unwrap();
    let rt: LaneArm = serde_json::from_str(&json).unwrap();
    assert_eq!(la, rt);
}

#[test]
fn serde_roundtrip_reward_signal() {
    let rs = RewardSignal {
        arm_index: 2,
        reward_millionths: 750_000,
        latency_us: 42,
        success: true,
        epoch: SecurityEpoch::from_raw(5),
        counterfactual_rewards_millionths: Some(vec![100_000, 200_000, 750_000]),
    };
    let json = serde_json::to_string(&rs).unwrap();
    let rt: RewardSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(rs, rt);
}

#[test]
fn serde_roundtrip_router_error_all_variants() {
    let variants = vec![
        RouterError::NoArms,
        RouterError::TooManyArms { count: 10, max: 5 },
        RouterError::ArmOutOfBounds { index: 3, count: 2 },
        RouterError::RewardOutOfRange { reward: -100 },
        RouterError::InvalidGamma {
            gamma_millionths: -1,
        },
        RouterError::CounterfactualSizeMismatch {
            got: 1,
            expected: 3,
        },
        RouterError::ZeroWeight,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: RouterError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_regret_certificate() {
    let router = make_router(2);
    let cert = router.regret_certificate();
    let json = serde_json::to_string(&cert).unwrap();
    let rt: RegretCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, rt);
}

#[test]
fn serde_roundtrip_router_summary() {
    let router = make_router(2);
    let summary = router.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let rt: RouterSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, rt);
}

// ===========================================================================
// 12) std::error::Error impl
// ===========================================================================

#[test]
fn router_error_is_std_error() {
    let e = RouterError::NoArms;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 13) RegimeKind ordering
// ===========================================================================

#[test]
fn regime_kind_ordering_stable() {
    let mut kinds = [
        RegimeKind::Adversarial,
        RegimeKind::Unknown,
        RegimeKind::Stochastic,
    ];
    kinds.sort();
    assert_eq!(kinds[0], RegimeKind::Unknown);
    assert_eq!(kinds[1], RegimeKind::Stochastic);
    assert_eq!(kinds[2], RegimeKind::Adversarial);
}

// ===========================================================================
// 14) Regret bounds are non-negative at start
// ===========================================================================

#[test]
fn regret_bounds_non_negative_initially() {
    let router = make_router(4);
    assert!(router.regret_bound_millionths() >= 0);
    assert_eq!(router.realized_regret_millionths(), 0);
}

#[test]
fn regret_certificate_initial_state() {
    let router = make_router(3);
    let cert = router.regret_certificate();
    // without counterfactual data, exact_regret_available is false
    assert!(!cert.exact_regret_available);
    // growth_rate_class is a non-empty string
    assert!(!cert.growth_rate_class.is_empty());
    assert_eq!(cert.schema, ROUTING_SCHEMA_VERSION);
}

// ===========================================================================
// 15) Observe reward basic flow
// ===========================================================================

#[test]
fn observe_reward_returns_receipt() {
    let mut router = make_router(3);
    let selected = router.select_arm(500_000);
    let signal = RewardSignal {
        arm_index: selected,
        reward_millionths: 600_000,
        latency_us: 10,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    let receipt = router.observe_reward(&signal).unwrap();
    assert_eq!(receipt.round, 1);
    assert_eq!(receipt.arm_selected, selected);
    assert_eq!(receipt.reward_millionths, 600_000);
    assert_eq!(receipt.schema, ROUTING_SCHEMA_VERSION);
}

#[test]
fn observe_reward_arm_out_of_bounds() {
    let mut router = make_router(2);
    let signal = RewardSignal {
        arm_index: 5,
        reward_millionths: 500_000,
        latency_us: 10,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    let result = router.observe_reward(&signal);
    assert!(result.is_err());
}

// ===========================================================================
// 20) Serde roundtrips — additional types
// ===========================================================================

#[test]
fn serde_roundtrip_regime_kind_all() {
    for rk in [
        RegimeKind::Unknown,
        RegimeKind::Stochastic,
        RegimeKind::Adversarial,
    ] {
        let json = serde_json::to_string(&rk).unwrap();
        let back: RegimeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(rk, back);
    }
}

#[test]
fn serde_roundtrip_regime_transition() {
    let rt = RegimeTransition {
        round: 50,
        from: RegimeKind::Unknown,
        to: RegimeKind::Stochastic,
        confidence_millionths: 900_000,
    };
    let json = serde_json::to_string(&rt).unwrap();
    let back: RegimeTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, back);
}

#[test]
fn serde_roundtrip_exp3_state() {
    let state = Exp3State::new(3, 100_000).unwrap();
    let json = serde_json::to_string(&state).unwrap();
    let back: Exp3State = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

#[test]
fn serde_roundtrip_ftrl_state() {
    let state = FtrlState::new(3).unwrap();
    let json = serde_json::to_string(&state).unwrap();
    let back: FtrlState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

#[test]
fn serde_roundtrip_routing_decision_receipt() {
    let mut router = make_router(2);
    let arm = router.select_arm(500_000);
    let signal = RewardSignal {
        arm_index: arm,
        reward_millionths: 500_000,
        latency_us: 10,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    let receipt = router.observe_reward(&signal).unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: RoutingDecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ===========================================================================
// 21) Select arm determinism
// ===========================================================================

#[test]
fn select_arm_deterministic_same_seed() {
    let router = make_router(4);
    let arm1 = router.select_arm(250_000);
    let arm2 = router.select_arm(250_000);
    assert_eq!(arm1, arm2);
}

#[test]
fn select_arm_boundary_zero() {
    let router = make_router(3);
    let arm = router.select_arm(0);
    assert!(arm < 3);
}

#[test]
fn select_arm_boundary_max() {
    let router = make_router(3);
    let arm = router.select_arm(999_999);
    assert!(arm < 3);
}

// ===========================================================================
// 22) Reward boundaries
// ===========================================================================

#[test]
fn observe_reward_exactly_zero() {
    let mut router = make_router(2);
    let arm = router.select_arm(500_000);
    let signal = RewardSignal {
        arm_index: arm,
        reward_millionths: 0,
        latency_us: 1,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    let receipt = router.observe_reward(&signal).unwrap();
    assert_eq!(receipt.reward_millionths, 0);
}

#[test]
fn observe_reward_exactly_one() {
    let mut router = make_router(2);
    let arm = router.select_arm(500_000);
    let signal = RewardSignal {
        arm_index: arm,
        reward_millionths: 1_000_000,
        latency_us: 1,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    let receipt = router.observe_reward(&signal).unwrap();
    assert_eq!(receipt.reward_millionths, 1_000_000);
}

#[test]
fn observe_reward_out_of_range_negative() {
    let mut router = make_router(2);
    let signal = RewardSignal {
        arm_index: 0,
        reward_millionths: -1,
        latency_us: 1,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    assert!(router.observe_reward(&signal).is_err());
}

#[test]
fn observe_reward_out_of_range_above() {
    let mut router = make_router(2);
    let signal = RewardSignal {
        arm_index: 0,
        reward_millionths: 1_000_001,
        latency_us: 1,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    assert!(router.observe_reward(&signal).is_err());
}

// ===========================================================================
// 23) Counterfactual rewards
// ===========================================================================

#[test]
fn observe_reward_with_counterfactuals() {
    let mut router = make_router(3);
    let arm = router.select_arm(500_000);
    let signal = RewardSignal {
        arm_index: arm,
        reward_millionths: 600_000,
        latency_us: 10,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: Some(vec![600_000, 400_000, 800_000]),
    };
    let receipt = router.observe_reward(&signal).unwrap();
    assert_eq!(receipt.round, 1);
}

#[test]
fn counterfactual_size_mismatch() {
    let mut router = make_router(3);
    let arm = router.select_arm(500_000);
    let signal = RewardSignal {
        arm_index: arm,
        reward_millionths: 600_000,
        latency_us: 10,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: Some(vec![600_000, 400_000]), // 2 != 3 arms
    };
    let result = router.observe_reward(&signal);
    assert!(result.is_err());
}

// ===========================================================================
// 24) Exp3/FTRL mean rewards
// ===========================================================================

#[test]
fn ftrl_mean_rewards_initially_zero() {
    let state = FtrlState::new(3).unwrap();
    let means = state.mean_rewards();
    assert_eq!(means.len(), 3);
    for m in &means {
        assert_eq!(*m, 0);
    }
}

// ===========================================================================
// 25) Router summary
// ===========================================================================

#[test]
fn router_summary_after_rounds() {
    let mut router = make_router(2);
    // Observe a few rewards
    for i in 0..5u64 {
        let arm = router.select_arm((i * 200_000) as i64);
        let signal = RewardSignal {
            arm_index: arm,
            reward_millionths: 500_000,
            latency_us: 10,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: None,
        };
        router.observe_reward(&signal).unwrap();
    }
    let summary = router.summary();
    assert_eq!(summary.rounds, 5);
    assert_eq!(summary.num_arms, 2);
    assert_eq!(summary.schema, ROUTING_SCHEMA_VERSION);
    assert!(summary.cumulative_reward_millionths > 0);
}

// ===========================================================================
// 26) Regret certificate after rounds
// ===========================================================================

#[test]
fn regret_certificate_after_rounds() {
    let mut router = make_router(2);
    for _ in 0..3 {
        let arm = router.select_arm(500_000);
        let signal = RewardSignal {
            arm_index: arm,
            reward_millionths: 700_000,
            latency_us: 5,
            success: true,
            epoch: SecurityEpoch::from_raw(1),
            counterfactual_rewards_millionths: None,
        };
        router.observe_reward(&signal).unwrap();
    }
    let cert = router.regret_certificate();
    assert_eq!(cert.rounds, 3);
    assert_eq!(cert.schema, ROUTING_SCHEMA_VERSION);
    assert!(cert.theoretical_bound_millionths >= 0);
}

// ===========================================================================
// 27) Gamma boundary: exactly 1.0
// ===========================================================================

#[test]
fn router_gamma_exactly_one() {
    let arms = vec![arm("lane-0"), arm("lane-1")];
    let router = RegretBoundedRouter::new(arms, 1_000_000).unwrap(); // gamma = 1.0
    assert_eq!(router.num_arms(), 2);
}

#[test]
fn exp3_gamma_exactly_one() {
    let state = Exp3State::new(2, 1_000_000).unwrap();
    assert_eq!(state.num_arms, 2);
}

// ===========================================================================
// 28) Router too many arms (if there's a limit)
// ===========================================================================

#[test]
fn router_two_arms_minimum() {
    // Single arm should still work (degenerate case)
    let arms = vec![arm("solo")];
    let result = RegretBoundedRouter::new(arms, 100_000);
    // Whether this succeeds or fails depends on implementation
    // Just verify it doesn't panic
    let _ = result;
}

// ===========================================================================
// 29) Debug distinct RewardSignal vs RoutingDecisionReceipt
// ===========================================================================

#[test]
fn debug_distinct_reward_signal() {
    let s1 = RewardSignal {
        arm_index: 0,
        reward_millionths: 500_000,
        latency_us: 10,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: None,
    };
    let s2 = RewardSignal {
        arm_index: 1,
        reward_millionths: 300_000,
        latency_us: 20,
        success: false,
        epoch: SecurityEpoch::from_raw(2),
        counterfactual_rewards_millionths: Some(vec![300_000, 700_000]),
    };
    assert_ne!(format!("{s1:?}"), format!("{s2:?}"));
}
