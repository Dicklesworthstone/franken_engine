#![forbid(unsafe_code)]
//! Integration tests for the `regret_bounded_router` module.
//!
//! Exercises EXP3/FTRL algorithms, regret-bounded routing, arm selection,
//! reward observation, regime detection, regret certificates, and serde
//! round-trips from outside the crate boundary.

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

use frankenengine_engine::regret_bounded_router::{
    Exp3State, FtrlState, LaneArm, ROUTING_SCHEMA_VERSION, RegimeKind, RegimeTransition,
    RegretBoundedRouter, RegretCertificate, RewardSignal, RouterError, RouterSummary,
    RoutingDecisionReceipt,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn make_arms(n: usize) -> Vec<LaneArm> {
    (0..n)
        .map(|i| LaneArm {
            lane_id: format!("lane_{i}"),
            description: format!("Lane {i}"),
        })
        .collect()
}

fn make_signal(arm: usize, reward: i64, round: u64) -> RewardSignal {
    RewardSignal {
        arm_index: arm,
        reward_millionths: reward,
        latency_us: 100,
        success: true,
        epoch: SecurityEpoch::from_raw(round),
        counterfactual_rewards_millionths: None,
    }
}

fn make_signal_full_info(arm: usize, rewards: Vec<i64>, round: u64) -> RewardSignal {
    RewardSignal {
        arm_index: arm,
        reward_millionths: rewards[arm],
        latency_us: 100,
        success: true,
        epoch: SecurityEpoch::from_raw(round),
        counterfactual_rewards_millionths: Some(rewards),
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!ROUTING_SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// 2. LaneArm — serde
// ===========================================================================

#[test]
fn lane_arm_serde_round_trip() {
    let arm = LaneArm {
        lane_id: "test_lane".into(),
        description: "Test Lane".into(),
    };
    let json = serde_json::to_string(&arm).unwrap();
    let back: LaneArm = serde_json::from_str(&json).unwrap();
    assert_eq!(back, arm);
}

// ===========================================================================
// 3. RegimeKind — ordering, serde
// ===========================================================================

#[test]
fn regime_kind_ordering() {
    assert!(RegimeKind::Unknown < RegimeKind::Stochastic);
    assert!(RegimeKind::Stochastic < RegimeKind::Adversarial);
}

#[test]
fn regime_kind_serde_round_trip() {
    for k in [
        RegimeKind::Unknown,
        RegimeKind::Stochastic,
        RegimeKind::Adversarial,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: RegimeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

// ===========================================================================
// 4. RouterError — serde
// ===========================================================================

#[test]
fn router_error_variants_display() {
    let errors = vec![
        RouterError::NoArms,
        RouterError::TooManyArms { count: 20, max: 16 },
        RouterError::ArmOutOfBounds { index: 5, count: 3 },
        RouterError::RewardOutOfRange { reward: -1 },
        RouterError::InvalidGamma {
            gamma_millionths: 0,
        },
        RouterError::CounterfactualSizeMismatch {
            got: 2,
            expected: 3,
        },
        RouterError::ZeroWeight,
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn router_error_serde_round_trip() {
    let err = RouterError::ArmOutOfBounds { index: 5, count: 3 };
    let json = serde_json::to_string(&err).unwrap();
    let back: RouterError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 5. Exp3State — creation, arm selection
// ===========================================================================

#[test]
fn exp3_new() {
    let exp3 = Exp3State::new(3, 100_000).unwrap();
    assert_eq!(exp3.num_arms, 3);
    assert_eq!(exp3.rounds, 0);
}

#[test]
fn exp3_arm_probabilities_sum_to_million() {
    let exp3 = Exp3State::new(4, 200_000).unwrap();
    let probs = exp3.arm_probabilities();
    assert_eq!(probs.len(), 4);
    let sum: i64 = probs.iter().sum();
    // Should sum to exactly 1_000_000
    assert_eq!(sum, 1_000_000);
}

#[test]
fn exp3_select_arm_deterministic() {
    let exp3 = Exp3State::new(3, 100_000).unwrap();
    let a1 = exp3.select_arm(300_000);
    let a2 = exp3.select_arm(300_000);
    assert_eq!(a1, a2);
}

#[test]
fn exp3_update_and_round_count() {
    let mut exp3 = Exp3State::new(3, 100_000).unwrap();
    exp3.update(0, 500_000).unwrap();
    assert_eq!(exp3.rounds, 1);
    exp3.update(1, 700_000).unwrap();
    assert_eq!(exp3.rounds, 2);
}

#[test]
fn exp3_regret_bound() {
    let mut exp3 = Exp3State::new(3, 100_000).unwrap();
    for _ in 0..10 {
        exp3.update(0, 500_000).unwrap();
    }
    let bound = exp3.regret_bound_millionths();
    assert!(bound > 0);
}

#[test]
fn exp3_serde_round_trip() {
    let exp3 = Exp3State::new(3, 100_000).unwrap();
    let json = serde_json::to_string(&exp3).unwrap();
    let back: Exp3State = serde_json::from_str(&json).unwrap();
    assert_eq!(back, exp3);
}

// ===========================================================================
// 6. FtrlState — creation, mean rewards
// ===========================================================================

#[test]
fn ftrl_new() {
    let ftrl = FtrlState::new(3).unwrap();
    assert_eq!(ftrl.num_arms, 3);
    assert_eq!(ftrl.rounds, 0);
}

#[test]
fn ftrl_arm_probabilities_sum_to_million() {
    let ftrl = FtrlState::new(4).unwrap();
    let probs = ftrl.arm_probabilities();
    assert_eq!(probs.len(), 4);
    let sum: i64 = probs.iter().sum();
    assert_eq!(sum, 1_000_000);
}

#[test]
fn ftrl_update_tracks_mean_rewards() {
    let mut ftrl = FtrlState::new(2).unwrap();
    ftrl.update(0, 800_000).unwrap();
    ftrl.update(0, 600_000).unwrap();
    ftrl.update(1, 200_000).unwrap();
    let means = ftrl.mean_rewards();
    // Arm 0: mean of 800k and 600k = 700k; Arm 1: 200k
    assert!(means[0] > means[1]);
}

#[test]
fn ftrl_serde_round_trip() {
    let ftrl = FtrlState::new(3).unwrap();
    let json = serde_json::to_string(&ftrl).unwrap();
    let back: FtrlState = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ftrl);
}

// ===========================================================================
// 7. RegretBoundedRouter — creation, errors
// ===========================================================================

#[test]
fn router_new_valid() {
    let router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    assert_eq!(router.num_arms(), 3);
    assert_eq!(router.rounds(), 0);
}

#[test]
fn router_new_no_arms_error() {
    let err = RegretBoundedRouter::new(vec![], 100_000).unwrap_err();
    assert!(matches!(err, RouterError::NoArms));
}

#[test]
fn router_new_too_many_arms_error() {
    let err = RegretBoundedRouter::new(make_arms(20), 100_000).unwrap_err();
    assert!(matches!(err, RouterError::TooManyArms { .. }));
}

#[test]
fn router_new_invalid_gamma_error() {
    let err = RegretBoundedRouter::new(make_arms(3), 0).unwrap_err();
    assert!(matches!(err, RouterError::InvalidGamma { .. }));
}

// ===========================================================================
// 8. Router — arm selection
// ===========================================================================

#[test]
fn router_select_arm_in_range() {
    let router = RegretBoundedRouter::new(make_arms(4), 100_000).unwrap();
    for seed in [0, 250_000, 500_000, 750_000, 999_999] {
        let arm = router.select_arm(seed);
        assert!(arm < 4, "arm {} out of range for seed {}", arm, seed);
    }
}

// ===========================================================================
// 9. Router — observe_reward
// ===========================================================================

#[test]
fn router_observe_reward_returns_receipt() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    let signal = make_signal(0, 500_000, 1);
    let receipt = router.observe_reward(&signal).unwrap();
    assert_eq!(receipt.round, 1);
    assert_eq!(receipt.arm_selected, 0);
    assert_eq!(receipt.reward_millionths, 500_000);
    assert_eq!(receipt.schema, ROUTING_SCHEMA_VERSION);
}

#[test]
fn router_observe_reward_invalid_arm_error() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    let signal = make_signal(5, 500_000, 1);
    let err = router.observe_reward(&signal).unwrap_err();
    assert!(matches!(err, RouterError::ArmOutOfBounds { .. }));
    // State should be unchanged (transactional)
    assert_eq!(router.rounds(), 0);
}

#[test]
fn router_observe_reward_invalid_reward_error() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    let signal = make_signal(0, -1, 1);
    let err = router.observe_reward(&signal).unwrap_err();
    assert!(matches!(err, RouterError::RewardOutOfRange { .. }));
}

#[test]
fn router_observe_reward_counterfactual_mismatch() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    let signal = RewardSignal {
        arm_index: 0,
        reward_millionths: 500_000,
        latency_us: 100,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: Some(vec![500_000, 600_000]), // 2 not 3
    };
    let err = router.observe_reward(&signal).unwrap_err();
    assert!(matches!(
        err,
        RouterError::CounterfactualSizeMismatch { .. }
    ));
}

// ===========================================================================
// 10. Router — multiple rounds
// ===========================================================================

#[test]
fn router_multiple_rounds_accumulate() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    for i in 0..20 {
        let arm = router.select_arm((i * 50_000) % 1_000_000);
        let signal = make_signal(arm, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    assert_eq!(router.rounds(), 20);
    assert!(router.cumulative_reward_millionths > 0);
}

// ===========================================================================
// 11. Router — full information (counterfactual) regret
// ===========================================================================

#[test]
fn router_exact_regret_with_counterfactuals() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 200_000).unwrap();
    // Always play arm 0, but arm 1 is always better
    for i in 0..20 {
        let signal = make_signal_full_info(0, vec![300_000, 800_000], i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    assert!(router.exact_regret_available());
    let regret = router.realized_regret_millionths();
    // Regret should be positive since arm 1 was consistently better
    assert!(regret > 0, "regret should be positive: {}", regret);
}

// ===========================================================================
// 12. Router — summary
// ===========================================================================

#[test]
fn router_summary_structure() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    for i in 0..5 {
        let signal = make_signal(i % 3, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let summary = router.summary();
    assert_eq!(summary.num_arms, 3);
    assert_eq!(summary.rounds, 5);
    assert_eq!(summary.arm_probabilities_millionths.len(), 3);
    let sum: i64 = summary.arm_probabilities_millionths.iter().sum();
    assert_eq!(sum, 1_000_000);
    assert_eq!(summary.schema, ROUTING_SCHEMA_VERSION);
}

#[test]
fn router_summary_serde_round_trip() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    for i in 0..5 {
        let signal = make_signal(i % 3, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let summary = router.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: RouterSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

// ===========================================================================
// 13. Router — regret certificate
// ===========================================================================

#[test]
fn router_regret_certificate() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    for i in 0..10 {
        let signal = make_signal(i % 3, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let cert = router.regret_certificate();
    assert_eq!(cert.rounds, 10);
    assert!(!cert.growth_rate_class.is_empty());
    assert_eq!(cert.schema, ROUTING_SCHEMA_VERSION);
}

#[test]
fn regret_certificate_serde_round_trip() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    for i in 0..10 {
        let signal = make_signal(i % 3, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let cert = router.regret_certificate();
    let json = serde_json::to_string(&cert).unwrap();
    let back: RegretCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cert);
}

// ===========================================================================
// 14. RegimeTransition — serde
// ===========================================================================

#[test]
fn regime_transition_serde_round_trip() {
    let rt = RegimeTransition {
        round: 50,
        from: RegimeKind::Unknown,
        to: RegimeKind::Stochastic,
        confidence_millionths: 850_000,
    };
    let json = serde_json::to_string(&rt).unwrap();
    let back: RegimeTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rt);
}

// ===========================================================================
// 15. RoutingDecisionReceipt — serde
// ===========================================================================

#[test]
fn routing_receipt_serde_round_trip() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();
    let signal = make_signal(0, 500_000, 1);
    let receipt = router.observe_reward(&signal).unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: RoutingDecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

// ===========================================================================
// 16. Router — serde round-trip
// ===========================================================================

#[test]
fn router_serde_round_trip() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    for i in 0..5 {
        let signal = make_signal(i % 3, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let json = serde_json::to_string(&router).unwrap();
    let back: RegretBoundedRouter = serde_json::from_str(&json).unwrap();
    assert_eq!(back, router);
}

// ===========================================================================
// 17. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_regret_bounded_router() {
    // 1. Create router with 3 arms
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    assert_eq!(router.num_arms(), 3);
    assert_eq!(router.active_regime, RegimeKind::Unknown);

    // 2. Run 30 rounds with full information
    for i in 0..30 {
        let arm = router.select_arm((i * 33_000) % 1_000_000);
        let rewards = vec![300_000, 700_000, 500_000]; // arm 1 is best
        let signal = make_signal_full_info(arm, rewards, i as u64 + 1);
        let receipt = router.observe_reward(&signal).unwrap();
        assert_eq!(receipt.round, i as u64 + 1);
    }
    assert_eq!(router.rounds(), 30);

    // 3. Check summary
    let summary = router.summary();
    assert_eq!(summary.num_arms, 3);
    assert_eq!(summary.rounds, 30);
    assert_eq!(summary.arm_probabilities_millionths.len(), 3);

    // 4. Check regret certificate
    let cert = router.regret_certificate();
    assert_eq!(cert.rounds, 30);
    assert!(router.exact_regret_available());

    // 5. Regret bound should be positive
    let bound = router.regret_bound_millionths();
    assert!(bound > 0);

    // 6. Serde round-trip
    let json = serde_json::to_string(&router).unwrap();
    let back: RegretBoundedRouter = serde_json::from_str(&json).unwrap();
    assert_eq!(back.rounds(), router.rounds());
    assert_eq!(back.summary(), router.summary());
}
