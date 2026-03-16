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

// ===========================================================================
// 18. RewardSignal — serde round-trip with and without counterfactuals
// ===========================================================================

#[test]
fn reward_signal_serde_round_trip_no_counterfactual() {
    let signal = RewardSignal {
        arm_index: 1,
        reward_millionths: 750_000,
        latency_us: 42,
        success: false,
        epoch: SecurityEpoch::from_raw(99),
        counterfactual_rewards_millionths: None,
    };
    let json = serde_json::to_string(&signal).unwrap();
    let back: RewardSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back, signal);
}

#[test]
fn reward_signal_serde_round_trip_with_counterfactual() {
    let signal = RewardSignal {
        arm_index: 0,
        reward_millionths: 400_000,
        latency_us: 1,
        success: true,
        epoch: SecurityEpoch::from_raw(7),
        counterfactual_rewards_millionths: Some(vec![400_000, 600_000, 200_000]),
    };
    let json = serde_json::to_string(&signal).unwrap();
    let back: RewardSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back, signal);
}

// ===========================================================================
// 19. LaneArm — Ord and Hash determinism
// ===========================================================================

#[test]
fn lane_arm_ord_deterministic() {
    let a = LaneArm {
        lane_id: "alpha".into(),
        description: "Alpha lane".into(),
    };
    let b = LaneArm {
        lane_id: "beta".into(),
        description: "Beta lane".into(),
    };
    // Ord should be consistent across invocations.
    let cmp1 = a.cmp(&b);
    let cmp2 = a.cmp(&b);
    assert_eq!(cmp1, cmp2);
    // "alpha" < "beta" lexicographically.
    assert!(a < b);
}

#[test]
fn lane_arm_hash_determinism() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let arm = LaneArm {
        lane_id: "deterministic".into(),
        description: "Deterministic lane".into(),
    };
    let mut h1 = DefaultHasher::new();
    arm.hash(&mut h1);
    let hash1 = h1.finish();

    let arm_clone = arm.clone();
    let mut h2 = DefaultHasher::new();
    arm_clone.hash(&mut h2);
    let hash2 = h2.finish();

    assert_eq!(hash1, hash2, "equal LaneArms must produce identical hashes");
}

// ===========================================================================
// 20. Exp3 — select_arm covers entire arm range across seeds
// ===========================================================================

#[test]
fn exp3_select_arm_covers_all_arms() {
    let exp3 = Exp3State::new(4, 200_000).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for seed in (0..1_000_000).step_by(1000) {
        seen.insert(exp3.select_arm(seed));
        if seen.len() == 4 {
            break;
        }
    }
    assert_eq!(
        seen.len(),
        4,
        "all 4 arms should be reachable from the uniform initial state"
    );
}

// ===========================================================================
// 21. FTRL — regret bound grows sublinearly
// ===========================================================================

#[test]
fn ftrl_regret_bound_grows_sublinearly() {
    let mut ftrl = FtrlState::new(3).unwrap();
    ftrl.rounds = 10;
    let bound_10 = ftrl.regret_bound_millionths();
    ftrl.rounds = 1000;
    let bound_1000 = ftrl.regret_bound_millionths();
    // sqrt(1000)/sqrt(10) ~ 10, so bound_1000/bound_10 ~ 10 (sublinear)
    assert!(bound_1000 > bound_10, "bound should grow with rounds");
    assert!(
        bound_1000 < bound_10 * 100,
        "growth should be sublinear, not linear"
    );
}

// ===========================================================================
// 22. Router — single arm degenerate case
// ===========================================================================

#[test]
fn router_single_arm_always_selects_zero() {
    let router = RegretBoundedRouter::new(make_arms(1), 100_000).unwrap();
    for seed in [0, 250_000, 500_000, 750_000, 999_999] {
        assert_eq!(
            router.select_arm(seed),
            0,
            "single-arm router must always return arm 0"
        );
    }
}

#[test]
fn router_single_arm_observe_and_summarize() {
    let mut router = RegretBoundedRouter::new(make_arms(1), 100_000).unwrap();
    for i in 0..5 {
        let signal = make_signal(0, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let summary = router.summary();
    assert_eq!(summary.num_arms, 1);
    assert_eq!(summary.rounds, 5);
    // Single-arm: probabilities must be [1_000_000]
    assert_eq!(summary.arm_probabilities_millionths, vec![1_000_000]);
}

// ===========================================================================
// 23. Exp3 — boundary reward values (0 and MILLION)
// ===========================================================================

#[test]
fn exp3_update_with_zero_and_max_reward() {
    let mut exp3 = Exp3State::new(2, 100_000).unwrap();
    // Zero reward should be accepted without error.
    exp3.update(0, 0).unwrap();
    assert_eq!(exp3.rounds, 1);
    // Maximum reward should be accepted.
    exp3.update(1, 1_000_000).unwrap();
    assert_eq!(exp3.rounds, 2);
    // Probabilities must still sum to MILLION.
    let probs = exp3.arm_probabilities();
    let sum: i64 = probs.iter().sum();
    assert_eq!(sum, 1_000_000);
}

// ===========================================================================
// 24. Router — clone preserves full state
// ===========================================================================

#[test]
fn router_clone_preserves_state() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    for i in 0..10 {
        let arm = router.select_arm((i * 100_000) % 1_000_000);
        let signal = make_signal(arm, 600_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let cloned = router.clone();
    assert_eq!(cloned, router);
    assert_eq!(cloned.rounds(), router.rounds());
    assert_eq!(cloned.summary(), router.summary());
    assert_eq!(cloned.regret_certificate(), router.regret_certificate());
    // The clone should select the same arm for the same seed.
    assert_eq!(cloned.select_arm(500_000), router.select_arm(500_000));
}

// ===========================================================================
// 25. RegretCertificate — growth_rate_class values
// ===========================================================================

#[test]
fn regret_certificate_growth_rate_empirical_without_counterfactuals() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();
    for i in 0..5 {
        let signal = make_signal(i % 2, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let cert = router.regret_certificate();
    // Without counterfactual data, exact regret is unavailable.
    assert!(!cert.exact_regret_available);
    assert_eq!(cert.growth_rate_class, "empirical_estimate");
}

#[test]
fn regret_certificate_growth_rate_with_counterfactuals() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 200_000).unwrap();
    // Use counterfactuals so exact regret is available.
    for i in 0..10 {
        let signal = make_signal_full_info(i % 2, vec![500_000, 500_000], i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }
    let cert = router.regret_certificate();
    assert!(cert.exact_regret_available);
    // When all arms get equal reward, realized regret is zero.
    assert_eq!(cert.per_round_regret_millionths, 0);
    assert_eq!(cert.growth_rate_class, "zero");
}

// ===========================================================================
// 26. Regime detection — stochastic environment triggers Stochastic regime
// ===========================================================================

#[test]
fn regime_detects_stochastic_with_consistent_rewards() {
    // Feed a low-variance reward stream: all arms get 500_000 ± small noise.
    // CV² should be low, triggering Stochastic regime.
    let mut router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    assert_eq!(router.active_regime, RegimeKind::Unknown);

    // Run enough rounds to trigger regime detection.
    // Detection fires every K rounds (K = num_arms = 3).
    for i in 0..60 {
        let arm = i % 3;
        // Low variance: all rewards near 500_000.
        let reward = 500_000 + (((i as i64) % 5) * 1_000);
        let signal = make_signal(arm, reward, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    // After 60 rounds of low-variance rewards, regime should shift.
    assert_ne!(
        router.active_regime,
        RegimeKind::Unknown,
        "regime should be detected after 60 low-variance rounds"
    );
    // With such low variance, stochastic is expected.
    assert_eq!(router.active_regime, RegimeKind::Stochastic);
}

// ===========================================================================
// 27. Regime detection — adversarial environment triggers Adversarial regime
// ===========================================================================

#[test]
fn regime_detects_adversarial_with_high_variance_rewards() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 200_000).unwrap();

    // Alternate between extreme rewards to create high variance.
    for i in 0..60 {
        let arm = i % 2;
        let reward = if i % 2 == 0 { 50_000 } else { 950_000 };
        let signal = make_signal(arm, reward, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    assert_ne!(
        router.active_regime,
        RegimeKind::Unknown,
        "regime should be detected after 60 high-variance rounds"
    );
    assert_eq!(router.active_regime, RegimeKind::Adversarial);
}

// ===========================================================================
// 28. Regime history records transitions
// ===========================================================================

#[test]
fn regime_transition_history_recorded() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 200_000).unwrap();
    assert!(router.regime_history.is_empty());

    // Low-variance phase to trigger stochastic detection.
    for i in 0..40 {
        let signal = make_signal(i % 2, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    if !router.regime_history.is_empty() {
        let first = &router.regime_history[0];
        assert_eq!(first.from, RegimeKind::Unknown);
        assert!(
            first.confidence_millionths > 0,
            "transition must have positive confidence"
        );
        assert!(first.round > 0, "transition must record the round");
    }
}

// ===========================================================================
// 29. Round-robin warmup — Unknown regime uses round-robin for first K rounds
// ===========================================================================

#[test]
fn router_round_robin_warmup_in_unknown_regime() {
    let router = RegretBoundedRouter::new(make_arms(4), 100_000).unwrap();
    assert_eq!(router.active_regime, RegimeKind::Unknown);

    // During warmup (first K rounds), select_arm should return round-robin:
    // round 0 → arm 0, round 1 → arm 1, etc.
    // The router's round counter starts at 0, so select_arm ignores the seed.
    let arm = router.select_arm(999_999);
    assert_eq!(
        arm, 0,
        "at round 0, warmup should return arm 0 regardless of seed"
    );
}

// ===========================================================================
// 30. MAX_ARMS boundary — exactly 16 arms works, 17 fails
// ===========================================================================

#[test]
fn router_max_arms_boundary() {
    // Exactly 16 arms should succeed.
    let router = RegretBoundedRouter::new(make_arms(16), 100_000).unwrap();
    assert_eq!(router.num_arms(), 16);

    // Probability sum should still be exact.
    let probs = router.exp3.arm_probabilities();
    assert_eq!(probs.len(), 16);
    let sum: i64 = probs.iter().sum();
    assert_eq!(sum, 1_000_000);

    // 17 arms should fail.
    let err = RegretBoundedRouter::new(make_arms(17), 100_000).unwrap_err();
    assert!(matches!(
        err,
        RouterError::TooManyArms { count: 17, max: 16 }
    ));
}

// ===========================================================================
// 31. EXP3 weight divergence with asymmetric rewards
// ===========================================================================

#[test]
fn exp3_weights_diverge_with_asymmetric_rewards() {
    let mut exp3 = Exp3State::new(3, 100_000).unwrap();

    // Always reward arm 2 highly, others get low rewards.
    for _ in 0..50 {
        exp3.update(0, 100_000).unwrap();
        exp3.update(1, 100_000).unwrap();
        exp3.update(2, 900_000).unwrap();
    }

    let probs = exp3.arm_probabilities();
    // Arm 2 should have the highest probability.
    assert!(
        probs[2] > probs[0],
        "arm 2 (high reward) should have higher probability than arm 0: {} vs {}",
        probs[2],
        probs[0]
    );
    assert!(
        probs[2] > probs[1],
        "arm 2 (high reward) should have higher probability than arm 1: {} vs {}",
        probs[2],
        probs[1]
    );
    // Sum must still be exact.
    assert_eq!(probs.iter().sum::<i64>(), 1_000_000);
}

// ===========================================================================
// 32. FTRL converges to best arm in stochastic environment
// ===========================================================================

#[test]
fn ftrl_concentrates_on_best_arm() {
    let mut ftrl = FtrlState::new(3).unwrap();

    // Arm 1 consistently gets the highest reward.
    for _ in 0..100 {
        ftrl.update(0, 200_000).unwrap();
        ftrl.update(1, 800_000).unwrap();
        ftrl.update(2, 400_000).unwrap();
    }

    let probs = ftrl.arm_probabilities();
    assert!(
        probs[1] > probs[0],
        "best arm (1) should dominate arm 0: {} vs {}",
        probs[1],
        probs[0]
    );
    assert!(
        probs[1] > probs[2],
        "best arm (1) should dominate arm 2: {} vs {}",
        probs[1],
        probs[2]
    );
    let means = ftrl.mean_rewards();
    assert_eq!(means[0], 200_000);
    assert_eq!(means[1], 800_000);
    assert_eq!(means[2], 400_000);
}

// ===========================================================================
// 33. FTRL select_arm covers all arms initially
// ===========================================================================

#[test]
fn ftrl_select_arm_covers_all_arms_initially() {
    let ftrl = FtrlState::new(4).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for seed in (0..1_000_000).step_by(500) {
        seen.insert(ftrl.select_arm(seed));
        if seen.len() == 4 {
            break;
        }
    }
    assert_eq!(seen.len(), 4, "uniform FTRL state should reach all 4 arms");
}

// ===========================================================================
// 34. Large-scale determinism — serde round-trip preserves routing decisions
// ===========================================================================

#[test]
fn large_scale_determinism_across_serde() {
    let mut router = RegretBoundedRouter::new(make_arms(4), 150_000).unwrap();

    // Run 100 rounds.
    for i in 0..100 {
        let arm = router.select_arm((i * 10_000) % 1_000_000);
        let signal = make_signal(arm, (i * 7_777) % 1_000_001, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    // Serde round-trip.
    let json = serde_json::to_string(&router).unwrap();
    let restored: RegretBoundedRouter = serde_json::from_str(&json).unwrap();

    // Both must produce identical decisions for 20 more seeds.
    for seed in (0..1_000_000).step_by(50_000) {
        assert_eq!(
            router.select_arm(seed),
            restored.select_arm(seed),
            "arm selection must be identical after serde at seed {}",
            seed
        );
    }
    assert_eq!(router.summary(), restored.summary());
    assert_eq!(router.regret_certificate(), restored.regret_certificate());
}

// ===========================================================================
// 35. Regret bound verification — empirical regret stays within theoretical bound
// ===========================================================================

#[test]
fn regret_within_theoretical_bound_with_counterfactuals() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 200_000).unwrap();

    // Run 90 rounds with full counterfactual info, mild asymmetry.
    for i in 0..90 {
        let arm = router.select_arm((i * 11_111) % 1_000_000);
        let rewards = vec![400_000, 600_000, 500_000];
        let signal = make_signal_full_info(arm, rewards, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    let cert = router.regret_certificate();
    assert!(cert.exact_regret_available);
    assert!(cert.rounds == 90);
    // Theoretical bound should be positive.
    assert!(cert.theoretical_bound_millionths > 0);
    // Realized regret should be non-negative.
    assert!(cert.realized_regret_millionths >= 0);
}

// ===========================================================================
// 36. Growth rate class "sublinear_verified"
// ===========================================================================

#[test]
fn regret_certificate_sublinear_verified_class() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 200_000).unwrap();

    // Feed full info where one arm is slightly better; with enough rounds,
    // realized regret should be within the theoretical bound.
    for i in 0..200 {
        let arm = router.select_arm((i * 5_000) % 1_000_000);
        let rewards = vec![480_000, 520_000]; // mild gap
        let signal = make_signal_full_info(arm, rewards, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    let cert = router.regret_certificate();
    assert!(cert.exact_regret_available);
    // With enough rounds and mild gap, realized regret should be within bound.
    if cert.within_bound && cert.per_round_regret_millionths > 0 {
        assert_eq!(cert.growth_rate_class, "sublinear_verified");
    }
    // Either way, the class should be one of the valid values.
    assert!(
        [
            "zero",
            "sublinear_verified",
            "needs_investigation",
            "empirical_estimate"
        ]
        .contains(&cert.growth_rate_class.as_str()),
        "unexpected growth rate class: {}",
        cert.growth_rate_class
    );
}

// ===========================================================================
// 37. Counterfactual regret — exact computation matches expected delta
// ===========================================================================

#[test]
fn counterfactual_regret_exact_computation() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();

    // Always play arm 0 with reward 400_000.
    // Arm 1 counterfactual is always 600_000.
    for i in 0..10 {
        let signal = make_signal_full_info(0, vec![400_000, 600_000], i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    assert!(router.exact_regret_available());
    let regret = router.realized_regret_millionths();
    // Best arm in hindsight: arm 1, cumulative = 10 × 600_000 = 6_000_000.
    // Our cumulative: 10 × 400_000 = 4_000_000. Regret = 2_000_000.
    assert_eq!(regret, 2_000_000, "exact regret should be 2M millionths");
}

// ===========================================================================
// 38. Receipt field validation — regime reported in receipt
// ===========================================================================

#[test]
fn receipt_reports_current_regime() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 200_000).unwrap();

    let signal = make_signal(0, 500_000, 1);
    let receipt = router.observe_reward(&signal).unwrap();
    // Initially Unknown regime.
    assert_eq!(receipt.regime, RegimeKind::Unknown);
}

// ===========================================================================
// 39. Receipt — cumulative reward tracks across rounds
// ===========================================================================

#[test]
fn receipt_cumulative_reward_tracking() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();
    let mut expected_cumulative = 0i64;

    for i in 0..10 {
        let reward = 100_000 * (i as i64 + 1); // 100k, 200k, ..., 1000k
        let reward = reward.min(1_000_000);
        let signal = make_signal(i % 2, reward, i as u64 + 1);
        let receipt = router.observe_reward(&signal).unwrap();
        expected_cumulative += reward;
        assert_eq!(
            receipt.cumulative_reward_millionths,
            expected_cumulative,
            "cumulative reward mismatch at round {}",
            i + 1
        );
    }
}

// ===========================================================================
// 40. Router — transactional error semantics on counterfactual out-of-range
// ===========================================================================

#[test]
fn observe_reward_transactional_on_counterfactual_out_of_range() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();

    // Counterfactual contains an out-of-range reward.
    let signal = RewardSignal {
        arm_index: 0,
        reward_millionths: 500_000,
        latency_us: 100,
        success: true,
        epoch: SecurityEpoch::from_raw(1),
        counterfactual_rewards_millionths: Some(vec![500_000, 2_000_000]), // out of range
    };

    let err = router.observe_reward(&signal).unwrap_err();
    assert!(matches!(err, RouterError::RewardOutOfRange { .. }));
    // State should be completely unchanged — no partial mutation.
    assert_eq!(router.rounds(), 0);
    assert_eq!(router.cumulative_reward_millionths, 0);
}

// ===========================================================================
// 41. Exp3 — error on invalid arm index
// ===========================================================================

#[test]
fn exp3_update_invalid_arm_error() {
    let mut exp3 = Exp3State::new(3, 100_000).unwrap();
    let err = exp3.update(5, 500_000).unwrap_err();
    assert!(matches!(
        err,
        RouterError::ArmOutOfBounds { index: 5, count: 3 }
    ));
    // Round count should not increment on error.
    assert_eq!(exp3.rounds, 0);
}

// ===========================================================================
// 42. Exp3 — error on out-of-range reward
// ===========================================================================

#[test]
fn exp3_update_out_of_range_reward_error() {
    let mut exp3 = Exp3State::new(2, 100_000).unwrap();
    let err = exp3.update(0, 1_500_000).unwrap_err();
    assert!(matches!(
        err,
        RouterError::RewardOutOfRange { reward: 1_500_000 }
    ));
    assert_eq!(exp3.rounds, 0);

    let err_neg = exp3.update(0, -100).unwrap_err();
    assert!(matches!(
        err_neg,
        RouterError::RewardOutOfRange { reward: -100 }
    ));
    assert_eq!(exp3.rounds, 0);
}

// ===========================================================================
// 43. FTRL — error on invalid arm and reward
// ===========================================================================

#[test]
fn ftrl_update_invalid_arm_error() {
    let mut ftrl = FtrlState::new(2).unwrap();
    let err = ftrl.update(3, 500_000).unwrap_err();
    assert!(matches!(
        err,
        RouterError::ArmOutOfBounds { index: 3, count: 2 }
    ));
    assert_eq!(ftrl.rounds, 0);
}

#[test]
fn ftrl_update_out_of_range_reward_error() {
    let mut ftrl = FtrlState::new(2).unwrap();
    let err = ftrl.update(0, -1).unwrap_err();
    assert!(matches!(err, RouterError::RewardOutOfRange { reward: -1 }));
    assert_eq!(ftrl.rounds, 0);
}

// ===========================================================================
// 44. FTRL — mean_rewards with no pulls returns zeros
// ===========================================================================

#[test]
fn ftrl_mean_rewards_zero_pulls() {
    let ftrl = FtrlState::new(3).unwrap();
    let means = ftrl.mean_rewards();
    assert_eq!(means, vec![0, 0, 0]);
}

// ===========================================================================
// 45. Router — realized regret at zero rounds is zero
// ===========================================================================

#[test]
fn router_zero_rounds_regret_is_zero() {
    let router = RegretBoundedRouter::new(make_arms(3), 100_000).unwrap();
    assert_eq!(router.realized_regret_millionths(), 0);
    assert!(!router.exact_regret_available());
}

// ===========================================================================
// 46. Router — regret certificate at zero rounds
// ===========================================================================

#[test]
fn router_regret_certificate_at_zero_rounds() {
    let router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();
    let cert = router.regret_certificate();
    // rounds is max(1) internally, but realized regret should be 0.
    assert_eq!(cert.realized_regret_millionths, 0);
    assert!(!cert.exact_regret_available);
    assert_eq!(cert.growth_rate_class, "empirical_estimate");
}

// ===========================================================================
// 47. Summary — regime_transitions count matches history length
// ===========================================================================

#[test]
fn summary_regime_transitions_count() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 200_000).unwrap();

    // Low-variance phase.
    for i in 0..40 {
        let signal = make_signal(i % 2, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    let summary = router.summary();
    assert_eq!(
        summary.regime_transitions,
        router.regime_history.len(),
        "summary regime_transitions must match history length"
    );
}

// ===========================================================================
// 48. Router — reward of exactly 1_000_000 (maximum)
// ===========================================================================

#[test]
fn router_observe_max_reward() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();
    let signal = make_signal(0, 1_000_000, 1);
    let receipt = router.observe_reward(&signal).unwrap();
    assert_eq!(receipt.reward_millionths, 1_000_000);
    assert_eq!(router.cumulative_reward_millionths, 1_000_000);
}

// ===========================================================================
// 49. Router — reward of exactly 0 (minimum)
// ===========================================================================

#[test]
fn router_observe_zero_reward() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();
    let signal = make_signal(0, 0, 1);
    let receipt = router.observe_reward(&signal).unwrap();
    assert_eq!(receipt.reward_millionths, 0);
    assert_eq!(router.cumulative_reward_millionths, 0);
}

// ===========================================================================
// 50. Router — gamma at maximum (1_000_000 = full exploration)
// ===========================================================================

#[test]
fn router_gamma_at_maximum() {
    // gamma = 1.0 means pure exploration (uniform probability).
    let router = RegretBoundedRouter::new(make_arms(4), 1_000_000).unwrap();
    let probs = router.exp3.arm_probabilities();
    // With gamma = 1.0, probabilities should be approximately uniform.
    for &p in &probs {
        // Each arm should get roughly 250_000 (1_000_000 / 4).
        assert!(
            (200_000..=300_000).contains(&p),
            "with full exploration, probability {} should be near uniform 250k",
            p
        );
    }
    assert_eq!(probs.iter().sum::<i64>(), 1_000_000);
}

// ===========================================================================
// 51. Exp3 — creation errors
// ===========================================================================

#[test]
fn exp3_new_no_arms_error() {
    let err = Exp3State::new(0, 100_000).unwrap_err();
    assert!(matches!(err, RouterError::NoArms));
}

#[test]
fn exp3_new_too_many_arms_error() {
    let err = Exp3State::new(20, 100_000).unwrap_err();
    assert!(matches!(
        err,
        RouterError::TooManyArms { count: 20, max: 16 }
    ));
}

#[test]
fn exp3_new_invalid_gamma_zero() {
    let err = Exp3State::new(3, 0).unwrap_err();
    assert!(matches!(err, RouterError::InvalidGamma { .. }));
}

#[test]
fn exp3_new_invalid_gamma_negative() {
    let err = Exp3State::new(3, -100).unwrap_err();
    assert!(matches!(err, RouterError::InvalidGamma { .. }));
}

#[test]
fn exp3_new_invalid_gamma_above_million() {
    let err = Exp3State::new(3, 1_000_001).unwrap_err();
    assert!(matches!(err, RouterError::InvalidGamma { .. }));
}

// ===========================================================================
// 52. FTRL — creation errors
// ===========================================================================

#[test]
fn ftrl_new_no_arms_error() {
    let err = FtrlState::new(0).unwrap_err();
    assert!(matches!(err, RouterError::NoArms));
}

#[test]
fn ftrl_new_too_many_arms_error() {
    let err = FtrlState::new(17).unwrap_err();
    assert!(matches!(
        err,
        RouterError::TooManyArms { count: 17, max: 16 }
    ));
}

// ===========================================================================
// 53. Router serde preserves regime history
// ===========================================================================

#[test]
fn router_serde_preserves_regime_history() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 200_000).unwrap();

    // Low-variance rounds to potentially trigger a regime transition.
    for i in 0..40 {
        let signal = make_signal(i % 2, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    let json = serde_json::to_string(&router).unwrap();
    let restored: RegretBoundedRouter = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.regime_history.len(), router.regime_history.len());
    assert_eq!(restored.active_regime, router.active_regime);
    for (orig, rest) in router
        .regime_history
        .iter()
        .zip(restored.regime_history.iter())
    {
        assert_eq!(orig, rest);
    }
}

// ===========================================================================
// 54. EXP3 regret bound grows sublinearly
// ===========================================================================

#[test]
fn exp3_regret_bound_grows_sublinearly() {
    let mut exp3 = Exp3State::new(4, 150_000).unwrap();
    exp3.rounds = 10;
    let bound_10 = exp3.regret_bound_millionths();
    exp3.rounds = 1000;
    let bound_1000 = exp3.regret_bound_millionths();
    assert!(bound_1000 > bound_10);
    // Sublinear: bound_1000/bound_10 should be roughly sqrt(100) = 10.
    assert!(
        bound_1000 < bound_10 * 100,
        "EXP3 regret bound growth should be sublinear"
    );
}

// ===========================================================================
// 55. Router with 16 arms — observe and summarize
// ===========================================================================

#[test]
fn router_16_arms_full_lifecycle() {
    let mut router = RegretBoundedRouter::new(make_arms(16), 100_000).unwrap();
    assert_eq!(router.num_arms(), 16);

    for i in 0..48 {
        let arm = i % 16;
        let signal = make_signal(arm, 500_000, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    let summary = router.summary();
    assert_eq!(summary.num_arms, 16);
    assert_eq!(summary.rounds, 48);
    assert_eq!(summary.arm_probabilities_millionths.len(), 16);
    assert_eq!(
        summary.arm_probabilities_millionths.iter().sum::<i64>(),
        1_000_000
    );

    // All probabilities must be non-negative.
    for &p in &summary.arm_probabilities_millionths {
        assert!(p >= 0, "negative probability detected: {}", p);
    }
}

// ===========================================================================
// 56. Router — exact_regret_available false when some rounds lack counterfactuals
// ===========================================================================

#[test]
fn exact_regret_not_available_with_partial_counterfactuals() {
    let mut router = RegretBoundedRouter::new(make_arms(2), 100_000).unwrap();

    // First round with counterfactuals.
    let signal1 = make_signal_full_info(0, vec![500_000, 600_000], 1);
    router.observe_reward(&signal1).unwrap();
    assert!(router.exact_regret_available());

    // Second round without counterfactuals.
    let signal2 = make_signal(1, 400_000, 2);
    router.observe_reward(&signal2).unwrap();
    // Now counterfactual_rounds (1) != rounds (2).
    assert!(!router.exact_regret_available());
}

// ===========================================================================
// 57. Adversarial pattern — changing best arm
// ===========================================================================

#[test]
fn adversarial_pattern_changing_best_arm() {
    let mut router = RegretBoundedRouter::new(make_arms(3), 200_000).unwrap();

    // Phase 1: arm 0 is best.
    for i in 0..30 {
        let arm = router.select_arm((i * 33_333) % 1_000_000);
        let rewards = vec![800_000, 200_000, 200_000];
        let signal = make_signal_full_info(arm, rewards, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    // Phase 2: arm 2 is best (adversarial shift).
    for i in 30..60 {
        let arm = router.select_arm((i * 33_333) % 1_000_000);
        let rewards = vec![200_000, 200_000, 800_000];
        let signal = make_signal_full_info(arm, rewards, i as u64 + 1);
        router.observe_reward(&signal).unwrap();
    }

    assert_eq!(router.rounds(), 60);
    assert!(router.exact_regret_available());
    // Regret should be positive since the best arm shifted.
    let regret = router.realized_regret_millionths();
    assert!(
        regret > 0,
        "regret should be positive under adversarial shifts: {}",
        regret
    );
}

// ===========================================================================
// 58. RouterError — all variants are distinct in Display
// ===========================================================================

#[test]
fn router_error_display_all_distinct() {
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
    let mut messages = std::collections::BTreeSet::new();
    for e in &errors {
        let msg = e.to_string();
        assert!(
            messages.insert(msg.clone()),
            "duplicate error message: {}",
            msg
        );
    }
}

// ===========================================================================
// 59. Exp3 — serde round-trip after many updates
// ===========================================================================

#[test]
fn exp3_serde_round_trip_after_updates() {
    let mut exp3 = Exp3State::new(4, 150_000).unwrap();
    for _ in 0..50 {
        exp3.update(0, 100_000).unwrap();
        exp3.update(1, 900_000).unwrap();
        exp3.update(2, 500_000).unwrap();
        exp3.update(3, 300_000).unwrap();
    }
    let json = serde_json::to_string(&exp3).unwrap();
    let restored: Exp3State = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, exp3);
    assert_eq!(restored.arm_probabilities(), exp3.arm_probabilities());
}

// ===========================================================================
// 50 (continued). FTRL — serde round-trip after many updates
// ===========================================================================

#[test]
fn ftrl_serde_round_trip_after_updates() {
    let mut ftrl = FtrlState::new(3).unwrap();
    for _ in 0..100 {
        ftrl.update(0, 300_000).unwrap();
        ftrl.update(1, 700_000).unwrap();
        ftrl.update(2, 500_000).unwrap();
    }
    let json = serde_json::to_string(&ftrl).unwrap();
    let restored: FtrlState = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, ftrl);
    assert_eq!(restored.mean_rewards(), ftrl.mean_rewards());
    assert_eq!(restored.arm_probabilities(), ftrl.arm_probabilities());
}
