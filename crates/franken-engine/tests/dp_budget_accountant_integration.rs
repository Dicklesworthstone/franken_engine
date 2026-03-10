#![forbid(unsafe_code)]
//! Integration tests for the `dp_budget_accountant` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! accountant construction, budget consumption (basic, advanced, Renyi, zCDP),
//! epoch transitions, lifetime tracking, exhaustion latch behavior, forecast,
//! serde round-trips, Display impls, and determinism.
//!
//! Fixed-point millionths: 1_000_000 = 1.0.

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

use frankenengine_engine::dp_budget_accountant::{
    AccountantConfig, AccountantError, BudgetAccountant, BudgetConsumption, BudgetForecast,
    EpochBudget, EpochSummary,
};
use frankenengine_engine::privacy_learning_contract::CompositionMethod;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_config() -> AccountantConfig {
    AccountantConfig {
        zone: "zone-A".into(),
        epsilon_per_epoch_millionths: 1_000_000,        // 1.0
        delta_per_epoch_millionths: 100_000,            // 0.1
        lifetime_epsilon_budget_millionths: 10_000_000, // 10.0
        lifetime_delta_budget_millionths: 1_000_000,    // 1.0
        composition_method: CompositionMethod::Basic,
        epoch: SecurityEpoch::from_raw(1),
        now_ns: 1_000_000_000,
    }
}

fn test_accountant() -> BudgetAccountant {
    BudgetAccountant::new(test_config()).unwrap()
}

// ---------------------------------------------------------------------------
// AccountantConfig serde
// ---------------------------------------------------------------------------

#[test]
fn accountant_config_serde_round_trip() {
    let cfg = test_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: AccountantConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn new_accountant_initial_state() {
    let acc = test_accountant();
    assert_eq!(acc.zone, "zone-A");
    assert_eq!(acc.current_epoch, SecurityEpoch::from_raw(1));
    assert!(!acc.is_exhausted());
    assert_eq!(acc.total_operations(), 0);
    assert_eq!(acc.epoch_epsilon_remaining(), 1_000_000);
    assert_eq!(acc.epoch_delta_remaining(), 100_000);
    assert_eq!(acc.lifetime_epsilon_remaining(), 10_000_000);
    assert_eq!(acc.lifetime_delta_remaining(), 1_000_000);
    assert!(acc.epoch_summaries().is_empty());
    assert!(acc.consumption_log().is_empty());
}

#[test]
fn new_accountant_epoch_budget_matches_config() {
    let acc = test_accountant();
    let eb = acc.epoch_budget();
    assert_eq!(eb.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(eb.epsilon_budget_millionths, 1_000_000);
    assert_eq!(eb.delta_budget_millionths, 100_000);
    assert_eq!(eb.epsilon_spent_millionths, 0);
    assert_eq!(eb.delta_spent_millionths, 0);
    assert_eq!(eb.operations_count, 0);
    assert!(!eb.exhausted);
}

// ---------------------------------------------------------------------------
// Construction — validation errors
// ---------------------------------------------------------------------------

#[test]
fn new_rejects_zero_epsilon_per_epoch() {
    let err = BudgetAccountant::new(AccountantConfig {
        epsilon_per_epoch_millionths: 0,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_negative_epsilon_per_epoch() {
    let err = BudgetAccountant::new(AccountantConfig {
        epsilon_per_epoch_millionths: -1,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_zero_delta_per_epoch() {
    let err = BudgetAccountant::new(AccountantConfig {
        delta_per_epoch_millionths: 0,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_negative_delta_per_epoch() {
    let err = BudgetAccountant::new(AccountantConfig {
        delta_per_epoch_millionths: -1,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_zero_lifetime_epsilon() {
    let err = BudgetAccountant::new(AccountantConfig {
        lifetime_epsilon_budget_millionths: 0,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_negative_lifetime_epsilon() {
    let err = BudgetAccountant::new(AccountantConfig {
        lifetime_epsilon_budget_millionths: -100,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_zero_lifetime_delta() {
    let err = BudgetAccountant::new(AccountantConfig {
        lifetime_delta_budget_millionths: 0,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_negative_lifetime_delta() {
    let err = BudgetAccountant::new(AccountantConfig {
        lifetime_delta_budget_millionths: -1,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

// ---------------------------------------------------------------------------
// Basic consumption
// ---------------------------------------------------------------------------

#[test]
fn consume_basic_returns_correct_record() {
    let mut acc = test_accountant();
    let record = acc
        .consume(100_000, 10_000, "noise addition", 2_000_000_000)
        .unwrap();
    assert_eq!(record.operation_id, 1);
    assert_eq!(record.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(record.epsilon_consumed_millionths, 100_000);
    assert_eq!(record.delta_consumed_millionths, 10_000);
    assert_eq!(record.composed_epsilon_millionths, 100_000); // basic: no change
    assert_eq!(record.composed_delta_millionths, 10_000);
    assert_eq!(record.timestamp_ns, 2_000_000_000);
    assert_eq!(record.description, "noise addition");
}

#[test]
fn consume_updates_remaining_budget() {
    let mut acc = test_accountant();
    acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    assert_eq!(acc.epoch_epsilon_remaining(), 900_000);
    assert_eq!(acc.epoch_delta_remaining(), 90_000);
    assert_eq!(acc.lifetime_epsilon_remaining(), 9_900_000);
    assert_eq!(acc.lifetime_delta_remaining(), 990_000);
}

#[test]
fn consume_increments_operation_counter() {
    let mut acc = test_accountant();
    acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    acc.consume(100_000, 10_000, "op2", 3_000_000_000).unwrap();
    acc.consume(100_000, 10_000, "op3", 4_000_000_000).unwrap();
    assert_eq!(acc.total_operations(), 3);
}

#[test]
fn consume_populates_consumption_log() {
    let mut acc = test_accountant();
    acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    acc.consume(200_000, 20_000, "op2", 3_000_000_000).unwrap();

    let log = acc.consumption_log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].description, "op1");
    assert_eq!(log[1].description, "op2");
    assert_eq!(log[0].operation_id, 1);
    assert_eq!(log[1].operation_id, 2);
}

#[test]
fn consume_zero_epsilon_and_delta() {
    let mut acc = test_accountant();
    let record = acc.consume(0, 0, "noop", 2_000_000_000).unwrap();
    assert_eq!(record.composed_epsilon_millionths, 0);
    assert_eq!(record.composed_delta_millionths, 0);
    assert_eq!(acc.total_operations(), 1);
    assert_eq!(acc.epoch_epsilon_remaining(), 1_000_000);
}

#[test]
fn consume_multiple_drains_budget_correctly() {
    let mut acc = test_accountant();
    for i in 0..5 {
        acc.consume(
            100_000,
            10_000,
            &format!("op-{i}"),
            (i as u64 + 2) * 1_000_000_000,
        )
        .unwrap();
    }
    assert_eq!(acc.epoch_epsilon_remaining(), 500_000);
    assert_eq!(acc.epoch_delta_remaining(), 50_000);
    assert_eq!(acc.total_operations(), 5);
    assert_eq!(acc.consumption_log().len(), 5);
}

// ---------------------------------------------------------------------------
// Consumption — negative input rejection
// ---------------------------------------------------------------------------

#[test]
fn consume_rejects_negative_epsilon() {
    let mut acc = test_accountant();
    let err = acc.consume(-1, 0, "bad-eps", 0).unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConsumption { .. }));
    // State should remain unchanged.
    assert_eq!(acc.total_operations(), 0);
}

#[test]
fn consume_rejects_negative_delta() {
    let mut acc = test_accountant();
    let err = acc.consume(0, -1, "bad-delta", 0).unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConsumption { .. }));
}

#[test]
fn consume_rejects_both_negative() {
    let mut acc = test_accountant();
    let err = acc.consume(-100, -100, "bad-both", 0).unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConsumption { .. }));
}

// ---------------------------------------------------------------------------
// Epoch exhaustion
// ---------------------------------------------------------------------------

#[test]
fn epoch_exhaustion_trips_latch() {
    let mut acc = test_accountant();
    acc.consume(900_000, 0, "big op", 2_000_000_000).unwrap();
    // Next consumption would exceed budget.
    let err = acc
        .consume(200_000, 0, "overflow", 3_000_000_000)
        .unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
    assert!(acc.is_exhausted());
}

#[test]
fn exhaustion_latch_stays_tripped_forever() {
    let mut acc = test_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
    assert!(acc.is_exhausted());

    // Even zero consumption is rejected once the latch is tripped.
    let err = acc.consume(0, 0, "zero", 4_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));

    // Even tiny consumption is rejected.
    let err = acc.consume(1, 0, "tiny", 5_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
}

#[test]
fn delta_exhaustion() {
    let mut acc = test_accountant();
    // Delta budget is 100_000.
    acc.consume(0, 90_000, "op1", 2_000_000_000).unwrap();
    let err = acc
        .consume(0, 20_000, "overflow", 3_000_000_000)
        .unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
    assert!(acc.is_exhausted());
}

#[test]
fn exact_budget_consumption_succeeds() {
    let mut acc = test_accountant();
    // Consume exactly the full epsilon budget.
    acc.consume(1_000_000, 0, "exact-eps", 2_000_000_000)
        .unwrap();
    assert_eq!(acc.epoch_epsilon_remaining(), 0);
    assert!(!acc.is_exhausted());
}

#[test]
fn one_over_budget_exhausts() {
    let mut acc = test_accountant();
    acc.consume(1_000_000, 0, "full", 2_000_000_000).unwrap();
    let err = acc.consume(1, 0, "one-over", 3_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
}

// ---------------------------------------------------------------------------
// Lifetime exhaustion
// ---------------------------------------------------------------------------

#[test]
fn lifetime_epsilon_exhaustion() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        lifetime_epsilon_budget_millionths: 500_000, // very small
        ..test_config()
    })
    .unwrap();

    acc.consume(400_000, 0, "op1", 2_000_000_000).unwrap();
    let err = acc.consume(200_000, 0, "op2", 3_000_000_000).unwrap_err();
    match &err {
        AccountantError::BudgetExhausted { dimension, .. } => {
            assert_eq!(dimension, "lifetime");
        }
        other => panic!("expected BudgetExhausted(lifetime), got {other:?}"),
    }
}

#[test]
fn lifetime_delta_exhaustion() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        lifetime_delta_budget_millionths: 50_000, // very small
        ..test_config()
    })
    .unwrap();

    acc.consume(0, 40_000, "op1", 2_000_000_000).unwrap();
    let err = acc.consume(0, 20_000, "op2", 3_000_000_000).unwrap_err();
    match &err {
        AccountantError::BudgetExhausted { dimension, .. } => {
            assert_eq!(dimension, "lifetime");
        }
        other => panic!("expected BudgetExhausted(lifetime), got {other:?}"),
    }
}

#[test]
fn lifetime_exhaustion_across_epochs() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        epsilon_per_epoch_millionths: 500_000,
        delta_per_epoch_millionths: 50_000,
        lifetime_epsilon_budget_millionths: 800_000,
        lifetime_delta_budget_millionths: 200_000,
        now_ns: 0,
        ..test_config()
    })
    .unwrap();

    acc.consume(400_000, 40_000, "ep1", 1_000_000_000).unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 5_000_000_000)
        .unwrap();
    acc.consume(400_000, 40_000, "ep2", 6_000_000_000).unwrap();

    // Lifetime is 800K eps, we've spent 800K.
    let err = acc
        .consume(100_000, 0, "over-lifetime", 7_000_000_000)
        .unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
}

// ---------------------------------------------------------------------------
// Epoch transitions
// ---------------------------------------------------------------------------

#[test]
fn advance_epoch_produces_correct_summary() {
    let mut acc = test_accountant();
    acc.consume(300_000, 30_000, "op1", 2_000_000_000).unwrap();

    let summary = acc
        .advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
        .unwrap();

    assert_eq!(summary.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(summary.zone, "zone-A");
    assert_eq!(summary.total_epsilon_spent_millionths, 300_000);
    assert_eq!(summary.total_delta_spent_millionths, 30_000);
    assert_eq!(summary.operations_count, 1);
    assert!(!summary.exhausted);
    assert_eq!(summary.started_at_ns, 1_000_000_000);
    assert_eq!(summary.closed_at_ns, 10_000_000_000);
    assert_eq!(summary.composition_method, CompositionMethod::Basic);
}

#[test]
fn advance_epoch_resets_budget() {
    let mut acc = test_accountant();
    acc.consume(500_000, 50_000, "half", 2_000_000_000).unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
        .unwrap();

    assert_eq!(acc.current_epoch, SecurityEpoch::from_raw(2));
    assert_eq!(acc.epoch_epsilon_remaining(), 1_000_000);
    assert_eq!(acc.epoch_delta_remaining(), 100_000);
    assert!(!acc.is_exhausted());
}

#[test]
fn advance_epoch_no_budget_rollover() {
    let mut acc = test_accountant();
    // Use only a tiny amount.
    acc.consume(10_000, 1_000, "tiny", 2_000_000_000).unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
        .unwrap();

    // New epoch has exactly the per-epoch allocation, not rolled-over surplus.
    assert_eq!(acc.epoch_epsilon_remaining(), 1_000_000);
    assert_eq!(acc.epoch_delta_remaining(), 100_000);
}

#[test]
fn advance_epoch_clears_exhaustion() {
    let mut acc = test_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
    assert!(acc.is_exhausted());

    acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
        .unwrap();
    assert!(!acc.is_exhausted());

    // Can consume again in new epoch.
    acc.consume(100_000, 10_000, "fresh op", 11_000_000_000)
        .unwrap();
}

#[test]
fn advance_epoch_retains_lifetime_spending() {
    let mut acc = test_accountant();
    acc.consume(300_000, 30_000, "ep1-op", 2_000_000_000)
        .unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
        .unwrap();
    acc.consume(200_000, 20_000, "ep2-op", 11_000_000_000)
        .unwrap();

    assert_eq!(acc.lifetime_epsilon_spent_millionths, 500_000);
    assert_eq!(acc.lifetime_delta_spent_millionths, 50_000);
    assert_eq!(acc.lifetime_epsilon_remaining(), 9_500_000);
    assert_eq!(acc.lifetime_delta_remaining(), 950_000);
}

#[test]
fn advance_epoch_stores_summaries() {
    let mut acc = test_accountant();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 5_000_000_000)
        .unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(3), 10_000_000_000)
        .unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(4), 15_000_000_000)
        .unwrap();

    let summaries = acc.epoch_summaries();
    assert_eq!(summaries.len(), 3);
    assert_eq!(summaries[0].epoch, SecurityEpoch::from_raw(1));
    assert_eq!(summaries[1].epoch, SecurityEpoch::from_raw(2));
    assert_eq!(summaries[2].epoch, SecurityEpoch::from_raw(3));
}

#[test]
fn advance_epoch_with_exhausted_summary() {
    let mut acc = test_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
    assert!(acc.is_exhausted());

    let summary = acc
        .advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
        .unwrap();
    assert!(summary.exhausted);
}

// ---------------------------------------------------------------------------
// Epoch transition — validation errors
// ---------------------------------------------------------------------------

#[test]
fn advance_epoch_rejects_same_epoch() {
    let mut acc = test_accountant();
    let err = acc
        .advance_epoch(SecurityEpoch::from_raw(1), 2_000_000_000)
        .unwrap_err();
    match &err {
        AccountantError::EpochNotAdvanced { current, proposed } => {
            assert_eq!(*current, SecurityEpoch::from_raw(1));
            assert_eq!(*proposed, SecurityEpoch::from_raw(1));
        }
        other => panic!("expected EpochNotAdvanced, got {other:?}"),
    }
}

#[test]
fn advance_epoch_rejects_lower_epoch() {
    let mut acc = test_accountant();
    acc.advance_epoch(SecurityEpoch::from_raw(5), 2_000_000_000)
        .unwrap();
    let err = acc
        .advance_epoch(SecurityEpoch::from_raw(3), 3_000_000_000)
        .unwrap_err();
    assert!(matches!(err, AccountantError::EpochNotAdvanced { .. }));
}

#[test]
fn advance_epoch_rejects_genesis_after_higher() {
    let mut acc = test_accountant();
    acc.advance_epoch(SecurityEpoch::from_raw(10), 2_000_000_000)
        .unwrap();
    let err = acc
        .advance_epoch(SecurityEpoch::GENESIS, 3_000_000_000)
        .unwrap_err();
    assert!(matches!(err, AccountantError::EpochNotAdvanced { .. }));
}

// ---------------------------------------------------------------------------
// Lifetime exhaustion blocks new epoch consumption
// ---------------------------------------------------------------------------

#[test]
fn lifetime_exhaustion_blocks_new_epoch_consumption() {
    // When lifetime is exactly consumed, advancing epoch starts exhausted.
    let mut acc = BudgetAccountant::new(AccountantConfig {
        epsilon_per_epoch_millionths: 500_000,
        delta_per_epoch_millionths: 50_000,
        lifetime_epsilon_budget_millionths: 500_000,
        lifetime_delta_budget_millionths: 100_000,
        now_ns: 0,
        ..test_config()
    })
    .unwrap();

    acc.consume(500_000, 50_000, "fill-lifetime", 1_000_000_000)
        .unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 5_000_000_000)
        .unwrap();

    // New epoch starts exhausted because lifetime is fully consumed.
    assert!(acc.is_exhausted());
    let err = acc.consume(1, 0, "blocked", 6_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
}

// ---------------------------------------------------------------------------
// Composition methods
// ---------------------------------------------------------------------------

#[test]
fn basic_composition_no_change() {
    let mut acc = test_accountant();
    let r = acc.consume(100_000, 10_000, "op", 1_000_000_000).unwrap();
    assert_eq!(r.composed_epsilon_millionths, 100_000);
    assert_eq!(r.composed_delta_millionths, 10_000);
}

#[test]
fn advanced_composition_first_op_full_cost() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::Advanced,
        ..test_config()
    })
    .unwrap();

    let r = acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    assert_eq!(r.composed_epsilon_millionths, 100_000); // k=0, scale=1.0
}

#[test]
fn advanced_composition_reduces_subsequent_cost() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::Advanced,
        ..test_config()
    })
    .unwrap();

    let r1 = acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    let r2 = acc.consume(100_000, 10_000, "op2", 3_000_000_000).unwrap();

    assert_eq!(r1.composed_epsilon_millionths, 100_000);
    assert!(
        r2.composed_epsilon_millionths < 100_000,
        "advanced composition should reduce cost: got {}",
        r2.composed_epsilon_millionths
    );
    // Delta is not affected by advanced composition.
    assert_eq!(r2.composed_delta_millionths, 10_000);
}

#[test]
fn advanced_composition_cost_decreases_with_more_ops() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::Advanced,
        ..test_config()
    })
    .unwrap();

    let mut composed_costs = Vec::new();
    for i in 0..10 {
        let r = acc
            .consume(
                100_000,
                10_000,
                &format!("op{i}"),
                (i as u64 + 2) * 1_000_000_000,
            )
            .unwrap();
        composed_costs.push(r.composed_epsilon_millionths);
    }

    // Composed costs should be non-increasing after the first.
    for window in composed_costs.windows(2).skip(1) {
        assert!(
            window[1] <= window[0],
            "advanced cost should not increase: {} > {}",
            window[1],
            window[0]
        );
    }
}

#[test]
fn renyi_composition_80_percent() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::Renyi,
        now_ns: 0,
        ..test_config()
    })
    .unwrap();

    let r = acc.consume(100_000, 10_000, "op", 1_000_000_000).unwrap();
    assert_eq!(r.composed_epsilon_millionths, 80_000); // 80% of 100K
    assert_eq!(r.composed_delta_millionths, 10_000); // delta unchanged
}

#[test]
fn zcdp_composition_70_percent() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::ZeroCdp,
        now_ns: 0,
        ..test_config()
    })
    .unwrap();

    let r = acc.consume(100_000, 10_000, "op", 1_000_000_000).unwrap();
    assert_eq!(r.composed_epsilon_millionths, 70_000); // 70% of 100K
    assert_eq!(r.composed_delta_millionths, 10_000); // delta unchanged
}

#[test]
fn composition_minimum_floor_of_1() {
    // Renyi with very small epsilon: 80% of 1 = 0, but should clamp to 1.
    let mut acc = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::Renyi,
        now_ns: 0,
        ..test_config()
    })
    .unwrap();

    let r = acc.consume(1, 0, "tiny", 1_000_000_000).unwrap();
    assert_eq!(r.composed_epsilon_millionths, 1); // clamped to 1
}

#[test]
fn zcdp_minimum_floor_of_1() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::ZeroCdp,
        now_ns: 0,
        ..test_config()
    })
    .unwrap();

    let r = acc.consume(1, 0, "tiny", 1_000_000_000).unwrap();
    assert_eq!(r.composed_epsilon_millionths, 1); // clamped to 1
}

// ---------------------------------------------------------------------------
// Forecast
// ---------------------------------------------------------------------------

#[test]
fn forecast_no_consumption() {
    let acc = test_accountant();
    let fc = acc.forecast();
    assert_eq!(fc.epoch_epsilon_remaining_millionths, 1_000_000);
    assert_eq!(fc.epoch_delta_remaining_millionths, 100_000);
    assert_eq!(fc.lifetime_epsilon_remaining_millionths, 10_000_000);
    assert_eq!(fc.lifetime_delta_remaining_millionths, 1_000_000);
    assert_eq!(fc.estimated_remaining_operations, u64::MAX);
    assert!(!fc.exhausted);
}

#[test]
fn forecast_with_uniform_consumption() {
    let mut acc = test_accountant();
    acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    acc.consume(100_000, 10_000, "op2", 3_000_000_000).unwrap();

    let fc = acc.forecast();
    assert_eq!(fc.epoch_epsilon_remaining_millionths, 800_000);
    assert_eq!(fc.epoch_delta_remaining_millionths, 80_000);
    // Avg eps per op = 100K, remaining = 800K -> ~8 ops.
    assert_eq!(fc.estimated_remaining_operations, 8);
}

#[test]
fn forecast_after_exhaustion() {
    let mut acc = test_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);

    let fc = acc.forecast();
    assert!(fc.exhausted);
}

#[test]
fn forecast_after_epoch_advance() {
    let mut acc = test_accountant();
    acc.consume(500_000, 50_000, "ep1", 2_000_000_000).unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
        .unwrap();

    let fc = acc.forecast();
    assert_eq!(fc.epoch_epsilon_remaining_millionths, 1_000_000);
    assert_eq!(fc.epoch_delta_remaining_millionths, 100_000);
    // No consumption in new epoch yet.
    assert_eq!(fc.estimated_remaining_operations, u64::MAX);
    assert!(!fc.exhausted);
}

#[test]
fn forecast_serde_round_trip() {
    let mut acc = test_accountant();
    acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    let fc = acc.forecast();
    let json = serde_json::to_string(&fc).unwrap();
    let restored: BudgetForecast = serde_json::from_str(&json).unwrap();
    assert_eq!(fc, restored);
}

// ---------------------------------------------------------------------------
// EpochBudget
// ---------------------------------------------------------------------------

#[test]
fn epoch_budget_remaining_calculation() {
    let eb = EpochBudget {
        epoch: SecurityEpoch::from_raw(1),
        epsilon_budget_millionths: 1_000_000,
        delta_budget_millionths: 100_000,
        epsilon_spent_millionths: 300_000,
        delta_spent_millionths: 50_000,
        composition_method: CompositionMethod::Basic,
        operations_count: 3,
        created_at_ns: 0,
        exhausted: false,
    };
    assert_eq!(eb.epsilon_remaining(), 700_000);
    assert_eq!(eb.delta_remaining(), 50_000);
}

#[test]
fn epoch_budget_would_exhaust_epsilon() {
    let eb = EpochBudget {
        epoch: SecurityEpoch::from_raw(1),
        epsilon_budget_millionths: 1_000_000,
        delta_budget_millionths: 100_000,
        epsilon_spent_millionths: 900_000,
        delta_spent_millionths: 0,
        composition_method: CompositionMethod::Basic,
        operations_count: 1,
        created_at_ns: 0,
        exhausted: false,
    };
    assert!(!eb.would_exhaust(100_000, 0)); // exactly at limit
    assert!(eb.would_exhaust(200_000, 0)); // over limit
    assert!(!eb.would_exhaust(0, 100_000)); // delta within limit
}

#[test]
fn epoch_budget_would_exhaust_delta() {
    let eb = EpochBudget {
        epoch: SecurityEpoch::from_raw(1),
        epsilon_budget_millionths: 1_000_000,
        delta_budget_millionths: 100_000,
        epsilon_spent_millionths: 0,
        delta_spent_millionths: 90_000,
        composition_method: CompositionMethod::Basic,
        operations_count: 1,
        created_at_ns: 0,
        exhausted: false,
    };
    assert!(!eb.would_exhaust(0, 10_000)); // at limit
    assert!(eb.would_exhaust(0, 20_000)); // over limit
}

#[test]
fn epoch_budget_serde_round_trip() {
    let eb = EpochBudget {
        epoch: SecurityEpoch::from_raw(3),
        epsilon_budget_millionths: 2_000_000,
        delta_budget_millionths: 200_000,
        epsilon_spent_millionths: 500_000,
        delta_spent_millionths: 50_000,
        composition_method: CompositionMethod::Advanced,
        operations_count: 5,
        created_at_ns: 1_000_000_000,
        exhausted: false,
    };
    let json = serde_json::to_string(&eb).unwrap();
    let restored: EpochBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(eb, restored);
}

// ---------------------------------------------------------------------------
// EpochSummary serde
// ---------------------------------------------------------------------------

#[test]
fn epoch_summary_serde_round_trip() {
    let summary = EpochSummary {
        epoch: SecurityEpoch::from_raw(1),
        zone: "zone-A".into(),
        total_epsilon_spent_millionths: 500_000,
        total_delta_spent_millionths: 50_000,
        operations_count: 5,
        exhausted: false,
        started_at_ns: 1_000_000_000,
        closed_at_ns: 10_000_000_000,
        composition_method: CompositionMethod::Basic,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: EpochSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn epoch_summary_with_each_composition_method() {
    for method in [
        CompositionMethod::Basic,
        CompositionMethod::Advanced,
        CompositionMethod::Renyi,
        CompositionMethod::ZeroCdp,
    ] {
        let summary = EpochSummary {
            epoch: SecurityEpoch::from_raw(1),
            zone: "zone-test".into(),
            total_epsilon_spent_millionths: 0,
            total_delta_spent_millionths: 0,
            operations_count: 0,
            exhausted: false,
            started_at_ns: 0,
            closed_at_ns: 0,
            composition_method: method,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: EpochSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored, "failed for method {method:?}");
    }
}

// ---------------------------------------------------------------------------
// BudgetConsumption serde
// ---------------------------------------------------------------------------

#[test]
fn budget_consumption_serde_round_trip() {
    let record = BudgetConsumption {
        operation_id: 42,
        epoch: SecurityEpoch::from_raw(3),
        epsilon_consumed_millionths: 100_000,
        delta_consumed_millionths: 10_000,
        composed_epsilon_millionths: 80_000,
        composed_delta_millionths: 10_000,
        timestamp_ns: 2_000_000_000,
        description: "test-op".into(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let restored: BudgetConsumption = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

// ---------------------------------------------------------------------------
// BudgetAccountant serde
// ---------------------------------------------------------------------------

#[test]
fn accountant_serde_round_trip_empty() {
    let acc = test_accountant();
    let json = serde_json::to_string(&acc).unwrap();
    let restored: BudgetAccountant = serde_json::from_str(&json).unwrap();
    assert_eq!(acc, restored);
}

#[test]
fn accountant_serde_round_trip_with_consumption() {
    let mut acc = test_accountant();
    acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    acc.consume(200_000, 20_000, "op2", 3_000_000_000).unwrap();

    let json = serde_json::to_string(&acc).unwrap();
    let restored: BudgetAccountant = serde_json::from_str(&json).unwrap();
    assert_eq!(acc, restored);
}

#[test]
fn accountant_serde_round_trip_with_epoch_advance() {
    let mut acc = test_accountant();
    acc.consume(300_000, 30_000, "ep1-op", 2_000_000_000)
        .unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000)
        .unwrap();
    acc.consume(100_000, 10_000, "ep2-op", 11_000_000_000)
        .unwrap();

    let json = serde_json::to_string(&acc).unwrap();
    let restored: BudgetAccountant = serde_json::from_str(&json).unwrap();
    assert_eq!(acc, restored);
}

#[test]
fn accountant_serde_round_trip_exhausted() {
    let mut acc = test_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);

    let json = serde_json::to_string(&acc).unwrap();
    let restored: BudgetAccountant = serde_json::from_str(&json).unwrap();
    assert_eq!(acc, restored);
    assert!(restored.is_exhausted());
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn deterministic_construction() {
    let a1 = test_accountant();
    let a2 = test_accountant();
    assert_eq!(
        serde_json::to_string(&a1).unwrap(),
        serde_json::to_string(&a2).unwrap()
    );
}

#[test]
fn deterministic_consumption_sequence() {
    let mut a1 = test_accountant();
    let mut a2 = test_accountant();

    for i in 0..5 {
        let ts = (i as u64 + 1) * 1_000_000_000;
        let desc = format!("op-{i}");
        a1.consume(50_000, 5_000, &desc, ts).unwrap();
        a2.consume(50_000, 5_000, &desc, ts).unwrap();
    }

    assert_eq!(
        serde_json::to_string(&a1).unwrap(),
        serde_json::to_string(&a2).unwrap()
    );
}

#[test]
fn deterministic_epoch_advance_sequence() {
    let mut a1 = test_accountant();
    let mut a2 = test_accountant();

    for i in 0..3 {
        let ep = SecurityEpoch::from_raw(i as u64 + 2);
        let ts = (i as u64 + 1) * 5_000_000_000;
        a1.advance_epoch(ep, ts).unwrap();
        a2.advance_epoch(ep, ts).unwrap();
    }

    assert_eq!(
        serde_json::to_string(&a1).unwrap(),
        serde_json::to_string(&a2).unwrap()
    );
}

// ---------------------------------------------------------------------------
// AccountantError Display
// ---------------------------------------------------------------------------

#[test]
fn error_display_budget_exhausted() {
    let err = AccountantError::BudgetExhausted {
        dimension: "epoch".into(),
        epsilon_remaining: -100,
        delta_remaining: 50,
    };
    let s = err.to_string();
    assert!(s.contains("budget exhausted"));
    assert!(s.contains("epoch"));
    assert!(s.contains("-100"));
    assert!(s.contains("50"));
}

#[test]
fn error_display_epoch_not_advanced() {
    let err = AccountantError::EpochNotAdvanced {
        current: SecurityEpoch::from_raw(5),
        proposed: SecurityEpoch::from_raw(3),
    };
    let s = err.to_string();
    assert!(s.contains("epoch not advanced"));
    assert!(s.contains('5'));
    assert!(s.contains('3'));
}

#[test]
fn error_display_invalid_consumption() {
    let err = AccountantError::InvalidConsumption {
        reason: "negative epsilon".into(),
    };
    let s = err.to_string();
    assert!(s.contains("invalid consumption"));
    assert!(s.contains("negative epsilon"));
}

#[test]
fn error_display_invalid_configuration() {
    let err = AccountantError::InvalidConfiguration {
        reason: "delta must be positive".into(),
    };
    let s = err.to_string();
    assert!(s.contains("invalid configuration"));
    assert!(s.contains("delta must be positive"));
}

#[test]
fn error_is_std_error() {
    let err = AccountantError::InvalidConsumption {
        reason: "test".into(),
    };
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// AccountantError serde
// ---------------------------------------------------------------------------

#[test]
fn error_serde_round_trip_all_variants() {
    let errors = vec![
        AccountantError::BudgetExhausted {
            dimension: "epoch".into(),
            epsilon_remaining: -100,
            delta_remaining: 50,
        },
        AccountantError::EpochNotAdvanced {
            current: SecurityEpoch::from_raw(5),
            proposed: SecurityEpoch::from_raw(3),
        },
        AccountantError::InvalidConsumption {
            reason: "negative".into(),
        },
        AccountantError::InvalidConfiguration {
            reason: "zero delta".into(),
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: AccountantError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "round-trip failed for {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Multi-epoch stress test
// ---------------------------------------------------------------------------

#[test]
fn multi_epoch_stress_test() {
    let mut acc = test_accountant();

    for epoch_num in 2u64..=10 {
        // Consume some budget in each epoch.
        for op in 0u64..3 {
            let ts = (epoch_num * 100 + op) * 1_000_000_000;
            acc.consume(50_000, 5_000, &format!("ep{epoch_num}-op{op}"), ts)
                .unwrap();
        }
        let ts = (epoch_num + 1) * 1_000 * 1_000_000_000;
        acc.advance_epoch(SecurityEpoch::from_raw(epoch_num), ts)
            .unwrap();
    }

    // 9 epochs of 3 ops each = 27 ops.
    assert_eq!(acc.total_operations(), 27);
    // 9 closed epochs.
    assert_eq!(acc.epoch_summaries().len(), 9);
    // Each epoch spent 150K eps and 15K delta (3 ops * 50K/5K).
    // Total lifetime: 1_350_000 eps, 135_000 delta.
    assert_eq!(acc.lifetime_epsilon_spent_millionths, 1_350_000);
    assert_eq!(acc.lifetime_delta_spent_millionths, 135_000);
    // Still within budget.
    assert!(!acc.is_exhausted());
}

// ---------------------------------------------------------------------------
// Operation IDs are globally monotonic
// ---------------------------------------------------------------------------

#[test]
fn operation_ids_monotonic_across_epochs() {
    let mut acc = test_accountant();

    let r1 = acc
        .consume(50_000, 5_000, "ep1-op1", 1_000_000_000)
        .unwrap();
    let r2 = acc
        .consume(50_000, 5_000, "ep1-op2", 2_000_000_000)
        .unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 5_000_000_000)
        .unwrap();
    let r3 = acc
        .consume(50_000, 5_000, "ep2-op1", 6_000_000_000)
        .unwrap();
    let r4 = acc
        .consume(50_000, 5_000, "ep2-op2", 7_000_000_000)
        .unwrap();

    assert_eq!(r1.operation_id, 1);
    assert_eq!(r2.operation_id, 2);
    assert_eq!(r3.operation_id, 3);
    assert_eq!(r4.operation_id, 4);
}
