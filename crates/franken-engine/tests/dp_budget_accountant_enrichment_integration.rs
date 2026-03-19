//! Enrichment integration tests for `dp_budget_accountant` module.
//!
//! Tests additional scenarios: composition methods, epoch transitions,
//! lifetime tracking, forecast, exhaustion latch, serde roundtrips, Display.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::dp_budget_accountant::{
    AccountantConfig, AccountantError, BudgetAccountant, BudgetConsumption,
    BudgetForecast, EpochBudget, EpochSummary,
};
use frankenengine_engine::privacy_learning_contract::CompositionMethod;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_config() -> AccountantConfig {
    AccountantConfig {
        zone: "zone-enrich".into(),
        epsilon_per_epoch_millionths: 1_000_000,
        delta_per_epoch_millionths: 100_000,
        lifetime_epsilon_budget_millionths: 10_000_000,
        lifetime_delta_budget_millionths: 1_000_000,
        composition_method: CompositionMethod::Basic,
        epoch: SecurityEpoch::from_raw(1),
        now_ns: 1_000_000_000,
    }
}

fn make_accountant() -> BudgetAccountant {
    BudgetAccountant::new(test_config()).unwrap()
}

// ---------------------------------------------------------------------------
// AccountantConfig serde
// ---------------------------------------------------------------------------

#[test]
fn config_serde_roundtrip() {
    let cfg = test_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: AccountantConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn config_all_composition_methods_serde() {
    for m in &[
        CompositionMethod::Basic,
        CompositionMethod::Advanced,
        CompositionMethod::Renyi,
        CompositionMethod::ZeroCdp,
    ] {
        let cfg = AccountantConfig {
            composition_method: *m,
            ..test_config()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: AccountantConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn new_accountant_initial_state() {
    let acc = make_accountant();
    assert_eq!(acc.zone, "zone-enrich");
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
fn new_accountant_epoch_budget_matches() {
    let acc = make_accountant();
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
// Construction validation errors
// ---------------------------------------------------------------------------

#[test]
fn new_rejects_zero_epsilon() {
    let err = BudgetAccountant::new(AccountantConfig {
        epsilon_per_epoch_millionths: 0,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_negative_epsilon() {
    let err = BudgetAccountant::new(AccountantConfig {
        epsilon_per_epoch_millionths: -1,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

#[test]
fn new_rejects_zero_delta() {
    let err = BudgetAccountant::new(AccountantConfig {
        delta_per_epoch_millionths: 0,
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
fn new_rejects_zero_lifetime_delta() {
    let err = BudgetAccountant::new(AccountantConfig {
        lifetime_delta_budget_millionths: 0,
        ..test_config()
    })
    .unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConfiguration { .. }));
}

// ---------------------------------------------------------------------------
// Basic consumption
// ---------------------------------------------------------------------------

#[test]
fn consume_basic_ok() {
    let mut acc = make_accountant();
    let rec = acc.consume(100_000, 10_000, "noise", 2_000_000_000).unwrap();
    assert_eq!(rec.operation_id, 1);
    assert_eq!(rec.epsilon_consumed_millionths, 100_000);
    assert_eq!(rec.delta_consumed_millionths, 10_000);
    // Basic composition: no change
    assert_eq!(rec.composed_epsilon_millionths, 100_000);
    assert_eq!(rec.composed_delta_millionths, 10_000);
    assert_eq!(acc.epoch_epsilon_remaining(), 900_000);
    assert_eq!(acc.epoch_delta_remaining(), 90_000);
    assert_eq!(acc.total_operations(), 1);
    assert_eq!(acc.consumption_log().len(), 1);
}

#[test]
fn consume_multiple_ok() {
    let mut acc = make_accountant();
    for i in 0..5 {
        acc.consume(100_000, 10_000, &format!("op-{i}"), (i + 2) * 1_000_000_000)
            .unwrap();
    }
    assert_eq!(acc.epoch_epsilon_remaining(), 500_000);
    assert_eq!(acc.total_operations(), 5);
}

#[test]
fn consume_rejects_negative_epsilon() {
    let mut acc = make_accountant();
    let err = acc.consume(-1, 0, "bad", 0).unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConsumption { .. }));
}

#[test]
fn consume_rejects_negative_delta() {
    let mut acc = make_accountant();
    let err = acc.consume(0, -1, "bad", 0).unwrap_err();
    assert!(matches!(err, AccountantError::InvalidConsumption { .. }));
}

// ---------------------------------------------------------------------------
// Exhaustion
// ---------------------------------------------------------------------------

#[test]
fn epoch_exhaustion_trips_latch() {
    let mut acc = make_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let err = acc.consume(200_000, 0, "overflow", 3_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
    assert!(acc.is_exhausted());
}

#[test]
fn exhaustion_latch_permanent() {
    let mut acc = make_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
    // Even tiny consumption rejected
    let err = acc.consume(1, 0, "tiny", 4_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
}

#[test]
fn delta_exhaustion() {
    let mut acc = make_accountant();
    acc.consume(0, 90_000, "delta-op", 2_000_000_000).unwrap();
    let err = acc.consume(0, 20_000, "overflow", 3_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::BudgetExhausted { .. }));
}

#[test]
fn lifetime_exhaustion() {
    let mut acc = BudgetAccountant::new(AccountantConfig {
        lifetime_epsilon_budget_millionths: 500_000,
        ..test_config()
    })
    .unwrap();
    acc.consume(400_000, 0, "op1", 2_000_000_000).unwrap();
    let err = acc.consume(200_000, 0, "op2", 3_000_000_000).unwrap_err();
    match err {
        AccountantError::BudgetExhausted { dimension, .. } => {
            assert_eq!(dimension, "lifetime");
        }
        _ => panic!("expected BudgetExhausted"),
    }
}

// ---------------------------------------------------------------------------
// Epoch transitions
// ---------------------------------------------------------------------------

#[test]
fn advance_epoch_ok() {
    let mut acc = make_accountant();
    acc.consume(300_000, 30_000, "op1", 2_000_000_000).unwrap();
    let summary = acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000).unwrap();
    assert_eq!(summary.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(summary.total_epsilon_spent_millionths, 300_000);
    assert_eq!(summary.total_delta_spent_millionths, 30_000);
    assert_eq!(summary.operations_count, 1);
    assert!(!summary.exhausted);
    assert_eq!(acc.current_epoch, SecurityEpoch::from_raw(2));
    assert_eq!(acc.epoch_epsilon_remaining(), 1_000_000);
    assert!(!acc.is_exhausted());
}

#[test]
fn advance_epoch_clears_exhaustion() {
    let mut acc = make_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
    assert!(acc.is_exhausted());
    acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000).unwrap();
    assert!(!acc.is_exhausted());
}

#[test]
fn advance_epoch_rejects_non_advancing() {
    let mut acc = make_accountant();
    let err = acc.advance_epoch(SecurityEpoch::from_raw(1), 10_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::EpochNotAdvanced { .. }));
}

#[test]
fn advance_epoch_rejects_backward() {
    let mut acc = make_accountant();
    acc.advance_epoch(SecurityEpoch::from_raw(5), 10_000_000_000).unwrap();
    let err = acc.advance_epoch(SecurityEpoch::from_raw(3), 20_000_000_000).unwrap_err();
    assert!(matches!(err, AccountantError::EpochNotAdvanced { .. }));
}

#[test]
fn advance_epoch_preserves_summaries() {
    let mut acc = make_accountant();
    acc.consume(100_000, 10_000, "op", 2_000_000_000).unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(2), 10_000_000_000).unwrap();
    acc.advance_epoch(SecurityEpoch::from_raw(3), 20_000_000_000).unwrap();
    assert_eq!(acc.epoch_summaries().len(), 2);
}

// ---------------------------------------------------------------------------
// Forecast
// ---------------------------------------------------------------------------

#[test]
fn forecast_initial_state() {
    let acc = make_accountant();
    let f = acc.forecast();
    assert_eq!(f.epoch_epsilon_remaining_millionths, 1_000_000);
    assert_eq!(f.epoch_delta_remaining_millionths, 100_000);
    assert_eq!(f.lifetime_epsilon_remaining_millionths, 10_000_000);
    assert_eq!(f.lifetime_delta_remaining_millionths, 1_000_000);
    assert!(!f.exhausted);
    // No ops yet -> unlimited remaining
    assert_eq!(f.estimated_remaining_operations, u64::MAX);
}

#[test]
fn forecast_after_consumption() {
    let mut acc = make_accountant();
    acc.consume(200_000, 20_000, "op1", 2_000_000_000).unwrap();
    let f = acc.forecast();
    assert_eq!(f.epoch_epsilon_remaining_millionths, 800_000);
    assert_eq!(f.epoch_delta_remaining_millionths, 80_000);
    // estimated_remaining = 800_000 / 200_000 = 4
    assert_eq!(f.estimated_remaining_operations, 4);
}

#[test]
fn forecast_when_exhausted() {
    let mut acc = make_accountant();
    acc.consume(900_000, 0, "big", 2_000_000_000).unwrap();
    let _ = acc.consume(200_000, 0, "overflow", 3_000_000_000);
    let f = acc.forecast();
    assert!(f.exhausted);
}

// ---------------------------------------------------------------------------
// EpochBudget
// ---------------------------------------------------------------------------

#[test]
fn epoch_budget_remaining_computation() {
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
fn epoch_budget_would_exhaust() {
    let eb = EpochBudget {
        epoch: SecurityEpoch::from_raw(1),
        epsilon_budget_millionths: 1_000_000,
        delta_budget_millionths: 100_000,
        epsilon_spent_millionths: 800_000,
        delta_spent_millionths: 0,
        composition_method: CompositionMethod::Basic,
        operations_count: 1,
        created_at_ns: 0,
        exhausted: false,
    };
    assert!(eb.would_exhaust(300_000, 0));
    assert!(!eb.would_exhaust(100_000, 0));
}

#[test]
fn epoch_budget_serde_roundtrip() {
    let eb = EpochBudget {
        epoch: SecurityEpoch::from_raw(5),
        epsilon_budget_millionths: 500_000,
        delta_budget_millionths: 50_000,
        epsilon_spent_millionths: 100_000,
        delta_spent_millionths: 10_000,
        composition_method: CompositionMethod::Renyi,
        operations_count: 2,
        created_at_ns: 1_000_000_000,
        exhausted: false,
    };
    let json = serde_json::to_string(&eb).unwrap();
    let back: EpochBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(eb, back);
}

// ---------------------------------------------------------------------------
// BudgetConsumption serde
// ---------------------------------------------------------------------------

#[test]
fn budget_consumption_serde_roundtrip() {
    let bc = BudgetConsumption {
        operation_id: 42,
        epoch: SecurityEpoch::from_raw(3),
        epsilon_consumed_millionths: 100_000,
        delta_consumed_millionths: 10_000,
        composed_epsilon_millionths: 80_000,
        composed_delta_millionths: 10_000,
        timestamp_ns: 5_000_000_000,
        description: "test op".into(),
    };
    let json = serde_json::to_string(&bc).unwrap();
    let back: BudgetConsumption = serde_json::from_str(&json).unwrap();
    assert_eq!(bc, back);
}

// ---------------------------------------------------------------------------
// BudgetForecast serde
// ---------------------------------------------------------------------------

#[test]
fn budget_forecast_serde_roundtrip() {
    let f = BudgetForecast {
        epoch_epsilon_remaining_millionths: 500_000,
        epoch_delta_remaining_millionths: 50_000,
        lifetime_epsilon_remaining_millionths: 5_000_000,
        lifetime_delta_remaining_millionths: 500_000,
        estimated_remaining_operations: 10,
        exhausted: false,
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: BudgetForecast = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// EpochSummary serde
// ---------------------------------------------------------------------------

#[test]
fn epoch_summary_serde_roundtrip() {
    let s = EpochSummary {
        epoch: SecurityEpoch::from_raw(1),
        zone: "zone-test".into(),
        total_epsilon_spent_millionths: 300_000,
        total_delta_spent_millionths: 30_000,
        operations_count: 5,
        exhausted: false,
        started_at_ns: 1_000_000_000,
        closed_at_ns: 2_000_000_000,
        composition_method: CompositionMethod::Basic,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: EpochSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// AccountantError Display and serde
// ---------------------------------------------------------------------------

#[test]
fn accountant_error_display_distinctness() {
    let errors: Vec<AccountantError> = vec![
        AccountantError::BudgetExhausted {
            dimension: "epoch".into(),
            epsilon_remaining: 0,
            delta_remaining: 0,
        },
        AccountantError::EpochNotAdvanced {
            current: SecurityEpoch::from_raw(1),
            proposed: SecurityEpoch::from_raw(1),
        },
        AccountantError::InvalidConsumption {
            reason: "neg".into(),
        },
        AccountantError::InvalidConfiguration {
            reason: "zero".into(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn accountant_error_serde_roundtrip() {
    let errors = vec![
        AccountantError::BudgetExhausted {
            dimension: "lifetime".into(),
            epsilon_remaining: -100,
            delta_remaining: -50,
        },
        AccountantError::EpochNotAdvanced {
            current: SecurityEpoch::from_raw(5),
            proposed: SecurityEpoch::from_raw(3),
        },
        AccountantError::InvalidConsumption {
            reason: "test".into(),
        },
        AccountantError::InvalidConfiguration {
            reason: "test".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: AccountantError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn accountant_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(AccountantError::InvalidConsumption {
        reason: "test".into(),
    });
    assert!(!e.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Composition methods
// ---------------------------------------------------------------------------

#[test]
fn advanced_composition_consumes_less_than_basic() {
    let mut basic = BudgetAccountant::new(test_config()).unwrap();
    let basic_rec = basic.consume(100_000, 10_000, "op", 2_000_000_000).unwrap();

    let mut advanced = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::Advanced,
        ..test_config()
    })
    .unwrap();
    let adv_rec = advanced.consume(100_000, 10_000, "op", 2_000_000_000).unwrap();

    // Advanced composition should give same or less epsilon
    assert!(adv_rec.composed_epsilon_millionths <= basic_rec.composed_epsilon_millionths);
}

#[test]
fn renyi_composition_consumes_less_than_basic() {
    let mut basic = BudgetAccountant::new(test_config()).unwrap();
    let basic_rec = basic.consume(100_000, 10_000, "op", 2_000_000_000).unwrap();

    let mut renyi = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::Renyi,
        ..test_config()
    })
    .unwrap();
    let renyi_rec = renyi.consume(100_000, 10_000, "op", 2_000_000_000).unwrap();

    assert!(renyi_rec.composed_epsilon_millionths <= basic_rec.composed_epsilon_millionths);
}

#[test]
fn zcdp_composition_consumes_less_than_basic() {
    let mut basic = BudgetAccountant::new(test_config()).unwrap();
    let basic_rec = basic.consume(100_000, 10_000, "op", 2_000_000_000).unwrap();

    let mut zcdp = BudgetAccountant::new(AccountantConfig {
        composition_method: CompositionMethod::ZeroCdp,
        ..test_config()
    })
    .unwrap();
    let zcdp_rec = zcdp.consume(100_000, 10_000, "op", 2_000_000_000).unwrap();

    assert!(zcdp_rec.composed_epsilon_millionths <= basic_rec.composed_epsilon_millionths);
}

// ---------------------------------------------------------------------------
// BudgetAccountant serde
// ---------------------------------------------------------------------------

#[test]
fn accountant_serde_roundtrip() {
    let mut acc = make_accountant();
    acc.consume(100_000, 10_000, "op1", 2_000_000_000).unwrap();
    let json = serde_json::to_string(&acc).unwrap();
    let back: BudgetAccountant = serde_json::from_str(&json).unwrap();
    assert_eq!(acc, back);
}
