#![forbid(unsafe_code)]
//! Integration tests for QQ.3 (bd-cixqu.43.3): per-fleet privacy budget
//! tracking + refusal.
//!
//! Exercises the aggregator-side [`FleetPrivacyBudget`] over a full fleet
//! lifetime: rounds are admitted until the fleet-wide `(ε, δ)` budget is
//! exhausted, after which every further aggregation is refused (fail-closed).
//! Covers cohort sizes N ∈ {3, 7, 25}, every composition method, the cohort
//! floor and round-cap refusal paths, and ledger-integrity / audit-trail
//! invariants.

use frankenengine_engine::fleet_privacy_budget::{
    FleetBudgetConfig, FleetBudgetError, FleetBudgetEvent, FleetPrivacyBudget,
};
use frankenengine_engine::privacy_learning_contract::CompositionMethod;

fn config_with(
    method: CompositionMethod,
    epsilon_budget: i64,
    delta_budget: i64,
    min_participants: usize,
    max_rounds: u64,
) -> FleetBudgetConfig {
    FleetBudgetConfig {
        fleet_id: "fleet-integration".into(),
        lifetime_epsilon_budget_millionths: epsilon_budget,
        lifetime_delta_budget_millionths: delta_budget,
        composition_method: method,
        min_participants_per_round: min_participants,
        max_rounds,
    }
}

/// A fleet runs equal-cost rounds until it is refused; the refusal must land
/// exactly when the next round would cross the epsilon ceiling, and never
/// silently degrade.
#[test]
fn fleet_runs_until_budget_refuses() {
    // 10.5 epsilon budget, 1.0 per round under basic composition -> 10 rounds
    // admitted (cumulative 10.0), the 11th (would reach 11.0) refused on
    // epsilon. Budget is deliberately non-exact so the refusal reports the
    // epsilon dimension rather than the terminal latch from exact exhaustion.
    let mut budget = FleetPrivacyBudget::new(config_with(
        CompositionMethod::Basic,
        10_500_000,
        10_000_000,
        3,
        0,
    ))
    .unwrap();

    let mut admitted = 0u64;
    for round in 0..50u64 {
        match budget.try_admit_round(1_000_000, 100_000, 7, round) {
            Ok(receipt) => {
                admitted += 1;
                assert_eq!(receipt.entry.round_id, admitted);
            }
            Err(FleetBudgetError::Refused { dimension, .. }) => {
                assert_eq!(dimension, "epsilon");
                break;
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    assert_eq!(admitted, 10);
    assert!(budget.is_exhausted());
    // One round's cost (1.0) no longer fits in the 0.5 remaining.
    assert!(budget.epsilon_remaining_millionths() < 1_000_000);
    assert!(budget.verify_ledger_integrity().is_ok());
}

/// Once refused on budget grounds, the latch is terminal: no later round, no
/// matter how cheap, is admitted.
#[test]
fn refusal_is_permanent() {
    let mut budget = FleetPrivacyBudget::new(config_with(
        CompositionMethod::Basic,
        1_000_000,
        1_000_000,
        1,
        0,
    ))
    .unwrap();
    budget.try_admit_round(1_000_000, 100_000, 3, 0).unwrap();
    assert!(budget.is_exhausted());

    for round in 1..5u64 {
        let err = budget.try_admit_round(1, 1, 3, round).unwrap_err();
        assert!(matches!(err, FleetBudgetError::Refused { .. }));
    }
    assert_eq!(budget.rounds_admitted(), 1);
}

/// Cohort sizes N ∈ {3, 7, 25} are all admitted when above the floor and
/// recorded as counts only.
#[test]
fn cohort_sizes_3_7_25_recorded_as_counts() {
    for &n in &[3usize, 7, 25] {
        let mut budget = FleetPrivacyBudget::new(config_with(
            CompositionMethod::Basic,
            100_000_000,
            100_000_000,
            3,
            0,
        ))
        .unwrap();
        let receipt = budget.try_admit_round(1_000_000, 10_000, n, 1).unwrap();
        assert_eq!(receipt.entry.participant_count, n);

        // The audit event carries the count, nothing else identifying.
        match &budget.events()[0] {
            FleetBudgetEvent::RoundAdmitted {
                participant_count, ..
            } => assert_eq!(*participant_count, n),
            other => panic!("expected RoundAdmitted, got {other:?}"),
        }
    }
}

/// A cohort below the floor is refused without charging the budget, regardless
/// of how much budget remains.
#[test]
fn small_cohort_refused_even_with_budget_available() {
    let mut budget = FleetPrivacyBudget::new(config_with(
        CompositionMethod::Basic,
        100_000_000,
        100_000_000,
        7,
        0,
    ))
    .unwrap();

    for n in [1usize, 3, 6] {
        let err = budget.try_admit_round(1_000_000, 10_000, n, 1).unwrap_err();
        assert!(matches!(
            err,
            FleetBudgetError::InsufficientCohort { required: 7, .. }
        ));
    }
    // Budget untouched, latch not tripped.
    assert!(!budget.is_exhausted());
    assert_eq!(budget.rounds_admitted(), 0);
    assert_eq!(budget.epsilon_remaining_millionths(), 100_000_000);

    // At the floor it is admitted.
    assert!(budget.try_admit_round(1_000_000, 10_000, 7, 2).is_ok());
}

/// Advanced composition admits strictly more rounds than basic for the same
/// budget and per-round request, because each round after the first is charged
/// sub-linearly.
#[test]
fn advanced_composition_admits_more_rounds_than_basic() {
    let count_rounds = |method| {
        let mut budget =
            FleetPrivacyBudget::new(config_with(method, 10_000_000, 1_000_000_000, 1, 0)).unwrap();
        let mut n = 0u64;
        for round in 0..1000u64 {
            if budget.try_admit_round(1_000_000, 1_000, 3, round).is_ok() {
                n += 1;
            } else {
                break;
            }
        }
        n
    };

    let basic = count_rounds(CompositionMethod::Basic);
    let advanced = count_rounds(CompositionMethod::Advanced);
    assert_eq!(basic, 10);
    assert!(
        advanced > basic,
        "advanced composition should admit more rounds (basic={basic}, advanced={advanced})"
    );
}

/// The round cap refuses further aggregation even when budget remains, and the
/// cap refusal does not trip the (terminal) budget latch.
#[test]
fn round_cap_enforced_independently_of_budget() {
    let mut budget = FleetPrivacyBudget::new(config_with(
        CompositionMethod::Basic,
        1_000_000_000,
        1_000_000_000,
        1,
        3,
    ))
    .unwrap();

    for round in 0..3u64 {
        budget.try_admit_round(1_000, 1_000, 3, round).unwrap();
    }
    let err = budget.try_admit_round(1_000, 1_000, 3, 99).unwrap_err();
    assert!(matches!(
        err,
        FleetBudgetError::RoundCapReached { max_rounds: 3 }
    ));
    assert!(!budget.is_exhausted());
    assert!(budget.epsilon_remaining_millionths() > 0);
}

/// Over a long multi-round lifetime the recorded cumulative spend always
/// matches an independent recomputation from the ledger.
#[test]
fn ledger_integrity_over_long_lifetime() {
    let mut budget = FleetPrivacyBudget::new(config_with(
        CompositionMethod::Advanced,
        1_000_000_000,
        1_000_000_000,
        3,
        0,
    ))
    .unwrap();

    let mut now = 0u64;
    for i in 0..200u64 {
        now += 1_000;
        // Vary cohort size across {3, 7, 25} and cost a little each round.
        let n = [3usize, 7, 25][(i % 3) as usize];
        if budget.try_admit_round(200_000, 1_000, n, now).is_err() {
            break;
        }
    }

    assert!(budget.rounds_admitted() > 0);
    assert!(budget.verify_ledger_integrity().is_ok());

    // Independent recomputation of cumulative epsilon from charged amounts.
    let recomputed: i64 = budget
        .ledger()
        .iter()
        .map(|e| e.epsilon_charged_millionths)
        .sum();
    let last_cumulative = budget
        .ledger()
        .last()
        .unwrap()
        .cumulative_epsilon_millionths;
    assert_eq!(recomputed, last_cumulative);
}

/// Every admission and every refusal produces exactly one audit event, in
/// order, carrying only counts and `(ε, δ)` figures.
#[test]
fn audit_trail_records_every_decision() {
    let mut budget = FleetPrivacyBudget::new(config_with(
        CompositionMethod::Basic,
        3_000_000,
        3_000_000,
        3,
        0,
    ))
    .unwrap();

    // Three admits (1.0 each) then refusals.
    budget.try_admit_round(1_000_000, 100_000, 5, 1).unwrap();
    budget.try_admit_round(1_000_000, 100_000, 5, 2).unwrap();
    budget.try_admit_round(1_000_000, 100_000, 5, 3).unwrap();
    let _ = budget
        .try_admit_round(1_000_000, 100_000, 5, 4)
        .unwrap_err(); // refused
    let _ = budget
        .try_admit_round(1_000_000, 100_000, 2, 5)
        .unwrap_err(); // also refused (latched)

    let events = budget.events();
    assert_eq!(events.len(), 5);
    let admitted = events
        .iter()
        .filter(|e| matches!(e, FleetBudgetEvent::RoundAdmitted { .. }))
        .count();
    let refused = events
        .iter()
        .filter(|e| matches!(e, FleetBudgetEvent::RoundRefused { .. }))
        .count();
    assert_eq!(admitted, 3);
    assert_eq!(refused, 2);
}

/// Full state serializes and deserializes losslessly mid-lifetime — replayable
/// audit artifact.
#[test]
fn budget_state_round_trips_through_json() {
    let mut budget = FleetPrivacyBudget::new(config_with(
        CompositionMethod::Renyi,
        50_000_000,
        50_000_000,
        3,
        0,
    ))
    .unwrap();
    for round in 0..5u64 {
        budget.try_admit_round(1_000_000, 10_000, 7, round).unwrap();
    }

    let json = serde_json::to_string(&budget).unwrap();
    let restored: FleetPrivacyBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, restored);
    assert_eq!(restored.rounds_admitted(), 5);
    assert!(restored.verify_ledger_integrity().is_ok());
}
