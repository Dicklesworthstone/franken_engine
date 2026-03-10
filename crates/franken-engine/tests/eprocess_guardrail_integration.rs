#![forbid(unsafe_code)]

//! Integration tests for the `eprocess_guardrail` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! guardrail construction, e-value accumulation, threshold triggering,
//! reset/suspend/resume lifecycle, GuardrailRegistry operations,
//! error conditions, Display impls, serde round-trips, and deterministic
//! replay guarantees.

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

use frankenengine_engine::eprocess_guardrail::{
    EProcessGuardrail, GuardrailError, GuardrailEvent, GuardrailRegistry, GuardrailState,
    ResetReceipt, ThresholdLikelihoodRatio, UniversalLikelihoodRatio,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn blocked_set(actions: &[&str]) -> BTreeSet<String> {
    actions.iter().map(|s| (*s).to_string()).collect()
}

fn threshold_guardrail(
    id: &str,
    stream: &str,
    threshold: i64,
    blocked: &[&str],
) -> EProcessGuardrail {
    EProcessGuardrail::new(
        id,
        stream,
        "null hypothesis",
        threshold,
        blocked_set(blocked),
        SecurityEpoch::GENESIS,
        Box::new(ThresholdLikelihoodRatio {
            threshold_millionths: 10_000,     // 0.01
            high_ratio_millionths: 5_000_000, // 5.0
            low_ratio_millionths: 500_000,    // 0.5
        }),
    )
}

fn make_receipt(auth: &str, rationale: &str) -> ResetReceipt {
    ResetReceipt {
        authorized_by: auth.to_string(),
        rationale: rationale.to_string(),
        epoch: SecurityEpoch::from_raw(1),
    }
}

// ---------------------------------------------------------------------------
// 1. Construction
// ---------------------------------------------------------------------------

#[test]
fn new_guardrail_starts_active_with_e_value_one() {
    let gr = threshold_guardrail("g1", "metric", 20_000_000, &["low"]);
    assert_eq!(gr.state(), GuardrailState::Active);
    assert_eq!(gr.e_value(), 1_000_000); // 1.0
    assert_eq!(gr.observation_count(), 0);
    assert_eq!(gr.threshold(), 20_000_000);
    assert_eq!(gr.config_epoch(), SecurityEpoch::GENESIS);
    assert_eq!(gr.guardrail_id, "g1");
    assert_eq!(gr.metric_stream, "metric");
}

#[test]
fn blocked_actions_set_populated_at_construction() {
    let gr = threshold_guardrail("g1", "m", 20_000_000, &["low", "medium"]);
    let blocked = gr.blocked_actions();
    assert!(blocked.contains("low"));
    assert!(blocked.contains("medium"));
    assert!(!blocked.contains("high"));
}

// ---------------------------------------------------------------------------
// 2. E-value accumulation
// ---------------------------------------------------------------------------

#[test]
fn below_threshold_observation_shrinks_e_value() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    // obs = 5000 < threshold 10000 -> lr = 0.5
    // e_new = 1.0 * 0.5 = 0.5 (500_000 millionths)
    gr.update(5_000).unwrap();
    assert_eq!(gr.e_value(), 500_000);
    assert_eq!(gr.state(), GuardrailState::Active);
    assert_eq!(gr.observation_count(), 1);
}

#[test]
fn above_threshold_observation_grows_e_value() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    // obs = 15000 >= threshold 10000 -> lr = 5.0
    // e_new = 1.0 * 5.0 = 5.0 (5_000_000 millionths)
    gr.update(15_000).unwrap();
    assert_eq!(gr.e_value(), 5_000_000);
    assert_eq!(gr.state(), GuardrailState::Active);
}

#[test]
fn repeated_high_observations_trigger_guardrail() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(15_000).unwrap(); // e = 5.0
    assert_eq!(gr.state(), GuardrailState::Active);

    gr.update(15_000).unwrap(); // e = 25.0 >= 20.0
    assert_eq!(gr.state(), GuardrailState::Triggered);
    assert_eq!(gr.e_value(), 25_000_000);
}

#[test]
fn exact_threshold_triggers() {
    // Set threshold = 5.0 (5_000_000), so single high obs (lr=5.0) hits exactly.
    let mut gr = EProcessGuardrail::new(
        "exact",
        "m",
        "null",
        5_000_000,
        blocked_set(&["block"]),
        SecurityEpoch::GENESIS,
        Box::new(ThresholdLikelihoodRatio {
            threshold_millionths: 10_000,
            high_ratio_millionths: 5_000_000,
            low_ratio_millionths: 500_000,
        }),
    );
    gr.update(15_000).unwrap(); // e = 5.0 == threshold
    assert_eq!(gr.state(), GuardrailState::Triggered);
}

#[test]
fn mixed_observations_accumulate_correctly() {
    let mut gr = threshold_guardrail("g1", "m", 100_000_000, &["low"]);
    // low: e *= 0.5; high: e *= 5.0
    gr.update(5_000).unwrap(); // e = 0.5
    gr.update(15_000).unwrap(); // e = 2.5
    gr.update(5_000).unwrap(); // e = 1.25
    gr.update(15_000).unwrap(); // e = 6.25
    assert_eq!(gr.e_value(), 6_250_000);
    assert_eq!(gr.observation_count(), 4);
    assert_eq!(gr.state(), GuardrailState::Active);
}

// ---------------------------------------------------------------------------
// 3. Blocking semantics
// ---------------------------------------------------------------------------

#[test]
fn active_guardrail_blocks_nothing() {
    let gr = threshold_guardrail("g1", "m", 20_000_000, &["low", "medium"]);
    assert!(!gr.blocks("low"));
    assert!(!gr.blocks("medium"));
    assert!(!gr.blocks("high"));
}

#[test]
fn triggered_guardrail_blocks_specified_actions() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low", "medium"]);
    gr.update(15_000).unwrap();
    gr.update(15_000).unwrap(); // triggers

    assert!(gr.blocks("low"));
    assert!(gr.blocks("medium"));
    assert!(!gr.blocks("high"));
}

#[test]
fn suspended_guardrail_blocks_nothing() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.suspend("maintenance");
    assert!(!gr.blocks("low"));
}

// ---------------------------------------------------------------------------
// 4. Error conditions
// ---------------------------------------------------------------------------

#[test]
fn update_when_triggered_returns_error() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(15_000).unwrap();
    gr.update(15_000).unwrap(); // triggers

    let err = gr.update(15_000).unwrap_err();
    assert_eq!(
        err,
        GuardrailError::AlreadyTriggered {
            guardrail_id: "g1".to_string()
        }
    );
}

#[test]
fn update_when_suspended_returns_error() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.suspend("test");

    let err = gr.update(15_000).unwrap_err();
    assert_eq!(
        err,
        GuardrailError::Suspended {
            guardrail_id: "g1".to_string()
        }
    );
}

#[test]
fn reset_non_triggered_returns_error() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    let receipt = make_receipt("operator", "test");
    let err = gr.reset(&receipt).unwrap_err();
    assert_eq!(
        err,
        GuardrailError::NotTriggered {
            guardrail_id: "g1".to_string()
        }
    );
}

#[test]
fn reset_with_empty_auth_returns_error() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(15_000).unwrap();
    gr.update(15_000).unwrap(); // triggers

    let receipt = make_receipt("", "test");
    let err = gr.reset(&receipt).unwrap_err();
    assert_eq!(
        err,
        GuardrailError::ResetUnauthorized {
            guardrail_id: "g1".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// 5. Reset lifecycle
// ---------------------------------------------------------------------------

#[test]
fn reset_triggered_guardrail_restores_active() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(15_000).unwrap();
    gr.update(15_000).unwrap(); // triggers

    let receipt = make_receipt("operator-1", "addressed");
    gr.reset(&receipt).unwrap();

    assert_eq!(gr.state(), GuardrailState::Active);
    assert_eq!(gr.e_value(), 1_000_000); // reset to 1.0
    assert_eq!(gr.observation_count(), 0);
}

#[test]
fn can_accumulate_after_reset() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(15_000).unwrap();
    gr.update(15_000).unwrap(); // triggers

    let receipt = make_receipt("operator", "ok");
    gr.reset(&receipt).unwrap();

    // Should accept new observations.
    gr.update(15_000).unwrap();
    assert_eq!(gr.e_value(), 5_000_000);
    assert_eq!(gr.observation_count(), 1);
}

// ---------------------------------------------------------------------------
// 6. Suspend / Resume
// ---------------------------------------------------------------------------

#[test]
fn suspend_then_resume_restores_active() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(15_000).unwrap(); // e = 5.0
    gr.suspend("maintenance");
    assert_eq!(gr.state(), GuardrailState::Suspended);

    gr.resume();
    assert_eq!(gr.state(), GuardrailState::Active);
    // e-value preserved across suspend/resume.
    assert_eq!(gr.e_value(), 5_000_000);
}

#[test]
fn resume_when_not_suspended_is_no_op() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.resume(); // no-op, already Active
    assert_eq!(gr.state(), GuardrailState::Active);
}

// ---------------------------------------------------------------------------
// 7. Events
// ---------------------------------------------------------------------------

#[test]
fn update_emits_e_value_updated_event() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(5_000).unwrap();

    let events = gr.drain_events();
    assert_eq!(events.len(), 1);
    match &events[0] {
        GuardrailEvent::EValueUpdated {
            guardrail_id,
            previous_e_value,
            new_e_value,
            observation,
            likelihood_ratio,
        } => {
            assert_eq!(guardrail_id, "g1");
            assert_eq!(*previous_e_value, 1_000_000);
            assert_eq!(*new_e_value, 500_000);
            assert_eq!(*observation, 5_000);
            assert_eq!(*likelihood_ratio, 500_000);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn trigger_emits_triggered_event() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low", "medium"]);
    gr.update(15_000).unwrap();
    gr.update(15_000).unwrap(); // triggers

    let events = gr.drain_events();
    // 2 EValueUpdated + 1 Triggered
    assert_eq!(events.len(), 3);
    match &events[2] {
        GuardrailEvent::Triggered {
            guardrail_id,
            e_value,
            threshold,
            blocked_actions,
        } => {
            assert_eq!(guardrail_id, "g1");
            assert_eq!(*e_value, 25_000_000);
            assert_eq!(*threshold, 20_000_000);
            assert_eq!(blocked_actions.len(), 2);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn reset_emits_reset_event() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(15_000).unwrap();
    gr.update(15_000).unwrap();
    gr.drain_events(); // clear

    let receipt = make_receipt("operator", "addressed");
    gr.reset(&receipt).unwrap();

    let events = gr.drain_events();
    assert_eq!(events.len(), 1);
    match &events[0] {
        GuardrailEvent::Reset {
            guardrail_id,
            authorized_by,
            rationale,
            epoch,
        } => {
            assert_eq!(guardrail_id, "g1");
            assert_eq!(authorized_by, "operator");
            assert_eq!(rationale, "addressed");
            assert_eq!(*epoch, SecurityEpoch::from_raw(1));
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn suspend_emits_suspended_event() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.suspend("maintenance window");

    let events = gr.drain_events();
    assert_eq!(events.len(), 1);
    match &events[0] {
        GuardrailEvent::SuspendedEvent {
            guardrail_id,
            reason,
        } => {
            assert_eq!(guardrail_id, "g1");
            assert_eq!(reason, "maintenance window");
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn resume_emits_resumed_event() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.suspend("test");
    gr.drain_events(); // clear

    gr.resume();
    let events = gr.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], GuardrailEvent::Resumed { guardrail_id } if guardrail_id == "g1"));
}

#[test]
fn drain_events_clears_buffer() {
    let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
    gr.update(5_000).unwrap();
    let events1 = gr.drain_events();
    assert_eq!(events1.len(), 1);

    let events2 = gr.drain_events();
    assert!(events2.is_empty());
}

// ---------------------------------------------------------------------------
// 8. ThresholdLikelihoodRatio
// ---------------------------------------------------------------------------

#[test]
fn threshold_lr_below_threshold() {
    use frankenengine_engine::eprocess_guardrail::LikelihoodRatioFn;
    let lr = ThresholdLikelihoodRatio {
        threshold_millionths: 10_000,
        high_ratio_millionths: 5_000_000,
        low_ratio_millionths: 500_000,
    };
    assert_eq!(lr.ratio(9_999), Some(500_000));
    assert_eq!(lr.family(), "threshold");
}

#[test]
fn threshold_lr_at_threshold() {
    use frankenengine_engine::eprocess_guardrail::LikelihoodRatioFn;
    let lr = ThresholdLikelihoodRatio {
        threshold_millionths: 10_000,
        high_ratio_millionths: 5_000_000,
        low_ratio_millionths: 500_000,
    };
    // At exactly threshold -> high_ratio
    assert_eq!(lr.ratio(10_000), Some(5_000_000));
}

// ---------------------------------------------------------------------------
// 9. UniversalLikelihoodRatio
// ---------------------------------------------------------------------------

#[test]
fn universal_lr_computes_ratio() {
    use frankenengine_engine::eprocess_guardrail::LikelihoodRatioFn;
    let lr = UniversalLikelihoodRatio {
        null_mean_millionths: 500_000, // 0.5
    };
    // obs=1.0, ratio = 1.0/0.5 = 2.0
    assert_eq!(lr.ratio(1_000_000), Some(2_000_000));
    // obs=0.25, ratio = 0.25/0.5 = 0.5
    assert_eq!(lr.ratio(250_000), Some(500_000));
    assert_eq!(lr.family(), "universal");
}

#[test]
fn universal_lr_zero_mean_returns_none() {
    use frankenengine_engine::eprocess_guardrail::LikelihoodRatioFn;
    let lr = UniversalLikelihoodRatio {
        null_mean_millionths: 0,
    };
    assert_eq!(lr.ratio(1_000_000), None);
}

#[test]
fn universal_lr_guardrail_triggers() {
    let mut gr = EProcessGuardrail::new(
        "univ",
        "metric",
        "null",
        4_000_000, // threshold = 4.0
        blocked_set(&["action"]),
        SecurityEpoch::GENESIS,
        Box::new(UniversalLikelihoodRatio {
            null_mean_millionths: 500_000, // 0.5
        }),
    );
    // obs=1.0, ratio=2.0, e=2.0
    gr.update(1_000_000).unwrap();
    assert_eq!(gr.e_value(), 2_000_000);
    assert_eq!(gr.state(), GuardrailState::Active);

    // obs=1.0, ratio=2.0, e=4.0 >= threshold
    gr.update(1_000_000).unwrap();
    assert_eq!(gr.e_value(), 4_000_000);
    assert_eq!(gr.state(), GuardrailState::Triggered);
}

// ---------------------------------------------------------------------------
// 10. GuardrailRegistry
// ---------------------------------------------------------------------------

#[test]
fn empty_registry() {
    let registry = GuardrailRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert!(registry.blocked_actions().is_empty());
    assert!(!registry.is_blocked("anything"));
}

#[test]
fn registry_add_and_len() {
    let mut registry = GuardrailRegistry::new();
    registry.add(threshold_guardrail("g1", "m1", 20_000_000, &["low"]));
    registry.add(threshold_guardrail("g2", "m2", 20_000_000, &["medium"]));
    assert_eq!(registry.len(), 2);
    assert!(!registry.is_empty());
}

#[test]
fn registry_get_and_get_mut() {
    let mut registry = GuardrailRegistry::new();
    registry.add(threshold_guardrail("g1", "m1", 20_000_000, &["low"]));

    assert!(registry.get("g1").is_some());
    assert!(registry.get("nonexistent").is_none());
    assert!(registry.get_mut("g1").is_some());
    assert!(registry.get_mut("nonexistent").is_none());
}

#[test]
fn registry_blocked_actions_union() {
    let mut registry = GuardrailRegistry::new();

    // gr1 triggers immediately (threshold=5, lr=10x)
    let mut gr1 = EProcessGuardrail::new(
        "gr1",
        "m",
        "null",
        5_000_000,
        blocked_set(&["low"]),
        SecurityEpoch::GENESIS,
        Box::new(ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 10_000_000,
            low_ratio_millionths: 500_000,
        }),
    );
    gr1.update(1_000_000).unwrap(); // triggers

    // gr2 triggers immediately
    let mut gr2 = EProcessGuardrail::new(
        "gr2",
        "m",
        "null",
        5_000_000,
        blocked_set(&["medium"]),
        SecurityEpoch::GENESIS,
        Box::new(ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 10_000_000,
            low_ratio_millionths: 500_000,
        }),
    );
    gr2.update(1_000_000).unwrap(); // triggers

    registry.add(gr1);
    registry.add(gr2);

    let blocked = registry.blocked_actions();
    assert!(blocked.contains("low"));
    assert!(blocked.contains("medium"));
    assert!(!blocked.contains("high"));
}

#[test]
fn registry_is_blocked() {
    let mut registry = GuardrailRegistry::new();
    let mut gr = EProcessGuardrail::new(
        "gr1",
        "m",
        "null",
        5_000_000,
        blocked_set(&["low"]),
        SecurityEpoch::GENESIS,
        Box::new(ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 10_000_000,
            low_ratio_millionths: 500_000,
        }),
    );
    gr.update(1_000_000).unwrap(); // triggers
    registry.add(gr);

    assert!(registry.is_blocked("low"));
    assert!(!registry.is_blocked("high"));
}

#[test]
fn registry_blocking_guardrails() {
    let mut registry = GuardrailRegistry::new();
    let mut gr = EProcessGuardrail::new(
        "gr1",
        "m",
        "null",
        5_000_000,
        blocked_set(&["low"]),
        SecurityEpoch::GENESIS,
        Box::new(ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 10_000_000,
            low_ratio_millionths: 500_000,
        }),
    );
    gr.update(1_000_000).unwrap(); // triggers
    registry.add(gr);

    let blockers = registry.blocking_guardrails("low");
    assert_eq!(blockers, vec!["gr1".to_string()]);

    let blockers = registry.blocking_guardrails("high");
    assert!(blockers.is_empty());
}

#[test]
fn registry_permitted_actions() {
    let mut registry = GuardrailRegistry::new();
    let mut gr = EProcessGuardrail::new(
        "gr1",
        "m",
        "null",
        5_000_000,
        blocked_set(&["low"]),
        SecurityEpoch::GENESIS,
        Box::new(ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 10_000_000,
            low_ratio_millionths: 500_000,
        }),
    );
    gr.update(1_000_000).unwrap(); // triggers
    registry.add(gr);

    let all = vec!["low".to_string(), "medium".to_string(), "high".to_string()];
    let permitted = registry.permitted_actions(&all);
    assert_eq!(permitted.len(), 2);
    assert!(permitted.contains(&&"medium".to_string()));
    assert!(permitted.contains(&&"high".to_string()));
    assert!(!permitted.contains(&&"low".to_string()));
}

#[test]
fn registry_update_stream_targets_matching() {
    let mut registry = GuardrailRegistry::new();
    registry.add(threshold_guardrail("g1", "fnr", 100_000_000, &["low"]));
    registry.add(threshold_guardrail("g2", "fpr", 100_000_000, &["medium"]));

    let errors = registry.update_stream("fnr", 15_000);
    assert!(errors.is_empty());
    assert_eq!(registry.get("g1").unwrap().observation_count(), 1);
    assert_eq!(registry.get("g2").unwrap().observation_count(), 0);
}

#[test]
fn registry_update_stream_skips_non_active() {
    let mut registry = GuardrailRegistry::new();
    let mut gr = threshold_guardrail("g1", "fnr", 20_000_000, &["low"]);
    gr.suspend("test");
    registry.add(gr);

    let errors = registry.update_stream("fnr", 15_000);
    assert!(errors.is_empty());
    assert_eq!(registry.get("g1").unwrap().observation_count(), 0);
}

#[test]
fn registry_reset_all() {
    let mut registry = GuardrailRegistry::new();

    let mut gr1 = EProcessGuardrail::new(
        "gr1",
        "m",
        "null",
        5_000_000,
        blocked_set(&["low"]),
        SecurityEpoch::GENESIS,
        Box::new(ThresholdLikelihoodRatio {
            threshold_millionths: 0,
            high_ratio_millionths: 10_000_000,
            low_ratio_millionths: 500_000,
        }),
    );
    gr1.update(1_000_000).unwrap(); // triggers

    let gr2 = threshold_guardrail("gr2", "m2", 100_000_000, &["medium"]); // active

    registry.add(gr1);
    registry.add(gr2);

    let receipt = make_receipt("operator", "epoch transition");
    let errors = registry.reset_all(&receipt);
    assert!(errors.is_empty());

    // gr1 was triggered, now reset to active.
    assert_eq!(registry.get("gr1").unwrap().state(), GuardrailState::Active);
    // gr2 was already active, unchanged.
    assert_eq!(registry.get("gr2").unwrap().state(), GuardrailState::Active);
}

#[test]
fn registry_drain_all_events() {
    let mut registry = GuardrailRegistry::new();
    registry.add(threshold_guardrail("g1", "fnr", 100_000_000, &["low"]));
    registry.add(threshold_guardrail("g2", "fpr", 100_000_000, &["medium"]));

    registry.update_stream("fnr", 15_000);
    registry.update_stream("fpr", 5_000);

    let events = registry.drain_all_events();
    assert_eq!(events.len(), 2); // 1 update per guardrail

    // Second drain is empty.
    let events2 = registry.drain_all_events();
    assert!(events2.is_empty());
}

// ---------------------------------------------------------------------------
// 11. Display impls
// ---------------------------------------------------------------------------

#[test]
fn guardrail_state_display() {
    assert_eq!(GuardrailState::Active.to_string(), "active");
    assert_eq!(GuardrailState::Triggered.to_string(), "triggered");
    assert_eq!(GuardrailState::Suspended.to_string(), "suspended");
}

#[test]
fn guardrail_error_display_all_variants() {
    assert_eq!(
        GuardrailError::Suspended {
            guardrail_id: "g1".to_string()
        }
        .to_string(),
        "guardrail 'g1' is suspended"
    );
    assert_eq!(
        GuardrailError::AlreadyTriggered {
            guardrail_id: "g1".to_string()
        }
        .to_string(),
        "guardrail 'g1' already triggered"
    );
    assert_eq!(
        GuardrailError::InvalidObservation {
            guardrail_id: "g1".to_string()
        }
        .to_string(),
        "invalid observation for guardrail 'g1'"
    );
    assert_eq!(
        GuardrailError::ResetUnauthorized {
            guardrail_id: "g1".to_string()
        }
        .to_string(),
        "unauthorized reset for guardrail 'g1'"
    );
    assert_eq!(
        GuardrailError::NotTriggered {
            guardrail_id: "g1".to_string()
        }
        .to_string(),
        "guardrail 'g1' is not triggered"
    );
    assert_eq!(
        GuardrailError::EValueOverflow {
            guardrail_id: "g1".to_string()
        }
        .to_string(),
        "e-value overflow for guardrail 'g1'"
    );
}

#[test]
fn guardrail_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(GuardrailError::Suspended {
        guardrail_id: "g".to_string(),
    });
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// 12. Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn guardrail_state_serde_roundtrip() {
    let states = [
        GuardrailState::Active,
        GuardrailState::Triggered,
        GuardrailState::Suspended,
    ];
    for state in &states {
        let json = serde_json::to_string(state).expect("serialize");
        let restored: GuardrailState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*state, restored);
    }
}

#[test]
fn guardrail_error_serde_roundtrip() {
    let errors = vec![
        GuardrailError::Suspended {
            guardrail_id: "g".to_string(),
        },
        GuardrailError::AlreadyTriggered {
            guardrail_id: "g".to_string(),
        },
        GuardrailError::InvalidObservation {
            guardrail_id: "g".to_string(),
        },
        GuardrailError::ResetUnauthorized {
            guardrail_id: "g".to_string(),
        },
        GuardrailError::NotTriggered {
            guardrail_id: "g".to_string(),
        },
        GuardrailError::EValueOverflow {
            guardrail_id: "g".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: GuardrailError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

#[test]
fn reset_receipt_serde_roundtrip() {
    let receipt = ResetReceipt {
        authorized_by: "operator-42".to_string(),
        rationale: "epoch transition".to_string(),
        epoch: SecurityEpoch::from_raw(7),
    };
    let json = serde_json::to_string(&receipt).expect("serialize");
    let restored: ResetReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, restored);
}

#[test]
fn guardrail_event_serde_roundtrip_all_variants() {
    let events = vec![
        GuardrailEvent::EValueUpdated {
            guardrail_id: "g".to_string(),
            previous_e_value: 1_000_000,
            new_e_value: 5_000_000,
            observation: 15_000,
            likelihood_ratio: 5_000_000,
        },
        GuardrailEvent::Triggered {
            guardrail_id: "g".to_string(),
            e_value: 25_000_000,
            threshold: 20_000_000,
            blocked_actions: vec!["low".to_string(), "medium".to_string()],
        },
        GuardrailEvent::Reset {
            guardrail_id: "g".to_string(),
            authorized_by: "op".to_string(),
            rationale: "ok".to_string(),
            epoch: SecurityEpoch::GENESIS,
        },
        GuardrailEvent::SuspendedEvent {
            guardrail_id: "g".to_string(),
            reason: "maintenance".to_string(),
        },
        GuardrailEvent::Resumed {
            guardrail_id: "g".to_string(),
        },
    ];
    for event in &events {
        let json = serde_json::to_string(event).expect("serialize");
        let restored: GuardrailEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, restored);
    }
}

#[test]
fn threshold_lr_serde_roundtrip() {
    let lr = ThresholdLikelihoodRatio {
        threshold_millionths: 10_000,
        high_ratio_millionths: 5_000_000,
        low_ratio_millionths: 500_000,
    };
    let json = serde_json::to_string(&lr).expect("serialize");
    let restored: ThresholdLikelihoodRatio = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(lr.threshold_millionths, restored.threshold_millionths);
    assert_eq!(lr.high_ratio_millionths, restored.high_ratio_millionths);
    assert_eq!(lr.low_ratio_millionths, restored.low_ratio_millionths);
}

#[test]
fn universal_lr_serde_roundtrip() {
    let lr = UniversalLikelihoodRatio {
        null_mean_millionths: 500_000,
    };
    let json = serde_json::to_string(&lr).expect("serialize");
    let restored: UniversalLikelihoodRatio = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(lr.null_mean_millionths, restored.null_mean_millionths);
}

// ---------------------------------------------------------------------------
// 13. Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_same_trigger_point() {
    let observations = vec![5_000i64, 15_000, 5_000, 15_000, 15_000, 15_000];

    let run = |obs: &[i64]| -> (u64, i64, GuardrailState) {
        let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
        for &o in obs {
            if gr.state() == GuardrailState::Triggered {
                break;
            }
            let _ = gr.update(o);
        }
        (gr.observation_count(), gr.e_value(), gr.state())
    };

    let (count1, ev1, state1) = run(&observations);
    let (count2, ev2, state2) = run(&observations);
    assert_eq!(count1, count2);
    assert_eq!(ev1, ev2);
    assert_eq!(state1, state2);
}

#[test]
fn deterministic_replay_events_identical() {
    let run = || -> Vec<GuardrailEvent> {
        let mut gr = threshold_guardrail("g1", "m", 20_000_000, &["low"]);
        gr.update(15_000).unwrap();
        gr.update(15_000).unwrap();
        gr.drain_events()
    };

    let events1 = run();
    let events2 = run();
    assert_eq!(events1, events2);
}
