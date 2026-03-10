//! Enrichment integration tests for `eprocess_guardrail`.
//!
//! Covers: JSON field-name stability, serde roundtrips, Display exact values,
//! Debug distinctness, GuardrailState/GuardrailError/GuardrailEvent variants,
//! ThresholdLikelihoodRatio/UniversalLikelihoodRatio semantics,
//! EProcessGuardrail lifecycle (new/update/trigger/reset/suspend/resume),
//! GuardrailRegistry (add/is_blocked/blocked_actions/permitted_actions/
//! update_stream/drain_all_events/get/reset_all), and ResetReceipt.

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

use frankenengine_engine::eprocess_guardrail::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ────────────────────────────────────────────────────────────

fn test_blocked() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert("low".to_string());
    s.insert("medium".to_string());
    s
}

fn test_threshold_lr() -> Box<ThresholdLikelihoodRatio> {
    Box::new(ThresholdLikelihoodRatio {
        threshold_millionths: 10_000,
        high_ratio_millionths: 5_000_000,
        low_ratio_millionths: 500_000,
    })
}

fn test_guardrail() -> EProcessGuardrail {
    EProcessGuardrail::new(
        "fnr-guard",
        "false_negative_rate",
        "false-negative rate <= 0.01",
        20_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    )
}

fn test_receipt() -> ResetReceipt {
    ResetReceipt {
        authorized_by: "operator-1".to_string(),
        rationale: "epoch transition".to_string(),
        epoch: SecurityEpoch::from_raw(2),
    }
}

// ── GuardrailState ─────────────────────────────────────────────────────

#[test]
fn guardrail_state_display_active() {
    assert_eq!(GuardrailState::Active.to_string(), "active");
}
#[test]
fn guardrail_state_display_triggered() {
    assert_eq!(GuardrailState::Triggered.to_string(), "triggered");
}
#[test]
fn guardrail_state_display_suspended() {
    assert_eq!(GuardrailState::Suspended.to_string(), "suspended");
}

#[test]
fn guardrail_state_debug_distinct() {
    let states = [
        GuardrailState::Active,
        GuardrailState::Triggered,
        GuardrailState::Suspended,
    ];
    let dbgs: BTreeSet<String> = states.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(dbgs.len(), 3);
}

#[test]
fn guardrail_state_serde_roundtrip() {
    for state in [
        GuardrailState::Active,
        GuardrailState::Triggered,
        GuardrailState::Suspended,
    ] {
        let json = serde_json::to_vec(&state).unwrap();
        let back: GuardrailState = serde_json::from_slice(&json).unwrap();
        assert_eq!(state, back);
    }
}

// ── ThresholdLikelihoodRatio ───────────────────────────────────────────

#[test]
fn threshold_lr_above_threshold() {
    let lr = ThresholdLikelihoodRatio {
        threshold_millionths: 1_000_000,
        high_ratio_millionths: 5_000_000,
        low_ratio_millionths: 500_000,
    };
    assert_eq!(lr.ratio(1_000_000), Some(5_000_000));
    assert_eq!(lr.ratio(2_000_000), Some(5_000_000));
}

#[test]
fn threshold_lr_below_threshold() {
    let lr = ThresholdLikelihoodRatio {
        threshold_millionths: 1_000_000,
        high_ratio_millionths: 5_000_000,
        low_ratio_millionths: 500_000,
    };
    assert_eq!(lr.ratio(999_999), Some(500_000));
}

#[test]
fn threshold_lr_family() {
    let lr = ThresholdLikelihoodRatio {
        threshold_millionths: 0,
        high_ratio_millionths: 0,
        low_ratio_millionths: 0,
    };
    assert_eq!(lr.family(), "threshold");
}

#[test]
fn threshold_lr_json_fields() {
    let lr = ThresholdLikelihoodRatio {
        threshold_millionths: 10_000,
        high_ratio_millionths: 5_000_000,
        low_ratio_millionths: 500_000,
    };
    let v: serde_json::Value = serde_json::to_value(&lr).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("threshold_millionths"));
    assert!(obj.contains_key("high_ratio_millionths"));
    assert!(obj.contains_key("low_ratio_millionths"));
}

#[test]
fn threshold_lr_serde_roundtrip() {
    let lr = ThresholdLikelihoodRatio {
        threshold_millionths: 10_000,
        high_ratio_millionths: 5_000_000,
        low_ratio_millionths: 500_000,
    };
    let json = serde_json::to_vec(&lr).unwrap();
    let back: ThresholdLikelihoodRatio = serde_json::from_slice(&json).unwrap();
    assert_eq!(lr.threshold_millionths, back.threshold_millionths);
    assert_eq!(lr.high_ratio_millionths, back.high_ratio_millionths);
    assert_eq!(lr.low_ratio_millionths, back.low_ratio_millionths);
}

// ── UniversalLikelihoodRatio ───────────────────────────────────────────

#[test]
fn universal_lr_computes_ratio() {
    let lr = UniversalLikelihoodRatio {
        null_mean_millionths: 1_000_000,
    };
    // observation = 2.0 => ratio = 2.0
    assert_eq!(lr.ratio(2_000_000), Some(2_000_000));
}

#[test]
fn universal_lr_zero_mean_returns_none() {
    let lr = UniversalLikelihoodRatio {
        null_mean_millionths: 0,
    };
    assert_eq!(lr.ratio(1_000_000), None);
}

#[test]
fn universal_lr_family() {
    let lr = UniversalLikelihoodRatio {
        null_mean_millionths: 1,
    };
    assert_eq!(lr.family(), "universal");
}

#[test]
fn universal_lr_serde_roundtrip() {
    let lr = UniversalLikelihoodRatio {
        null_mean_millionths: 500_000,
    };
    let json = serde_json::to_vec(&lr).unwrap();
    let back: UniversalLikelihoodRatio = serde_json::from_slice(&json).unwrap();
    assert_eq!(lr.null_mean_millionths, back.null_mean_millionths);
}

// ── GuardrailError ─────────────────────────────────────────────────────

#[test]
fn guardrail_error_display_suspended() {
    let e = GuardrailError::Suspended {
        guardrail_id: "g1".to_string(),
    };
    assert_eq!(e.to_string(), "guardrail 'g1' is suspended");
}

#[test]
fn guardrail_error_display_already_triggered() {
    let e = GuardrailError::AlreadyTriggered {
        guardrail_id: "g2".to_string(),
    };
    assert_eq!(e.to_string(), "guardrail 'g2' already triggered");
}

#[test]
fn guardrail_error_display_invalid_observation() {
    let e = GuardrailError::InvalidObservation {
        guardrail_id: "g3".to_string(),
    };
    assert_eq!(e.to_string(), "invalid observation for guardrail 'g3'");
}

#[test]
fn guardrail_error_display_reset_unauthorized() {
    let e = GuardrailError::ResetUnauthorized {
        guardrail_id: "g4".to_string(),
    };
    assert_eq!(e.to_string(), "unauthorized reset for guardrail 'g4'");
}

#[test]
fn guardrail_error_display_not_triggered() {
    let e = GuardrailError::NotTriggered {
        guardrail_id: "g5".to_string(),
    };
    assert_eq!(e.to_string(), "guardrail 'g5' is not triggered");
}

#[test]
fn guardrail_error_display_overflow() {
    let e = GuardrailError::EValueOverflow {
        guardrail_id: "g6".to_string(),
    };
    assert_eq!(e.to_string(), "e-value overflow for guardrail 'g6'");
}

#[test]
fn guardrail_error_is_std_error() {
    let e = GuardrailError::Suspended {
        guardrail_id: "x".to_string(),
    };
    let err: &dyn std::error::Error = &e;
    assert!(!err.to_string().is_empty());
}

#[test]
fn guardrail_error_debug_all_distinct() {
    let variants: Vec<GuardrailError> = vec![
        GuardrailError::Suspended {
            guardrail_id: "a".to_string(),
        },
        GuardrailError::AlreadyTriggered {
            guardrail_id: "a".to_string(),
        },
        GuardrailError::InvalidObservation {
            guardrail_id: "a".to_string(),
        },
        GuardrailError::ResetUnauthorized {
            guardrail_id: "a".to_string(),
        },
        GuardrailError::NotTriggered {
            guardrail_id: "a".to_string(),
        },
        GuardrailError::EValueOverflow {
            guardrail_id: "a".to_string(),
        },
    ];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 6);
}

#[test]
fn guardrail_error_serde_roundtrip_all() {
    let variants = vec![
        GuardrailError::Suspended {
            guardrail_id: "a".to_string(),
        },
        GuardrailError::AlreadyTriggered {
            guardrail_id: "b".to_string(),
        },
        GuardrailError::InvalidObservation {
            guardrail_id: "c".to_string(),
        },
        GuardrailError::ResetUnauthorized {
            guardrail_id: "d".to_string(),
        },
        GuardrailError::NotTriggered {
            guardrail_id: "e".to_string(),
        },
        GuardrailError::EValueOverflow {
            guardrail_id: "f".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_vec(v).unwrap();
        let back: GuardrailError = serde_json::from_slice(&json).unwrap();
        assert_eq!(v, &back);
    }
}

// ── ResetReceipt ───────────────────────────────────────────────────────

#[test]
fn reset_receipt_json_fields() {
    let r = test_receipt();
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("authorized_by"));
    assert!(obj.contains_key("rationale"));
    assert!(obj.contains_key("epoch"));
}

#[test]
fn reset_receipt_serde_roundtrip() {
    let r = test_receipt();
    let json = serde_json::to_vec(&r).unwrap();
    let back: ResetReceipt = serde_json::from_slice(&json).unwrap();
    assert_eq!(r, back);
}

// ── GuardrailEvent ─────────────────────────────────────────────────────

#[test]
fn guardrail_event_serde_roundtrip_updated() {
    let ev = GuardrailEvent::EValueUpdated {
        guardrail_id: "g1".to_string(),
        previous_e_value: 1_000_000,
        new_e_value: 5_000_000,
        observation: 2_000_000,
        likelihood_ratio: 5_000_000,
    };
    let json = serde_json::to_vec(&ev).unwrap();
    let back: GuardrailEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn guardrail_event_serde_roundtrip_triggered() {
    let ev = GuardrailEvent::Triggered {
        guardrail_id: "g1".to_string(),
        e_value: 25_000_000,
        threshold: 20_000_000,
        blocked_actions: vec!["low".to_string()],
    };
    let json = serde_json::to_vec(&ev).unwrap();
    let back: GuardrailEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn guardrail_event_serde_roundtrip_reset() {
    let ev = GuardrailEvent::Reset {
        guardrail_id: "g1".to_string(),
        authorized_by: "op".to_string(),
        rationale: "safe".to_string(),
        epoch: SecurityEpoch::from_raw(3),
    };
    let json = serde_json::to_vec(&ev).unwrap();
    let back: GuardrailEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn guardrail_event_serde_roundtrip_suspended() {
    let ev = GuardrailEvent::SuspendedEvent {
        guardrail_id: "g1".to_string(),
        reason: "maintenance".to_string(),
    };
    let json = serde_json::to_vec(&ev).unwrap();
    let back: GuardrailEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn guardrail_event_serde_roundtrip_resumed() {
    let ev = GuardrailEvent::Resumed {
        guardrail_id: "g1".to_string(),
    };
    let json = serde_json::to_vec(&ev).unwrap();
    let back: GuardrailEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(ev, back);
}

// ── EProcessGuardrail lifecycle ────────────────────────────────────────

#[test]
fn guardrail_starts_active_with_e_value_one() {
    let gr = test_guardrail();
    assert_eq!(gr.state(), GuardrailState::Active);
    assert_eq!(gr.e_value(), 1_000_000);
    assert_eq!(gr.observation_count(), 0);
}

#[test]
fn guardrail_update_below_threshold() {
    let mut gr = test_guardrail();
    // observation below threshold => low_ratio = 0.5
    gr.update(5_000).unwrap(); // below 10_000
    assert_eq!(gr.state(), GuardrailState::Active);
    assert_eq!(gr.e_value(), 500_000); // 1.0 * 0.5
    assert_eq!(gr.observation_count(), 1);
}

#[test]
fn guardrail_update_triggers() {
    let mut gr = EProcessGuardrail::new(
        "test",
        "metric",
        "null",
        5_000_000, // threshold = 5.0
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    // observation above threshold => high_ratio = 5.0, e = 1.0 * 5.0 = 5.0 >= 5.0
    gr.update(100_000).unwrap();
    assert_eq!(gr.state(), GuardrailState::Triggered);
}

#[test]
fn guardrail_blocks_action_when_triggered() {
    let mut gr = EProcessGuardrail::new(
        "test",
        "metric",
        "null",
        5_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    assert!(!gr.blocks("low"));
    gr.update(100_000).unwrap();
    assert!(gr.blocks("low"));
    assert!(gr.blocks("medium"));
    assert!(!gr.blocks("high"));
}

#[test]
fn guardrail_update_on_triggered_returns_error() {
    let mut gr = EProcessGuardrail::new(
        "test",
        "metric",
        "null",
        5_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr.update(100_000).unwrap();
    assert!(matches!(
        gr.update(100_000),
        Err(GuardrailError::AlreadyTriggered { .. })
    ));
}

#[test]
fn guardrail_suspend_and_resume() {
    let mut gr = test_guardrail();
    gr.suspend("maintenance");
    assert_eq!(gr.state(), GuardrailState::Suspended);
    assert!(matches!(
        gr.update(100_000),
        Err(GuardrailError::Suspended { .. })
    ));
    gr.resume();
    assert_eq!(gr.state(), GuardrailState::Active);
    gr.update(5_000).unwrap(); // should work again
}

#[test]
fn guardrail_reset_from_triggered() {
    let mut gr = EProcessGuardrail::new(
        "test",
        "metric",
        "null",
        5_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr.update(100_000).unwrap();
    assert_eq!(gr.state(), GuardrailState::Triggered);
    gr.reset(&test_receipt()).unwrap();
    assert_eq!(gr.state(), GuardrailState::Active);
    assert_eq!(gr.e_value(), 1_000_000);
    assert_eq!(gr.observation_count(), 0);
}

#[test]
fn guardrail_reset_not_triggered_returns_error() {
    let mut gr = test_guardrail();
    assert!(matches!(
        gr.reset(&test_receipt()),
        Err(GuardrailError::NotTriggered { .. })
    ));
}

#[test]
fn guardrail_reset_unauthorized_returns_error() {
    let mut gr = EProcessGuardrail::new(
        "test",
        "metric",
        "null",
        5_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr.update(100_000).unwrap();
    let bad_receipt = ResetReceipt {
        authorized_by: "".to_string(),
        rationale: "x".to_string(),
        epoch: SecurityEpoch::from_raw(2),
    };
    assert!(matches!(
        gr.reset(&bad_receipt),
        Err(GuardrailError::ResetUnauthorized { .. })
    ));
}

#[test]
fn guardrail_drain_events() {
    let mut gr = test_guardrail();
    gr.update(5_000).unwrap();
    let events = gr.drain_events();
    assert!(!events.is_empty());
    assert!(matches!(&events[0], GuardrailEvent::EValueUpdated { .. }));
    let events2 = gr.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn guardrail_config_epoch() {
    let gr = test_guardrail();
    assert_eq!(gr.config_epoch(), SecurityEpoch::GENESIS);
}

#[test]
fn guardrail_threshold() {
    let gr = test_guardrail();
    assert_eq!(gr.threshold(), 20_000_000);
}

// ── GuardrailRegistry ──────────────────────────────────────────────────

#[test]
fn registry_starts_empty() {
    let reg = GuardrailRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn registry_add_and_len() {
    let mut reg = GuardrailRegistry::new();
    reg.add(test_guardrail());
    assert_eq!(reg.len(), 1);
    assert!(!reg.is_empty());
}

#[test]
fn registry_is_blocked_when_triggered() {
    let mut reg = GuardrailRegistry::new();
    let mut gr = EProcessGuardrail::new(
        "test",
        "metric",
        "null",
        5_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr.update(100_000).unwrap();
    reg.add(gr);
    assert!(reg.is_blocked("low"));
    assert!(reg.is_blocked("medium"));
    assert!(!reg.is_blocked("high"));
}

#[test]
fn registry_blocked_actions_union() {
    let mut reg = GuardrailRegistry::new();
    let mut blocked1 = BTreeSet::new();
    blocked1.insert("action-a".to_string());
    let mut gr1 = EProcessGuardrail::new(
        "g1",
        "m",
        "n",
        5_000_000,
        blocked1,
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr1.update(100_000).unwrap();

    let mut blocked2 = BTreeSet::new();
    blocked2.insert("action-b".to_string());
    let mut gr2 = EProcessGuardrail::new(
        "g2",
        "m",
        "n",
        5_000_000,
        blocked2,
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr2.update(100_000).unwrap();

    reg.add(gr1);
    reg.add(gr2);
    let blocked = reg.blocked_actions();
    assert!(blocked.contains("action-a"));
    assert!(blocked.contains("action-b"));
}

#[test]
fn registry_blocking_guardrails() {
    let mut reg = GuardrailRegistry::new();
    let mut gr = EProcessGuardrail::new(
        "g1",
        "m",
        "n",
        5_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr.update(100_000).unwrap();
    reg.add(gr);
    let blockers = reg.blocking_guardrails("low");
    assert_eq!(blockers, vec!["g1".to_string()]);
}

#[test]
fn registry_permitted_actions() {
    let mut reg = GuardrailRegistry::new();
    let mut gr = EProcessGuardrail::new(
        "g1",
        "m",
        "n",
        5_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr.update(100_000).unwrap();
    reg.add(gr);
    let all = vec!["low".to_string(), "medium".to_string(), "high".to_string()];
    let permitted = reg.permitted_actions(&all);
    assert_eq!(permitted.len(), 1);
    assert_eq!(*permitted[0], "high");
}

#[test]
fn registry_update_stream_targets_matching() {
    let mut reg = GuardrailRegistry::new();
    reg.add(EProcessGuardrail::new(
        "g1",
        "stream-a",
        "n",
        20_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    ));
    reg.add(EProcessGuardrail::new(
        "g2",
        "stream-b",
        "n",
        20_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    ));
    let errors = reg.update_stream("stream-a", 5_000);
    assert!(errors.is_empty());
    // g1 was updated, g2 was not
    assert_eq!(reg.get("g1").unwrap().observation_count(), 1);
    assert_eq!(reg.get("g2").unwrap().observation_count(), 0);
}

#[test]
fn registry_drain_all_events() {
    let mut reg = GuardrailRegistry::new();
    reg.add(test_guardrail());
    reg.update_stream("false_negative_rate", 5_000);
    let events = reg.drain_all_events();
    assert!(!events.is_empty());
    let events2 = reg.drain_all_events();
    assert!(events2.is_empty());
}

#[test]
fn registry_get_and_get_mut() {
    let mut reg = GuardrailRegistry::new();
    reg.add(test_guardrail());
    assert!(reg.get("fnr-guard").is_some());
    assert!(reg.get("nonexistent").is_none());
    assert!(reg.get_mut("fnr-guard").is_some());
}

#[test]
fn registry_reset_all_triggered() {
    let mut reg = GuardrailRegistry::new();
    let mut gr1 = EProcessGuardrail::new(
        "g1",
        "m",
        "n",
        5_000_000,
        test_blocked(),
        SecurityEpoch::GENESIS,
        test_threshold_lr(),
    );
    gr1.update(100_000).unwrap();
    let gr2 = test_guardrail(); // not triggered
    reg.add(gr1);
    reg.add(gr2);
    let errors = reg.reset_all(&test_receipt());
    assert!(errors.is_empty());
    assert_eq!(reg.get("g1").unwrap().state(), GuardrailState::Active);
    // g2 wasn't triggered so wasn't reset (stays active)
    assert_eq!(
        reg.get("fnr-guard").unwrap().state(),
        GuardrailState::Active
    );
}

#[test]
fn registry_default_is_empty() {
    let reg = GuardrailRegistry::default();
    assert!(reg.is_empty());
}
