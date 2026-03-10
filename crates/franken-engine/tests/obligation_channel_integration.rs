//! Integration tests for the `obligation_channel` module.
//!
//! Exercises the public API from outside the crate: Display impls,
//! construction/defaults, send/commit/abort lifecycle, backpressure,
//! leak detection, drain semantics, force-abort, event emission,
//! serde round-trips, deterministic replay, and edge cases.

#![forbid(unsafe_code)]
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

use frankenengine_engine::obligation_channel::{
    AbortReason, ChannelConfig, ObligationChannel, ObligationError, ObligationEvent,
    ObligationRecord, ObligationState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_channel(max_pending: usize, lab_mode: bool) -> ObligationChannel {
    ObligationChannel::new(
        "test-chan",
        "test-trace",
        ChannelConfig {
            max_pending,
            lab_mode,
        },
    )
}

fn default_channel() -> ObligationChannel {
    ObligationChannel::new("chan-default", "trace-default", ChannelConfig::default())
}

// ---------------------------------------------------------------------------
// 1. ObligationState — Display
// ---------------------------------------------------------------------------

#[test]
fn obligation_state_display_all_variants() {
    assert_eq!(ObligationState::Pending.to_string(), "pending");
    assert_eq!(ObligationState::Committed.to_string(), "committed");
    assert_eq!(ObligationState::Aborted.to_string(), "aborted");
    assert_eq!(ObligationState::Leaked.to_string(), "leaked");
}

#[test]
fn obligation_state_serde_round_trip_all_variants() {
    let states = [
        ObligationState::Pending,
        ObligationState::Committed,
        ObligationState::Aborted,
        ObligationState::Leaked,
    ];
    for s in &states {
        let json = serde_json::to_string(s).unwrap();
        let decoded: ObligationState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, decoded);
    }
}

#[test]
fn obligation_state_clone_and_copy() {
    let s = ObligationState::Pending;
    let s2 = s;
    assert_eq!(s, s2);
}

// ---------------------------------------------------------------------------
// 2. AbortReason — Display
// ---------------------------------------------------------------------------

#[test]
fn abort_reason_display_all_variants() {
    assert_eq!(AbortReason::DrainTimeout.to_string(), "drain_timeout");
    assert_eq!(AbortReason::UpstreamFailure.to_string(), "upstream_failure");
    assert_eq!(AbortReason::PolicyViolation.to_string(), "policy_violation");
    assert_eq!(AbortReason::OperatorAbort.to_string(), "operator_abort");
    assert_eq!(
        AbortReason::Custom("timeout-42".into()).to_string(),
        "custom:timeout-42"
    );
}

#[test]
fn abort_reason_custom_empty_string() {
    assert_eq!(AbortReason::Custom(String::new()).to_string(), "custom:");
}

#[test]
fn abort_reason_serde_round_trip_all_variants() {
    let reasons = vec![
        AbortReason::DrainTimeout,
        AbortReason::UpstreamFailure,
        AbortReason::PolicyViolation,
        AbortReason::OperatorAbort,
        AbortReason::Custom("my-reason".into()),
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let decoded: AbortReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, decoded);
    }
}

// ---------------------------------------------------------------------------
// 3. ObligationError — Display and std::error::Error
// ---------------------------------------------------------------------------

#[test]
fn obligation_error_display_not_found() {
    let err = ObligationError::NotFound { obligation_id: 42 };
    assert_eq!(err.to_string(), "obligation 42 not found");
}

#[test]
fn obligation_error_display_already_resolved() {
    let err = ObligationError::AlreadyResolved { obligation_id: 7 };
    assert_eq!(err.to_string(), "obligation 7 already resolved");
}

#[test]
fn obligation_error_display_backpressure() {
    let err = ObligationError::Backpressure { max_pending: 256 };
    assert_eq!(err.to_string(), "backpressure: max 256 pending obligations");
}

#[test]
fn obligation_error_display_leaked() {
    let err = ObligationError::Leaked { obligation_id: 99 };
    assert_eq!(err.to_string(), "obligation 99 leaked");
}

#[test]
fn obligation_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ObligationError::NotFound { obligation_id: 1 });
    assert!(err.to_string().contains("not found"));
}

#[test]
fn obligation_error_serde_round_trip_all_variants() {
    let errors = vec![
        ObligationError::NotFound { obligation_id: 1 },
        ObligationError::AlreadyResolved { obligation_id: 2 },
        ObligationError::Backpressure { max_pending: 100 },
        ObligationError::Leaked { obligation_id: 3 },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let decoded: ObligationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, decoded);
    }
}

// ---------------------------------------------------------------------------
// 4. ChannelConfig — defaults and serde
// ---------------------------------------------------------------------------

#[test]
fn channel_config_default_values() {
    let cfg = ChannelConfig::default();
    assert_eq!(cfg.max_pending, 256);
    assert!(!cfg.lab_mode);
}

#[test]
fn channel_config_serde_round_trip() {
    let cfg = ChannelConfig {
        max_pending: 512,
        lab_mode: true,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: ChannelConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

#[test]
fn channel_config_default_serde_round_trip() {
    let cfg = ChannelConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: ChannelConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

// ---------------------------------------------------------------------------
// 5. ObligationChannel — construction
// ---------------------------------------------------------------------------

#[test]
fn new_channel_has_zero_pending() {
    let chan = default_channel();
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), 0);
    assert_eq!(chan.leak_count(), 0);
}

#[test]
fn new_channel_drain_check_true() {
    let chan = default_channel();
    assert!(chan.drain_check());
}

#[test]
fn new_channel_oldest_pending_is_none() {
    let chan = default_channel();
    assert!(chan.oldest_pending().is_none());
}

#[test]
fn new_channel_lab_mode_off_by_default() {
    let chan = default_channel();
    assert!(!chan.is_lab_mode());
}

#[test]
fn new_channel_lab_mode_on() {
    let chan = make_channel(10, true);
    assert!(chan.is_lab_mode());
}

#[test]
fn new_channel_id_accessible() {
    let chan = default_channel();
    assert_eq!(chan.channel_id, "chan-default");
}

// ---------------------------------------------------------------------------
// 6. send — creates pending obligations
// ---------------------------------------------------------------------------

#[test]
fn send_returns_sequential_ids() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("creator-a").unwrap();
    let id2 = chan.send("creator-b").unwrap();
    let id3 = chan.send("creator-c").unwrap();
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(id3, 3);
}

#[test]
fn send_increments_pending_count() {
    let mut chan = make_channel(10, false);
    assert_eq!(chan.pending_count(), 0);
    chan.send("t").unwrap();
    assert_eq!(chan.pending_count(), 1);
    chan.send("t").unwrap();
    assert_eq!(chan.pending_count(), 2);
}

#[test]
fn send_increments_total_count() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    assert_eq!(chan.total_count(), 2);
}

#[test]
fn send_records_tick() {
    let mut chan = make_channel(10, false);
    chan.set_tick(42);
    chan.send("t").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 42);
}

// ---------------------------------------------------------------------------
// 7. commit — resolves pending obligation
// ---------------------------------------------------------------------------

#[test]
fn commit_decrements_pending_count() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    assert_eq!(chan.pending_count(), 1);
    chan.commit(id, "evidence-hash").unwrap();
    assert_eq!(chan.pending_count(), 0);
}

#[test]
fn commit_does_not_decrement_total_count() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    assert_eq!(chan.total_count(), 1);
}

#[test]
fn double_commit_returns_already_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let err = chan.commit(id, "h2").unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn commit_nonexistent_returns_not_found() {
    let mut chan = make_channel(10, false);
    let err = chan.commit(999, "h").unwrap_err();
    assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
}

// ---------------------------------------------------------------------------
// 8. abort — resolves pending obligation
// ---------------------------------------------------------------------------

#[test]
fn abort_decrements_pending_count() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::UpstreamFailure, "h").unwrap();
    assert_eq!(chan.pending_count(), 0);
}

#[test]
fn abort_does_not_decrement_total_count() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::DrainTimeout, "h").unwrap();
    assert_eq!(chan.total_count(), 1);
}

#[test]
fn double_abort_returns_already_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::DrainTimeout, "h").unwrap();
    let err = chan
        .abort(id, &AbortReason::DrainTimeout, "h2")
        .unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn abort_nonexistent_returns_not_found() {
    let mut chan = make_channel(10, false);
    let err = chan
        .abort(999, &AbortReason::OperatorAbort, "h")
        .unwrap_err();
    assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
}

#[test]
fn commit_after_abort_returns_already_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::PolicyViolation, "h").unwrap();
    let err = chan.commit(id, "h2").unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn abort_after_commit_returns_already_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let err = chan
        .abort(id, &AbortReason::OperatorAbort, "h2")
        .unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

// ---------------------------------------------------------------------------
// 9. Backpressure
// ---------------------------------------------------------------------------

#[test]
fn backpressure_at_limit() {
    let mut chan = make_channel(3, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    let err = chan.send("t").unwrap_err();
    assert_eq!(err, ObligationError::Backpressure { max_pending: 3 });
}

#[test]
fn backpressure_clears_after_commit() {
    let mut chan = make_channel(2, false);
    let id1 = chan.send("t").unwrap();
    chan.send("t").unwrap();
    assert!(chan.send("t").is_err());
    chan.commit(id1, "h").unwrap();
    // Now one slot freed.
    let id3 = chan.send("t").unwrap();
    assert!(id3 > 0);
}

#[test]
fn backpressure_clears_after_abort() {
    let mut chan = make_channel(1, false);
    let id1 = chan.send("t").unwrap();
    assert!(chan.send("t").is_err());
    chan.abort(id1, &AbortReason::UpstreamFailure, "h").unwrap();
    assert!(chan.send("t").is_ok());
}

#[test]
fn backpressure_clears_after_leak() {
    let mut chan = make_channel(1, false);
    let id1 = chan.send("t").unwrap();
    assert!(chan.send("t").is_err());
    chan.mark_leaked(id1).unwrap();
    assert!(chan.send("t").is_ok());
}

#[test]
fn backpressure_limit_one() {
    let mut chan = make_channel(1, false);
    chan.send("t").unwrap();
    let err = chan.send("t").unwrap_err();
    assert_eq!(err, ObligationError::Backpressure { max_pending: 1 });
}

// ---------------------------------------------------------------------------
// 10. mark_leaked
// ---------------------------------------------------------------------------

#[test]
fn mark_leaked_increments_leak_count() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.mark_leaked(id).unwrap();
    assert_eq!(chan.leak_count(), 1);
}

#[test]
fn mark_leaked_decrements_pending_count() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.mark_leaked(id).unwrap();
    assert_eq!(chan.pending_count(), 0);
}

#[test]
fn mark_leaked_nonexistent_returns_not_found() {
    let mut chan = make_channel(10, false);
    let err = chan.mark_leaked(999).unwrap_err();
    assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
}

#[test]
fn mark_leaked_already_committed_returns_already_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let err = chan.mark_leaked(id).unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn mark_leaked_already_aborted_returns_already_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::DrainTimeout, "h").unwrap();
    let err = chan.mark_leaked(id).unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn mark_leaked_already_leaked_returns_already_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.mark_leaked(id).unwrap();
    let err = chan.mark_leaked(id).unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn multiple_leaks_tracked() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("t").unwrap();
    let id2 = chan.send("t").unwrap();
    chan.mark_leaked(id1).unwrap();
    chan.mark_leaked(id2).unwrap();
    assert_eq!(chan.leak_count(), 2);
}

// ---------------------------------------------------------------------------
// 11. oldest_pending
// ---------------------------------------------------------------------------

#[test]
fn oldest_pending_returns_earliest_by_tick() {
    let mut chan = make_channel(10, false);
    chan.set_tick(100);
    chan.send("early").unwrap();
    chan.set_tick(200);
    chan.send("late").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 100);
    assert_eq!(oldest.creator_trace_id, "early");
}

#[test]
fn oldest_pending_skips_resolved() {
    let mut chan = make_channel(10, false);
    chan.set_tick(10);
    let id1 = chan.send("first").unwrap();
    chan.set_tick(20);
    chan.send("second").unwrap();
    chan.commit(id1, "h").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 20);
}

#[test]
fn oldest_pending_none_when_all_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    assert!(chan.oldest_pending().is_none());
}

// ---------------------------------------------------------------------------
// 12. drain_check
// ---------------------------------------------------------------------------

#[test]
fn drain_check_true_on_empty_channel() {
    let chan = make_channel(10, false);
    assert!(chan.drain_check());
}

#[test]
fn drain_check_false_with_pending() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    assert!(!chan.drain_check());
}

#[test]
fn drain_check_true_after_all_resolved() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("t").unwrap();
    let id2 = chan.send("t").unwrap();
    chan.commit(id1, "h").unwrap();
    chan.abort(id2, &AbortReason::OperatorAbort, "h").unwrap();
    assert!(chan.drain_check());
}

// ---------------------------------------------------------------------------
// 13. force_abort_all_pending
// ---------------------------------------------------------------------------

#[test]
fn force_abort_all_pending_returns_count() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    let id3 = chan.send("t").unwrap();
    chan.commit(id3, "h").unwrap(); // One resolved.
    let count = chan.force_abort_all_pending("forced-hash");
    assert_eq!(count, 2);
}

#[test]
fn force_abort_all_pending_leaves_drain_clean() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    chan.force_abort_all_pending("timeout");
    assert!(chan.drain_check());
    assert_eq!(chan.pending_count(), 0);
}

#[test]
fn force_abort_all_pending_on_empty_returns_zero() {
    let mut chan = make_channel(10, false);
    let count = chan.force_abort_all_pending("h");
    assert_eq!(count, 0);
}

#[test]
fn force_abort_all_pending_preserves_committed() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("t").unwrap();
    chan.send("t").unwrap();
    chan.commit(id1, "h").unwrap();
    chan.force_abort_all_pending("timeout");
    // Total is still 2 (1 committed + 1 force-aborted).
    assert_eq!(chan.total_count(), 2);
    assert_eq!(chan.pending_count(), 0);
}

// ---------------------------------------------------------------------------
// 14. drain_events
// ---------------------------------------------------------------------------

#[test]
fn drain_events_returns_all_events() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let events = chan.drain_events();
    assert_eq!(events.len(), 2);
}

#[test]
fn drain_events_clears_buffer() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    let events1 = chan.drain_events();
    assert_eq!(events1.len(), 1);
    let events2 = chan.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn events_carry_correct_channel_and_trace_ids() {
    let mut chan = ObligationChannel::new("my-channel", "my-trace", ChannelConfig::default());
    chan.send("creator-x").unwrap();
    let events = chan.drain_events();
    assert_eq!(events[0].channel_id, "my-channel");
    assert_eq!(events[0].trace_id, "my-trace");
}

#[test]
fn event_pending_has_no_resolution_type() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    let events = chan.drain_events();
    assert_eq!(events[0].state, ObligationState::Pending);
    assert!(events[0].resolution_type.is_none());
    assert!(events[0].evidence_hash.is_none());
}

#[test]
fn event_commit_has_resolution_type_and_hash() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "ev-hash-42").unwrap();
    let events = chan.drain_events();
    let commit_event = &events[1];
    assert_eq!(commit_event.state, ObligationState::Committed);
    assert_eq!(commit_event.resolution_type, Some("commit".into()));
    assert_eq!(commit_event.evidence_hash, Some("ev-hash-42".into()));
}

#[test]
fn event_abort_has_resolution_type_and_hash() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::PolicyViolation, "abort-hash")
        .unwrap();
    let events = chan.drain_events();
    let abort_event = &events[1];
    assert_eq!(abort_event.state, ObligationState::Aborted);
    assert_eq!(abort_event.resolution_type, Some("abort".into()));
    assert_eq!(abort_event.evidence_hash, Some("abort-hash".into()));
}

#[test]
fn event_leak_has_resolution_type_no_hash() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.mark_leaked(id).unwrap();
    let events = chan.drain_events();
    let leak_event = &events[1];
    assert_eq!(leak_event.state, ObligationState::Leaked);
    assert_eq!(leak_event.resolution_type, Some("leak".into()));
    assert!(leak_event.evidence_hash.is_none());
}

#[test]
fn events_from_force_abort_all_pending() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    chan.drain_events(); // Clear send events.
    chan.force_abort_all_pending("forced");
    let events = chan.drain_events();
    assert_eq!(events.len(), 2);
    for ev in &events {
        assert_eq!(ev.state, ObligationState::Aborted);
        assert_eq!(ev.resolution_type, Some("abort".into()));
        assert_eq!(ev.evidence_hash, Some("forced".into()));
    }
}

// ---------------------------------------------------------------------------
// 15. ObligationRecord — serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn obligation_record_serde_pending() {
    let record = ObligationRecord {
        obligation_id: 1,
        created_at_tick: 0,
        creator_trace_id: "trace-abc".into(),
        state: ObligationState::Pending,
        resolution_evidence_hash: None,
    };
    let json = serde_json::to_string(&record).unwrap();
    let decoded: ObligationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
}

#[test]
fn obligation_record_serde_committed_with_hash() {
    let record = ObligationRecord {
        obligation_id: 42,
        created_at_tick: 1000,
        creator_trace_id: "trace-xyz".into(),
        state: ObligationState::Committed,
        resolution_evidence_hash: Some("hash-value".into()),
    };
    let json = serde_json::to_string(&record).unwrap();
    let decoded: ObligationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
}

// ---------------------------------------------------------------------------
// 16. ObligationEvent — serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn obligation_event_serde_round_trip() {
    let event = ObligationEvent {
        trace_id: "trace-1".into(),
        channel_id: "chan-1".into(),
        obligation_id: 5,
        state: ObligationState::Committed,
        resolution_type: Some("commit".into()),
        evidence_hash: Some("ev-h".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: ObligationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn obligation_event_serde_with_none_fields() {
    let event = ObligationEvent {
        trace_id: "t".into(),
        channel_id: "c".into(),
        obligation_id: 1,
        state: ObligationState::Pending,
        resolution_type: None,
        evidence_hash: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: ObligationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ---------------------------------------------------------------------------
// 17. Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_event_sequence_two_runs() {
    let run = || -> Vec<ObligationEvent> {
        let mut chan = make_channel(10, false);
        chan.set_tick(100);
        let id1 = chan.send("a").unwrap();
        chan.set_tick(200);
        let id2 = chan.send("b").unwrap();
        chan.set_tick(300);
        let id3 = chan.send("c").unwrap();
        chan.commit(id1, "h1").unwrap();
        chan.abort(id2, &AbortReason::DrainTimeout, "h2").unwrap();
        chan.mark_leaked(id3).unwrap();
        chan.drain_events()
    };
    let events1 = run();
    let events2 = run();
    assert_eq!(events1, events2);
}

#[test]
fn deterministic_ids_across_runs() {
    let run = || -> Vec<u64> {
        let mut chan = make_channel(10, false);
        let id1 = chan.send("t").unwrap();
        let id2 = chan.send("t").unwrap();
        let id3 = chan.send("t").unwrap();
        vec![id1, id2, id3]
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_pending_count_across_runs() {
    let run = || -> usize {
        let mut chan = make_channel(10, false);
        chan.send("t").unwrap();
        chan.send("t").unwrap();
        let id3 = chan.send("t").unwrap();
        chan.commit(id3, "h").unwrap();
        chan.pending_count()
    };
    assert_eq!(run(), run());
    assert_eq!(run(), 2);
}

// ---------------------------------------------------------------------------
// 18. set_tick
// ---------------------------------------------------------------------------

#[test]
fn set_tick_affects_subsequent_sends() {
    let mut chan = make_channel(10, false);
    chan.set_tick(0);
    chan.send("t").unwrap();
    chan.set_tick(1000);
    chan.send("t").unwrap();
    let _events = chan.drain_events();
    // Both events record the tick via obligation_id lookup.
    // We verify indirectly through oldest_pending.
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 0);
}

#[test]
fn set_tick_can_go_backward() {
    // Virtual clock can be set freely.
    let mut chan = make_channel(10, false);
    chan.set_tick(1000);
    chan.send("t").unwrap();
    chan.set_tick(500); // backward
    chan.send("t").unwrap();
    // oldest_pending should be tick 500 (second send, but lower tick).
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 500);
}

// ---------------------------------------------------------------------------
// 19. Multiple independent obligations
// ---------------------------------------------------------------------------

#[test]
fn multiple_obligations_independent_lifecycle() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("a").unwrap();
    let id2 = chan.send("b").unwrap();
    let id3 = chan.send("c").unwrap();
    let _id4 = chan.send("d").unwrap();

    chan.commit(id1, "h1").unwrap();
    chan.abort(id2, &AbortReason::OperatorAbort, "h2").unwrap();
    chan.mark_leaked(id3).unwrap();
    // id4 remains pending.

    assert_eq!(chan.pending_count(), 1);
    assert_eq!(chan.total_count(), 4);
    assert_eq!(chan.leak_count(), 1);
    assert!(!chan.drain_check());
}

#[test]
fn resolve_all_yields_drain_clean() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("a").unwrap();
    let id2 = chan.send("b").unwrap();
    let id3 = chan.send("c").unwrap();
    chan.commit(id1, "h1").unwrap();
    chan.commit(id2, "h2").unwrap();
    chan.commit(id3, "h3").unwrap();
    assert!(chan.drain_check());
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), 3);
}

// ---------------------------------------------------------------------------
// 20. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn high_volume_send_and_resolve() {
    let mut chan = make_channel(500, false);
    let mut ids = Vec::new();
    for i in 0..500 {
        chan.set_tick(i as u64);
        ids.push(chan.send("bulk").unwrap());
    }
    assert_eq!(chan.pending_count(), 500);
    // Backpressure at 500.
    assert!(chan.send("overflow").is_err());

    // Resolve all.
    for id in &ids {
        chan.commit(*id, "bulk-h").unwrap();
    }
    assert!(chan.drain_check());
    assert_eq!(chan.total_count(), 500);
}

#[test]
fn interleaved_send_and_commit() {
    let mut chan = make_channel(5, false);
    let id1 = chan.send("t").unwrap();
    let id2 = chan.send("t").unwrap();
    chan.commit(id1, "h").unwrap();
    let id3 = chan.send("t").unwrap();
    chan.commit(id2, "h").unwrap();
    let id4 = chan.send("t").unwrap();
    chan.commit(id3, "h").unwrap();
    chan.commit(id4, "h").unwrap();
    assert!(chan.drain_check());
    assert_eq!(chan.total_count(), 4);
}

#[test]
fn force_abort_then_send_new() {
    let mut chan = make_channel(3, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    assert!(chan.send("t").is_err()); // At limit.
    chan.force_abort_all_pending("timeout");
    // Now can send again.
    let id = chan.send("post-abort").unwrap();
    assert!(id > 3);
    assert_eq!(chan.pending_count(), 1);
}

#[test]
fn events_order_matches_operation_order() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("a").unwrap();
    let id2 = chan.send("b").unwrap();
    chan.commit(id2, "h2").unwrap();
    chan.abort(id1, &AbortReason::PolicyViolation, "h1")
        .unwrap();
    let events = chan.drain_events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].obligation_id, id1); // send id1
    assert_eq!(events[0].state, ObligationState::Pending);
    assert_eq!(events[1].obligation_id, id2); // send id2
    assert_eq!(events[1].state, ObligationState::Pending);
    assert_eq!(events[2].obligation_id, id2); // commit id2
    assert_eq!(events[2].state, ObligationState::Committed);
    assert_eq!(events[3].obligation_id, id1); // abort id1
    assert_eq!(events[3].state, ObligationState::Aborted);
}

#[test]
fn different_abort_reasons_all_work() {
    let reasons = vec![
        AbortReason::DrainTimeout,
        AbortReason::UpstreamFailure,
        AbortReason::PolicyViolation,
        AbortReason::OperatorAbort,
        AbortReason::Custom("custom-reason".into()),
    ];
    let mut chan = make_channel(10, false);
    for reason in &reasons {
        let id = chan.send("t").unwrap();
        chan.abort(id, reason, "h").unwrap();
    }
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), reasons.len());
}

#[test]
fn channel_config_zero_max_pending_blocks_all_sends() {
    let mut chan = make_channel(0, false);
    let err = chan.send("t").unwrap_err();
    assert_eq!(err, ObligationError::Backpressure { max_pending: 0 });
}
