//! Enrichment integration tests for the `obligation_channel` module.
//!
//! Exercises advanced lifecycle patterns, backpressure edge cases, leak
//! detection under stress, force-abort semantics, event ordering invariants,
//! serde fidelity, and deterministic replay guarantees.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
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
        "enrich-chan",
        "enrich-trace",
        ChannelConfig {
            max_pending,
            lab_mode,
        },
    )
}

// ===========================================================================
// Section 1: ObligationState
// ===========================================================================

#[test]
fn enrich_obligation_state_display_pending() {
    assert_eq!(ObligationState::Pending.to_string(), "pending");
}

#[test]
fn enrich_obligation_state_display_committed() {
    assert_eq!(ObligationState::Committed.to_string(), "committed");
}

#[test]
fn enrich_obligation_state_display_aborted() {
    assert_eq!(ObligationState::Aborted.to_string(), "aborted");
}

#[test]
fn enrich_obligation_state_display_leaked() {
    assert_eq!(ObligationState::Leaked.to_string(), "leaked");
}

#[test]
fn enrich_obligation_state_serde_roundtrip() {
    let states = [
        ObligationState::Pending,
        ObligationState::Committed,
        ObligationState::Aborted,
        ObligationState::Leaked,
    ];
    for s in &states {
        let json = serde_json::to_string(s).unwrap();
        let back: ObligationState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// Section 2: AbortReason
// ===========================================================================

#[test]
fn enrich_abort_reason_display_all_variants() {
    assert_eq!(AbortReason::DrainTimeout.to_string(), "drain_timeout");
    assert_eq!(AbortReason::UpstreamFailure.to_string(), "upstream_failure");
    assert_eq!(AbortReason::PolicyViolation.to_string(), "policy_violation");
    assert_eq!(AbortReason::OperatorAbort.to_string(), "operator_abort");
    assert_eq!(
        AbortReason::Custom("my-reason".into()).to_string(),
        "custom:my-reason"
    );
}

#[test]
fn enrich_abort_reason_serde_roundtrip() {
    let reasons = vec![
        AbortReason::DrainTimeout,
        AbortReason::UpstreamFailure,
        AbortReason::PolicyViolation,
        AbortReason::OperatorAbort,
        AbortReason::Custom("enrichment".into()),
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: AbortReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// Section 3: ObligationError
// ===========================================================================

#[test]
fn enrich_error_display_not_found() {
    let err = ObligationError::NotFound { obligation_id: 42 };
    assert_eq!(err.to_string(), "obligation 42 not found");
}

#[test]
fn enrich_error_display_already_resolved() {
    let err = ObligationError::AlreadyResolved { obligation_id: 7 };
    assert_eq!(err.to_string(), "obligation 7 already resolved");
}

#[test]
fn enrich_error_display_backpressure() {
    let err = ObligationError::Backpressure { max_pending: 128 };
    assert_eq!(err.to_string(), "backpressure: max 128 pending obligations");
}

#[test]
fn enrich_error_display_leaked() {
    let err = ObligationError::Leaked { obligation_id: 99 };
    assert_eq!(err.to_string(), "obligation 99 leaked");
}

#[test]
fn enrich_error_is_std_error() {
    let err: Box<dyn std::error::Error> =
        Box::new(ObligationError::NotFound { obligation_id: 1 });
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrich_error_serde_roundtrip_all() {
    let errors = vec![
        ObligationError::NotFound { obligation_id: 10 },
        ObligationError::AlreadyResolved { obligation_id: 20 },
        ObligationError::Backpressure { max_pending: 50 },
        ObligationError::Leaked { obligation_id: 30 },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: ObligationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// Section 4: ChannelConfig
// ===========================================================================

#[test]
fn enrich_channel_config_default() {
    let cfg = ChannelConfig::default();
    assert_eq!(cfg.max_pending, 256);
    assert!(!cfg.lab_mode);
}

#[test]
fn enrich_channel_config_serde_roundtrip() {
    let cfg = ChannelConfig {
        max_pending: 1024,
        lab_mode: true,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ChannelConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// Section 5: Channel construction
// ===========================================================================

#[test]
fn enrich_new_channel_defaults() {
    let chan = make_channel(10, false);
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), 0);
    assert_eq!(chan.leak_count(), 0);
    assert!(chan.drain_check());
    assert!(chan.oldest_pending().is_none());
    assert!(!chan.is_lab_mode());
    assert_eq!(chan.channel_id, "enrich-chan");
}

#[test]
fn enrich_new_channel_lab_mode() {
    let chan = make_channel(10, true);
    assert!(chan.is_lab_mode());
}

// ===========================================================================
// Section 6: Send lifecycle
// ===========================================================================

#[test]
fn enrich_send_sequential_ids() {
    let mut chan = make_channel(10, false);
    let ids: Vec<u64> = (0..5).map(|_| chan.send("t").unwrap()).collect();
    assert_eq!(ids, vec![1, 2, 3, 4, 5]);
}

#[test]
fn enrich_send_increments_pending_and_total() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    assert_eq!(chan.pending_count(), 2);
    assert_eq!(chan.total_count(), 2);
}

#[test]
fn enrich_send_with_tick() {
    let mut chan = make_channel(10, false);
    chan.set_tick(100);
    chan.send("t").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 100);
}

// ===========================================================================
// Section 7: Commit lifecycle
// ===========================================================================

#[test]
fn enrich_commit_decrements_pending() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "hash").unwrap();
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), 1);
}

#[test]
fn enrich_double_commit_fails() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h1").unwrap();
    let err = chan.commit(id, "h2").unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn enrich_commit_nonexistent_fails() {
    let mut chan = make_channel(10, false);
    let err = chan.commit(999, "h").unwrap_err();
    assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
}

// ===========================================================================
// Section 8: Abort lifecycle
// ===========================================================================

#[test]
fn enrich_abort_decrements_pending() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::UpstreamFailure, "h").unwrap();
    assert_eq!(chan.pending_count(), 0);
}

#[test]
fn enrich_abort_after_commit_fails() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let err = chan
        .abort(id, &AbortReason::DrainTimeout, "h2")
        .unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn enrich_commit_after_abort_fails() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::PolicyViolation, "h").unwrap();
    let err = chan.commit(id, "h2").unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

// ===========================================================================
// Section 9: Backpressure edge cases
// ===========================================================================

#[test]
fn enrich_backpressure_at_limit() {
    let mut chan = make_channel(2, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    let err = chan.send("t").unwrap_err();
    assert_eq!(err, ObligationError::Backpressure { max_pending: 2 });
}

#[test]
fn enrich_backpressure_clears_after_commit() {
    let mut chan = make_channel(1, false);
    let id = chan.send("t").unwrap();
    assert!(chan.send("t").is_err());
    chan.commit(id, "h").unwrap();
    assert!(chan.send("t").is_ok());
}

#[test]
fn enrich_backpressure_clears_after_abort() {
    let mut chan = make_channel(1, false);
    let id = chan.send("t").unwrap();
    assert!(chan.send("t").is_err());
    chan.abort(id, &AbortReason::DrainTimeout, "h").unwrap();
    assert!(chan.send("t").is_ok());
}

#[test]
fn enrich_backpressure_clears_after_leak() {
    let mut chan = make_channel(1, false);
    let id = chan.send("t").unwrap();
    assert!(chan.send("t").is_err());
    chan.mark_leaked(id).unwrap();
    assert!(chan.send("t").is_ok());
}

#[test]
fn enrich_zero_max_pending_blocks_all() {
    let mut chan = make_channel(0, false);
    let err = chan.send("t").unwrap_err();
    assert_eq!(err, ObligationError::Backpressure { max_pending: 0 });
}

// ===========================================================================
// Section 10: Leak tracking
// ===========================================================================

#[test]
fn enrich_mark_leaked_increments_leak_count() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.mark_leaked(id).unwrap();
    assert_eq!(chan.leak_count(), 1);
    assert_eq!(chan.pending_count(), 0);
}

#[test]
fn enrich_mark_leaked_committed_fails() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let err = chan.mark_leaked(id).unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn enrich_mark_leaked_nonexistent_fails() {
    let mut chan = make_channel(10, false);
    let err = chan.mark_leaked(999).unwrap_err();
    assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
}

#[test]
fn enrich_multiple_leaks() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("t").unwrap();
    let id2 = chan.send("t").unwrap();
    let id3 = chan.send("t").unwrap();
    chan.mark_leaked(id1).unwrap();
    chan.mark_leaked(id2).unwrap();
    chan.mark_leaked(id3).unwrap();
    assert_eq!(chan.leak_count(), 3);
    assert_eq!(chan.pending_count(), 0);
}

// ===========================================================================
// Section 11: oldest_pending
// ===========================================================================

#[test]
fn enrich_oldest_pending_returns_earliest_tick() {
    let mut chan = make_channel(10, false);
    chan.set_tick(200);
    chan.send("late").unwrap();
    chan.set_tick(100);
    chan.send("early").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 100);
}

#[test]
fn enrich_oldest_pending_skips_resolved() {
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
fn enrich_oldest_pending_none_when_all_resolved() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    assert!(chan.oldest_pending().is_none());
}

// ===========================================================================
// Section 12: drain_check
// ===========================================================================

#[test]
fn enrich_drain_check_true_empty() {
    let chan = make_channel(10, false);
    assert!(chan.drain_check());
}

#[test]
fn enrich_drain_check_false_with_pending() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    assert!(!chan.drain_check());
}

#[test]
fn enrich_drain_check_true_all_resolved() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("t").unwrap();
    let id2 = chan.send("t").unwrap();
    chan.commit(id1, "h").unwrap();
    chan.abort(id2, &AbortReason::OperatorAbort, "h").unwrap();
    assert!(chan.drain_check());
}

// ===========================================================================
// Section 13: force_abort_all_pending
// ===========================================================================

#[test]
fn enrich_force_abort_returns_count() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    let id3 = chan.send("t").unwrap();
    chan.commit(id3, "h").unwrap();
    let count = chan.force_abort_all_pending("forced");
    assert_eq!(count, 2);
    assert!(chan.drain_check());
}

#[test]
fn enrich_force_abort_empty_returns_zero() {
    let mut chan = make_channel(10, false);
    assert_eq!(chan.force_abort_all_pending("h"), 0);
}

#[test]
fn enrich_force_abort_allows_new_sends() {
    let mut chan = make_channel(2, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    assert!(chan.send("t").is_err());
    chan.force_abort_all_pending("h");
    assert!(chan.send("t").is_ok());
}

// ===========================================================================
// Section 14: Events
// ===========================================================================

#[test]
fn enrich_drain_events_returns_all_and_clears() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let events = chan.drain_events();
    assert_eq!(events.len(), 2);
    assert!(chan.drain_events().is_empty());
}

#[test]
fn enrich_event_send_is_pending() {
    let mut chan = make_channel(10, false);
    chan.send("creator-a").unwrap();
    let events = chan.drain_events();
    assert_eq!(events[0].state, ObligationState::Pending);
    assert!(events[0].resolution_type.is_none());
    assert!(events[0].evidence_hash.is_none());
}

#[test]
fn enrich_event_commit_has_hash() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.commit(id, "ev-42").unwrap();
    let events = chan.drain_events();
    let commit_ev = &events[1];
    assert_eq!(commit_ev.state, ObligationState::Committed);
    assert_eq!(commit_ev.resolution_type, Some("commit".into()));
    assert_eq!(commit_ev.evidence_hash, Some("ev-42".into()));
}

#[test]
fn enrich_event_abort_has_hash() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::PolicyViolation, "abort-hash")
        .unwrap();
    let events = chan.drain_events();
    let abort_ev = &events[1];
    assert_eq!(abort_ev.state, ObligationState::Aborted);
    assert_eq!(abort_ev.resolution_type, Some("abort".into()));
    assert_eq!(abort_ev.evidence_hash, Some("abort-hash".into()));
}

#[test]
fn enrich_event_leak_no_hash() {
    let mut chan = make_channel(10, false);
    let id = chan.send("t").unwrap();
    chan.mark_leaked(id).unwrap();
    let events = chan.drain_events();
    let leak_ev = &events[1];
    assert_eq!(leak_ev.state, ObligationState::Leaked);
    assert_eq!(leak_ev.resolution_type, Some("leak".into()));
    assert!(leak_ev.evidence_hash.is_none());
}

#[test]
fn enrich_events_carry_channel_and_trace_ids() {
    let mut chan =
        ObligationChannel::new("my-chan", "my-trace", ChannelConfig::default());
    chan.send("t").unwrap();
    let events = chan.drain_events();
    assert_eq!(events[0].channel_id, "my-chan");
    assert_eq!(events[0].trace_id, "my-trace");
}

#[test]
fn enrich_force_abort_events() {
    let mut chan = make_channel(10, false);
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    chan.drain_events(); // Clear send events.
    chan.force_abort_all_pending("forced");
    let events = chan.drain_events();
    assert_eq!(events.len(), 2);
    for ev in &events {
        assert_eq!(ev.state, ObligationState::Aborted);
        assert_eq!(ev.evidence_hash, Some("forced".into()));
    }
}

// ===========================================================================
// Section 15: ObligationRecord serde
// ===========================================================================

#[test]
fn enrich_obligation_record_serde_roundtrip() {
    let record = ObligationRecord {
        obligation_id: 42,
        created_at_tick: 1000,
        creator_trace_id: "trace-xyz".into(),
        state: ObligationState::Committed,
        resolution_evidence_hash: Some("hash-val".into()),
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: ObligationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ===========================================================================
// Section 16: ObligationEvent serde
// ===========================================================================

#[test]
fn enrich_obligation_event_serde_roundtrip() {
    let event = ObligationEvent {
        trace_id: "t".into(),
        channel_id: "c".into(),
        obligation_id: 5,
        state: ObligationState::Committed,
        resolution_type: Some("commit".into()),
        evidence_hash: Some("h".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ObligationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrich_obligation_event_serde_none_fields() {
    let event = ObligationEvent {
        trace_id: "t".into(),
        channel_id: "c".into(),
        obligation_id: 1,
        state: ObligationState::Pending,
        resolution_type: None,
        evidence_hash: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ObligationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// Section 17: Deterministic replay
// ===========================================================================

#[test]
fn enrich_deterministic_replay_events() {
    let run = || -> Vec<ObligationEvent> {
        let mut chan = make_channel(10, false);
        chan.set_tick(50);
        let id1 = chan.send("a").unwrap();
        chan.set_tick(100);
        let id2 = chan.send("b").unwrap();
        chan.commit(id1, "h1").unwrap();
        chan.abort(id2, &AbortReason::DrainTimeout, "h2").unwrap();
        chan.drain_events()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrich_deterministic_replay_ids() {
    let run = || -> Vec<u64> {
        let mut chan = make_channel(10, false);
        (0..5).map(|_| chan.send("t").unwrap()).collect()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Section 18: set_tick behavior
// ===========================================================================

#[test]
fn enrich_set_tick_affects_subsequent_sends() {
    let mut chan = make_channel(10, false);
    chan.set_tick(0);
    chan.send("t").unwrap();
    chan.set_tick(500);
    chan.send("t").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 0);
}

#[test]
fn enrich_set_tick_backward() {
    let mut chan = make_channel(10, false);
    chan.set_tick(1000);
    chan.send("late").unwrap();
    chan.set_tick(100);
    chan.send("early").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 100);
}

// ===========================================================================
// Section 19: Complex multi-obligation lifecycle
// ===========================================================================

#[test]
fn enrich_mixed_resolution_lifecycle() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("a").unwrap();
    let id2 = chan.send("b").unwrap();
    let id3 = chan.send("c").unwrap();
    let _id4 = chan.send("d").unwrap();

    chan.commit(id1, "h1").unwrap();
    chan.abort(id2, &AbortReason::OperatorAbort, "h2").unwrap();
    chan.mark_leaked(id3).unwrap();
    // id4 stays pending.

    assert_eq!(chan.pending_count(), 1);
    assert_eq!(chan.total_count(), 4);
    assert_eq!(chan.leak_count(), 1);
    assert!(!chan.drain_check());
}

#[test]
fn enrich_resolve_all_yields_drain_clean() {
    let mut chan = make_channel(10, false);
    let ids: Vec<u64> = (0..5).map(|_| chan.send("t").unwrap()).collect();
    for id in ids {
        chan.commit(id, "h").unwrap();
    }
    assert!(chan.drain_check());
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), 5);
}

// ===========================================================================
// Section 20: High-volume stress
// ===========================================================================

#[test]
fn enrich_high_volume_send_commit() {
    let mut chan = make_channel(200, false);
    let mut ids = Vec::new();
    for i in 0..200 {
        chan.set_tick(i as u64);
        ids.push(chan.send("bulk").unwrap());
    }
    assert_eq!(chan.pending_count(), 200);
    assert!(chan.send("overflow").is_err());

    for id in &ids {
        chan.commit(*id, "bulk-h").unwrap();
    }
    assert!(chan.drain_check());
    assert_eq!(chan.total_count(), 200);
}

#[test]
fn enrich_interleaved_send_resolve() {
    let mut chan = make_channel(5, false);
    let id1 = chan.send("t").unwrap();
    let id2 = chan.send("t").unwrap();
    chan.commit(id1, "h").unwrap();
    let id3 = chan.send("t").unwrap();
    chan.abort(id2, &AbortReason::UpstreamFailure, "h").unwrap();
    let id4 = chan.send("t").unwrap();
    chan.commit(id3, "h").unwrap();
    chan.commit(id4, "h").unwrap();
    assert!(chan.drain_check());
    assert_eq!(chan.total_count(), 4);
}

#[test]
fn enrich_events_order_matches_operations() {
    let mut chan = make_channel(10, false);
    let id1 = chan.send("a").unwrap();
    let id2 = chan.send("b").unwrap();
    chan.commit(id2, "h2").unwrap();
    chan.abort(id1, &AbortReason::PolicyViolation, "h1").unwrap();

    let events = chan.drain_events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].obligation_id, id1);
    assert_eq!(events[0].state, ObligationState::Pending);
    assert_eq!(events[1].obligation_id, id2);
    assert_eq!(events[1].state, ObligationState::Pending);
    assert_eq!(events[2].obligation_id, id2);
    assert_eq!(events[2].state, ObligationState::Committed);
    assert_eq!(events[3].obligation_id, id1);
    assert_eq!(events[3].state, ObligationState::Aborted);
}
