//! Enrichment integration tests for `obligation_channel`.
//!
//! Covers: serde round-trips for all types, ObligationChannel lifecycle,
//! backpressure, leak detection, force-abort, drain semantics, event
//! emission, deterministic replay, Display implementations, clone
//! independence, and boundary conditions.

#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::obligation_channel::{
    AbortReason, ChannelConfig, ObligationChannel, ObligationError, ObligationEvent,
    ObligationRecord, ObligationState,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn test_channel() -> ObligationChannel {
    ObligationChannel::new(
        "chan-test",
        "trace-test",
        ChannelConfig {
            max_pending: 10,
            lab_mode: false,
        },
    )
}

// ===========================================================================
// Serde round-trip tests
// ===========================================================================

#[test]
fn integ_obligation_state_serde_all_variants() {
    for state in [
        ObligationState::Pending,
        ObligationState::Committed,
        ObligationState::Aborted,
        ObligationState::Leaked,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: ObligationState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

#[test]
fn integ_abort_reason_serde_all_variants() {
    let reasons = [
        AbortReason::DrainTimeout,
        AbortReason::UpstreamFailure,
        AbortReason::PolicyViolation,
        AbortReason::OperatorAbort,
        AbortReason::Custom("custom-reason".to_string()),
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: AbortReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn integ_obligation_error_serde_all_variants() {
    let errors = [
        ObligationError::NotFound { obligation_id: 1 },
        ObligationError::AlreadyResolved { obligation_id: 2 },
        ObligationError::Backpressure { max_pending: 10 },
        ObligationError::Leaked { obligation_id: 3 },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ObligationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn integ_obligation_record_serde_roundtrip() {
    let record = ObligationRecord {
        obligation_id: 42,
        created_at_tick: 100,
        creator_trace_id: "trace-abc".to_string(),
        state: ObligationState::Committed,
        resolution_evidence_hash: Some("hash-xyz".to_string()),
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: ObligationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn integ_obligation_event_serde_roundtrip() {
    let event = ObligationEvent {
        trace_id: "t".to_string(),
        channel_id: "c".to_string(),
        obligation_id: 7,
        state: ObligationState::Aborted,
        resolution_type: Some("abort".to_string()),
        evidence_hash: Some("ev-hash".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ObligationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn integ_channel_config_serde_roundtrip() {
    let cfg = ChannelConfig {
        max_pending: 128,
        lab_mode: true,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ChannelConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// Display tests
// ===========================================================================

#[test]
fn integ_obligation_state_display_all_unique() {
    let states = [
        ObligationState::Pending,
        ObligationState::Committed,
        ObligationState::Aborted,
        ObligationState::Leaked,
    ];
    let mut displays = BTreeSet::new();
    for s in &states {
        displays.insert(s.to_string());
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn integ_abort_reason_display_all_unique() {
    let reasons = [
        AbortReason::DrainTimeout,
        AbortReason::UpstreamFailure,
        AbortReason::PolicyViolation,
        AbortReason::OperatorAbort,
        AbortReason::Custom("test".to_string()),
    ];
    let mut displays = BTreeSet::new();
    for r in &reasons {
        displays.insert(r.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn integ_obligation_error_display_all_unique() {
    let errors = [
        ObligationError::NotFound { obligation_id: 1 },
        ObligationError::AlreadyResolved { obligation_id: 2 },
        ObligationError::Backpressure { max_pending: 10 },
        ObligationError::Leaked { obligation_id: 3 },
    ];
    let mut displays = BTreeSet::new();
    for e in &errors {
        displays.insert(e.to_string());
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn integ_obligation_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ObligationError::NotFound { obligation_id: 1 });
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

// ===========================================================================
// Channel lifecycle tests
// ===========================================================================

#[test]
fn integ_send_creates_pending_obligation() {
    let mut chan = test_channel();
    let id = chan.send("trace-a").unwrap();
    assert_eq!(id, 1);
    assert_eq!(chan.pending_count(), 1);
    assert_eq!(chan.total_count(), 1);
}

#[test]
fn integ_sequential_sends_increment_ids() {
    let mut chan = test_channel();
    let id1 = chan.send("t").unwrap();
    let id2 = chan.send("t").unwrap();
    let id3 = chan.send("t").unwrap();
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(id3, 3);
}

#[test]
fn integ_commit_resolves_obligation() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.commit(id, "hash-1").unwrap();
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), 1);
}

#[test]
fn integ_abort_resolves_obligation() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::UpstreamFailure, "hash-2").unwrap();
    assert_eq!(chan.pending_count(), 0);
}

#[test]
fn integ_double_commit_fails() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let err = chan.commit(id, "h").unwrap_err();
    assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
}

#[test]
fn integ_commit_after_abort_fails() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.abort(id, &AbortReason::DrainTimeout, "h").unwrap();
    assert!(chan.commit(id, "h").is_err());
}

#[test]
fn integ_commit_nonexistent_fails() {
    let mut chan = test_channel();
    let err = chan.commit(999, "h").unwrap_err();
    assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
}

#[test]
fn integ_abort_nonexistent_fails() {
    let mut chan = test_channel();
    let err = chan.abort(999, &AbortReason::DrainTimeout, "h").unwrap_err();
    assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
}

// ===========================================================================
// Backpressure tests
// ===========================================================================

#[test]
fn integ_backpressure_at_limit() {
    let mut chan = ObligationChannel::new("c", "t", ChannelConfig { max_pending: 3, lab_mode: false });
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    let err = chan.send("t").unwrap_err();
    assert_eq!(err, ObligationError::Backpressure { max_pending: 3 });
}

#[test]
fn integ_backpressure_clears_after_resolution() {
    let mut chan = ObligationChannel::new("c", "t", ChannelConfig { max_pending: 2, lab_mode: false });
    let id1 = chan.send("t").unwrap();
    chan.send("t").unwrap();
    assert!(chan.send("t").is_err());
    chan.commit(id1, "h").unwrap();
    assert!(chan.send("t").is_ok());
}

#[test]
fn integ_backpressure_zero_max_blocks_all() {
    let mut chan = ObligationChannel::new("c", "t", ChannelConfig { max_pending: 0, lab_mode: false });
    let err = chan.send("t").unwrap_err();
    assert!(matches!(err, ObligationError::Backpressure { max_pending: 0 }));
}

// ===========================================================================
// Leak detection tests
// ===========================================================================

#[test]
fn integ_mark_leaked() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.mark_leaked(id).unwrap();
    assert_eq!(chan.leak_count(), 1);
    assert_eq!(chan.pending_count(), 0);
}

#[test]
fn integ_leak_already_resolved_fails() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    assert!(chan.mark_leaked(id).is_err());
}

#[test]
fn integ_leak_nonexistent_fails() {
    let mut chan = test_channel();
    assert!(chan.mark_leaked(999).is_err());
}

#[test]
fn integ_multiple_leaks_increment() {
    let mut chan = test_channel();
    for _ in 0..5 {
        let id = chan.send("t").unwrap();
        chan.mark_leaked(id).unwrap();
    }
    assert_eq!(chan.leak_count(), 5);
}

// ===========================================================================
// Oldest pending tests
// ===========================================================================

#[test]
fn integ_oldest_pending_returns_earliest() {
    let mut chan = test_channel();
    chan.set_tick(10);
    chan.send("t").unwrap();
    chan.set_tick(20);
    chan.send("t").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 10);
}

#[test]
fn integ_oldest_pending_none_when_empty() {
    let chan = test_channel();
    assert!(chan.oldest_pending().is_none());
}

#[test]
fn integ_oldest_pending_skips_resolved() {
    let mut chan = test_channel();
    chan.set_tick(10);
    let id1 = chan.send("t").unwrap();
    chan.set_tick(20);
    chan.send("t").unwrap();
    chan.commit(id1, "h").unwrap();
    let oldest = chan.oldest_pending().unwrap();
    assert_eq!(oldest.created_at_tick, 20);
}

// ===========================================================================
// Drain tests
// ===========================================================================

#[test]
fn integ_drain_check_true_when_all_resolved() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    assert!(chan.drain_check());
}

#[test]
fn integ_drain_check_false_when_pending() {
    let mut chan = test_channel();
    chan.send("t").unwrap();
    assert!(!chan.drain_check());
}

#[test]
fn integ_force_abort_all_pending() {
    let mut chan = test_channel();
    chan.send("t").unwrap();
    chan.send("t").unwrap();
    let id3 = chan.send("t").unwrap();
    chan.commit(id3, "h").unwrap();
    let aborted = chan.force_abort_all_pending("timeout-hash");
    assert_eq!(aborted, 2);
    assert!(chan.drain_check());
}

#[test]
fn integ_force_abort_with_no_pending() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    assert_eq!(chan.force_abort_all_pending("h"), 0);
}

// ===========================================================================
// Event tests
// ===========================================================================

#[test]
fn integ_events_emitted_on_lifecycle() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.commit(id, "h").unwrap();
    let events = chan.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].state, ObligationState::Pending);
    assert_eq!(events[1].state, ObligationState::Committed);
}

#[test]
fn integ_event_fields_correct() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.commit(id, "evidence-hash").unwrap();
    let events = chan.drain_events();
    let commit_event = &events[1];
    assert_eq!(commit_event.trace_id, "trace-test");
    assert_eq!(commit_event.channel_id, "chan-test");
    assert_eq!(commit_event.resolution_type, Some("commit".to_string()));
    assert_eq!(commit_event.evidence_hash, Some("evidence-hash".to_string()));
}

#[test]
fn integ_drain_events_clears_buffer() {
    let mut chan = test_channel();
    chan.send("t").unwrap();
    assert!(!chan.drain_events().is_empty());
    assert!(chan.drain_events().is_empty());
}

#[test]
fn integ_pending_event_no_resolution_type() {
    let mut chan = test_channel();
    chan.send("t").unwrap();
    let events = chan.drain_events();
    assert_eq!(events[0].resolution_type, None);
    assert_eq!(events[0].evidence_hash, None);
}

#[test]
fn integ_leak_event_has_leak_resolution_type() {
    let mut chan = test_channel();
    let id = chan.send("t").unwrap();
    chan.drain_events();
    chan.mark_leaked(id).unwrap();
    let events = chan.drain_events();
    assert_eq!(events[0].resolution_type, Some("leak".to_string()));
}

// ===========================================================================
// Deterministic replay tests
// ===========================================================================

#[test]
fn integ_deterministic_event_sequence() {
    let run = || -> Vec<ObligationEvent> {
        let mut chan = test_channel();
        chan.set_tick(10);
        let id1 = chan.send("t").unwrap();
        chan.set_tick(20);
        let id2 = chan.send("t").unwrap();
        chan.commit(id1, "h1").unwrap();
        chan.abort(id2, &AbortReason::DrainTimeout, "h2").unwrap();
        chan.drain_events()
    };
    assert_eq!(run(), run());
}

#[test]
fn integ_deterministic_complex_lifecycle() {
    let run = || -> Vec<ObligationEvent> {
        let mut chan = ObligationChannel::new(
            "replay",
            "replay-trace",
            ChannelConfig { max_pending: 10, lab_mode: true },
        );
        chan.set_tick(100);
        let id1 = chan.send("t").unwrap();
        chan.set_tick(200);
        let id2 = chan.send("t").unwrap();
        chan.set_tick(300);
        let id3 = chan.send("t").unwrap();
        chan.commit(id1, "h1").unwrap();
        chan.mark_leaked(id2).unwrap();
        chan.abort(id3, &AbortReason::PolicyViolation, "h3").unwrap();
        chan.drain_events()
    };
    let e1 = run();
    let e2 = run();
    assert_eq!(e1.len(), e2.len());
    for (a, b) in e1.iter().zip(e2.iter()) {
        assert_eq!(a, b);
    }
}

// ===========================================================================
// Clone independence tests
// ===========================================================================

#[test]
fn integ_obligation_record_clone_independence() {
    let rec = ObligationRecord {
        obligation_id: 42,
        created_at_tick: 100,
        creator_trace_id: "trace-x".to_string(),
        state: ObligationState::Pending,
        resolution_evidence_hash: None,
    };
    let mut cloned = rec.clone();
    cloned.state = ObligationState::Committed;
    assert_ne!(rec.state, cloned.state);
}

#[test]
fn integ_obligation_event_clone_independence() {
    let evt = ObligationEvent {
        trace_id: "t".to_string(),
        channel_id: "c".to_string(),
        obligation_id: 1,
        state: ObligationState::Pending,
        resolution_type: None,
        evidence_hash: None,
    };
    let mut cloned = evt.clone();
    cloned.resolution_type = Some("commit".to_string());
    assert_ne!(evt.resolution_type, cloned.resolution_type);
}

// ===========================================================================
// Stress tests
// ===========================================================================

#[test]
fn integ_stress_20_send_commit() {
    let mut chan = ObligationChannel::new("stress", "t", ChannelConfig { max_pending: 20, lab_mode: false });
    let mut ids = Vec::new();
    for i in 0..20 {
        chan.set_tick(i as u64);
        ids.push(chan.send("t").unwrap());
    }
    assert_eq!(chan.pending_count(), 20);
    assert!(chan.send("t").is_err());
    for id in &ids {
        chan.commit(*id, "h").unwrap();
    }
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), 20);
}

#[test]
fn integ_stress_interleaved_send_commit_abort() {
    let mut chan = test_channel();
    for i in 0u64..30 {
        chan.set_tick(i);
        let id = chan.send("t").unwrap();
        if i % 3 == 0 {
            chan.abort(id, &AbortReason::OperatorAbort, "h").unwrap();
        } else {
            chan.commit(id, "h").unwrap();
        }
    }
    assert_eq!(chan.pending_count(), 0);
    assert_eq!(chan.total_count(), 30);
}

// ===========================================================================
// Lab mode and config tests
// ===========================================================================

#[test]
fn integ_lab_mode_flag() {
    let chan = ObligationChannel::new("c", "t", ChannelConfig { max_pending: 10, lab_mode: true });
    assert!(chan.is_lab_mode());
}

#[test]
fn integ_channel_config_default() {
    let cfg = ChannelConfig::default();
    assert_eq!(cfg.max_pending, 256);
    assert!(!cfg.lab_mode);
}

#[test]
fn integ_multiple_channels_independent() {
    let mut chan1 = ObligationChannel::new("c1", "t1", ChannelConfig::default());
    let mut chan2 = ObligationChannel::new("c2", "t2", ChannelConfig::default());
    let id1 = chan1.send("t").unwrap();
    let id2 = chan2.send("t").unwrap();
    assert_eq!(id1, 1);
    assert_eq!(id2, 1);
    chan1.commit(id1, "h").unwrap();
    assert_eq!(chan1.pending_count(), 0);
    assert_eq!(chan2.pending_count(), 1);
}
