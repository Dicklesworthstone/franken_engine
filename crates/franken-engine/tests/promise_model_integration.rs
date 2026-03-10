#![forbid(unsafe_code)]

//! Integration tests for the `promise_model` module.
//!
//! Covers: construction & defaults, Display impls, serde round-trips,
//! promise creation / resolution / rejection, microtask queue semantics,
//! macrotask priority ordering, event loop turns, virtual clock,
//! Promise combinators (all / allSettled / race / any), unhandled rejections,
//! IFC label propagation, witness events, determinism, and edge cases.

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

use std::collections::BTreeMap;

use frankenengine_engine::closure_model::ClosureHandle;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::{
    EventLoop, Macrotask, MacrotaskQueue, MacrotaskSource, Microtask, MicrotaskQueue,
    PromiseAllSettledTracker, PromiseAllTracker, PromiseAnyTracker, PromiseError, PromiseHandle,
    PromiseRaceTracker, PromiseReaction, PromiseRecord, PromiseState, PromiseStore, ReactionKind,
    SettledOutcome, VirtualClock, WitnessEvent,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn js_int(n: i64) -> JsValue {
    JsValue::Int(n)
}

fn js_str(s: &str) -> JsValue {
    JsValue::Str(s.to_string())
}

// ===========================================================================
// 1. Construction and default values
// ===========================================================================

#[test]
fn promise_handle_construction() {
    let h = PromiseHandle(0);
    assert_eq!(h.0, 0);
    let h2 = PromiseHandle(u32::MAX);
    assert_eq!(h2.0, u32::MAX);
}

#[test]
fn promise_state_pending_is_not_settled() {
    let state = PromiseState::Pending;
    assert!(!state.is_settled());
    assert!(!state.is_fulfilled());
    assert!(!state.is_rejected());
}

#[test]
fn promise_state_fulfilled_is_settled() {
    let state = PromiseState::Fulfilled(js_int(1));
    assert!(state.is_settled());
    assert!(state.is_fulfilled());
    assert!(!state.is_rejected());
}

#[test]
fn promise_state_rejected_is_settled() {
    let state = PromiseState::Rejected(js_str("err"));
    assert!(state.is_settled());
    assert!(!state.is_fulfilled());
    assert!(state.is_rejected());
}

#[test]
fn promise_store_new_is_empty() {
    let store = PromiseStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.witness_log().is_empty());
}

#[test]
fn promise_store_default_equals_new() {
    let store_new = PromiseStore::new();
    let store_def = PromiseStore::default();
    assert_eq!(store_new.len(), store_def.len());
    assert!(store_def.is_empty());
}

#[test]
fn microtask_queue_new_is_empty() {
    let queue = MicrotaskQueue::new();
    assert!(queue.is_empty());
    assert_eq!(queue.pending_count(), 0);
    assert_eq!(queue.total_enqueued(), 0);
}

#[test]
fn microtask_queue_default_equals_new() {
    let queue = MicrotaskQueue::default();
    assert!(queue.is_empty());
    assert_eq!(queue.total_enqueued(), 0);
}

#[test]
fn macrotask_queue_new_is_empty() {
    let queue = MacrotaskQueue::new();
    assert!(queue.is_empty());
    assert_eq!(queue.len(), 0);
    assert!(queue.next_scheduled_time().is_none());
}

#[test]
fn virtual_clock_new_starts_at_zero() {
    let clock = VirtualClock::new();
    assert_eq!(clock.now_ms(), 0);
}

#[test]
fn virtual_clock_default_equals_new() {
    let clock = VirtualClock::default();
    assert_eq!(clock.now_ms(), 0);
}

#[test]
fn event_loop_new_has_no_pending_work() {
    let el = EventLoop::new();
    assert!(!el.has_pending_work());
    assert_eq!(el.clock.now_ms(), 0);
}

#[test]
fn event_loop_default_equals_new() {
    let el = EventLoop::default();
    assert!(!el.has_pending_work());
}

// ===========================================================================
// 2. Display impls
// ===========================================================================

#[test]
fn promise_handle_display() {
    assert_eq!(PromiseHandle(0).to_string(), "Promise(0)");
    assert_eq!(PromiseHandle(42).to_string(), "Promise(42)");
    assert_eq!(
        PromiseHandle(u32::MAX).to_string(),
        format!("Promise({})", u32::MAX)
    );
}

#[test]
fn promise_state_display_pending() {
    assert_eq!(PromiseState::Pending.to_string(), "pending");
}

#[test]
fn promise_state_display_fulfilled() {
    assert_eq!(PromiseState::Fulfilled(js_int(1)).to_string(), "fulfilled");
}

#[test]
fn promise_state_display_rejected() {
    assert_eq!(PromiseState::Rejected(js_str("e")).to_string(), "rejected");
}

#[test]
fn promise_error_display_already_settled() {
    let err = PromiseError::AlreadySettled {
        handle: PromiseHandle(5),
    };
    let display = err.to_string();
    assert!(display.contains("already settled"));
    assert!(display.contains("Promise(5)"));
}

#[test]
fn promise_error_display_invalid_handle() {
    let err = PromiseError::InvalidHandle {
        handle: PromiseHandle(99),
    };
    let display = err.to_string();
    assert!(display.contains("invalid"));
    assert!(display.contains("Promise(99)"));
}

#[test]
fn promise_error_display_label_violation() {
    let err = PromiseError::LabelViolation {
        handle: PromiseHandle(3),
        value_label: Label::Secret,
        context_label: Label::Public,
    };
    let display = err.to_string();
    assert!(display.contains("IFCError"));
    assert!(display.contains("Promise(3)"));
}

// ===========================================================================
// 3. Serde round-trips
// ===========================================================================

#[test]
fn serde_promise_handle() {
    let h = PromiseHandle(77);
    let json = serde_json::to_string(&h).unwrap();
    let back: PromiseHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, h);
}

#[test]
fn serde_promise_state_all_variants() {
    let states = vec![
        PromiseState::Pending,
        PromiseState::Fulfilled(js_int(42)),
        PromiseState::Fulfilled(JsValue::Undefined),
        PromiseState::Rejected(js_str("error")),
        PromiseState::Rejected(JsValue::Null),
    ];
    for state in &states {
        let json = serde_json::to_string(state).unwrap();
        let back: PromiseState = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, state);
    }
}

#[test]
fn serde_reaction_kind() {
    for kind in &[ReactionKind::Fulfill, ReactionKind::Reject] {
        let json = serde_json::to_string(kind).unwrap();
        let back: ReactionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, kind);
    }
}

#[test]
fn serde_promise_reaction() {
    let reaction = PromiseReaction {
        kind: ReactionKind::Fulfill,
        handler: Some(ClosureHandle(10)),
        result_promise: PromiseHandle(5),
        label: Label::Confidential,
    };
    let json = serde_json::to_string(&reaction).unwrap();
    let back: PromiseReaction = serde_json::from_str(&json).unwrap();
    assert_eq!(back, reaction);
}

#[test]
fn serde_promise_record() {
    let record = PromiseRecord {
        handle: PromiseHandle(0),
        state: PromiseState::Fulfilled(js_int(99)),
        reactions: vec![],
        label: Label::Public,
        creation_seq: 0,
        rejection_handled: false,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: PromiseRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, record);
}

#[test]
fn serde_microtask_promise_reaction() {
    let task = Microtask::PromiseReaction {
        handler: Some(ClosureHandle(3)),
        argument: js_int(7),
        result_promise: PromiseHandle(1),
        label: Label::Internal,
    };
    let json = serde_json::to_string(&task).unwrap();
    let back: Microtask = serde_json::from_str(&json).unwrap();
    assert_eq!(back, task);
}

#[test]
fn serde_microtask_resolve_thenable() {
    let task = Microtask::ResolveThenable {
        promise: PromiseHandle(2),
        then_handler: ClosureHandle(5),
        thenable: js_str("thenable"),
        label: Label::Secret,
    };
    let json = serde_json::to_string(&task).unwrap();
    let back: Microtask = serde_json::from_str(&json).unwrap();
    assert_eq!(back, task);
}

#[test]
fn serde_macrotask_source_all_variants() {
    for source in &[
        MacrotaskSource::MessageChannel,
        MacrotaskSource::Timer,
        MacrotaskSource::IoCompletion,
    ] {
        let json = serde_json::to_string(source).unwrap();
        let back: MacrotaskSource = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, source);
    }
}

#[test]
fn serde_macrotask() {
    let task = Macrotask {
        source: MacrotaskSource::Timer,
        handler: ClosureHandle(5),
        scheduled_at: 1000,
        registration_seq: 7,
        label: Label::Internal,
    };
    let json = serde_json::to_string(&task).unwrap();
    let back: Macrotask = serde_json::from_str(&json).unwrap();
    assert_eq!(back, task);
}

#[test]
fn serde_virtual_clock() {
    let mut clock = VirtualClock::new();
    clock.advance_to(12345);
    clock.register_timer();
    clock.register_timer();
    let json = serde_json::to_string(&clock).unwrap();
    let back: VirtualClock = serde_json::from_str(&json).unwrap();
    assert_eq!(back, clock);
}

#[test]
fn serde_witness_event_all_variants() {
    let events = vec![
        WitnessEvent::PromiseCreated {
            handle: PromiseHandle(0),
            seq: 0,
        },
        WitnessEvent::PromiseFulfilled {
            handle: PromiseHandle(1),
            value: js_int(42),
            label: Label::Public,
        },
        WitnessEvent::PromiseRejected {
            handle: PromiseHandle(2),
            reason: js_str("err"),
            label: Label::Secret,
        },
        WitnessEvent::MicrotaskEnqueued { index: 5 },
        WitnessEvent::MicrotaskDequeued { index: 3 },
        WitnessEvent::MacrotaskExecuted {
            source: MacrotaskSource::Timer,
            registration_seq: 1,
        },
        WitnessEvent::ClockAdvanced {
            from_ms: 0,
            to_ms: 100,
        },
    ];
    for event in &events {
        let json = serde_json::to_string(event).unwrap();
        let back: WitnessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, event);
    }
}

#[test]
fn serde_promise_error_all_variants() {
    let errors = vec![
        PromiseError::AlreadySettled {
            handle: PromiseHandle(0),
        },
        PromiseError::InvalidHandle {
            handle: PromiseHandle(99),
        },
        PromiseError::LabelViolation {
            handle: PromiseHandle(1),
            value_label: Label::Secret,
            context_label: Label::Public,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: PromiseError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn serde_settled_outcome() {
    let outcome = SettledOutcome {
        status: "fulfilled".into(),
        value: js_int(42),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: SettledOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back, outcome);
}

#[test]
fn serde_promise_store_roundtrip() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .fulfill(h, js_int(42), Label::Public, &mut queue)
        .unwrap();
    let json = serde_json::to_string(&store).unwrap();
    let back: PromiseStore = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), store.len());
    assert_eq!(back.witness_log().len(), store.witness_log().len());
}

#[test]
fn serde_event_loop_roundtrip() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 100, Label::Public);
    el.microtasks.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(1),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    let json = serde_json::to_string(&el).unwrap();
    let back: EventLoop = serde_json::from_str(&json).unwrap();
    assert!(back.has_pending_work());
    assert_eq!(back.clock.now_ms(), 0);
}

// ===========================================================================
// 4. Core functionality - promise lifecycle
// ===========================================================================

#[test]
fn create_promise_returns_sequential_handles() {
    let mut store = PromiseStore::new();
    let h0 = store.create();
    let h1 = store.create();
    let h2 = store.create();
    assert_eq!(h0, PromiseHandle(0));
    assert_eq!(h1, PromiseHandle(1));
    assert_eq!(h2, PromiseHandle(2));
    assert_eq!(store.len(), 3);
}

#[test]
fn fulfill_promise_transitions_state() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .fulfill(h, js_int(42), Label::Public, &mut queue)
        .unwrap();
    let record = store.get(h).unwrap();
    assert_eq!(record.state, PromiseState::Fulfilled(js_int(42)));
    assert_eq!(record.label, Label::Public);
}

#[test]
fn reject_promise_transitions_state() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("err"), Label::Secret, &mut queue)
        .unwrap();
    let record = store.get(h).unwrap();
    assert_eq!(record.state, PromiseState::Rejected(js_str("err")));
    assert_eq!(record.label, Label::Secret);
}

#[test]
fn double_fulfill_returns_already_settled_error() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .fulfill(h, js_int(1), Label::Public, &mut queue)
        .unwrap();
    let err = store
        .fulfill(h, js_int(2), Label::Public, &mut queue)
        .unwrap_err();
    assert!(matches!(err, PromiseError::AlreadySettled { .. }));
}

#[test]
fn double_reject_returns_already_settled_error() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("e1"), Label::Public, &mut queue)
        .unwrap();
    let err = store
        .reject(h, js_str("e2"), Label::Public, &mut queue)
        .unwrap_err();
    assert!(matches!(err, PromiseError::AlreadySettled { .. }));
}

#[test]
fn fulfill_then_reject_returns_already_settled() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .fulfill(h, js_int(1), Label::Public, &mut queue)
        .unwrap();
    let err = store
        .reject(h, js_str("e"), Label::Public, &mut queue)
        .unwrap_err();
    assert!(matches!(err, PromiseError::AlreadySettled { .. }));
}

#[test]
fn reject_then_fulfill_returns_already_settled() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("e"), Label::Public, &mut queue)
        .unwrap();
    let err = store
        .fulfill(h, js_int(1), Label::Public, &mut queue)
        .unwrap_err();
    assert!(matches!(err, PromiseError::AlreadySettled { .. }));
}

#[test]
fn get_invalid_handle_returns_error() {
    let store = PromiseStore::new();
    let err = store.get(PromiseHandle(999)).unwrap_err();
    assert!(matches!(err, PromiseError::InvalidHandle { .. }));
}

#[test]
fn fulfill_invalid_handle_returns_error() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let err = store
        .fulfill(PromiseHandle(0), js_int(1), Label::Public, &mut queue)
        .unwrap_err();
    assert!(matches!(err, PromiseError::InvalidHandle { .. }));
}

#[test]
fn reject_invalid_handle_returns_error() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let err = store
        .reject(PromiseHandle(0), js_str("e"), Label::Public, &mut queue)
        .unwrap_err();
    assert!(matches!(err, PromiseError::InvalidHandle { .. }));
}

#[test]
fn promise_resolve_creates_pre_fulfilled() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.resolve(js_int(7), Label::Public, &mut queue);
    let record = store.get(h).unwrap();
    assert!(record.state.is_fulfilled());
    assert_eq!(record.state, PromiseState::Fulfilled(js_int(7)));
}

#[test]
fn promise_reject_with_creates_pre_rejected() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.reject_with(js_str("boom"), Label::Secret, &mut queue);
    let record = store.get(h).unwrap();
    assert!(record.state.is_rejected());
    assert_eq!(record.label, Label::Secret);
}

// ===========================================================================
// 5. .then() reactions
// ===========================================================================

#[test]
fn then_on_pending_registers_two_reactions() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    let result_h = store
        .then(
            h,
            Some(ClosureHandle(0)),
            Some(ClosureHandle(1)),
            Label::Public,
            &mut queue,
        )
        .unwrap();
    assert!(queue.is_empty()); // still pending
    let record = store.get(h).unwrap();
    assert_eq!(record.reactions.len(), 2);
    let result_record = store.get(result_h).unwrap();
    assert_eq!(result_record.state, PromiseState::Pending);
}

#[test]
fn then_on_fulfilled_enqueues_microtask_immediately() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.resolve(js_int(10), Label::Public, &mut queue);
    store
        .then(h, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
        .unwrap();
    assert!(queue.pending_count() >= 1);
}

#[test]
fn then_on_rejected_enqueues_microtask_immediately() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.reject_with(js_str("fail"), Label::Public, &mut queue);
    store
        .then(h, None, Some(ClosureHandle(2)), Label::Public, &mut queue)
        .unwrap();
    assert!(queue.pending_count() >= 1);
}

#[test]
fn fulfill_triggers_all_registered_reactions() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .then(h, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
        .unwrap();
    store
        .then(h, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
        .unwrap();
    store
        .fulfill(h, js_int(42), Label::Public, &mut queue)
        .unwrap();
    // 2 .then() calls = 4 reactions (2 fulfill + 2 reject) -> 4 microtasks
    assert_eq!(queue.pending_count(), 4);
}

#[test]
fn then_on_invalid_handle_returns_error() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let err = store
        .then(PromiseHandle(0), None, None, Label::Public, &mut queue)
        .unwrap_err();
    assert!(matches!(err, PromiseError::InvalidHandle { .. }));
}

#[test]
fn chained_then_creates_distinct_result_promises() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let p1 = store.create();
    let p2 = store
        .then(p1, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
        .unwrap();
    let p3 = store
        .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
        .unwrap();
    assert_ne!(p1, p2);
    assert_ne!(p2, p3);
    assert_ne!(p1, p3);
}

// ===========================================================================
// 6. Microtask queue behavior
// ===========================================================================

#[test]
fn microtask_queue_fifo_ordering() {
    let mut queue = MicrotaskQueue::new();
    for i in 0..5 {
        queue.enqueue(Microtask::PromiseReaction {
            handler: Some(ClosureHandle(i)),
            argument: js_int(i as i64),
            result_promise: PromiseHandle(i),
            label: Label::Public,
        });
    }
    assert_eq!(queue.pending_count(), 5);
    assert_eq!(queue.total_enqueued(), 5);

    for i in 0..5 {
        let task = queue.dequeue().unwrap();
        if let Microtask::PromiseReaction { argument, .. } = task {
            assert_eq!(argument, js_int(i as i64));
        } else {
            panic!("expected PromiseReaction");
        }
    }
    assert!(queue.dequeue().is_none());
    assert!(queue.is_empty());
}

#[test]
fn microtask_queue_compact_resets_cursor() {
    let mut queue = MicrotaskQueue::new();
    for _ in 0..3 {
        queue.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(1),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
    }
    queue.dequeue();
    queue.dequeue();
    assert_eq!(queue.pending_count(), 1);
    queue.compact();
    assert_eq!(queue.pending_count(), 1);
    // Can still dequeue the remaining task after compact
    assert!(queue.dequeue().is_some());
    assert!(queue.is_empty());
}

#[test]
fn microtask_queue_witness_events() {
    let mut queue = MicrotaskQueue::new();
    queue.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(1),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    queue.dequeue();
    let log = queue.witness_log();
    assert_eq!(log.len(), 2);
    assert!(matches!(
        log[0],
        WitnessEvent::MicrotaskEnqueued { index: 0 }
    ));
    assert!(matches!(
        log[1],
        WitnessEvent::MicrotaskDequeued { index: 0 }
    ));
}

#[test]
fn microtask_dequeue_on_empty_returns_none() {
    let mut queue = MicrotaskQueue::new();
    assert!(queue.dequeue().is_none());
}

// ===========================================================================
// 7. Virtual clock
// ===========================================================================

#[test]
fn virtual_clock_advance_does_not_go_backward() {
    let mut clock = VirtualClock::new();
    clock.advance_to(100);
    assert_eq!(clock.now_ms(), 100);
    clock.advance_to(50);
    assert_eq!(clock.now_ms(), 100); // unchanged
    clock.advance_to(100);
    assert_eq!(clock.now_ms(), 100); // unchanged on same value
}

#[test]
fn virtual_clock_timer_registration_is_monotonic() {
    let mut clock = VirtualClock::new();
    let seq0 = clock.register_timer();
    let seq1 = clock.register_timer();
    let seq2 = clock.register_timer();
    assert_eq!(seq0, 0);
    assert_eq!(seq1, 1);
    assert_eq!(seq2, 2);
}

// ===========================================================================
// 8. Macrotask queue and priority
// ===========================================================================

#[test]
fn macrotask_message_channel_highest_priority() {
    let mut queue = MacrotaskQueue::new();
    queue.schedule(
        MacrotaskSource::IoCompletion,
        ClosureHandle(0),
        0,
        Label::Public,
    );
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(1), 0, Label::Public);
    queue.schedule(
        MacrotaskSource::MessageChannel,
        ClosureHandle(2),
        0,
        Label::Public,
    );

    let first = queue.dequeue_ready(0).unwrap();
    assert_eq!(first.source, MacrotaskSource::MessageChannel);
    let second = queue.dequeue_ready(0).unwrap();
    assert_eq!(second.source, MacrotaskSource::Timer);
    let third = queue.dequeue_ready(0).unwrap();
    assert_eq!(third.source, MacrotaskSource::IoCompletion);
}

#[test]
fn macrotask_timer_ordered_by_scheduled_time_then_seq() {
    let mut queue = MacrotaskQueue::new();
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 100, Label::Public);
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(1), 50, Label::Public);
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(2), 50, Label::Public);

    let first = queue.dequeue_ready(100).unwrap();
    assert_eq!(first.handler, ClosureHandle(1)); // 50ms, seq=1
    let second = queue.dequeue_ready(100).unwrap();
    assert_eq!(second.handler, ClosureHandle(2)); // 50ms, seq=2
    let third = queue.dequeue_ready(100).unwrap();
    assert_eq!(third.handler, ClosureHandle(0)); // 100ms, seq=0
}

#[test]
fn macrotask_not_dequeued_before_scheduled_time() {
    let mut queue = MacrotaskQueue::new();
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 100, Label::Public);
    assert!(queue.dequeue_ready(99).is_none());
    assert!(queue.dequeue_ready(100).is_some());
}

#[test]
fn macrotask_schedule_returns_sequential_registration_seq() {
    let mut queue = MacrotaskQueue::new();
    let s0 = queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 0, Label::Public);
    let s1 = queue.schedule(MacrotaskSource::Timer, ClosureHandle(1), 0, Label::Public);
    assert_eq!(s0, 0);
    assert_eq!(s1, 1);
}

#[test]
fn macrotask_next_scheduled_time_returns_minimum() {
    let mut queue = MacrotaskQueue::new();
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 200, Label::Public);
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(1), 50, Label::Public);
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(2), 150, Label::Public);
    assert_eq!(queue.next_scheduled_time(), Some(50));
}

// ===========================================================================
// 9. Event loop turns
// ===========================================================================

#[test]
fn event_loop_drains_microtasks_before_macrotask() {
    let mut el = EventLoop::new();
    el.microtasks.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(1),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    el.macrotasks
        .schedule(MacrotaskSource::Timer, ClosureHandle(0), 0, Label::Public);

    let result = el.turn();
    assert_eq!(result.microtasks_drained, 1);
    assert!(result.macrotask.is_some());
}

#[test]
fn event_loop_advances_clock_for_future_timer() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 500, Label::Public);
    let result = el.turn();
    assert!(result.clock_advanced);
    assert_eq!(el.clock.now_ms(), 500);
    assert!(result.macrotask.is_some());
}

#[test]
fn event_loop_turn_with_no_work_returns_empty() {
    let mut el = EventLoop::new();
    let result = el.turn();
    assert_eq!(result.microtasks_drained, 0);
    assert!(result.macrotask.is_none());
    assert!(!result.clock_advanced);
}

#[test]
fn event_loop_multiple_timers_fire_in_time_order() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 300, Label::Public);
    el.set_timeout(ClosureHandle(1), 100, Label::Public);
    el.set_timeout(ClosureHandle(2), 200, Label::Public);

    let r1 = el.turn();
    assert_eq!(r1.macrotask.as_ref().unwrap().handler, ClosureHandle(1));
    assert_eq!(el.clock.now_ms(), 100);

    let r2 = el.turn();
    assert_eq!(r2.macrotask.as_ref().unwrap().handler, ClosureHandle(2));
    assert_eq!(el.clock.now_ms(), 200);

    let r3 = el.turn();
    assert_eq!(r3.macrotask.as_ref().unwrap().handler, ClosureHandle(0));
    assert_eq!(el.clock.now_ms(), 300);

    let r4 = el.turn();
    assert!(r4.macrotask.is_none());
}

#[test]
fn event_loop_set_timeout_zero_delay() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 0, Label::Public);
    let result = el.turn();
    assert!(result.macrotask.is_some());
    assert!(!result.clock_advanced);
    assert_eq!(el.clock.now_ms(), 0);
}

#[test]
fn event_loop_has_pending_work_with_microtasks() {
    let mut el = EventLoop::new();
    assert!(!el.has_pending_work());
    el.microtasks.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(1),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    assert!(el.has_pending_work());
}

#[test]
fn event_loop_has_pending_work_with_macrotasks() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 100, Label::Public);
    assert!(el.has_pending_work());
}

#[test]
fn event_loop_drain_microtasks_respects_max_limit() {
    let mut el = EventLoop::new();
    el.max_microtasks_per_turn = 5;
    for i in 0..10 {
        el.microtasks.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(i),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
    }
    let drained = el.drain_microtasks();
    assert_eq!(drained, 5);
    assert_eq!(el.microtasks.pending_count(), 5);
}

#[test]
fn event_loop_witness_records_clock_advance_and_macrotask() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 500, Label::Public);
    el.turn();
    let has_clock = el.witness.iter().any(|e| {
        matches!(
            e,
            WitnessEvent::ClockAdvanced {
                from_ms: 0,
                to_ms: 500
            }
        )
    });
    let has_macro = el
        .witness
        .iter()
        .any(|e| matches!(e, WitnessEvent::MacrotaskExecuted { .. }));
    assert!(has_clock);
    assert!(has_macro);
}

// ===========================================================================
// 10. Unhandled rejections
// ===========================================================================

#[test]
fn unhandled_rejection_is_tracked() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("unhandled"), Label::Public, &mut queue)
        .unwrap();
    let unhandled = store.unhandled_rejections();
    assert_eq!(unhandled.len(), 1);
    assert_eq!(unhandled[0], h);
}

#[test]
fn rejection_with_handler_registered_before_reject_is_handled() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .then(h, None, Some(ClosureHandle(0)), Label::Public, &mut queue)
        .unwrap();
    store
        .reject(h, js_str("handled"), Label::Public, &mut queue)
        .unwrap();
    assert!(store.unhandled_rejections().is_empty());
}

#[test]
fn rejection_with_only_on_fulfilled_registered_before_reject_is_unhandled() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .then(h, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
        .unwrap();
    store
        .reject(h, js_str("still_unhandled"), Label::Public, &mut queue)
        .unwrap();
    let unhandled = store.unhandled_rejections();
    assert_eq!(unhandled, vec![h]);
}

#[test]
fn then_on_rejected_promise_marks_as_handled() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("err"), Label::Public, &mut queue)
        .unwrap();
    assert_eq!(store.unhandled_rejections().len(), 1);
    store
        .then(h, None, Some(ClosureHandle(0)), Label::Public, &mut queue)
        .unwrap();
    assert!(store.unhandled_rejections().is_empty());
}

#[test]
fn then_on_rejected_without_on_rejected_does_not_mark_handled() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("err"), Label::Public, &mut queue)
        .unwrap();
    assert_eq!(store.unhandled_rejections(), vec![h]);

    store
        .then(h, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
        .unwrap();
    assert_eq!(store.unhandled_rejections(), vec![h]);
}

#[test]
fn multiple_unhandled_rejections() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h1 = store.create();
    let h2 = store.create();
    store
        .reject(h1, js_str("e1"), Label::Public, &mut queue)
        .unwrap();
    store
        .reject(h2, js_str("e2"), Label::Public, &mut queue)
        .unwrap();
    let unhandled = store.unhandled_rejections();
    assert_eq!(unhandled.len(), 2);
}

// ===========================================================================
// 11. IFC label propagation
// ===========================================================================

#[test]
fn fulfilled_promise_carries_label() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .fulfill(h, js_str("data"), Label::Confidential, &mut queue)
        .unwrap();
    assert_eq!(store.get(h).unwrap().label, Label::Confidential);
}

#[test]
fn rejected_promise_carries_label() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("err"), Label::TopSecret, &mut queue)
        .unwrap();
    assert_eq!(store.get(h).unwrap().label, Label::TopSecret);
}

#[test]
fn new_promise_default_label_is_public() {
    let mut store = PromiseStore::new();
    let h = store.create();
    assert_eq!(store.get(h).unwrap().label, Label::Public);
}

// ===========================================================================
// 12. Witness events
// ===========================================================================

#[test]
fn witness_records_create_and_fulfill() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .fulfill(h, js_int(1), Label::Public, &mut queue)
        .unwrap();
    let log = store.witness_log();
    assert_eq!(log.len(), 2);
    assert!(matches!(
        log[0],
        WitnessEvent::PromiseCreated { seq: 0, .. }
    ));
    assert!(matches!(log[1], WitnessEvent::PromiseFulfilled { .. }));
}

#[test]
fn witness_records_create_and_reject() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("err"), Label::Public, &mut queue)
        .unwrap();
    let log = store.witness_log();
    assert_eq!(log.len(), 2);
    assert!(matches!(
        log[0],
        WitnessEvent::PromiseCreated { seq: 0, .. }
    ));
    assert!(matches!(log[1], WitnessEvent::PromiseRejected { .. }));
}

#[test]
fn witness_creation_seq_increments() {
    let mut store = PromiseStore::new();
    store.create();
    store.create();
    store.create();
    let log = store.witness_log();
    assert_eq!(log.len(), 3);
    if let WitnessEvent::PromiseCreated { seq, .. } = &log[0] {
        assert_eq!(*seq, 0);
    }
    if let WitnessEvent::PromiseCreated { seq, .. } = &log[1] {
        assert_eq!(*seq, 1);
    }
    if let WitnessEvent::PromiseCreated { seq, .. } = &log[2] {
        assert_eq!(*seq, 2);
    }
}

// ===========================================================================
// 13. Promise combinators
// ===========================================================================

#[test]
fn promise_all_tracker_collects_in_order() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(10),
        values: BTreeMap::new(),
        total: 3,
        resolved_count: 0,
        settled: false,
    };
    assert!(!tracker.record_fulfillment(2, js_int(30)));
    assert!(!tracker.record_fulfillment(0, js_int(10)));
    assert!(tracker.record_fulfillment(1, js_int(20)));
    let values = tracker.collect_values();
    assert_eq!(values, vec![js_int(10), js_int(20), js_int(30)]);
}

#[test]
fn promise_all_tracker_short_circuits_when_settled() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total: 3,
        resolved_count: 0,
        settled: false,
    };
    tracker.mark_settled();
    assert!(!tracker.record_fulfillment(0, js_int(1)));
    assert_eq!(tracker.resolved_count, 0);
}

#[test]
fn promise_all_tracker_single_promise() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total: 1,
        resolved_count: 0,
        settled: false,
    };
    assert!(tracker.record_fulfillment(0, js_int(99)));
    assert_eq!(tracker.collect_values(), vec![js_int(99)]);
}

#[test]
fn promise_all_tracker_collect_values_with_gaps() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total: 3,
        resolved_count: 0,
        settled: false,
    };
    // Only fulfill index 1 of 3
    tracker.record_fulfillment(1, js_int(20));
    let values = tracker.collect_values();
    assert_eq!(
        values,
        vec![JsValue::Undefined, js_int(20), JsValue::Undefined]
    );
}

#[test]
fn promise_all_settled_tracker_records_both_outcomes() {
    let mut tracker = PromiseAllSettledTracker {
        result_promise: PromiseHandle(0),
        outcomes: BTreeMap::new(),
        total: 3,
        settled_count: 0,
    };
    assert!(!tracker.record_fulfillment(0, js_int(1)));
    assert!(!tracker.record_rejection(1, js_str("err")));
    assert!(tracker.record_fulfillment(2, js_int(3)));
    assert_eq!(tracker.outcomes.get(&0).unwrap().status, "fulfilled");
    assert_eq!(tracker.outcomes.get(&1).unwrap().status, "rejected");
    assert_eq!(tracker.outcomes.get(&2).unwrap().status, "fulfilled");
}

#[test]
fn promise_all_settled_tracker_empty_input() {
    let tracker = PromiseAllSettledTracker {
        result_promise: PromiseHandle(0),
        outcomes: BTreeMap::new(),
        total: 0,
        settled_count: 0,
    };
    assert_eq!(tracker.settled_count, tracker.total);
}

#[test]
fn promise_race_tracker_first_settlement_wins() {
    let mut tracker = PromiseRaceTracker {
        result_promise: PromiseHandle(0),
        settled: false,
    };
    assert!(tracker.try_settle());
    assert!(!tracker.try_settle()); // second attempt ignored
    assert!(!tracker.try_settle()); // third attempt also ignored
}

#[test]
fn promise_any_tracker_all_rejected_triggers_aggregate() {
    let mut tracker = PromiseAnyTracker {
        result_promise: PromiseHandle(0),
        errors: BTreeMap::new(),
        total: 3,
        rejected_count: 0,
        settled: false,
    };
    assert!(!tracker.record_rejection(0, js_str("e1")));
    assert!(!tracker.record_rejection(1, js_str("e2")));
    assert!(tracker.record_rejection(2, js_str("e3")));
    let errors = tracker.collect_errors();
    assert_eq!(errors, vec![js_str("e1"), js_str("e2"), js_str("e3")]);
}

#[test]
fn promise_any_tracker_short_circuits_on_settled() {
    let mut tracker = PromiseAnyTracker {
        result_promise: PromiseHandle(0),
        errors: BTreeMap::new(),
        total: 3,
        rejected_count: 0,
        settled: false,
    };
    tracker.mark_settled();
    assert!(!tracker.record_rejection(0, js_str("e1")));
    assert_eq!(tracker.rejected_count, 0);
}

#[test]
fn promise_any_tracker_collect_errors_with_gaps() {
    let mut tracker = PromiseAnyTracker {
        result_promise: PromiseHandle(0),
        errors: BTreeMap::new(),
        total: 3,
        rejected_count: 0,
        settled: false,
    };
    tracker.record_rejection(1, js_str("only_1"));
    let errors = tracker.collect_errors();
    assert_eq!(
        errors,
        vec![JsValue::Undefined, js_str("only_1"), JsValue::Undefined]
    );
}

// ===========================================================================
// 14. Determinism
// ===========================================================================

#[test]
fn deterministic_microtask_ordering_across_10_runs() {
    let mut witness_logs: Vec<Vec<WitnessEvent>> = Vec::new();
    for _ in 0..10 {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let p1 = store.create();
        let p2 = store.create();
        store
            .then(p1, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
            .unwrap();
        store
            .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .unwrap();
        store
            .fulfill(p1, js_int(1), Label::Public, &mut queue)
            .unwrap();
        store
            .fulfill(p2, js_int(2), Label::Public, &mut queue)
            .unwrap();
        while queue.dequeue().is_some() {}
        witness_logs.push(store.witness_log().to_vec());
    }
    for log in &witness_logs[1..] {
        assert_eq!(log, &witness_logs[0]);
    }
}

#[test]
fn deterministic_event_loop_timer_ordering() {
    let mut results_a = Vec::new();
    let mut results_b = Vec::new();

    for results in [&mut results_a, &mut results_b] {
        let mut el = EventLoop::new();
        el.set_timeout(ClosureHandle(0), 300, Label::Public);
        el.set_timeout(ClosureHandle(1), 100, Label::Public);
        el.set_timeout(ClosureHandle(2), 200, Label::Public);
        for _ in 0..3 {
            let turn = el.turn();
            if let Some(task) = turn.macrotask {
                results.push(task.handler);
            }
        }
    }
    assert_eq!(results_a, results_b);
    assert_eq!(
        results_a,
        vec![ClosureHandle(1), ClosureHandle(2), ClosureHandle(0)]
    );
}

#[test]
fn deterministic_promise_resolve_chain() {
    let mut all_witnesses: Vec<Vec<WitnessEvent>> = Vec::new();
    for _ in 0..50 {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let p1 = store.resolve(js_int(1), Label::Public, &mut queue);
        let p2 = store.resolve(js_int(2), Label::Public, &mut queue);
        store
            .then(p1, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
            .unwrap();
        store
            .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .unwrap();
        while queue.dequeue().is_some() {}
        all_witnesses.push(store.witness_log().to_vec());
    }
    for w in &all_witnesses[1..] {
        assert_eq!(w, &all_witnesses[0]);
    }
}

// ===========================================================================
// 15. Edge cases
// ===========================================================================

#[test]
fn promise_fulfilled_with_undefined() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.resolve(JsValue::Undefined, Label::Public, &mut queue);
    let record = store.get(h).unwrap();
    assert_eq!(record.state, PromiseState::Fulfilled(JsValue::Undefined));
}

#[test]
fn promise_rejected_with_null() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.reject_with(JsValue::Null, Label::Public, &mut queue);
    let record = store.get(h).unwrap();
    assert_eq!(record.state, PromiseState::Rejected(JsValue::Null));
}

#[test]
fn promise_fulfilled_with_bool() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.resolve(JsValue::Bool(true), Label::Public, &mut queue);
    let record = store.get(h).unwrap();
    assert_eq!(record.state, PromiseState::Fulfilled(JsValue::Bool(true)));
}

#[test]
fn many_promises_sequential() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let count = 100;
    for i in 0..count {
        let h = store.create();
        store
            .fulfill(h, js_int(i), Label::Public, &mut queue)
            .unwrap();
    }
    assert_eq!(store.len(), count as usize);
    assert!(store.unhandled_rejections().is_empty());
}

#[test]
fn event_loop_set_timeout_with_large_delay() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), u64::MAX / 2, Label::Public);
    let result = el.turn();
    assert!(result.clock_advanced);
    assert_eq!(el.clock.now_ms(), u64::MAX / 2);
    assert!(result.macrotask.is_some());
}

#[test]
fn macrotask_queue_empty_dequeue_returns_none() {
    let mut queue = MacrotaskQueue::new();
    assert!(queue.dequeue_ready(0).is_none());
    assert!(queue.dequeue_ready(u64::MAX).is_none());
}

#[test]
fn promise_handle_ordering() {
    let h0 = PromiseHandle(0);
    let h1 = PromiseHandle(1);
    let h2 = PromiseHandle(2);
    assert!(h0 < h1);
    assert!(h1 < h2);
    assert_eq!(h0, PromiseHandle(0));
}

#[test]
fn macrotask_source_ordering() {
    // MessageChannel < Timer < IoCompletion (as declared)
    assert!(MacrotaskSource::MessageChannel < MacrotaskSource::Timer);
    assert!(MacrotaskSource::Timer < MacrotaskSource::IoCompletion);
}

#[test]
fn settle_then_then_enqueues_for_correct_handler() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .reject(h, js_str("fail"), Label::Public, &mut queue)
        .unwrap();

    // Calling .then on already-rejected promise with only onFulfilled should
    // still enqueue a microtask (with on_rejected handler = None).
    let count_before = queue.pending_count();
    store
        .then(h, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
        .unwrap();
    assert!(queue.pending_count() > count_before);
}

#[test]
fn promise_store_witness_log_grows_with_operations() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    assert!(store.witness_log().is_empty());
    store.create();
    assert_eq!(store.witness_log().len(), 1);
    let h = store.create();
    assert_eq!(store.witness_log().len(), 2);
    store
        .fulfill(h, js_int(1), Label::Public, &mut queue)
        .unwrap();
    assert_eq!(store.witness_log().len(), 3);
}

#[test]
fn promise_all_tracker_serde_roundtrip() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total: 2,
        resolved_count: 1,
        settled: false,
    };
    tracker.values.insert(0, js_int(42));
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PromiseAllTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total, 2);
    assert_eq!(back.resolved_count, 1);
    assert_eq!(back.values.get(&0), Some(&js_int(42)));
}

#[test]
fn promise_race_tracker_serde_roundtrip() {
    let tracker = PromiseRaceTracker {
        result_promise: PromiseHandle(5),
        settled: true,
    };
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PromiseRaceTracker = serde_json::from_str(&json).unwrap();
    assert!(back.settled);
    assert_eq!(back.result_promise, PromiseHandle(5));
}

#[test]
fn promise_any_tracker_serde_roundtrip() {
    let mut tracker = PromiseAnyTracker {
        result_promise: PromiseHandle(3),
        errors: BTreeMap::new(),
        total: 2,
        rejected_count: 1,
        settled: false,
    };
    tracker.errors.insert(0, js_str("e"));
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PromiseAnyTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total, 2);
    assert_eq!(back.rejected_count, 1);
}

#[test]
fn promise_all_settled_tracker_serde_roundtrip() {
    let mut tracker = PromiseAllSettledTracker {
        result_promise: PromiseHandle(0),
        outcomes: BTreeMap::new(),
        total: 1,
        settled_count: 1,
    };
    tracker.outcomes.insert(
        0,
        SettledOutcome {
            status: "fulfilled".into(),
            value: js_int(10),
        },
    );
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PromiseAllSettledTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back.settled_count, 1);
}

#[test]
fn microtask_queue_enqueue_after_compact_works() {
    let mut queue = MicrotaskQueue::new();
    queue.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(1),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    queue.dequeue();
    queue.compact();
    // Now enqueue more after compaction
    queue.enqueue(Microtask::PromiseReaction {
        handler: Some(ClosureHandle(99)),
        argument: js_int(2),
        result_promise: PromiseHandle(1),
        label: Label::Public,
    });
    assert_eq!(queue.pending_count(), 1);
    let task = queue.dequeue().unwrap();
    if let Microtask::PromiseReaction { handler, .. } = task {
        assert_eq!(handler, Some(ClosureHandle(99)));
    } else {
        panic!("expected PromiseReaction");
    }
}

#[test]
fn event_loop_interleaved_micro_and_macro_tasks() {
    let mut el = EventLoop::new();
    // Schedule two timers
    el.set_timeout(ClosureHandle(0), 0, Label::Public);
    el.set_timeout(ClosureHandle(1), 100, Label::Public);

    // Also enqueue a microtask
    el.microtasks.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(1),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });

    // First turn: microtask drained first, then timer at 0
    let r1 = el.turn();
    assert_eq!(r1.microtasks_drained, 1);
    assert!(r1.macrotask.is_some());
    assert_eq!(r1.macrotask.as_ref().unwrap().handler, ClosureHandle(0));

    // Second turn: clock advances to 100
    let r2 = el.turn();
    assert!(r2.macrotask.is_some());
    assert_eq!(el.clock.now_ms(), 100);
}
