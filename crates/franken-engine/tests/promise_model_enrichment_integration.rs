#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the `promise_model` module.

use std::collections::BTreeMap;

use frankenengine_engine::closure_model::ClosureHandle;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::*;

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
// PromiseHandle enrichment
// ===========================================================================

#[test]
fn promise_handle_display() {
    let h = PromiseHandle(42);
    assert_eq!(h.to_string(), "Promise(42)");
}

#[test]
fn promise_handle_ordering() {
    assert!(PromiseHandle(0) < PromiseHandle(1));
    assert!(PromiseHandle(100) > PromiseHandle(99));
}

#[test]
fn promise_handle_copy_semantics() {
    let a = PromiseHandle(5);
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn promise_handle_serde_roundtrip() {
    let h = PromiseHandle(999);
    let json = serde_json::to_string(&h).expect("serialize");
    let restored: PromiseHandle = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(h, restored);
}

// ===========================================================================
// PromiseState enrichment
// ===========================================================================

#[test]
fn promise_state_pending_not_settled() {
    let s = PromiseState::Pending;
    assert!(!s.is_settled());
    assert!(!s.is_fulfilled());
    assert!(!s.is_rejected());
}

#[test]
fn promise_state_fulfilled_is_settled() {
    let s = PromiseState::Fulfilled(js_int(1));
    assert!(s.is_settled());
    assert!(s.is_fulfilled());
    assert!(!s.is_rejected());
}

#[test]
fn promise_state_rejected_is_settled() {
    let s = PromiseState::Rejected(js_str("err"));
    assert!(s.is_settled());
    assert!(!s.is_fulfilled());
    assert!(s.is_rejected());
}

#[test]
fn promise_state_display_all() {
    assert_eq!(PromiseState::Pending.to_string(), "pending");
    assert_eq!(PromiseState::Fulfilled(js_int(0)).to_string(), "fulfilled");
    assert_eq!(PromiseState::Rejected(js_int(0)).to_string(), "rejected");
}

#[test]
fn promise_state_serde_roundtrip() {
    let states = vec![
        PromiseState::Pending,
        PromiseState::Fulfilled(js_int(42)),
        PromiseState::Rejected(js_str("error")),
    ];
    for s in &states {
        let json = serde_json::to_string(s).expect("serialize");
        let restored: PromiseState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*s, restored);
    }
}

// ===========================================================================
// ReactionKind enrichment
// ===========================================================================

#[test]
fn reaction_kind_serde_roundtrip() {
    for kind in [ReactionKind::Fulfill, ReactionKind::Reject] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let restored: ReactionKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, restored);
    }
}

// ===========================================================================
// PromiseError enrichment
// ===========================================================================

#[test]
fn promise_error_already_settled_display() {
    let err = PromiseError::AlreadySettled { handle: PromiseHandle(3) };
    assert!(err.to_string().contains("already settled"));
    assert!(err.to_string().contains("Promise(3)"));
}

#[test]
fn promise_error_invalid_handle_display() {
    let err = PromiseError::InvalidHandle { handle: PromiseHandle(999) };
    assert!(err.to_string().contains("invalid promise handle"));
}

#[test]
fn promise_error_label_violation_display() {
    let err = PromiseError::LabelViolation {
        handle: PromiseHandle(1),
        value_label: Label::Secret,
        context_label: Label::Public,
    };
    assert!(err.to_string().contains("IFCError"));
}

#[test]
fn promise_error_serde_roundtrip() {
    let errors = vec![
        PromiseError::AlreadySettled { handle: PromiseHandle(1) },
        PromiseError::InvalidHandle { handle: PromiseHandle(2) },
        PromiseError::LabelViolation {
            handle: PromiseHandle(3),
            value_label: Label::Public,
            context_label: Label::Secret,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: PromiseError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// PromiseStore enrichment
// ===========================================================================

#[test]
fn store_new_is_empty() {
    let store = PromiseStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn store_create_increments_len() {
    let mut store = PromiseStore::new();
    store.create();
    assert_eq!(store.len(), 1);
    store.create();
    assert_eq!(store.len(), 2);
    assert!(!store.is_empty());
}

#[test]
fn store_create_returns_sequential_handles() {
    let mut store = PromiseStore::new();
    let h0 = store.create();
    let h1 = store.create();
    let h2 = store.create();
    assert_eq!(h0, PromiseHandle(0));
    assert_eq!(h1, PromiseHandle(1));
    assert_eq!(h2, PromiseHandle(2));
}

#[test]
fn store_get_invalid_handle() {
    let store = PromiseStore::new();
    assert!(store.get(PromiseHandle(0)).is_err());
}

#[test]
fn store_fulfill_sets_state() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store.fulfill(h, js_int(100), Label::Public, &mut queue).unwrap();
    let p = store.get(h).unwrap();
    assert_eq!(p.state, PromiseState::Fulfilled(js_int(100)));
}

#[test]
fn store_reject_sets_state() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store.reject(h, js_str("fail"), Label::Public, &mut queue).unwrap();
    let p = store.get(h).unwrap();
    assert_eq!(p.state, PromiseState::Rejected(js_str("fail")));
}

#[test]
fn store_double_fulfill_error() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store.fulfill(h, js_int(1), Label::Public, &mut queue).unwrap();
    let err = store.fulfill(h, js_int(2), Label::Public, &mut queue).unwrap_err();
    assert!(matches!(err, PromiseError::AlreadySettled { .. }));
}

#[test]
fn store_double_reject_error() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store.reject(h, js_str("a"), Label::Public, &mut queue).unwrap();
    let err = store.reject(h, js_str("b"), Label::Public, &mut queue).unwrap_err();
    assert!(matches!(err, PromiseError::AlreadySettled { .. }));
}

#[test]
fn store_resolve_creates_fulfilled_promise() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.resolve(js_int(42), Label::Public, &mut queue);
    let p = store.get(h).unwrap();
    assert!(p.state.is_fulfilled());
}

#[test]
fn store_reject_with_creates_rejected_promise() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.reject_with(js_str("err"), Label::Public, &mut queue);
    let p = store.get(h).unwrap();
    assert!(p.state.is_rejected());
}

#[test]
fn store_unhandled_rejections() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h1 = store.create();
    let h2 = store.create();
    store.reject(h1, js_str("err1"), Label::Public, &mut queue).unwrap();
    store.reject(h2, js_str("err2"), Label::Public, &mut queue).unwrap();
    let unhandled = store.unhandled_rejections();
    assert_eq!(unhandled.len(), 2);
}

#[test]
fn store_witness_log_records_events() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store.fulfill(h, js_int(1), Label::Public, &mut queue).unwrap();
    let log = store.witness_log();
    assert!(log.len() >= 2); // created + fulfilled
}

// ===========================================================================
// MicrotaskQueue enrichment
// ===========================================================================

#[test]
fn microtask_queue_new_is_empty() {
    let q = MicrotaskQueue::new();
    assert!(q.is_empty());
    assert_eq!(q.pending_count(), 0);
    assert_eq!(q.total_enqueued(), 0);
}

#[test]
fn microtask_queue_fifo_order() {
    let mut q = MicrotaskQueue::new();
    q.enqueue(Microtask::PromiseReaction {
        handler: Some(ClosureHandle(0)),
        argument: js_int(1),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    q.enqueue(Microtask::PromiseReaction {
        handler: Some(ClosureHandle(1)),
        argument: js_int(2),
        result_promise: PromiseHandle(1),
        label: Label::Public,
    });
    assert_eq!(q.pending_count(), 2);
    let first = q.dequeue().unwrap();
    if let Microtask::PromiseReaction { argument, .. } = first {
        assert_eq!(argument, js_int(1));
    }
    let second = q.dequeue().unwrap();
    if let Microtask::PromiseReaction { argument, .. } = second {
        assert_eq!(argument, js_int(2));
    }
    assert!(q.is_empty());
}

#[test]
fn microtask_queue_dequeue_empty_returns_none() {
    let mut q = MicrotaskQueue::new();
    assert!(q.dequeue().is_none());
}

#[test]
fn microtask_queue_total_enqueued_counts_all() {
    let mut q = MicrotaskQueue::new();
    for _ in 0..5 {
        q.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(0),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
    }
    assert_eq!(q.total_enqueued(), 5);
    // Drain some
    q.dequeue();
    q.dequeue();
    assert_eq!(q.total_enqueued(), 5); // still 5
    assert_eq!(q.pending_count(), 3);
}

#[test]
fn microtask_queue_compact() {
    let mut q = MicrotaskQueue::new();
    for _ in 0..3 {
        q.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(0),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
    }
    q.dequeue();
    q.dequeue();
    q.compact();
    assert_eq!(q.pending_count(), 1);
}

#[test]
fn microtask_queue_witness_log() {
    let mut q = MicrotaskQueue::new();
    q.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(0),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    q.dequeue();
    let log = q.witness_log();
    assert!(log.len() >= 2); // enqueue + dequeue
}

// ===========================================================================
// MacrotaskQueue enrichment
// ===========================================================================

#[test]
fn macrotask_queue_new_is_empty() {
    let q = MacrotaskQueue::new();
    assert!(q.is_empty());
    assert_eq!(q.len(), 0);
}

#[test]
fn macrotask_queue_schedule_and_dequeue() {
    let mut q = MacrotaskQueue::new();
    q.schedule(MacrotaskSource::Timer, ClosureHandle(0), 100, Label::Public);
    assert_eq!(q.len(), 1);
    assert!(!q.is_empty());
    let task = q.dequeue_ready(100).unwrap();
    assert_eq!(task.source, MacrotaskSource::Timer);
    assert!(q.is_empty());
}

#[test]
fn macrotask_queue_not_ready_before_time() {
    let mut q = MacrotaskQueue::new();
    q.schedule(MacrotaskSource::Timer, ClosureHandle(0), 200, Label::Public);
    assert!(q.dequeue_ready(100).is_none());
    assert!(q.dequeue_ready(200).is_some());
}

#[test]
fn macrotask_queue_priority_order() {
    let mut q = MacrotaskQueue::new();
    q.schedule(MacrotaskSource::IoCompletion, ClosureHandle(0), 0, Label::Public);
    q.schedule(MacrotaskSource::MessageChannel, ClosureHandle(1), 0, Label::Public);
    q.schedule(MacrotaskSource::Timer, ClosureHandle(2), 0, Label::Public);

    let first = q.dequeue_ready(0).unwrap();
    assert_eq!(first.source, MacrotaskSource::MessageChannel);
    let second = q.dequeue_ready(0).unwrap();
    assert_eq!(second.source, MacrotaskSource::Timer);
    let third = q.dequeue_ready(0).unwrap();
    assert_eq!(third.source, MacrotaskSource::IoCompletion);
}

#[test]
fn macrotask_queue_next_scheduled_time() {
    let mut q = MacrotaskQueue::new();
    assert!(q.next_scheduled_time().is_none());
    q.schedule(MacrotaskSource::Timer, ClosureHandle(0), 300, Label::Public);
    q.schedule(MacrotaskSource::Timer, ClosureHandle(1), 100, Label::Public);
    assert_eq!(q.next_scheduled_time(), Some(100));
}

// ===========================================================================
// VirtualClock enrichment
// ===========================================================================

#[test]
fn virtual_clock_starts_at_zero() {
    let c = VirtualClock::new();
    assert_eq!(c.now_ms(), 0);
}

#[test]
fn virtual_clock_advance() {
    let mut c = VirtualClock::new();
    c.advance_to(100);
    assert_eq!(c.now_ms(), 100);
}

#[test]
fn virtual_clock_no_backward() {
    let mut c = VirtualClock::new();
    c.advance_to(100);
    c.advance_to(50);
    assert_eq!(c.now_ms(), 100);
}

#[test]
fn virtual_clock_timer_seq() {
    let mut c = VirtualClock::new();
    assert_eq!(c.register_timer(), 0);
    assert_eq!(c.register_timer(), 1);
    assert_eq!(c.register_timer(), 2);
}

#[test]
fn virtual_clock_serde_roundtrip() {
    let mut c = VirtualClock::new();
    c.advance_to(42);
    c.register_timer();
    let json = serde_json::to_string(&c).expect("serialize");
    let restored: VirtualClock = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, restored);
}

// ===========================================================================
// EventLoop enrichment
// ===========================================================================

#[test]
fn event_loop_new_no_pending_work() {
    let el = EventLoop::new();
    assert!(!el.has_pending_work());
}

#[test]
fn event_loop_with_microtask_has_work() {
    let mut el = EventLoop::new();
    el.microtasks.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(0),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    assert!(el.has_pending_work());
}

#[test]
fn event_loop_set_timeout() {
    let mut el = EventLoop::new();
    let seq = el.set_timeout(ClosureHandle(0), 100, Label::Public);
    assert_eq!(seq, 0);
    assert!(el.has_pending_work());
}

#[test]
fn event_loop_turn_drains_microtasks() {
    let mut el = EventLoop::new();
    for _ in 0..5 {
        el.microtasks.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(0),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
    }
    let result = el.turn();
    assert_eq!(result.microtasks_drained, 5);
    assert!(el.microtasks.is_empty());
}

#[test]
fn event_loop_turn_picks_macrotask() {
    let mut el = EventLoop::new();
    el.macrotasks.schedule(MacrotaskSource::Timer, ClosureHandle(0), 0, Label::Public);
    let result = el.turn();
    assert!(result.macrotask.is_some());
}

#[test]
fn event_loop_turn_advances_clock_for_future_macrotask() {
    let mut el = EventLoop::new();
    el.macrotasks.schedule(MacrotaskSource::Timer, ClosureHandle(0), 500, Label::Public);
    let result = el.turn();
    assert!(result.clock_advanced);
    assert_eq!(el.clock.now_ms(), 500);
    assert!(result.macrotask.is_some());
}

// ===========================================================================
// Promise.all tracker enrichment
// ===========================================================================

#[test]
fn promise_all_tracker_complete() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total: 3,
        resolved_count: 0,
        settled: false,
    };
    assert!(!tracker.record_fulfillment(0, js_int(10)));
    assert!(!tracker.record_fulfillment(1, js_int(20)));
    assert!(tracker.record_fulfillment(2, js_int(30)));
    let values = tracker.collect_values();
    assert_eq!(values, vec![js_int(10), js_int(20), js_int(30)]);
}

#[test]
fn promise_all_tracker_settled_ignores_further() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total: 2,
        resolved_count: 0,
        settled: false,
    };
    tracker.mark_settled();
    assert!(!tracker.record_fulfillment(0, js_int(1)));
}

#[test]
fn promise_all_tracker_collect_missing_yields_undefined() {
    let tracker = PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total: 3,
        resolved_count: 0,
        settled: false,
    };
    let values = tracker.collect_values();
    assert_eq!(values, vec![JsValue::Undefined, JsValue::Undefined, JsValue::Undefined]);
}

// ===========================================================================
// Promise.allSettled tracker enrichment
// ===========================================================================

#[test]
fn promise_all_settled_mixed_outcomes() {
    let mut tracker = PromiseAllSettledTracker {
        result_promise: PromiseHandle(0),
        outcomes: BTreeMap::new(),
        total: 3,
        settled_count: 0,
    };
    assert!(!tracker.record_fulfillment(0, js_int(1)));
    assert!(!tracker.record_rejection(1, js_str("err")));
    assert!(tracker.record_fulfillment(2, js_int(3)));
    assert_eq!(tracker.outcomes.len(), 3);
    assert_eq!(tracker.outcomes[&0].status, "fulfilled");
    assert_eq!(tracker.outcomes[&1].status, "rejected");
}

// ===========================================================================
// Promise.race tracker enrichment
// ===========================================================================

#[test]
fn promise_race_first_settles() {
    let mut tracker = PromiseRaceTracker {
        result_promise: PromiseHandle(0),
        settled: false,
    };
    assert!(tracker.try_settle());
    assert!(!tracker.try_settle()); // second attempt fails
}

// ===========================================================================
// Promise.any tracker enrichment
// ===========================================================================

#[test]
fn promise_any_all_rejected() {
    let mut tracker = PromiseAnyTracker {
        result_promise: PromiseHandle(0),
        errors: BTreeMap::new(),
        total: 2,
        rejected_count: 0,
        settled: false,
    };
    assert!(!tracker.record_rejection(0, js_str("e1")));
    assert!(tracker.record_rejection(1, js_str("e2")));
    let errors = tracker.collect_errors();
    assert_eq!(errors, vec![js_str("e1"), js_str("e2")]);
}

#[test]
fn promise_any_settled_ignores_further() {
    let mut tracker = PromiseAnyTracker {
        result_promise: PromiseHandle(0),
        errors: BTreeMap::new(),
        total: 3,
        rejected_count: 0,
        settled: false,
    };
    tracker.mark_settled();
    assert!(!tracker.record_rejection(0, js_str("e1")));
}

// ===========================================================================
// WitnessEvent enrichment
// ===========================================================================

#[test]
fn witness_event_all_variants_serde() {
    let events = vec![
        WitnessEvent::PromiseCreated { handle: PromiseHandle(0), seq: 0 },
        WitnessEvent::PromiseFulfilled { handle: PromiseHandle(1), value: js_int(42), label: Label::Public },
        WitnessEvent::PromiseRejected { handle: PromiseHandle(2), reason: js_str("err"), label: Label::Secret },
        WitnessEvent::MicrotaskEnqueued { index: 0 },
        WitnessEvent::MicrotaskDequeued { index: 0 },
        WitnessEvent::MacrotaskExecuted { source: MacrotaskSource::Timer, registration_seq: 0 },
        WitnessEvent::ClockAdvanced { from_ms: 0, to_ms: 100 },
    ];
    for ev in &events {
        let json = serde_json::to_string(ev).expect("serialize");
        let restored: WitnessEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*ev, restored);
    }
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn promise_operations_deterministic() {
    let run = || {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h1 = store.create();
        let h2 = store.create();
        store.fulfill(h1, js_int(1), Label::Public, &mut queue).unwrap();
        store.reject(h2, js_str("err"), Label::Public, &mut queue).unwrap();
        store.witness_log().to_vec()
    };
    let log1 = run();
    let log2 = run();
    assert_eq!(log1, log2);
}

#[test]
fn microtask_queue_deterministic_ordering() {
    let run = || {
        let mut q = MicrotaskQueue::new();
        for i in 0..10 {
            q.enqueue(Microtask::PromiseReaction {
                handler: Some(ClosureHandle(i)),
                argument: js_int(i as i64),
                result_promise: PromiseHandle(i as u32),
                label: Label::Public,
            });
        }
        let mut dequeued = Vec::new();
        while let Some(task) = q.dequeue() {
            dequeued.push(task);
        }
        dequeued
    };
    let d1 = run();
    let d2 = run();
    assert_eq!(d1, d2);
}
