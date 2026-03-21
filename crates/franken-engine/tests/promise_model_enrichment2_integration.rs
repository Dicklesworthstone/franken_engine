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
    clippy::identity_op
)]

//! Enrichment integration tests (batch 2) for the `promise_model` module.

use std::collections::{BTreeMap, BTreeSet};

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
// PromiseState Display uniqueness
// ===========================================================================

#[test]
fn enrichment_promise_state_display_values_are_all_distinct() {
    let displays: BTreeSet<String> = vec![
        PromiseState::Pending,
        PromiseState::Fulfilled(JsValue::Undefined),
        PromiseState::Rejected(JsValue::Undefined),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

// ===========================================================================
// PromiseError Display uniqueness
// ===========================================================================

#[test]
fn enrichment_promise_error_display_all_distinct() {
    let errors = vec![
        PromiseError::AlreadySettled {
            handle: PromiseHandle(0),
        },
        PromiseError::InvalidHandle {
            handle: PromiseHandle(1),
        },
        PromiseError::LabelViolation {
            handle: PromiseHandle(2),
            value_label: Label::Secret,
            context_label: Label::Public,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

// ===========================================================================
// MacrotaskSource Display uniqueness
// ===========================================================================

#[test]
fn enrichment_macrotask_source_ordering_is_deterministic() {
    let mut sources = vec![
        MacrotaskSource::IoCompletion,
        MacrotaskSource::Timer,
        MacrotaskSource::MessageChannel,
    ];
    let sources2 = sources.clone();
    sources.sort();
    let mut sources3 = sources2;
    sources3.sort();
    assert_eq!(sources, sources3);
    assert_eq!(sources[0], MacrotaskSource::MessageChannel);
}

// ===========================================================================
// PromiseStore serde roundtrip
// ===========================================================================

#[test]
fn enrichment_promise_store_serde_roundtrip_empty() {
    let store = PromiseStore::new();
    let json = serde_json::to_string(&store).unwrap();
    let back: PromiseStore = serde_json::from_str(&json).unwrap();
    assert!(back.is_empty());
    assert_eq!(back.len(), 0);
}

#[test]
fn enrichment_promise_store_serde_roundtrip_with_promises() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    store.create();
    let h2 = store.create();
    store
        .fulfill(h2, js_int(42), Label::Public, &mut queue)
        .unwrap();
    let json = serde_json::to_string(&store).unwrap();
    let back: PromiseStore = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
}

// ===========================================================================
// MicrotaskQueue serde roundtrip
// ===========================================================================

#[test]
fn enrichment_microtask_queue_serde_roundtrip() {
    let mut queue = MicrotaskQueue::new();
    queue.enqueue(Microtask::PromiseReaction {
        handler: Some(ClosureHandle(10)),
        argument: js_str("hello"),
        result_promise: PromiseHandle(0),
        label: Label::Internal,
    });
    let json = serde_json::to_string(&queue).unwrap();
    let back: MicrotaskQueue = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_enqueued(), 1);
}

// ===========================================================================
// MacrotaskQueue serde roundtrip
// ===========================================================================

#[test]
fn enrichment_macrotask_queue_serde_roundtrip() {
    let mut queue = MacrotaskQueue::new();
    queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 100, Label::Public);
    queue.schedule(
        MacrotaskSource::IoCompletion,
        ClosureHandle(1),
        200,
        Label::Secret,
    );
    let json = serde_json::to_string(&queue).unwrap();
    let back: MacrotaskQueue = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
}

// ===========================================================================
// EventLoop serde roundtrip
// ===========================================================================

#[test]
fn enrichment_event_loop_serde_roundtrip() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 500, Label::Public);
    let json = serde_json::to_string(&el).unwrap();
    let back: EventLoop = serde_json::from_str(&json).unwrap();
    assert!(back.has_pending_work());
}

// ===========================================================================
// Multiple then on fulfilled promise
// ===========================================================================

#[test]
fn enrichment_multiple_then_on_fulfilled_each_enqueue_microtask() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.resolve(js_int(10), Label::Public, &mut queue);
    for i in 0..5 {
        store
            .then(h, Some(ClosureHandle(i)), None, Label::Public, &mut queue)
            .unwrap();
    }
    // 5 .then calls on a fulfilled promise => 5 microtasks
    assert!(queue.pending_count() >= 5);
}

// ===========================================================================
// Rejection propagation chain
// ===========================================================================

#[test]
fn enrichment_reject_propagates_through_chain() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let p1 = store.create();
    let p2 = store
        .then(p1, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
        .unwrap();
    let _p3 = store
        .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
        .unwrap();
    store
        .reject(p1, js_str("err"), Label::Public, &mut queue)
        .unwrap();
    // Rejection should have enqueued microtasks for reaction chain
    assert!(queue.pending_count() >= 2);
}

// ===========================================================================
// EventLoop drain_microtasks returns correct count
// ===========================================================================

#[test]
fn enrichment_event_loop_drain_returns_count() {
    let mut el = EventLoop::new();
    el.microtasks.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(1),
        result_promise: PromiseHandle(0),
        label: Label::Public,
    });
    el.microtasks.enqueue(Microtask::PromiseReaction {
        handler: None,
        argument: js_int(2),
        result_promise: PromiseHandle(1),
        label: Label::Public,
    });
    let count = el.drain_microtasks();
    assert_eq!(count, 2);
    assert!(el.microtasks.is_empty());
}

// ===========================================================================
// EventLoop max_microtasks_per_turn limit
// ===========================================================================

#[test]
fn enrichment_event_loop_max_microtask_limit() {
    let mut el = EventLoop::new();
    el.max_microtasks_per_turn = 3;
    for i in 0..10 {
        el.microtasks.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(i),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
    }
    let drained = el.drain_microtasks();
    assert_eq!(drained, 3);
    assert_eq!(el.microtasks.pending_count(), 7);
}

// ===========================================================================
// PromiseAllSettledTracker serde roundtrip
// ===========================================================================

#[test]
fn enrichment_promise_all_settled_tracker_serde_roundtrip() {
    let mut tracker = PromiseAllSettledTracker {
        result_promise: PromiseHandle(5),
        outcomes: BTreeMap::new(),
        total: 3,
        settled_count: 0,
    };
    tracker.record_fulfillment(0, js_int(10));
    tracker.record_rejection(1, js_str("err"));
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PromiseAllSettledTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back.settled_count, 2);
    assert_eq!(back.outcomes.len(), 2);
}

// ===========================================================================
// PromiseAllTracker serde roundtrip
// ===========================================================================

#[test]
fn enrichment_promise_all_tracker_serde_roundtrip() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(10),
        values: BTreeMap::new(),
        total: 2,
        resolved_count: 0,
        settled: false,
    };
    tracker.record_fulfillment(0, js_int(1));
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PromiseAllTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back.resolved_count, 1);
}

// ===========================================================================
// PromiseRaceTracker serde roundtrip
// ===========================================================================

#[test]
fn enrichment_promise_race_tracker_serde_roundtrip() {
    let tracker = PromiseRaceTracker {
        result_promise: PromiseHandle(20),
        settled: false,
    };
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PromiseRaceTracker = serde_json::from_str(&json).unwrap();
    assert!(!back.settled);
}

// ===========================================================================
// PromiseAnyTracker serde roundtrip
// ===========================================================================

#[test]
fn enrichment_promise_any_tracker_serde_roundtrip() {
    let mut tracker = PromiseAnyTracker {
        result_promise: PromiseHandle(30),
        errors: BTreeMap::new(),
        total: 3,
        rejected_count: 0,
        settled: false,
    };
    tracker.record_rejection(0, js_str("e1"));
    let json = serde_json::to_string(&tracker).unwrap();
    let back: PromiseAnyTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back.rejected_count, 1);
}

// ===========================================================================
// SettledOutcome serde
// ===========================================================================

#[test]
fn enrichment_settled_outcome_serde_roundtrip() {
    let outcome = SettledOutcome {
        status: "fulfilled".to_string(),
        value: js_int(42),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: SettledOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

// ===========================================================================
// PromiseReaction serde
// ===========================================================================

#[test]
fn enrichment_promise_reaction_serde_roundtrip() {
    let reaction = PromiseReaction {
        kind: ReactionKind::Fulfill,
        handler: Some(ClosureHandle(5)),
        result_promise: PromiseHandle(10),
        label: Label::Secret,
    };
    let json = serde_json::to_string(&reaction).unwrap();
    let back: PromiseReaction = serde_json::from_str(&json).unwrap();
    assert_eq!(reaction, back);
}

// ===========================================================================
// Macrotask serde
// ===========================================================================

#[test]
fn enrichment_macrotask_all_sources_serde() {
    for source in [
        MacrotaskSource::MessageChannel,
        MacrotaskSource::Timer,
        MacrotaskSource::IoCompletion,
    ] {
        let task = Macrotask {
            source,
            handler: ClosureHandle(0),
            scheduled_at: 0,
            registration_seq: 0,
            label: Label::Public,
        };
        let json = serde_json::to_string(&task).unwrap();
        let back: Macrotask = serde_json::from_str(&json).unwrap();
        assert_eq!(task, back);
    }
}

// ===========================================================================
// Multiple timers same time, deterministic tie-break
// ===========================================================================

#[test]
fn enrichment_macrotask_queue_deterministic_tiebreak_on_same_time() {
    let mut q = MacrotaskQueue::new();
    for i in 0..5 {
        q.schedule(MacrotaskSource::Timer, ClosureHandle(i), 100, Label::Public);
    }
    let mut handlers = Vec::new();
    while let Some(task) = q.dequeue_ready(100) {
        handlers.push(task.handler);
    }
    // Should dequeue in registration order (seq 0..4)
    assert_eq!(handlers, (0..5).map(ClosureHandle).collect::<Vec<_>>());
}

// ===========================================================================
// VirtualClock advance to same time is no-op
// ===========================================================================

#[test]
fn enrichment_virtual_clock_advance_to_same_time_noop() {
    let mut clock = VirtualClock::new();
    clock.advance_to(100);
    clock.advance_to(100);
    assert_eq!(clock.now_ms(), 100);
}

// ===========================================================================
// EventLoop multiple turns drain all work
// ===========================================================================

#[test]
fn enrichment_event_loop_drain_all_work_in_multiple_turns() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 10, Label::Public);
    el.set_timeout(ClosureHandle(1), 20, Label::Public);
    el.set_timeout(ClosureHandle(2), 30, Label::Public);

    let mut turn_count = 0;
    while el.has_pending_work() && turn_count < 10 {
        el.turn();
        turn_count += 1;
    }
    assert!(!el.has_pending_work());
    assert_eq!(turn_count, 3);
    assert_eq!(el.clock.now_ms(), 30);
}

// ===========================================================================
// Witness log length grows with operations
// ===========================================================================

#[test]
fn enrichment_witness_log_grows_with_operations() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    assert_eq!(store.witness_log().len(), 0);
    let h1 = store.create();
    assert_eq!(store.witness_log().len(), 1);
    let h2 = store.create();
    assert_eq!(store.witness_log().len(), 2);
    store
        .fulfill(h1, js_int(1), Label::Public, &mut queue)
        .unwrap();
    assert_eq!(store.witness_log().len(), 3);
    store
        .reject(h2, js_str("err"), Label::Public, &mut queue)
        .unwrap();
    assert_eq!(store.witness_log().len(), 4);
}

// ===========================================================================
// PromiseAllTracker collect_values with gaps
// ===========================================================================

#[test]
fn enrichment_promise_all_tracker_collect_values_with_gaps() {
    let mut tracker = PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total: 5,
        resolved_count: 0,
        settled: false,
    };
    // Only fulfill index 0, 2, 4 — gaps at 1 and 3
    tracker.record_fulfillment(0, js_int(10));
    tracker.record_fulfillment(2, js_int(30));
    tracker.record_fulfillment(4, js_int(50));
    let vals = tracker.collect_values();
    assert_eq!(vals.len(), 5);
    assert_eq!(vals[0], js_int(10));
    assert_eq!(vals[1], JsValue::Undefined);
    assert_eq!(vals[2], js_int(30));
    assert_eq!(vals[3], JsValue::Undefined);
    assert_eq!(vals[4], js_int(50));
}

// ===========================================================================
// PromiseAnyTracker collect_errors with gaps
// ===========================================================================

#[test]
fn enrichment_promise_any_tracker_collect_errors_with_gaps() {
    let mut tracker = PromiseAnyTracker {
        result_promise: PromiseHandle(0),
        errors: BTreeMap::new(),
        total: 4,
        rejected_count: 0,
        settled: false,
    };
    tracker.record_rejection(1, js_str("e1"));
    tracker.record_rejection(3, js_str("e3"));
    let errs = tracker.collect_errors();
    assert_eq!(errs.len(), 4);
    assert_eq!(errs[0], JsValue::Undefined);
    assert_eq!(errs[1], js_str("e1"));
    assert_eq!(errs[2], JsValue::Undefined);
    assert_eq!(errs[3], js_str("e3"));
}

// ===========================================================================
// Microtask ResolveThenable serde
// ===========================================================================

#[test]
fn enrichment_microtask_resolve_thenable_serde_roundtrip() {
    let task = Microtask::ResolveThenable {
        promise: PromiseHandle(7),
        then_handler: ClosureHandle(3),
        thenable: js_str("thenable_val"),
        label: Label::Internal,
    };
    let json = serde_json::to_string(&task).unwrap();
    let back: Microtask = serde_json::from_str(&json).unwrap();
    assert_eq!(task, back);
}

// ===========================================================================
// IFC label variants in reactions
// ===========================================================================

#[test]
fn enrichment_ifc_labels_propagated_through_fulfill() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let h = store.create();
    store
        .fulfill(h, js_int(1), Label::Secret, &mut queue)
        .unwrap();
    let record = store.get(h).unwrap();
    assert_eq!(record.label, Label::Secret);
    // Witness should record the label
    let fulfilled_witness = store.witness_log().iter().find(|e| {
        matches!(
            e,
            WitnessEvent::PromiseFulfilled {
                label: Label::Secret,
                ..
            }
        )
    });
    assert!(fulfilled_witness.is_some());
}

// ===========================================================================
// EventLoop witness records clock advances
// ===========================================================================

#[test]
fn enrichment_event_loop_witness_records_macrotask_execution() {
    let mut el = EventLoop::new();
    el.set_timeout(ClosureHandle(0), 100, Label::Public);
    el.turn();
    let has_macro_event = el
        .witness
        .iter()
        .any(|e| matches!(e, WitnessEvent::MacrotaskExecuted { .. }));
    assert!(has_macro_event);
}

// ===========================================================================
// Promise.resolve then reject_with deterministic sequence
// ===========================================================================

#[test]
fn enrichment_resolve_reject_with_deterministic_witness() {
    let run = || {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let _h1 = store.resolve(js_int(1), Label::Public, &mut queue);
        let _h2 = store.reject_with(js_str("err"), Label::Public, &mut queue);
        store.witness_log().to_vec()
    };
    let w1 = run();
    let w2 = run();
    assert_eq!(w1, w2);
}

// ===========================================================================
// PromiseHandle Display format
// ===========================================================================

#[test]
fn enrichment_promise_handle_display_format() {
    assert_eq!(PromiseHandle(0).to_string(), "Promise(0)");
    assert_eq!(PromiseHandle(999).to_string(), "Promise(999)");
}

// ===========================================================================
// MacrotaskQueue dequeue_ready returns None when empty
// ===========================================================================

#[test]
fn enrichment_macrotask_queue_dequeue_empty_returns_none() {
    let mut q = MacrotaskQueue::new();
    assert!(q.dequeue_ready(0).is_none());
    assert!(q.dequeue_ready(u64::MAX).is_none());
}

// ===========================================================================
// ExceptionToRejectionBridge integration tests (bd-1lsy.4.13.3)
// ===========================================================================

#[test]
fn enrichment_bridge_new_has_zero_transitions() {
    let bridge = ExceptionToRejectionBridge::new();
    assert_eq!(bridge.transition_count(), 0);
    assert!(bridge.witness_log().is_empty());
}

#[test]
fn enrichment_bridge_default_matches_new() {
    let a = ExceptionToRejectionBridge::new();
    let b = ExceptionToRejectionBridge::default();
    assert_eq!(a.transition_count(), b.transition_count());
    assert_eq!(a.witness_log().len(), b.witness_log().len());
}

#[test]
fn enrichment_bridge_async_exception_witness_has_correct_boundary() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let mut bridge = ExceptionToRejectionBridge::new();
    let p = store.create();

    bridge
        .bridge_async_exception(JsValue::Str("oops".into()), p, &mut store, &mut queue)
        .unwrap();

    let log = bridge.witness_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].boundary, ExceptionBoundaryKind::AsyncFunctionBody);
    assert_eq!(log[0].promise, Some(p));
    assert!(log[0].module_specifier.is_none());
}

#[test]
fn enrichment_bridge_module_exception_witness_has_specifier() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let mut bridge = ExceptionToRejectionBridge::new();
    let p = store.create();

    bridge
        .bridge_module_exception(
            JsValue::Int(42),
            "entry.mjs",
            Some(p),
            &mut store,
            &mut queue,
        )
        .unwrap();

    let log = bridge.witness_log();
    assert_eq!(log[0].boundary, ExceptionBoundaryKind::ModuleEvaluation);
    assert_eq!(log[0].module_specifier.as_deref(), Some("entry.mjs"));
}

#[test]
fn enrichment_bridge_hostcall_exception_without_promise_succeeds() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let mut bridge = ExceptionToRejectionBridge::new();

    let outcome = bridge
        .bridge_hostcall_exception(JsValue::Null, None, &mut store, &mut queue)
        .unwrap();

    assert!(outcome.rejected_promise.is_none());
    assert_eq!(outcome.rejection_reason, JsValue::Null);
}

#[test]
fn enrichment_bridge_microtask_exception_increments_counter() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let mut bridge = ExceptionToRejectionBridge::new();

    for i in 0..5 {
        let p = store.create();
        bridge
            .bridge_microtask_exception(JsValue::Int(i), Some(p), &mut store, &mut queue)
            .unwrap();
    }

    assert_eq!(bridge.transition_count(), 5);
    assert_eq!(bridge.witness_log().len(), 5);
    for (idx, event) in bridge.witness_log().iter().enumerate() {
        assert_eq!(event.seq, idx as u64);
        assert_eq!(event.boundary, ExceptionBoundaryKind::MicrotaskReaction);
    }
}

#[test]
fn enrichment_bridge_mixed_boundaries_maintain_ordering() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let mut bridge = ExceptionToRejectionBridge::new();

    let p1 = store.create();
    let p2 = store.create();
    let p3 = store.create();

    bridge
        .bridge_async_exception(JsValue::Str("a".into()), p1, &mut store, &mut queue)
        .unwrap();
    bridge
        .bridge_module_exception(
            JsValue::Str("m".into()),
            "mod.js",
            Some(p2),
            &mut store,
            &mut queue,
        )
        .unwrap();
    bridge
        .bridge_hostcall_exception(JsValue::Str("h".into()), Some(p3), &mut store, &mut queue)
        .unwrap();

    let log = bridge.witness_log();
    assert_eq!(log[0].boundary, ExceptionBoundaryKind::AsyncFunctionBody);
    assert_eq!(log[1].boundary, ExceptionBoundaryKind::ModuleEvaluation);
    assert_eq!(log[2].boundary, ExceptionBoundaryKind::HostcallBoundary);
    assert_eq!(log[0].seq, 0);
    assert_eq!(log[1].seq, 1);
    assert_eq!(log[2].seq, 2);
}

#[test]
fn enrichment_bridge_outcome_description_contains_value() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let mut bridge = ExceptionToRejectionBridge::new();
    let p = store.create();

    let outcome = bridge
        .bridge_async_exception(
            JsValue::Str("TypeError: cannot read property".into()),
            p,
            &mut store,
            &mut queue,
        )
        .unwrap();

    assert!(
        outcome
            .reason_description
            .contains("TypeError: cannot read property")
    );
}

#[test]
fn enrichment_bridge_rejected_promise_matches_unhandled_list() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let mut bridge = ExceptionToRejectionBridge::new();
    let p = store.create();

    bridge
        .bridge_async_exception(JsValue::Str("err".into()), p, &mut store, &mut queue)
        .unwrap();

    let unhandled = store.unhandled_rejections();
    assert!(
        unhandled.contains(&p),
        "rejected promise should be unhandled"
    );
}

#[test]
fn enrichment_bridge_outcome_serde_roundtrip_with_all_fields() {
    let outcome = ExceptionRejectionOutcome {
        rejected_promise: Some(PromiseHandle(42)),
        rejection_reason: JsValue::Str("test error".into()),
        reason_description: "Str(\"test error\")".into(),
        module_specifier: Some("index.mjs".into()),
        propagated: true,
        affected_module_count: 7,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ExceptionRejectionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
    assert!(json.contains("index.mjs"));
    assert!(json.contains("42"));
}

#[test]
fn enrichment_exception_boundary_kind_all_variants_distinct() {
    let variants = [
        ExceptionBoundaryKind::AsyncFunctionBody,
        ExceptionBoundaryKind::ModuleEvaluation,
        ExceptionBoundaryKind::HostcallBoundary,
        ExceptionBoundaryKind::MicrotaskReaction,
    ];
    let mut serialized = BTreeSet::new();
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        assert!(serialized.insert(json), "duplicate variant serialization");
    }
    assert_eq!(serialized.len(), 4);
}

#[test]
fn enrichment_bridge_witness_event_deterministic_across_runs() {
    let store = PromiseStore::new();
    let queue = MicrotaskQueue::new();

    let run = |store: &mut PromiseStore, queue: &mut MicrotaskQueue| {
        let mut bridge = ExceptionToRejectionBridge::new();
        let p = store.create();
        bridge
            .bridge_async_exception(JsValue::Int(1), p, store, queue)
            .unwrap();
        serde_json::to_string(bridge.witness_log()).unwrap()
    };

    let r1 = run(&mut store.clone(), &mut queue.clone());
    let r2 = run(&mut store.clone(), &mut queue.clone());
    assert_eq!(r1, r2, "witness log must be deterministic across runs");
}
