//! Exercise the real promise store and waiter table, not an alternate scheduler.
use super::*;
use crate::promise_model::{PromiseHandle, PromiseState};

fn fixture(throughput: bool) -> (InterpreterCore, TypedArrayView, TypedArrayView) {
    let tree = crate::parser_api_stability::parse_script(
        "({ a: new Int32Array(new SharedArrayBuffer(32)), b: new Int32Array(new SharedArrayBuffer(32)) });",
    )
    .expect("fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "atomics-notify-state.js"),
        &LoweringContext::new("atomics-notify", "waiter-ownership", "builtin-only"),
    )
    .expect("fixture lowers")
    .ir3;
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "atomics-notify-state");
    let Value::Object(root) = core.execute(&module).expect("fixture executes").value else {
        panic!("fixture root");
    };
    core.seed_register(0, Value::Object(root)).unwrap();
    let view = |name: &str| {
        let Some(Value::Object(id)) = core.heap[root.0 as usize].properties.get(name) else {
            panic!("fixture view");
        };
        core.heap[id.0 as usize]
            .typed_array
            .as_deref()
            .expect("native typed array")
            .clone()
    };
    let a = view("a");
    let b = view("b");
    (core, a, b)
}

fn queue(core: &InterpreterCore) -> Vec<PromiseHandle> {
    core.atomics_async_waiters.iter().map(|w| w.promise).collect()
}

fn pending(core: &InterpreterCore, promise: PromiseHandle) {
    assert_eq!(core.promise_store.get(promise).unwrap().state, PromiseState::Pending);
}

fn fulfilled(core: &InterpreterCore, promise: PromiseHandle, value: &str) {
    assert_eq!(
        core.promise_store.get(promise).unwrap().state,
        PromiseState::Fulfilled(crate::object_model::JsValue::Str(value.to_string()))
    );
}

fn accounted(core: &InterpreterCore) {
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
}

#[test]
fn partial_notifications_preserve_fifo_across_interleaved_buffers_and_offsets() {
    for throughput in [false, true] {
        let (mut core, a, b) = fixture(throughput);
        let mut original = Vec::new();
        for index in 0..36 {
            let (view, offset) = match index % 3 {
                0 => (&a, 0),
                1 => (&b, 0),
                _ => (&a, 1),
            };
            original.push(core.atomics_add_async_waiter(view, offset, f64::INFINITY).unwrap());
        }
        assert_eq!(core.notify_atomics_waiters(a.buffer, 0, 3.0, &Label::Public).unwrap(), 3);
        let expected: Vec<_> = original.iter().enumerate()
            .filter(|(i, _)| ![0, 3, 6].contains(i)).map(|(_, p)| *p).collect();
        assert_eq!(queue(&core), expected);
        for (index, promise) in original.iter().enumerate() {
            if [0, 3, 6].contains(&index) { fulfilled(&core, *promise, "ok"); }
            else { pending(&core, *promise); }
        }
        assert_eq!(core.notify_atomics_waiters(a.buffer, 4, f64::INFINITY, &Label::Public).unwrap(), 12);
        assert_eq!(core.notify_atomics_waiters(b.buffer, 0, f64::INFINITY, &Label::Public).unwrap(), 12);
        assert_eq!(core.notify_atomics_waiters(a.buffer, 0, f64::INFINITY, &Label::Public).unwrap(), 9);
        assert!(core.atomics_async_waiters.is_empty());
        for promise in original { fulfilled(&core, promise, "ok"); }
        accounted(&core);
    }
}

#[test]
fn notification_reuses_the_queue_allocation_and_releases_all_waiter_charges() {
    for throughput in [false, true] {
        let (mut core, a, _) = fixture(throughput);
        let mut promises = Vec::new();
        for _ in 0..512 {
            promises.push(core.atomics_add_async_waiter(&a, 0, f64::INFINITY).unwrap());
        }
        let pointer = core.atomics_async_waiters.as_ptr();
        let capacity = core.atomics_async_waiters.capacity();
        assert_eq!(core.atomics_async_waiters_memory_bytes(), 512 * ATOMICS_WAITER_BYTES);
        assert_eq!(core.notify_atomics_waiters(a.buffer, 0, f64::INFINITY, &Label::Public).unwrap(), 512);
        assert_eq!(core.atomics_async_waiters.as_ptr(), pointer);
        assert_eq!(core.atomics_async_waiters.capacity(), capacity);
        assert_eq!(core.atomics_async_waiters_memory_bytes(), 0);
        for promise in promises { fulfilled(&core, promise, "ok"); }
        accounted(&core);
    }
}

#[test]
fn completed_waiters_retire_both_timer_indexes_but_leave_live_timeouts_owned() {
    for throughput in [false, true] {
        let (mut core, a, b) = fixture(throughput);
        let first = core.atomics_add_async_waiter(&a, 0, 100_000.0).unwrap();
        let first_timer = core.atomics_async_waiters.last().unwrap().timer_id.unwrap();
        let other = core.atomics_add_async_waiter(&b, 0, 100_000.0).unwrap();
        let other_timer = core.atomics_async_waiters.last().unwrap().timer_id.unwrap();
        let expired = core.atomics_add_async_waiter(&a, 0, 100_000.0).unwrap();
        let expired_timer = core.atomics_async_waiters.last().unwrap().timer_id.unwrap();
        // Inject the timer's actual terminal promise state, without relying on
        // wall-clock sleeps or pretending this unit test drives the event loop.
        core.fulfill_promise(expired, crate::object_model::JsValue::Str("timed-out".into()), Label::Public).unwrap();
        assert_eq!(core.notify_atomics_waiters(a.buffer, 0, f64::INFINITY, &Label::Public).unwrap(), 1);
        fulfilled(&core, first, "ok");
        fulfilled(&core, expired, "timed-out");
        pending(&core, other);
        assert_eq!(queue(&core), [other]);
        for timer in [first_timer, expired_timer] {
            assert!(!core.active_timers.contains_key(&timer));
            assert!(!core.unref_timer_ids.contains(&timer));
        }
        assert!(core.active_timers.contains_key(&other_timer));
        assert!(core.unref_timer_ids.contains(&other_timer));
        let before = core.estimated_memory_bytes();
        core.prune_settled_atomics_waiters();
        assert_eq!(core.estimated_memory_bytes(), before, "retirement is idempotent");
        accounted(&core);
    }
}

#[test]
fn work_refusal_does_not_unlink_a_pending_waiter_or_cancel_its_timeout() {
    for throughput in [false, true] {
        let (mut core, a, _) = fixture(throughput);
        let promise = core.atomics_add_async_waiter(&a, 0, 100_000.0).unwrap();
        let timer = core.atomics_async_waiters[0].timer_id.unwrap();
        let limit = core.config.instruction_budget;
        core.config.instruction_budget = 0;
        let outcome = core.notify_atomics_waiters(a.buffer, 0, f64::INFINITY, &Label::Public);
        assert!(matches!(outcome, Err(InterpreterError::BudgetExhausted { .. })), "{outcome:?}");
        assert_eq!(queue(&core), [promise]);
        pending(&core, promise);
        assert!(core.active_timers.contains_key(&timer));
        assert!(core.unref_timer_ids.contains(&timer));
        assert!(core.pending_exception.is_none());
        core.config.instruction_budget = limit;
        assert_eq!(core.notify_atomics_waiters(a.buffer, 0, 1.0, &Label::Public).unwrap(), 1);
        fulfilled(&core, promise, "ok");
        accounted(&core);
    }
}

#[test]
fn settlement_admission_failure_keeps_the_waiter_available_for_retry() {
    for throughput in [false, true] {
        let (mut core, a, _) = fixture(throughput);
        let promise = core.atomics_add_async_waiter(&a, 0, 100_000.0).unwrap();
        let timer = core.atomics_async_waiters[0].timer_id.unwrap();
        let limit = core.config.max_total_memory_bytes;
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        let label = Label::Custom { name: "notification-context".repeat(1024), level: 2 };
        let outcome = core.notify_atomics_waiters(a.buffer, 0, 1.0, &label);
        assert!(matches!(outcome, Err(InterpreterError::MemoryBudgetExceeded { .. })), "{outcome:?}");
        assert_eq!(queue(&core), [promise]);
        pending(&core, promise);
        assert!(core.active_timers.contains_key(&timer));
        assert!(core.unref_timer_ids.contains(&timer));
        assert!(core.pending_exception.is_none());
        core.config.max_total_memory_bytes = limit;
        assert_eq!(core.notify_atomics_waiters(a.buffer, 0, 1.0, &Label::Secret).unwrap(), 1);
        fulfilled(&core, promise, "ok");
        assert_eq!(core.promise_store.get(promise).unwrap().label, Label::Secret);
        accounted(&core);
    }
}

#[test]
fn zero_count_never_settles_a_live_waiter() {
    let (mut core, a, _) = fixture(false);
    let promise = core.atomics_add_async_waiter(&a, 0, f64::INFINITY).unwrap();
    assert_eq!(core.notify_atomics_waiters(a.buffer, 0, 0.0, &Label::Public).unwrap(), 0);
    assert_eq!(queue(&core), [promise]);
    pending(&core, promise);
    accounted(&core);
}
