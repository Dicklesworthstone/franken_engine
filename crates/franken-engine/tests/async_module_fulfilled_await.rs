#![forbid(unsafe_code)]

//! Regressions for already-fulfilled awaits at the runtime boundary. These
//! exercise real Promise/evaluator/scheduler state, not JavaScript execution.

use frankenengine_engine::async_module_graph::ModuleGraphNode;
use frankenengine_engine::async_module_promise_bridge::{
    AsyncModulePromiseBridge, AsyncModulePromiseBridgeError, ModulePromiseStatus,
};
use frankenengine_engine::async_module_runtime::AsyncModuleRuntime;
use frankenengine_engine::async_module_scheduler::{
    AsyncModuleScheduler, AsyncModuleSchedulerConfig, AsyncModuleSchedulerError, ModuleTaskKind,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::module_async_evaluation::{
    AsyncEvalConfig, AsyncEvalEventType, AsyncModulePhase,
};
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::{PromiseHandle, PromiseState};

fn node(name: &str, tla: bool, dependencies: &[&str]) -> ModuleGraphNode {
    ModuleGraphNode {
        specifier: name.to_string(),
        has_top_level_await: tla,
        dependencies: dependencies
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
    }
}

fn scheduler_state(scheduler: &AsyncModuleScheduler) -> serde_json::Value {
    let bridge = scheduler.bridge();
    let in_flight: Vec<_> = bridge
        .evaluator()
        .states()
        .keys()
        .filter_map(|name| scheduler.in_flight_task(name))
        .collect();
    let active_awaits: Vec<_> = bridge
        .evaluator()
        .states()
        .keys()
        .map(|name| (name, bridge.active_await(name)))
        .collect();
    serde_json::json!({
        "snapshot": scheduler.snapshot(),
        "states": bridge.evaluator().states(),
        "events": bridge.evaluator().witness_events(),
        "promises": bridge.promise_store(),
        "microtasks": bridge.microtasks(),
        "bindings": bridge.live_bindings(),
        "in_flight": in_flight,
        "active_awaits": active_awaits,
    })
}

#[test]
fn bridge_records_fulfilled_await_without_resettling_or_retaining_waiter() {
    let mut bridge = AsyncModulePromiseBridge::with_defaults();
    let evaluation = bridge.register_module("app", true, &[]).unwrap().unwrap();
    let promise = bridge.create_pending_promise();
    assert!(
        bridge
            .fulfill_awaited_promise(promise, JsValue::Int(42), Label::Secret)
            .unwrap()
            .is_empty()
    );
    let promises_before = serde_json::to_value(bridge.promise_store()).unwrap();
    let microtasks_before = serde_json::to_value(bridge.microtasks()).unwrap();

    bridge.suspend_module_on_promise("app", promise).unwrap();

    let state = &bridge.evaluator().states()["app"];
    assert!(!state.phase.is_terminal());
    assert_eq!(state.suspensions.len(), 1);
    assert_eq!(state.suspensions[0].awaiting_promise, promise);
    assert!(state.suspensions[0].resolved);
    assert!(state.suspensions[0].resume_seq > state.suspensions[0].suspension_seq);
    assert_eq!(bridge.active_await("app"), None);
    assert_eq!(
        bridge.promise_store().get(evaluation).unwrap().state,
        PromiseState::Pending
    );
    assert_eq!(
        serde_json::to_value(bridge.promise_store()).unwrap(),
        promises_before
    );
    assert_eq!(
        serde_json::to_value(bridge.microtasks()).unwrap(),
        microtasks_before
    );
    assert_eq!(
        bridge
            .evaluator()
            .witness_events()
            .iter()
            .filter(|event| event.event_type == AsyncEvalEventType::EvaluationResumed)
            .count(),
        1
    );
}

#[test]
fn fulfilled_host_promise_hands_off_value_label_and_a_new_lease() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
    let evaluation = runtime.evaluation_promise("app").unwrap();
    let start = runtime.next_task().unwrap().unwrap();
    let promise = runtime.create_pending_promise();
    runtime
        .fulfill_awaited_promise(promise, JsValue::Str("secret".into()), Label::Secret)
        .unwrap();

    runtime.suspend_task(&start, promise).unwrap();

    assert_eq!(runtime.snapshot().in_flight_tasks, 0);
    assert_eq!(runtime.snapshot().ready_tasks, 1);
    assert_eq!(
        runtime.promise_result(evaluation).unwrap().0,
        &PromiseState::Pending
    );
    assert!(runtime.resume_input(&start).is_err());
    let resume = runtime.next_task().unwrap().unwrap();
    assert_eq!(resume.kind, ModuleTaskKind::Resume);
    assert!(resume.generation > start.generation);
    assert!(resume.sequence > start.sequence);
    let input = runtime.resume_input(&resume).unwrap().unwrap();
    assert_eq!(input.promise, promise);
    assert_eq!(input.value, JsValue::Str("secret".into()));
    assert_eq!(input.label, Label::Secret);
    assert_eq!(runtime.resume_input(&resume).unwrap(), Some(input));
    assert!(runtime.next_task().unwrap().is_none());
    runtime
        .complete_task(&resume, JsValue::Int(7), Label::Secret)
        .unwrap();
    assert_eq!(runtime.module_phases()["app"], AsyncModulePhase::Settled);
}

#[test]
fn completed_dependency_evaluation_promise_can_be_awaited() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[
        node("app", true, &["provider"]),
        node("provider", true, &[]),
    ])
    .unwrap();
    let provider_promise = runtime.evaluation_promise("provider").unwrap();
    let provider = runtime.next_task().unwrap().unwrap();
    assert_eq!(provider.module_specifier, "provider");
    runtime
        .complete_task(&provider, JsValue::Int(13), Label::Confidential)
        .unwrap();
    let app = runtime.next_task().unwrap().unwrap();
    assert_eq!(app.module_specifier, "app");

    runtime.suspend_task(&app, provider_promise).unwrap();

    let resume = runtime.next_task().unwrap().unwrap();
    let input = runtime.resume_input(&resume).unwrap().unwrap();
    assert_eq!(input.promise, provider_promise);
    assert_eq!(input.value, JsValue::Int(13));
    assert_eq!(input.label, Label::Confidential);
    assert_eq!(
        runtime.module_phases()["provider"],
        AsyncModulePhase::Settled
    );
    assert_eq!(
        runtime
            .promise_result(runtime.evaluation_promise("app").unwrap())
            .unwrap()
            .0,
        &PromiseState::Pending
    );
}

#[test]
fn fulfilled_undefined_is_a_real_resume_input() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
    let start = runtime.next_task().unwrap().unwrap();
    assert_eq!(runtime.resume_input(&start).unwrap(), None);
    let promise = runtime.create_pending_promise();
    runtime
        .fulfill_awaited_promise(promise, JsValue::Undefined, Label::Public)
        .unwrap();
    runtime.suspend_task(&start, promise).unwrap();
    let resume = runtime.next_task().unwrap().unwrap();
    let input = runtime.resume_input(&resume).unwrap().unwrap();
    assert_eq!(input.promise, promise);
    assert_eq!(input.value, JsValue::Undefined);
}

#[test]
fn repeated_fulfilled_awaits_issue_distinct_leases_and_do_not_reuse_values() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
    let first = runtime.create_pending_promise();
    let second = runtime.create_pending_promise();
    runtime
        .fulfill_awaited_promise(first, JsValue::Int(1), Label::Secret)
        .unwrap();
    runtime
        .fulfill_awaited_promise(second, JsValue::Int(2), Label::Confidential)
        .unwrap();
    let mut task = runtime.next_task().unwrap().unwrap();
    for promise in [first, first, second, second, first] {
        let previous = task;
        runtime.suspend_task(&previous, promise).unwrap();
        task = runtime.next_task().unwrap().unwrap();
        assert!(task.generation > previous.generation);
        assert!(task.sequence > previous.sequence);
        assert!(runtime.resume_input(&previous).is_err());
        let input = runtime.resume_input(&task).unwrap().unwrap();
        assert_eq!(input.promise, promise);
        let (expected_value, expected_label) = if promise == first {
            (JsValue::Int(1), Label::Secret)
        } else {
            (JsValue::Int(2), Label::Confidential)
        };
        assert_eq!(input.value, expected_value);
        assert_eq!(input.label, expected_label);
        assert_eq!(runtime.snapshot().ready_tasks, 0);
    }
    assert_eq!(runtime.snapshot().dispatched_tasks, 6);
    runtime
        .complete_task(&task, JsValue::Undefined, Label::Secret)
        .unwrap();
}

#[test]
fn already_ready_work_runs_before_a_fulfilled_await_continuation() {
    let mut scheduler = AsyncModuleScheduler::default();
    scheduler.register_module("app", true, &[]).unwrap();
    let app = scheduler.next_task().unwrap().unwrap();
    scheduler.register_module("other", false, &[]).unwrap();
    let promise = scheduler.create_pending_promise();
    scheduler
        .fulfill_awaited_promise(promise, JsValue::Int(1), Label::Public)
        .unwrap();
    scheduler.suspend_task(&app, promise).unwrap();
    assert_eq!(scheduler.snapshot().dispatched_tasks, 1);
    let other = scheduler.next_task().unwrap().unwrap();
    assert_eq!(other.module_specifier, "other");
    let resume = scheduler.next_task().unwrap().unwrap();
    assert_eq!(resume.module_specifier, "app");
    assert_eq!(resume.kind, ModuleTaskKind::Resume);
}

#[test]
fn full_ready_queue_refuses_before_any_mutation_and_original_lease_is_retryable() {
    let mut scheduler = AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
        max_ready_tasks: 1,
        ..AsyncModuleSchedulerConfig::default()
    });
    scheduler.register_module("app", true, &[]).unwrap();
    let app = scheduler.next_task().unwrap().unwrap();
    scheduler.register_module("other", false, &[]).unwrap();
    let promise = scheduler.create_pending_promise();
    scheduler
        .fulfill_awaited_promise(promise, JsValue::Int(1), Label::Secret)
        .unwrap();
    let before = scheduler_state(&scheduler);

    assert!(matches!(
        scheduler.suspend_task(&app, promise),
        Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded { max: 1 })
    ));
    assert_eq!(scheduler_state(&scheduler), before);
    assert_eq!(scheduler.in_flight_task("app"), Some(&app));

    let other = scheduler.next_task().unwrap().unwrap();
    scheduler
        .complete_task(&other, JsValue::Undefined, Label::Public)
        .unwrap();
    scheduler.suspend_task(&app, promise).unwrap();
    let resume = scheduler.next_task().unwrap().unwrap();
    assert_eq!(resume.module_specifier, "app");
    assert_eq!(resume.kind, ModuleTaskKind::Resume);
}

#[test]
fn resolved_await_history_still_consumes_the_per_module_suspension_budget() {
    let mut scheduler = AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
        evaluator: AsyncEvalConfig {
            max_suspensions_per_module: 1,
            ..AsyncEvalConfig::default()
        },
        ..AsyncModuleSchedulerConfig::default()
    });
    scheduler.register_module("app", true, &[]).unwrap();
    let app = scheduler.next_task().unwrap().unwrap();
    let promise = scheduler.create_pending_promise();
    scheduler
        .fulfill_awaited_promise(promise, JsValue::Int(1), Label::Public)
        .unwrap();
    scheduler.suspend_task(&app, promise).unwrap();
    let resume = scheduler.next_task().unwrap().unwrap();
    let before = scheduler_state(&scheduler);
    assert!(scheduler.suspend_task(&resume, promise).is_err());
    assert_eq!(scheduler_state(&scheduler), before);
    assert_eq!(scheduler.in_flight_task("app"), Some(&resume));
    scheduler
        .complete_task(&resume, JsValue::Undefined, Label::Public)
        .unwrap();
}

#[test]
fn resolved_await_history_still_consumes_the_global_suspension_budget() {
    let mut scheduler = AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
        evaluator: AsyncEvalConfig {
            max_total_suspensions: 1,
            ..AsyncEvalConfig::default()
        },
        ..AsyncModuleSchedulerConfig::default()
    });
    scheduler.register_module("a", true, &[]).unwrap();
    scheduler.register_module("b", true, &[]).unwrap();
    let a = scheduler.next_task().unwrap().unwrap();
    let b = scheduler.next_task().unwrap().unwrap();
    let promise = scheduler.create_pending_promise();
    scheduler
        .fulfill_awaited_promise(promise, JsValue::Int(1), Label::Public)
        .unwrap();
    scheduler.suspend_task(&a, promise).unwrap();
    let before = scheduler_state(&scheduler);
    assert!(scheduler.suspend_task(&b, promise).is_err());
    assert_eq!(scheduler_state(&scheduler), before);
    assert_eq!(scheduler.in_flight_task("b"), Some(&b));
}

#[test]
fn fulfilled_await_cannot_bypass_dispatch_budget() {
    let mut scheduler = AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
        max_dispatched_tasks: 1,
        ..AsyncModuleSchedulerConfig::default()
    });
    scheduler.register_module("app", true, &[]).unwrap();
    let app = scheduler.next_task().unwrap().unwrap();
    let promise = scheduler.create_pending_promise();
    scheduler
        .fulfill_awaited_promise(promise, JsValue::Int(1), Label::Public)
        .unwrap();
    scheduler.suspend_task(&app, promise).unwrap();
    let before = scheduler_state(&scheduler);
    assert!(matches!(
        scheduler.next_task(),
        Err(AsyncModuleSchedulerError::DispatchBudgetExceeded { max: 1 })
    ));
    assert_eq!(scheduler_state(&scheduler), before);
    assert_eq!(scheduler.snapshot().ready_tasks, 1);
}

#[test]
fn pending_await_still_waits_for_settlement() {
    let mut scheduler = AsyncModuleScheduler::default();
    scheduler.register_module("app", true, &[]).unwrap();
    let app = scheduler.next_task().unwrap().unwrap();
    let promise = scheduler.create_pending_promise();
    scheduler.suspend_task(&app, promise).unwrap();
    assert_eq!(scheduler.bridge().active_await("app"), Some(promise));
    assert!(scheduler.next_task().unwrap().is_none());
    assert_eq!(
        scheduler
            .fulfill_awaited_promise(promise, JsValue::Int(1), Label::Public)
            .unwrap(),
        vec!["app"]
    );
    assert_eq!(
        scheduler.next_task().unwrap().unwrap().kind,
        ModuleTaskKind::Resume
    );
}

#[test]
fn invalid_handles_self_awaits_and_rejected_promises_leave_state_unchanged() {
    let mut scheduler = AsyncModuleScheduler::default();
    let evaluation = scheduler
        .register_module("app", true, &[])
        .unwrap()
        .unwrap();
    let app = scheduler.next_task().unwrap().unwrap();
    let rejected = scheduler.create_pending_promise();
    scheduler
        .reject_awaited_promise(rejected, JsValue::Int(9), Label::Secret)
        .unwrap();
    for promise in [PromiseHandle(u32::MAX), evaluation, rejected] {
        let before = scheduler_state(&scheduler);
        assert!(scheduler.suspend_task(&app, promise).is_err());
        assert_eq!(scheduler_state(&scheduler), before);
        assert_eq!(scheduler.in_flight_task("app"), Some(&app));
    }
}

#[test]
fn fulfilled_await_does_not_relax_dependency_or_tla_checks() {
    let mut bridge = AsyncModulePromiseBridge::with_defaults();
    bridge.register_module("dependency", false, &[]).unwrap();
    bridge
        .register_module("blocked", true, &["dependency".into()])
        .unwrap();
    bridge.register_module("sync", false, &[]).unwrap();
    let promise = bridge.create_pending_promise();
    bridge
        .fulfill_awaited_promise(promise, JsValue::Int(1), Label::Public)
        .unwrap();
    let before = serde_json::to_value(bridge.evaluator().states()).unwrap();
    let events = bridge.evaluator().witness_events().to_vec();
    assert!(matches!(
        bridge.suspend_module_on_promise("blocked", promise),
        Err(AsyncModulePromiseBridgeError::ModuleStillWaitingOnDependencies { .. })
    ));
    assert!(matches!(
        bridge.suspend_module_on_promise("sync", promise),
        Err(AsyncModulePromiseBridgeError::ModuleNotTopLevelAwait { .. })
    ));
    assert_eq!(
        serde_json::to_value(bridge.evaluator().states()).unwrap(),
        before
    );
    assert_eq!(bridge.evaluator().witness_events(), events.as_slice());
}

#[test]
fn rejected_await_behavior_is_not_silently_changed_by_the_fulfillment_fix() {
    let mut bridge = AsyncModulePromiseBridge::with_defaults();
    bridge.register_module("app", true, &[]).unwrap();
    let promise = bridge.create_pending_promise();
    bridge
        .reject_awaited_promise(promise, JsValue::Int(9), Label::Secret)
        .unwrap();
    assert!(matches!(
        bridge.suspend_module_on_promise("app", promise),
        Err(AsyncModulePromiseBridgeError::AwaitPromiseNotPending {
            status: ModulePromiseStatus::Rejected,
            ..
        })
    ));
}

#[test]
fn old_lease_cannot_suspend_or_complete_the_new_continuation() {
    let mut scheduler = AsyncModuleScheduler::default();
    scheduler.register_module("app", true, &[]).unwrap();
    let start = scheduler.next_task().unwrap().unwrap();
    let promise = scheduler.create_pending_promise();
    scheduler
        .fulfill_awaited_promise(promise, JsValue::Int(1), Label::Public)
        .unwrap();
    scheduler.suspend_task(&start, promise).unwrap();
    let before = scheduler_state(&scheduler);
    assert!(scheduler.suspend_task(&start, promise).is_err());
    assert_eq!(scheduler_state(&scheduler), before);
    let resume = scheduler.next_task().unwrap().unwrap();
    let before = scheduler_state(&scheduler);
    assert!(scheduler.suspend_task(&start, promise).is_err());
    assert!(
        scheduler
            .complete_task(&start, JsValue::Int(999), Label::Public)
            .is_err()
    );
    assert_eq!(scheduler_state(&scheduler), before);
    assert_eq!(scheduler.in_flight_task("app"), Some(&resume));
}

#[test]
fn replay_of_fulfilled_await_transitions_is_deterministic() {
    fn run() -> serde_json::Value {
        let mut scheduler = AsyncModuleScheduler::default();
        scheduler.register_module("app", true, &[]).unwrap();
        let promise = scheduler.create_pending_promise();
        scheduler
            .fulfill_awaited_promise(promise, JsValue::Int(42), Label::Secret)
            .unwrap();
        let mut task = scheduler.next_task().unwrap().unwrap();
        for _ in 0..8 {
            scheduler.suspend_task(&task, promise).unwrap();
            task = scheduler.next_task().unwrap().unwrap();
        }
        scheduler
            .complete_task(&task, JsValue::Int(43), Label::Secret)
            .unwrap();
        scheduler_state(&scheduler)
    }
    assert_eq!(run(), run());
}

#[test]
fn runtime_debug_is_bounded_and_does_not_include_guest_promise_values() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
    let promise = runtime.create_pending_promise();
    let marker = "private-promise-payload-not-for-logs";
    runtime
        .fulfill_awaited_promise(promise, JsValue::Str(marker.into()), Label::Secret)
        .unwrap();
    let debug = format!("{runtime:?}");
    assert!(debug.starts_with("AsyncModuleRuntime"));
    assert!(debug.contains("snapshot"));
    assert!(!debug.contains(marker));
}
