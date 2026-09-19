#![forbid(unsafe_code)]

//! Host cancellation and complete lease identity through the owning runtime.

use frankenengine_engine::async_module_graph::{ModuleGraphLimits, ModuleGraphNode};
use frankenengine_engine::async_module_runtime::AsyncModuleRuntime;
use frankenengine_engine::async_module_scheduler::{AsyncModuleSchedulerConfig, ModuleTaskKind};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::module_async_evaluation::{AsyncEvalConfig, AsyncModulePhase};
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::PromiseState;

fn node(name: &str, tla: bool, dependencies: &[&str]) -> ModuleGraphNode {
    ModuleGraphNode {
        specifier: name.to_string(),
        has_top_level_await: tla,
        dependencies: dependencies.iter().map(|name| (*name).to_string()).collect(),
    }
}

fn state(runtime: &AsyncModuleRuntime) -> serde_json::Value {
    let evaluation_results: Vec<_> = runtime
        .metadata()
        .evaluation_promises
        .iter()
        .map(|(name, promise)| (name, runtime.promise_result(*promise).unwrap()))
        .collect();
    serde_json::json!({
        "snapshot": runtime.snapshot(),
        "phases": runtime.module_phases(),
        "evaluation_results": evaluation_results,
    })
}

#[test]
fn queued_graph_can_be_cancelled_without_dispatching_a_task() {
    let mut runtime = AsyncModuleRuntime::from_graph(
        &[node("root", true, &[]), node("child", true, &["root"])],
        &ModuleGraphLimits::default(),
        AsyncModuleSchedulerConfig {
            max_dispatched_tasks: 0,
            ..AsyncModuleSchedulerConfig::default()
        },
    )
    .unwrap();
    let reason = JsValue::Str("supervisor cancelled".into());
    assert!(runtime.cancel_module("root", reason.clone(), Label::Secret).unwrap());
    assert_eq!(runtime.snapshot().ready_tasks, 0);
    assert_eq!(runtime.snapshot().in_flight_tasks, 0);
    assert_eq!(runtime.snapshot().dispatched_tasks, 0);
    assert!(runtime.next_task().unwrap().is_none());
    for name in ["root", "child"] {
        assert_eq!(runtime.module_phases()[name], AsyncModulePhase::Rejected);
        let (result, label) = runtime
            .promise_result(runtime.evaluation_promise(name).unwrap())
            .unwrap();
        assert_eq!(result, &PromiseState::Rejected(reason.clone()));
        assert_eq!(label, &Label::Secret);
    }
}

#[test]
fn suspended_module_cancellation_preserves_shared_host_operation_and_other_waiter() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[
        node("a", true, &[]),
        node("b", true, &[]),
    ])
    .unwrap();
    let a = runtime.next_task().unwrap().unwrap();
    let b = runtime.next_task().unwrap().unwrap();
    let host = runtime.create_pending_promise();
    runtime.suspend_task(&a, host).unwrap();
    runtime.suspend_task(&b, host).unwrap();

    assert!(runtime.cancel_module("a", JsValue::Int(9), Label::Confidential).unwrap());
    assert_eq!(runtime.promise_result(host).unwrap().0, &PromiseState::Pending);
    assert_eq!(
        runtime.fulfill_awaited_promise(host, JsValue::Int(42), Label::Secret).unwrap(),
        vec!["b"]
    );
    let resume = runtime.next_task().unwrap().unwrap();
    assert_eq!(resume.module_specifier, "b");
    assert_eq!(resume.kind, ModuleTaskKind::Resume);
    let input = runtime.resume_input(&resume).unwrap().unwrap();
    assert_eq!(input.value, JsValue::Int(42));
    assert_eq!(input.label, Label::Secret);
    assert!(runtime.resume_input(&a).is_err());
    assert!(runtime.next_task().unwrap().is_none());
    runtime.complete_task(&resume, JsValue::Int(43), Label::Secret).unwrap();
    assert_eq!(runtime.module_phases()["a"], AsyncModulePhase::Rejected);
    assert_eq!(runtime.module_phases()["b"], AsyncModulePhase::Settled);
}

#[test]
fn dependency_blocked_module_can_be_cancelled_without_cancelling_provider() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[
        node("provider", true, &[]),
        node("blocked", false, &["provider"]),
    ])
    .unwrap();
    assert!(runtime.cancel_module("blocked", JsValue::Int(9), Label::Secret).unwrap());
    let provider = runtime.next_task().unwrap().unwrap();
    assert_eq!(provider.module_specifier, "provider");
    runtime.complete_task(&provider, JsValue::Int(42), Label::Public).unwrap();
    assert!(runtime.next_task().unwrap().is_none());
    assert_eq!(runtime.module_phases()["provider"], AsyncModulePhase::Settled);
    assert_eq!(runtime.module_phases()["blocked"], AsyncModulePhase::Rejected);
}

#[test]
fn in_flight_cancellation_revokes_every_guest_completion_operation() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
    let task = runtime.next_task().unwrap().unwrap();
    let promise = runtime.create_pending_promise();
    assert!(runtime.cancel_module("app", JsValue::Int(9), Label::Secret).unwrap());
    let before = state(&runtime);
    assert!(runtime.complete_task(&task, JsValue::Int(999), Label::Public).is_err());
    assert!(runtime.reject_task(&task, JsValue::Int(999), Label::Public).is_err());
    assert!(runtime.suspend_task(&task, promise).is_err());
    assert!(runtime.resume_input(&task).is_err());
    assert_eq!(state(&runtime), before);
    assert_eq!(runtime.promise_result(promise).unwrap().0, &PromiseState::Pending);
}

#[test]
fn cancel_all_breaks_runtime_wait_cycles_and_preserves_prior_terminal_results() {
    let mut runtime = AsyncModuleRuntime::from_graph(
        &[
            node("a-done", true, &[]),
            node("b-failed", true, &[]),
            node("c", true, &[]),
            node("d", true, &[]),
            node("e-blocked", false, &["c"]),
        ],
        &ModuleGraphLimits::default(),
        AsyncModuleSchedulerConfig {
            evaluator: AsyncEvalConfig {
                transitive_rejection_propagation: false,
                ..AsyncEvalConfig::default()
            },
            ..AsyncModuleSchedulerConfig::default()
        },
    )
    .unwrap();
    let done = runtime.next_task().unwrap().unwrap();
    assert_eq!(done.module_specifier, "a-done");
    runtime.complete_task(&done, JsValue::Int(7), Label::Public).unwrap();
    let failed = runtime.next_task().unwrap().unwrap();
    assert_eq!(failed.module_specifier, "b-failed");
    runtime.reject_task(&failed, JsValue::Int(8), Label::Confidential).unwrap();
    let c = runtime.next_task().unwrap().unwrap();
    let d = runtime.next_task().unwrap().unwrap();
    let c_promise = runtime.evaluation_promise("c").unwrap();
    let d_promise = runtime.evaluation_promise("d").unwrap();
    runtime.suspend_task(&c, d_promise).unwrap();
    runtime.suspend_task(&d, c_promise).unwrap();
    assert!(runtime.next_task().unwrap().is_none());

    assert_eq!(runtime.cancel_all(JsValue::Int(99), Label::Secret).unwrap(), 3);
    assert_eq!(runtime.snapshot().ready_tasks, 0);
    assert_eq!(runtime.snapshot().in_flight_tasks, 0);
    assert!(runtime.next_task().unwrap().is_none());
    for name in ["c", "d", "e-blocked"] {
        assert_eq!(runtime.module_phases()[name], AsyncModulePhase::Rejected);
    }
    for promise in [c_promise, d_promise] {
        assert_eq!(
            runtime.promise_result(promise).unwrap(),
            (&PromiseState::Rejected(JsValue::Int(99)), &Label::Secret)
        );
    }
    assert_eq!(
        runtime.promise_result(runtime.evaluation_promise("a-done").unwrap()).unwrap(),
        (&PromiseState::Fulfilled(JsValue::Int(7)), &Label::Public)
    );
    assert_eq!(
        runtime.promise_result(runtime.evaluation_promise("b-failed").unwrap()).unwrap(),
        (&PromiseState::Rejected(JsValue::Int(8)), &Label::Confidential)
    );
    let before = state(&runtime);
    assert_eq!(runtime.cancel_all(JsValue::Int(0), Label::Public).unwrap(), 0);
    assert!(!runtime.cancel_module("c", JsValue::Int(0), Label::Public).unwrap());
    assert_eq!(state(&runtime), before);
}

#[test]
fn cancelling_an_unknown_module_is_read_only() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
    let before = state(&runtime);
    assert!(runtime.cancel_module("missing", JsValue::Int(9), Label::Secret).is_err());
    assert_eq!(state(&runtime), before);
    assert_eq!(runtime.next_task().unwrap().unwrap().module_specifier, "app");
}

#[test]
fn cancellation_removes_a_queued_fulfilled_await_continuation() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
    let start = runtime.next_task().unwrap().unwrap();
    let promise = runtime.create_pending_promise();
    runtime.fulfill_awaited_promise(promise, JsValue::Int(42), Label::Secret).unwrap();
    runtime.suspend_task(&start, promise).unwrap();
    assert_eq!(runtime.snapshot().ready_tasks, 1);
    assert!(runtime.cancel_module("app", JsValue::Int(9), Label::Confidential).unwrap());
    assert!(runtime.next_task().unwrap().is_none());
    assert_eq!(
        runtime.promise_result(promise).unwrap(),
        (&PromiseState::Fulfilled(JsValue::Int(42)), &Label::Secret)
    );
}

#[test]
fn forged_sequence_cannot_complete_reject_or_suspend_a_live_lease() {
    let mut runtime = AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
    let task = runtime.next_task().unwrap().unwrap();
    let promise = runtime.create_pending_promise();
    let mut forged = task.clone();
    forged.sequence += 1;
    let before = state(&runtime);
    assert!(runtime.resume_input(&forged).is_err());
    assert!(runtime.complete_task(&forged, JsValue::Int(999), Label::Public).is_err());
    assert!(runtime.reject_task(&forged, JsValue::Int(999), Label::Public).is_err());
    assert!(runtime.suspend_task(&forged, promise).is_err());
    assert_eq!(state(&runtime), before);
    assert_eq!(runtime.promise_result(promise).unwrap().0, &PromiseState::Pending);
    runtime.complete_task(&task, JsValue::Int(42), Label::Secret).unwrap();
    assert_eq!(runtime.module_phases()["app"], AsyncModulePhase::Settled);
}
