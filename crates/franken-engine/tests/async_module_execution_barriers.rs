#![forbid(unsafe_code)]

//! Exercise the graph/Promise/scheduler components used by the async-module
//! scenario executable. These are lifecycle integration tests, not claims of
//! executing JavaScript source or of full ESM conformance.

use std::collections::{BTreeMap, BTreeSet};

pub use frankenengine_engine::{
    esm_loader, ifc_artifacts, module_async_evaluation, module_live_binding, object_model,
    promise_model,
};

#[path = "../src/async_module_graph.rs"]
pub mod async_module_graph;
#[path = "../src/async_module_promise_bridge.rs"]
pub mod async_module_promise_bridge;
#[path = "../src/async_module_scheduler.rs"]
pub mod async_module_scheduler;

use async_module_graph::{ModuleGraphLimits, ModuleGraphNode, register_module_graph};
use async_module_scheduler::{
    AsyncModuleScheduler, AsyncModuleSchedulerConfig, AsyncModuleSchedulerError, ModuleTask,
    ModuleTaskKind,
};
use ifc_artifacts::Label;
use module_async_evaluation::AsyncModulePhase;
use object_model::JsValue;
use promise_model::{PromiseHandle, PromiseState};

fn node(name: &str, tla: bool, deps: &[&str]) -> ModuleGraphNode {
    ModuleGraphNode {
        specifier: name.to_string(),
        has_top_level_await: tla,
        dependencies: deps.iter().map(|dep| (*dep).to_string()).collect(),
    }
}

fn state(scheduler: &AsyncModuleScheduler) -> serde_json::Value {
    let in_flight: Vec<_> = scheduler
        .bridge()
        .evaluator()
        .states()
        .keys()
        .filter_map(|name| scheduler.in_flight_task(name))
        .collect();
    serde_json::json!({
        "snapshot": scheduler.snapshot(),
        "modules": scheduler.bridge().evaluator().states(),
        "events": scheduler.bridge().evaluator().witness_events(),
        "promises": scheduler.bridge().promise_store(),
        "microtasks": scheduler.bridge().microtasks(),
        "bindings": scheduler.bridge().live_bindings(),
        "in_flight": in_flight,
    })
}

fn complete(scheduler: &mut AsyncModuleScheduler, task: &ModuleTask) {
    scheduler
        .complete_task(task, JsValue::Undefined, Label::Public)
        .expect("admitted body completes");
}

fn assert_cancelled(
    scheduler: &AsyncModuleScheduler,
    module: &str,
    reason: &JsValue,
    label: &Label,
) {
    let bridge = scheduler.bridge();
    assert_eq!(
        bridge.evaluator().states()[module].phase,
        AsyncModulePhase::Rejected
    );
    assert_eq!(bridge.active_await(module), None);
    assert!(scheduler.in_flight_task(module).is_none());
    if let Some(promise) = bridge.module_promise(module) {
        let record = bridge.promise_store().get(promise).unwrap();
        assert_eq!(&record.state, &PromiseState::Rejected(reason.clone()));
        assert_eq!(&record.label, label);
    }
}

#[test]
fn cancel_queued_module_needs_neither_dispatch_nor_queue_capacity() {
    for tla in [false, true] {
        let mut scheduler = AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
            max_ready_tasks: 1,
            max_dispatched_tasks: 0,
            ..AsyncModuleSchedulerConfig::default()
        });
        scheduler.register_module("root", tla, &[]).unwrap();
        scheduler
            .register_module("child", true, &["root".into()])
            .unwrap();
        assert!(matches!(
            scheduler.next_task(),
            Err(AsyncModuleSchedulerError::DispatchBudgetExceeded { max: 0 })
        ));
        let before = scheduler.snapshot();
        let reason = JsValue::Int(17);
        assert!(
            scheduler
                .cancel_module("root", reason.clone(), Label::Secret)
                .unwrap()
        );
        for name in ["root", "child"] {
            assert_cancelled(&scheduler, name, &reason, &Label::Secret);
        }
        assert!(scheduler.next_task().unwrap().is_none());
        let after = scheduler.snapshot();
        assert_eq!(after.dispatched_tasks, 0);
        assert_eq!(after.started_modules, 0);
        assert_eq!(after.next_sequence, before.next_sequence);
    }
}

#[test]
fn cancel_dependency_blocked_sync_body_preserves_its_provider() {
    let mut scheduler = AsyncModuleScheduler::default();
    scheduler.register_module("provider", true, &[]).unwrap();
    scheduler
        .register_module("blocked", false, &["provider".into()])
        .unwrap();
    scheduler
        .register_module("child", true, &["blocked".into()])
        .unwrap();
    let reason = JsValue::Str("revoked".into());
    assert!(
        scheduler
            .cancel_module("blocked", reason.clone(), Label::Confidential)
            .unwrap()
    );
    for name in ["blocked", "child"] {
        assert_cancelled(&scheduler, name, &reason, &Label::Confidential);
    }
    let provider = scheduler.next_task().unwrap().unwrap();
    assert_eq!(provider.module_specifier, "provider");
    complete(&mut scheduler, &provider);
    assert!(scheduler.next_task().unwrap().is_none());
    scheduler
        .register_module("late", true, &["blocked".into()])
        .unwrap();
    assert_cancelled(&scheduler, "late", &reason, &Label::Confidential);
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn cancel_running_module_revokes_every_completion_route() {
    let mut scheduler = AsyncModuleScheduler::default();
    scheduler.register_module("running", true, &[]).unwrap();
    scheduler.register_module("unrelated", false, &[]).unwrap();
    let task = scheduler.next_task().unwrap().unwrap();
    let host = scheduler.create_pending_promise();
    let reason = JsValue::Str("stopped".into());
    scheduler
        .cancel_module("running", reason.clone(), Label::Secret)
        .unwrap();
    let after = state(&scheduler);
    assert!(
        scheduler
            .complete_task(&task, JsValue::Int(99), Label::Public)
            .is_err()
    );
    assert_eq!(state(&scheduler), after);
    assert!(
        scheduler
            .reject_task(&task, JsValue::Int(98), Label::Public)
            .is_err()
    );
    assert_eq!(state(&scheduler), after);
    assert!(scheduler.suspend_task(&task, host).is_err());
    assert_eq!(state(&scheduler), after);
    assert_cancelled(&scheduler, "running", &reason, &Label::Secret);
    let unrelated = scheduler.next_task().unwrap().unwrap();
    assert_eq!(unrelated.module_specifier, "unrelated");
    complete(&mut scheduler, &unrelated);
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn cancel_suspended_waiter_does_not_cancel_a_shared_host_promise() {
    let mut scheduler = AsyncModuleScheduler::default();
    for name in ["a", "b"] {
        scheduler.register_module(name, true, &[]).unwrap();
    }
    let a = scheduler.next_task().unwrap().unwrap();
    let b = scheduler.next_task().unwrap().unwrap();
    let host = scheduler.create_pending_promise();
    scheduler.suspend_task(&a, host).unwrap();
    scheduler.suspend_task(&b, host).unwrap();
    let reason = JsValue::Int(7);
    scheduler
        .cancel_module("a", reason.clone(), Label::Confidential)
        .unwrap();
    assert_eq!(
        scheduler.bridge().promise_store().get(host).unwrap().state,
        PromiseState::Pending
    );
    assert_eq!(scheduler.bridge().active_await("b"), Some(host));
    assert_eq!(
        scheduler
            .fulfill_awaited_promise(host, JsValue::Int(42), Label::Secret)
            .unwrap(),
        vec!["b"]
    );
    let resumed = scheduler.next_task().unwrap().unwrap();
    assert_eq!(resumed.module_specifier, "b");
    assert_eq!(resumed.kind, ModuleTaskKind::Resume);
    scheduler
        .complete_task(&resumed, JsValue::Int(43), Label::Secret)
        .unwrap();
    assert_cancelled(&scheduler, "a", &reason, &Label::Confidential);
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn cancel_breaks_evaluation_wait_cycle_without_another_dispatch() {
    let mut scheduler = AsyncModuleScheduler::default();
    let mut promises = Vec::new();
    for name in ["a", "b", "c"] {
        promises.push(scheduler.register_module(name, true, &[]).unwrap().unwrap());
    }
    let tasks: Vec<_> = (0..3)
        .map(|_| scheduler.next_task().unwrap().unwrap())
        .collect();
    for (index, task) in tasks.iter().enumerate() {
        scheduler
            .suspend_task(task, promises[(index + 1) % promises.len()])
            .unwrap();
    }
    assert!(scheduler.next_task().unwrap().is_none());
    let reason = JsValue::Str("cycle cancelled".into());
    scheduler
        .cancel_module("a", reason.clone(), Label::Secret)
        .unwrap();
    for name in ["a", "b", "c"] {
        assert_cancelled(&scheduler, name, &reason, &Label::Secret);
    }
    assert!(scheduler.next_task().unwrap().is_none());
    assert_eq!(scheduler.snapshot().dispatched_tasks, 3);
    let after = state(&scheduler);
    assert!(
        !scheduler
            .cancel_module("a", JsValue::Int(0), Label::Public)
            .unwrap()
    );
    assert_eq!(state(&scheduler), after);
}

#[test]
fn cancel_all_quiesces_all_phases_even_without_transitive_rejection() {
    let config = AsyncModuleSchedulerConfig {
        max_dispatched_tasks: 4,
        evaluator: module_async_evaluation::AsyncEvalConfig {
            transitive_rejection_propagation: false,
            ..module_async_evaluation::AsyncEvalConfig::default()
        },
        ..AsyncModuleSchedulerConfig::default()
    };
    let mut scheduler = AsyncModuleScheduler::new(config);
    let done = scheduler
        .register_module("done", true, &[])
        .unwrap()
        .unwrap();
    let task = scheduler.next_task().unwrap().unwrap();
    scheduler
        .complete_task(&task, JsValue::Int(42), Label::Public)
        .unwrap();
    scheduler.register_module("failed", true, &[]).unwrap();
    let task = scheduler.next_task().unwrap().unwrap();
    let old_reason = JsValue::Int(1);
    scheduler
        .reject_task(&task, old_reason.clone(), Label::Confidential)
        .unwrap();
    scheduler.register_module("suspended", true, &[]).unwrap();
    let task = scheduler.next_task().unwrap().unwrap();
    let host = scheduler.create_pending_promise();
    scheduler.suspend_task(&task, host).unwrap();
    scheduler.register_module("running", true, &[]).unwrap();
    let stale = scheduler.next_task().unwrap().unwrap();
    scheduler.register_module("queued", false, &[]).unwrap();
    scheduler
        .register_module("blocked", false, &["running".into()])
        .unwrap();
    scheduler
        .register_module("tail", true, &["blocked".into()])
        .unwrap();
    assert!(matches!(
        scheduler.next_task(),
        Err(AsyncModuleSchedulerError::DispatchBudgetExceeded { max: 4 })
    ));
    let reason = JsValue::Str("shutdown".into());
    assert_eq!(
        scheduler.cancel_all(reason.clone(), Label::Secret).unwrap(),
        5
    );
    for name in ["suspended", "running", "queued", "blocked", "tail"] {
        assert_cancelled(&scheduler, name, &reason, &Label::Secret);
    }
    assert_cancelled(&scheduler, "failed", &old_reason, &Label::Confidential);
    assert_eq!(
        scheduler.bridge().promise_store().get(done).unwrap().state,
        PromiseState::Fulfilled(JsValue::Int(42))
    );
    assert_eq!(scheduler.snapshot().ready_tasks, 0);
    assert_eq!(scheduler.snapshot().in_flight_tasks, 0);
    assert_eq!(scheduler.snapshot().dispatched_tasks, 4);
    assert!(scheduler.next_task().unwrap().is_none());
    let after = state(&scheduler);
    assert_eq!(
        scheduler
            .cancel_all(JsValue::Int(0), Label::Public)
            .unwrap(),
        0
    );
    assert_eq!(state(&scheduler), after);
    assert!(
        scheduler
            .complete_task(&stale, JsValue::Undefined, Label::Public)
            .is_err()
    );
    assert_eq!(state(&scheduler), after);
    assert!(
        scheduler
            .fulfill_awaited_promise(host, JsValue::Int(9), Label::Public)
            .unwrap()
            .is_empty()
    );
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn cancel_unknown_or_successful_module_preserves_runtime_state() {
    let mut scheduler = AsyncModuleScheduler::default();
    let empty = state(&scheduler);
    assert_eq!(
        scheduler
            .cancel_all(JsValue::Undefined, Label::Public)
            .unwrap(),
        0
    );
    assert_eq!(state(&scheduler), empty);
    scheduler.register_module("done", true, &[]).unwrap();
    let done = scheduler.next_task().unwrap().unwrap();
    complete(&mut scheduler, &done);
    scheduler.register_module("keep", true, &[]).unwrap();
    let before = state(&scheduler);
    assert!(
        scheduler
            .cancel_module("missing", JsValue::Int(1), Label::Secret)
            .is_err()
    );
    assert_eq!(state(&scheduler), before);
    assert!(
        !scheduler
            .cancel_module("done", JsValue::Int(1), Label::Secret)
            .unwrap()
    );
    assert_eq!(state(&scheduler), before);
    let keep = scheduler.next_task().unwrap().unwrap();
    assert_eq!(keep.module_specifier, "keep");
    complete(&mut scheduler, &keep);
}

#[test]
fn global_suspension_refusal_preserves_task_lease_and_cancellation_remains_available() {
    let config = AsyncModuleSchedulerConfig {
        evaluator: module_async_evaluation::AsyncEvalConfig {
            max_total_suspensions: 1,
            max_suspensions_per_module: 4,
            ..module_async_evaluation::AsyncEvalConfig::default()
        },
        ..AsyncModuleSchedulerConfig::default()
    };
    let mut scheduler = AsyncModuleScheduler::new(config);
    for name in ["a", "b"] {
        scheduler.register_module(name, true, &[]).unwrap();
    }
    let a = scheduler.next_task().unwrap().unwrap();
    let b = scheduler.next_task().unwrap().unwrap();
    let first = scheduler.create_pending_promise();
    let second = scheduler.create_pending_promise();
    scheduler.suspend_task(&a, first).unwrap();
    let before = state(&scheduler);
    let error = scheduler.suspend_task(&b, second).unwrap_err();
    assert!(matches!(error, AsyncModuleSchedulerError::Bridge { detail }
        if detail.contains("suspension limit 1 exceeded")));
    assert_eq!(state(&scheduler), before);
    assert_eq!(scheduler.in_flight_task("b"), Some(&b));
    assert_eq!(scheduler.bridge().active_await("a"), Some(first));
    assert_eq!(scheduler.bridge().active_await("b"), None);
    assert_eq!(
        scheduler
            .bridge()
            .promise_store()
            .get(second)
            .unwrap()
            .state,
        PromiseState::Pending
    );
    let reason = JsValue::Str("budget cancelled".into());
    assert_eq!(
        scheduler.cancel_all(reason.clone(), Label::Secret).unwrap(),
        2
    );
    for name in ["a", "b"] {
        assert_cancelled(&scheduler, name, &reason, &Label::Secret);
    }
    assert_eq!(scheduler.snapshot().ready_tasks, 0);
    assert_eq!(scheduler.snapshot().in_flight_tasks, 0);
}

#[test]
fn missing_dependency_refusal_is_atomic_and_retry_preserves_identifiers() {
    for tla in [false, true] {
        let mut scheduler = AsyncModuleScheduler::default();
        let before = state(&scheduler);
        let error = scheduler
            .register_module("app", tla, &["dep".into()])
            .unwrap_err();
        assert!(matches!(
            error,
            AsyncModuleSchedulerError::Bridge { detail }
                if detail.contains("unregistered dependency dep")
        ));
        assert_eq!(state(&scheduler), before);

        scheduler.register_module("dep", false, &[]).unwrap();
        let promise = scheduler
            .register_module("app", tla, &["dep".into()])
            .unwrap();
        assert_eq!(promise, tla.then_some(PromiseHandle(0)));
        let dep = scheduler.next_task().unwrap().unwrap();
        assert_eq!((dep.module_specifier.as_str(), dep.sequence), ("dep", 0));
        assert!(scheduler.next_task().unwrap().is_none());
        complete(&mut scheduler, &dep);
        let app = scheduler.next_task().unwrap().unwrap();
        assert_eq!((app.module_specifier.as_str(), app.sequence), ("app", 1));
        assert_eq!(app.generation, 1);
        complete(&mut scheduler, &app);
        assert!(scheduler.next_task().unwrap().is_none());
    }
}

#[test]
fn known_dependencies_cannot_hide_missing_or_self_dependencies() {
    let mut scheduler = AsyncModuleScheduler::default();
    scheduler.register_module("known", false, &[]).unwrap();
    let known = scheduler.next_task().unwrap().unwrap();
    for reject_known in [false, true] {
        if reject_known {
            scheduler
                .reject_task(&known, JsValue::Int(9), Label::Secret)
                .unwrap();
        }
        for deps in [
            vec!["known".to_string(), "missing".to_string()],
            vec!["missing".to_string(), "known".to_string()],
            vec!["app".to_string()],
        ] {
            let before = state(&scheduler);
            assert!(matches!(
                scheduler.register_module("app", true, &deps),
                Err(AsyncModuleSchedulerError::Bridge { .. })
            ));
            assert_eq!(state(&scheduler), before);
        }
    }
    assert_eq!(scheduler.create_pending_promise(), PromiseHandle(0));
}

#[test]
fn synchronous_graph_chain_needs_one_slot_but_each_body_must_complete() {
    let mut scheduler = AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
        max_ready_tasks: 1,
        ..AsyncModuleSchedulerConfig::default()
    });
    let graph = register_module_graph(
        &mut scheduler,
        &[
            node("app", false, &["middle"]),
            node("middle", false, &["dep"]),
            node("dep", false, &[]),
        ],
        &ModuleGraphLimits::default(),
    )
    .unwrap();
    assert!(graph.evaluation_promises.is_empty());
    for expected in ["dep", "middle", "app"] {
        let task = scheduler.next_task().unwrap().unwrap();
        assert_eq!(task.module_specifier, expected);
        assert_eq!(task.kind, ModuleTaskKind::Start);
        assert!(scheduler.next_task().unwrap().is_none());
        assert!(
            !scheduler.bridge().evaluator().states()[expected]
                .phase
                .is_terminal()
        );
        complete(&mut scheduler, &task);
    }
    assert!(
        scheduler
            .bridge()
            .evaluator()
            .states()
            .values()
            .all(|record| { record.phase == AsyncModulePhase::Settled })
    );
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn mixed_importers_wait_for_body_completion_not_just_inner_promise_resolution() {
    for dep_tla in [false, true] {
        for app_tla in [false, true] {
            let mut scheduler = AsyncModuleScheduler::default();
            scheduler.register_module("dep", dep_tla, &[]).unwrap();
            scheduler
                .register_module("app", app_tla, &["dep".into()])
                .unwrap();
            let mut dep = scheduler.next_task().unwrap().unwrap();
            assert_eq!(dep.module_specifier, "dep");
            assert!(scheduler.next_task().unwrap().is_none());
            if dep_tla {
                let awaited = scheduler.create_pending_promise();
                scheduler.suspend_task(&dep, awaited).unwrap();
                assert!(scheduler.next_task().unwrap().is_none());
                scheduler
                    .fulfill_awaited_promise(awaited, JsValue::Int(42), Label::Public)
                    .unwrap();
                dep = scheduler.next_task().unwrap().unwrap();
                assert_eq!(dep.module_specifier, "dep");
                assert_eq!(dep.kind, ModuleTaskKind::Resume);
                assert!(scheduler.next_task().unwrap().is_none());
            }
            complete(&mut scheduler, &dep);
            let app = scheduler.next_task().unwrap().unwrap();
            assert_eq!(app.module_specifier, "app");
            assert_eq!(app.kind, ModuleTaskKind::Start);
            complete(&mut scheduler, &app);
            assert!(scheduler.next_task().unwrap().is_none());
        }
    }
}

#[test]
fn synchronous_diamond_allows_independent_bodies_but_not_early_importer_dispatch() {
    let mut scheduler = AsyncModuleScheduler::default();
    register_module_graph(
        &mut scheduler,
        &[
            node("app", false, &["left", "right"]),
            node("right", false, &["root"]),
            node("left", false, &["root"]),
            node("root", false, &[]),
        ],
        &ModuleGraphLimits::default(),
    )
    .unwrap();
    let root = scheduler.next_task().unwrap().unwrap();
    assert_eq!(root.module_specifier, "root");
    assert!(scheduler.next_task().unwrap().is_none());
    complete(&mut scheduler, &root);
    let left = scheduler.next_task().unwrap().unwrap();
    let right = scheduler.next_task().unwrap().unwrap();
    assert_eq!(left.module_specifier, "left");
    assert_eq!(right.module_specifier, "right");
    assert!(scheduler.next_task().unwrap().is_none());
    complete(&mut scheduler, &right);
    assert!(scheduler.next_task().unwrap().is_none());
    complete(&mut scheduler, &left);
    let app = scheduler.next_task().unwrap().unwrap();
    assert_eq!(app.module_specifier, "app");
    complete(&mut scheduler, &app);
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn synchronous_throw_rejects_mixed_descendants_and_preserves_unrelated_work() {
    let mut scheduler = AsyncModuleScheduler::default();
    register_module_graph(
        &mut scheduler,
        &[
            node("app", true, &["middle"]),
            node("middle", false, &["root"]),
            node("root", false, &[]),
            node("unrelated", false, &[]),
        ],
        &ModuleGraphLimits::default(),
    )
    .unwrap();
    let root = scheduler.next_task().unwrap().unwrap();
    assert_eq!(root.module_specifier, "root");
    let reason = JsValue::Str("dependency failure".into());
    scheduler
        .reject_task(&root, reason.clone(), Label::Secret)
        .unwrap();
    for name in ["root", "middle", "app"] {
        assert_eq!(
            scheduler.bridge().evaluator().states()[name].phase,
            AsyncModulePhase::Rejected
        );
    }
    let app = scheduler.bridge().module_promise("app").unwrap();
    let record = scheduler.bridge().promise_store().get(app).unwrap();
    assert_eq!(record.state, PromiseState::Rejected(reason.clone()));
    assert_eq!(record.label, Label::Secret);
    let unrelated = scheduler.next_task().unwrap().unwrap();
    assert_eq!(unrelated.module_specifier, "unrelated");
    complete(&mut scheduler, &unrelated);
    let late = scheduler
        .register_module("late", true, &["middle".into()])
        .unwrap()
        .unwrap();
    let record = scheduler.bridge().promise_store().get(late).unwrap();
    assert_eq!(record.state, PromiseState::Rejected(reason));
    assert_eq!(record.label, Label::Secret);
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn synchronous_completion_backpressure_preserves_lease_and_all_wakeups() {
    let mut scheduler = AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
        max_ready_tasks: 2,
        ..AsyncModuleSchedulerConfig::default()
    });
    scheduler.register_module("root", false, &[]).unwrap();
    scheduler.register_module("occupied", false, &[]).unwrap();
    let root = scheduler.next_task().unwrap().unwrap();
    for name in ["a", "b"] {
        scheduler
            .register_module(name, false, &["root".into()])
            .unwrap();
    }
    let before = state(&scheduler);
    assert!(matches!(
        scheduler.complete_task(&root, JsValue::Undefined, Label::Public),
        Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded { max: 2 })
    ));
    assert_eq!(state(&scheduler), before);
    let occupied = scheduler.next_task().unwrap().unwrap();
    assert_eq!(occupied.module_specifier, "occupied");
    complete(&mut scheduler, &occupied);
    complete(&mut scheduler, &root);
    for (expected, seq) in [("a", 2), ("b", 3)] {
        let task = scheduler.next_task().unwrap().unwrap();
        assert_eq!(
            (task.module_specifier.as_str(), task.sequence),
            (expected, seq)
        );
        complete(&mut scheduler, &task);
    }
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn all_four_node_dag_tla_mixes_enforce_completion_barriers_during_dispatch() {
    let names = ["z", "b", "y", "a"];
    let edges = [(1, 0), (2, 0), (2, 1), (3, 0), (3, 1), (3, 2)];
    for edge_mask in 0u32..64 {
        for tla_mask in 0u32..16 {
            let mut nodes: Vec<_> = names
                .iter()
                .enumerate()
                .map(|(index, name)| node(name, tla_mask & (1 << index) != 0, &[]))
                .collect();
            for (bit, &(consumer, dependency)) in edges.iter().enumerate() {
                if edge_mask & (1 << bit) != 0 {
                    nodes[consumer].dependencies.push(names[dependency].into());
                }
            }
            // The oracle is the original declared dependency graph and the
            // set of completed task leases, not the runtime's pending sets.
            let dependencies: BTreeMap<_, _> = nodes
                .iter()
                .map(|entry| (entry.specifier.clone(), entry.dependencies.clone()))
                .collect();
            nodes.reverse();
            let mut scheduler = AsyncModuleScheduler::default();
            register_module_graph(&mut scheduler, &nodes, &ModuleGraphLimits::default()).unwrap();
            let mut completed = BTreeSet::<String>::new();
            let mut issued = BTreeSet::<String>::new();
            for _ in 0..4 {
                let mut tasks = Vec::new();
                while let Some(task) = scheduler.next_task().unwrap() {
                    assert!(
                        dependencies[&task.module_specifier]
                            .iter()
                            .all(|dep| completed.contains(dep)),
                        "premature dispatch: edges={edge_mask} tla={tla_mask} task={task:?}"
                    );
                    assert!(
                        issued.insert(task.module_specifier.clone()),
                        "duplicate start"
                    );
                    assert_eq!(task.kind, ModuleTaskKind::Start);
                    tasks.push(task);
                }
                if completed.len() == 4 {
                    break;
                }
                assert!(
                    !tasks.is_empty(),
                    "stranded graph: edges={edge_mask} tla={tla_mask}"
                );
                // Complete independent in-flight bodies opposite dispatch order.
                for task in tasks.into_iter().rev() {
                    complete(&mut scheduler, &task);
                    assert!(completed.insert(task.module_specifier));
                }
            }
            assert_eq!(completed.len(), 4);
            assert_eq!(issued.len(), 4);
            assert!(scheduler.next_task().unwrap().is_none());
            assert_eq!(scheduler.snapshot().in_flight_tasks, 0);
            assert!(
                scheduler
                    .bridge()
                    .evaluator()
                    .states()
                    .values()
                    .all(|entry| { entry.phase == AsyncModulePhase::Settled })
            );
        }
    }
}
