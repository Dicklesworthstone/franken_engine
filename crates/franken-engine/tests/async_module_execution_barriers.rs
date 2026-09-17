#![forbid(unsafe_code)]

//! Exercise the graph/Promise/scheduler components used by the async-module
//! scenario executable. These are lifecycle integration tests, not claims of
//! executing JavaScript source or of full ESM conformance.

use std::collections::{BTreeMap, BTreeSet};

pub use frankenengine_engine::{
    esm_loader, ifc_artifacts, module_async_evaluation, module_live_binding,
    object_model, promise_model,
};

#[path = "../src/async_module_graph.rs"]
pub mod async_module_graph;
#[path = "../src/async_module_promise_bridge.rs"]
pub mod async_module_promise_bridge;
#[path = "../src/async_module_scheduler.rs"]
pub mod async_module_scheduler;

use async_module_graph::{ModuleGraphLimits, ModuleGraphNode, register_module_graph};
use async_module_scheduler::{
    AsyncModuleScheduler, AsyncModuleSchedulerConfig, AsyncModuleSchedulerError,
    ModuleTask, ModuleTaskKind,
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

#[test]
fn missing_dependency_refusal_is_atomic_and_retry_preserves_identifiers() {
    for tla in [false, true] {
        let mut scheduler = AsyncModuleScheduler::default();
        let before = state(&scheduler);
        let error = scheduler.register_module("app", tla, &["dep".into()]).unwrap_err();
        assert!(matches!(
            error,
            AsyncModuleSchedulerError::Bridge { detail }
                if detail.contains("unregistered dependency dep")
        ));
        assert_eq!(state(&scheduler), before);

        scheduler.register_module("dep", false, &[]).unwrap();
        let promise = scheduler.register_module("app", tla, &["dep".into()]).unwrap();
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
            scheduler.reject_task(&known, JsValue::Int(9), Label::Secret).unwrap();
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
    ).unwrap();
    assert!(graph.evaluation_promises.is_empty());
    for expected in ["dep", "middle", "app"] {
        let task = scheduler.next_task().unwrap().unwrap();
        assert_eq!(task.module_specifier, expected);
        assert_eq!(task.kind, ModuleTaskKind::Start);
        assert!(scheduler.next_task().unwrap().is_none());
        assert!(!scheduler.bridge().evaluator().states()[expected].phase.is_terminal());
        complete(&mut scheduler, &task);
    }
    assert!(scheduler.bridge().evaluator().states().values().all(|record| {
        record.phase == AsyncModulePhase::Settled
    }));
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn mixed_importers_wait_for_body_completion_not_just_inner_promise_resolution() {
    for dep_tla in [false, true] {
        for app_tla in [false, true] {
            let mut scheduler = AsyncModuleScheduler::default();
            scheduler.register_module("dep", dep_tla, &[]).unwrap();
            scheduler.register_module("app", app_tla, &["dep".into()]).unwrap();
            let mut dep = scheduler.next_task().unwrap().unwrap();
            assert_eq!(dep.module_specifier, "dep");
            assert!(scheduler.next_task().unwrap().is_none());
            if dep_tla {
                let awaited = scheduler.create_pending_promise();
                scheduler.suspend_task(&dep, awaited).unwrap();
                assert!(scheduler.next_task().unwrap().is_none());
                scheduler.fulfill_awaited_promise(awaited, JsValue::Int(42), Label::Public).unwrap();
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
    ).unwrap();
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
    ).unwrap();
    let root = scheduler.next_task().unwrap().unwrap();
    assert_eq!(root.module_specifier, "root");
    let reason = JsValue::Str("dependency failure".into());
    scheduler.reject_task(&root, reason.clone(), Label::Secret).unwrap();
    for name in ["root", "middle", "app"] {
        assert_eq!(scheduler.bridge().evaluator().states()[name].phase, AsyncModulePhase::Rejected);
    }
    let app = scheduler.bridge().module_promise("app").unwrap();
    let record = scheduler.bridge().promise_store().get(app).unwrap();
    assert_eq!(record.state, PromiseState::Rejected(reason.clone()));
    assert_eq!(record.label, Label::Secret);
    let unrelated = scheduler.next_task().unwrap().unwrap();
    assert_eq!(unrelated.module_specifier, "unrelated");
    complete(&mut scheduler, &unrelated);
    let late = scheduler.register_module("late", true, &["middle".into()]).unwrap().unwrap();
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
        scheduler.register_module(name, false, &["root".into()]).unwrap();
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
        assert_eq!((task.module_specifier.as_str(), task.sequence), (expected, seq));
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
            let mut nodes: Vec<_> = names.iter().enumerate()
                .map(|(index, name)| node(name, tla_mask & (1 << index) != 0, &[]))
                .collect();
            for (bit, &(consumer, dependency)) in edges.iter().enumerate() {
                if edge_mask & (1 << bit) != 0 {
                    nodes[consumer].dependencies.push(names[dependency].into());
                }
            }
            // The oracle is the original declared dependency graph and the
            // set of completed task leases, not the runtime's pending sets.
            let dependencies: BTreeMap<_, _> = nodes.iter()
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
                    assert!(dependencies[&task.module_specifier].iter().all(|dep| completed.contains(dep)),
                        "premature dispatch: edges={edge_mask} tla={tla_mask} task={task:?}");
                    assert!(issued.insert(task.module_specifier.clone()), "duplicate start");
                    assert_eq!(task.kind, ModuleTaskKind::Start);
                    tasks.push(task);
                }
                if completed.len() == 4 {
                    break;
                }
                assert!(!tasks.is_empty(), "stranded graph: edges={edge_mask} tla={tla_mask}");
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
            assert!(scheduler.bridge().evaluator().states().values().all(|entry| {
                entry.phase == AsyncModulePhase::Settled
            }));
        }
    }
}
