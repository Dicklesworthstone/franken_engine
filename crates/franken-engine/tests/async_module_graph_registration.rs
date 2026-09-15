#![forbid(unsafe_code)]

pub use frankenengine_engine::esm_loader;
pub use frankenengine_engine::ifc_artifacts;
pub use frankenengine_engine::module_async_evaluation;
pub use frankenengine_engine::module_live_binding;
pub use frankenengine_engine::object_model;
pub use frankenengine_engine::promise_model;

#[path = "../src/async_module_promise_bridge.rs"]
mod async_module_promise_bridge;
#[path = "../src/async_module_scheduler.rs"]
mod async_module_scheduler;
#[path = "../src/async_module_graph.rs"]
mod async_module_graph;

use async_module_graph::{
    ModuleGraphError, ModuleGraphLimits, ModuleGraphNode, register_module_graph,
};
use async_module_scheduler::AsyncModuleScheduler;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::module_async_evaluation::AsyncModulePhase;
use frankenengine_engine::object_model::JsValue;

fn node(name: &str, has_tla: bool, dependencies: &[&str]) -> ModuleGraphNode {
    ModuleGraphNode {
        specifier: name.to_string(),
        has_top_level_await: has_tla,
        dependencies: dependencies.iter().map(|dep| (*dep).to_string()).collect(),
    }
}

#[test]
fn arbitrary_discovery_order_executes_dependency_first() {
    let nodes = vec![
        node("app.mjs", false, &["lib.mjs"]),
        node("base.mjs", true, &[]),
        node("lib.mjs", false, &["base.mjs"]),
    ];
    let mut scheduler = AsyncModuleScheduler::default();
    let registered = register_module_graph(
        &mut scheduler,
        &nodes,
        &ModuleGraphLimits::default(),
    )
    .expect("valid graph");
    assert_eq!(
        registered.plan.registration_order,
        vec!["base.mjs", "lib.mjs", "app.mjs"]
    );
    assert!(registered.evaluation_promises.contains_key("base.mjs"));

    let base = scheduler.next_task().unwrap().expect("base ready");
    assert_eq!(base.module_specifier, "base.mjs");
    assert!(scheduler.next_task().unwrap().is_none());
    scheduler
        .complete_task(&base, JsValue::Undefined, Label::Public)
        .unwrap();

    let lib = scheduler.next_task().unwrap().expect("lib ready");
    assert_eq!(lib.module_specifier, "lib.mjs");
    scheduler
        .complete_task(&lib, JsValue::Undefined, Label::Public)
        .unwrap();

    let app = scheduler.next_task().unwrap().expect("app ready");
    assert_eq!(app.module_specifier, "app.mjs");
    scheduler
        .complete_task(&app, JsValue::Undefined, Label::Public)
        .unwrap();
    assert!(scheduler.next_task().unwrap().is_none());
    for specifier in ["base.mjs", "lib.mjs", "app.mjs"] {
        assert_eq!(
            scheduler.bridge().evaluator().states()[specifier].phase,
            AsyncModulePhase::Settled
        );
    }
}

#[test]
fn invalid_graph_is_transactional_at_registration_boundary() {
    let nodes = vec![
        node("good.mjs", false, &[]),
        node("bad.mjs", true, &["missing.mjs"]),
    ];
    let mut scheduler = AsyncModuleScheduler::default();
    let error = register_module_graph(
        &mut scheduler,
        &nodes,
        &ModuleGraphLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(error, ModuleGraphError::UnknownDependency { .. }));
    assert_eq!(scheduler.snapshot().registered_modules, 0);
    assert!(scheduler.next_task().unwrap().is_none());
}

#[test]
fn cyclic_graph_is_rejected_before_any_runtime_state_exists() {
    let nodes = vec![
        node("a.mjs", true, &["b.mjs"]),
        node("b.mjs", false, &["a.mjs"]),
    ];
    let mut scheduler = AsyncModuleScheduler::default();
    let error = register_module_graph(
        &mut scheduler,
        &nodes,
        &ModuleGraphLimits::default(),
    )
    .unwrap_err();
    match error {
        ModuleGraphError::Cycle { modules } => {
            assert_eq!(modules, vec!["a.mjs", "b.mjs"]);
        }
        other => panic!("expected cycle error, got {other:?}"),
    }
    assert_eq!(scheduler.snapshot().registered_modules, 0);
}
