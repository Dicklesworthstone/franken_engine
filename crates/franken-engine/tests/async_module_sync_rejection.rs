#![forbid(unsafe_code)]

pub use frankenengine_engine::esm_loader;
pub use frankenengine_engine::ifc_artifacts;
pub use frankenengine_engine::module_async_evaluation;
pub use frankenengine_engine::module_live_binding;
pub use frankenengine_engine::object_model;
pub use frankenengine_engine::promise_model;

#[path = "../src/async_module_promise_bridge.rs"]
mod async_module_promise_bridge;

use async_module_promise_bridge::{AsyncModulePromiseBridge, ModulePromiseStatus};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::module_async_evaluation::AsyncModulePhase;
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::PromiseState;

#[test]
fn sync_throw_rejects_transitive_tla_promises_with_exact_payload() {
    let mut bridge = AsyncModulePromiseBridge::with_defaults();
    bridge.register_module("root.mjs", false, &[]).unwrap();
    let child_promise = bridge
        .register_module("child.mjs", true, &["root.mjs".into()])
        .unwrap()
        .unwrap();
    let leaf_promise = bridge
        .register_module("leaf.mjs", true, &["child.mjs".into()])
        .unwrap()
        .unwrap();

    let linkage = bridge
        .reject_synchronous_module(
            "root.mjs",
            JsValue::Str("sync throw".into()),
            Label::Secret,
        )
        .unwrap();

    assert!(linkage.transitive_closure.contains("child.mjs"));
    assert!(linkage.transitive_closure.contains("leaf.mjs"));
    for specifier in ["root.mjs", "child.mjs", "leaf.mjs"] {
        assert_eq!(
            bridge.evaluator().states()[specifier].phase,
            AsyncModulePhase::Rejected,
            "{specifier} must be rejected"
        );
    }
    for promise in [child_promise, leaf_promise] {
        let record = bridge.promise_store().get(promise).unwrap();
        assert_eq!(
            record.state,
            PromiseState::Rejected(JsValue::Str("sync throw".into()))
        );
        assert_eq!(record.label, Label::Secret);
    }
}

#[test]
fn late_tla_registration_after_sync_throw_is_immediately_rejected() {
    let mut bridge = AsyncModulePromiseBridge::with_defaults();
    bridge.register_module("root.mjs", false, &[]).unwrap();
    bridge
        .reject_synchronous_module(
            "root.mjs",
            JsValue::Str("boom".into()),
            Label::Confidential,
        )
        .unwrap();

    let late = bridge
        .register_module("late.mjs", true, &["root.mjs".into()])
        .unwrap()
        .unwrap();
    let record = bridge.promise_store().get(late).unwrap();
    assert_eq!(record.state, PromiseState::Rejected(JsValue::Str("boom".into())));
    assert_eq!(record.label, Label::Confidential);
    assert_eq!(
        bridge.evaluator().states()["late.mjs"].phase,
        AsyncModulePhase::Rejected
    );
    let update = bridge.synchronize_module("late.mjs").unwrap();
    assert_eq!(update.status, ModulePromiseStatus::Rejected);
}

#[test]
fn settled_synchronous_module_cannot_be_rejected_retroactively() {
    let mut bridge = AsyncModulePromiseBridge::with_defaults();
    bridge.register_module("done.mjs", false, &[]).unwrap();
    bridge.complete_synchronous_module("done.mjs").unwrap();
    let error = bridge
        .reject_synchronous_module(
            "done.mjs",
            JsValue::Str("too late".into()),
            Label::Public,
        )
        .unwrap_err();
    assert!(error.to_string().contains("already settled"));
    assert_eq!(
        bridge.evaluator().states()["done.mjs"].phase,
        AsyncModulePhase::Settled
    );
}

#[test]
fn synchronous_rejection_cannot_skip_pending_dependency() {
    let mut bridge = AsyncModulePromiseBridge::with_defaults();
    bridge.register_module("dep.mjs", true, &[]).unwrap();
    bridge
        .register_module("app.mjs", false, &["dep.mjs".into()])
        .unwrap();
    let error = bridge
        .reject_synchronous_module(
            "app.mjs",
            JsValue::Str("premature".into()),
            Label::Public,
        )
        .unwrap_err();
    assert!(error.to_string().contains("before async dependencies settle"));
    assert_eq!(
        bridge.evaluator().states()["app.mjs"].phase,
        AsyncModulePhase::Synchronous
    );
}
