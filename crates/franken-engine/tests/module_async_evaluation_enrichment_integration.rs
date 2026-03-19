#![allow(clippy::too_many_arguments)]

//! Enrichment integration tests for `module_async_evaluation`.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::esm_loader::BindingType;
use frankenengine_engine::module_async_evaluation::*;
use frankenengine_engine::module_live_binding::{
    BindingCell, BindingCellState, BindingId, LiveBindingMap,
};
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::PromiseHandle;

fn js_error(msg: &str) -> JsValue {
    JsValue::Str(msg.to_string())
}

fn empty_live_bindings() -> LiveBindingMap {
    LiveBindingMap {
        cells: BTreeMap::new(),
        namespaces: BTreeMap::new(),
        imports: Vec::new(),
        events: Vec::new(),
        schema_version: "test".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_non_empty() {
    assert!(!MODULE_ASYNC_EVAL_SCHEMA_VERSION.is_empty());
    assert!(!MODULE_ASYNC_EVAL_COMPONENT.is_empty());
    assert!(MODULE_ASYNC_EVAL_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ---------------------------------------------------------------------------
// AsyncModulePhase
// ---------------------------------------------------------------------------

#[test]
fn phase_all_count() {
    assert_eq!(AsyncModulePhase::ALL.len(), 5);
}

#[test]
fn phase_as_str_distinct() {
    let strs: BTreeSet<&str> = AsyncModulePhase::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn phase_display_matches_as_str() {
    for p in AsyncModulePhase::ALL {
        assert_eq!(p.to_string(), p.as_str());
    }
}

#[test]
fn phase_terminal_check() {
    assert!(AsyncModulePhase::Synchronous.is_terminal());
    assert!(!AsyncModulePhase::Suspended.is_terminal());
    assert!(!AsyncModulePhase::AwaitingDependencies.is_terminal());
    assert!(AsyncModulePhase::Settled.is_terminal());
    assert!(AsyncModulePhase::Rejected.is_terminal());
}

#[test]
fn phase_serde_roundtrip() {
    for p in AsyncModulePhase::ALL {
        let json = serde_json::to_string(p).unwrap();
        let back: AsyncModulePhase = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, back);
    }
}

#[test]
fn phase_ordering() {
    assert!(AsyncModulePhase::Synchronous < AsyncModulePhase::Rejected);
}

// ---------------------------------------------------------------------------
// LinkageKind
// ---------------------------------------------------------------------------

#[test]
fn linkage_kind_all_count() {
    assert_eq!(LinkageKind::ALL.len(), 4);
}

#[test]
fn linkage_kind_serde_roundtrip() {
    for k in LinkageKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: LinkageKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn linkage_kind_display_matches_as_str() {
    for k in LinkageKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

// ---------------------------------------------------------------------------
// AsyncEvalEventType
// ---------------------------------------------------------------------------

#[test]
fn event_type_all_count() {
    assert_eq!(AsyncEvalEventType::ALL.len(), 10);
}

#[test]
fn event_type_serde_roundtrip() {
    for t in AsyncEvalEventType::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: AsyncEvalEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn event_type_as_str_all_distinct() {
    let strs: BTreeSet<&str> = AsyncEvalEventType::ALL.iter().map(|e| e.as_str()).collect();
    assert_eq!(strs.len(), 10);
}

// ---------------------------------------------------------------------------
// SuspensionContext serde
// ---------------------------------------------------------------------------

#[test]
fn suspension_context_serde_roundtrip() {
    for ctx in [
        SuspensionContext::TopLevelAwait,
        SuspensionContext::AwaitingDependency {
            module_specifier: "dep.js".into(),
        },
        SuspensionContext::AwaitingBinding {
            binding_id: BindingId::new("m.js", "x"),
        },
    ] {
        let json = serde_json::to_string(&ctx).unwrap();
        let back: SuspensionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, back);
    }
}

// ---------------------------------------------------------------------------
// SuspensionRecord
// ---------------------------------------------------------------------------

#[test]
fn suspension_record_new_unresolved() {
    let sr = SuspensionRecord::new(
        "mod.js".into(),
        0,
        PromiseHandle(1),
        SuspensionContext::TopLevelAwait,
    );
    assert!(!sr.resolved);
    assert_eq!(sr.resume_seq, 0);
}

#[test]
fn suspension_record_resolve() {
    let mut sr = SuspensionRecord::new(
        "mod.js".into(),
        0,
        PromiseHandle(1),
        SuspensionContext::TopLevelAwait,
    );
    sr.resolve(5);
    assert!(sr.resolved);
    assert_eq!(sr.resume_seq, 5);
}

#[test]
fn suspension_record_serde_roundtrip() {
    let sr = SuspensionRecord::new(
        "m.js".into(),
        3,
        PromiseHandle(7),
        SuspensionContext::TopLevelAwait,
    );
    let json = serde_json::to_string(&sr).unwrap();
    let back: SuspensionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(sr, back);
}

// ---------------------------------------------------------------------------
// AsyncModuleState
// ---------------------------------------------------------------------------

#[test]
fn state_synchronous() {
    let s = AsyncModuleState::synchronous("sync.js".into());
    assert_eq!(s.phase, AsyncModulePhase::Synchronous);
    assert!(!s.has_top_level_await);
    assert!(s.evaluation_promise.is_none());
    assert!(s.all_dependencies_settled());
}

#[test]
fn state_async_pending() {
    let s = AsyncModuleState::async_pending("async.js".into(), PromiseHandle(42));
    assert_eq!(s.phase, AsyncModulePhase::Suspended);
    assert!(s.has_top_level_await);
    assert_eq!(s.evaluation_promise, Some(PromiseHandle(42)));
}

#[test]
fn state_settle_clears_deps() {
    let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    s.add_pending_dependency("dep.js".into());
    s.settle();
    assert_eq!(s.phase, AsyncModulePhase::Settled);
    assert!(s.all_dependencies_settled());
}

#[test]
fn state_reject_sets_hash() {
    let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    s.reject("hash123".into());
    assert_eq!(s.phase, AsyncModulePhase::Rejected);
    assert_eq!(s.rejection_reason_hash, Some("hash123".to_string()));
}

#[test]
fn state_dependency_tracking() {
    let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    s.add_pending_dependency("a.js".into());
    s.add_pending_dependency("b.js".into());
    assert!(!s.all_dependencies_settled());
    s.resolve_dependency("a.js");
    assert!(!s.all_dependencies_settled());
    s.resolve_dependency("b.js");
    assert!(s.all_dependencies_settled());
}

#[test]
fn state_add_dependency_transitions_from_suspended_to_awaiting() {
    let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    assert_eq!(s.phase, AsyncModulePhase::Suspended);
    s.add_pending_dependency("dep.js".into());
    assert_eq!(s.phase, AsyncModulePhase::AwaitingDependencies);
}

#[test]
fn state_serde_roundtrip() {
    let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(42));
    s.record_suspension(PromiseHandle(100), SuspensionContext::TopLevelAwait);
    s.record_resumption();
    s.add_pending_dependency("dep.js".into());
    let json = serde_json::to_string(&s).unwrap();
    let back: AsyncModuleState = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// AsyncEvalError
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_variants() {
    let errors: Vec<AsyncEvalError> = vec![
        AsyncEvalError::ModuleNotFound {
            specifier: "x.js".into(),
        },
        AsyncEvalError::InvalidPhaseTransition {
            specifier: "m.js".into(),
            from: AsyncModulePhase::Synchronous,
            to: AsyncModulePhase::Rejected,
        },
        AsyncEvalError::CycleDetected {
            modules: vec!["a.js".into(), "b.js".into()],
        },
        AsyncEvalError::SuspensionLimitExceeded {
            specifier: "h.js".into(),
            limit: 10,
        },
        AsyncEvalError::RejectionPropagationFailed {
            specifier: "s.js".into(),
            detail: "timeout".into(),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn error_serde_roundtrip() {
    let errors: Vec<AsyncEvalError> = vec![
        AsyncEvalError::ModuleNotFound {
            specifier: "a.js".into(),
        },
        AsyncEvalError::CycleDetected {
            modules: vec!["c.js".into(), "d.js".into()],
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: AsyncEvalError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn error_implements_std_error() {
    let err = AsyncEvalError::ModuleNotFound {
        specifier: "x.js".into(),
    };
    let as_error: &dyn std::error::Error = &err;
    assert!(as_error.source().is_none());
}

// ---------------------------------------------------------------------------
// AsyncEvalConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let cfg = AsyncEvalConfig::default();
    assert_eq!(cfg.max_suspensions_per_module, 256);
    assert_eq!(cfg.max_total_suspensions, 4096);
    assert!(cfg.transitive_rejection_propagation);
}

#[test]
fn config_serde_roundtrip() {
    let cfg = AsyncEvalConfig {
        max_suspensions_per_module: 10,
        max_total_suspensions: 50,
        transitive_rejection_propagation: false,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: AsyncEvalConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// AsyncModuleEvaluator basic operations
// ---------------------------------------------------------------------------

#[test]
fn evaluator_register_sync() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("sync.js", false, &[], None);
    assert_eq!(
        eval.states()["sync.js"].phase,
        AsyncModulePhase::Synchronous
    );
}

#[test]
fn evaluator_register_async() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("async.js", true, &[], Some(PromiseHandle(10)));
    assert_eq!(eval.states()["async.js"].phase, AsyncModulePhase::Suspended);
}

#[test]
fn evaluator_suspend_and_resume() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("tla.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("tla.js", PromiseHandle(2))
        .unwrap();
    assert_eq!(eval.states()["tla.js"].suspensions.len(), 1);
    eval.resume_evaluation("tla.js").unwrap();
    assert!(eval.states()["tla.js"].suspensions[0].resolved);
}

#[test]
fn evaluator_settle_module() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    let resumable = eval.settle_module("m.js").unwrap();
    assert!(resumable.is_empty());
    assert_eq!(eval.states()["m.js"].phase, AsyncModulePhase::Settled);
}

#[test]
fn evaluator_reject_module() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
    let mut bindings = empty_live_bindings();
    let linkage = eval
        .reject_module("bad.js", &js_error("oops"), &mut bindings)
        .unwrap();
    assert_eq!(linkage.rejected_module, "bad.js");
    assert_eq!(eval.states()["bad.js"].phase, AsyncModulePhase::Rejected);
}

// ---------------------------------------------------------------------------
// Evaluator: module not found errors
// ---------------------------------------------------------------------------

#[test]
fn evaluator_suspend_tla_not_found() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let err = eval
        .suspend_at_top_level_await("ghost.js", PromiseHandle(1))
        .unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

#[test]
fn evaluator_suspend_dep_not_found() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let err = eval
        .suspend_on_dependency("ghost.js", "dep.js", PromiseHandle(1))
        .unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

#[test]
fn evaluator_resume_not_found() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let err = eval.resume_evaluation("ghost.js").unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

#[test]
fn evaluator_settle_not_found() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let err = eval.settle_module("ghost.js").unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

#[test]
fn evaluator_reject_not_found() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let mut bindings = empty_live_bindings();
    let err = eval
        .reject_module("ghost.js", &js_error("err"), &mut bindings)
        .unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Evaluator: suspension limit
// ---------------------------------------------------------------------------

#[test]
fn evaluator_suspension_limit() {
    let config = AsyncEvalConfig {
        max_suspensions_per_module: 2,
        ..Default::default()
    };
    let mut eval = AsyncModuleEvaluator::new(config);
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("m.js", PromiseHandle(2))
        .unwrap();
    eval.suspend_at_top_level_await("m.js", PromiseHandle(3))
        .unwrap();
    let err = eval
        .suspend_at_top_level_await("m.js", PromiseHandle(4))
        .unwrap_err();
    assert!(matches!(
        err,
        AsyncEvalError::SuspensionLimitExceeded { .. }
    ));
}

// ---------------------------------------------------------------------------
// Evaluator: dependency notification
// ---------------------------------------------------------------------------

#[test]
fn evaluator_dependency_settled_notification() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("dep.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module(
        "consumer.js",
        true,
        &["dep.js".to_string()],
        Some(PromiseHandle(2)),
    );
    eval.suspend_on_dependency("consumer.js", "dep.js", PromiseHandle(1))
        .unwrap();
    let resumable = eval.notify_dependency_settled("dep.js").unwrap();
    assert!(resumable.contains(&"consumer.js".to_string()));
}

#[test]
fn evaluator_notify_unknown_dep_returns_empty() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    let resumable = eval.notify_dependency_settled("unknown.js").unwrap();
    assert!(resumable.is_empty());
}

// ---------------------------------------------------------------------------
// Evaluator: rejection propagation
// ---------------------------------------------------------------------------

#[test]
fn evaluator_rejection_propagation_transitive() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("root.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module("mid.js", true, &["root.js".into()], Some(PromiseHandle(2)));
    eval.suspend_on_dependency("mid.js", "root.js", PromiseHandle(1))
        .unwrap();
    eval.register_module("leaf.js", true, &["mid.js".into()], Some(PromiseHandle(3)));
    eval.suspend_on_dependency("leaf.js", "mid.js", PromiseHandle(2))
        .unwrap();

    let mut bindings = empty_live_bindings();
    let linkage = eval
        .reject_module("root.js", &js_error("cascade"), &mut bindings)
        .unwrap();
    assert!(linkage.transitive_closure.contains("mid.js"));
    assert!(linkage.transitive_closure.contains("leaf.js"));
    assert_eq!(eval.states()["mid.js"].phase, AsyncModulePhase::Rejected);
    assert_eq!(eval.states()["leaf.js"].phase, AsyncModulePhase::Rejected);
}

#[test]
fn evaluator_rejection_no_transitive_when_disabled() {
    let config = AsyncEvalConfig {
        transitive_rejection_propagation: false,
        ..Default::default()
    };
    let mut eval = AsyncModuleEvaluator::new(config);
    eval.register_module("root.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module("mid.js", true, &["root.js".into()], Some(PromiseHandle(2)));
    eval.suspend_on_dependency("mid.js", "root.js", PromiseHandle(1))
        .unwrap();
    eval.register_module("leaf.js", true, &["mid.js".into()], Some(PromiseHandle(3)));
    eval.suspend_on_dependency("leaf.js", "mid.js", PromiseHandle(2))
        .unwrap();

    let mut bindings = empty_live_bindings();
    let linkage = eval
        .reject_module("root.js", &js_error("no-cascade"), &mut bindings)
        .unwrap();
    assert!(linkage.transitive_closure.contains("mid.js"));
    assert!(!linkage.transitive_closure.contains("leaf.js"));
}

// ---------------------------------------------------------------------------
// Evaluator: binding death on rejection
// ---------------------------------------------------------------------------

#[test]
fn evaluator_reject_marks_bindings_dead() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("lib.js", true, &[], Some(PromiseHandle(1)));

    let mut bindings = empty_live_bindings();
    let id1 = bindings.register_cell(BindingCell::new(
        "lib.js",
        "alpha",
        "alpha",
        BindingType::Direct,
    ));
    let id2 = bindings.register_cell(BindingCell::new(
        "lib.js",
        "beta",
        "beta",
        BindingType::Direct,
    ));
    let id_other = bindings.register_cell(BindingCell::new(
        "other.js",
        "gamma",
        "gamma",
        BindingType::Direct,
    ));

    let linkage = eval
        .reject_module("lib.js", &js_error("err"), &mut bindings)
        .unwrap();

    assert!(linkage.dead_bindings.contains(&id1));
    assert!(linkage.dead_bindings.contains(&id2));
    assert!(!linkage.dead_bindings.contains(&id_other));
    assert_eq!(
        bindings.get_cell(&id1).unwrap().state,
        BindingCellState::Dead
    );
    assert_ne!(
        bindings.get_cell(&id_other).unwrap().state,
        BindingCellState::Dead
    );
}

#[test]
fn evaluator_reject_already_dead_not_double_counted() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("lib.js", true, &[], Some(PromiseHandle(1)));
    let mut bindings = empty_live_bindings();
    let id = bindings.register_cell(BindingCell::new(
        "lib.js",
        "val",
        "val",
        BindingType::Direct,
    ));
    bindings.mark_dead(&id).unwrap();

    let linkage = eval
        .reject_module("lib.js", &js_error("err"), &mut bindings)
        .unwrap();
    assert!(linkage.dead_bindings.is_empty());
}

// ---------------------------------------------------------------------------
// Evaluator: finalize
// ---------------------------------------------------------------------------

#[test]
fn evaluator_finalize_all_settled() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("a.js", false, &[], None);
    eval.register_module("b.js", true, &[], Some(PromiseHandle(1)));
    eval.settle_module("b.js").unwrap();
    let result = eval.finalize();
    assert!(result.all_settled);
    assert_eq!(result.total_rejections, 0);
    assert_eq!(result.settled_count(), 2);
    assert_eq!(result.rejected_count(), 0);
}

#[test]
fn evaluator_finalize_with_rejection() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
    let mut bindings = empty_live_bindings();
    eval.reject_module("bad.js", &js_error("err"), &mut bindings)
        .unwrap();
    let result = eval.finalize();
    assert!(!result.all_settled);
    assert_eq!(result.total_rejections, 1);
    assert_eq!(result.rejected_count(), 1);
}

#[test]
fn finalize_hash_deterministic() {
    let build = || {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("a.js", false, &[], None);
        eval.register_module("b.js", true, &[], Some(PromiseHandle(1)));
        eval.settle_module("b.js").unwrap();
        eval.finalize()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.result_hash, r2.result_hash);
}

#[test]
fn finalize_hash_differs_for_different_inputs() {
    let mut eval1 = AsyncModuleEvaluator::with_defaults();
    eval1.register_module("a.js", false, &[], None);
    let r1 = eval1.finalize();

    let mut eval2 = AsyncModuleEvaluator::with_defaults();
    eval2.register_module("a.js", false, &[], None);
    eval2.register_module("b.js", false, &[], None);
    let r2 = eval2.finalize();

    assert_ne!(r1.result_hash, r2.result_hash);
}

// ---------------------------------------------------------------------------
// AsyncEvalResult serde
// ---------------------------------------------------------------------------

#[test]
fn async_eval_result_serde_roundtrip() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("a.js", false, &[], None);
    eval.register_module("b.js", true, &[], Some(PromiseHandle(1)));
    eval.settle_module("b.js").unwrap();
    let result = eval.finalize();
    let json = serde_json::to_string(&result).unwrap();
    let back: AsyncEvalResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// RejectionLinkage serde
// ---------------------------------------------------------------------------

#[test]
fn rejection_linkage_serde_roundtrip() {
    let rl = RejectionLinkage {
        rejected_module: "bad.js".into(),
        rejection_reason_hash: "abc123".into(),
        linked_modules: vec![LinkedModule {
            module_specifier: "consumer.js".into(),
            import_bindings: vec![BindingId::new("bad.js", "x")],
            linkage_kind: LinkageKind::DirectImport,
        }],
        transitive_closure: {
            let mut s = BTreeSet::new();
            s.insert("consumer.js".into());
            s
        },
        dead_bindings: vec![BindingId::new("bad.js", "x")],
    };
    let json = serde_json::to_string(&rl).unwrap();
    let back: RejectionLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(rl, back);
}

// ---------------------------------------------------------------------------
// Topological ordering
// ---------------------------------------------------------------------------

#[test]
fn topo_order_simple_chain() {
    let modules = vec!["a.js".into(), "b.js".into(), "c.js".into()];
    let mut deps = BTreeMap::new();
    deps.insert("b.js".into(), vec!["a.js".into()]);
    deps.insert("c.js".into(), vec!["b.js".into()]);
    let order = compute_async_evaluation_order(&modules, &deps).unwrap();
    let pos = |n: &str| order.iter().position(|s| s == n).unwrap();
    assert!(pos("a.js") < pos("b.js"));
    assert!(pos("b.js") < pos("c.js"));
}

#[test]
fn topo_order_no_deps() {
    let modules = vec!["x.js".into(), "y.js".into()];
    let deps = BTreeMap::new();
    let order = compute_async_evaluation_order(&modules, &deps).unwrap();
    assert_eq!(order.len(), 2);
}

#[test]
fn topo_order_cycle_detected() {
    let modules = vec!["a.js".into(), "b.js".into()];
    let mut deps = BTreeMap::new();
    deps.insert("a.js".into(), vec!["b.js".into()]);
    deps.insert("b.js".into(), vec!["a.js".into()]);
    let err = compute_async_evaluation_order(&modules, &deps).unwrap_err();
    assert!(matches!(err, AsyncEvalError::CycleDetected { .. }));
}

#[test]
fn topo_order_diamond() {
    let modules: Vec<String> = vec!["a.js".into(), "b.js".into(), "c.js".into(), "d.js".into()];
    let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    deps.insert("b.js".into(), vec!["a.js".into()]);
    deps.insert("c.js".into(), vec!["a.js".into()]);
    deps.insert("d.js".into(), vec!["b.js".into(), "c.js".into()]);
    let order = compute_async_evaluation_order(&modules, &deps).unwrap();
    let pos = |n: &str| order.iter().position(|s| s == n).unwrap();
    assert!(pos("a.js") < pos("b.js"));
    assert!(pos("a.js") < pos("c.js"));
    assert!(pos("b.js") < pos("d.js"));
    assert!(pos("c.js") < pos("d.js"));
}

#[test]
fn topo_order_empty() {
    let modules: Vec<String> = vec![];
    let deps = BTreeMap::new();
    let order = compute_async_evaluation_order(&modules, &deps).unwrap();
    assert!(order.is_empty());
}

#[test]
fn topo_order_deterministic_across_runs() {
    let modules: Vec<String> = vec!["z.js".into(), "y.js".into(), "x.js".into()];
    let deps = BTreeMap::new();
    let o1 = compute_async_evaluation_order(&modules, &deps).unwrap();
    let o2 = compute_async_evaluation_order(&modules, &deps).unwrap();
    assert_eq!(o1, o2);
}

#[test]
fn topo_order_external_dep_ignored() {
    let modules = vec!["a.js".into(), "b.js".into()];
    let mut deps = BTreeMap::new();
    deps.insert("b.js".into(), vec!["external.js".into()]);
    let order = compute_async_evaluation_order(&modules, &deps).unwrap();
    assert_eq!(order.len(), 2);
}

// ---------------------------------------------------------------------------
// Witness events
// ---------------------------------------------------------------------------

#[test]
fn witness_events_monotonic_seq() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("a.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("a.js", PromiseHandle(2))
        .unwrap();
    eval.resume_evaluation("a.js").unwrap();
    eval.settle_module("a.js").unwrap();

    let events = eval.witness_events();
    for window in events.windows(2) {
        assert!(window[0].seq < window[1].seq);
    }
}

#[test]
fn witness_events_contain_expected_types() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("m.js", PromiseHandle(2))
        .unwrap();
    eval.resume_evaluation("m.js").unwrap();
    eval.settle_module("m.js").unwrap();

    let types: Vec<AsyncEvalEventType> =
        eval.witness_events().iter().map(|e| e.event_type).collect();
    assert!(types.contains(&AsyncEvalEventType::EvaluationStarted));
    assert!(types.contains(&AsyncEvalEventType::TopLevelAwaitSuspended));
    assert!(types.contains(&AsyncEvalEventType::EvaluationResumed));
    assert!(types.contains(&AsyncEvalEventType::EvaluationSettled));
}

// ---------------------------------------------------------------------------
// Diamond dependency graph
// ---------------------------------------------------------------------------

#[test]
fn evaluator_diamond_dependency() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("d.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module("b.js", true, &["d.js".into()], Some(PromiseHandle(2)));
    eval.register_module("c.js", true, &["d.js".into()], Some(PromiseHandle(3)));
    eval.register_module(
        "a.js",
        true,
        &["b.js".into(), "c.js".into()],
        Some(PromiseHandle(4)),
    );

    let resumable = eval.settle_module("d.js").unwrap();
    assert!(resumable.contains(&"b.js".to_string()));
    assert!(resumable.contains(&"c.js".to_string()));
    assert!(!resumable.contains(&"a.js".to_string()));

    eval.settle_module("b.js").unwrap();
    let r3 = eval.settle_module("c.js").unwrap();
    assert!(r3.contains(&"a.js".to_string()));
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn evaluator_full_lifecycle() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("dep.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module("app.js", true, &["dep.js".into()], Some(PromiseHandle(2)));
    eval.suspend_at_top_level_await("app.js", PromiseHandle(10))
        .unwrap();
    eval.suspend_on_dependency("app.js", "dep.js", PromiseHandle(1))
        .unwrap();
    eval.settle_module("dep.js").unwrap();
    assert!(eval.states()["app.js"].all_dependencies_settled());
    eval.resume_evaluation("app.js").unwrap();
    eval.settle_module("app.js").unwrap();
    let result = eval.finalize();
    assert!(result.all_settled);
    assert_eq!(result.settled_count(), 2);
    assert!(result.total_suspensions >= 2);
}
