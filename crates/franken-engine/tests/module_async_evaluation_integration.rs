#![forbid(unsafe_code)]

//! Integration tests for module_async_evaluation.
//!
//! Covers: async module lifecycle, suspension/resumption, rejection
//! propagation, live binding death, topological ordering, determinism,
//! serde roundtrips, and multi-module evaluation pipelines.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::esm_loader::BindingType;
use frankenengine_engine::module_async_evaluation::{
    AsyncEvalConfig, AsyncEvalError, AsyncEvalEventType, AsyncEvalResult, AsyncEvalWitnessEvent,
    AsyncModuleEvaluator, AsyncModulePhase, AsyncModuleState, LinkageKind, LinkedModule,
    MODULE_ASYNC_EVAL_COMPONENT, MODULE_ASYNC_EVAL_SCHEMA_VERSION, RejectionLinkage,
    SuspensionContext, SuspensionRecord, compute_async_evaluation_order,
};
use frankenengine_engine::module_live_binding::{
    BindingCell, BindingCellState, BindingEvent, BindingId, LiveBindingMap,
};
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::PromiseHandle;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_binding_id(module: &str, export: &str) -> BindingId {
    BindingId {
        module_specifier: module.to_string(),
        export_name: export.to_string(),
    }
}

fn make_binding_cell(module: &str, export: &str) -> BindingCell {
    let mut cell = BindingCell::new(module, export, export, BindingType::Direct);
    cell.state = BindingCellState::Initialized;
    cell
}

fn bindings_with_cells(pairs: &[(&str, &str)]) -> LiveBindingMap {
    let mut map = LiveBindingMap::new();
    for &(module, export) in pairs {
        let id = make_binding_id(module, export);
        let cell = make_binding_cell(module, export);
        map.cells.insert(id, cell);
    }
    map
}

fn empty_bindings() -> LiveBindingMap {
    LiveBindingMap::new()
}

fn js_error(msg: &str) -> JsValue {
    JsValue::Str(msg.to_string())
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_non_empty() {
    assert!(!MODULE_ASYNC_EVAL_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_version_prefixed() {
    assert!(MODULE_ASYNC_EVAL_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn component_name_non_empty() {
    assert!(!MODULE_ASYNC_EVAL_COMPONENT.is_empty());
}

#[test]
fn component_name_matches_expected() {
    assert_eq!(MODULE_ASYNC_EVAL_COMPONENT, "module_async_evaluation");
}

// ---------------------------------------------------------------------------
// AsyncModulePhase
// ---------------------------------------------------------------------------

#[test]
fn phase_all_covers_five_variants() {
    assert_eq!(AsyncModulePhase::ALL.len(), 5);
}

#[test]
fn phase_as_str_all_distinct() {
    let strs: BTreeSet<&str> = AsyncModulePhase::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn phase_terminal_synchronous_settled_rejected() {
    assert!(AsyncModulePhase::Synchronous.is_terminal());
    assert!(AsyncModulePhase::Settled.is_terminal());
    assert!(AsyncModulePhase::Rejected.is_terminal());
}

#[test]
fn phase_non_terminal_suspended_awaiting() {
    assert!(!AsyncModulePhase::Suspended.is_terminal());
    assert!(!AsyncModulePhase::AwaitingDependencies.is_terminal());
}

#[test]
fn phase_display_matches_as_str() {
    for p in AsyncModulePhase::ALL {
        assert_eq!(format!("{p}"), p.as_str());
    }
}

#[test]
fn phase_serde_all_variants() {
    for p in AsyncModulePhase::ALL {
        let json = serde_json::to_string(p).unwrap();
        let back: AsyncModulePhase = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, back);
    }
}

#[test]
fn phase_ord_defined() {
    // Enum ordering should be consistent (derive Ord)
    assert!(AsyncModulePhase::Synchronous < AsyncModulePhase::Suspended);
    assert!(AsyncModulePhase::Suspended < AsyncModulePhase::AwaitingDependencies);
    assert!(AsyncModulePhase::AwaitingDependencies < AsyncModulePhase::Settled);
    assert!(AsyncModulePhase::Settled < AsyncModulePhase::Rejected);
}

// ---------------------------------------------------------------------------
// SuspensionContext
// ---------------------------------------------------------------------------

#[test]
fn suspension_context_top_level_await_serde() {
    let ctx = SuspensionContext::TopLevelAwait;
    let json = serde_json::to_string(&ctx).unwrap();
    let back: SuspensionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn suspension_context_awaiting_dependency_serde() {
    let ctx = SuspensionContext::AwaitingDependency {
        module_specifier: "dep.js".into(),
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let back: SuspensionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn suspension_context_awaiting_binding_serde() {
    let ctx = SuspensionContext::AwaitingBinding {
        binding_id: make_binding_id("mod.js", "value"),
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let back: SuspensionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

// ---------------------------------------------------------------------------
// SuspensionRecord
// ---------------------------------------------------------------------------

#[test]
fn suspension_record_new_is_unresolved() {
    let sr = SuspensionRecord::new(
        "mod.js".into(),
        0,
        PromiseHandle(1),
        SuspensionContext::TopLevelAwait,
    );
    assert!(!sr.resolved);
    assert_eq!(sr.resume_seq, 0);
    assert_eq!(sr.suspension_seq, 0);
    assert_eq!(sr.module_specifier, "mod.js");
}

#[test]
fn suspension_record_resolve_sets_resume_seq() {
    let mut sr = SuspensionRecord::new(
        "mod.js".into(),
        3,
        PromiseHandle(10),
        SuspensionContext::TopLevelAwait,
    );
    sr.resolve(7);
    assert!(sr.resolved);
    assert_eq!(sr.resume_seq, 7);
    assert_eq!(sr.suspension_seq, 3);
}

#[test]
fn suspension_record_serde_roundtrip() {
    let mut sr = SuspensionRecord::new(
        "entry.js".into(),
        5,
        PromiseHandle(42),
        SuspensionContext::AwaitingDependency {
            module_specifier: "helper.js".into(),
        },
    );
    sr.resolve(10);
    let json = serde_json::to_string(&sr).unwrap();
    let back: SuspensionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(sr, back);
}

// ---------------------------------------------------------------------------
// LinkageKind
// ---------------------------------------------------------------------------

#[test]
fn linkage_kind_all_four_variants() {
    assert_eq!(LinkageKind::ALL.len(), 4);
}

#[test]
fn linkage_kind_as_str_distinct() {
    let strs: BTreeSet<&str> = LinkageKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn linkage_kind_display_matches_as_str() {
    for k in LinkageKind::ALL {
        assert_eq!(format!("{k}"), k.as_str());
    }
}

#[test]
fn linkage_kind_serde_all_variants() {
    for k in LinkageKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: LinkageKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// LinkedModule
// ---------------------------------------------------------------------------

#[test]
fn linked_module_serde_roundtrip() {
    let lm = LinkedModule {
        module_specifier: "consumer.js".into(),
        import_bindings: vec![make_binding_id("consumer.js", "foo")],
        linkage_kind: LinkageKind::NamespaceImport,
    };
    let json = serde_json::to_string(&lm).unwrap();
    let back: LinkedModule = serde_json::from_str(&json).unwrap();
    assert_eq!(lm, back);
}

// ---------------------------------------------------------------------------
// AsyncEvalEventType
// ---------------------------------------------------------------------------

#[test]
fn event_type_all_ten_variants() {
    assert_eq!(AsyncEvalEventType::ALL.len(), 10);
}

#[test]
fn event_type_as_str_all_distinct() {
    let strs: BTreeSet<&str> = AsyncEvalEventType::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(strs.len(), 10);
}

#[test]
fn event_type_serde_all_variants() {
    for t in AsyncEvalEventType::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: AsyncEvalEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ---------------------------------------------------------------------------
// AsyncEvalError
// ---------------------------------------------------------------------------

#[test]
fn error_module_not_found_display() {
    let err = AsyncEvalError::ModuleNotFound {
        specifier: "missing.js".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("missing.js"));
    assert!(msg.contains("not found"));
}

#[test]
fn error_invalid_phase_transition_display() {
    let err = AsyncEvalError::InvalidPhaseTransition {
        specifier: "a.js".into(),
        from: AsyncModulePhase::Synchronous,
        to: AsyncModulePhase::Settled,
    };
    let msg = err.to_string();
    assert!(msg.contains("a.js"));
    assert!(msg.contains("synchronous"));
    assert!(msg.contains("settled"));
}

#[test]
fn error_cycle_detected_display() {
    let err = AsyncEvalError::CycleDetected {
        modules: vec!["a.js".into(), "b.js".into()],
    };
    let msg = err.to_string();
    assert!(msg.contains("a.js"));
    assert!(msg.contains("b.js"));
}

#[test]
fn error_suspension_limit_display() {
    let err = AsyncEvalError::SuspensionLimitExceeded {
        specifier: "loop.js".into(),
        limit: 10,
    };
    let msg = err.to_string();
    assert!(msg.contains("loop.js"));
    assert!(msg.contains("10"));
}

#[test]
fn error_rejection_propagation_failed_display() {
    let err = AsyncEvalError::RejectionPropagationFailed {
        specifier: "bad.js".into(),
        detail: "internal".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("bad.js"));
    assert!(msg.contains("internal"));
}

#[test]
fn error_is_std_error() {
    let err = AsyncEvalError::ModuleNotFound {
        specifier: "x.js".into(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn error_serde_roundtrip() {
    let err = AsyncEvalError::CycleDetected {
        modules: vec!["a.js".into(), "b.js".into(), "c.js".into()],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: AsyncEvalError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ---------------------------------------------------------------------------
// AsyncEvalConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_sensible() {
    let cfg = AsyncEvalConfig::default();
    assert!(cfg.max_suspensions_per_module > 0);
    assert!(cfg.max_total_suspensions > cfg.max_suspensions_per_module);
    assert!(cfg.transitive_rejection_propagation);
}

#[test]
fn config_serde_roundtrip() {
    let cfg = AsyncEvalConfig {
        max_suspensions_per_module: 10,
        max_total_suspensions: 100,
        transitive_rejection_propagation: false,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: AsyncEvalConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// AsyncModuleState
// ---------------------------------------------------------------------------

#[test]
fn state_synchronous_construction() {
    let state = AsyncModuleState::synchronous("sync.js".into());
    assert_eq!(state.phase, AsyncModulePhase::Synchronous);
    assert!(!state.has_top_level_await);
    assert!(state.evaluation_promise.is_none());
    assert!(state.suspensions.is_empty());
    assert!(state.pending_dependencies.is_empty());
    assert_eq!(state.event_seq, 0);
}

#[test]
fn state_async_pending_construction() {
    let state = AsyncModuleState::async_pending("tla.js".into(), PromiseHandle(5));
    assert_eq!(state.phase, AsyncModulePhase::Suspended);
    assert!(state.has_top_level_await);
    assert_eq!(state.evaluation_promise, Some(PromiseHandle(5)));
}

#[test]
fn state_record_suspension_advances_seq() {
    let mut state = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    state.record_suspension(PromiseHandle(10), SuspensionContext::TopLevelAwait);
    assert_eq!(state.suspensions.len(), 1);
    assert_eq!(state.event_seq, 1);
    state.record_suspension(PromiseHandle(20), SuspensionContext::TopLevelAwait);
    assert_eq!(state.suspensions.len(), 2);
    assert_eq!(state.event_seq, 2);
}

#[test]
fn state_record_resumption_resolves_last() {
    let mut state = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    state.record_suspension(PromiseHandle(10), SuspensionContext::TopLevelAwait);
    state.record_resumption();
    assert!(state.suspensions[0].resolved);
}

#[test]
fn state_dependency_tracking_lifecycle() {
    let mut state = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    assert!(state.all_dependencies_settled());

    state.add_pending_dependency("a.js".into());
    state.add_pending_dependency("b.js".into());
    assert!(!state.all_dependencies_settled());
    assert_eq!(state.phase, AsyncModulePhase::AwaitingDependencies);

    state.resolve_dependency("a.js");
    assert!(!state.all_dependencies_settled());

    state.resolve_dependency("b.js");
    assert!(state.all_dependencies_settled());
}

#[test]
fn state_settle_clears_pending() {
    let mut state = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    state.add_pending_dependency("dep.js".into());
    state.settle();
    assert_eq!(state.phase, AsyncModulePhase::Settled);
    assert!(state.pending_dependencies.is_empty());
}

#[test]
fn state_reject_stores_hash() {
    let mut state = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    state.reject("abc123".into(), None);
    assert_eq!(state.phase, AsyncModulePhase::Rejected);
    assert_eq!(state.rejection_reason_hash, Some("abc123".to_string()));
}

#[test]
fn state_serde_roundtrip() {
    let mut state = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
    state.record_suspension(PromiseHandle(10), SuspensionContext::TopLevelAwait);
    state.add_pending_dependency("dep.js".into());
    let json = serde_json::to_string(&state).unwrap();
    let back: AsyncModuleState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

// ---------------------------------------------------------------------------
// AsyncModuleEvaluator — registration
// ---------------------------------------------------------------------------

#[test]
fn evaluator_register_sync_module_phase() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("sync.js", false, &[], None);
    assert_eq!(
        eval.states()["sync.js"].phase,
        AsyncModulePhase::Synchronous
    );
}

#[test]
fn evaluator_register_async_module_phase() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("async.js", true, &[], Some(PromiseHandle(1)));
    assert_eq!(eval.states()["async.js"].phase, AsyncModulePhase::Suspended);
}

#[test]
fn evaluator_register_with_unsettled_dep_tracks_pending() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("dep.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module(
        "consumer.js",
        true,
        &["dep.js".to_string()],
        Some(PromiseHandle(2)),
    );
    // dep.js is not settled so consumer should track it as pending
    assert!(
        eval.states()["consumer.js"]
            .pending_dependencies
            .contains("dep.js")
    );
}

#[test]
fn evaluator_register_emits_evaluation_started() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", false, &[], None);
    let events = eval.witness_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AsyncEvalEventType::EvaluationStarted);
    assert_eq!(events[0].module_specifier, "m.js");
}

// ---------------------------------------------------------------------------
// AsyncModuleEvaluator — suspension/resumption
// ---------------------------------------------------------------------------

#[test]
fn evaluator_suspend_at_tla() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("tla.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("tla.js", PromiseHandle(10))
        .unwrap();
    assert_eq!(eval.states()["tla.js"].suspensions.len(), 1);
    let events = eval.witness_events();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == AsyncEvalEventType::TopLevelAwaitSuspended)
    );
}

#[test]
fn evaluator_suspend_unknown_module_errors() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let err = eval
        .suspend_at_top_level_await("ghost.js", PromiseHandle(1))
        .unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

#[test]
fn evaluator_resume_resolves_suspension() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("m.js", PromiseHandle(10))
        .unwrap();
    eval.resume_evaluation("m.js").unwrap();
    assert!(eval.states()["m.js"].suspensions[0].resolved);
}

#[test]
fn evaluator_resume_unknown_module_errors() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let err = eval.resume_evaluation("ghost.js").unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

#[test]
fn evaluator_suspension_limit_enforced() {
    let config = AsyncEvalConfig {
        max_suspensions_per_module: 3,
        ..Default::default()
    };
    let mut eval = AsyncModuleEvaluator::new(config);
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    for i in 0..3 {
        eval.suspend_at_top_level_await("m.js", PromiseHandle(10 + i))
            .unwrap();
    }
    let err = eval
        .suspend_at_top_level_await("m.js", PromiseHandle(99))
        .unwrap_err();
    assert!(matches!(
        err,
        AsyncEvalError::SuspensionLimitExceeded { limit: 3, .. }
    ));
}

// ---------------------------------------------------------------------------
// AsyncModuleEvaluator — settle
// ---------------------------------------------------------------------------

#[test]
fn evaluator_settle_module_success() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    let resumable = eval.settle_module("m.js").unwrap();
    assert!(resumable.is_empty());
    assert_eq!(eval.states()["m.js"].phase, AsyncModulePhase::Settled);
}

#[test]
fn evaluator_settle_notifies_dependents() {
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

    let resumable = eval.settle_module("dep.js").unwrap();
    assert!(resumable.contains(&"consumer.js".to_string()));
}

#[test]
fn evaluator_settle_unknown_module_errors() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let err = eval.settle_module("ghost.js").unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

// ---------------------------------------------------------------------------
// AsyncModuleEvaluator — dependency notification
// ---------------------------------------------------------------------------

#[test]
fn evaluator_dependency_settled_notification() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("leaf.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module(
        "mid.js",
        true,
        &["leaf.js".to_string()],
        Some(PromiseHandle(2)),
    );
    eval.suspend_on_dependency("mid.js", "leaf.js", PromiseHandle(1))
        .unwrap();

    let resumable = eval.notify_dependency_settled("leaf.js").unwrap();
    assert!(resumable.contains(&"mid.js".to_string()));
    assert!(eval.states()["mid.js"].all_dependencies_settled());
}

#[test]
fn evaluator_multiple_deps_only_resume_when_all_settled() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("a.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module("b.js", true, &[], Some(PromiseHandle(2)));
    eval.register_module(
        "c.js",
        true,
        &["a.js".to_string(), "b.js".to_string()],
        Some(PromiseHandle(3)),
    );
    eval.suspend_on_dependency("c.js", "a.js", PromiseHandle(1))
        .unwrap();
    eval.suspend_on_dependency("c.js", "b.js", PromiseHandle(2))
        .unwrap();

    let resumable_a = eval.notify_dependency_settled("a.js").unwrap();
    assert!(resumable_a.is_empty()); // c.js still waiting on b.js

    let resumable_b = eval.notify_dependency_settled("b.js").unwrap();
    assert!(resumable_b.contains(&"c.js".to_string()));
}

// ---------------------------------------------------------------------------
// AsyncModuleEvaluator — rejection
// ---------------------------------------------------------------------------

#[test]
fn evaluator_reject_module_sets_phase() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
    let mut bindings = empty_bindings();
    eval.reject_module("bad.js", &js_error("fail"), &mut bindings)
        .unwrap();
    assert_eq!(eval.states()["bad.js"].phase, AsyncModulePhase::Rejected);
}

#[test]
fn evaluator_reject_module_returns_linkage() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
    let mut bindings = empty_bindings();
    let linkage = eval
        .reject_module("bad.js", &js_error("crash"), &mut bindings)
        .unwrap();
    assert_eq!(linkage.rejected_module, "bad.js");
    assert!(!linkage.rejection_reason_hash.is_empty());
}

#[test]
fn evaluator_reject_unknown_module_errors() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let mut bindings = empty_bindings();
    let err = eval
        .reject_module("ghost.js", &js_error("err"), &mut bindings)
        .unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}

#[test]
fn evaluator_reject_marks_bindings_dead() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
    let mut bindings = bindings_with_cells(&[("bad.js", "x"), ("bad.js", "y"), ("other.js", "z")]);

    let linkage = eval
        .reject_module("bad.js", &js_error("err"), &mut bindings)
        .unwrap();

    // Bindings from bad.js should be dead
    assert_eq!(linkage.dead_bindings.len(), 2);
    for id in &linkage.dead_bindings {
        assert_eq!(id.module_specifier, "bad.js");
        assert_eq!(bindings.cells[id].state, BindingCellState::Dead);
    }
    // Binding from other.js should be unaffected
    let other_id = make_binding_id("other.js", "z");
    assert_eq!(
        bindings.cells[&other_id].state,
        BindingCellState::Initialized
    );
}

#[test]
fn evaluator_reject_propagates_transitively() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("root.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module(
        "mid.js",
        true,
        &["root.js".to_string()],
        Some(PromiseHandle(2)),
    );
    eval.register_module(
        "leaf.js",
        true,
        &["mid.js".to_string()],
        Some(PromiseHandle(3)),
    );
    eval.suspend_on_dependency("mid.js", "root.js", PromiseHandle(1))
        .unwrap();
    eval.suspend_on_dependency("leaf.js", "mid.js", PromiseHandle(2))
        .unwrap();

    let mut bindings = empty_bindings();
    let linkage = eval
        .reject_module("root.js", &js_error("boom"), &mut bindings)
        .unwrap();

    // Both mid.js and leaf.js should be in transitive closure
    assert!(linkage.transitive_closure.contains("mid.js"));
    assert!(linkage.transitive_closure.contains("leaf.js"));

    // All should be rejected
    assert_eq!(eval.states()["root.js"].phase, AsyncModulePhase::Rejected);
    assert_eq!(eval.states()["mid.js"].phase, AsyncModulePhase::Rejected);
    assert_eq!(eval.states()["leaf.js"].phase, AsyncModulePhase::Rejected);
}

#[test]
fn evaluator_reject_without_transitive_propagation() {
    let config = AsyncEvalConfig {
        transitive_rejection_propagation: false,
        ..Default::default()
    };
    let mut eval = AsyncModuleEvaluator::new(config);
    eval.register_module("root.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module(
        "mid.js",
        true,
        &["root.js".to_string()],
        Some(PromiseHandle(2)),
    );
    eval.register_module(
        "leaf.js",
        true,
        &["mid.js".to_string()],
        Some(PromiseHandle(3)),
    );
    eval.suspend_on_dependency("mid.js", "root.js", PromiseHandle(1))
        .unwrap();
    eval.suspend_on_dependency("leaf.js", "mid.js", PromiseHandle(2))
        .unwrap();

    let mut bindings = empty_bindings();
    let linkage = eval
        .reject_module("root.js", &js_error("boom"), &mut bindings)
        .unwrap();

    // Only direct dependents, not transitive
    assert!(linkage.transitive_closure.contains("mid.js"));
    // leaf.js depends on mid.js not root.js, so it should not be directly linked
}

#[test]
fn evaluator_reject_emits_witness_events() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
    let mut bindings = bindings_with_cells(&[("bad.js", "x")]);

    eval.reject_module("bad.js", &js_error("err"), &mut bindings)
        .unwrap();

    let events = eval.witness_events();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == AsyncEvalEventType::EvaluationRejected)
    );
    assert!(
        events
            .iter()
            .any(|e| e.event_type == AsyncEvalEventType::BindingMarkedDead)
    );
}

#[test]
fn evaluator_reject_records_live_binding_cell_died_event() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));

    let mut bindings = LiveBindingMap::new();
    let binding_id = bindings.register_cell(BindingCell::new(
        "bad.js",
        "value",
        "value",
        BindingType::Direct,
    ));

    let linkage = eval
        .reject_module("bad.js", &js_error("err"), &mut bindings)
        .unwrap();

    assert_eq!(linkage.dead_bindings, vec![binding_id.clone()]);
    assert_eq!(
        bindings.get_cell(&binding_id).map(|cell| cell.state),
        Some(BindingCellState::Dead)
    );
    assert!(bindings.events.iter().any(|event| matches!(
        event,
        BindingEvent::CellDied { binding_id: event_id } if event_id == &binding_id
    )));
}

// ---------------------------------------------------------------------------
// AsyncModuleEvaluator — finalize
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
    assert!(!result.result_hash.is_empty());
}

#[test]
fn evaluator_finalize_with_rejection() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("ok.js", false, &[], None);
    eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
    let mut bindings = empty_bindings();
    eval.reject_module("bad.js", &js_error("err"), &mut bindings)
        .unwrap();

    let result = eval.finalize();
    assert!(!result.all_settled);
    assert_eq!(result.total_rejections, 1);
    assert_eq!(result.settled_count(), 1);
    assert_eq!(result.rejected_count(), 1);
}

#[test]
fn evaluator_finalize_counts_suspensions() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("m.js", PromiseHandle(10))
        .unwrap();
    eval.suspend_at_top_level_await("m.js", PromiseHandle(20))
        .unwrap();
    eval.settle_module("m.js").unwrap();

    let result = eval.finalize();
    assert_eq!(result.total_suspensions, 2);
}

#[test]
fn evaluator_finalize_result_serde_roundtrip() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("a.js", false, &[], None);
    eval.register_module("b.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("b.js", PromiseHandle(5))
        .unwrap();
    eval.resume_evaluation("b.js").unwrap();
    eval.settle_module("b.js").unwrap();

    let result = eval.finalize();
    let json = serde_json::to_string(&result).unwrap();
    let back: AsyncEvalResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// AsyncModuleEvaluator — witness events
// ---------------------------------------------------------------------------

#[test]
fn evaluator_witness_events_monotonic_seq() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("m.js", PromiseHandle(10))
        .unwrap();
    eval.resume_evaluation("m.js").unwrap();
    eval.settle_module("m.js").unwrap();

    let events = eval.witness_events();
    for window in events.windows(2) {
        assert!(
            window[0].seq < window[1].seq,
            "seq must be monotonically increasing"
        );
    }
}

#[test]
fn evaluator_witness_event_types_cover_lifecycle() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
    eval.suspend_at_top_level_await("m.js", PromiseHandle(10))
        .unwrap();
    eval.resume_evaluation("m.js").unwrap();
    eval.settle_module("m.js").unwrap();

    let event_types: BTreeSet<_> = eval.witness_events().iter().map(|e| e.event_type).collect();
    assert!(event_types.contains(&AsyncEvalEventType::EvaluationStarted));
    assert!(event_types.contains(&AsyncEvalEventType::TopLevelAwaitSuspended));
    assert!(event_types.contains(&AsyncEvalEventType::EvaluationResumed));
    assert!(event_types.contains(&AsyncEvalEventType::EvaluationSettled));
}

#[test]
fn evaluator_witness_event_serde_roundtrip() {
    let event = AsyncEvalWitnessEvent {
        module_specifier: "test.js".into(),
        event_type: AsyncEvalEventType::DependencySettled,
        seq: 42,
        detail: "settled=dep.js".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: AsyncEvalWitnessEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// Topological ordering — compute_async_evaluation_order
// ---------------------------------------------------------------------------

#[test]
fn topological_order_empty() {
    let order = compute_async_evaluation_order(&[], &BTreeMap::new()).unwrap();
    assert!(order.is_empty());
}

#[test]
fn topological_order_single_module() {
    let modules = vec!["only.js".into()];
    let order = compute_async_evaluation_order(&modules, &BTreeMap::new()).unwrap();
    assert_eq!(order, vec!["only.js".to_string()]);
}

#[test]
fn topological_order_linear_chain() {
    let modules: Vec<String> = vec!["a.js".into(), "b.js".into(), "c.js".into(), "d.js".into()];
    let mut deps = BTreeMap::new();
    deps.insert("b.js".into(), vec!["a.js".into()]);
    deps.insert("c.js".into(), vec!["b.js".into()]);
    deps.insert("d.js".into(), vec!["c.js".into()]);
    let order = compute_async_evaluation_order(&modules, &deps).unwrap();
    let pos_a = order.iter().position(|s| s == "a.js").unwrap();
    let pos_b = order.iter().position(|s| s == "b.js").unwrap();
    let pos_c = order.iter().position(|s| s == "c.js").unwrap();
    let pos_d = order.iter().position(|s| s == "d.js").unwrap();
    assert!(pos_a < pos_b);
    assert!(pos_b < pos_c);
    assert!(pos_c < pos_d);
}

#[test]
fn topological_order_diamond_dependency() {
    // a.js -> b.js, a.js -> c.js, b.js -> d.js, c.js -> d.js
    let modules: Vec<String> = vec!["a.js".into(), "b.js".into(), "c.js".into(), "d.js".into()];
    let mut deps = BTreeMap::new();
    deps.insert("b.js".into(), vec!["a.js".into()]);
    deps.insert("c.js".into(), vec!["a.js".into()]);
    deps.insert("d.js".into(), vec!["b.js".into(), "c.js".into()]);
    let order = compute_async_evaluation_order(&modules, &deps).unwrap();
    assert_eq!(order.len(), 4);
    let pos_a = order.iter().position(|s| s == "a.js").unwrap();
    let pos_d = order.iter().position(|s| s == "d.js").unwrap();
    assert!(pos_a < pos_d);
}

#[test]
fn topological_order_no_deps_deterministic() {
    let modules: Vec<String> = vec!["z.js".into(), "a.js".into(), "m.js".into()];
    let order1 = compute_async_evaluation_order(&modules, &BTreeMap::new()).unwrap();
    let order2 = compute_async_evaluation_order(&modules, &BTreeMap::new()).unwrap();
    assert_eq!(order1, order2);
}

#[test]
fn topological_order_cycle_two_modules() {
    let modules: Vec<String> = vec!["a.js".into(), "b.js".into()];
    let mut deps = BTreeMap::new();
    deps.insert("a.js".into(), vec!["b.js".into()]);
    deps.insert("b.js".into(), vec!["a.js".into()]);
    let err = compute_async_evaluation_order(&modules, &deps).unwrap_err();
    match err {
        AsyncEvalError::CycleDetected { modules } => {
            assert!(!modules.is_empty());
        }
        _ => panic!("expected CycleDetected"),
    }
}

#[test]
fn topological_order_cycle_three_modules() {
    let modules: Vec<String> = vec!["a.js".into(), "b.js".into(), "c.js".into()];
    let mut deps = BTreeMap::new();
    deps.insert("a.js".into(), vec!["c.js".into()]);
    deps.insert("b.js".into(), vec!["a.js".into()]);
    deps.insert("c.js".into(), vec!["b.js".into()]);
    let err = compute_async_evaluation_order(&modules, &deps).unwrap_err();
    assert!(matches!(err, AsyncEvalError::CycleDetected { .. }));
}

#[test]
fn topological_order_external_dep_ignored() {
    // Dependencies on modules not in the specifier list are ignored
    let modules: Vec<String> = vec!["a.js".into(), "b.js".into()];
    let mut deps = BTreeMap::new();
    deps.insert("a.js".into(), vec!["external.js".into()]);
    deps.insert("b.js".into(), vec!["a.js".into()]);
    let order = compute_async_evaluation_order(&modules, &deps).unwrap();
    assert_eq!(order.len(), 2);
}

// ---------------------------------------------------------------------------
// Multi-module evaluation pipelines
// ---------------------------------------------------------------------------

#[test]
fn pipeline_three_module_chain_settle_in_order() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("base.js", false, &[], None);
    eval.register_module(
        "mid.js",
        true,
        &["base.js".to_string()],
        Some(PromiseHandle(1)),
    );
    eval.register_module(
        "top.js",
        true,
        &["mid.js".to_string()],
        Some(PromiseHandle(2)),
    );
    eval.suspend_on_dependency("top.js", "mid.js", PromiseHandle(1))
        .unwrap();

    // Settle mid.js
    let resumable = eval.settle_module("mid.js").unwrap();
    assert!(resumable.contains(&"top.js".to_string()));

    // Resume and settle top.js
    eval.resume_evaluation("top.js").unwrap();
    eval.settle_module("top.js").unwrap();

    let result = eval.finalize();
    assert!(result.all_settled);
    assert_eq!(result.settled_count(), 3);
}

#[test]
fn pipeline_mixed_sync_async_modules() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("sync1.js", false, &[], None);
    eval.register_module("sync2.js", false, &[], None);
    eval.register_module("async1.js", true, &[], Some(PromiseHandle(1)));

    eval.suspend_at_top_level_await("async1.js", PromiseHandle(10))
        .unwrap();
    eval.resume_evaluation("async1.js").unwrap();
    eval.settle_module("async1.js").unwrap();

    let result = eval.finalize();
    assert!(result.all_settled);
    assert_eq!(result.settled_count(), 3);
    assert_eq!(result.total_suspensions, 1);
}

#[test]
fn pipeline_rejection_in_diamond_graph() {
    // dep1.js, dep2.js -> consumer.js
    // dep1.js rejects -> consumer.js should be affected
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("dep1.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module("dep2.js", true, &[], Some(PromiseHandle(2)));
    eval.register_module(
        "consumer.js",
        true,
        &["dep1.js".to_string(), "dep2.js".to_string()],
        Some(PromiseHandle(3)),
    );
    eval.suspend_on_dependency("consumer.js", "dep1.js", PromiseHandle(1))
        .unwrap();
    eval.suspend_on_dependency("consumer.js", "dep2.js", PromiseHandle(2))
        .unwrap();

    let mut bindings = empty_bindings();
    let linkage = eval
        .reject_module("dep1.js", &js_error("timeout"), &mut bindings)
        .unwrap();
    assert!(linkage.transitive_closure.contains("consumer.js"));
    assert_eq!(
        eval.states()["consumer.js"].phase,
        AsyncModulePhase::Rejected
    );
    // dep2.js should remain unaffected
    assert_eq!(eval.states()["dep2.js"].phase, AsyncModulePhase::Suspended);
}

#[test]
fn pipeline_full_lifecycle_with_binding_death() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("provider.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module(
        "consumer.js",
        true,
        &["provider.js".to_string()],
        Some(PromiseHandle(2)),
    );
    eval.suspend_on_dependency("consumer.js", "provider.js", PromiseHandle(1))
        .unwrap();

    let mut bindings = bindings_with_cells(&[
        ("provider.js", "exportA"),
        ("provider.js", "exportB"),
        ("consumer.js", "local"),
    ]);

    let linkage = eval
        .reject_module("provider.js", &js_error("crash"), &mut bindings)
        .unwrap();

    // Provider bindings dead
    assert_eq!(linkage.dead_bindings.len(), 2);
    // Consumer's own binding should also be dead (transitive propagation)
    let consumer_binding = make_binding_id("consumer.js", "local");
    assert_eq!(
        bindings.cells[&consumer_binding].state,
        BindingCellState::Dead
    );

    let result = eval.finalize();
    assert!(!result.all_settled);
    assert_eq!(result.total_rejections, 2);
    assert!(!result.rejection_linkages.is_empty());
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn determinism_same_inputs_same_result_hash() {
    fn run_scenario() -> String {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("a.js", false, &[], None);
        eval.register_module("b.js", true, &[], Some(PromiseHandle(1)));
        eval.suspend_at_top_level_await("b.js", PromiseHandle(10))
            .unwrap();
        eval.resume_evaluation("b.js").unwrap();
        eval.settle_module("b.js").unwrap();
        eval.finalize().result_hash
    }
    assert_eq!(run_scenario(), run_scenario());
}

#[test]
fn determinism_witness_event_order_stable() {
    fn collect_events() -> Vec<(String, AsyncEvalEventType, u64)> {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("x.js", true, &[], Some(PromiseHandle(1)));
        eval.register_module("y.js", false, &[], None);
        eval.suspend_at_top_level_await("x.js", PromiseHandle(2))
            .unwrap();
        eval.settle_module("x.js").unwrap();
        eval.witness_events()
            .iter()
            .map(|e| (e.module_specifier.clone(), e.event_type, e.seq))
            .collect()
    }
    assert_eq!(collect_events(), collect_events());
}

// ---------------------------------------------------------------------------
// RejectionLinkage
// ---------------------------------------------------------------------------

#[test]
fn rejection_linkage_serde_roundtrip() {
    let linkage = RejectionLinkage {
        rejected_module: "error.js".into(),
        rejection_reason_hash: "deadbeef".into(),
        rejection_reason_description: Some("Error: test".into()),
        linked_modules: vec![
            LinkedModule {
                module_specifier: "a.js".into(),
                import_bindings: vec![make_binding_id("a.js", "foo")],
                linkage_kind: LinkageKind::DirectImport,
            },
            LinkedModule {
                module_specifier: "b.js".into(),
                import_bindings: vec![],
                linkage_kind: LinkageKind::ReExport,
            },
        ],
        transitive_closure: {
            let mut s = BTreeSet::new();
            s.insert("a.js".into());
            s.insert("b.js".into());
            s
        },
        dead_bindings: vec![make_binding_id("error.js", "val")],
    };
    let json = serde_json::to_string(&linkage).unwrap();
    let back: RejectionLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(linkage, back);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn evaluator_register_many_modules() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    for i in 0..100 {
        eval.register_module(
            &format!("mod_{i}.js"),
            i % 2 == 0,
            &[],
            if i % 2 == 0 {
                Some(PromiseHandle(i as u32))
            } else {
                None
            },
        );
    }
    assert_eq!(eval.states().len(), 100);
}

#[test]
fn evaluator_multiple_rejections_independent() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("bad1.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module("bad2.js", true, &[], Some(PromiseHandle(2)));
    eval.register_module("good.js", false, &[], None);

    let mut bindings = empty_bindings();
    eval.reject_module("bad1.js", &js_error("err1"), &mut bindings)
        .unwrap();
    eval.reject_module("bad2.js", &js_error("err2"), &mut bindings)
        .unwrap();

    let result = eval.finalize();
    assert_eq!(result.total_rejections, 2);
    assert_eq!(result.settled_count(), 1);
    assert_eq!(result.rejection_linkages.len(), 2);
}

#[test]
fn evaluator_suspend_on_dependency_tracks_pending() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    eval.register_module("dep.js", true, &[], Some(PromiseHandle(1)));
    eval.register_module("user.js", true, &[], Some(PromiseHandle(2)));
    eval.suspend_on_dependency("user.js", "dep.js", PromiseHandle(1))
        .unwrap();

    assert!(
        eval.states()["user.js"]
            .pending_dependencies
            .contains("dep.js")
    );
    assert_eq!(eval.states()["user.js"].suspensions.len(), 1);
}

#[test]
fn evaluator_suspend_on_dependency_unknown_module_errors() {
    let mut eval = AsyncModuleEvaluator::with_defaults();
    let err = eval
        .suspend_on_dependency("ghost.js", "dep.js", PromiseHandle(1))
        .unwrap_err();
    assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
}
