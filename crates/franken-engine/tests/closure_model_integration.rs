//! Integration tests for the `closure_model` module.
//!
//! Exercises the public API from outside the crate: scope chain lifecycle,
//! var hoisting, let/const TDZ enforcement, closure capture, IFC label
//! propagation, ClosureStore management, serde round-trips, Display impls,
//! determinism, and edge cases.

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
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::closure_model::{
    BindingSlot, Closure, ClosureCapture, ClosureHandle, ClosureStore, EnvValue, EnvironmentHandle,
    EnvironmentKind, EnvironmentRecord, ScopeChain, ScopeError,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{BindingKind, ScopeId, ScopeKind};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sid(depth: u32, index: u32) -> ScopeId {
    ScopeId { depth, index }
}

fn fresh_chain() -> ScopeChain {
    ScopeChain::new()
}

// ---------------------------------------------------------------------------
// 1. ScopeChain construction and defaults
// ---------------------------------------------------------------------------

#[test]
fn scope_chain_new_has_global_scope() {
    let chain = fresh_chain();
    assert_eq!(chain.depth(), 1);
    let handle = chain.current_handle().unwrap();
    let env = chain.get_env(handle).unwrap();
    assert_eq!(env.scope_kind, ScopeKind::Global);
    assert_eq!(env.env_kind, EnvironmentKind::Global);
    assert!(env.bindings.is_empty());
    assert_eq!(env.max_label, Label::Public);
}

#[test]
fn scope_chain_default_equals_new() {
    let a = ScopeChain::new();
    let b = ScopeChain::default();
    assert_eq!(a.depth(), b.depth());
}

// ---------------------------------------------------------------------------
// 2. Push/pop scope lifecycle
// ---------------------------------------------------------------------------

#[test]
fn push_scope_increments_depth() {
    let mut chain = fresh_chain();
    chain.push_scope(sid(1, 0), ScopeKind::Block);
    assert_eq!(chain.depth(), 2);
    chain.push_scope(sid(2, 0), ScopeKind::Function);
    assert_eq!(chain.depth(), 3);
}

#[test]
fn pop_scope_decrements_depth() {
    let mut chain = fresh_chain();
    chain.push_scope(sid(1, 0), ScopeKind::Block);
    chain.pop_scope().unwrap();
    assert_eq!(chain.depth(), 1);
}

#[test]
fn pop_global_scope_returns_empty_scope_chain_error() {
    let mut chain = fresh_chain();
    let err = chain.pop_scope().unwrap_err();
    assert!(matches!(err, ScopeError::EmptyScopeChain));
}

#[test]
fn push_returns_handle_and_current_matches() {
    let mut chain = fresh_chain();
    let handle = chain.push_scope(sid(1, 0), ScopeKind::Block);
    assert_eq!(chain.current_handle().unwrap(), handle);
}

#[test]
fn push_maps_scope_kind_to_environment_kind() {
    let mut chain = fresh_chain();
    let h1 = chain.push_scope(sid(1, 0), ScopeKind::Function);
    assert_eq!(
        chain.get_env(h1).unwrap().env_kind,
        EnvironmentKind::Function
    );
    let h2 = chain.push_scope(sid(2, 0), ScopeKind::Module);
    assert_eq!(chain.get_env(h2).unwrap().env_kind, EnvironmentKind::Module);
    let h3 = chain.push_scope(sid(3, 0), ScopeKind::Catch);
    assert_eq!(
        chain.get_env(h3).unwrap().env_kind,
        EnvironmentKind::Declarative
    );
}

// ---------------------------------------------------------------------------
// 3. Var hoisting
// ---------------------------------------------------------------------------

#[test]
fn var_hoists_past_block_to_global() {
    let mut chain = fresh_chain();
    chain.push_scope(sid(1, 0), ScopeKind::Block);
    chain.declare_var("x".into(), 1).unwrap();
    // Should be in global, not block.
    let global_env = chain.get_env(EnvironmentHandle(0)).unwrap();
    assert!(global_env.get_binding("x").is_some());
    let block = chain.get_env(chain.current_handle().unwrap()).unwrap();
    assert!(block.get_binding("x").is_none());
}

#[test]
fn var_hoists_to_function_scope() {
    let mut chain = fresh_chain();
    let fn_h = chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.push_scope(sid(2, 0), ScopeKind::Block);
    chain.declare_var("y".into(), 2).unwrap();
    let fn_env = chain.get_env(fn_h).unwrap();
    assert!(fn_env.get_binding("y").is_some());
    let global_env = chain.get_env(EnvironmentHandle(0)).unwrap();
    assert!(global_env.get_binding("y").is_none());
}

#[test]
fn var_hoists_to_module_scope() {
    let mut chain = fresh_chain();
    let mod_h = chain.push_scope(sid(1, 0), ScopeKind::Module);
    chain.push_scope(sid(2, 0), ScopeKind::Block);
    chain.declare_var("z".into(), 3).unwrap();
    let mod_env = chain.get_env(mod_h).unwrap();
    assert!(mod_env.get_binding("z").is_some());
}

#[test]
fn var_redeclaration_is_noop() {
    let mut chain = fresh_chain();
    chain.declare_var("x".into(), 1).unwrap();
    chain.declare_var("x".into(), 2).unwrap();
    let val = chain.get_value("x").unwrap();
    assert_eq!(*val, EnvValue::Undefined);
}

// ---------------------------------------------------------------------------
// 4. Let/const declarations with TDZ
// ---------------------------------------------------------------------------

#[test]
fn let_starts_in_tdz() {
    let mut chain = fresh_chain();
    chain.declare_let("a".into(), 10).unwrap();
    let err = chain.get_value("a").unwrap_err();
    assert!(matches!(err, ScopeError::TemporalDeadZone { .. }));
}

#[test]
fn let_accessible_after_initialization() {
    let mut chain = fresh_chain();
    chain.declare_let("a".into(), 10).unwrap();
    chain
        .initialize_binding("a", EnvValue::Number(42_000_000), Label::Public)
        .unwrap();
    assert_eq!(*chain.get_value("a").unwrap(), EnvValue::Number(42_000_000));
}

#[test]
fn const_assignment_after_init_fails() {
    let mut chain = fresh_chain();
    chain.declare_const("PI".into(), 20).unwrap();
    chain
        .initialize_binding("PI", EnvValue::Number(3_141_593), Label::Public)
        .unwrap();
    let err = chain
        .set_value("PI", EnvValue::Number(0), Label::Public)
        .unwrap_err();
    assert!(matches!(err, ScopeError::ConstAssignment { .. }));
    // Value unchanged.
    assert_eq!(*chain.get_value("PI").unwrap(), EnvValue::Number(3_141_593));
}

#[test]
fn let_reassignment_works() {
    let mut chain = fresh_chain();
    chain.declare_let("x".into(), 11).unwrap();
    chain
        .initialize_binding("x", EnvValue::Number(1), Label::Public)
        .unwrap();
    chain
        .set_value("x", EnvValue::Number(2), Label::Public)
        .unwrap();
    assert_eq!(*chain.get_value("x").unwrap(), EnvValue::Number(2));
}

#[test]
fn write_to_tdz_binding_fails() {
    let mut chain = fresh_chain();
    chain.declare_let("x".into(), 1).unwrap();
    let err = chain
        .set_value("x", EnvValue::Number(1), Label::Public)
        .unwrap_err();
    assert!(matches!(err, ScopeError::TemporalDeadZone { .. }));
}

// ---------------------------------------------------------------------------
// 5. Duplicate lexical declarations
// ---------------------------------------------------------------------------

#[test]
fn duplicate_let_in_same_scope_fails() {
    let mut chain = fresh_chain();
    chain.declare_let("x".into(), 1).unwrap();
    let err = chain.declare_let("x".into(), 2).unwrap_err();
    assert!(matches!(err, ScopeError::DuplicateBinding { .. }));
}

#[test]
fn duplicate_const_in_same_scope_fails() {
    let mut chain = fresh_chain();
    chain.declare_const("C".into(), 1).unwrap();
    let err = chain.declare_const("C".into(), 2).unwrap_err();
    assert!(matches!(err, ScopeError::DuplicateBinding { .. }));
}

#[test]
fn same_name_in_different_scopes_ok() {
    let mut chain = fresh_chain();
    chain.declare_let("x".into(), 1).unwrap();
    chain
        .initialize_binding("x", EnvValue::Number(10), Label::Public)
        .unwrap();

    chain.push_scope(sid(1, 0), ScopeKind::Block);
    chain.declare_let("x".into(), 2).unwrap();
    chain
        .initialize_binding("x", EnvValue::Number(20), Label::Public)
        .unwrap();
    assert_eq!(*chain.get_value("x").unwrap(), EnvValue::Number(20));

    chain.pop_scope().unwrap();
    assert_eq!(*chain.get_value("x").unwrap(), EnvValue::Number(10));
}

// ---------------------------------------------------------------------------
// 6. Variable shadowing
// ---------------------------------------------------------------------------

#[test]
fn block_scoped_let_shadows_var() {
    let mut chain = fresh_chain();
    chain.declare_var("x".into(), 1).unwrap();
    chain
        .set_value("x", EnvValue::Number(100), Label::Public)
        .unwrap();

    chain.push_scope(sid(1, 0), ScopeKind::Block);
    chain.declare_let("x".into(), 2).unwrap();
    chain
        .initialize_binding("x", EnvValue::Number(200), Label::Public)
        .unwrap();
    assert_eq!(*chain.get_value("x").unwrap(), EnvValue::Number(200));

    chain.pop_scope().unwrap();
    assert_eq!(*chain.get_value("x").unwrap(), EnvValue::Number(100));
}

// ---------------------------------------------------------------------------
// 7. Undeclared variable
// ---------------------------------------------------------------------------

#[test]
fn undeclared_variable_error_on_read() {
    let chain = fresh_chain();
    let err = chain.get_value("nope").unwrap_err();
    assert!(matches!(err, ScopeError::UndeclaredVariable { .. }));
}

#[test]
fn undeclared_variable_error_on_write() {
    let mut chain = fresh_chain();
    let err = chain
        .set_value("nope", EnvValue::Number(1), Label::Public)
        .unwrap_err();
    assert!(matches!(err, ScopeError::UndeclaredVariable { .. }));
}

// ---------------------------------------------------------------------------
// 8. Function declaration hoisting
// ---------------------------------------------------------------------------

#[test]
fn function_decl_hoisted_with_value() {
    let mut chain = fresh_chain();
    let closure_ref = EnvValue::ClosureRef(ClosureHandle(0));
    chain
        .declare_function("foo".into(), 50, closure_ref.clone())
        .unwrap();
    assert_eq!(*chain.get_value("foo").unwrap(), closure_ref);
}

#[test]
fn function_decl_overwrites_var() {
    let mut chain = fresh_chain();
    chain.declare_var("f".into(), 1).unwrap();
    assert_eq!(*chain.get_value("f").unwrap(), EnvValue::Undefined);

    let closure_ref = EnvValue::ClosureRef(ClosureHandle(7));
    chain
        .declare_function("f".into(), 2, closure_ref.clone())
        .unwrap();
    assert_eq!(*chain.get_value("f").unwrap(), closure_ref);
}

// ---------------------------------------------------------------------------
// 9. Parameter bindings
// ---------------------------------------------------------------------------

#[test]
fn parameter_binding_is_mutable_and_initialized() {
    let mut chain = fresh_chain();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain
        .declare_parameter("arg".into(), 100, EnvValue::Number(5), Label::Public)
        .unwrap();
    assert_eq!(*chain.get_value("arg").unwrap(), EnvValue::Number(5));
    chain
        .set_value("arg", EnvValue::Number(10), Label::Public)
        .unwrap();
    assert_eq!(*chain.get_value("arg").unwrap(), EnvValue::Number(10));
}

#[test]
fn parameter_binding_carries_ifc_label() {
    let mut chain = fresh_chain();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain
        .declare_parameter(
            "secret_arg".into(),
            101,
            EnvValue::Str("key".into()),
            Label::Secret,
        )
        .unwrap();
    let handle = chain.current_handle().unwrap();
    let env = chain.get_env(handle).unwrap();
    let slot = env.get_binding("secret_arg").unwrap();
    assert_eq!(slot.label, Label::Secret);
}

// ---------------------------------------------------------------------------
// 10. Closure capture
// ---------------------------------------------------------------------------

#[test]
fn capture_from_enclosing_scope() {
    let mut chain = fresh_chain();
    chain.declare_let("outer".into(), 1).unwrap();
    chain
        .initialize_binding("outer", EnvValue::Number(42), Label::Public)
        .unwrap();
    chain.push_scope(sid(1, 0), ScopeKind::Function);

    let captures = chain.compute_captures(&["outer".into()]).unwrap();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].name, "outer");
    assert_eq!(captures[0].source_scope, sid(0, 0));
    assert_eq!(captures[0].label, Label::Public);
}

#[test]
fn capture_multiple_from_different_scopes() {
    let mut chain = fresh_chain();
    chain.declare_let("a".into(), 1).unwrap();
    chain
        .initialize_binding("a", EnvValue::Number(10), Label::Public)
        .unwrap();

    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.declare_let("b".into(), 2).unwrap();
    chain
        .initialize_binding("b", EnvValue::Number(20), Label::Internal)
        .unwrap();

    chain.push_scope(sid(2, 0), ScopeKind::Function);
    let captures = chain.compute_captures(&["a".into(), "b".into()]).unwrap();
    assert_eq!(captures.len(), 2);
    assert_eq!(captures[0].source_scope, sid(0, 0));
    assert_eq!(captures[1].source_scope, sid(1, 0));
}

#[test]
fn capture_undeclared_fails() {
    let chain = fresh_chain();
    let err = chain.compute_captures(&["missing".into()]).unwrap_err();
    assert!(matches!(err, ScopeError::UndeclaredVariable { .. }));
}

#[test]
fn capture_empty_free_vars_yields_empty_captures() {
    let chain = fresh_chain();
    let captures = chain.compute_captures(&[]).unwrap();
    assert!(captures.is_empty());
}

// ---------------------------------------------------------------------------
// 11. IFC label propagation
// ---------------------------------------------------------------------------

#[test]
fn ifc_label_propagates_on_init() {
    let mut chain = fresh_chain();
    chain.declare_let("secret".into(), 1).unwrap();
    chain
        .initialize_binding("secret", EnvValue::Str("key".into()), Label::Secret)
        .unwrap();
    let handle = chain.current_handle().unwrap();
    let env = chain.get_env(handle).unwrap();
    assert!(env.max_label >= Label::Secret);
    let slot = env.get_binding("secret").unwrap();
    assert_eq!(slot.label, Label::Secret);
}

#[test]
fn ifc_label_propagates_on_set() {
    let mut chain = fresh_chain();
    chain.declare_var("data".into(), 1).unwrap();
    chain
        .set_value(
            "data",
            EnvValue::Str("classified".into()),
            Label::Confidential,
        )
        .unwrap();
    let global = chain.get_env(EnvironmentHandle(0)).unwrap();
    assert!(global.max_label >= Label::Confidential);
}

#[test]
fn max_label_ratchets_upward() {
    let mut chain = fresh_chain();
    chain.declare_let("a".into(), 1).unwrap();
    chain
        .initialize_binding("a", EnvValue::Number(1), Label::Internal)
        .unwrap();
    chain.declare_let("b".into(), 2).unwrap();
    chain
        .initialize_binding("b", EnvValue::Number(2), Label::TopSecret)
        .unwrap();
    let handle = chain.current_handle().unwrap();
    let env = chain.get_env(handle).unwrap();
    assert!(env.max_label >= Label::TopSecret);

    // Now add Public — max should still be TopSecret.
    chain.declare_let("c".into(), 3).unwrap();
    chain
        .initialize_binding("c", EnvValue::Number(3), Label::Public)
        .unwrap();
    let env = chain.get_env(handle).unwrap();
    assert!(env.max_label >= Label::TopSecret);
}

#[test]
fn capture_carries_ifc_label() {
    let mut chain = fresh_chain();
    chain.declare_let("classified".into(), 1).unwrap();
    chain
        .initialize_binding(
            "classified",
            EnvValue::Str("data".into()),
            Label::Confidential,
        )
        .unwrap();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    let captures = chain.compute_captures(&["classified".into()]).unwrap();
    assert_eq!(captures[0].label, Label::Confidential);
}

// ---------------------------------------------------------------------------
// 12. Catch scope
// ---------------------------------------------------------------------------

#[test]
fn catch_scope_binds_error_variable() {
    let mut chain = fresh_chain();
    chain.push_scope(sid(1, 0), ScopeKind::Catch);
    chain.declare_let("err".into(), 1).unwrap();
    chain
        .initialize_binding("err", EnvValue::Str("oops".into()), Label::Public)
        .unwrap();
    assert_eq!(
        *chain.get_value("err").unwrap(),
        EnvValue::Str("oops".into())
    );
    chain.pop_scope().unwrap();
    assert!(chain.get_value("err").is_err());
}

// ---------------------------------------------------------------------------
// 13. Nested scope chain traversal
// ---------------------------------------------------------------------------

#[test]
fn nested_scope_chain_traversal() {
    let mut chain = fresh_chain();
    chain.declare_var("a".into(), 1).unwrap();
    chain
        .set_value("a", EnvValue::Number(1), Label::Public)
        .unwrap();

    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.declare_let("b".into(), 2).unwrap();
    chain
        .initialize_binding("b", EnvValue::Number(2), Label::Public)
        .unwrap();

    chain.push_scope(sid(2, 0), ScopeKind::Block);
    chain.declare_let("c".into(), 3).unwrap();
    chain
        .initialize_binding("c", EnvValue::Number(3), Label::Public)
        .unwrap();

    assert_eq!(*chain.get_value("a").unwrap(), EnvValue::Number(1));
    assert_eq!(*chain.get_value("b").unwrap(), EnvValue::Number(2));
    assert_eq!(*chain.get_value("c").unwrap(), EnvValue::Number(3));
}

// ---------------------------------------------------------------------------
// 14. resolve_binding
// ---------------------------------------------------------------------------

#[test]
fn resolve_binding_identifies_correct_scope() {
    let mut chain = fresh_chain();
    chain.declare_var("global_var".into(), 1).unwrap();

    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.declare_let("fn_local".into(), 2).unwrap();
    chain
        .initialize_binding("fn_local", EnvValue::Number(1), Label::Public)
        .unwrap();

    let (_, scope) = chain.resolve_binding("global_var").unwrap();
    assert_eq!(scope, sid(0, 0));

    let (_, scope) = chain.resolve_binding("fn_local").unwrap();
    assert_eq!(scope, sid(1, 0));
}

#[test]
fn resolve_binding_undeclared_returns_error() {
    let chain = fresh_chain();
    let err = chain.resolve_binding("ghost").unwrap_err();
    assert!(matches!(err, ScopeError::UndeclaredVariable { .. }));
}

// ---------------------------------------------------------------------------
// 15. This binding on function environments
// ---------------------------------------------------------------------------

#[test]
fn function_env_this_binding() {
    let mut chain = fresh_chain();
    let fn_handle = chain.push_scope(sid(1, 0), ScopeKind::Function);
    let env = chain.get_env_mut(fn_handle).unwrap();
    env.this_binding = Some(EnvValue::ObjectRef(99));
    let env = chain.get_env(fn_handle).unwrap();
    assert_eq!(env.this_binding, Some(EnvValue::ObjectRef(99)));
}

// ---------------------------------------------------------------------------
// 16. Invalid environment handle
// ---------------------------------------------------------------------------

#[test]
fn invalid_environment_handle_error() {
    let chain = fresh_chain();
    let err = chain.get_env(EnvironmentHandle(999)).unwrap_err();
    assert!(matches!(err, ScopeError::InvalidEnvironment { .. }));
}

// ---------------------------------------------------------------------------
// 17. ClosureStore
// ---------------------------------------------------------------------------

#[test]
fn closure_store_new_is_empty() {
    let store = ClosureStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn closure_store_default_is_empty() {
    let store = ClosureStore::default();
    assert!(store.is_empty());
}

#[test]
fn closure_store_create_and_get() {
    let mut store = ClosureStore::new();
    let captures = vec![ClosureCapture {
        name: "x".into(),
        binding_id: 1,
        source_scope: sid(0, 0),
        label: Label::Public,
    }];
    let h = store.create_closure("add".into(), 2, true, captures, EnvironmentHandle(0));
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
    let closure = store.get(h).unwrap();
    assert_eq!(closure.name, "add");
    assert_eq!(closure.arity, 2);
    assert!(closure.strict);
    assert_eq!(closure.captures.len(), 1);
    assert_eq!(closure.max_capture_label, Label::Public);
    assert_eq!(closure.creation_env, EnvironmentHandle(0));
}

#[test]
fn closure_store_max_capture_label_computed() {
    let mut store = ClosureStore::new();
    let captures = vec![
        ClosureCapture {
            name: "a".into(),
            binding_id: 1,
            source_scope: sid(0, 0),
            label: Label::Public,
        },
        ClosureCapture {
            name: "b".into(),
            binding_id: 2,
            source_scope: sid(0, 0),
            label: Label::Secret,
        },
    ];
    let h = store.create_closure("f".into(), 0, false, captures, EnvironmentHandle(0));
    let closure = store.get(h).unwrap();
    assert_eq!(closure.max_capture_label, Label::Secret);
}

#[test]
fn closure_store_no_captures_defaults_to_public() {
    let mut store = ClosureStore::new();
    let h = store.create_closure("pure".into(), 0, true, vec![], EnvironmentHandle(0));
    let closure = store.get(h).unwrap();
    assert_eq!(closure.max_capture_label, Label::Public);
}

#[test]
fn closure_store_get_invalid_handle_returns_none() {
    let store = ClosureStore::new();
    assert!(store.get(ClosureHandle(0)).is_none());
    assert!(store.get(ClosureHandle(999)).is_none());
}

#[test]
fn closure_store_multiple_closures() {
    let mut store = ClosureStore::new();
    let h0 = store.create_closure("a".into(), 0, false, vec![], EnvironmentHandle(0));
    let h1 = store.create_closure("b".into(), 1, true, vec![], EnvironmentHandle(1));
    let h2 = store.create_closure("c".into(), 2, false, vec![], EnvironmentHandle(2));
    assert_eq!(store.len(), 3);
    assert_eq!(store.get(h0).unwrap().name, "a");
    assert_eq!(store.get(h1).unwrap().name, "b");
    assert_eq!(store.get(h2).unwrap().name, "c");
}

// ---------------------------------------------------------------------------
// 18. BindingSlot constructors
// ---------------------------------------------------------------------------

#[test]
fn binding_slot_new_lexical_let() {
    let slot = BindingSlot::new_lexical("x".into(), 42, BindingKind::Let);
    assert_eq!(slot.name, "x");
    assert_eq!(slot.binding_id, 42);
    assert_eq!(slot.kind, BindingKind::Let);
    assert_eq!(slot.value, EnvValue::Tdz);
    assert!(!slot.initialized);
    assert!(slot.mutable);
    assert_eq!(slot.label, Label::Public);
}

#[test]
fn binding_slot_new_lexical_const() {
    let slot = BindingSlot::new_lexical("C".into(), 43, BindingKind::Const);
    assert!(!slot.mutable);
    assert!(!slot.initialized);
    assert_eq!(slot.value, EnvValue::Tdz);
}

#[test]
fn binding_slot_new_hoisted() {
    let slot = BindingSlot::new_hoisted("v".into(), 44, BindingKind::Var);
    assert_eq!(slot.value, EnvValue::Undefined);
    assert!(slot.initialized);
    assert!(slot.mutable);
}

#[test]
fn binding_slot_new_parameter() {
    let slot = BindingSlot::new_parameter("p".into(), 45, EnvValue::Number(5), Label::Confidential);
    assert_eq!(slot.kind, BindingKind::Parameter);
    assert!(slot.initialized);
    assert!(slot.mutable);
    assert_eq!(slot.value, EnvValue::Number(5));
    assert_eq!(slot.label, Label::Confidential);
}

// ---------------------------------------------------------------------------
// 19. EnvironmentRecord
// ---------------------------------------------------------------------------

#[test]
fn environment_record_new_is_empty() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Global,
        EnvironmentKind::Global,
    );
    assert!(env.bindings.is_empty());
    assert_eq!(env.this_binding, None);
    assert_eq!(env.arguments_handle, None);
    assert_eq!(env.max_label, Label::Public);
}

#[test]
fn environment_record_add_and_get_binding() {
    let mut env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Global,
        EnvironmentKind::Global,
    );
    let slot = BindingSlot::new_hoisted("x".into(), 1, BindingKind::Var);
    env.add_binding(slot);
    assert!(env.get_binding("x").is_some());
    assert!(env.get_binding("y").is_none());
}

#[test]
fn environment_record_is_var_scope_classification() {
    let cases = [
        (ScopeKind::Global, true),
        (ScopeKind::Module, true),
        (ScopeKind::Function, true),
        (ScopeKind::Block, false),
        (ScopeKind::Catch, false),
    ];
    for (kind, expected) in cases {
        let env = EnvironmentRecord::new(
            EnvironmentHandle(0),
            sid(0, 0),
            kind,
            EnvironmentKind::Declarative,
        );
        assert_eq!(env.is_var_scope(), expected, "ScopeKind::{kind:?}");
    }
}

// ---------------------------------------------------------------------------
// 20. EnvValue Display
// ---------------------------------------------------------------------------

#[test]
fn env_value_display_undefined() {
    assert_eq!(EnvValue::Undefined.to_string(), "undefined");
}

#[test]
fn env_value_display_null() {
    assert_eq!(EnvValue::Null.to_string(), "null");
}

#[test]
fn env_value_display_bool() {
    assert_eq!(EnvValue::Bool(true).to_string(), "true");
    assert_eq!(EnvValue::Bool(false).to_string(), "false");
}

#[test]
fn env_value_display_number() {
    assert_eq!(EnvValue::Number(1_000_000).to_string(), "1000000");
    assert_eq!(EnvValue::Number(-42).to_string(), "-42");
    assert_eq!(EnvValue::Number(0).to_string(), "0");
}

#[test]
fn env_value_display_str() {
    assert_eq!(EnvValue::Str("hi".into()).to_string(), "\"hi\"");
    assert_eq!(EnvValue::Str(String::new()).to_string(), "\"\"");
}

#[test]
fn env_value_display_object_ref() {
    assert_eq!(EnvValue::ObjectRef(42).to_string(), "ObjectRef(42)");
}

#[test]
fn env_value_display_closure_ref() {
    assert_eq!(
        EnvValue::ClosureRef(ClosureHandle(7)).to_string(),
        "ClosureRef(7)"
    );
}

#[test]
fn env_value_display_tdz() {
    assert_eq!(EnvValue::Tdz.to_string(), "<TDZ>");
}

// ---------------------------------------------------------------------------
// 21. ScopeError Display
// ---------------------------------------------------------------------------

#[test]
fn scope_error_display_temporal_dead_zone() {
    let err = ScopeError::TemporalDeadZone { name: "x".into() };
    let msg = err.to_string();
    assert!(msg.contains("ReferenceError"));
    assert!(msg.contains("before initialization"));
    assert!(msg.contains("'x'"));
}

#[test]
fn scope_error_display_const_assignment() {
    let err = ScopeError::ConstAssignment { name: "PI".into() };
    let msg = err.to_string();
    assert!(msg.contains("TypeError"));
    assert!(msg.contains("constant variable"));
    assert!(msg.contains("'PI'"));
}

#[test]
fn scope_error_display_undeclared_variable() {
    let err = ScopeError::UndeclaredVariable { name: "y".into() };
    let msg = err.to_string();
    assert!(msg.contains("ReferenceError"));
    assert!(msg.contains("not defined"));
    assert!(msg.contains("'y'"));
}

#[test]
fn scope_error_display_empty_scope_chain() {
    let err = ScopeError::EmptyScopeChain;
    assert!(err.to_string().contains("scope chain is empty"));
}

#[test]
fn scope_error_display_label_violation() {
    let err = ScopeError::LabelViolation {
        name: "token".into(),
        value_label: Label::Secret,
        scope_max: Label::Public,
    };
    let msg = err.to_string();
    assert!(msg.contains("IFCError"));
    assert!(msg.contains("'token'"));
}

#[test]
fn scope_error_display_duplicate_binding() {
    let err = ScopeError::DuplicateBinding { name: "z".into() };
    let msg = err.to_string();
    assert!(msg.contains("SyntaxError"));
    assert!(msg.contains("already been declared"));
    assert!(msg.contains("'z'"));
}

#[test]
fn scope_error_display_invalid_environment() {
    let err = ScopeError::InvalidEnvironment {
        handle: EnvironmentHandle(42),
    };
    let msg = err.to_string();
    assert!(msg.contains("InternalError"));
    assert!(msg.contains("42"));
}

// ---------------------------------------------------------------------------
// 22. Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn env_value_serde_roundtrip_all_variants() {
    let values = vec![
        EnvValue::Undefined,
        EnvValue::Null,
        EnvValue::Bool(true),
        EnvValue::Bool(false),
        EnvValue::Number(0),
        EnvValue::Number(i64::MAX),
        EnvValue::Number(i64::MIN),
        EnvValue::Str("hello".into()),
        EnvValue::Str(String::new()),
        EnvValue::ObjectRef(0),
        EnvValue::ObjectRef(u64::MAX),
        EnvValue::ClosureRef(ClosureHandle(0)),
        EnvValue::ClosureRef(ClosureHandle(u32::MAX)),
        EnvValue::Tdz,
    ];
    for val in &values {
        let json = serde_json::to_string(val).unwrap();
        let back: EnvValue = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, val, "serde roundtrip failed for {val:?}");
    }
}

#[test]
fn binding_slot_serde_roundtrip() {
    let slot = BindingSlot::new_lexical("x".into(), 42, BindingKind::Let);
    let json = serde_json::to_string(&slot).unwrap();
    let back: BindingSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, slot);
}

#[test]
fn closure_capture_serde_roundtrip() {
    let cap = ClosureCapture {
        name: "outer".into(),
        binding_id: 7,
        source_scope: sid(2, 3),
        label: Label::Confidential,
    };
    let json = serde_json::to_string(&cap).unwrap();
    let back: ClosureCapture = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cap);
}

#[test]
fn closure_serde_roundtrip() {
    let closure = Closure {
        handle: ClosureHandle(0),
        name: "test".into(),
        arity: 1,
        strict: true,
        captures: vec![ClosureCapture {
            name: "x".into(),
            binding_id: 1,
            source_scope: sid(0, 0),
            label: Label::Internal,
        }],
        max_capture_label: Label::Internal,
        creation_env: EnvironmentHandle(0),
    };
    let json = serde_json::to_string(&closure).unwrap();
    let back: Closure = serde_json::from_str(&json).unwrap();
    assert_eq!(back, closure);
}

#[test]
fn environment_kind_serde_roundtrip() {
    let kinds = [
        EnvironmentKind::Declarative,
        EnvironmentKind::Object,
        EnvironmentKind::Global,
        EnvironmentKind::Module,
        EnvironmentKind::Function,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: EnvironmentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, kind);
    }
}

#[test]
fn environment_record_serde_roundtrip() {
    let mut env = EnvironmentRecord::new(
        EnvironmentHandle(5),
        sid(1, 2),
        ScopeKind::Function,
        EnvironmentKind::Function,
    );
    env.add_binding(BindingSlot::new_hoisted("x".into(), 1, BindingKind::Var));
    env.this_binding = Some(EnvValue::ObjectRef(42));
    env.arguments_handle = Some(7);

    let json = serde_json::to_string(&env).unwrap();
    let back: EnvironmentRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, env);
}

#[test]
fn scope_error_serde_roundtrip_all_variants() {
    let errors = vec![
        ScopeError::TemporalDeadZone { name: "x".into() },
        ScopeError::ConstAssignment { name: "C".into() },
        ScopeError::UndeclaredVariable { name: "y".into() },
        ScopeError::EmptyScopeChain,
        ScopeError::LabelViolation {
            name: "t".into(),
            value_label: Label::Secret,
            scope_max: Label::Public,
        },
        ScopeError::DuplicateBinding { name: "z".into() },
        ScopeError::InvalidEnvironment {
            handle: EnvironmentHandle(99),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ScopeError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err, "serde roundtrip failed for {err:?}");
    }
}

#[test]
fn scope_chain_serde_roundtrip() {
    let mut chain = fresh_chain();
    chain.declare_var("x".into(), 1).unwrap();
    chain
        .set_value("x", EnvValue::Number(42), Label::Public)
        .unwrap();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.declare_let("y".into(), 2).unwrap();
    chain
        .initialize_binding("y", EnvValue::Str("hello".into()), Label::Internal)
        .unwrap();

    let json = serde_json::to_string(&chain).unwrap();
    let back: ScopeChain = serde_json::from_str(&json).unwrap();
    assert_eq!(back.depth(), chain.depth());
    assert_eq!(
        *back.get_value("x").unwrap(),
        *chain.get_value("x").unwrap()
    );
    assert_eq!(
        *back.get_value("y").unwrap(),
        *chain.get_value("y").unwrap()
    );
}

#[test]
fn closure_store_serde_roundtrip() {
    let mut store = ClosureStore::new();
    store.create_closure(
        "f".into(),
        2,
        true,
        vec![ClosureCapture {
            name: "a".into(),
            binding_id: 1,
            source_scope: sid(0, 0),
            label: Label::Public,
        }],
        EnvironmentHandle(0),
    );
    let json = serde_json::to_string(&store).unwrap();
    let back: ClosureStore = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back.get(ClosureHandle(0)).unwrap().name, "f");
}

#[test]
fn closure_handle_serde_roundtrip() {
    let h = ClosureHandle(42);
    let json = serde_json::to_string(&h).unwrap();
    let back: ClosureHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, h);
}

#[test]
fn environment_handle_serde_roundtrip() {
    let h = EnvironmentHandle(99);
    let json = serde_json::to_string(&h).unwrap();
    let back: EnvironmentHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, h);
}

// ---------------------------------------------------------------------------
// 23. Determinism — same inputs produce same outputs
// ---------------------------------------------------------------------------

#[test]
fn deterministic_scope_chain_construction() {
    let build = || {
        let mut chain = fresh_chain();
        chain.declare_var("x".into(), 1).unwrap();
        chain
            .set_value("x", EnvValue::Number(100), Label::Public)
            .unwrap();
        chain.push_scope(sid(1, 0), ScopeKind::Block);
        chain.declare_let("y".into(), 2).unwrap();
        chain
            .initialize_binding("y", EnvValue::Number(200), Label::Internal)
            .unwrap();
        serde_json::to_string(&chain).unwrap()
    };
    let a = build();
    let b = build();
    assert_eq!(a, b);
}

#[test]
fn deterministic_closure_store_construction() {
    let build = || {
        let mut store = ClosureStore::new();
        let captures = vec![
            ClosureCapture {
                name: "a".into(),
                binding_id: 1,
                source_scope: sid(0, 0),
                label: Label::Public,
            },
            ClosureCapture {
                name: "b".into(),
                binding_id: 2,
                source_scope: sid(1, 0),
                label: Label::Secret,
            },
        ];
        store.create_closure("f".into(), 2, true, captures, EnvironmentHandle(0));
        serde_json::to_string(&store).unwrap()
    };
    let a = build();
    let b = build();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 24. Edge cases — boundary values and special inputs
// ---------------------------------------------------------------------------

#[test]
fn env_value_number_boundary_values() {
    let min = EnvValue::Number(i64::MIN);
    let max = EnvValue::Number(i64::MAX);
    let zero = EnvValue::Number(0);
    assert_ne!(min, max);
    assert_ne!(min, zero);
    assert_ne!(max, zero);

    // Serde roundtrip for boundary values.
    for val in &[min, max, zero] {
        let json = serde_json::to_string(val).unwrap();
        let back: EnvValue = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, val);
    }
}

#[test]
fn env_value_empty_string() {
    let val = EnvValue::Str(String::new());
    assert_eq!(val.to_string(), "\"\"");
    let json = serde_json::to_string(&val).unwrap();
    let back: EnvValue = serde_json::from_str(&json).unwrap();
    assert_eq!(back, val);
}

#[test]
fn closure_handle_ordering() {
    let a = ClosureHandle(0);
    let b = ClosureHandle(1);
    let c = ClosureHandle(u32::MAX);
    assert!(a < b);
    assert!(b < c);
}

#[test]
fn environment_handle_ordering() {
    let a = EnvironmentHandle(0);
    let b = EnvironmentHandle(1);
    assert!(a < b);
}

#[test]
fn deeply_nested_scope_chain() {
    let mut chain = fresh_chain();
    for i in 0..20u32 {
        chain.push_scope(sid(i + 1, 0), ScopeKind::Block);
    }
    assert_eq!(chain.depth(), 21);
    // Declare a var — should hoist to global.
    chain.declare_var("deep_var".into(), 1).unwrap();
    let global = chain.get_env(EnvironmentHandle(0)).unwrap();
    assert!(global.get_binding("deep_var").is_some());
    // Pop all nested scopes.
    for _ in 0..20 {
        chain.pop_scope().unwrap();
    }
    assert_eq!(chain.depth(), 1);
}

#[test]
fn unicode_binding_name() {
    let mut chain = fresh_chain();
    chain
        .declare_let("\u{03B1}\u{03B2}\u{03B3}".into(), 1)
        .unwrap();
    chain
        .initialize_binding(
            "\u{03B1}\u{03B2}\u{03B3}",
            EnvValue::Str("greek".into()),
            Label::Public,
        )
        .unwrap();
    assert_eq!(
        *chain.get_value("\u{03B1}\u{03B2}\u{03B3}").unwrap(),
        EnvValue::Str("greek".into())
    );
}

#[test]
fn closure_anonymous_name_empty_string() {
    let mut store = ClosureStore::new();
    let h = store.create_closure(String::new(), 0, false, vec![], EnvironmentHandle(0));
    let closure = store.get(h).unwrap();
    assert_eq!(closure.name, "");
}

// ---------------------------------------------------------------------------
// 25. Full closure creation workflow
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_closure_creation_workflow() {
    // Simulate:
    //   let x = 10;
    //   function add(y) { return x + y; }
    let mut chain = fresh_chain();
    let mut store = ClosureStore::new();

    // Global: declare and init x.
    chain.declare_let("x".into(), 1).unwrap();
    chain
        .initialize_binding("x", EnvValue::Number(10_000_000), Label::Public)
        .unwrap();

    // Create closure for add — captures x.
    let creation_env = chain.current_handle().unwrap();
    let captures = chain.compute_captures(&["x".into()]).unwrap();
    let closure_handle = store.create_closure("add".into(), 1, false, captures, creation_env);

    // Register the function declaration.
    chain
        .declare_function("add".into(), 2, EnvValue::ClosureRef(closure_handle))
        .unwrap();

    // Verify closure state.
    let closure = store.get(closure_handle).unwrap();
    assert_eq!(closure.name, "add");
    assert_eq!(closure.arity, 1);
    assert_eq!(closure.captures.len(), 1);
    assert_eq!(closure.captures[0].name, "x");
    assert_eq!(closure.max_capture_label, Label::Public);

    // Verify function is callable.
    assert_eq!(
        *chain.get_value("add").unwrap(),
        EnvValue::ClosureRef(closure_handle)
    );
}

#[test]
fn end_to_end_nested_closure_with_ifc() {
    // Simulate:
    //   let secret = "key";  // Label::Secret
    //   function outer() {
    //     let middle = 42;   // Label::Internal
    //     function inner() { return secret + middle; }
    //   }
    let mut chain = fresh_chain();
    let mut store = ClosureStore::new();

    chain.declare_let("secret".into(), 1).unwrap();
    chain
        .initialize_binding("secret", EnvValue::Str("key".into()), Label::Secret)
        .unwrap();

    // Enter outer function scope.
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.declare_let("middle".into(), 2).unwrap();
    chain
        .initialize_binding("middle", EnvValue::Number(42_000_000), Label::Internal)
        .unwrap();

    // Create inner closure.
    chain.push_scope(sid(2, 0), ScopeKind::Function);
    let captures = chain
        .compute_captures(&["secret".into(), "middle".into()])
        .unwrap();
    let creation_env = chain.current_handle().unwrap();
    let h = store.create_closure("inner".into(), 0, true, captures, creation_env);

    let closure = store.get(h).unwrap();
    assert_eq!(closure.captures.len(), 2);
    assert_eq!(closure.captures[0].label, Label::Secret);
    assert_eq!(closure.captures[1].label, Label::Internal);
    // Max capture label should be Secret (highest).
    assert_eq!(closure.max_capture_label, Label::Secret);
    assert!(closure.strict);
}

// ---------------------------------------------------------------------------
// 26. EnvironmentKind coverage
// ---------------------------------------------------------------------------

#[test]
fn environment_kind_equality() {
    assert_eq!(EnvironmentKind::Declarative, EnvironmentKind::Declarative);
    assert_ne!(EnvironmentKind::Declarative, EnvironmentKind::Object);
    assert_ne!(EnvironmentKind::Global, EnvironmentKind::Module);
    assert_ne!(EnvironmentKind::Function, EnvironmentKind::Global);
}

// ---------------------------------------------------------------------------
// 27. Arguments handle on function env
// ---------------------------------------------------------------------------

#[test]
fn function_env_arguments_handle() {
    let mut chain = fresh_chain();
    let fn_handle = chain.push_scope(sid(1, 0), ScopeKind::Function);
    let env = chain.get_env_mut(fn_handle).unwrap();
    assert_eq!(env.arguments_handle, None);
    env.arguments_handle = Some(123);
    let env = chain.get_env(fn_handle).unwrap();
    assert_eq!(env.arguments_handle, Some(123));
}
