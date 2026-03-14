#![forbid(unsafe_code)]

//! Enrichment integration tests for the closure_model module.

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

use std::collections::BTreeSet;

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

fn make_chain_with_binding() -> ScopeChain {
    let mut chain = ScopeChain::new();
    let _h = chain.push_scope(sid(0, 0), ScopeKind::Global);
    chain.declare_var("x".into(), 1).unwrap();
    chain
        .initialize_binding("x", EnvValue::Number(42), Label::Public)
        .unwrap();
    chain
}

// ---------------------------------------------------------------------------
// ClosureHandle — Copy / BTreeSet / Clone / Debug / Ord
// ---------------------------------------------------------------------------

#[test]
fn enrichment_closure_handle_copy_semantics() {
    let a = ClosureHandle(1);
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_closure_handle_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(ClosureHandle(0));
    set.insert(ClosureHandle(1));
    set.insert(ClosureHandle(2));
    set.insert(ClosureHandle(0));
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_closure_handle_clone_independence() {
    let a = ClosureHandle(99);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_closure_handle_debug_nonempty() {
    assert!(!format!("{:?}", ClosureHandle(0)).is_empty());
}

#[test]
fn enrichment_closure_handle_ord() {
    assert!(ClosureHandle(0) < ClosureHandle(1));
    assert!(ClosureHandle(5) > ClosureHandle(3));
    assert_eq!(
        ClosureHandle(7).cmp(&ClosureHandle(7)),
        std::cmp::Ordering::Equal
    );
}

#[test]
fn enrichment_closure_handle_serde_roundtrip() {
    let h = ClosureHandle(42);
    let json = serde_json::to_string(&h).unwrap();
    let rt: ClosureHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(h, rt);
}

// ---------------------------------------------------------------------------
// EnvironmentHandle — Copy / BTreeSet / Clone / Debug / Ord
// ---------------------------------------------------------------------------

#[test]
fn enrichment_environment_handle_copy_semantics() {
    let a = EnvironmentHandle(0);
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_environment_handle_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(EnvironmentHandle(0));
    set.insert(EnvironmentHandle(1));
    set.insert(EnvironmentHandle(2));
    set.insert(EnvironmentHandle(0));
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_environment_handle_clone_independence() {
    let a = EnvironmentHandle(10);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_environment_handle_debug_nonempty() {
    assert!(!format!("{:?}", EnvironmentHandle(0)).is_empty());
}

#[test]
fn enrichment_environment_handle_ord() {
    assert!(EnvironmentHandle(0) < EnvironmentHandle(1));
    assert!(EnvironmentHandle(5) > EnvironmentHandle(3));
}

#[test]
fn enrichment_environment_handle_serde_roundtrip() {
    let h = EnvironmentHandle(99);
    let json = serde_json::to_string(&h).unwrap();
    let rt: EnvironmentHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(h, rt);
}

// ---------------------------------------------------------------------------
// EnvValue — Clone / Debug / PartialEq
// ---------------------------------------------------------------------------

#[test]
fn enrichment_env_value_clone_independence() {
    let a = EnvValue::Str("hello".into());
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_env_value_debug_all_unique() {
    let values = [
        EnvValue::Undefined,
        EnvValue::Null,
        EnvValue::Bool(true),
        EnvValue::Number(0),
        EnvValue::Str("s".into()),
        EnvValue::ObjectRef(1),
        EnvValue::ClosureRef(ClosureHandle(1)),
        EnvValue::Tdz,
    ];
    let dbgs: BTreeSet<String> = values.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 8);
}

#[test]
fn enrichment_env_value_partial_eq_variants() {
    assert_ne!(EnvValue::Undefined, EnvValue::Null);
    assert_ne!(EnvValue::Null, EnvValue::Tdz);
    assert_ne!(EnvValue::Bool(true), EnvValue::Bool(false));
    assert_eq!(EnvValue::Number(42), EnvValue::Number(42));
    assert_ne!(EnvValue::Number(1), EnvValue::Number(2));
    assert_eq!(EnvValue::Str("a".into()), EnvValue::Str("a".into()));
    assert_ne!(EnvValue::ObjectRef(1), EnvValue::ObjectRef(2));
    assert_ne!(
        EnvValue::ClosureRef(ClosureHandle(0)),
        EnvValue::ClosureRef(ClosureHandle(1))
    );
}

// ---------------------------------------------------------------------------
// EnvironmentKind — Copy / BTreeSet / Clone / Debug / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_environment_kind_copy_semantics() {
    let a = EnvironmentKind::Declarative;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_environment_kind_all_5_unique() {
    let kinds = [
        EnvironmentKind::Declarative,
        EnvironmentKind::Object,
        EnvironmentKind::Global,
        EnvironmentKind::Module,
        EnvironmentKind::Function,
    ];
    // No Ord, so use HashSet-like dedup via Debug strings
    let strs: BTreeSet<String> = kinds.iter().map(|k| format!("{:?}", k)).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_environment_kind_clone_independence() {
    let a = EnvironmentKind::Module;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_environment_kind_debug_all_unique() {
    let kinds = [
        EnvironmentKind::Declarative,
        EnvironmentKind::Object,
        EnvironmentKind::Global,
        EnvironmentKind::Module,
        EnvironmentKind::Function,
    ];
    let dbgs: BTreeSet<String> = kinds.iter().map(|k| format!("{:?}", k)).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn enrichment_environment_kind_serde_roundtrip_all() {
    let kinds = [
        EnvironmentKind::Declarative,
        EnvironmentKind::Object,
        EnvironmentKind::Global,
        EnvironmentKind::Module,
        EnvironmentKind::Function,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let rt: EnvironmentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, rt);
    }
}

// ---------------------------------------------------------------------------
// ScopeError — Clone / Debug / Display unique / std::error::Error / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scope_error_clone_independence() {
    let a = ScopeError::TemporalDeadZone { name: "x".into() };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_scope_error_debug_all_unique() {
    let errors: Vec<ScopeError> = vec![
        ScopeError::TemporalDeadZone { name: "x".into() },
        ScopeError::ConstAssignment { name: "y".into() },
        ScopeError::UndeclaredVariable { name: "z".into() },
        ScopeError::EmptyScopeChain,
        ScopeError::LabelViolation {
            name: "s".into(),
            value_label: Label::Secret,
            scope_max: Label::Public,
        },
        ScopeError::DuplicateBinding { name: "d".into() },
        ScopeError::InvalidEnvironment {
            handle: EnvironmentHandle(99),
        },
    ];
    let dbgs: BTreeSet<String> = errors.iter().map(|e| format!("{:?}", e)).collect();
    assert_eq!(dbgs.len(), 7);
}

#[test]
fn enrichment_scope_error_display_all_unique() {
    let errors: Vec<ScopeError> = vec![
        ScopeError::TemporalDeadZone { name: "x".into() },
        ScopeError::ConstAssignment { name: "y".into() },
        ScopeError::UndeclaredVariable { name: "z".into() },
        ScopeError::EmptyScopeChain,
        ScopeError::LabelViolation {
            name: "s".into(),
            value_label: Label::Secret,
            scope_max: Label::Public,
        },
        ScopeError::DuplicateBinding { name: "d".into() },
        ScopeError::InvalidEnvironment {
            handle: EnvironmentHandle(99),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{}", e)).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_scope_error_display_all_nonempty() {
    let errors: Vec<ScopeError> = vec![
        ScopeError::TemporalDeadZone { name: "x".into() },
        ScopeError::ConstAssignment { name: "y".into() },
        ScopeError::UndeclaredVariable { name: "z".into() },
        ScopeError::EmptyScopeChain,
        ScopeError::LabelViolation {
            name: "s".into(),
            value_label: Label::Secret,
            scope_max: Label::Public,
        },
        ScopeError::DuplicateBinding { name: "d".into() },
        ScopeError::InvalidEnvironment {
            handle: EnvironmentHandle(99),
        },
    ];
    for e in &errors {
        assert!(!format!("{}", e).is_empty(), "empty display for: {:?}", e);
    }
}

// ---------------------------------------------------------------------------
// BindingSlot — Clone / Debug / constructors / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_binding_slot_clone_independence() {
    let a = BindingSlot::new_lexical("x".into(), 1, BindingKind::Let);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_binding_slot_debug_nonempty() {
    let s = BindingSlot::new_lexical("x".into(), 1, BindingKind::Let);
    assert!(!format!("{:?}", s).is_empty());
}

#[test]
fn enrichment_binding_slot_lexical_let_not_initialized() {
    let s = BindingSlot::new_lexical("x".into(), 1, BindingKind::Let);
    assert!(!s.initialized);
    assert!(s.mutable);
    assert_eq!(s.value, EnvValue::Tdz);
    assert_eq!(s.label, Label::Public);
}

#[test]
fn enrichment_binding_slot_lexical_const_not_mutable() {
    let s = BindingSlot::new_lexical("c".into(), 2, BindingKind::Const);
    assert!(!s.mutable);
    assert!(!s.initialized);
}

#[test]
fn enrichment_binding_slot_hoisted_initialized() {
    let s = BindingSlot::new_hoisted("v".into(), 3, BindingKind::Var);
    assert!(s.initialized);
    assert!(s.mutable);
    assert_eq!(s.value, EnvValue::Undefined);
}

#[test]
fn enrichment_binding_slot_parameter_has_value_and_label() {
    let s = BindingSlot::new_parameter("p".into(), 4, EnvValue::Number(10), Label::Confidential);
    assert!(s.initialized);
    assert!(s.mutable);
    assert_eq!(s.value, EnvValue::Number(10));
    assert_eq!(s.label, Label::Confidential);
}

#[test]
fn enrichment_binding_slot_serde_roundtrip() {
    let s = BindingSlot::new_parameter("p".into(), 4, EnvValue::Bool(true), Label::Internal);
    let json = serde_json::to_string(&s).unwrap();
    let rt: BindingSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

// ---------------------------------------------------------------------------
// EnvironmentRecord — Clone / Debug / add/get/get_mut / is_var_scope / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_environment_record_clone_independence() {
    let mut env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Global,
        EnvironmentKind::Global,
    );
    env.add_binding(BindingSlot::new_hoisted("x".into(), 1, BindingKind::Var));
    let env2 = env.clone();
    assert_eq!(env, env2);
}

#[test]
fn enrichment_environment_record_debug_nonempty() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Global,
        EnvironmentKind::Global,
    );
    assert!(!format!("{:?}", env).is_empty());
}

#[test]
fn enrichment_environment_record_get_binding_not_found() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Global,
        EnvironmentKind::Global,
    );
    assert!(env.get_binding("nonexistent").is_none());
}

#[test]
fn enrichment_environment_record_get_binding_mut_modify() {
    let mut env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Function,
        EnvironmentKind::Function,
    );
    env.add_binding(BindingSlot::new_hoisted("x".into(), 1, BindingKind::Var));
    let slot = env.get_binding_mut("x").unwrap();
    slot.value = EnvValue::Number(100);
    assert_eq!(env.get_binding("x").unwrap().value, EnvValue::Number(100));
}

#[test]
fn enrichment_environment_record_is_var_scope_function() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Function,
        EnvironmentKind::Function,
    );
    assert!(env.is_var_scope());
}

#[test]
fn enrichment_environment_record_is_var_scope_block() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Block,
        EnvironmentKind::Declarative,
    );
    assert!(!env.is_var_scope());
}

#[test]
fn enrichment_environment_record_this_binding_default_none() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Global,
        EnvironmentKind::Global,
    );
    assert!(env.this_binding.is_none());
}

#[test]
fn enrichment_environment_record_arguments_handle_default_none() {
    let env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Global,
        EnvironmentKind::Global,
    );
    assert!(env.arguments_handle.is_none());
}

#[test]
fn enrichment_environment_record_serde_roundtrip() {
    let mut env = EnvironmentRecord::new(
        EnvironmentHandle(0),
        sid(0, 0),
        ScopeKind::Function,
        EnvironmentKind::Function,
    );
    env.add_binding(BindingSlot::new_hoisted("y".into(), 5, BindingKind::Var));
    let json = serde_json::to_string(&env).unwrap();
    let rt: EnvironmentRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(env, rt);
}

// ---------------------------------------------------------------------------
// ClosureCapture — Clone / Debug / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_closure_capture_clone_independence() {
    let a = ClosureCapture {
        name: "outer".into(),
        binding_id: 1,
        source_scope: sid(0, 0),
        label: Label::Public,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_closure_capture_debug_nonempty() {
    let c = ClosureCapture {
        name: "cap".into(),
        binding_id: 2,
        source_scope: sid(1, 0),
        label: Label::Internal,
    };
    assert!(!format!("{:?}", c).is_empty());
}

#[test]
fn enrichment_closure_capture_serde_roundtrip() {
    let c = ClosureCapture {
        name: "cap".into(),
        binding_id: 3,
        source_scope: sid(2, 1),
        label: Label::Confidential,
    };
    let json = serde_json::to_string(&c).unwrap();
    let rt: ClosureCapture = serde_json::from_str(&json).unwrap();
    assert_eq!(c, rt);
}

// ---------------------------------------------------------------------------
// Closure — Clone / Debug / fields / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_closure_clone_independence() {
    let c = Closure {
        handle: ClosureHandle(0),
        name: "add".into(),
        arity: 2,
        strict: true,
        captures: vec![],
        max_capture_label: Label::Public,
        creation_env: EnvironmentHandle(0),
    };
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn enrichment_closure_debug_nonempty() {
    let c = Closure {
        handle: ClosureHandle(1),
        name: "fn".into(),
        arity: 0,
        strict: false,
        captures: vec![],
        max_capture_label: Label::Public,
        creation_env: EnvironmentHandle(0),
    };
    assert!(!format!("{:?}", c).is_empty());
}

#[test]
fn enrichment_closure_fields() {
    let c = Closure {
        handle: ClosureHandle(5),
        name: "myFn".into(),
        arity: 3,
        strict: true,
        captures: vec![ClosureCapture {
            name: "outer".into(),
            binding_id: 1,
            source_scope: sid(0, 0),
            label: Label::Secret,
        }],
        max_capture_label: Label::Secret,
        creation_env: EnvironmentHandle(10),
    };
    assert_eq!(c.handle, ClosureHandle(5));
    assert_eq!(c.name, "myFn");
    assert_eq!(c.arity, 3);
    assert!(c.strict);
    assert_eq!(c.captures.len(), 1);
    assert_eq!(c.max_capture_label, Label::Secret);
    assert_eq!(c.creation_env, EnvironmentHandle(10));
}

#[test]
fn enrichment_closure_serde_roundtrip() {
    let c = Closure {
        handle: ClosureHandle(0),
        name: "test".into(),
        arity: 1,
        strict: false,
        captures: vec![ClosureCapture {
            name: "x".into(),
            binding_id: 1,
            source_scope: sid(0, 0),
            label: Label::Internal,
        }],
        max_capture_label: Label::Internal,
        creation_env: EnvironmentHandle(0),
    };
    let json = serde_json::to_string(&c).unwrap();
    let rt: Closure = serde_json::from_str(&json).unwrap();
    assert_eq!(c, rt);
}

// ---------------------------------------------------------------------------
// ScopeChain — depth / push-pop / declare / get_value / set_value / errors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scope_chain_default_depth_1() {
    let chain = ScopeChain::new();
    assert_eq!(chain.depth(), 1); // global scope
}

#[test]
fn enrichment_scope_chain_push_increases_depth() {
    let mut chain = ScopeChain::new();
    assert_eq!(chain.depth(), 1);
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    assert_eq!(chain.depth(), 2);
    chain.push_scope(sid(2, 0), ScopeKind::Block);
    assert_eq!(chain.depth(), 3);
}

#[test]
fn enrichment_scope_chain_pop_decreases_depth() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    assert_eq!(chain.depth(), 2);
    chain.pop_scope().unwrap();
    assert_eq!(chain.depth(), 1);
}

#[test]
fn enrichment_scope_chain_current_handle_after_push() {
    let mut chain = ScopeChain::new();
    let h1 = chain.current_handle().unwrap();
    let h2 = chain.push_scope(sid(1, 0), ScopeKind::Function);
    let current = chain.current_handle().unwrap();
    assert_eq!(current, h2);
    assert_ne!(h1, h2);
}

#[test]
fn enrichment_scope_chain_get_env_returns_correct_record() {
    let mut chain = ScopeChain::new();
    let h = chain.current_handle().unwrap();
    let env = chain.get_env(h).unwrap();
    assert_eq!(env.env_kind, EnvironmentKind::Global);
}

#[test]
fn enrichment_scope_chain_get_env_mut_modifies() {
    let mut chain = ScopeChain::new();
    let h = chain.current_handle().unwrap();
    {
        let env = chain.get_env_mut(h).unwrap();
        env.this_binding = Some(EnvValue::Undefined);
    }
    assert_eq!(
        chain.get_env(h).unwrap().this_binding,
        Some(EnvValue::Undefined)
    );
}

#[test]
fn enrichment_scope_chain_declare_let_tdz() {
    let mut chain = ScopeChain::new();
    chain.declare_let("y".into(), 1).unwrap();
    let err = chain.get_value("y").unwrap_err();
    assert!(matches!(err, ScopeError::TemporalDeadZone { .. }));
}

#[test]
fn enrichment_scope_chain_declare_const_then_set_fails() {
    let mut chain = ScopeChain::new();
    chain.declare_const("C".into(), 1).unwrap();
    chain
        .initialize_binding("C", EnvValue::Number(1), Label::Public)
        .unwrap();
    let err = chain
        .set_value("C", EnvValue::Number(2), Label::Public)
        .unwrap_err();
    assert!(matches!(err, ScopeError::ConstAssignment { .. }));
}

#[test]
fn enrichment_scope_chain_declare_function_initialized() {
    let mut chain = ScopeChain::new();
    chain
        .declare_function("f".into(), 1, EnvValue::ClosureRef(ClosureHandle(0)))
        .unwrap();
    let val = chain.get_value("f").unwrap();
    assert_eq!(*val, EnvValue::ClosureRef(ClosureHandle(0)));
}

#[test]
fn enrichment_scope_chain_declare_parameter_with_label() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain
        .declare_parameter("p".into(), 1, EnvValue::Number(5), Label::Confidential)
        .unwrap();
    let val = chain.get_value("p").unwrap();
    assert_eq!(*val, EnvValue::Number(5));
}

#[test]
fn enrichment_scope_chain_set_value_updates() {
    let chain = make_chain_with_binding();
    assert_eq!(*chain.get_value("x").unwrap(), EnvValue::Number(42));
}

#[test]
fn enrichment_scope_chain_undeclared_variable_error() {
    let chain = ScopeChain::new();
    let err = chain.get_value("ghost").unwrap_err();
    assert!(matches!(err, ScopeError::UndeclaredVariable { .. }));
}

#[test]
fn enrichment_scope_chain_duplicate_let_binding_error() {
    let mut chain = ScopeChain::new();
    chain.declare_let("x".into(), 1).unwrap();
    let err = chain.declare_let("x".into(), 2).unwrap_err();
    assert!(matches!(err, ScopeError::DuplicateBinding { .. }));
}

#[test]
fn enrichment_scope_chain_resolve_binding_finds_scope() {
    let mut chain = ScopeChain::new();
    chain.declare_var("g".into(), 1).unwrap();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.declare_let("local".into(), 2).unwrap();
    let (_, scope) = chain.resolve_binding("g").unwrap();
    assert_eq!(scope, sid(0, 0));
    let (_, scope) = chain.resolve_binding("local").unwrap();
    assert_eq!(scope, sid(1, 0));
}

#[test]
fn enrichment_scope_chain_compute_captures_empty() {
    let chain = make_chain_with_binding();
    let captures = chain.compute_captures(&[]).unwrap();
    assert!(captures.is_empty());
}

#[test]
fn enrichment_scope_chain_compute_captures_finds_outer() {
    let mut chain = ScopeChain::new();
    chain.declare_var("outer".into(), 1).unwrap();
    chain
        .initialize_binding("outer", EnvValue::Number(1), Label::Public)
        .unwrap();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    let captures = chain.compute_captures(&["outer".into()]).unwrap();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].name, "outer");
}

#[test]
fn enrichment_scope_chain_compute_captures_missing_errors() {
    let chain = ScopeChain::new();
    let err = chain.compute_captures(&["missing".into()]).unwrap_err();
    assert!(matches!(err, ScopeError::UndeclaredVariable { .. }));
}

#[test]
fn enrichment_scope_chain_serde_roundtrip() {
    let chain = make_chain_with_binding();
    let json = serde_json::to_string(&chain).unwrap();
    let rt: ScopeChain = serde_json::from_str(&json).unwrap();
    // ScopeChain may not impl PartialEq — compare via serialized form
    let json2 = serde_json::to_string(&rt).unwrap();
    assert_eq!(json, json2);
}

// ---------------------------------------------------------------------------
// ClosureStore — create / get / len / is_empty / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_closure_store_new_is_empty() {
    let store = ClosureStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn enrichment_closure_store_default_is_empty() {
    let store = ClosureStore::default();
    assert!(store.is_empty());
}

#[test]
fn enrichment_closure_store_create_increments_len() {
    let mut store = ClosureStore::new();
    store.create_closure("f1".into(), 0, false, vec![], EnvironmentHandle(0));
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
    store.create_closure("f2".into(), 1, true, vec![], EnvironmentHandle(0));
    assert_eq!(store.len(), 2);
}

#[test]
fn enrichment_closure_store_get_returns_closure() {
    let mut store = ClosureStore::new();
    let h = store.create_closure("myFunc".into(), 2, true, vec![], EnvironmentHandle(0));
    let c = store.get(h).unwrap();
    assert_eq!(c.name, "myFunc");
    assert_eq!(c.arity, 2);
    assert!(c.strict);
}

#[test]
fn enrichment_closure_store_get_invalid_returns_none() {
    let store = ClosureStore::new();
    assert!(store.get(ClosureHandle(999)).is_none());
}

#[test]
fn enrichment_closure_store_captures_max_label() {
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
    let h = store.create_closure("fn".into(), 0, false, captures, EnvironmentHandle(0));
    let c = store.get(h).unwrap();
    assert_eq!(c.max_capture_label, Label::Secret);
}

#[test]
fn enrichment_closure_store_clone_independence() {
    let mut store = ClosureStore::new();
    store.create_closure("f".into(), 0, false, vec![], EnvironmentHandle(0));
    let store2 = store.clone();
    // ClosureStore may not impl PartialEq — compare via serialized form
    let j1 = serde_json::to_string(&store).unwrap();
    let j2 = serde_json::to_string(&store2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn enrichment_closure_store_serde_roundtrip() {
    let mut store = ClosureStore::new();
    store.create_closure("f1".into(), 1, true, vec![], EnvironmentHandle(0));
    store.create_closure("f2".into(), 0, false, vec![], EnvironmentHandle(0));
    let json = serde_json::to_string(&store).unwrap();
    let rt: ClosureStore = serde_json::from_str(&json).unwrap();
    let json2 = serde_json::to_string(&rt).unwrap();
    assert_eq!(json, json2);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_scope_chain() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&make_chain_with_binding()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "scope chain should be deterministic");
}

#[test]
fn enrichment_five_run_determinism_closure_store() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| {
            let mut store = ClosureStore::new();
            store.create_closure("f".into(), 1, true, vec![], EnvironmentHandle(0));
            serde_json::to_string(&store).unwrap()
        })
        .collect();
    assert_eq!(jsons.len(), 1, "closure store should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_global_scope_has_global_env_kind() {
    let chain = ScopeChain::new();
    let h = chain.current_handle().unwrap();
    let env = chain.get_env(h).unwrap();
    assert_eq!(env.env_kind, EnvironmentKind::Global);
    assert_eq!(env.scope_kind, ScopeKind::Global);
}

#[test]
fn enrichment_cross_cutting_pushed_function_scope_env_kind() {
    let mut chain = ScopeChain::new();
    let h = chain.push_scope(sid(1, 0), ScopeKind::Function);
    let env = chain.get_env(h).unwrap();
    assert_eq!(env.env_kind, EnvironmentKind::Function);
}

#[test]
fn enrichment_cross_cutting_pushed_module_scope_env_kind() {
    let mut chain = ScopeChain::new();
    let h = chain.push_scope(sid(1, 0), ScopeKind::Module);
    let env = chain.get_env(h).unwrap();
    assert_eq!(env.env_kind, EnvironmentKind::Module);
}

#[test]
fn enrichment_cross_cutting_pushed_block_scope_env_kind() {
    let mut chain = ScopeChain::new();
    let h = chain.push_scope(sid(1, 0), ScopeKind::Block);
    let env = chain.get_env(h).unwrap();
    assert_eq!(env.env_kind, EnvironmentKind::Declarative);
}

#[test]
fn enrichment_cross_cutting_var_hoists_to_function_scope() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Function);
    chain.push_scope(sid(2, 0), ScopeKind::Block);
    chain.declare_var("v".into(), 1).unwrap();
    // var should resolve at the function scope, not block scope
    let (_, scope) = chain.resolve_binding("v").unwrap();
    assert_ne!(scope, sid(2, 0), "var should not be in block scope");
}

#[test]
fn enrichment_cross_cutting_let_in_block_not_visible_after_pop() {
    let mut chain = ScopeChain::new();
    chain.push_scope(sid(1, 0), ScopeKind::Block);
    chain.declare_let("block_var".into(), 1).unwrap();
    chain
        .initialize_binding("block_var", EnvValue::Number(1), Label::Public)
        .unwrap();
    chain.pop_scope().unwrap();
    let err = chain.get_value("block_var").unwrap_err();
    assert!(matches!(err, ScopeError::UndeclaredVariable { .. }));
}

#[test]
fn enrichment_cross_cutting_closure_store_handles_monotonic() {
    let mut store = ClosureStore::new();
    let h1 = store.create_closure("f1".into(), 0, false, vec![], EnvironmentHandle(0));
    let h2 = store.create_closure("f2".into(), 0, false, vec![], EnvironmentHandle(0));
    let h3 = store.create_closure("f3".into(), 0, false, vec![], EnvironmentHandle(0));
    assert!(h1 < h2);
    assert!(h2 < h3);
}
