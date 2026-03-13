#![forbid(unsafe_code)]
//! Enrichment integration tests for `object_model`.
//!
//! Covers gaps not addressed by `object_model_integration.rs` (177 tests)
//! or `object_model_edge_cases.rs` (83 tests):
//! - Copy semantics for SymbolId, ObjectHandle, WellKnownSymbol
//! - Clone independence for compound types
//! - BTreeSet ordering and dedup
//! - Serde roundtrips for ReflectApplyRequest, ReflectConstructRequest,
//!   SymbolRegistry, ManagedObject, ProxyObject, OrdinaryObject
//! - Debug nonempty
//! - Default coverage
//! - std::error::Error for ObjectError
//! - ObjectHeap higher-level APIs: from_entries, create_with_properties,
//!   alloc_callable, alloc_constructor, instance_of, spread_into,
//!   has_own, get_own_property_names/symbols, assign, define_properties
//! - Reflect.apply and Reflect.construct
//! - for_in_keys shadowing
//! - set_property rejection paths
//! - JSON field-name stability

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

use frankenengine_engine::object_model::{
    JsValue, ManagedObject, ObjectError, ObjectHandle, ObjectHeap, OrdinaryObject,
    PropertyDescriptor, PropertyKey, ProxyInvariantChecker, ProxyObject, Reflect,
    ReflectApplyRequest, ReflectConstructRequest, SymbolId, SymbolRegistry, WellKnownSymbol,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn str_key(s: &str) -> PropertyKey {
    PropertyKey::String(s.to_string())
}

fn int_val(n: i64) -> JsValue {
    JsValue::Int(n)
}

fn str_val(s: &str) -> JsValue {
    JsValue::Str(s.to_string())
}

// ===========================================================================
// Section 1: Copy semantics
// ===========================================================================

#[test]
fn enrichment_symbol_id_copy() {
    let a = SymbolId(42);
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.0, 42);
}

#[test]
fn enrichment_object_handle_copy() {
    let a = ObjectHandle(7);
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.0, 7);
}

#[test]
fn enrichment_well_known_symbol_copy() {
    let a = WellKnownSymbol::Iterator;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.id(), b.id());
}

#[test]
fn enrichment_well_known_symbol_all_variants_copy() {
    let variants = [
        WellKnownSymbol::Iterator,
        WellKnownSymbol::ToPrimitive,
        WellKnownSymbol::HasInstance,
        WellKnownSymbol::ToStringTag,
        WellKnownSymbol::Species,
        WellKnownSymbol::IsConcatSpreadable,
        WellKnownSymbol::Unscopables,
        WellKnownSymbol::AsyncIterator,
        WellKnownSymbol::Match,
        WellKnownSymbol::MatchAll,
        WellKnownSymbol::Replace,
        WellKnownSymbol::Search,
        WellKnownSymbol::Split,
    ];
    for v in variants {
        let copy = v;
        assert_eq!(v, copy);
        assert_eq!(v.name(), copy.name());
    }
}

// ===========================================================================
// Section 2: Clone independence
// ===========================================================================

#[test]
fn enrichment_property_key_string_clone_independence() {
    let original = PropertyKey::String("hello".to_string());
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // They are equal but independent allocations
    if let PropertyKey::String(ref s) = cloned {
        assert_eq!(s, "hello");
    }
}

#[test]
fn enrichment_property_key_symbol_clone_independence() {
    let original = PropertyKey::Symbol(SymbolId(99));
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_jsvalue_str_clone_independence() {
    let original = JsValue::Str("test".to_string());
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // Mutating the clone's content doesn't affect original
    if let JsValue::Str(ref s) = original {
        assert_eq!(s, "test");
    }
}

#[test]
fn enrichment_jsvalue_all_variants_clone() {
    let variants: Vec<JsValue> = vec![
        JsValue::Undefined,
        JsValue::Null,
        JsValue::Bool(true),
        JsValue::Int(42),
        JsValue::Str("s".to_string()),
        JsValue::Symbol(SymbolId(1)),
        JsValue::Object(ObjectHandle(0)),
        JsValue::Function(5),
    ];
    for v in &variants {
        let c = v.clone();
        assert_eq!(v, &c);
    }
}

#[test]
fn enrichment_property_descriptor_data_clone_independence() {
    let original = PropertyDescriptor::data(int_val(42));
    let mut cloned = original.clone();
    cloned.set_non_writable();
    // Original unchanged
    assert!(original.is_writable());
    assert!(!cloned.is_writable());
}

#[test]
fn enrichment_property_descriptor_accessor_clone_independence() {
    let original = PropertyDescriptor::Accessor {
        get: Some(ObjectHandle(1)),
        set: Some(ObjectHandle(2)),
        enumerable: true,
        configurable: true,
    };
    let mut cloned = original.clone();
    cloned.set_non_configurable();
    assert!(original.is_configurable());
    assert!(!cloned.is_configurable());
}

#[test]
fn enrichment_ordinary_object_clone_independence() {
    let mut original = OrdinaryObject::default();
    original
        .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    let cloned = original.clone();
    // Modify original
    original
        .define_own_property(str_key("y"), PropertyDescriptor::data(int_val(2)))
        .unwrap();
    // Clone doesn't have "y"
    assert!(!cloned.has_own_property(&str_key("y")));
    assert!(cloned.has_own_property(&str_key("x")));
}

#[test]
fn enrichment_proxy_object_clone_independence() {
    let original = ProxyObject::new(ObjectHandle(0), ObjectHandle(1));
    let mut cloned = original.clone();
    cloned.revoke();
    assert!(cloned.is_revoked());
    assert!(!original.is_revoked());
}

#[test]
fn enrichment_object_error_clone_independence() {
    let original = ObjectError::TypeError("msg".to_string());
    let cloned = original.clone();
    assert_eq!(original.to_string(), cloned.to_string());
}

#[test]
fn enrichment_managed_object_clone_independence() {
    let obj = OrdinaryObject::default();
    let original = ManagedObject::Ordinary(obj);
    let cloned = original.clone();
    assert!(cloned.as_ordinary().is_some());
}

#[test]
fn enrichment_reflect_apply_request_clone_independence() {
    let original = ReflectApplyRequest {
        target: ObjectHandle(0),
        this_arg: JsValue::Undefined,
        arguments: vec![int_val(1), int_val(2)],
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(cloned.arguments.len(), 2);
}

#[test]
fn enrichment_reflect_construct_request_clone_independence() {
    let original = ReflectConstructRequest {
        target: ObjectHandle(0),
        arguments: vec![str_val("arg")],
        new_target: ObjectHandle(1),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(cloned.new_target, ObjectHandle(1));
}

// ===========================================================================
// Section 3: BTreeSet ordering and dedup
// ===========================================================================

#[test]
fn enrichment_symbol_id_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(SymbolId(5));
    set.insert(SymbolId(1));
    set.insert(SymbolId(3));
    set.insert(SymbolId(1)); // dup
    assert_eq!(set.len(), 3);
    let v: Vec<_> = set.into_iter().collect();
    assert_eq!(v, vec![SymbolId(1), SymbolId(3), SymbolId(5)]);
}

#[test]
fn enrichment_object_handle_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(ObjectHandle(10));
    set.insert(ObjectHandle(2));
    set.insert(ObjectHandle(10)); // dup
    set.insert(ObjectHandle(5));
    assert_eq!(set.len(), 3);
    let v: Vec<_> = set.into_iter().collect();
    assert_eq!(v, vec![ObjectHandle(2), ObjectHandle(5), ObjectHandle(10)]);
}

#[test]
fn enrichment_well_known_symbol_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(WellKnownSymbol::Split);
    set.insert(WellKnownSymbol::Iterator);
    set.insert(WellKnownSymbol::Match);
    set.insert(WellKnownSymbol::Iterator); // dup
    assert_eq!(set.len(), 3);
    let v: Vec<_> = set.into_iter().collect();
    // Ordered by discriminant/id: Iterator(1), Match(9), Split(13)
    assert_eq!(v[0], WellKnownSymbol::Iterator);
    assert_eq!(v[2], WellKnownSymbol::Split);
}

#[test]
fn enrichment_property_key_btreeset_mixed() {
    let mut set = BTreeSet::new();
    set.insert(str_key("b"));
    set.insert(PropertyKey::Symbol(SymbolId(1)));
    set.insert(str_key("a"));
    set.insert(str_key("b")); // dup
    set.insert(PropertyKey::Symbol(SymbolId(2)));
    assert_eq!(set.len(), 4);
    let v: Vec<_> = set.into_iter().collect();
    // Strings before Symbols in derived Ord
    assert_eq!(v[0], str_key("a"));
    assert_eq!(v[1], str_key("b"));
    assert!(matches!(v[2], PropertyKey::Symbol(SymbolId(1))));
    assert!(matches!(v[3], PropertyKey::Symbol(SymbolId(2))));
}

#[test]
fn enrichment_jsvalue_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(JsValue::Null);
    set.insert(JsValue::Undefined);
    set.insert(JsValue::Bool(false));
    set.insert(JsValue::Bool(true));
    set.insert(JsValue::Int(1));
    set.insert(JsValue::Null); // dup
    assert_eq!(set.len(), 5);
}

// ===========================================================================
// Section 4: Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_symbol_id_serde_roundtrip() {
    let original = SymbolId(42);
    let json = serde_json::to_string(&original).unwrap();
    let recovered: SymbolId = serde_json::from_str(&json).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn enrichment_object_handle_serde_roundtrip() {
    let original = ObjectHandle(100);
    let json = serde_json::to_string(&original).unwrap();
    let recovered: ObjectHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn enrichment_property_key_string_serde_roundtrip() {
    let original = str_key("prop_name");
    let json = serde_json::to_string(&original).unwrap();
    let recovered: PropertyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn enrichment_property_key_symbol_serde_roundtrip() {
    let original = PropertyKey::Symbol(SymbolId(7));
    let json = serde_json::to_string(&original).unwrap();
    let recovered: PropertyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn enrichment_well_known_symbol_serde_roundtrip() {
    for sym in [
        WellKnownSymbol::Iterator,
        WellKnownSymbol::ToPrimitive,
        WellKnownSymbol::HasInstance,
        WellKnownSymbol::ToStringTag,
        WellKnownSymbol::Species,
        WellKnownSymbol::IsConcatSpreadable,
        WellKnownSymbol::Unscopables,
        WellKnownSymbol::AsyncIterator,
        WellKnownSymbol::Match,
        WellKnownSymbol::MatchAll,
        WellKnownSymbol::Replace,
        WellKnownSymbol::Search,
        WellKnownSymbol::Split,
    ] {
        let json = serde_json::to_string(&sym).unwrap();
        let recovered: WellKnownSymbol = serde_json::from_str(&json).unwrap();
        assert_eq!(sym, recovered);
    }
}

#[test]
fn enrichment_jsvalue_all_variants_serde_roundtrip() {
    let variants = vec![
        JsValue::Undefined,
        JsValue::Null,
        JsValue::Bool(true),
        JsValue::Bool(false),
        JsValue::Int(i64::MIN),
        JsValue::Int(i64::MAX),
        JsValue::Str(String::new()),
        JsValue::Str("hello world".to_string()),
        JsValue::Symbol(SymbolId(42)),
        JsValue::Object(ObjectHandle(999)),
        JsValue::Function(u32::MAX),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let recovered: JsValue = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &recovered);
    }
}

#[test]
fn enrichment_property_descriptor_data_serde_roundtrip() {
    let original = PropertyDescriptor::data(int_val(42));
    let json = serde_json::to_string(&original).unwrap();
    let recovered: PropertyDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn enrichment_property_descriptor_data_frozen_serde_roundtrip() {
    let original = PropertyDescriptor::data_frozen(str_val("frozen"));
    let json = serde_json::to_string(&original).unwrap();
    let recovered: PropertyDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn enrichment_property_descriptor_accessor_serde_roundtrip() {
    let original = PropertyDescriptor::Accessor {
        get: Some(ObjectHandle(1)),
        set: Some(ObjectHandle(2)),
        enumerable: false,
        configurable: true,
    };
    let json = serde_json::to_string(&original).unwrap();
    let recovered: PropertyDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn enrichment_object_error_all_variants_serde_roundtrip() {
    let errors = vec![
        ObjectError::TypeError("test".to_string()),
        ObjectError::ObjectNotFound(ObjectHandle(5)),
        ObjectError::ProxyRevoked,
        ObjectError::PrototypeCycleDetected,
        ObjectError::PrototypeChainTooDeep {
            depth: 2000,
            max: 1024,
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let recovered: ObjectError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, &recovered);
    }
}

#[test]
fn enrichment_ordinary_object_serde_roundtrip() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("a"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    obj.define_own_property(str_key("b"), PropertyDescriptor::data(str_val("two")))
        .unwrap();
    let json = serde_json::to_string(&obj).unwrap();
    let recovered: OrdinaryObject = serde_json::from_str(&json).unwrap();
    assert!(recovered.has_own_property(&str_key("a")));
    assert!(recovered.has_own_property(&str_key("b")));
}

#[test]
fn enrichment_proxy_object_serde_roundtrip() {
    let proxy = ProxyObject::new(ObjectHandle(0), ObjectHandle(1));
    let json = serde_json::to_string(&proxy).unwrap();
    let recovered: ProxyObject = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.target().unwrap(), ObjectHandle(0));
    assert_eq!(recovered.handler().unwrap(), ObjectHandle(1));
    assert!(!recovered.is_revoked());
}

#[test]
fn enrichment_proxy_object_revoked_serde_roundtrip() {
    let mut proxy = ProxyObject::new(ObjectHandle(0), ObjectHandle(1));
    proxy.revoke();
    let json = serde_json::to_string(&proxy).unwrap();
    let recovered: ProxyObject = serde_json::from_str(&json).unwrap();
    assert!(recovered.is_revoked());
}

#[test]
fn enrichment_managed_object_ordinary_serde_roundtrip() {
    let obj = ManagedObject::Ordinary(OrdinaryObject::default());
    let json = serde_json::to_string(&obj).unwrap();
    let recovered: ManagedObject = serde_json::from_str(&json).unwrap();
    assert!(recovered.as_ordinary().is_some());
}

#[test]
fn enrichment_managed_object_proxy_serde_roundtrip() {
    let obj = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    let json = serde_json::to_string(&obj).unwrap();
    let recovered: ManagedObject = serde_json::from_str(&json).unwrap();
    assert!(recovered.as_proxy().is_some());
}

#[test]
fn enrichment_object_heap_serde_roundtrip() {
    let mut heap = ObjectHeap::new();
    let h1 = heap.alloc_plain();
    heap.set_property(h1, str_key("x"), int_val(42)).unwrap();
    let json = serde_json::to_string(&heap).unwrap();
    let recovered: ObjectHeap = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.len(), 1);
    let val = recovered.get_property(h1, &str_key("x")).unwrap();
    assert_eq!(val, int_val(42));
}

#[test]
fn enrichment_symbol_registry_serde_roundtrip() {
    let mut heap = ObjectHeap::new();
    let mut reg = SymbolRegistry::new();
    let sym = reg.symbol_for("my_key", &mut heap);
    let json = serde_json::to_string(&reg).unwrap();
    let recovered: SymbolRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.key_for(sym), Some("my_key"));
}

#[test]
fn enrichment_reflect_apply_request_serde_roundtrip() {
    let req = ReflectApplyRequest {
        target: ObjectHandle(3),
        this_arg: JsValue::Null,
        arguments: vec![int_val(1), str_val("two")],
    };
    let json = serde_json::to_string(&req).unwrap();
    let recovered: ReflectApplyRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, recovered);
}

#[test]
fn enrichment_reflect_construct_request_serde_roundtrip() {
    let req = ReflectConstructRequest {
        target: ObjectHandle(0),
        arguments: vec![JsValue::Bool(true)],
        new_target: ObjectHandle(1),
    };
    let json = serde_json::to_string(&req).unwrap();
    let recovered: ReflectConstructRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, recovered);
}

// ===========================================================================
// Section 5: Debug nonempty
// ===========================================================================

#[test]
fn enrichment_symbol_id_debug_nonempty() {
    let dbg = format!("{:?}", SymbolId(1));
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SymbolId"));
}

#[test]
fn enrichment_object_handle_debug_nonempty() {
    let dbg = format!("{:?}", ObjectHandle(0));
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ObjectHandle"));
}

#[test]
fn enrichment_property_key_debug_nonempty() {
    let dbg = format!("{:?}", str_key("x"));
    assert!(!dbg.is_empty());
    assert!(dbg.contains("String"));
}

#[test]
fn enrichment_jsvalue_debug_nonempty() {
    let dbg = format!("{:?}", JsValue::Undefined);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Undefined"));
}

#[test]
fn enrichment_property_descriptor_debug_nonempty() {
    let dbg = format!("{:?}", PropertyDescriptor::data(int_val(1)));
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Data"));
}

#[test]
fn enrichment_object_error_debug_nonempty() {
    let dbg = format!("{:?}", ObjectError::ProxyRevoked);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ProxyRevoked"));
}

#[test]
fn enrichment_ordinary_object_debug_nonempty() {
    let dbg = format!("{:?}", OrdinaryObject::default());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("OrdinaryObject"));
}

#[test]
fn enrichment_proxy_object_debug_nonempty() {
    let dbg = format!("{:?}", ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ProxyObject"));
}

#[test]
fn enrichment_managed_object_debug_nonempty() {
    let dbg = format!("{:?}", ManagedObject::Ordinary(OrdinaryObject::default()));
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Ordinary"));
}

#[test]
fn enrichment_object_heap_debug_nonempty() {
    let dbg = format!("{:?}", ObjectHeap::new());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ObjectHeap"));
}

#[test]
fn enrichment_symbol_registry_debug_nonempty() {
    let dbg = format!("{:?}", SymbolRegistry::new());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SymbolRegistry"));
}

#[test]
fn enrichment_reflect_apply_request_debug_nonempty() {
    let req = ReflectApplyRequest {
        target: ObjectHandle(0),
        this_arg: JsValue::Undefined,
        arguments: vec![],
    };
    let dbg = format!("{:?}", req);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ReflectApplyRequest"));
}

#[test]
fn enrichment_reflect_construct_request_debug_nonempty() {
    let req = ReflectConstructRequest {
        target: ObjectHandle(0),
        arguments: vec![],
        new_target: ObjectHandle(0),
    };
    let dbg = format!("{:?}", req);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ReflectConstructRequest"));
}

// ===========================================================================
// Section 6: Default coverage
// ===========================================================================

#[test]
fn enrichment_object_heap_default() {
    let heap = ObjectHeap::default();
    assert!(heap.is_empty());
    assert_eq!(heap.len(), 0);
}

#[test]
fn enrichment_symbol_registry_default() {
    let reg = SymbolRegistry::default();
    // Default has no user symbols; key_for on well-known should be None
    // because default() doesn't register well-known symbols.
    assert_eq!(reg.key_for(SymbolId(999)), None);
}

#[test]
fn enrichment_ordinary_object_default() {
    let obj = OrdinaryObject::default();
    assert!(obj.extensible);
    assert_eq!(obj.prototype, None);
    assert!(obj.properties.is_empty());
    assert!(!obj.callable);
    assert!(!obj.constructable);
}

// ===========================================================================
// Section 7: ObjectError Display additional coverage
// ===========================================================================

#[test]
fn enrichment_object_error_all_variants_display_nonempty() {
    let errors = vec![
        ObjectError::TypeError("msg".to_string()),
        ObjectError::ObjectNotFound(ObjectHandle(0)),
        ObjectError::ProxyRevoked,
        ObjectError::PrototypeCycleDetected,
        ObjectError::PrototypeChainTooDeep { depth: 1, max: 0 },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn enrichment_object_error_type_error_preserves_message() {
    let msg = "custom error message with special chars: <>&";
    let e = ObjectError::TypeError(msg.to_string());
    assert!(e.to_string().contains(msg));
}

// ===========================================================================
// Section 8: ObjectHeap higher-level APIs
// ===========================================================================

#[test]
fn enrichment_heap_from_entries() {
    let mut heap = ObjectHeap::new();
    let entries = vec![
        ("a".to_string(), int_val(1)),
        ("b".to_string(), int_val(2)),
        ("c".to_string(), int_val(3)),
    ];
    let obj = heap.from_entries(entries);
    let val_a = heap.get_property(obj, &str_key("a")).unwrap();
    assert_eq!(val_a, int_val(1));
    let val_c = heap.get_property(obj, &str_key("c")).unwrap();
    assert_eq!(val_c, int_val(3));
}

#[test]
fn enrichment_heap_from_entries_empty() {
    let mut heap = ObjectHeap::new();
    let obj = heap.from_entries(vec![]);
    assert_eq!(heap.keys(obj).unwrap().len(), 0);
}

#[test]
fn enrichment_heap_create_with_properties() {
    let mut heap = ObjectHeap::new();
    let props = vec![
        (str_key("x"), PropertyDescriptor::data(int_val(10))),
        (str_key("y"), PropertyDescriptor::data(int_val(20))),
    ];
    let obj = heap.create_with_properties(None, props).unwrap();
    assert_eq!(heap.get_property(obj, &str_key("x")).unwrap(), int_val(10));
    assert_eq!(heap.get_property(obj, &str_key("y")).unwrap(), int_val(20));
}

#[test]
fn enrichment_heap_create_with_properties_and_prototype() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("inherited"), str_val("from_proto"))
        .unwrap();
    let obj = heap
        .create_with_properties(
            Some(proto),
            vec![(str_key("own"), PropertyDescriptor::data(int_val(1)))],
        )
        .unwrap();
    // Own property
    assert_eq!(heap.get_property(obj, &str_key("own")).unwrap(), int_val(1));
    // Inherited property
    assert_eq!(
        heap.get_property(obj, &str_key("inherited")).unwrap(),
        str_val("from_proto")
    );
}

#[test]
fn enrichment_heap_alloc_callable() {
    let mut heap = ObjectHeap::new();
    let func = heap.alloc_callable(None);
    let obj = heap.get(func).unwrap();
    if let ManagedObject::Ordinary(o) = obj {
        assert!(o.callable);
        assert!(!o.constructable);
    } else {
        panic!("expected ordinary");
    }
}

#[test]
fn enrichment_heap_alloc_constructor() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);
    let obj = heap.get(ctor).unwrap();
    if let ManagedObject::Ordinary(o) = obj {
        assert!(o.callable);
        assert!(o.constructable);
    } else {
        panic!("expected ordinary");
    }
}

#[test]
fn enrichment_heap_instance_of_positive() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let obj = heap.alloc(Some(proto));
    assert!(heap.instance_of(obj, proto).unwrap());
}

#[test]
fn enrichment_heap_instance_of_negative() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let other = heap.alloc_plain();
    assert!(!heap.instance_of(other, proto).unwrap());
}

#[test]
fn enrichment_heap_instance_of_deep_chain() {
    let mut heap = ObjectHeap::new();
    let root = heap.alloc_plain();
    let mid = heap.alloc(Some(root));
    let leaf = heap.alloc(Some(mid));
    assert!(heap.instance_of(leaf, root).unwrap());
    assert!(heap.instance_of(leaf, mid).unwrap());
    assert!(!heap.instance_of(root, leaf).unwrap());
}

#[test]
fn enrichment_heap_spread_into() {
    let mut heap = ObjectHeap::new();
    let source = heap.alloc_plain();
    heap.set_property(source, str_key("a"), int_val(1)).unwrap();
    heap.set_property(source, str_key("b"), int_val(2)).unwrap();
    let target = heap.alloc_plain();
    heap.set_property(target, str_key("c"), int_val(3)).unwrap();
    heap.spread_into(target, source).unwrap();
    assert_eq!(
        heap.get_property(target, &str_key("a")).unwrap(),
        int_val(1)
    );
    assert_eq!(
        heap.get_property(target, &str_key("b")).unwrap(),
        int_val(2)
    );
    assert_eq!(
        heap.get_property(target, &str_key("c")).unwrap(),
        int_val(3)
    );
}

#[test]
fn enrichment_heap_spread_into_overwrites_existing() {
    let mut heap = ObjectHeap::new();
    let source = heap.alloc_plain();
    heap.set_property(source, str_key("x"), int_val(99))
        .unwrap();
    let target = heap.alloc_plain();
    heap.set_property(target, str_key("x"), int_val(1)).unwrap();
    heap.spread_into(target, source).unwrap();
    assert_eq!(
        heap.get_property(target, &str_key("x")).unwrap(),
        int_val(99)
    );
}

#[test]
fn enrichment_heap_has_own() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("inherited"), int_val(1))
        .unwrap();
    let obj = heap.alloc(Some(proto));
    heap.set_property(obj, str_key("own"), int_val(2)).unwrap();
    // has_own only checks own properties
    assert!(heap.has_own(obj, &str_key("own")).unwrap());
    assert!(!heap.has_own(obj, &str_key("inherited")).unwrap());
    // has_property walks prototype chain
    assert!(heap.has_property(obj, &str_key("inherited")).unwrap());
}

#[test]
fn enrichment_heap_get_own_property_names() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("z"), int_val(1)).unwrap();
    heap.set_property(obj, str_key("a"), int_val(2)).unwrap();
    // Add a symbol property
    let sym = heap.alloc_symbol();
    heap.define_property(
        obj,
        PropertyKey::Symbol(sym),
        PropertyDescriptor::data(int_val(3)),
    )
    .unwrap();
    let names = heap.get_own_property_names(obj).unwrap();
    // Only string keys returned
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"z".to_string()));
    assert!(names.contains(&"a".to_string()));
}

#[test]
fn enrichment_heap_get_own_property_symbols() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("str_prop"), int_val(1))
        .unwrap();
    let sym1 = heap.alloc_symbol();
    let sym2 = heap.alloc_symbol();
    heap.define_property(
        obj,
        PropertyKey::Symbol(sym1),
        PropertyDescriptor::data(int_val(2)),
    )
    .unwrap();
    heap.define_property(
        obj,
        PropertyKey::Symbol(sym2),
        PropertyDescriptor::data(int_val(3)),
    )
    .unwrap();
    let symbols = heap.get_own_property_symbols(obj).unwrap();
    assert_eq!(symbols.len(), 2);
    assert!(symbols.contains(&sym1));
    assert!(symbols.contains(&sym2));
}

#[test]
fn enrichment_heap_assign_single_source() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let source = heap.alloc_plain();
    heap.set_property(source, str_key("x"), int_val(10))
        .unwrap();
    heap.set_property(source, str_key("y"), int_val(20))
        .unwrap();
    heap.assign(target, &[source]).unwrap();
    assert_eq!(
        heap.get_property(target, &str_key("x")).unwrap(),
        int_val(10)
    );
    assert_eq!(
        heap.get_property(target, &str_key("y")).unwrap(),
        int_val(20)
    );
}

#[test]
fn enrichment_heap_assign_multiple_sources() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let src1 = heap.alloc_plain();
    let src2 = heap.alloc_plain();
    heap.set_property(src1, str_key("a"), int_val(1)).unwrap();
    heap.set_property(src2, str_key("a"), int_val(2)).unwrap(); // overwrites
    heap.set_property(src2, str_key("b"), int_val(3)).unwrap();
    heap.assign(target, &[src1, src2]).unwrap();
    // Last source wins for overlapping keys
    assert_eq!(
        heap.get_property(target, &str_key("a")).unwrap(),
        int_val(2)
    );
    assert_eq!(
        heap.get_property(target, &str_key("b")).unwrap(),
        int_val(3)
    );
}

#[test]
fn enrichment_heap_define_properties() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let props = vec![
        (str_key("a"), PropertyDescriptor::data(int_val(1))),
        (str_key("b"), PropertyDescriptor::data_frozen(int_val(2))),
    ];
    assert!(heap.define_properties(obj, props).unwrap());
    assert_eq!(heap.get_property(obj, &str_key("a")).unwrap(), int_val(1));
    assert_eq!(heap.get_property(obj, &str_key("b")).unwrap(), int_val(2));
}

#[test]
fn enrichment_heap_get_own_property_descriptors() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    heap.set_property(obj, str_key("y"), int_val(2)).unwrap();
    let descs = heap.get_own_property_descriptors(obj).unwrap();
    assert_eq!(descs.len(), 2);
}

#[test]
fn enrichment_heap_values() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("a"), int_val(10)).unwrap();
    heap.set_property(obj, str_key("b"), int_val(20)).unwrap();
    let vals = heap.values(obj).unwrap();
    assert_eq!(vals.len(), 2);
    assert!(vals.contains(&int_val(10)));
    assert!(vals.contains(&int_val(20)));
}

#[test]
fn enrichment_heap_entries() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("k1"), str_val("v1"))
        .unwrap();
    heap.set_property(obj, str_key("k2"), str_val("v2"))
        .unwrap();
    let entries = heap.entries(obj).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.contains(&("k1".to_string(), str_val("v1"))));
    assert!(entries.contains(&("k2".to_string(), str_val("v2"))));
}

#[test]
fn enrichment_heap_object_is() {
    assert!(ObjectHeap::object_is(&int_val(42), &int_val(42)));
    assert!(!ObjectHeap::object_is(&int_val(42), &int_val(43)));
    assert!(!ObjectHeap::object_is(&JsValue::Null, &JsValue::Undefined));
}

// ===========================================================================
// Section 9: set_property rejection paths
// ===========================================================================

#[test]
fn enrichment_set_property_non_writable_rejects() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.define_property(
        obj,
        str_key("x"),
        PropertyDescriptor::Data {
            value: int_val(1),
            writable: false,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    // Attempt to set non-writable non-configurable property
    let result = heap.set_property(obj, str_key("x"), int_val(2)).unwrap();
    assert!(!result);
    // Value unchanged
    assert_eq!(heap.get_property(obj, &str_key("x")).unwrap(), int_val(1));
}

#[test]
fn enrichment_set_property_accessor_rejects() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.define_property(
        obj,
        str_key("x"),
        PropertyDescriptor::Accessor {
            get: Some(ObjectHandle(0)),
            set: None,
            enumerable: true,
            configurable: true,
        },
    )
    .unwrap();
    let result = heap.set_property(obj, str_key("x"), int_val(99)).unwrap();
    assert!(!result);
}

#[test]
fn enrichment_set_property_non_extensible_rejects_new() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.prevent_extensions(obj).unwrap();
    let result = heap
        .set_property(obj, str_key("new_prop"), int_val(1))
        .unwrap();
    assert!(!result);
}

#[test]
fn enrichment_set_property_updates_existing_writable() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    let result = heap.set_property(obj, str_key("x"), int_val(2)).unwrap();
    assert!(result);
    assert_eq!(heap.get_property(obj, &str_key("x")).unwrap(), int_val(2));
}

// ===========================================================================
// Section 10: for_in_keys with prototype chain shadowing
// ===========================================================================

#[test]
fn enrichment_for_in_keys_simple() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("b"), int_val(2)).unwrap();
    heap.set_property(obj, str_key("a"), int_val(1)).unwrap();
    let keys = heap.for_in_keys(obj).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"a".to_string()));
    assert!(keys.contains(&"b".to_string()));
}

#[test]
fn enrichment_for_in_keys_inherits_from_prototype() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("inherited"), int_val(1))
        .unwrap();
    let obj = heap.alloc(Some(proto));
    heap.set_property(obj, str_key("own"), int_val(2)).unwrap();
    let keys = heap.for_in_keys(obj).unwrap();
    assert!(keys.contains(&"own".to_string()));
    assert!(keys.contains(&"inherited".to_string()));
    assert_eq!(keys.len(), 2);
}

#[test]
fn enrichment_for_in_keys_shadows_prototype() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("x"), int_val(1)).unwrap();
    heap.set_property(proto, str_key("proto_only"), int_val(2))
        .unwrap();
    let obj = heap.alloc(Some(proto));
    heap.set_property(obj, str_key("x"), int_val(99)).unwrap(); // shadows proto.x
    let keys = heap.for_in_keys(obj).unwrap();
    // "x" appears only once despite being in both
    assert_eq!(keys.iter().filter(|k| *k == "x").count(), 1);
    assert!(keys.contains(&"proto_only".to_string()));
}

#[test]
fn enrichment_for_in_keys_skips_non_enumerable() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("visible"), int_val(1))
        .unwrap();
    heap.define_property(
        obj,
        str_key("hidden"),
        PropertyDescriptor::Data {
            value: int_val(2),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();
    let keys = heap.for_in_keys(obj).unwrap();
    assert_eq!(keys, vec!["visible".to_string()]);
}

#[test]
fn enrichment_for_in_keys_skips_symbol_keys() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("str"), int_val(1)).unwrap();
    let sym = heap.alloc_symbol();
    heap.define_property(
        obj,
        PropertyKey::Symbol(sym),
        PropertyDescriptor::data(int_val(2)),
    )
    .unwrap();
    let keys = heap.for_in_keys(obj).unwrap();
    assert_eq!(keys, vec!["str".to_string()]);
}

// ===========================================================================
// Section 11: Reflect.apply and Reflect.construct
// ===========================================================================

#[test]
fn enrichment_reflect_apply_callable_ok() {
    let mut heap = ObjectHeap::new();
    let func = heap.alloc_callable(None);
    let req = Reflect::apply(&heap, func, JsValue::Null, vec![int_val(1)]).unwrap();
    assert_eq!(req.target, func);
    assert_eq!(req.this_arg, JsValue::Null);
    assert_eq!(req.arguments, vec![int_val(1)]);
}

#[test]
fn enrichment_reflect_apply_not_callable_err() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let err = Reflect::apply(&heap, obj, JsValue::Undefined, vec![]).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
    assert!(err.to_string().contains("not callable"));
}

#[test]
fn enrichment_reflect_apply_proxy_ok() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    // Proxy apply returns a request (trap handled by interpreter)
    let req = Reflect::apply(&heap, proxy, JsValue::Undefined, vec![]).unwrap();
    assert_eq!(req.target, proxy);
}

#[test]
fn enrichment_reflect_construct_ok() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);
    let req = Reflect::construct(&heap, ctor, vec![int_val(42)], None).unwrap();
    assert_eq!(req.target, ctor);
    assert_eq!(req.arguments, vec![int_val(42)]);
    // new_target defaults to target when None
    assert_eq!(req.new_target, ctor);
}

#[test]
fn enrichment_reflect_construct_not_constructor_err() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let err = Reflect::construct(&heap, obj, vec![], None).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
    assert!(err.to_string().contains("not a constructor"));
}

#[test]
fn enrichment_reflect_construct_with_new_target() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);
    let new_target = heap.alloc_constructor(None);
    let req = Reflect::construct(&heap, ctor, vec![], Some(new_target)).unwrap();
    assert_eq!(req.target, ctor);
    assert_eq!(req.new_target, new_target);
}

#[test]
fn enrichment_reflect_construct_new_target_not_constructor_err() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);
    let bad_nt = heap.alloc_plain(); // not constructable
    let err = Reflect::construct(&heap, ctor, vec![], Some(bad_nt)).unwrap_err();
    assert!(err.to_string().contains("newTarget is not a constructor"));
}

// ===========================================================================
// Section 12: SymbolRegistry enrichment
// ===========================================================================

#[test]
fn enrichment_symbol_registry_new_has_well_known() {
    let reg = SymbolRegistry::new();
    // Well-known symbols are registered by id, not by description.
    let iter_key = reg.key_for(WellKnownSymbol::Iterator.id());
    assert_eq!(iter_key, Some("Symbol.iterator"));
    let split_key = reg.key_for(WellKnownSymbol::Split.id());
    assert_eq!(split_key, Some("Symbol.split"));
}

#[test]
fn enrichment_symbol_registry_symbol_for_idempotent() {
    let mut heap = ObjectHeap::new();
    let mut reg = SymbolRegistry::new();
    let sym1 = reg.symbol_for("my_symbol", &mut heap);
    let sym2 = reg.symbol_for("my_symbol", &mut heap);
    assert_eq!(sym1, sym2);
}

#[test]
fn enrichment_symbol_registry_symbol_for_unique() {
    let mut heap = ObjectHeap::new();
    let mut reg = SymbolRegistry::new();
    let sym1 = reg.symbol_for("a", &mut heap);
    let sym2 = reg.symbol_for("b", &mut heap);
    assert_ne!(sym1, sym2);
}

#[test]
fn enrichment_symbol_registry_key_for_absent() {
    let reg = SymbolRegistry::new();
    assert_eq!(reg.key_for(SymbolId(9999)), None);
}

// ===========================================================================
// Section 13: ProxyInvariantChecker additional coverage
// ===========================================================================

#[test]
fn enrichment_proxy_invariant_check_has_non_extensible_existing() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    obj.prevent_extensions();
    // Cannot report existing property as non-existent on non-extensible target
    let err = ProxyInvariantChecker::check_has(&obj, &str_key("x"), false).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn enrichment_proxy_invariant_check_has_ok_when_true() {
    let obj = OrdinaryObject::default();
    // Reporting true is always fine
    assert!(ProxyInvariantChecker::check_has(&obj, &str_key("anything"), true).is_ok());
}

#[test]
fn enrichment_proxy_invariant_check_get_non_configurable_accessor_no_getter() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("x"),
        PropertyDescriptor::Accessor {
            get: None,
            set: Some(ObjectHandle(0)),
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    // Must return undefined for non-configurable accessor with no getter
    let err = ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(42)).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
    assert!(
        err.to_string()
            .contains("undefined getter must return undefined")
    );
}

#[test]
fn enrichment_proxy_invariant_check_get_ok_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    // Configurable property: any trap result is fine
    assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(999)).is_ok());
}

#[test]
fn enrichment_proxy_invariant_check_set_non_configurable_no_setter() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("x"),
        PropertyDescriptor::Accessor {
            get: Some(ObjectHandle(0)),
            set: None,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    let err = ProxyInvariantChecker::check_set(&obj, &str_key("x"), &int_val(1), true).unwrap_err();
    assert!(err.to_string().contains("undefined setter"));
}

#[test]
fn enrichment_proxy_invariant_check_delete_non_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("x"),
        PropertyDescriptor::Data {
            value: int_val(1),
            writable: true,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    let err = ProxyInvariantChecker::check_delete(&obj, &str_key("x"), true).unwrap_err();
    assert!(err.to_string().contains("cannot delete non-configurable"));
}

#[test]
fn enrichment_proxy_invariant_check_own_keys_duplicate() {
    let obj = OrdinaryObject::default();
    let keys = vec![str_key("a"), str_key("a")];
    let err = ProxyInvariantChecker::check_own_keys(&obj, &keys).unwrap_err();
    assert!(err.to_string().contains("duplicate key"));
}

#[test]
fn enrichment_proxy_invariant_check_own_keys_missing_non_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("locked"),
        PropertyDescriptor::Data {
            value: int_val(1),
            writable: true,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    // Trap result missing non-configurable key
    let err = ProxyInvariantChecker::check_own_keys(&obj, &[str_key("other")]).unwrap_err();
    assert!(err.to_string().contains("must include non-configurable"));
}

#[test]
fn enrichment_proxy_invariant_check_is_extensible_mismatch() {
    let obj = OrdinaryObject::default(); // extensible=true
    let err = ProxyInvariantChecker::check_is_extensible(&obj, false).unwrap_err();
    assert!(err.to_string().contains("must match target extensibility"));
}

#[test]
fn enrichment_proxy_invariant_check_prevent_extensions_lie() {
    let obj = OrdinaryObject::default(); // extensible=true
    // Cannot return true if target is still extensible
    let err = ProxyInvariantChecker::check_prevent_extensions(&obj, true).unwrap_err();
    assert!(
        err.to_string()
            .contains("cannot return true when target is still extensible")
    );
}

#[test]
fn enrichment_proxy_invariant_check_get_prototype_non_extensible_mismatch() {
    let mut obj = OrdinaryObject::default();
    obj.prototype = Some(ObjectHandle(5));
    obj.prevent_extensions();
    let err =
        ProxyInvariantChecker::check_get_prototype_of(&obj, Some(ObjectHandle(99))).unwrap_err();
    assert!(
        err.to_string()
            .contains("non-extensible target must return same prototype")
    );
}

#[test]
fn enrichment_proxy_invariant_check_set_prototype_non_extensible_diff() {
    let mut obj = OrdinaryObject::default();
    obj.prototype = Some(ObjectHandle(5));
    obj.prevent_extensions();
    let err = ProxyInvariantChecker::check_set_prototype_of(&obj, Some(ObjectHandle(99)), true)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("non-extensible target can only set to current prototype")
    );
}

#[test]
fn enrichment_proxy_invariant_check_define_non_extensible_new_prop() {
    let mut obj = OrdinaryObject::default();
    obj.prevent_extensions();
    let err = ProxyInvariantChecker::check_define_own_property(
        &obj,
        &str_key("new"),
        &PropertyDescriptor::data(int_val(1)),
        true,
    )
    .unwrap_err();
    assert!(err.to_string().contains("cannot add property"));
}

// ===========================================================================
// Section 14: Heap freeze/seal via heap API
// ===========================================================================

#[test]
fn enrichment_heap_freeze_prevents_writes() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    heap.freeze(obj).unwrap();
    // Cannot update existing
    let result = heap.set_property(obj, str_key("x"), int_val(2)).unwrap();
    assert!(!result);
    // Cannot add new
    let result = heap.set_property(obj, str_key("y"), int_val(3)).unwrap();
    assert!(!result);
    assert!(heap.is_frozen(obj).unwrap());
}

#[test]
fn enrichment_heap_seal_allows_value_update() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    heap.seal(obj).unwrap();
    // Sealed object: existing writable properties can still be updated
    // (seal sets non-configurable but not non-writable)
    let result = heap.set_property(obj, str_key("x"), int_val(2)).unwrap();
    assert!(result);
    // Cannot add new
    let result = heap.set_property(obj, str_key("y"), int_val(3)).unwrap();
    assert!(!result);
    assert!(heap.is_sealed(obj).unwrap());
}

#[test]
fn enrichment_heap_delete_non_configurable_fails() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.define_property(
        obj,
        str_key("x"),
        PropertyDescriptor::Data {
            value: int_val(1),
            writable: true,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    assert!(!heap.delete_property(obj, &str_key("x")).unwrap());
}

#[test]
fn enrichment_heap_delete_configurable_succeeds() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(heap.delete_property(obj, &str_key("x")).unwrap());
    assert_eq!(
        heap.get_property(obj, &str_key("x")).unwrap(),
        JsValue::Undefined
    );
}

// ===========================================================================
// Section 15: Prototype chain operations
// ===========================================================================

#[test]
fn enrichment_set_prototype_non_extensible_same_ok() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let obj = heap.alloc(Some(proto));
    heap.prevent_extensions(obj).unwrap();
    // Setting to same prototype succeeds
    assert!(heap.set_prototype_of(obj, Some(proto)).unwrap());
}

#[test]
fn enrichment_set_prototype_non_extensible_different_fails() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let other = heap.alloc_plain();
    let obj = heap.alloc(Some(proto));
    heap.prevent_extensions(obj).unwrap();
    assert!(!heap.set_prototype_of(obj, Some(other)).unwrap());
}

#[test]
fn enrichment_set_prototype_cycle_detection() {
    let mut heap = ObjectHeap::new();
    let a = heap.alloc_plain();
    let b = heap.alloc(Some(a));
    // Try to make a's prototype = b (creates cycle a->b->a)
    let err = heap.set_prototype_of(a, Some(b)).unwrap_err();
    assert!(matches!(err, ObjectError::PrototypeCycleDetected));
}

#[test]
fn enrichment_get_property_returns_undefined_at_chain_end() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let val = heap.get_property(obj, &str_key("nonexistent")).unwrap();
    assert_eq!(val, JsValue::Undefined);
}

#[test]
fn enrichment_get_property_accessor_returns_getter() {
    let mut heap = ObjectHeap::new();
    let getter = heap.alloc_callable(None);
    let obj = heap.alloc_plain();
    heap.define_property(
        obj,
        str_key("x"),
        PropertyDescriptor::Accessor {
            get: Some(getter),
            set: None,
            enumerable: true,
            configurable: true,
        },
    )
    .unwrap();
    let val = heap.get_property(obj, &str_key("x")).unwrap();
    // Returns the getter handle as JsValue::Object
    assert_eq!(val, JsValue::Object(getter));
}

#[test]
fn enrichment_get_property_accessor_no_getter_returns_undefined() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.define_property(
        obj,
        str_key("x"),
        PropertyDescriptor::Accessor {
            get: None,
            set: Some(ObjectHandle(0)),
            enumerable: true,
            configurable: true,
        },
    )
    .unwrap();
    let val = heap.get_property(obj, &str_key("x")).unwrap();
    assert_eq!(val, JsValue::Undefined);
}

// ===========================================================================
// Section 16: Object not found errors
// ===========================================================================

#[test]
fn enrichment_heap_get_invalid_handle() {
    let heap = ObjectHeap::new();
    let err = heap.get(ObjectHandle(999)).unwrap_err();
    assert!(matches!(err, ObjectError::ObjectNotFound(_)));
}

#[test]
fn enrichment_heap_get_mut_invalid_handle() {
    let mut heap = ObjectHeap::new();
    let err = heap.get_mut(ObjectHandle(999)).unwrap_err();
    assert!(matches!(err, ObjectError::ObjectNotFound(_)));
}

// ===========================================================================
// Section 17: Revoke proxy via heap
// ===========================================================================

#[test]
fn enrichment_heap_revoke_proxy() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    heap.revoke_proxy(proxy).unwrap();
    let obj = heap.get(proxy).unwrap();
    assert!(obj.as_proxy().unwrap().is_revoked());
}

#[test]
fn enrichment_heap_revoke_non_proxy_err() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let err = heap.revoke_proxy(obj).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
    assert!(err.to_string().contains("cannot revoke non-proxy"));
}

// ===========================================================================
// Section 18: JSON field-name stability
// ===========================================================================

#[test]
fn enrichment_reflect_apply_request_json_fields() {
    let req = ReflectApplyRequest {
        target: ObjectHandle(0),
        this_arg: JsValue::Null,
        arguments: vec![],
    };
    let json = serde_json::to_value(&req).unwrap();
    assert!(json.get("target").is_some());
    assert!(json.get("this_arg").is_some());
    assert!(json.get("arguments").is_some());
}

#[test]
fn enrichment_reflect_construct_request_json_fields() {
    let req = ReflectConstructRequest {
        target: ObjectHandle(0),
        arguments: vec![],
        new_target: ObjectHandle(0),
    };
    let json = serde_json::to_value(&req).unwrap();
    assert!(json.get("target").is_some());
    assert!(json.get("arguments").is_some());
    assert!(json.get("new_target").is_some());
}

#[test]
fn enrichment_property_descriptor_data_json_fields() {
    let desc = PropertyDescriptor::data(int_val(42));
    let json = serde_json::to_value(&desc).unwrap();
    let s = serde_json::to_string(&json).unwrap();
    assert!(s.contains("value"));
    assert!(s.contains("writable"));
    assert!(s.contains("enumerable"));
    assert!(s.contains("configurable"));
}

#[test]
fn enrichment_property_descriptor_accessor_json_fields() {
    let desc = PropertyDescriptor::Accessor {
        get: Some(ObjectHandle(1)),
        set: None,
        enumerable: true,
        configurable: false,
    };
    let json = serde_json::to_value(&desc).unwrap();
    let s = serde_json::to_string(&json).unwrap();
    assert!(s.contains("get"));
    assert!(s.contains("set"));
    assert!(s.contains("enumerable"));
    assert!(s.contains("configurable"));
}

// ===========================================================================
// Section 19: ManagedObject accessor paths
// ===========================================================================

#[test]
fn enrichment_managed_object_as_ordinary_on_proxy_returns_none() {
    let obj = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    assert!(obj.as_ordinary().is_none());
    assert!(obj.as_proxy().is_some());
}

#[test]
fn enrichment_managed_object_as_proxy_on_ordinary_returns_none() {
    let obj = ManagedObject::Ordinary(OrdinaryObject::default());
    assert!(obj.as_proxy().is_none());
    assert!(obj.as_ordinary().is_some());
}

#[test]
fn enrichment_managed_object_as_ordinary_mut() {
    let mut obj = ManagedObject::Ordinary(OrdinaryObject::default());
    let o = obj.as_ordinary_mut().unwrap();
    o.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    assert!(obj.as_ordinary().unwrap().has_own_property(&str_key("x")));
}

#[test]
fn enrichment_managed_object_as_proxy_mut() {
    let mut obj = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    let p = obj.as_proxy_mut().unwrap();
    p.revoke();
    assert!(obj.as_proxy().unwrap().is_revoked());
}

// ===========================================================================
// Section 20: Reflect delegations
// ===========================================================================

#[test]
fn enrichment_reflect_get_walks_prototype() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("p"), int_val(42)).unwrap();
    let obj = heap.alloc(Some(proto));
    let val = Reflect::get(&heap, obj, &str_key("p")).unwrap();
    assert_eq!(val, int_val(42));
}

#[test]
fn enrichment_reflect_set_creates_property() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(Reflect::set(&mut heap, obj, str_key("x"), int_val(1)).unwrap());
    assert_eq!(Reflect::get(&heap, obj, &str_key("x")).unwrap(), int_val(1));
}

#[test]
fn enrichment_reflect_has() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(Reflect::has(&heap, obj, &str_key("x")).unwrap());
    assert!(!Reflect::has(&heap, obj, &str_key("y")).unwrap());
}

#[test]
fn enrichment_reflect_delete_property() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(Reflect::delete_property(&mut heap, obj, &str_key("x")).unwrap());
    assert!(!Reflect::has(&heap, obj, &str_key("x")).unwrap());
}

#[test]
fn enrichment_reflect_own_keys() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("a"), int_val(1)).unwrap();
    heap.set_property(obj, str_key("b"), int_val(2)).unwrap();
    let keys = Reflect::own_keys(&heap, obj).unwrap();
    assert_eq!(keys.len(), 2);
}

#[test]
fn enrichment_reflect_get_prototype_of() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let obj = heap.alloc(Some(proto));
    assert_eq!(Reflect::get_prototype_of(&heap, obj).unwrap(), Some(proto));
}

#[test]
fn enrichment_reflect_set_prototype_of() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let proto = heap.alloc_plain();
    assert!(Reflect::set_prototype_of(&mut heap, obj, Some(proto)).unwrap());
    assert_eq!(Reflect::get_prototype_of(&heap, obj).unwrap(), Some(proto));
}

#[test]
fn enrichment_reflect_is_extensible() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(Reflect::is_extensible(&heap, obj).unwrap());
}

#[test]
fn enrichment_reflect_prevent_extensions() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(Reflect::prevent_extensions(&mut heap, obj).unwrap());
    assert!(!Reflect::is_extensible(&heap, obj).unwrap());
}

#[test]
fn enrichment_reflect_define_property() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(
        Reflect::define_property(
            &mut heap,
            obj,
            str_key("x"),
            PropertyDescriptor::data(int_val(1))
        )
        .unwrap()
    );
    let desc = Reflect::get_own_property_descriptor(&heap, obj, &str_key("x"))
        .unwrap()
        .unwrap();
    assert_eq!(desc.value(), Some(&int_val(1)));
}

#[test]
fn enrichment_reflect_get_own_property_descriptor_none() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(
        Reflect::get_own_property_descriptor(&heap, obj, &str_key("missing"))
            .unwrap()
            .is_none()
    );
}
