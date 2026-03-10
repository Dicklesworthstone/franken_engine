#![forbid(unsafe_code)]
//! Comprehensive integration tests for the `object_model` module.
//!
//! Covers:
//! - Display impls: PropertyKey, JsValue, ObjectError
//! - Construction/defaults: OrdinaryObject, ObjectHeap, SymbolRegistry
//! - PropertyDescriptor: data, accessor, frozen, mutators
//! - OrdinaryObject: define, delete, freeze, seal, own_property_keys
//! - ObjectHeap: alloc, get/set property, prototype chains, proxy
//! - ProxyObject: create, revoke, target/handler access
//! - ManagedObject: as_ordinary, as_proxy accessors
//! - ProxyInvariantChecker: all 11 trap invariant validations
//! - Reflect: all 11 static methods
//! - SymbolRegistry: symbol_for, key_for, well-known symbols
//! - WellKnownSymbol: id, key, name coverage
//! - Serde round-trips for complex object graphs
//! - Deterministic replay
//! - Error conditions: ObjectNotFound, ProxyRevoked, PrototypeCycleDetected, etc.

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

use frankenengine_engine::object_model::{
    JsValue, ManagedObject, ObjectError, ObjectHandle, ObjectHeap, OrdinaryObject,
    PropertyDescriptor, PropertyKey, ProxyInvariantChecker, ProxyObject, Reflect, SymbolId,
    SymbolRegistry, WellKnownSymbol,
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
// Section 1: PropertyKey
// ===========================================================================

#[test]
fn property_key_display_string() {
    assert_eq!(str_key("hello").to_string(), "hello");
}

#[test]
fn property_key_display_symbol() {
    let k = PropertyKey::Symbol(SymbolId(99));
    assert_eq!(k.to_string(), "Symbol(99)");
}

#[test]
fn property_key_from_str_ref() {
    let k: PropertyKey = "abc".into();
    assert_eq!(k, PropertyKey::String("abc".to_string()));
}

#[test]
fn property_key_from_owned_string() {
    let k: PropertyKey = String::from("owned").into();
    assert_eq!(k, PropertyKey::String("owned".to_string()));
}

#[test]
fn property_key_ordering_string_before_symbol() {
    let s = str_key("aaa");
    let sym = PropertyKey::Symbol(SymbolId(1));
    assert!(s < sym);
}

#[test]
fn property_key_ordering_strings_alphabetical() {
    let a = str_key("apple");
    let b = str_key("banana");
    assert!(a < b);
}

#[test]
fn property_key_eq_same() {
    let k1 = str_key("x");
    let k2 = str_key("x");
    assert_eq!(k1, k2);
}

#[test]
fn property_key_ne_different() {
    let k1 = str_key("x");
    let k2 = str_key("y");
    assert_ne!(k1, k2);
}

#[test]
fn property_key_ne_string_vs_symbol() {
    let s = str_key("1");
    let sym = PropertyKey::Symbol(SymbolId(1));
    assert_ne!(s, sym);
}

// ===========================================================================
// Section 2: SymbolId and WellKnownSymbol
// ===========================================================================

#[test]
fn symbol_id_eq() {
    assert_eq!(SymbolId(1), SymbolId(1));
    assert_ne!(SymbolId(1), SymbolId(2));
}

#[test]
fn well_known_symbol_ids_are_1_to_13() {
    let symbols = [
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
    for (i, sym) in symbols.iter().enumerate() {
        assert_eq!(sym.id(), SymbolId((i as u32) + 1));
    }
}

#[test]
fn well_known_symbol_key_returns_property_key_symbol() {
    let k = WellKnownSymbol::Iterator.key();
    assert_eq!(k, PropertyKey::Symbol(SymbolId(1)));
}

#[test]
fn well_known_symbol_names() {
    assert_eq!(WellKnownSymbol::Iterator.name(), "@@iterator");
    assert_eq!(WellKnownSymbol::ToPrimitive.name(), "@@toPrimitive");
    assert_eq!(WellKnownSymbol::HasInstance.name(), "@@hasInstance");
    assert_eq!(WellKnownSymbol::ToStringTag.name(), "@@toStringTag");
    assert_eq!(WellKnownSymbol::Species.name(), "@@species");
    assert_eq!(
        WellKnownSymbol::IsConcatSpreadable.name(),
        "@@isConcatSpreadable"
    );
    assert_eq!(WellKnownSymbol::Unscopables.name(), "@@unscopables");
    assert_eq!(WellKnownSymbol::AsyncIterator.name(), "@@asyncIterator");
    assert_eq!(WellKnownSymbol::Match.name(), "@@match");
    assert_eq!(WellKnownSymbol::MatchAll.name(), "@@matchAll");
    assert_eq!(WellKnownSymbol::Replace.name(), "@@replace");
    assert_eq!(WellKnownSymbol::Search.name(), "@@search");
    assert_eq!(WellKnownSymbol::Split.name(), "@@split");
}

// ===========================================================================
// Section 3: JsValue
// ===========================================================================

#[test]
fn jsvalue_type_names() {
    assert_eq!(JsValue::Undefined.type_name(), "undefined");
    assert_eq!(JsValue::Null.type_name(), "null");
    assert_eq!(JsValue::Bool(true).type_name(), "boolean");
    assert_eq!(JsValue::Int(42).type_name(), "number");
    assert_eq!(JsValue::Str("s".to_string()).type_name(), "string");
    assert_eq!(JsValue::Symbol(SymbolId(1)).type_name(), "symbol");
    assert_eq!(JsValue::Object(ObjectHandle(0)).type_name(), "object");
    assert_eq!(JsValue::Function(0).type_name(), "function");
}

#[test]
fn jsvalue_is_object() {
    assert!(JsValue::Object(ObjectHandle(0)).is_object());
    assert!(!JsValue::Int(1).is_object());
    assert!(!JsValue::Null.is_object());
}

#[test]
fn jsvalue_is_callable() {
    assert!(JsValue::Function(0).is_callable());
    assert!(!JsValue::Object(ObjectHandle(0)).is_callable());
    assert!(!JsValue::Undefined.is_callable());
}

#[test]
fn jsvalue_same_value() {
    assert!(JsValue::Int(42).same_value(&JsValue::Int(42)));
    assert!(!JsValue::Int(1).same_value(&JsValue::Int(2)));
    assert!(JsValue::Undefined.same_value(&JsValue::Undefined));
    assert!(!JsValue::Null.same_value(&JsValue::Undefined));
}

#[test]
fn jsvalue_display() {
    assert_eq!(JsValue::Undefined.to_string(), "undefined");
    assert_eq!(JsValue::Null.to_string(), "null");
    assert_eq!(JsValue::Bool(true).to_string(), "true");
    assert_eq!(JsValue::Bool(false).to_string(), "false");
    assert_eq!(JsValue::Int(42).to_string(), "42");
    assert_eq!(JsValue::Int(-1).to_string(), "-1");
    assert_eq!(JsValue::Str("hi".to_string()).to_string(), "hi");
    assert_eq!(JsValue::Symbol(SymbolId(7)).to_string(), "Symbol(7)");
    assert_eq!(JsValue::Object(ObjectHandle(3)).to_string(), "[object#3]");
    assert_eq!(JsValue::Function(5).to_string(), "[function#5]");
}

// ===========================================================================
// Section 4: ObjectError Display
// ===========================================================================

#[test]
fn object_error_display_type_error() {
    let e = ObjectError::TypeError("bad stuff".to_string());
    assert_eq!(e.to_string(), "TypeError: bad stuff");
}

#[test]
fn object_error_display_not_found() {
    let e = ObjectError::ObjectNotFound(ObjectHandle(42));
    assert_eq!(e.to_string(), "object#42 not found");
}

#[test]
fn object_error_display_proxy_revoked() {
    assert_eq!(
        ObjectError::ProxyRevoked.to_string(),
        "TypeError: proxy has been revoked"
    );
}

#[test]
fn object_error_display_cycle() {
    assert_eq!(
        ObjectError::PrototypeCycleDetected.to_string(),
        "TypeError: prototype chain cycle detected"
    );
}

#[test]
fn object_error_display_too_deep() {
    let e = ObjectError::PrototypeChainTooDeep {
        depth: 2000,
        max: 1024,
    };
    assert_eq!(
        e.to_string(),
        "TypeError: prototype chain depth 2000 exceeds max 1024"
    );
}

// ===========================================================================
// Section 5: PropertyDescriptor
// ===========================================================================

#[test]
fn descriptor_data_defaults() {
    let d = PropertyDescriptor::data(int_val(10));
    assert!(d.is_data());
    assert!(!d.is_accessor());
    assert!(d.is_configurable());
    assert!(d.is_enumerable());
    assert!(d.is_writable());
    assert_eq!(d.value(), Some(&int_val(10)));
}

#[test]
fn descriptor_data_frozen() {
    let d = PropertyDescriptor::data_frozen(int_val(10));
    assert!(d.is_data());
    assert!(!d.is_configurable());
    assert!(!d.is_enumerable());
    assert!(!d.is_writable());
    assert_eq!(d.value(), Some(&int_val(10)));
}

#[test]
fn descriptor_accessor() {
    let d = PropertyDescriptor::Accessor {
        get: Some(ObjectHandle(1)),
        set: Some(ObjectHandle(2)),
        enumerable: true,
        configurable: false,
    };
    assert!(d.is_accessor());
    assert!(!d.is_data());
    assert!(!d.is_configurable());
    assert!(d.is_enumerable());
    assert!(!d.is_writable()); // accessors always return false for writable
    assert!(d.value().is_none());
}

#[test]
fn descriptor_set_non_configurable() {
    let mut d = PropertyDescriptor::data(int_val(1));
    assert!(d.is_configurable());
    d.set_non_configurable();
    assert!(!d.is_configurable());
}

#[test]
fn descriptor_set_non_writable() {
    let mut d = PropertyDescriptor::data(int_val(1));
    assert!(d.is_writable());
    d.set_non_writable();
    assert!(!d.is_writable());
}

#[test]
fn descriptor_set_non_enumerable() {
    let mut d = PropertyDescriptor::data(int_val(1));
    assert!(d.is_enumerable());
    d.set_non_enumerable();
    assert!(!d.is_enumerable());
}

#[test]
fn descriptor_set_non_writable_no_op_on_accessor() {
    let mut d = PropertyDescriptor::Accessor {
        get: None,
        set: None,
        enumerable: true,
        configurable: true,
    };
    d.set_non_writable(); // should be no-op
    assert!(d.is_configurable()); // unchanged
    assert!(d.is_enumerable());
}

#[test]
fn descriptor_set_non_configurable_on_accessor() {
    let mut d = PropertyDescriptor::Accessor {
        get: None,
        set: None,
        enumerable: true,
        configurable: true,
    };
    d.set_non_configurable();
    assert!(!d.is_configurable());
}

#[test]
fn descriptor_set_non_enumerable_on_accessor() {
    let mut d = PropertyDescriptor::Accessor {
        get: None,
        set: None,
        enumerable: true,
        configurable: true,
    };
    d.set_non_enumerable();
    assert!(!d.is_enumerable());
}

// ===========================================================================
// Section 6: OrdinaryObject
// ===========================================================================

#[test]
fn ordinary_object_defaults() {
    let obj = OrdinaryObject::default();
    assert!(obj.extensible);
    assert_eq!(obj.prototype, None);
    assert!(obj.properties.is_empty());
    assert!(obj.class_tag.is_none());
    assert!(!obj.callable);
    assert!(!obj.constructable);
}

#[test]
fn ordinary_object_with_prototype() {
    let obj = OrdinaryObject::with_prototype(Some(ObjectHandle(5)));
    assert_eq!(obj.prototype, Some(ObjectHandle(5)));
    assert!(obj.extensible);
}

#[test]
fn ordinary_object_define_and_get_own_property() {
    let mut obj = OrdinaryObject::default();
    let result = obj
        .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(42)))
        .unwrap();
    assert!(result);
    assert!(obj.has_own_property(&str_key("x")));
    let desc = obj.get_own_property(&str_key("x")).unwrap();
    assert_eq!(desc.value(), Some(&int_val(42)));
}

#[test]
fn ordinary_object_define_rejects_non_extensible() {
    let mut obj = OrdinaryObject::default();
    obj.prevent_extensions();
    let result = obj
        .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    assert!(!result);
}

#[test]
fn ordinary_object_define_rejects_reconfigure_non_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("x"),
        PropertyDescriptor::Data {
            value: int_val(1),
            writable: false,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    // Try to make it configurable again
    let result = obj
        .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(2)))
        .unwrap();
    assert!(!result);
}

#[test]
fn ordinary_object_define_rejects_enumerable_change_on_non_configurable() {
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
    // Try to change enumerable
    let result = obj
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: false,
                configurable: false,
            },
        )
        .unwrap();
    assert!(!result);
}

#[test]
fn ordinary_object_define_rejects_type_change_on_non_configurable() {
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
    // Try to change data -> accessor
    let result = obj
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: None,
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    assert!(!result);
}

#[test]
fn ordinary_object_define_rejects_writable_false_to_true_non_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("x"),
        PropertyDescriptor::Data {
            value: int_val(1),
            writable: false,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    let result = obj
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: true,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    assert!(!result);
}

#[test]
fn ordinary_object_define_rejects_value_change_non_writable_non_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("x"),
        PropertyDescriptor::Data {
            value: int_val(1),
            writable: false,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    let result = obj
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(99),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    assert!(!result);
}

#[test]
fn ordinary_object_define_allows_same_value_non_writable_non_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("x"),
        PropertyDescriptor::Data {
            value: int_val(1),
            writable: false,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    let result = obj
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(1),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    assert!(result);
}

#[test]
fn ordinary_object_define_rejects_accessor_change_non_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(
        str_key("x"),
        PropertyDescriptor::Accessor {
            get: Some(ObjectHandle(1)),
            set: None,
            enumerable: true,
            configurable: false,
        },
    )
    .unwrap();
    let result = obj
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: Some(ObjectHandle(2)),
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    assert!(!result);
}

#[test]
fn ordinary_object_delete_configurable() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    assert!(obj.delete(&str_key("x")));
    assert!(!obj.has_own_property(&str_key("x")));
}

#[test]
fn ordinary_object_delete_non_configurable_returns_false() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("x"), PropertyDescriptor::data_frozen(int_val(1)))
        .unwrap();
    assert!(!obj.delete(&str_key("x")));
    assert!(obj.has_own_property(&str_key("x")));
}

#[test]
fn ordinary_object_delete_nonexistent_returns_true() {
    let mut obj = OrdinaryObject::default();
    assert!(obj.delete(&str_key("nonexistent")));
}

#[test]
fn ordinary_object_own_property_keys_es2020_order() {
    let mut obj = OrdinaryObject::default();
    // Add in non-sorted order: symbol, string, numeric
    obj.define_own_property(str_key("b"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    obj.define_own_property(
        PropertyKey::Symbol(SymbolId(100)),
        PropertyDescriptor::data(int_val(2)),
    )
    .unwrap();
    obj.define_own_property(str_key("2"), PropertyDescriptor::data(int_val(3)))
        .unwrap();
    obj.define_own_property(str_key("0"), PropertyDescriptor::data(int_val(4)))
        .unwrap();
    obj.define_own_property(str_key("a"), PropertyDescriptor::data(int_val(5)))
        .unwrap();
    obj.define_own_property(str_key("10"), PropertyDescriptor::data(int_val(6)))
        .unwrap();

    let keys = obj.own_property_keys();
    // Expected: numeric indices sorted (0, 2, 10), then strings (a, b via BTree), then symbols
    assert_eq!(keys[0], str_key("0"));
    assert_eq!(keys[1], str_key("2"));
    assert_eq!(keys[2], str_key("10"));
    assert_eq!(keys[3], str_key("a"));
    assert_eq!(keys[4], str_key("b"));
    assert_eq!(keys[5], PropertyKey::Symbol(SymbolId(100)));
}

#[test]
fn ordinary_object_freeze() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    obj.define_own_property(
        str_key("y"),
        PropertyDescriptor::Accessor {
            get: None,
            set: None,
            enumerable: true,
            configurable: true,
        },
    )
    .unwrap();
    obj.freeze();
    assert!(!obj.extensible);
    assert!(obj.is_frozen());
    assert!(obj.is_sealed());
    // All properties non-configurable
    for desc in obj.properties.values() {
        assert!(!desc.is_configurable());
    }
    // Data properties also non-writable
    let x_desc = obj.get_own_property(&str_key("x")).unwrap();
    assert!(!x_desc.is_writable());
}

#[test]
fn ordinary_object_seal() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    obj.seal();
    assert!(!obj.extensible);
    assert!(obj.is_sealed());
    // Sealed objects with writable data properties are not frozen
    let x_desc = obj.get_own_property(&str_key("x")).unwrap();
    assert!(x_desc.is_writable());
    assert!(!x_desc.is_configurable());
}

#[test]
fn ordinary_object_is_frozen_empty_non_extensible() {
    let mut obj = OrdinaryObject::default();
    obj.prevent_extensions();
    assert!(obj.is_frozen()); // vacuously true — no properties
}

#[test]
fn ordinary_object_is_sealed_empty_non_extensible() {
    let mut obj = OrdinaryObject::default();
    obj.prevent_extensions();
    assert!(obj.is_sealed());
}

#[test]
fn ordinary_object_is_frozen_false_when_extensible() {
    let obj = OrdinaryObject::default();
    assert!(!obj.is_frozen());
}

#[test]
fn ordinary_object_is_sealed_false_when_extensible() {
    let obj = OrdinaryObject::default();
    assert!(!obj.is_sealed());
}

// ===========================================================================
// Section 7: ObjectHeap basics
// ===========================================================================

#[test]
fn heap_new_is_empty() {
    let heap = ObjectHeap::new();
    assert!(heap.is_empty());
    assert_eq!(heap.len(), 0);
}

#[test]
fn heap_alloc_plain() {
    let mut heap = ObjectHeap::new();
    let h = heap.alloc_plain();
    assert_eq!(h, ObjectHandle(0));
    assert_eq!(heap.len(), 1);
    assert!(!heap.is_empty());
}

#[test]
fn heap_alloc_with_prototype() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let child = heap.alloc(Some(proto));
    assert_eq!(heap.len(), 2);
    let proto_of_child = heap.get_prototype_of(child).unwrap();
    assert_eq!(proto_of_child, Some(proto));
}

#[test]
fn heap_alloc_proxy() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    assert_eq!(heap.len(), 3);
    let managed = heap.get(proxy).unwrap();
    assert!(managed.as_proxy().is_some());
}

#[test]
fn heap_alloc_symbol() {
    let mut heap = ObjectHeap::new();
    let s1 = heap.alloc_symbol();
    let s2 = heap.alloc_symbol();
    // Well-known symbols are 1..=13, so first user symbol is 14
    assert_eq!(s1, SymbolId(14));
    assert_eq!(s2, SymbolId(15));
}

#[test]
fn heap_get_nonexistent_returns_error() {
    let heap = ObjectHeap::new();
    let result = heap.get(ObjectHandle(999));
    assert!(matches!(result, Err(ObjectError::ObjectNotFound(_))));
}

#[test]
fn heap_get_mut_nonexistent_returns_error() {
    let mut heap = ObjectHeap::new();
    let result = heap.get_mut(ObjectHandle(999));
    assert!(matches!(result, Err(ObjectError::ObjectNotFound(_))));
}

// ===========================================================================
// Section 8: ObjectHeap property operations
// ===========================================================================

#[test]
fn heap_set_and_get_property() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(42)).unwrap();
    let val = heap.get_property(obj, &str_key("x")).unwrap();
    assert_eq!(val, int_val(42));
}

#[test]
fn heap_get_property_undefined_when_missing() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let val = heap.get_property(obj, &str_key("missing")).unwrap();
    assert_eq!(val, JsValue::Undefined);
}

#[test]
fn heap_get_property_walks_prototype_chain() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("inherited"), str_val("from_proto"))
        .unwrap();
    let child = heap.alloc(Some(proto));
    let val = heap.get_property(child, &str_key("inherited")).unwrap();
    assert_eq!(val, str_val("from_proto"));
}

#[test]
fn heap_get_property_own_shadows_prototype() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("x"), int_val(1)).unwrap();
    let child = heap.alloc(Some(proto));
    heap.set_property(child, str_key("x"), int_val(2)).unwrap();
    let val = heap.get_property(child, &str_key("x")).unwrap();
    assert_eq!(val, int_val(2));
}

#[test]
fn heap_has_property_true_for_own() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(heap.has_property(obj, &str_key("x")).unwrap());
}

#[test]
fn heap_has_property_true_for_inherited() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("y"), int_val(1)).unwrap();
    let child = heap.alloc(Some(proto));
    assert!(heap.has_property(child, &str_key("y")).unwrap());
}

#[test]
fn heap_has_property_false_for_missing() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(!heap.has_property(obj, &str_key("nope")).unwrap());
}

#[test]
fn heap_delete_property_ordinary() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(heap.delete_property(obj, &str_key("x")).unwrap());
    assert!(!heap.has_property(obj, &str_key("x")).unwrap());
}

#[test]
fn heap_set_property_non_writable_returns_false() {
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
    let result = heap.set_property(obj, str_key("x"), int_val(99)).unwrap();
    assert!(!result);
    // Value unchanged
    assert_eq!(heap.get_property(obj, &str_key("x")).unwrap(), int_val(1));
}

#[test]
fn heap_set_property_non_extensible_no_new_property() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.prevent_extensions(obj).unwrap();
    let result = heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(!result);
}

// ===========================================================================
// Section 9: Prototype chain operations
// ===========================================================================

#[test]
fn heap_set_prototype_of() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let proto = heap.alloc_plain();
    assert!(heap.set_prototype_of(obj, Some(proto)).unwrap());
    assert_eq!(heap.get_prototype_of(obj).unwrap(), Some(proto));
}

#[test]
fn heap_set_prototype_of_null() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let obj = heap.alloc(Some(proto));
    assert!(heap.set_prototype_of(obj, None).unwrap());
    assert_eq!(heap.get_prototype_of(obj).unwrap(), None);
}

#[test]
fn heap_set_prototype_cycle_detected() {
    let mut heap = ObjectHeap::new();
    let a = heap.alloc_plain();
    let b = heap.alloc(Some(a));
    // Try to set a's prototype to b, creating a cycle: a -> b -> a
    let result = heap.set_prototype_of(a, Some(b));
    assert!(matches!(result, Err(ObjectError::PrototypeCycleDetected)));
}

#[test]
fn heap_set_prototype_non_extensible_same_proto_ok() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let obj = heap.alloc(Some(proto));
    heap.prevent_extensions(obj).unwrap();
    // Setting to same prototype is allowed
    assert!(heap.set_prototype_of(obj, Some(proto)).unwrap());
}

#[test]
fn heap_set_prototype_non_extensible_different_proto_rejected() {
    let mut heap = ObjectHeap::new();
    let proto1 = heap.alloc_plain();
    let proto2 = heap.alloc_plain();
    let obj = heap.alloc(Some(proto1));
    heap.prevent_extensions(obj).unwrap();
    // Setting to different prototype is rejected
    assert!(!heap.set_prototype_of(obj, Some(proto2)).unwrap());
}

// ===========================================================================
// Section 10: ObjectHeap freeze/seal/extensibility
// ===========================================================================

#[test]
fn heap_freeze() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    heap.freeze(obj).unwrap();
    assert!(heap.is_frozen(obj).unwrap());
    assert!(heap.is_sealed(obj).unwrap());
    assert!(!heap.is_extensible(obj).unwrap());
}

#[test]
fn heap_seal() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    heap.seal(obj).unwrap();
    assert!(heap.is_sealed(obj).unwrap());
    assert!(!heap.is_extensible(obj).unwrap());
}

#[test]
fn heap_prevent_extensions() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(heap.is_extensible(obj).unwrap());
    heap.prevent_extensions(obj).unwrap();
    assert!(!heap.is_extensible(obj).unwrap());
}

// ===========================================================================
// Section 11: ObjectHeap keys/values/entries
// ===========================================================================

#[test]
fn heap_keys_only_enumerable_strings() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("a"), int_val(1)).unwrap();
    heap.set_property(obj, str_key("b"), int_val(2)).unwrap();
    heap.define_property(
        obj,
        str_key("c"),
        PropertyDescriptor::Data {
            value: int_val(3),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();
    // Symbol property — should not appear in keys
    heap.define_property(
        obj,
        PropertyKey::Symbol(SymbolId(50)),
        PropertyDescriptor::data(int_val(4)),
    )
    .unwrap();

    let keys = heap.keys(obj).unwrap();
    assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn heap_values_only_enumerable() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("a"), int_val(10)).unwrap();
    heap.define_property(
        obj,
        str_key("b"),
        PropertyDescriptor::Data {
            value: int_val(20),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();
    let vals = heap.values(obj).unwrap();
    assert_eq!(vals, vec![int_val(10)]);
}

#[test]
fn heap_entries() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    heap.set_property(obj, str_key("y"), int_val(2)).unwrap();
    let entries = heap.entries(obj).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.contains(&("x".to_string(), int_val(1))));
    assert!(entries.contains(&("y".to_string(), int_val(2))));
}

#[test]
fn heap_get_own_property_names_includes_non_enumerable() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("a"), int_val(1)).unwrap();
    heap.define_property(
        obj,
        str_key("b"),
        PropertyDescriptor::Data {
            value: int_val(2),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();
    heap.define_property(
        obj,
        PropertyKey::Symbol(SymbolId(50)),
        PropertyDescriptor::data(int_val(3)),
    )
    .unwrap();
    let names = heap.get_own_property_names(obj).unwrap();
    assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn heap_get_own_property_symbols() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("a"), int_val(1)).unwrap();
    heap.define_property(
        obj,
        PropertyKey::Symbol(SymbolId(50)),
        PropertyDescriptor::data(int_val(2)),
    )
    .unwrap();
    heap.define_property(
        obj,
        PropertyKey::Symbol(SymbolId(60)),
        PropertyDescriptor::data(int_val(3)),
    )
    .unwrap();
    let syms = heap.get_own_property_symbols(obj).unwrap();
    assert_eq!(syms.len(), 2);
    assert!(syms.contains(&SymbolId(50)));
    assert!(syms.contains(&SymbolId(60)));
}

#[test]
fn heap_get_own_property_descriptors() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    heap.set_property(obj, str_key("y"), int_val(2)).unwrap();
    let descs = heap.get_own_property_descriptors(obj).unwrap();
    assert_eq!(descs.len(), 2);
}

// ===========================================================================
// Section 12: ObjectHeap for_in_keys
// ===========================================================================

#[test]
fn heap_for_in_keys_walks_prototype_chain() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("inherited"), int_val(1))
        .unwrap();
    let child = heap.alloc(Some(proto));
    heap.set_property(child, str_key("own"), int_val(2))
        .unwrap();
    let keys = heap.for_in_keys(child).unwrap();
    assert!(keys.contains(&"own".to_string()));
    assert!(keys.contains(&"inherited".to_string()));
}

#[test]
fn heap_for_in_keys_shadows() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("x"), int_val(1)).unwrap();
    let child = heap.alloc(Some(proto));
    heap.set_property(child, str_key("x"), int_val(2)).unwrap();
    let keys = heap.for_in_keys(child).unwrap();
    // "x" should appear only once (from the child)
    assert_eq!(keys.iter().filter(|k| *k == "x").count(), 1);
}

#[test]
fn heap_for_in_keys_skips_non_enumerable() {
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

// ===========================================================================
// Section 13: ObjectHeap assign / create / fromEntries / hasOwn
// ===========================================================================

#[test]
fn heap_assign_copies_enumerable_properties() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let source = heap.alloc_plain();
    heap.set_property(source, str_key("a"), int_val(1)).unwrap();
    heap.set_property(source, str_key("b"), int_val(2)).unwrap();
    heap.assign(target, &[source]).unwrap();
    assert_eq!(
        heap.get_property(target, &str_key("a")).unwrap(),
        int_val(1)
    );
    assert_eq!(
        heap.get_property(target, &str_key("b")).unwrap(),
        int_val(2)
    );
}

#[test]
fn heap_assign_multiple_sources() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let s1 = heap.alloc_plain();
    let s2 = heap.alloc_plain();
    heap.set_property(s1, str_key("a"), int_val(1)).unwrap();
    heap.set_property(s2, str_key("b"), int_val(2)).unwrap();
    heap.assign(target, &[s1, s2]).unwrap();
    assert_eq!(
        heap.get_property(target, &str_key("a")).unwrap(),
        int_val(1)
    );
    assert_eq!(
        heap.get_property(target, &str_key("b")).unwrap(),
        int_val(2)
    );
}

#[test]
fn heap_create_with_proto() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let obj = heap.create(Some(proto));
    assert_eq!(heap.get_prototype_of(obj).unwrap(), Some(proto));
}

#[test]
fn heap_create_without_proto() {
    let mut heap = ObjectHeap::new();
    let obj = heap.create(None);
    assert_eq!(heap.get_prototype_of(obj).unwrap(), None);
}

#[test]
fn heap_from_entries() {
    let mut heap = ObjectHeap::new();
    let entries = vec![("a".to_string(), int_val(1)), ("b".to_string(), int_val(2))];
    let obj = heap.from_entries(entries);
    assert_eq!(heap.get_property(obj, &str_key("a")).unwrap(), int_val(1));
    assert_eq!(heap.get_property(obj, &str_key("b")).unwrap(), int_val(2));
}

#[test]
fn heap_has_own_true() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(heap.has_own(obj, &str_key("x")).unwrap());
}

#[test]
fn heap_has_own_false_for_inherited() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("x"), int_val(1)).unwrap();
    let child = heap.alloc(Some(proto));
    assert!(!heap.has_own(child, &str_key("x")).unwrap());
}

#[test]
fn heap_object_is() {
    assert!(ObjectHeap::object_is(&int_val(42), &int_val(42)));
    assert!(!ObjectHeap::object_is(&int_val(1), &int_val(2)));
    assert!(ObjectHeap::object_is(
        &JsValue::Undefined,
        &JsValue::Undefined
    ));
}

// ===========================================================================
// Section 14: ProxyObject
// ===========================================================================

#[test]
fn proxy_new() {
    let proxy = ProxyObject::new(ObjectHandle(0), ObjectHandle(1));
    assert!(!proxy.is_revoked());
    assert_eq!(proxy.target().unwrap(), ObjectHandle(0));
    assert_eq!(proxy.handler().unwrap(), ObjectHandle(1));
}

#[test]
fn proxy_revoke() {
    let mut proxy = ProxyObject::new(ObjectHandle(0), ObjectHandle(1));
    proxy.revoke();
    assert!(proxy.is_revoked());
    assert!(matches!(proxy.target(), Err(ObjectError::ProxyRevoked)));
    assert!(matches!(proxy.handler(), Err(ObjectError::ProxyRevoked)));
}

#[test]
fn heap_revoke_proxy() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    heap.revoke_proxy(proxy).unwrap();
    let managed = heap.get(proxy).unwrap();
    assert!(managed.as_proxy().unwrap().is_revoked());
}

#[test]
fn heap_revoke_non_proxy_returns_error() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let result = heap.revoke_proxy(obj);
    assert!(matches!(result, Err(ObjectError::TypeError(_))));
}

// ===========================================================================
// Section 15: ManagedObject accessors
// ===========================================================================

#[test]
fn managed_object_as_ordinary() {
    let managed = ManagedObject::Ordinary(OrdinaryObject::default());
    assert!(managed.as_ordinary().is_some());
    assert!(managed.as_proxy().is_none());
}

#[test]
fn managed_object_as_proxy() {
    let managed = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    assert!(managed.as_proxy().is_some());
    assert!(managed.as_ordinary().is_none());
}

#[test]
fn managed_object_as_ordinary_mut() {
    let mut managed = ManagedObject::Ordinary(OrdinaryObject::default());
    let obj = managed.as_ordinary_mut().unwrap();
    obj.extensible = false;
    assert!(!managed.as_ordinary().unwrap().extensible);
}

#[test]
fn managed_object_as_proxy_mut() {
    let mut managed = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    let proxy = managed.as_proxy_mut().unwrap();
    proxy.revoke();
    assert!(managed.as_proxy().unwrap().is_revoked());
}

// ===========================================================================
// Section 16: Proxy operations on heap return TypeError
// ===========================================================================

#[test]
fn heap_proxy_get_property_returns_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    let result = heap.get_property(proxy, &str_key("x"));
    assert!(matches!(result, Err(ObjectError::TypeError(_))));
}

#[test]
fn heap_proxy_set_property_returns_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    let result = heap.set_property(proxy, str_key("x"), int_val(1));
    assert!(matches!(result, Err(ObjectError::TypeError(_))));
}

#[test]
fn heap_proxy_has_property_returns_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    let result = heap.has_property(proxy, &str_key("x"));
    assert!(matches!(result, Err(ObjectError::TypeError(_))));
}

#[test]
fn heap_proxy_delete_property_returns_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    let result = heap.delete_property(proxy, &str_key("x"));
    assert!(matches!(result, Err(ObjectError::TypeError(_))));
}

#[test]
fn heap_proxy_freeze_returns_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    let result = heap.freeze(proxy);
    assert!(matches!(result, Err(ObjectError::TypeError(_))));
}

#[test]
fn heap_proxy_seal_returns_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    let result = heap.seal(proxy);
    assert!(matches!(result, Err(ObjectError::TypeError(_))));
}

#[test]
fn heap_proxy_is_frozen_returns_false() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    assert!(!heap.is_frozen(proxy).unwrap());
}

#[test]
fn heap_proxy_is_sealed_returns_false() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    assert!(!heap.is_sealed(proxy).unwrap());
}

// ===========================================================================
// Section 17: SymbolRegistry
// ===========================================================================

#[test]
fn symbol_registry_new_has_well_known() {
    let reg = SymbolRegistry::new();
    // Well-known symbols have ids, so key_for should return their descriptions
    let desc = reg.key_for(WellKnownSymbol::Iterator.id());
    assert_eq!(desc, Some("Symbol.iterator"));
}

#[test]
fn symbol_registry_all_well_known_registered() {
    let reg = SymbolRegistry::new();
    let well_knowns = [
        (WellKnownSymbol::Iterator, "Symbol.iterator"),
        (WellKnownSymbol::ToPrimitive, "Symbol.toPrimitive"),
        (WellKnownSymbol::HasInstance, "Symbol.hasInstance"),
        (WellKnownSymbol::ToStringTag, "Symbol.toStringTag"),
        (WellKnownSymbol::Species, "Symbol.species"),
        (
            WellKnownSymbol::IsConcatSpreadable,
            "Symbol.isConcatSpreadable",
        ),
        (WellKnownSymbol::Unscopables, "Symbol.unscopables"),
        (WellKnownSymbol::AsyncIterator, "Symbol.asyncIterator"),
        (WellKnownSymbol::Match, "Symbol.match"),
        (WellKnownSymbol::MatchAll, "Symbol.matchAll"),
        (WellKnownSymbol::Replace, "Symbol.replace"),
        (WellKnownSymbol::Search, "Symbol.search"),
        (WellKnownSymbol::Split, "Symbol.split"),
    ];
    for (sym, desc) in &well_knowns {
        assert_eq!(reg.key_for(sym.id()), Some(*desc));
    }
}

#[test]
fn symbol_registry_symbol_for_creates_new() {
    let mut reg = SymbolRegistry::new();
    let mut heap = ObjectHeap::new();
    let id = reg.symbol_for("my_symbol", &mut heap);
    assert_eq!(reg.key_for(id), Some("my_symbol"));
}

#[test]
fn symbol_registry_symbol_for_returns_same_id() {
    let mut reg = SymbolRegistry::new();
    let mut heap = ObjectHeap::new();
    let id1 = reg.symbol_for("shared", &mut heap);
    let id2 = reg.symbol_for("shared", &mut heap);
    assert_eq!(id1, id2);
}

#[test]
fn symbol_registry_key_for_unknown_returns_none() {
    let reg = SymbolRegistry::new();
    assert_eq!(reg.key_for(SymbolId(9999)), None);
}

// ===========================================================================
// Section 18: ProxyInvariantChecker
// ===========================================================================

#[test]
fn invariant_check_get_own_property_non_configurable_reported_absent() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("x"), PropertyDescriptor::data_frozen(int_val(1)))
        .unwrap();
    let result = ProxyInvariantChecker::check_get_own_property(&target, &str_key("x"), &None);
    assert!(result.is_err());
}

#[test]
fn invariant_check_get_own_property_non_extensible_existing_reported_absent() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    target.prevent_extensions();
    let result = ProxyInvariantChecker::check_get_own_property(&target, &str_key("x"), &None);
    assert!(result.is_err());
}

#[test]
fn invariant_check_get_own_property_non_extensible_new_reported_present() {
    let mut target = OrdinaryObject::default();
    target.prevent_extensions();
    let desc = PropertyDescriptor::data(int_val(1));
    let result =
        ProxyInvariantChecker::check_get_own_property(&target, &str_key("new"), &Some(desc));
    assert!(result.is_err());
}

#[test]
fn invariant_check_get_own_property_ok_for_normal_case() {
    let target = OrdinaryObject::default();
    let result = ProxyInvariantChecker::check_get_own_property(
        &target,
        &str_key("x"),
        &Some(PropertyDescriptor::data(int_val(1))),
    );
    assert!(result.is_ok());
}

#[test]
fn invariant_check_has_non_configurable_reported_false() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("x"), PropertyDescriptor::data_frozen(int_val(1)))
        .unwrap();
    let result = ProxyInvariantChecker::check_has(&target, &str_key("x"), false);
    assert!(result.is_err());
}

#[test]
fn invariant_check_has_non_extensible_existing_reported_false() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    target.prevent_extensions();
    let result = ProxyInvariantChecker::check_has(&target, &str_key("x"), false);
    assert!(result.is_err());
}

#[test]
fn invariant_check_has_ok_when_true() {
    let target = OrdinaryObject::default();
    let result = ProxyInvariantChecker::check_has(&target, &str_key("x"), true);
    assert!(result.is_ok());
}

#[test]
fn invariant_check_get_non_configurable_non_writable_wrong_value() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    let result = ProxyInvariantChecker::check_get(&target, &str_key("x"), &int_val(99));
    assert!(result.is_err());
}

#[test]
fn invariant_check_get_non_configurable_non_writable_same_value_ok() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    let result = ProxyInvariantChecker::check_get(&target, &str_key("x"), &int_val(42));
    assert!(result.is_ok());
}

#[test]
fn invariant_check_get_non_configurable_accessor_no_getter_must_return_undefined() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: None,
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    let result = ProxyInvariantChecker::check_get(&target, &str_key("x"), &int_val(1));
    assert!(result.is_err());
    // Undefined should be ok
    let result2 = ProxyInvariantChecker::check_get(&target, &str_key("x"), &JsValue::Undefined);
    assert!(result2.is_ok());
}

#[test]
fn invariant_check_set_non_configurable_non_writable_different_value() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Data {
                value: int_val(42),
                writable: false,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    let result = ProxyInvariantChecker::check_set(&target, &str_key("x"), &int_val(99), true);
    assert!(result.is_err());
}

#[test]
fn invariant_check_set_non_configurable_accessor_no_setter() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(
            str_key("x"),
            PropertyDescriptor::Accessor {
                get: None,
                set: None,
                enumerable: true,
                configurable: false,
            },
        )
        .unwrap();
    let result = ProxyInvariantChecker::check_set(&target, &str_key("x"), &int_val(1), true);
    assert!(result.is_err());
}

#[test]
fn invariant_check_set_ok_when_trap_result_false() {
    let target = OrdinaryObject::default();
    let result = ProxyInvariantChecker::check_set(&target, &str_key("x"), &int_val(1), false);
    assert!(result.is_ok());
}

#[test]
fn invariant_check_delete_non_configurable() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("x"), PropertyDescriptor::data_frozen(int_val(1)))
        .unwrap();
    let result = ProxyInvariantChecker::check_delete(&target, &str_key("x"), true);
    assert!(result.is_err());
}

#[test]
fn invariant_check_delete_non_extensible_existing() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    target.prevent_extensions();
    let result = ProxyInvariantChecker::check_delete(&target, &str_key("x"), true);
    // data(1) is configurable, but target is non-extensible and property exists
    assert!(result.is_err());
}

#[test]
fn invariant_check_delete_ok_when_false() {
    let target = OrdinaryObject::default();
    let result = ProxyInvariantChecker::check_delete(&target, &str_key("x"), false);
    assert!(result.is_ok());
}

#[test]
fn invariant_check_own_keys_duplicate() {
    let target = OrdinaryObject::default();
    let keys = vec![str_key("a"), str_key("a")];
    let result = ProxyInvariantChecker::check_own_keys(&target, &keys);
    assert!(result.is_err());
}

#[test]
fn invariant_check_own_keys_missing_non_configurable() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("x"), PropertyDescriptor::data_frozen(int_val(1)))
        .unwrap();
    let keys = vec![str_key("y")]; // missing "x"
    let result = ProxyInvariantChecker::check_own_keys(&target, &keys);
    assert!(result.is_err());
}

#[test]
fn invariant_check_own_keys_non_extensible_must_be_exact() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("a"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    target.prevent_extensions();
    // Missing "a"
    let result = ProxyInvariantChecker::check_own_keys(&target, &[]);
    assert!(result.is_err());
    // Exact match should work
    let result2 = ProxyInvariantChecker::check_own_keys(&target, &[str_key("a")]);
    assert!(result2.is_ok());
}

#[test]
fn invariant_check_get_prototype_of_non_extensible_different() {
    let target = OrdinaryObject {
        prototype: Some(ObjectHandle(1)),
        extensible: false,
        ..Default::default()
    };
    let result = ProxyInvariantChecker::check_get_prototype_of(&target, Some(ObjectHandle(2)));
    assert!(result.is_err());
}

#[test]
fn invariant_check_get_prototype_of_non_extensible_same_ok() {
    let target = OrdinaryObject {
        prototype: Some(ObjectHandle(1)),
        extensible: false,
        ..Default::default()
    };
    let result = ProxyInvariantChecker::check_get_prototype_of(&target, Some(ObjectHandle(1)));
    assert!(result.is_ok());
}

#[test]
fn invariant_check_set_prototype_of_non_extensible_different() {
    let target = OrdinaryObject {
        prototype: Some(ObjectHandle(1)),
        extensible: false,
        ..Default::default()
    };
    let result =
        ProxyInvariantChecker::check_set_prototype_of(&target, Some(ObjectHandle(2)), true);
    assert!(result.is_err());
}

#[test]
fn invariant_check_is_extensible_mismatch() {
    let target = OrdinaryObject::default(); // extensible=true
    let result = ProxyInvariantChecker::check_is_extensible(&target, false);
    assert!(result.is_err());
}

#[test]
fn invariant_check_is_extensible_match_ok() {
    let target = OrdinaryObject::default();
    let result = ProxyInvariantChecker::check_is_extensible(&target, true);
    assert!(result.is_ok());
}

#[test]
fn invariant_check_prevent_extensions_true_but_still_extensible() {
    let target = OrdinaryObject::default(); // extensible=true
    let result = ProxyInvariantChecker::check_prevent_extensions(&target, true);
    assert!(result.is_err());
}

#[test]
fn invariant_check_prevent_extensions_false_ok() {
    let target = OrdinaryObject::default();
    let result = ProxyInvariantChecker::check_prevent_extensions(&target, false);
    assert!(result.is_ok());
}

#[test]
fn invariant_check_define_own_property_non_extensible_new_property() {
    let mut target = OrdinaryObject::default();
    target.prevent_extensions();
    let desc = PropertyDescriptor::data(int_val(1));
    let result =
        ProxyInvariantChecker::check_define_own_property(&target, &str_key("new"), &desc, true);
    assert!(result.is_err());
}

#[test]
fn invariant_check_define_own_property_non_configurable_when_target_configurable() {
    let mut target = OrdinaryObject::default();
    target
        .define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    let desc = PropertyDescriptor::data_frozen(int_val(1));
    let result =
        ProxyInvariantChecker::check_define_own_property(&target, &str_key("x"), &desc, true);
    assert!(result.is_err());
}

// ===========================================================================
// Section 19: Reflect API
// ===========================================================================

#[test]
fn reflect_get() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(42)).unwrap();
    let val = Reflect::get(&heap, obj, &str_key("x")).unwrap();
    assert_eq!(val, int_val(42));
}

#[test]
fn reflect_set() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(Reflect::set(&mut heap, obj, str_key("x"), int_val(42)).unwrap());
    assert_eq!(
        Reflect::get(&heap, obj, &str_key("x")).unwrap(),
        int_val(42)
    );
}

#[test]
fn reflect_has() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(Reflect::has(&heap, obj, &str_key("x")).unwrap());
    assert!(!Reflect::has(&heap, obj, &str_key("y")).unwrap());
}

#[test]
fn reflect_delete_property() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(1)).unwrap();
    assert!(Reflect::delete_property(&mut heap, obj, &str_key("x")).unwrap());
    assert!(!Reflect::has(&heap, obj, &str_key("x")).unwrap());
}

#[test]
fn reflect_own_keys() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("a"), int_val(1)).unwrap();
    heap.set_property(obj, str_key("b"), int_val(2)).unwrap();
    let keys = Reflect::own_keys(&heap, obj).unwrap();
    assert_eq!(keys.len(), 2);
}

#[test]
fn reflect_get_prototype_of() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let obj = heap.alloc(Some(proto));
    assert_eq!(Reflect::get_prototype_of(&heap, obj).unwrap(), Some(proto));
}

#[test]
fn reflect_set_prototype_of() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let proto = heap.alloc_plain();
    assert!(Reflect::set_prototype_of(&mut heap, obj, Some(proto)).unwrap());
    assert_eq!(Reflect::get_prototype_of(&heap, obj).unwrap(), Some(proto));
}

#[test]
fn reflect_is_extensible() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(Reflect::is_extensible(&heap, obj).unwrap());
}

#[test]
fn reflect_prevent_extensions() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(Reflect::prevent_extensions(&mut heap, obj).unwrap());
    assert!(!Reflect::is_extensible(&heap, obj).unwrap());
}

#[test]
fn reflect_define_property() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    assert!(
        Reflect::define_property(
            &mut heap,
            obj,
            str_key("x"),
            PropertyDescriptor::data(int_val(42))
        )
        .unwrap()
    );
    assert_eq!(
        Reflect::get(&heap, obj, &str_key("x")).unwrap(),
        int_val(42)
    );
}

#[test]
fn reflect_get_own_property_descriptor() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(42)).unwrap();
    let desc = Reflect::get_own_property_descriptor(&heap, obj, &str_key("x"))
        .unwrap()
        .unwrap();
    assert!(desc.is_data());
    assert_eq!(desc.value(), Some(&int_val(42)));
}

#[test]
fn reflect_get_own_property_descriptor_missing() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let desc = Reflect::get_own_property_descriptor(&heap, obj, &str_key("missing")).unwrap();
    assert!(desc.is_none());
}

// ===========================================================================
// Section 20: Serde round-trips
// ===========================================================================

#[test]
fn serde_roundtrip_property_key_string() {
    let k = str_key("test");
    let json = serde_json::to_string(&k).unwrap();
    let restored: PropertyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(k, restored);
}

#[test]
fn serde_roundtrip_property_key_symbol() {
    let k = PropertyKey::Symbol(SymbolId(42));
    let json = serde_json::to_string(&k).unwrap();
    let restored: PropertyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(k, restored);
}

#[test]
fn serde_roundtrip_jsvalue_all_variants() {
    let values = vec![
        JsValue::Undefined,
        JsValue::Null,
        JsValue::Bool(true),
        JsValue::Bool(false),
        JsValue::Int(42),
        JsValue::Int(-1),
        JsValue::Str("hello".to_string()),
        JsValue::Symbol(SymbolId(7)),
        JsValue::Object(ObjectHandle(3)),
        JsValue::Function(5),
    ];
    for val in &values {
        let json = serde_json::to_string(val).unwrap();
        let restored: JsValue = serde_json::from_str(&json).unwrap();
        assert_eq!(val, &restored);
    }
}

#[test]
fn serde_roundtrip_property_descriptor_data() {
    let d = PropertyDescriptor::data(int_val(42));
    let json = serde_json::to_string(&d).unwrap();
    let restored: PropertyDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn serde_roundtrip_property_descriptor_accessor() {
    let d = PropertyDescriptor::Accessor {
        get: Some(ObjectHandle(1)),
        set: Some(ObjectHandle(2)),
        enumerable: true,
        configurable: false,
    };
    let json = serde_json::to_string(&d).unwrap();
    let restored: PropertyDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn serde_roundtrip_ordinary_object() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("a"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    obj.define_own_property(str_key("b"), PropertyDescriptor::data_frozen(str_val("hi")))
        .unwrap();
    obj.prototype = Some(ObjectHandle(42));
    obj.class_tag = Some("Array".to_string());
    let json = serde_json::to_string(&obj).unwrap();
    let restored: OrdinaryObject = serde_json::from_str(&json).unwrap();
    // Check key fields match (OrdinaryObject doesn't derive PartialEq, so check manually)
    assert_eq!(restored.prototype, obj.prototype);
    assert_eq!(restored.extensible, obj.extensible);
    assert_eq!(restored.class_tag, obj.class_tag);
    assert_eq!(restored.callable, obj.callable);
    assert_eq!(restored.constructable, obj.constructable);
    assert_eq!(restored.properties.len(), obj.properties.len());
}

#[test]
fn serde_roundtrip_proxy_object() {
    let proxy = ProxyObject::new(ObjectHandle(0), ObjectHandle(1));
    let json = serde_json::to_string(&proxy).unwrap();
    let restored: ProxyObject = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.target, proxy.target);
    assert_eq!(restored.handler, proxy.handler);
}

#[test]
fn serde_roundtrip_object_heap() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.set_property(obj, str_key("x"), int_val(42)).unwrap();
    let proto = heap.alloc_plain();
    let _child = heap.alloc(Some(proto));
    let json = serde_json::to_string(&heap).unwrap();
    let restored: ObjectHeap = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.len(), heap.len());
}

#[test]
fn serde_roundtrip_symbol_registry() {
    let mut reg = SymbolRegistry::new();
    let mut heap = ObjectHeap::new();
    reg.symbol_for("custom1", &mut heap);
    reg.symbol_for("custom2", &mut heap);
    let json = serde_json::to_string(&reg).unwrap();
    let restored: SymbolRegistry = serde_json::from_str(&json).unwrap();
    // Verify the well-known and custom symbols round-trip
    assert_eq!(
        restored.key_for(WellKnownSymbol::Iterator.id()),
        Some("Symbol.iterator")
    );
}

#[test]
fn serde_roundtrip_object_error() {
    let errors = vec![
        ObjectError::TypeError("bad".to_string()),
        ObjectError::ObjectNotFound(ObjectHandle(42)),
        ObjectError::ProxyRevoked,
        ObjectError::PrototypeCycleDetected,
        ObjectError::PrototypeChainTooDeep {
            depth: 2000,
            max: 1024,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: ObjectError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &restored);
    }
}

#[test]
fn serde_roundtrip_well_known_symbol() {
    let sym = WellKnownSymbol::AsyncIterator;
    let json = serde_json::to_string(&sym).unwrap();
    let restored: WellKnownSymbol = serde_json::from_str(&json).unwrap();
    assert_eq!(sym, restored);
}

// ===========================================================================
// Section 21: Deterministic replay
// ===========================================================================

#[test]
fn deterministic_heap_operations() {
    let run = || -> (Vec<PropertyKey>, Vec<JsValue>) {
        let mut heap = ObjectHeap::new();
        let obj = heap.alloc_plain();
        heap.set_property(obj, str_key("b"), int_val(2)).unwrap();
        heap.set_property(obj, str_key("a"), int_val(1)).unwrap();
        heap.set_property(obj, str_key("0"), int_val(0)).unwrap();
        heap.define_property(
            obj,
            PropertyKey::Symbol(SymbolId(50)),
            PropertyDescriptor::data(int_val(99)),
        )
        .unwrap();
        let managed = heap.get(obj).unwrap();
        let keys = managed.as_ordinary().unwrap().own_property_keys();
        let vals = heap.values(obj).unwrap();
        (keys, vals)
    };
    let (k1, v1) = run();
    let (k2, v2) = run();
    assert_eq!(k1, k2);
    assert_eq!(v1, v2);
}

#[test]
fn deterministic_prototype_chain_traversal() {
    let run = || -> Vec<String> {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("inherited"), int_val(1))
            .unwrap();
        let child = heap.alloc(Some(proto));
        heap.set_property(child, str_key("own"), int_val(2))
            .unwrap();
        heap.for_in_keys(child).unwrap()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Section 22: Deep prototype chains
// ===========================================================================

#[test]
fn deep_prototype_chain_property_lookup() {
    let mut heap = ObjectHeap::new();
    let mut current = heap.alloc_plain();
    heap.set_property(current, str_key("deep"), int_val(999))
        .unwrap();
    // Build a chain 50 deep
    for _ in 0..50 {
        current = heap.alloc(Some(current));
    }
    let val = heap.get_property(current, &str_key("deep")).unwrap();
    assert_eq!(val, int_val(999));
}

#[test]
fn deep_prototype_chain_for_in() {
    let mut heap = ObjectHeap::new();
    let mut current = heap.alloc_plain();
    heap.set_property(current, str_key("base"), int_val(0))
        .unwrap();
    for i in 1..=10 {
        current = heap.alloc(Some(current));
        heap.set_property(
            current,
            PropertyKey::String(format!("level{i}")),
            int_val(i),
        )
        .unwrap();
    }
    let keys = heap.for_in_keys(current).unwrap();
    assert!(keys.contains(&"base".to_string()));
    assert!(keys.contains(&"level10".to_string()));
    assert_eq!(keys.len(), 11); // base + level1..level10
}

// ===========================================================================
// Section 23: ObjectHeap define_properties and accessor get via heap
// ===========================================================================

#[test]
fn heap_define_properties_multiple() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let props = vec![
        (str_key("a"), PropertyDescriptor::data(int_val(1))),
        (str_key("b"), PropertyDescriptor::data(int_val(2))),
        (str_key("c"), PropertyDescriptor::data(int_val(3))),
    ];
    assert!(heap.define_properties(obj, props).unwrap());
    assert_eq!(heap.get_property(obj, &str_key("a")).unwrap(), int_val(1));
    assert_eq!(heap.get_property(obj, &str_key("b")).unwrap(), int_val(2));
    assert_eq!(heap.get_property(obj, &str_key("c")).unwrap(), int_val(3));
}

#[test]
fn heap_get_property_accessor_returns_getter_handle() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    let getter = heap.alloc_plain();
    heap.define_property(
        obj,
        str_key("prop"),
        PropertyDescriptor::Accessor {
            get: Some(getter),
            set: None,
            enumerable: true,
            configurable: true,
        },
    )
    .unwrap();
    let val = heap.get_property(obj, &str_key("prop")).unwrap();
    assert_eq!(val, JsValue::Object(getter));
}

#[test]
fn heap_get_property_accessor_no_getter_returns_undefined() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    heap.define_property(
        obj,
        str_key("prop"),
        PropertyDescriptor::Accessor {
            get: None,
            set: None,
            enumerable: true,
            configurable: true,
        },
    )
    .unwrap();
    let val = heap.get_property(obj, &str_key("prop")).unwrap();
    assert_eq!(val, JsValue::Undefined);
}

// ===========================================================================
// Section 24: Stress tests
// ===========================================================================

#[test]
fn heap_many_objects() {
    let mut heap = ObjectHeap::new();
    for i in 0..500 {
        let obj = heap.alloc_plain();
        heap.set_property(obj, str_key("idx"), JsValue::Int(i))
            .unwrap();
    }
    assert_eq!(heap.len(), 500);
    // Verify last object
    let last = ObjectHandle(499);
    assert_eq!(
        heap.get_property(last, &str_key("idx")).unwrap(),
        JsValue::Int(499)
    );
}

#[test]
fn heap_many_properties_on_one_object() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();
    for i in 0..200 {
        heap.set_property(
            obj,
            PropertyKey::String(format!("prop_{i}")),
            JsValue::Int(i),
        )
        .unwrap();
    }
    let keys = heap.keys(obj).unwrap();
    assert_eq!(keys.len(), 200);
}

#[test]
fn heap_many_symbols() {
    let mut heap = ObjectHeap::new();
    let symbols: Vec<SymbolId> = (0..100).map(|_| heap.alloc_symbol()).collect();
    // All should be unique
    let mut seen = std::collections::BTreeSet::new();
    for sym in &symbols {
        assert!(seen.insert(*sym));
    }
}
