//! Integration tests for `object_model` edge cases and cross-cutting concerns
//! not covered by the module's 80 inline unit tests.
//!
//! Focus areas:
//! - Complex multi-step property descriptor workflows
//! - Heap-level proxy error paths (all operations on proxy → TypeError)
//! - Deep and wide prototype chains
//! - Concurrent large-scale heap operations
//! - PropertyKey ordering with tricky inputs
//! - ObjectError / JsValue Display exact format verification
//! - WellKnownSymbol exhaustive id coverage
//! - SymbolRegistry edge cases
//! - Reflect API error paths
//! - Serde round-trips for complex object graphs
//! - ManagedObject mutable accessor paths

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
// 1. PropertyKey edge cases
// ===========================================================================

#[test]
fn property_key_from_owned_string() {
    let owned = String::from("owned_key");
    let k: PropertyKey = owned.into();
    assert_eq!(k, PropertyKey::String("owned_key".to_string()));
}

#[test]
fn property_key_ord_string_before_symbol() {
    let s = str_key("z");
    let sym = PropertyKey::Symbol(SymbolId(1));
    // String < Symbol in the derived Ord
    assert!(s < sym);
}

#[test]
fn property_key_symbol_ord_by_id() {
    let a = PropertyKey::Symbol(SymbolId(1));
    let b = PropertyKey::Symbol(SymbolId(100));
    assert!(a < b);
}

// ===========================================================================
// 2. JsValue Display — exact format verification for all variants
// ===========================================================================

#[test]
fn js_value_display_all_variants() {
    assert_eq!(JsValue::Undefined.to_string(), "undefined");
    assert_eq!(JsValue::Null.to_string(), "null");
    assert_eq!(JsValue::Bool(true).to_string(), "true");
    assert_eq!(JsValue::Bool(false).to_string(), "false");
    assert_eq!(JsValue::Int(0).to_string(), "0");
    assert_eq!(JsValue::Int(-42).to_string(), "-42");
    assert_eq!(JsValue::Int(i64::MAX).to_string(), i64::MAX.to_string());
    assert_eq!(str_val("").to_string(), "");
    assert_eq!(JsValue::Symbol(SymbolId(7)).to_string(), "Symbol(7)");
    assert_eq!(JsValue::Object(ObjectHandle(3)).to_string(), "[object#3]");
    assert_eq!(JsValue::Function(12).to_string(), "[function#12]");
}

#[test]
fn js_value_same_value_different_types() {
    // Different types are never SameValue.
    assert!(!JsValue::Int(0).same_value(&JsValue::Bool(false)));
    assert!(!JsValue::Null.same_value(&JsValue::Undefined));
    assert!(!str_val("42").same_value(&int_val(42)));
    assert!(!JsValue::Object(ObjectHandle(0)).same_value(&JsValue::Function(0)));
}

#[test]
fn js_value_same_value_symbols_distinct() {
    let a = JsValue::Symbol(SymbolId(1));
    let b = JsValue::Symbol(SymbolId(2));
    assert!(!a.same_value(&b));
    assert!(a.same_value(&JsValue::Symbol(SymbolId(1))));
}

#[test]
fn js_value_predicates_exhaustive() {
    let vals = [
        JsValue::Undefined,
        JsValue::Null,
        JsValue::Bool(true),
        int_val(1),
        str_val("hi"),
        JsValue::Symbol(SymbolId(1)),
        JsValue::Object(ObjectHandle(0)),
        JsValue::Function(0),
    ];
    // Only Object is_object
    for (i, v) in vals.iter().enumerate() {
        assert_eq!(v.is_object(), i == 6, "is_object mismatch at index {i}");
    }
    // Only Function is_callable
    for (i, v) in vals.iter().enumerate() {
        assert_eq!(v.is_callable(), i == 7, "is_callable mismatch at index {i}");
    }
}

// ===========================================================================
// 3. ObjectError Display — exact messages
// ===========================================================================

#[test]
fn object_error_display_type_error() {
    let e = ObjectError::TypeError("test message".to_string());
    assert_eq!(e.to_string(), "TypeError: test message");
}

#[test]
fn object_error_display_object_not_found() {
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
fn object_error_display_chain_too_deep() {
    let e = ObjectError::PrototypeChainTooDeep {
        depth: 1025,
        max: 1024,
    };
    assert_eq!(
        e.to_string(),
        "TypeError: prototype chain depth 1025 exceeds max 1024"
    );
}

// ===========================================================================
// 4. WellKnownSymbol — exhaustive id and key coverage
// ===========================================================================

#[test]
fn well_known_symbol_ids_are_1_through_13() {
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
fn well_known_symbol_key_is_symbol_property_key() {
    for sym in [
        WellKnownSymbol::Iterator,
        WellKnownSymbol::Split,
        WellKnownSymbol::AsyncIterator,
    ] {
        let key = sym.key();
        assert!(matches!(key, PropertyKey::Symbol(_)));
        if let PropertyKey::Symbol(id) = key {
            assert_eq!(id, sym.id());
        }
    }
}

// ===========================================================================
// 5. PropertyDescriptor — accessor mutator edge cases
// ===========================================================================

#[test]
fn set_non_writable_on_accessor_is_noop() {
    let mut d = PropertyDescriptor::Accessor {
        get: Some(ObjectHandle(1)),
        set: None,
        enumerable: true,
        configurable: true,
    };
    d.set_non_writable(); // no-op on accessor
    // Still an accessor, still configurable.
    assert!(d.is_accessor());
    assert!(d.is_configurable());
}

#[test]
fn set_non_enumerable_on_accessor() {
    let mut d = PropertyDescriptor::Accessor {
        get: None,
        set: Some(ObjectHandle(2)),
        enumerable: true,
        configurable: true,
    };
    d.set_non_enumerable();
    assert!(!d.is_enumerable());
}

#[test]
fn set_non_configurable_on_accessor() {
    let mut d = PropertyDescriptor::Accessor {
        get: Some(ObjectHandle(1)),
        set: Some(ObjectHandle(2)),
        enumerable: false,
        configurable: true,
    };
    d.set_non_configurable();
    assert!(!d.is_configurable());
}

// ===========================================================================
// 6. OrdinaryObject — empty frozen/sealed is trivially true
// ===========================================================================

#[test]
fn empty_object_frozen_when_non_extensible() {
    let mut obj = OrdinaryObject::default();
    // Extensible object with no properties is NOT frozen.
    assert!(!obj.is_frozen());
    assert!(!obj.is_sealed());

    obj.prevent_extensions();
    // Non-extensible object with no properties IS both frozen and sealed.
    assert!(obj.is_frozen());
    assert!(obj.is_sealed());
}

#[test]
fn with_prototype_constructor() {
    let proto = ObjectHandle(42);
    let obj = OrdinaryObject::with_prototype(Some(proto));
    assert_eq!(obj.prototype, Some(proto));
    assert!(obj.extensible);
    assert!(obj.properties.is_empty());
}

// ===========================================================================
// 7. Heap — proxy operations all return TypeError
// ===========================================================================

#[test]
fn proxy_get_property_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.get_property(proxy, &str_key("x")).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_set_property_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap
        .set_property(proxy, str_key("x"), int_val(1))
        .unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_has_property_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.has_property(proxy, &str_key("x")).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_delete_property_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.delete_property(proxy, &str_key("x")).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_get_prototype_of_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.get_prototype_of(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_set_prototype_of_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.set_prototype_of(proxy, None).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_is_extensible_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.is_extensible(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_prevent_extensions_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.prevent_extensions(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_define_property_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap
        .define_property(proxy, str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_get_own_property_descriptor_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap
        .get_own_property_descriptor(proxy, &str_key("x"))
        .unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_keys_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.keys(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_values_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.values(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_entries_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.entries(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_get_own_property_descriptors_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.get_own_property_descriptors(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_for_in_keys_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.for_in_keys(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_freeze_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.freeze(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_seal_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = heap.seal(proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn proxy_is_frozen_returns_false() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    // Proxy is_frozen/is_sealed returns false (not error).
    assert!(!heap.is_frozen(proxy).unwrap());
    assert!(!heap.is_sealed(proxy).unwrap());
}

#[test]
fn proxy_assign_source_returns_type_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);
    let dest = heap.alloc_plain();

    let err = heap.assign(dest, &[proxy]).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

// ===========================================================================
// 8. Heap — invalid handle operations
// ===========================================================================

#[test]
fn invalid_handle_get_property() {
    let heap = ObjectHeap::new();
    let err = heap
        .get_property(ObjectHandle(999), &str_key("x"))
        .unwrap_err();
    assert!(matches!(
        err,
        ObjectError::ObjectNotFound(ObjectHandle(999))
    ));
}

#[test]
fn invalid_handle_set_property() {
    let mut heap = ObjectHeap::new();
    let err = heap
        .set_property(ObjectHandle(999), str_key("x"), int_val(1))
        .unwrap_err();
    assert!(matches!(err, ObjectError::ObjectNotFound(_)));
}

#[test]
fn invalid_handle_has_property() {
    let heap = ObjectHeap::new();
    let err = heap
        .has_property(ObjectHandle(999), &str_key("x"))
        .unwrap_err();
    assert!(matches!(err, ObjectError::ObjectNotFound(_)));
}

#[test]
fn invalid_handle_delete_property() {
    let mut heap = ObjectHeap::new();
    let err = heap
        .delete_property(ObjectHandle(999), &str_key("x"))
        .unwrap_err();
    assert!(matches!(err, ObjectError::ObjectNotFound(_)));
}

#[test]
fn invalid_handle_freeze() {
    let mut heap = ObjectHeap::new();
    let err = heap.freeze(ObjectHandle(999)).unwrap_err();
    assert!(matches!(err, ObjectError::ObjectNotFound(_)));
}

#[test]
fn invalid_handle_seal() {
    let mut heap = ObjectHeap::new();
    let err = heap.seal(ObjectHandle(999)).unwrap_err();
    assert!(matches!(err, ObjectError::ObjectNotFound(_)));
}

// ===========================================================================
// 9. Deep prototype chain
// ===========================================================================

#[test]
fn deep_prototype_chain_property_lookup() {
    let mut heap = ObjectHeap::new();
    let root = heap.alloc_plain();
    heap.set_property(root, str_key("deep"), int_val(42))
        .unwrap();

    // Build a chain of 100 objects.
    let mut current = root;
    for _ in 0..100 {
        current = heap.alloc(Some(current));
    }

    // Property lookup at depth 100 should still work.
    let val = heap.get_property(current, &str_key("deep")).unwrap();
    assert_eq!(val, int_val(42));
    assert!(heap.has_property(current, &str_key("deep")).unwrap());
}

#[test]
fn deep_for_in_keys_through_chain() {
    let mut heap = ObjectHeap::new();
    let root = heap.alloc_plain();
    heap.set_property(root, str_key("root_prop"), int_val(1))
        .unwrap();

    let mid = heap.alloc(Some(root));
    heap.set_property(mid, str_key("mid_prop"), int_val(2))
        .unwrap();

    let leaf = heap.alloc(Some(mid));
    heap.set_property(leaf, str_key("leaf_prop"), int_val(3))
        .unwrap();

    let keys = heap.for_in_keys(leaf).unwrap();
    assert_eq!(
        keys,
        vec![
            "leaf_prop".to_string(),
            "mid_prop".to_string(),
            "root_prop".to_string(),
        ]
    );
}

// ===========================================================================
// 10. SymbolRegistry edge cases
// ===========================================================================

#[test]
fn symbol_registry_key_for_unknown_symbol_returns_none() {
    let reg = SymbolRegistry::new();
    assert_eq!(reg.key_for(SymbolId(999)), None);
}

#[test]
fn symbol_registry_well_known_key_for_all_13() {
    let reg = SymbolRegistry::new();
    let expected = [
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
    for (sym, desc) in expected {
        assert_eq!(
            reg.key_for(sym.id()),
            Some(desc),
            "failed for {}",
            sym.name()
        );
    }
}

#[test]
fn symbol_registry_for_idempotent_returns_same_id() {
    let mut heap = ObjectHeap::new();
    let mut reg = SymbolRegistry::new();
    let s1 = reg.symbol_for("mykey", &mut heap);
    let s2 = reg.symbol_for("mykey", &mut heap);
    let s3 = reg.symbol_for("mykey", &mut heap);
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
    assert_eq!(reg.key_for(s1), Some("mykey"));
}

#[test]
fn symbol_registry_for_distinct_keys_get_distinct_ids() {
    let mut heap = ObjectHeap::new();
    let mut reg = SymbolRegistry::new();
    let ids: Vec<SymbolId> = (0..10)
        .map(|i| reg.symbol_for(&format!("key_{i}"), &mut heap))
        .collect();
    // All unique.
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j], "duplicate id at i={i}, j={j}");
        }
    }
}

// ===========================================================================
// 11. ManagedObject mutable accessors
// ===========================================================================

#[test]
fn managed_object_as_ordinary_mut() {
    let mut obj = ManagedObject::Ordinary(OrdinaryObject::default());
    let ord = obj.as_ordinary_mut().unwrap();
    ord.callable = true;
    assert!(obj.as_ordinary().unwrap().callable);
}

#[test]
fn managed_object_as_proxy_mut() {
    let mut obj = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    let p = obj.as_proxy_mut().unwrap();
    p.revoke();
    assert!(obj.as_proxy().unwrap().is_revoked());
}

#[test]
fn managed_object_cross_variant_returns_none() {
    let ord = ManagedObject::Ordinary(OrdinaryObject::default());
    assert!(ord.as_proxy().is_none());

    let mut ord_mut = ManagedObject::Ordinary(OrdinaryObject::default());
    assert!(ord_mut.as_proxy_mut().is_none());

    let proxy = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    assert!(proxy.as_ordinary().is_none());

    let mut proxy_mut = ManagedObject::Proxy(ProxyObject::new(ObjectHandle(0), ObjectHandle(1)));
    assert!(proxy_mut.as_ordinary_mut().is_none());
}

// ===========================================================================
// 12. Reflect API — error paths
// ===========================================================================

#[test]
fn reflect_own_keys_on_proxy_returns_error() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_plain();
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    let err = Reflect::own_keys(&heap, proxy).unwrap_err();
    assert!(matches!(err, ObjectError::TypeError(_)));
}

#[test]
fn reflect_on_invalid_handle_returns_error() {
    let heap = ObjectHeap::new();
    let bad = ObjectHandle(999);

    assert!(Reflect::get(&heap, bad, &str_key("x")).is_err());
    assert!(Reflect::has(&heap, bad, &str_key("x")).is_err());
    assert!(Reflect::get_prototype_of(&heap, bad).is_err());
    assert!(Reflect::is_extensible(&heap, bad).is_err());
    assert!(Reflect::own_keys(&heap, bad).is_err());
    assert!(Reflect::get_own_property_descriptor(&heap, bad, &str_key("x")).is_err());
}

#[test]
fn reflect_mutating_on_invalid_handle_returns_error() {
    let mut heap = ObjectHeap::new();
    let bad = ObjectHandle(999);

    assert!(Reflect::set(&mut heap, bad, str_key("x"), int_val(1)).is_err());
    assert!(Reflect::delete_property(&mut heap, bad, &str_key("x")).is_err());
    assert!(Reflect::set_prototype_of(&mut heap, bad, None).is_err());
    assert!(Reflect::prevent_extensions(&mut heap, bad).is_err());
    assert!(
        Reflect::define_property(
            &mut heap,
            bad,
            str_key("x"),
            PropertyDescriptor::data(int_val(1))
        )
        .is_err()
    );
}

// ===========================================================================
// 13. Complex multi-step workflows
// ===========================================================================

#[test]
fn define_seal_then_attempt_redefine() {
    let mut heap = ObjectHeap::new();
    let h = heap.alloc_plain();

    // Define writable property, then seal, then redefine value.
    heap.set_property(h, str_key("x"), int_val(1)).unwrap();
    heap.seal(h).unwrap();

    // set_property on sealed writable data property should succeed.
    assert!(heap.set_property(h, str_key("x"), int_val(2)).unwrap());
    assert_eq!(heap.get_property(h, &str_key("x")).unwrap(), int_val(2));

    // Adding new property should fail (non-extensible).
    assert!(!heap.set_property(h, str_key("y"), int_val(3)).unwrap());
}

#[test]
fn freeze_then_seal_is_noop() {
    let mut heap = ObjectHeap::new();
    let h = heap.alloc_plain();
    heap.set_property(h, str_key("x"), int_val(1)).unwrap();

    heap.freeze(h).unwrap();
    assert!(heap.is_frozen(h).unwrap());
    assert!(heap.is_sealed(h).unwrap());

    // Seal after freeze is effectively a no-op — already sealed.
    heap.seal(h).unwrap();
    assert!(heap.is_frozen(h).unwrap());
    assert!(heap.is_sealed(h).unwrap());
}

#[test]
fn assign_skips_non_enumerable_source_properties() {
    let mut heap = ObjectHeap::new();
    let src = heap.alloc_plain();
    heap.set_property(src, str_key("visible"), int_val(1))
        .unwrap();
    heap.define_property(
        src,
        str_key("hidden"),
        PropertyDescriptor::Data {
            value: int_val(2),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    let target = heap.alloc_plain();
    heap.assign(target, &[src]).unwrap();

    assert_eq!(
        heap.get_property(target, &str_key("visible")).unwrap(),
        int_val(1)
    );
    // Hidden property was NOT copied.
    assert_eq!(
        heap.get_property(target, &str_key("hidden")).unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn assign_to_frozen_target_silently_fails() {
    let mut heap = ObjectHeap::new();
    let src = heap.alloc_plain();
    heap.set_property(src, str_key("a"), int_val(1)).unwrap();

    let target = heap.alloc_plain();
    heap.set_property(target, str_key("existing"), int_val(0))
        .unwrap();
    heap.freeze(target).unwrap();

    // Object.assign to frozen target: new properties can't be added,
    // existing frozen properties can't be changed.
    // The set_property calls inside assign return false but don't error.
    heap.assign(target, &[src]).unwrap();

    // "a" not added (frozen/non-extensible).
    assert_eq!(
        heap.get_property(target, &str_key("a")).unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn prototype_chain_with_shadowed_accessor() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.define_property(
        proto,
        str_key("x"),
        PropertyDescriptor::Accessor {
            get: Some(ObjectHandle(100)),
            set: None,
            enumerable: true,
            configurable: true,
        },
    )
    .unwrap();

    let child = heap.alloc(Some(proto));
    // Own data property shadows prototype's accessor.
    heap.set_property(child, str_key("x"), int_val(42)).unwrap();

    let val = heap.get_property(child, &str_key("x")).unwrap();
    assert_eq!(val, int_val(42)); // own data property, not accessor
}

// ===========================================================================
// 14. PropertyKey ordering edge cases
// ===========================================================================

#[test]
fn own_property_keys_negative_not_integer_index() {
    let mut obj = OrdinaryObject::default();
    // Negative numbers are NOT valid integer indices per ES2020.
    // They should be treated as regular string keys.
    obj.define_own_property(str_key("-1"), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    obj.define_own_property(str_key("0"), PropertyDescriptor::data(int_val(2)))
        .unwrap();
    obj.define_own_property(str_key("abc"), PropertyDescriptor::data(int_val(3)))
        .unwrap();

    let keys = obj.own_property_keys();
    // "0" is integer index → first.
    // "-1" and "abc" are string keys, ordered by BTreeMap (lexicographic).
    assert_eq!(keys[0], str_key("0"));
    // "-1" < "abc" lexicographically.
    assert_eq!(keys[1], str_key("-1"));
    assert_eq!(keys[2], str_key("abc"));
}

#[test]
fn own_property_keys_empty_string_key() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key(""), PropertyDescriptor::data(int_val(1)))
        .unwrap();
    obj.define_own_property(str_key("a"), PropertyDescriptor::data(int_val(2)))
        .unwrap();

    let keys = obj.own_property_keys();
    // Empty string is not a valid integer index; it's a string key.
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], str_key(""));
    assert_eq!(keys[1], str_key("a"));
}

// ===========================================================================
// 15. Large-scale heap operations
// ===========================================================================

#[test]
fn allocate_many_objects() {
    let mut heap = ObjectHeap::new();
    let mut handles = Vec::new();
    for i in 0..500 {
        let h = heap.alloc_plain();
        heap.set_property(h, str_key("id"), int_val(i)).unwrap();
        handles.push(h);
    }
    assert_eq!(heap.len(), 500);

    // Verify each object.
    for (i, &h) in handles.iter().enumerate() {
        let val = heap.get_property(h, &str_key("id")).unwrap();
        assert_eq!(val, int_val(i as i64));
    }
}

#[test]
fn many_properties_on_single_object() {
    let mut heap = ObjectHeap::new();
    let h = heap.alloc_plain();

    for i in 0..200 {
        heap.set_property(h, str_key(&format!("prop_{i}")), int_val(i))
            .unwrap();
    }

    let keys = heap.keys(h).unwrap();
    assert_eq!(keys.len(), 200);

    for i in 0..200 {
        let val = heap
            .get_property(h, &str_key(&format!("prop_{i}")))
            .unwrap();
        assert_eq!(val, int_val(i));
    }
}

// ===========================================================================
// 16. Serde round-trip for complex object graph
// ===========================================================================

#[test]
fn serde_roundtrip_heap_with_prototype_chain() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("inherited"), str_val("hello"))
        .unwrap();

    let child = heap.alloc(Some(proto));
    heap.set_property(child, str_key("own"), int_val(42))
        .unwrap();

    let proxy_target = heap.alloc_plain();
    let proxy_handler = heap.alloc_plain();
    let _proxy = heap.alloc_proxy(proxy_target, proxy_handler);

    let json = serde_json::to_string(&heap).unwrap();
    let deser: ObjectHeap = serde_json::from_str(&json).unwrap();

    assert_eq!(deser.len(), 5);
    assert_eq!(
        deser
            .get_property(ObjectHandle(1), &str_key("own"))
            .unwrap(),
        int_val(42)
    );
    // Inherited property through prototype chain.
    assert_eq!(
        deser
            .get_property(ObjectHandle(1), &str_key("inherited"))
            .unwrap(),
        str_val("hello")
    );
    // Proxy is preserved.
    assert!(deser.get(ObjectHandle(4)).unwrap().as_proxy().is_some());
}

#[test]
fn serde_roundtrip_symbol_registry_preserves_custom_symbols() {
    let mut heap = ObjectHeap::new();
    let mut reg = SymbolRegistry::new();
    let s1 = reg.symbol_for("custom_a", &mut heap);
    let s2 = reg.symbol_for("custom_b", &mut heap);

    let json = serde_json::to_string(&reg).unwrap();
    let deser: SymbolRegistry = serde_json::from_str(&json).unwrap();

    assert_eq!(deser.key_for(s1), Some("custom_a"));
    assert_eq!(deser.key_for(s2), Some("custom_b"));
    // Well-known symbols preserved.
    assert_eq!(
        deser.key_for(WellKnownSymbol::Iterator.id()),
        Some("Symbol.iterator")
    );
}

// ===========================================================================
// 17. ProxyInvariantChecker — additional edge cases
// ===========================================================================

#[test]
fn proxy_invariant_get_configurable_property_allows_anything() {
    let mut obj = OrdinaryObject::default();
    obj.define_own_property(str_key("x"), PropertyDescriptor::data(int_val(1)))
        .unwrap(); // configurable=true

    // Trap can return anything for configurable properties.
    assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(999)).is_ok());
    assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &JsValue::Undefined).is_ok());
    assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &str_val("whatever")).is_ok());
}

#[test]
fn proxy_invariant_get_nonexistent_property_allows_anything() {
    let obj = OrdinaryObject::default();
    // Property doesn't exist — trap can return anything.
    assert!(ProxyInvariantChecker::check_get(&obj, &str_key("x"), &int_val(42)).is_ok());
}

#[test]
fn proxy_invariant_has_nonexistent_property_allows_false() {
    let obj = OrdinaryObject::default();
    assert!(ProxyInvariantChecker::check_has(&obj, &str_key("x"), false).is_ok());
    assert!(ProxyInvariantChecker::check_has(&obj, &str_key("x"), true).is_ok());
}

#[test]
fn proxy_invariant_delete_nonexistent_succeeds() {
    let obj = OrdinaryObject::default();
    assert!(ProxyInvariantChecker::check_delete(&obj, &str_key("x"), true).is_ok());
    assert!(ProxyInvariantChecker::check_delete(&obj, &str_key("x"), false).is_ok());
}

#[test]
fn proxy_invariant_own_keys_empty_extensible_ok() {
    let obj = OrdinaryObject::default();
    assert!(ProxyInvariantChecker::check_own_keys(&obj, &[]).is_ok());
    // Extra keys on extensible target is fine.
    assert!(ProxyInvariantChecker::check_own_keys(&obj, &[str_key("extra")]).is_ok());
}

#[test]
fn proxy_invariant_get_prototype_of_extensible_allows_any() {
    let obj = OrdinaryObject::default(); // extensible=true
    // Extensible target — any prototype is fine.
    assert!(ProxyInvariantChecker::check_get_prototype_of(&obj, None).is_ok());
    assert!(ProxyInvariantChecker::check_get_prototype_of(&obj, Some(ObjectHandle(42))).is_ok());
}

#[test]
fn proxy_invariant_set_prototype_of_false_always_ok() {
    let obj = OrdinaryObject {
        extensible: false,
        prototype: Some(ObjectHandle(5)),
        ..Default::default()
    };
    // Trap returning false is always ok (operation was rejected).
    assert!(
        ProxyInvariantChecker::check_set_prototype_of(&obj, Some(ObjectHandle(99)), false).is_ok()
    );
}

#[test]
fn proxy_invariant_prevent_extensions_non_extensible_target_allows_true() {
    let obj = OrdinaryObject {
        extensible: false,
        ..Default::default()
    };
    // Target is already non-extensible — returning true is valid.
    assert!(ProxyInvariantChecker::check_prevent_extensions(&obj, true).is_ok());
}

#[test]
fn proxy_invariant_define_property_configurable_desc_on_extensible_ok() {
    let obj = OrdinaryObject::default();
    let desc = PropertyDescriptor::data(int_val(1)); // configurable=true
    assert!(
        ProxyInvariantChecker::check_define_own_property(&obj, &str_key("x"), &desc, true).is_ok()
    );
}

// ===========================================================================
// 18. set_property on accessor returns false
// ===========================================================================

#[test]
fn set_property_on_accessor_returns_false() {
    let mut heap = ObjectHeap::new();
    let h = heap.alloc_plain();
    heap.define_property(
        h,
        str_key("x"),
        PropertyDescriptor::Accessor {
            get: Some(ObjectHandle(1)),
            set: Some(ObjectHandle(2)),
            enumerable: true,
            configurable: true,
        },
    )
    .unwrap();

    // set_property on accessor property returns false (interpreter handles).
    let result = heap.set_property(h, str_key("x"), int_val(42)).unwrap();
    assert!(!result);
}

// ===========================================================================
// 19. ProxyObject direct API
// ===========================================================================

#[test]
fn proxy_object_new_and_accessors() {
    let p = ProxyObject::new(ObjectHandle(10), ObjectHandle(20));
    assert!(!p.is_revoked());
    assert_eq!(p.target().unwrap(), ObjectHandle(10));
    assert_eq!(p.handler().unwrap(), ObjectHandle(20));
}

#[test]
fn proxy_object_revoke_clears_both() {
    let mut p = ProxyObject::new(ObjectHandle(10), ObjectHandle(20));
    p.revoke();
    assert!(p.is_revoked());
    assert_eq!(p.target, None);
    assert_eq!(p.handler, None);
    assert!(p.target().is_err());
    assert!(p.handler().is_err());
}

// ===========================================================================
// 20. Heap alloc_symbol starts after well-known range
// ===========================================================================

#[test]
fn heap_alloc_symbol_sequence() {
    let mut heap = ObjectHeap::new();
    let s1 = heap.alloc_symbol();
    let s2 = heap.alloc_symbol();
    let s3 = heap.alloc_symbol();
    assert_eq!(s1, SymbolId(14));
    assert_eq!(s2, SymbolId(15));
    assert_eq!(s3, SymbolId(16));
}

// ===========================================================================
// 21. Object.is static method
// ===========================================================================

#[test]
fn object_is_covers_all_value_types() {
    // Same type, same value.
    assert!(ObjectHeap::object_is(
        &JsValue::Undefined,
        &JsValue::Undefined
    ));
    assert!(ObjectHeap::object_is(&JsValue::Null, &JsValue::Null));
    assert!(ObjectHeap::object_is(
        &JsValue::Bool(true),
        &JsValue::Bool(true)
    ));
    assert!(ObjectHeap::object_is(&int_val(0), &int_val(0)));
    assert!(ObjectHeap::object_is(&str_val("a"), &str_val("a")));
    assert!(ObjectHeap::object_is(
        &JsValue::Symbol(SymbolId(1)),
        &JsValue::Symbol(SymbolId(1))
    ));
    assert!(ObjectHeap::object_is(
        &JsValue::Object(ObjectHandle(0)),
        &JsValue::Object(ObjectHandle(0))
    ));
    assert!(ObjectHeap::object_is(
        &JsValue::Function(0),
        &JsValue::Function(0)
    ));

    // Same type, different value.
    assert!(!ObjectHeap::object_is(
        &JsValue::Bool(true),
        &JsValue::Bool(false)
    ));
    assert!(!ObjectHeap::object_is(&int_val(0), &int_val(1)));
    assert!(!ObjectHeap::object_is(&str_val("a"), &str_val("b")));
}

// ===========================================================================
// 22. define_properties partial failure
// ===========================================================================

#[test]
fn define_properties_stops_on_first_failure() {
    let mut heap = ObjectHeap::new();
    let h = heap.alloc_plain();
    heap.prevent_extensions(h).unwrap();

    // Non-extensible: new properties are rejected.
    let props = vec![
        (str_key("a"), PropertyDescriptor::data(int_val(1))),
        (str_key("b"), PropertyDescriptor::data(int_val(2))),
    ];
    let result = heap.define_properties(h, props).unwrap();
    assert!(!result);
}

// ===========================================================================
// 23. Determinism: identical operations produce identical results
// ===========================================================================

#[test]
fn deterministic_object_operations() {
    fn build_heap() -> ObjectHeap {
        let mut heap = ObjectHeap::new();
        let proto = heap.alloc_plain();
        heap.set_property(proto, str_key("inherited"), int_val(1))
            .unwrap();
        let child = heap.alloc(Some(proto));
        heap.set_property(child, str_key("own_a"), int_val(2))
            .unwrap();
        heap.set_property(child, str_key("own_b"), int_val(3))
            .unwrap();
        heap.set_property(child, str_key("1"), int_val(4)).unwrap();
        heap.set_property(child, str_key("0"), int_val(5)).unwrap();
        heap.freeze(child).unwrap();
        heap
    }

    let h1 = build_heap();
    let h2 = build_heap();

    let json1 = serde_json::to_string(&h1).unwrap();
    let json2 = serde_json::to_string(&h2).unwrap();
    assert_eq!(json1, json2);

    // Keys, values, entries all deterministic.
    let child = ObjectHandle(1);
    assert_eq!(h1.keys(child).unwrap(), h2.keys(child).unwrap());
    assert_eq!(h1.values(child).unwrap(), h2.values(child).unwrap());
    assert_eq!(h1.entries(child).unwrap(), h2.entries(child).unwrap());
    assert_eq!(
        h1.for_in_keys(child).unwrap(),
        h2.for_in_keys(child).unwrap()
    );
}
