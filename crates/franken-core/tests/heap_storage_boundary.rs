//! Boundary tests for franken-core heap-backed own-property storage.

use frankenengine_core::object_model::{
    JsValue, ObjectError, ObjectHandle, ObjectHeap, PropertyDescriptor, PropertyKey, SymbolId,
};

fn key(name: &str) -> PropertyKey {
    PropertyKey::String(name.to_string())
}

fn int_value(value: i64) -> JsValue {
    JsValue::Int(value)
}

fn str_value(value: &str) -> JsValue {
    JsValue::Str(value.to_string())
}

fn data_descriptor(
    value: JsValue,
    writable: bool,
    enumerable: bool,
    configurable: bool,
) -> PropertyDescriptor {
    PropertyDescriptor::Data {
        value,
        writable,
        enumerable,
        configurable,
    }
}

fn own_descriptor(heap: &ObjectHeap, object: ObjectHandle, name: &str) -> PropertyDescriptor {
    heap.get_own_property_descriptor(object, &key(name))
        .expect("own descriptor lookup should not fail")
        .expect("own descriptor should exist")
}

fn assert_data_descriptor(
    descriptor: &PropertyDescriptor,
    value: JsValue,
    writable: bool,
    enumerable: bool,
    configurable: bool,
) {
    match descriptor {
        PropertyDescriptor::Data {
            value: actual,
            writable: actual_writable,
            enumerable: actual_enumerable,
            configurable: actual_configurable,
        } => {
            assert_eq!(actual, &value);
            assert_eq!(*actual_writable, writable);
            assert_eq!(*actual_enumerable, enumerable);
            assert_eq!(*actual_configurable, configurable);
        }
        PropertyDescriptor::Accessor { .. } => panic!("expected data descriptor"),
    }
}

#[test]
fn set_property_allocates_first_own_property() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();

    assert!(
        heap.set_property(object, key("answer"), int_value(42))
            .unwrap()
    );

    assert!(heap.has_own(object, &key("answer")).unwrap());
    assert_eq!(
        heap.get_property(object, &key("answer")).unwrap(),
        int_value(42)
    );
    assert_data_descriptor(
        &own_descriptor(&heap, object, "answer"),
        int_value(42),
        true,
        true,
        true,
    );
}

#[test]
fn set_property_updates_existing_writable_own_property() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.set_property(object, key("count"), int_value(1))
        .unwrap();

    assert!(
        heap.set_property(object, key("count"), int_value(2))
            .unwrap()
    );

    assert_eq!(
        heap.get_property(object, &key("count")).unwrap(),
        int_value(2)
    );
    assert_eq!(heap.get_own_property_names(object).unwrap(), vec!["count"]);
}

#[test]
fn set_property_rejects_non_writable_own_property() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("constant"),
        data_descriptor(int_value(1), false, true, true),
    )
    .unwrap();

    assert!(
        !heap
            .set_property(object, key("constant"), int_value(2))
            .unwrap()
    );
    assert_eq!(
        heap.get_property(object, &key("constant")).unwrap(),
        int_value(1)
    );
}

#[test]
fn define_property_creates_non_default_descriptor() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();

    assert!(
        heap.define_property(
            object,
            key("hidden"),
            data_descriptor(str_value("secret"), false, false, false),
        )
        .unwrap()
    );

    assert_data_descriptor(
        &own_descriptor(&heap, object, "hidden"),
        str_value("secret"),
        false,
        false,
        false,
    );
    assert!(heap.keys(object).unwrap().is_empty());
}

#[test]
fn redefine_configurable_data_descriptor_changes_flags_and_value() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.set_property(object, key("mode"), str_value("old"))
        .unwrap();

    assert!(
        heap.define_property(
            object,
            key("mode"),
            data_descriptor(str_value("new"), false, false, true),
        )
        .unwrap()
    );

    assert_data_descriptor(
        &own_descriptor(&heap, object, "mode"),
        str_value("new"),
        false,
        false,
        true,
    );
}

#[test]
fn redefine_non_configurable_cannot_become_configurable() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("fixed"),
        data_descriptor(int_value(1), true, true, false),
    )
    .unwrap();

    assert!(
        !heap
            .define_property(
                object,
                key("fixed"),
                data_descriptor(int_value(1), true, true, true),
            )
            .unwrap()
    );
}

#[test]
fn non_configurable_non_writable_rejects_value_change() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("fixed"),
        data_descriptor(int_value(1), false, true, false),
    )
    .unwrap();

    assert!(
        !heap
            .define_property(
                object,
                key("fixed"),
                data_descriptor(int_value(2), false, true, false),
            )
            .unwrap()
    );
    assert_eq!(
        heap.get_property(object, &key("fixed")).unwrap(),
        int_value(1)
    );
}

#[test]
fn non_configurable_non_writable_rejects_writable_upgrade() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("fixed"),
        data_descriptor(int_value(1), false, true, false),
    )
    .unwrap();

    assert!(
        !heap
            .define_property(
                object,
                key("fixed"),
                data_descriptor(int_value(1), true, true, false),
            )
            .unwrap()
    );
}

#[test]
fn configurable_property_deletion_removes_own_property() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.set_property(object, key("temporary"), int_value(1))
        .unwrap();

    assert!(heap.delete_property(object, &key("temporary")).unwrap());

    assert!(!heap.has_own(object, &key("temporary")).unwrap());
    assert_eq!(
        heap.get_property(object, &key("temporary")).unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn missing_property_deletion_succeeds_without_shape_change() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();

    assert!(heap.delete_property(object, &key("missing")).unwrap());
    assert!(heap.get_own_property_names(object).unwrap().is_empty());
}

#[test]
fn non_configurable_property_deletion_fails() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("pinned"),
        data_descriptor(int_value(9), true, true, false),
    )
    .unwrap();

    assert!(!heap.delete_property(object, &key("pinned")).unwrap());
    assert!(heap.has_own(object, &key("pinned")).unwrap());
}

#[test]
fn prevent_extensions_rejects_new_set_property() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();

    assert!(heap.prevent_extensions(object).unwrap());

    assert!(!heap.set_property(object, key("new"), int_value(1)).unwrap());
    assert!(!heap.has_own(object, &key("new")).unwrap());
}

#[test]
fn prevent_extensions_allows_existing_writable_update() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.set_property(object, key("existing"), int_value(1))
        .unwrap();
    heap.prevent_extensions(object).unwrap();

    assert!(
        heap.set_property(object, key("existing"), int_value(2))
            .unwrap()
    );

    assert_eq!(
        heap.get_property(object, &key("existing")).unwrap(),
        int_value(2)
    );
}

#[test]
fn prevent_extensions_rejects_define_new_property() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.prevent_extensions(object).unwrap();

    assert!(
        !heap
            .define_property(
                object,
                key("new"),
                data_descriptor(int_value(1), true, true, true),
            )
            .unwrap()
    );
}

#[test]
fn set_property_creates_own_shadow_without_mutating_prototype() {
    let mut heap = ObjectHeap::new();
    let prototype = heap.alloc_plain();
    heap.set_property(prototype, key("shared"), str_value("proto"))
        .unwrap();
    let object = heap.alloc(Some(prototype));

    assert!(
        heap.set_property(object, key("shared"), str_value("own"))
            .unwrap()
    );

    assert_eq!(
        heap.get_property(object, &key("shared")).unwrap(),
        str_value("own")
    );
    assert_eq!(
        heap.get_property(prototype, &key("shared")).unwrap(),
        str_value("proto")
    );
}

#[test]
fn inherited_non_writable_property_blocks_shadow_assignment() {
    let mut heap = ObjectHeap::new();
    let prototype = heap.alloc_plain();
    heap.define_property(
        prototype,
        key("locked"),
        data_descriptor(int_value(1), false, true, true),
    )
    .unwrap();
    let object = heap.alloc(Some(prototype));

    assert!(
        !heap
            .set_property(object, key("locked"), int_value(2))
            .unwrap()
    );

    assert!(!heap.has_own(object, &key("locked")).unwrap());
    assert_eq!(
        heap.get_property(object, &key("locked")).unwrap(),
        int_value(1)
    );
}

#[test]
fn get_property_walks_prototype_chain_to_root() {
    let mut heap = ObjectHeap::new();
    let root = heap.alloc_plain();
    heap.set_property(root, key("root"), str_value("root"))
        .unwrap();
    let middle = heap.alloc(Some(root));
    heap.set_property(middle, key("middle"), str_value("middle"))
        .unwrap();
    let leaf = heap.alloc(Some(middle));

    assert_eq!(
        heap.get_property(leaf, &key("root")).unwrap(),
        str_value("root")
    );
    assert_eq!(
        heap.get_property(leaf, &key("middle")).unwrap(),
        str_value("middle")
    );
}

#[test]
fn has_property_walks_chain_but_has_own_stays_local() {
    let mut heap = ObjectHeap::new();
    let prototype = heap.alloc_plain();
    heap.set_property(prototype, key("inherited"), int_value(1))
        .unwrap();
    let object = heap.alloc(Some(prototype));

    assert!(heap.has_property(object, &key("inherited")).unwrap());
    assert!(!heap.has_own(object, &key("inherited")).unwrap());
}

#[test]
fn delete_own_shadow_reveals_prototype_property() {
    let mut heap = ObjectHeap::new();
    let prototype = heap.alloc_plain();
    heap.set_property(prototype, key("name"), str_value("proto"))
        .unwrap();
    let object = heap.alloc(Some(prototype));
    heap.set_property(object, key("name"), str_value("own"))
        .unwrap();

    assert!(heap.delete_property(object, &key("name")).unwrap());

    assert_eq!(
        heap.get_property(object, &key("name")).unwrap(),
        str_value("proto")
    );
}

#[test]
fn set_prototype_rejects_cycles() {
    let mut heap = ObjectHeap::new();
    let parent = heap.alloc_plain();
    let child = heap.alloc(Some(parent));

    let result = heap.set_prototype_of(parent, Some(child));

    assert!(matches!(result, Err(ObjectError::PrototypeCycleDetected)));
}

#[test]
fn set_prototype_on_non_extensible_allows_same_only() {
    let mut heap = ObjectHeap::new();
    let prototype = heap.alloc_plain();
    let other = heap.alloc_plain();
    let object = heap.alloc(Some(prototype));
    heap.prevent_extensions(object).unwrap();

    assert!(heap.set_prototype_of(object, Some(prototype)).unwrap());
    assert!(!heap.set_prototype_of(object, Some(other)).unwrap());
    assert_eq!(heap.get_prototype_of(object).unwrap(), Some(prototype));
}

#[test]
fn own_property_names_use_deterministic_integer_then_string_order() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    for name in ["zeta", "2", "alpha", "10", "1", "4294967295"] {
        heap.set_property(object, key(name), str_value(name))
            .unwrap();
    }

    assert_eq!(
        heap.get_own_property_names(object).unwrap(),
        vec!["1", "2", "10", "4294967295", "alpha", "zeta"]
    );
}

#[test]
fn own_property_symbols_return_symbol_keys_in_symbol_order() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        PropertyKey::Symbol(SymbolId(22)),
        data_descriptor(str_value("second"), true, true, true),
    )
    .unwrap();
    heap.define_property(
        object,
        PropertyKey::Symbol(SymbolId(14)),
        data_descriptor(str_value("first"), true, true, true),
    )
    .unwrap();

    assert_eq!(
        heap.get_own_property_symbols(object).unwrap(),
        vec![SymbolId(14), SymbolId(22)]
    );
}

#[test]
fn get_own_property_descriptors_follow_own_key_order() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    for name in ["beta", "1", "alpha"] {
        heap.set_property(object, key(name), str_value(name))
            .unwrap();
    }

    let keys: Vec<PropertyKey> = heap
        .get_own_property_descriptors(object)
        .unwrap()
        .into_iter()
        .map(|(name, _)| name)
        .collect();

    assert_eq!(keys, vec![key("1"), key("alpha"), key("beta")]);
}

#[test]
fn keys_filters_to_enumerable_string_properties() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("visible"),
        data_descriptor(int_value(1), true, true, true),
    )
    .unwrap();
    heap.define_property(
        object,
        key("hidden"),
        data_descriptor(int_value(2), true, false, true),
    )
    .unwrap();
    heap.define_property(
        object,
        PropertyKey::Symbol(SymbolId(14)),
        data_descriptor(int_value(3), true, true, true),
    )
    .unwrap();

    assert_eq!(heap.keys(object).unwrap(), vec!["visible"]);
}

#[test]
fn values_follow_key_order_and_skip_non_enumerable() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("b"),
        data_descriptor(str_value("b"), true, true, true),
    )
    .unwrap();
    heap.define_property(
        object,
        key("a"),
        data_descriptor(str_value("a"), true, true, true),
    )
    .unwrap();
    heap.define_property(
        object,
        key("hidden"),
        data_descriptor(str_value("hidden"), true, false, true),
    )
    .unwrap();

    assert_eq!(
        heap.values(object).unwrap(),
        vec![str_value("a"), str_value("b")]
    );
}

#[test]
fn entries_follow_key_order_and_skip_symbols() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.set_property(object, key("b"), int_value(2)).unwrap();
    heap.set_property(object, key("a"), int_value(1)).unwrap();
    heap.define_property(
        object,
        PropertyKey::Symbol(SymbolId(14)),
        data_descriptor(int_value(3), true, true, true),
    )
    .unwrap();

    assert_eq!(
        heap.entries(object).unwrap(),
        vec![
            ("a".to_string(), int_value(1)),
            ("b".to_string(), int_value(2)),
        ]
    );
}

#[test]
fn for_in_keys_includes_enumerable_prototypes_after_own_keys() {
    let mut heap = ObjectHeap::new();
    let root = heap.alloc_plain();
    heap.set_property(root, key("root"), int_value(1)).unwrap();
    let prototype = heap.alloc(Some(root));
    heap.set_property(prototype, key("middle"), int_value(2))
        .unwrap();
    let object = heap.alloc(Some(prototype));
    heap.set_property(object, key("own"), int_value(3)).unwrap();

    assert_eq!(
        heap.for_in_keys(object).unwrap(),
        vec!["own", "middle", "root"]
    );
}

#[test]
fn for_in_keys_skips_shadowed_prototype_key() {
    let mut heap = ObjectHeap::new();
    let prototype = heap.alloc_plain();
    heap.set_property(prototype, key("shared"), int_value(1))
        .unwrap();
    heap.set_property(prototype, key("proto_only"), int_value(2))
        .unwrap();
    let object = heap.alloc(Some(prototype));
    heap.define_property(
        object,
        key("shared"),
        data_descriptor(int_value(3), true, false, true),
    )
    .unwrap();

    assert_eq!(heap.for_in_keys(object).unwrap(), vec!["proto_only"]);
}

#[test]
fn freeze_makes_data_properties_non_writable_and_non_configurable() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.set_property(object, key("value"), int_value(1))
        .unwrap();

    heap.freeze(object).unwrap();

    assert!(heap.is_frozen(object).unwrap());
    assert!(
        !heap
            .set_property(object, key("value"), int_value(2))
            .unwrap()
    );
    assert!(!heap.delete_property(object, &key("value")).unwrap());
    assert_data_descriptor(
        &own_descriptor(&heap, object, "value"),
        int_value(1),
        false,
        true,
        false,
    );
}

#[test]
fn seal_preserves_writable_but_blocks_delete_and_new_properties() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.set_property(object, key("value"), int_value(1))
        .unwrap();

    heap.seal(object).unwrap();

    assert!(heap.is_sealed(object).unwrap());
    assert!(
        heap.set_property(object, key("value"), int_value(2))
            .unwrap()
    );
    assert!(!heap.delete_property(object, &key("value")).unwrap());
    assert!(!heap.set_property(object, key("new"), int_value(3)).unwrap());
    assert_eq!(
        heap.get_property(object, &key("value")).unwrap(),
        int_value(2)
    );
}

#[test]
fn assign_copies_only_enumerable_own_data_properties() {
    let mut heap = ObjectHeap::new();
    let source_prototype = heap.alloc_plain();
    heap.set_property(source_prototype, key("inherited"), int_value(9))
        .unwrap();
    let source = heap.alloc(Some(source_prototype));
    heap.set_property(source, key("visible"), int_value(1))
        .unwrap();
    heap.define_property(
        source,
        key("hidden"),
        data_descriptor(int_value(2), true, false, true),
    )
    .unwrap();
    let target = heap.alloc_plain();

    heap.assign(target, &[source]).unwrap();

    assert_eq!(
        heap.get_own_property_names(target).unwrap(),
        vec!["visible"]
    );
    assert_eq!(
        heap.get_property(target, &key("visible")).unwrap(),
        int_value(1)
    );
}

#[test]
fn from_entries_creates_plain_extensible_object_with_entries() {
    let mut heap = ObjectHeap::new();

    let object = heap.from_entries(vec![
        ("beta".to_string(), int_value(2)),
        ("alpha".to_string(), int_value(1)),
    ]);

    assert!(heap.is_extensible(object).unwrap());
    assert_eq!(
        heap.entries(object).unwrap(),
        vec![
            ("alpha".to_string(), int_value(1)),
            ("beta".to_string(), int_value(2)),
        ]
    );
}

#[test]
fn define_properties_stops_at_first_rejected_descriptor() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("locked"),
        data_descriptor(int_value(1), false, true, false),
    )
    .unwrap();

    assert!(
        !heap
            .define_properties(
                object,
                vec![
                    (
                        key("locked"),
                        data_descriptor(int_value(2), false, true, false),
                    ),
                    (
                        key("after"),
                        data_descriptor(int_value(3), true, true, true)
                    ),
                ],
            )
            .unwrap()
    );

    assert!(!heap.has_own(object, &key("after")).unwrap());
}

#[test]
fn heap_serialization_preserves_property_descriptor_shape() {
    let mut heap = ObjectHeap::new();
    let object = heap.alloc_plain();
    heap.define_property(
        object,
        key("persisted"),
        data_descriptor(str_value("value"), false, false, false),
    )
    .unwrap();
    heap.define_property(
        object,
        PropertyKey::Symbol(SymbolId(14)),
        data_descriptor(int_value(14), true, true, true),
    )
    .unwrap();

    let json = serde_json::to_string(&heap).expect("heap should serialize");
    let restored: ObjectHeap = serde_json::from_str(&json).expect("heap should deserialize");

    assert_data_descriptor(
        &own_descriptor(&restored, object, "persisted"),
        str_value("value"),
        false,
        false,
        false,
    );
    assert_eq!(
        restored.get_own_property_symbols(object).unwrap(),
        vec![SymbolId(14)]
    );
}
