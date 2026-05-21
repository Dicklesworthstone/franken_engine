//! Class semantics boundary tests for franken-core object model.
//!
//! Tests the ES2020 object model class semantics implementation through the public API.
//! Focuses on constructor allocation, prototype chain management, property descriptors,
//! and class inheritance patterns using franken-core's boundary interface.

use frankenengine_core::object_model::{
    JsValue, ManagedObject, ObjectError, ObjectHandle, ObjectHeap, OrdinaryObject,
    PropertyDescriptor, PropertyKey, ProxyInvariantChecker, ProxyObject, Reflect,
    ReflectApplyRequest, ReflectConstructRequest, SymbolId, SymbolRegistry, WellKnownSymbol,
};

// Helper functions for test clarity
fn str_key(s: &str) -> PropertyKey {
    PropertyKey::String(s.to_string())
}

fn int_val(n: i64) -> JsValue {
    JsValue::Int(n)
}

fn str_val(s: &str) -> JsValue {
    JsValue::Str(s.to_string())
}

// ---------------------------------------------------------------------------
// 1. Constructor allocation and properties
// ---------------------------------------------------------------------------

#[test]
fn alloc_constructor_creates_constructable_callable() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);

    let obj = heap.get(ctor).unwrap().as_ordinary().unwrap();
    assert!(obj.callable, "constructor must be callable");
    assert!(obj.constructable, "constructor must be constructable");
    assert_eq!(obj.prototype, None, "no prototype specified");
    assert!(obj.extensible, "constructors start extensible");
}

#[test]
fn alloc_constructor_with_prototype() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let ctor = heap.alloc_constructor(Some(proto));

    let obj = heap.get(ctor).unwrap().as_ordinary().unwrap();
    assert_eq!(obj.prototype, Some(proto), "prototype chain established");
    assert!(obj.callable && obj.constructable);
}

#[test]
fn constructor_property_definition() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);

    // Define constructor.prototype property
    let proto_obj = heap.alloc_plain();
    heap.set_property(ctor, str_key("prototype"), JsValue::Object(proto_obj))
        .unwrap();

    // Define constructor.name property
    heap.define_property(
        ctor,
        str_key("name"),
        PropertyDescriptor::Data {
            value: str_val("MyClass"),
            writable: false,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    assert_eq!(
        heap.get_property(ctor, &str_key("prototype")).unwrap(),
        JsValue::Object(proto_obj)
    );
    assert_eq!(
        heap.get_property(ctor, &str_key("name")).unwrap(),
        str_val("MyClass")
    );
}

#[test]
fn constructor_length_property() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);

    // Define constructor.length (arity)
    heap.define_property(
        ctor,
        str_key("length"),
        PropertyDescriptor::Data {
            value: int_val(2),
            writable: false,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    let desc = heap
        .get_own_property_descriptor(ctor, &str_key("length"))
        .unwrap()
        .unwrap();
    assert_eq!(desc.value().unwrap(), &int_val(2));
    assert!(!desc.is_writable());
    assert!(!desc.is_enumerable());
}

// ---------------------------------------------------------------------------
// 2. Class prototype chain management
// ---------------------------------------------------------------------------

#[test]
fn class_prototype_chain_basic() {
    let mut heap = ObjectHeap::new();

    // Create Function.prototype (base for all constructors)
    let function_proto = heap.alloc_plain();

    // Create Object.prototype (base for all instances)
    let object_proto = heap.alloc_plain();

    // Create MyClass constructor
    let my_class = heap.alloc_constructor(Some(function_proto));

    // Create MyClass.prototype
    let my_class_proto = heap.alloc(Some(object_proto));
    heap.set_property(
        my_class,
        str_key("prototype"),
        JsValue::Object(my_class_proto),
    )
    .unwrap();

    // Verify prototype chain
    assert_eq!(
        heap.get_prototype_of(my_class).unwrap(),
        Some(function_proto)
    );
    assert_eq!(
        heap.get_prototype_of(my_class_proto).unwrap(),
        Some(object_proto)
    );
    assert_eq!(heap.get_prototype_of(object_proto).unwrap(), None);
}

#[test]
fn prototype_chain_property_lookup() {
    let mut heap = ObjectHeap::new();

    // Create prototype chain: instance -> MyClass.prototype -> Object.prototype
    let object_proto = heap.alloc_plain();
    heap.set_property(
        object_proto,
        str_key("toString"),
        str_val("[object Object]"),
    )
    .unwrap();

    let class_proto = heap.alloc(Some(object_proto));
    heap.set_property(class_proto, str_key("myMethod"), str_val("custom"))
        .unwrap();

    let instance = heap.alloc(Some(class_proto));
    heap.set_property(instance, str_key("ownProp"), str_val("own"))
        .unwrap();

    // Test property resolution
    assert_eq!(
        heap.get_property(instance, &str_key("ownProp")).unwrap(),
        str_val("own")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("myMethod")).unwrap(),
        str_val("custom")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("toString")).unwrap(),
        str_val("[object Object]")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("nonexistent"))
            .unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn prototype_chain_has_property() {
    let mut heap = ObjectHeap::new();

    let proto = heap.alloc_plain();
    heap.set_property(proto, str_key("inherited"), int_val(1))
        .unwrap();

    let instance = heap.alloc(Some(proto));
    heap.set_property(instance, str_key("own"), int_val(2))
        .unwrap();

    assert!(heap.has_property(instance, &str_key("own")).unwrap());
    assert!(heap.has_property(instance, &str_key("inherited")).unwrap());
    assert!(!heap.has_property(instance, &str_key("missing")).unwrap());
}

#[test]
fn prototype_chain_cycle_prevention() {
    let mut heap = ObjectHeap::new();

    let a = heap.alloc_plain();
    let b = heap.alloc(Some(a));

    // Attempt to create cycle: a -> b -> a
    let result = heap.set_prototype_of(a, Some(b));
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ObjectError::PrototypeCycleDetected
    ));
}

// ---------------------------------------------------------------------------
// 3. Property descriptor handling for class properties
// ---------------------------------------------------------------------------

#[test]
fn class_method_property_descriptors() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();

    // Define method as non-enumerable (ES class semantics)
    heap.define_property(
        proto,
        str_key("method"),
        PropertyDescriptor::Data {
            value: str_val("function"),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    // Define accessor property
    let getter = heap.alloc_callable(None);
    heap.define_property(
        proto,
        str_key("accessor"),
        PropertyDescriptor::Accessor {
            get: Some(getter),
            set: None,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    let desc = heap
        .get_own_property_descriptor(proto, &str_key("method"))
        .unwrap()
        .unwrap();
    assert!(desc.is_data());
    assert!(!desc.is_enumerable());

    let acc_desc = heap
        .get_own_property_descriptor(proto, &str_key("accessor"))
        .unwrap()
        .unwrap();
    assert!(acc_desc.is_accessor());
    assert!(!acc_desc.is_enumerable());
}

#[test]
fn class_property_enumeration() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();

    // Instance property (enumerable)
    heap.set_property(obj, str_key("instanceProp"), int_val(1))
        .unwrap();

    // Method (non-enumerable, like ES classes)
    heap.define_property(
        obj,
        str_key("method"),
        PropertyDescriptor::Data {
            value: str_val("fn"),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    let keys = heap.keys(obj).unwrap();
    assert_eq!(keys, vec!["instanceProp".to_string()]);

    let names = heap.get_own_property_names(obj).unwrap();
    assert!(names.contains(&"instanceProp".to_string()));
    assert!(names.contains(&"method".to_string()));
    assert_eq!(names.len(), 2);
}

#[test]
fn class_property_configuration() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();

    // Non-configurable property (like some built-in class properties)
    heap.define_property(
        obj,
        str_key("constant"),
        PropertyDescriptor::Data {
            value: int_val(42),
            writable: false,
            enumerable: false,
            configurable: false,
        },
    )
    .unwrap();

    // Attempt to delete non-configurable property
    assert!(!heap.delete_property(obj, &str_key("constant")).unwrap());

    // Attempt to redefine non-configurable property
    let redefined = heap
        .define_property(
            obj,
            str_key("constant"),
            PropertyDescriptor::Data {
                value: int_val(99),
                writable: false,
                enumerable: false,
                configurable: false,
            },
        )
        .unwrap();
    assert!(!redefined);
}

// ---------------------------------------------------------------------------
// 4. Class inheritance patterns
// ---------------------------------------------------------------------------

#[test]
fn class_inheritance_constructor_chain() {
    let mut heap = ObjectHeap::new();

    // Base class: Function.prototype
    let function_proto = heap.alloc_plain();

    // Object constructor (root)
    let object_ctor = heap.alloc_constructor(Some(function_proto));

    // Custom base class
    let base_class = heap.alloc_constructor(Some(object_ctor));

    // Derived class
    let derived_class = heap.alloc_constructor(Some(base_class));

    // Verify constructor inheritance chain
    assert_eq!(
        heap.get_prototype_of(derived_class).unwrap(),
        Some(base_class)
    );
    assert_eq!(
        heap.get_prototype_of(base_class).unwrap(),
        Some(object_ctor)
    );
    assert_eq!(
        heap.get_prototype_of(object_ctor).unwrap(),
        Some(function_proto)
    );
}

#[test]
fn class_inheritance_instance_chain() {
    let mut heap = ObjectHeap::new();

    // Create inheritance chain for instances
    let object_proto = heap.alloc_plain();
    heap.set_property(object_proto, str_key("toString"), str_val("base"))
        .unwrap();

    let base_proto = heap.alloc(Some(object_proto));
    heap.set_property(base_proto, str_key("baseMethod"), str_val("base"))
        .unwrap();

    let derived_proto = heap.alloc(Some(base_proto));
    heap.set_property(derived_proto, str_key("derivedMethod"), str_val("derived"))
        .unwrap();

    // Instance inherits from derived prototype
    let instance = heap.alloc(Some(derived_proto));
    heap.set_property(instance, str_key("instanceProp"), str_val("own"))
        .unwrap();

    // Verify inheritance chain resolution
    assert_eq!(
        heap.get_property(instance, &str_key("instanceProp"))
            .unwrap(),
        str_val("own")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("derivedMethod"))
            .unwrap(),
        str_val("derived")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("baseMethod")).unwrap(),
        str_val("base")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("toString")).unwrap(),
        str_val("base")
    );
}

#[test]
fn class_inheritance_method_override() {
    let mut heap = ObjectHeap::new();

    // Base class prototype with method
    let base_proto = heap.alloc_plain();
    heap.set_property(base_proto, str_key("method"), str_val("base"))
        .unwrap();

    // Derived class prototype overrides method
    let derived_proto = heap.alloc(Some(base_proto));
    heap.set_property(derived_proto, str_key("method"), str_val("derived"))
        .unwrap();

    let instance = heap.alloc(Some(derived_proto));

    // Override takes precedence
    assert_eq!(
        heap.get_property(instance, &str_key("method")).unwrap(),
        str_val("derived")
    );
}

#[test]
fn class_inheritance_super_method_access() {
    let mut heap = ObjectHeap::new();

    // Base class with method
    let base_proto = heap.alloc_plain();
    heap.set_property(base_proto, str_key("greet"), str_val("Hello"))
        .unwrap();

    // Derived class with own method but can still access base
    let derived_proto = heap.alloc(Some(base_proto));
    heap.set_property(derived_proto, str_key("greetFormal"), str_val("Good day"))
        .unwrap();

    let instance = heap.alloc(Some(derived_proto));

    // Instance can access both own and inherited methods
    assert_eq!(
        heap.get_property(instance, &str_key("greet")).unwrap(),
        str_val("Hello")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("greetFormal"))
            .unwrap(),
        str_val("Good day")
    );

    // Base prototype method is still accessible through prototype chain
    assert_eq!(
        heap.get_property(base_proto, &str_key("greet")).unwrap(),
        str_val("Hello")
    );
}

// ---------------------------------------------------------------------------
// 5. Reflect operations for class construction
// ---------------------------------------------------------------------------

#[test]
fn reflect_construct_basic_class() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);

    let request = Reflect::construct(&heap, ctor, vec![int_val(42)], None).unwrap();

    assert_eq!(request.target, ctor);
    assert_eq!(request.new_target, ctor);
    assert_eq!(request.arguments, vec![int_val(42)]);
}

#[test]
fn reflect_construct_with_new_target() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);
    let new_target = heap.alloc_constructor(None);

    let request = Reflect::construct(&heap, ctor, vec![], Some(new_target)).unwrap();

    assert_eq!(request.target, ctor);
    assert_eq!(request.new_target, new_target);
}

#[test]
fn reflect_construct_non_constructor_error() {
    let mut heap = ObjectHeap::new();
    let func = heap.alloc_callable(None); // callable but not constructable

    let result = Reflect::construct(&heap, func, vec![], None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ObjectError::TypeError(_)));
}

#[test]
fn reflect_construct_invalid_new_target() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);
    let non_ctor = heap.alloc_plain();

    let result = Reflect::construct(&heap, ctor, vec![], Some(non_ctor));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ObjectError::TypeError(_)));
}

#[test]
fn reflect_apply_class_method() {
    let mut heap = ObjectHeap::new();
    let method = heap.alloc_callable(None);
    let this_arg = heap.alloc_plain();

    let request = Reflect::apply(
        &heap,
        method,
        JsValue::Object(this_arg),
        vec![str_val("arg1"), int_val(42)],
    )
    .unwrap();

    assert_eq!(request.target, method);
    assert_eq!(request.this_arg, JsValue::Object(this_arg));
    assert_eq!(request.arguments.len(), 2);
}

#[test]
fn reflect_apply_non_callable_error() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();

    let result = Reflect::apply(&heap, obj, JsValue::Undefined, vec![]);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ObjectError::TypeError(_)));
}

// ---------------------------------------------------------------------------
// 6. Symbol properties in class definitions
// ---------------------------------------------------------------------------

#[test]
fn class_well_known_symbol_properties() {
    let mut heap = ObjectHeap::new();
    let class_proto = heap.alloc_plain();

    // Define Symbol.iterator method
    heap.define_property(
        class_proto,
        WellKnownSymbol::Iterator.key(),
        PropertyDescriptor::Data {
            value: str_val("iterator function"),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    // Define Symbol.toStringTag
    heap.define_property(
        class_proto,
        WellKnownSymbol::ToStringTag.key(),
        PropertyDescriptor::Data {
            value: str_val("MyClass"),
            writable: false,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    let iterator_val = heap
        .get_property(class_proto, &WellKnownSymbol::Iterator.key())
        .unwrap();
    assert_eq!(iterator_val, str_val("iterator function"));

    let tag_val = heap
        .get_property(class_proto, &WellKnownSymbol::ToStringTag.key())
        .unwrap();
    assert_eq!(tag_val, str_val("MyClass"));
}

#[test]
fn class_symbol_enumeration() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();

    // Add string and symbol properties
    heap.set_property(obj, str_key("stringProp"), int_val(1))
        .unwrap();
    heap.define_property(
        obj,
        WellKnownSymbol::Iterator.key(),
        PropertyDescriptor::data(str_val("fn")),
    )
    .unwrap();

    // String keys only in enumeration
    let keys = heap.keys(obj).unwrap();
    assert_eq!(keys, vec!["stringProp".to_string()]);

    // Symbol keys separate
    let symbols = heap.get_own_property_symbols(obj).unwrap();
    assert_eq!(symbols, vec![WellKnownSymbol::Iterator.id()]);

    // Both in own property keys
    let all_keys = heap.get_own_property_descriptors(obj).unwrap();
    assert_eq!(all_keys.len(), 2);
}

// ---------------------------------------------------------------------------
// 7. Proxy wrapper behavior for class objects
// ---------------------------------------------------------------------------

#[test]
fn proxy_wrapped_constructor() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_constructor(None);
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    // Proxy is properly created
    let proxy_obj = heap.get(proxy).unwrap().as_proxy().unwrap();
    assert_eq!(proxy_obj.target().unwrap(), target);
    assert_eq!(proxy_obj.handler().unwrap(), handler);
    assert!(!proxy_obj.is_revoked());
}

#[test]
fn proxy_constructor_revocation() {
    let mut heap = ObjectHeap::new();
    let target = heap.alloc_constructor(None);
    let handler = heap.alloc_plain();
    let proxy = heap.alloc_proxy(target, handler);

    heap.revoke_proxy(proxy).unwrap();

    let proxy_obj = heap.get(proxy).unwrap().as_proxy().unwrap();
    assert!(proxy_obj.is_revoked());
    assert!(proxy_obj.target().is_err());
    assert!(proxy_obj.handler().is_err());
}

#[test]
fn proxy_invariant_constructor_property() {
    let mut target = OrdinaryObject::default();
    target.constructable = true;
    target
        .define_own_property(
            str_key("length"),
            PropertyDescriptor::Data {
                value: int_val(2),
                writable: false,
                enumerable: false,
                configurable: false,
            },
        )
        .unwrap();

    // Non-configurable non-writable property must return same value
    assert!(ProxyInvariantChecker::check_get(&target, &str_key("length"), &int_val(2)).is_ok());
    assert!(ProxyInvariantChecker::check_get(&target, &str_key("length"), &int_val(3)).is_err());
}

// ---------------------------------------------------------------------------
// 8. Class property descriptor edge cases
// ---------------------------------------------------------------------------

#[test]
fn class_frozen_constructor() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);

    // Add properties before freezing
    heap.set_property(ctor, str_key("name"), str_val("MyClass"))
        .unwrap();
    heap.set_property(ctor, str_key("length"), int_val(1))
        .unwrap();

    heap.freeze(ctor).unwrap();

    // Cannot modify frozen constructor
    assert!(
        !heap
            .set_property(ctor, str_key("name"), str_val("Other"))
            .unwrap()
    );
    assert!(
        !heap
            .set_property(ctor, str_key("newProp"), int_val(1))
            .unwrap()
    );

    assert!(heap.is_frozen(ctor).unwrap());
    assert!(heap.is_sealed(ctor).unwrap());
}

#[test]
fn class_sealed_prototype() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();

    // Add methods before sealing
    heap.set_property(proto, str_key("method1"), str_val("fn1"))
        .unwrap();
    heap.set_property(proto, str_key("method2"), str_val("fn2"))
        .unwrap();

    heap.seal(proto).unwrap();

    // Can modify existing properties but cannot add/delete
    assert!(
        heap.set_property(proto, str_key("method1"), str_val("updated"))
            .unwrap()
    );
    assert!(
        !heap
            .set_property(proto, str_key("method3"), str_val("fn3"))
            .unwrap()
    );
    assert!(!heap.delete_property(proto, &str_key("method1")).unwrap());

    assert!(heap.is_sealed(proto).unwrap());
    assert!(!heap.is_frozen(proto).unwrap());
}

#[test]
fn class_accessor_property_definition() {
    let mut heap = ObjectHeap::new();
    let proto = heap.alloc_plain();
    let getter = heap.alloc_callable(None);
    let setter = heap.alloc_callable(None);

    // Define getter/setter pair
    heap.define_property(
        proto,
        str_key("accessor"),
        PropertyDescriptor::Accessor {
            get: Some(getter),
            set: Some(setter),
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    let desc = heap
        .get_own_property_descriptor(proto, &str_key("accessor"))
        .unwrap()
        .unwrap();
    assert!(desc.is_accessor());
    assert!(!desc.is_enumerable());
    assert!(desc.is_configurable());

    // Getter returns object handle per object model semantics
    let value = heap.get_property(proto, &str_key("accessor")).unwrap();
    assert_eq!(value, JsValue::Object(getter));
}

#[test]
fn class_property_redefinition() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();

    // Initially data property
    heap.define_property(
        obj,
        str_key("prop"),
        PropertyDescriptor::data(str_val("data")),
    )
    .unwrap();

    // Redefine as accessor (allowed when configurable)
    let getter = heap.alloc_callable(None);
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

    let desc = heap
        .get_own_property_descriptor(obj, &str_key("prop"))
        .unwrap()
        .unwrap();
    assert!(desc.is_accessor());
}

// ---------------------------------------------------------------------------
// 9. Error conditions and edge cases
// ---------------------------------------------------------------------------

#[test]
fn deep_prototype_chain_depth_limit() {
    let mut heap = ObjectHeap::new();

    // Create a very deep chain to test depth limits
    let mut current = heap.alloc_plain();
    for _i in 0..10 {
        let next = heap.alloc(Some(current));
        current = next;
    }

    // Should still work within reasonable limits
    assert_eq!(
        heap.get_property(current, &str_key("test")).unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn non_extensible_class_behavior() {
    let mut heap = ObjectHeap::new();
    let ctor = heap.alloc_constructor(None);

    // Add essential properties
    heap.set_property(ctor, str_key("name"), str_val("MyClass"))
        .unwrap();
    heap.set_property(ctor, str_key("length"), int_val(0))
        .unwrap();

    heap.prevent_extensions(ctor).unwrap();

    // Cannot add new properties
    assert!(
        !heap
            .set_property(ctor, str_key("newProp"), int_val(1))
            .unwrap()
    );

    // Can still modify existing writable properties
    assert!(
        heap.set_property(ctor, str_key("name"), str_val("RenamedClass"))
            .unwrap()
    );

    assert!(!heap.is_extensible(ctor).unwrap());
}

#[test]
fn invalid_object_handle_error() {
    let heap = ObjectHeap::new();
    let invalid_handle = ObjectHandle(999);

    let result = heap.get(invalid_handle);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ObjectError::ObjectNotFound(_)
    ));
}

#[test]
fn property_key_ordering_in_class() {
    let mut heap = ObjectHeap::new();
    let obj = heap.alloc_plain();

    // Add properties in mixed order
    heap.set_property(obj, str_key("zebra"), str_val("z"))
        .unwrap();
    heap.set_property(obj, str_key("1"), str_val("one"))
        .unwrap();
    heap.set_property(obj, str_key("alpha"), str_val("a"))
        .unwrap();
    heap.set_property(obj, str_key("10"), str_val("ten"))
        .unwrap();
    heap.define_property(
        obj,
        WellKnownSymbol::Iterator.key(),
        PropertyDescriptor::data(str_val("iter")),
    )
    .unwrap();

    let names = heap.get_own_property_names(obj).unwrap();
    // Integer indices come first (sorted), then strings (insertion/BTreeMap order)
    assert!(
        names.iter().position(|x| x == "1").unwrap()
            < names.iter().position(|x| x == "10").unwrap()
    );
    assert!(
        names.iter().position(|x| x == "10").unwrap()
            < names.iter().position(|x| x == "alpha").unwrap()
    );
}

// ---------------------------------------------------------------------------
// 10. Complex integration scenarios
// ---------------------------------------------------------------------------

#[test]
fn complete_class_definition_scenario() {
    let mut heap = ObjectHeap::new();

    // 1. Create Function.prototype
    let function_proto = heap.alloc_plain();

    // 2. Create Object.prototype
    let object_proto = heap.alloc_plain();
    heap.set_property(
        object_proto,
        str_key("toString"),
        str_val("[object Object]"),
    )
    .unwrap();

    // 3. Create MyClass constructor
    let my_class = heap.alloc_constructor(Some(function_proto));
    heap.define_property(
        my_class,
        str_key("name"),
        PropertyDescriptor::Data {
            value: str_val("MyClass"),
            writable: false,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();
    heap.define_property(
        my_class,
        str_key("length"),
        PropertyDescriptor::Data {
            value: int_val(2),
            writable: false,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    // 4. Create MyClass.prototype
    let my_class_proto = heap.alloc(Some(object_proto));
    heap.set_property(
        my_class,
        str_key("prototype"),
        JsValue::Object(my_class_proto),
    )
    .unwrap();
    heap.set_property(
        my_class_proto,
        str_key("constructor"),
        JsValue::Object(my_class),
    )
    .unwrap();

    // 5. Add methods to prototype
    heap.define_property(
        my_class_proto,
        str_key("greet"),
        PropertyDescriptor::Data {
            value: str_val("Hello"),
            writable: true,
            enumerable: false,
            configurable: true,
        },
    )
    .unwrap();

    // 6. Add Symbol.toStringTag
    heap.define_property(
        my_class_proto,
        WellKnownSymbol::ToStringTag.key(),
        PropertyDescriptor::Data {
            value: str_val("MyClass"),
            writable: false,
            enumerable: false,
            configurable: false,
        },
    )
    .unwrap();

    // 7. Create instance
    let instance = heap.alloc(Some(my_class_proto));
    heap.set_property(instance, str_key("name"), str_val("Alice"))
        .unwrap();

    // 8. Verify everything works
    assert_eq!(
        heap.get_property(my_class, &str_key("name")).unwrap(),
        str_val("MyClass")
    );
    assert_eq!(
        heap.get_property(my_class, &str_key("length")).unwrap(),
        int_val(2)
    );
    assert_eq!(
        heap.get_property(instance, &str_key("name")).unwrap(),
        str_val("Alice")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("greet")).unwrap(),
        str_val("Hello")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("toString")).unwrap(),
        str_val("[object Object]")
    );
    assert_eq!(
        heap.get_property(instance, &WellKnownSymbol::ToStringTag.key())
            .unwrap(),
        str_val("MyClass")
    );

    // 9. Verify constructor relationship
    assert_eq!(
        heap.get_property(my_class_proto, &str_key("constructor"))
            .unwrap(),
        JsValue::Object(my_class)
    );

    // 10. Verify prototype chains
    assert_eq!(
        heap.get_prototype_of(instance).unwrap(),
        Some(my_class_proto)
    );
    assert_eq!(
        heap.get_prototype_of(my_class_proto).unwrap(),
        Some(object_proto)
    );
    assert_eq!(
        heap.get_prototype_of(my_class).unwrap(),
        Some(function_proto)
    );
}

#[test]
fn class_inheritance_with_method_dispatch() {
    let mut heap = ObjectHeap::new();

    // Base class
    let base_class = heap.alloc_constructor(None);
    let base_proto = heap.alloc_plain();
    heap.set_property(
        base_class,
        str_key("prototype"),
        JsValue::Object(base_proto),
    )
    .unwrap();
    heap.set_property(base_proto, str_key("baseMethod"), str_val("base"))
        .unwrap();

    // Derived class
    let derived_class = heap.alloc_constructor(Some(base_class));
    let derived_proto = heap.alloc(Some(base_proto));
    heap.set_property(
        derived_class,
        str_key("prototype"),
        JsValue::Object(derived_proto),
    )
    .unwrap();
    heap.set_property(derived_proto, str_key("derivedMethod"), str_val("derived"))
        .unwrap();
    heap.set_property(derived_proto, str_key("baseMethod"), str_val("overridden"))
        .unwrap(); // override

    // Instance
    let instance = heap.alloc(Some(derived_proto));

    // Method resolution: derived takes precedence, but base method still accessible via chain
    assert_eq!(
        heap.get_property(instance, &str_key("baseMethod")).unwrap(),
        str_val("overridden")
    );
    assert_eq!(
        heap.get_property(instance, &str_key("derivedMethod"))
            .unwrap(),
        str_val("derived")
    );

    // Original base method accessible through base prototype
    assert_eq!(
        heap.get_property(base_proto, &str_key("baseMethod"))
            .unwrap(),
        str_val("base")
    );
}
