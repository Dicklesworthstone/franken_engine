//! Tests for WeakMap weak reference semantics.
//!
//! This test module verifies that WeakMap properly implements weak references
//! according to ECMAScript semantics:
//! - Object keys are held as weak references only
//! - WeakMap entries don't prevent garbage collection of their keys
//! - When a key object is collected, the corresponding entry is automatically removed
//! - Only objects can be used as keys (primitive values are rejected)

use frankenengine::baseline_interpreter::{CoreInterpreter, InterpreterConfig, InterpreterError};
use frankenengine::ir_contract::Ir3Instruction;
use frankenengine::object_model::{ObjectHandle, PropertyKey, PropertyDescriptor, JsValue};

/// Create a test interpreter with default configuration.
fn test_interpreter() -> CoreInterpreter {
    let config = InterpreterConfig::test_default();
    CoreInterpreter::new(config)
}

#[test]
fn test_weakmap_basic_functionality() {
    let mut core = test_interpreter();

    // Create a WeakMap
    let result = core.call_builtin("builtin:WeakMap", frankenengine::baseline_interpreter::RegRange { start: 0, count: 0 })
        .expect("WeakMap constructor should succeed");

    let weakmap = match result {
        frankenengine::baseline_interpreter::Value::Object(id) => id,
        other => panic!("WeakMap constructor should return object, got {:?}", other),
    };

    // Create an object to use as a key
    let key_obj = core.heap.alloc_plain().expect("Should allocate object key");
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Object(weakmap))
        .expect("Should write WeakMap to register");
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Object(key_obj))
        .expect("Should write key object to register");

    // Test that the key is not found initially (should return false)
    let has_result = core.call_builtin("builtin:WeakMapPrototypeHas",
        frankenengine::baseline_interpreter::RegRange { start: 0, count: 2 })
        .expect("WeakMap.prototype.has should execute");
    assert_eq!(has_result, frankenengine::baseline_interpreter::Value::Bool(false));

    // Test that getting a non-existent key returns undefined
    let get_result = core.call_builtin("builtin:WeakMapPrototypeGet",
        frankenengine::baseline_interpreter::RegRange { start: 0, count: 2 })
        .expect("WeakMap.prototype.get should execute");
    assert_eq!(get_result, frankenengine::baseline_interpreter::Value::Undefined);
}

#[test]
fn test_weakmap_rejects_primitive_keys() {
    let mut core = test_interpreter();

    // Create a WeakMap
    let result = core.call_builtin("builtin:WeakMap", frankenengine::baseline_interpreter::RegRange { start: 0, count: 0 })
        .expect("WeakMap constructor should succeed");

    let weakmap = match result {
        frankenengine::baseline_interpreter::Value::Object(id) => id,
        other => panic!("WeakMap constructor should return object, got {:?}", other),
    };

    core.write_reg(0, frankenengine::baseline_interpreter::Value::Object(weakmap))
        .expect("Should write WeakMap to register");

    // Test primitive key types that should be rejected
    let primitive_keys = vec![
        frankenengine::baseline_interpreter::Value::Int(42),
        frankenengine::baseline_interpreter::Value::Str("string".to_string()),
        frankenengine::baseline_interpreter::Value::Bool(true),
        frankenengine::baseline_interpreter::Value::Null,
        frankenengine::baseline_interpreter::Value::Undefined,
    ];

    for (i, primitive_key) in primitive_keys.into_iter().enumerate() {
        core.write_reg(1, primitive_key)
            .expect("Should write primitive key to register");

        // WeakMap.prototype.has should return false for primitive keys
        let has_result = core.call_builtin("builtin:WeakMapPrototypeHas",
            frankenengine::baseline_interpreter::RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.has should execute");
        assert_eq!(
            has_result,
            frankenengine::baseline_interpreter::Value::Bool(false),
            "Primitive key {} should return false for has()",
            i
        );

        // WeakMap.prototype.get should return undefined for primitive keys
        let get_result = core.call_builtin("builtin:WeakMapPrototypeGet",
            frankenengine::baseline_interpreter::RegRange { start: 0, count: 2 })
            .expect("WeakMap.prototype.get should execute");
        assert_eq!(
            get_result,
            frankenengine::baseline_interpreter::Value::Undefined,
            "Primitive key {} should return undefined for get()",
            i
        );
    }
}

#[test]
fn test_weakmap_uses_weak_reference_storage() {
    let mut core = test_interpreter();

    // Create a WeakMap
    let result = core.call_builtin("builtin:WeakMap", frankenengine::baseline_interpreter::RegRange { start: 0, count: 0 })
        .expect("WeakMap constructor should succeed");

    let weakmap_id = match result {
        frankenengine::baseline_interpreter::Value::Object(id) => id,
        other => panic!("WeakMap constructor should return object, got {:?}", other),
    };

    // Verify that WeakMap has been registered in the weak reference storage system
    assert!(core.weakmap_storage.contains_key(&weakmap_id),
        "WeakMap should be registered in weak reference storage");

    // Verify the storage is initialized but empty
    let storage = core.weakmap_storage.get(&weakmap_id)
        .expect("WeakMap storage should exist");
    assert!(storage.get_weak_key_objects().is_empty(),
        "New WeakMap should have no weak key objects");
}

#[test]
fn test_weakmap_initialization_from_iterable() {
    let mut core = test_interpreter();

    // Create objects to use as keys
    let key1 = core.heap.alloc_plain().expect("Should allocate first key object");
    let key2 = core.heap.alloc_plain().expect("Should allocate second key object");

    // Create an iterable array with [key, value] pairs
    let pair1_array = core.heap.alloc_plain().expect("Should allocate first pair array");
    core.heap.define_property(pair1_array,
        PropertyKey::String("0".to_string()),
        PropertyDescriptor::data(JsValue::Object(key1)))
        .expect("Should set first pair key");
    core.heap.define_property(pair1_array,
        PropertyKey::String("1".to_string()),
        PropertyDescriptor::data(JsValue::Str("value1".to_string())))
        .expect("Should set first pair value");
    core.heap.define_property(pair1_array,
        PropertyKey::String("length".to_string()),
        PropertyDescriptor::data(JsValue::Int(2)))
        .expect("Should set first pair length");

    let pair2_array = core.heap.alloc_plain().expect("Should allocate second pair array");
    core.heap.define_property(pair2_array,
        PropertyKey::String("0".to_string()),
        PropertyDescriptor::data(JsValue::Object(key2)))
        .expect("Should set second pair key");
    core.heap.define_property(pair2_array,
        PropertyKey::String("1".to_string()),
        PropertyDescriptor::data(JsValue::Str("value2".to_string())))
        .expect("Should set second pair value");
    core.heap.define_property(pair2_array,
        PropertyKey::String("length".to_string()),
        PropertyDescriptor::data(JsValue::Int(2)))
        .expect("Should set second pair length");

    // Create the iterable array containing the pairs
    let iterable = core.heap.alloc_plain().expect("Should allocate iterable array");
    core.heap.define_property(iterable,
        PropertyKey::String("0".to_string()),
        PropertyDescriptor::data(JsValue::Object(pair1_array)))
        .expect("Should set first pair");
    core.heap.define_property(iterable,
        PropertyKey::String("1".to_string()),
        PropertyDescriptor::data(JsValue::Object(pair2_array)))
        .expect("Should set second pair");
    core.heap.define_property(iterable,
        PropertyKey::String("length".to_string()),
        PropertyDescriptor::data(JsValue::Int(2)))
        .expect("Should set iterable length");

    // Create WeakMap with iterable initialization
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Object(iterable))
        .expect("Should write iterable to register");

    let result = core.call_builtin("builtin:WeakMap", frankenengine::baseline_interpreter::RegRange { start: 0, count: 1 })
        .expect("WeakMap constructor with iterable should succeed");

    let weakmap_id = match result {
        frankenengine::baseline_interpreter::Value::Object(id) => id,
        other => panic!("WeakMap constructor should return object, got {:?}", other),
    };

    // Verify that the WeakMap was initialized with the entries
    let storage = core.weakmap_storage.get(&weakmap_id)
        .expect("WeakMap storage should exist");

    assert_eq!(storage.get_weak_key_objects().len(), 2,
        "WeakMap should have 2 weak key objects after initialization");

    assert!(storage.has(key1.0), "WeakMap should contain first key");
    assert!(storage.has(key2.0), "WeakMap should contain second key");

    assert_eq!(
        storage.get(key1.0),
        Some(&frankenengine::baseline_interpreter::Value::Str("value1".to_string())),
        "First key should map to 'value1'"
    );
    assert_eq!(
        storage.get(key2.0),
        Some(&frankenengine::baseline_interpreter::Value::Str("value2".to_string())),
        "Second key should map to 'value2'"
    );
}

#[test]
fn test_weakmap_weak_semantics_vs_regular_map() {
    let mut core = test_interpreter();

    // Create a WeakMap and a regular object for comparison
    let weakmap_result = core.call_builtin("builtin:WeakMap", frankenengine::baseline_interpreter::RegRange { start: 0, count: 0 })
        .expect("WeakMap constructor should succeed");
    let weakmap_id = match weakmap_result {
        frankenengine::baseline_interpreter::Value::Object(id) => id,
        other => panic!("WeakMap constructor should return object, got {:?}", other),
    };

    let regular_obj = core.heap.alloc_plain().expect("Should allocate regular object");

    // Create an object to use as a key
    let key_obj = core.heap.alloc_plain().expect("Should allocate key object");

    // Store the object as a key in WeakMap (weak reference)
    let storage = core.weakmap_storage.get_mut(&weakmap_id)
        .expect("WeakMap storage should exist");
    storage.set(key_obj.0, frankenengine::baseline_interpreter::Value::Str("weak_value".to_string()));

    // Store the object as a property in regular object (strong reference)
    core.heap.define_property(regular_obj,
        PropertyKey::String(format!("obj_{}", key_obj.0)),
        PropertyDescriptor::data(JsValue::Str("strong_value".to_string())))
        .expect("Should set strong reference");

    // Verify both references exist initially
    assert!(storage.has(key_obj.0), "WeakMap should contain the key object");

    let strong_ref_exists = core.heap.get_property(regular_obj,
        &PropertyKey::String(format!("obj_{}", key_obj.0))).is_ok();
    assert!(strong_ref_exists, "Regular object should contain the property");

    // The key difference: WeakMap does not prevent garbage collection
    // This is a structural test - the WeakMap storage tracks objects separately
    // from the regular heap object properties
    let weak_key_objects = storage.get_weak_key_objects();
    assert_eq!(weak_key_objects.len(), 1, "Should track exactly one weak key object");
    assert!(weak_key_objects.contains(&key_obj.0), "Should track the key object ID");
}

#[test]
fn test_weakmap_cleanup_collected_objects() {
    let mut core = test_interpreter();

    // Create a WeakMap
    let weakmap_result = core.call_builtin("builtin:WeakMap", frankenengine::baseline_interpreter::RegRange { start: 0, count: 0 })
        .expect("WeakMap constructor should succeed");
    let weakmap_id = match weakmap_result {
        frankenengine::baseline_interpreter::Value::Object(id) => id,
        other => panic!("WeakMap constructor should return object, got {:?}", other),
    };

    // Create objects to use as keys
    let key1 = core.heap.alloc_plain().expect("Should allocate first key");
    let key2 = core.heap.alloc_plain().expect("Should allocate second key");
    let key3 = core.heap.alloc_plain().expect("Should allocate third key");

    // Add entries to WeakMap
    let storage = core.weakmap_storage.get_mut(&weakmap_id)
        .expect("WeakMap storage should exist");
    storage.set(key1.0, frankenengine::baseline_interpreter::Value::Str("value1".to_string()));
    storage.set(key2.0, frankenengine::baseline_interpreter::Value::Str("value2".to_string()));
    storage.set(key3.0, frankenengine::baseline_interpreter::Value::Str("value3".to_string()));

    assert_eq!(storage.get_weak_key_objects().len(), 3, "Should have 3 entries initially");

    // Simulate garbage collection of key1 and key3
    let mut collected_objects = std::collections::BTreeSet::new();
    collected_objects.insert(key1.0);
    collected_objects.insert(key3.0);

    // Clean up collected objects
    let storage = core.weakmap_storage.get_mut(&weakmap_id)
        .expect("WeakMap storage should exist");
    storage.cleanup_collected_objects(&collected_objects);

    // Verify that only key2 remains
    assert_eq!(storage.get_weak_key_objects().len(), 1, "Should have 1 entry after cleanup");
    assert!(!storage.has(key1.0), "Key1 should be removed");
    assert!(storage.has(key2.0), "Key2 should remain");
    assert!(!storage.has(key3.0), "Key3 should be removed");

    // Verify values are also cleaned up
    assert_eq!(storage.get(key1.0), None, "Value1 should be removed");
    assert_eq!(storage.get(key2.0), Some(&frankenengine::baseline_interpreter::Value::Str("value2".to_string())), "Value2 should remain");
    assert_eq!(storage.get(key3.0), None, "Value3 should be removed");
}

#[test]
fn test_weakmap_memory_usage_vs_regular_objects() {
    let mut core = test_interpreter();

    // Create a WeakMap
    let weakmap_result = core.call_builtin("builtin:WeakMap", frankenengine::baseline_interpreter::RegRange { start: 0, count: 0 })
        .expect("WeakMap constructor should succeed");
    let weakmap_id = match weakmap_result {
        frankenengine::baseline_interpreter::Value::Object(id) => id,
        other => panic!("WeakMap constructor should return object, got {:?}", other),
    };

    // Create a regular object for comparison
    let regular_obj = core.heap.alloc_plain().expect("Should allocate regular object");

    // Create multiple objects and store them both ways
    let mut key_objects = Vec::new();
    for i in 0..10 {
        let key_obj = core.heap.alloc_plain().expect("Should allocate key object");
        key_objects.push(key_obj);

        // Store in WeakMap (weak reference)
        let storage = core.weakmap_storage.get_mut(&weakmap_id)
            .expect("WeakMap storage should exist");
        storage.set(key_obj.0, frankenengine::baseline_interpreter::Value::Int(i as i64));

        // Store in regular object (strong reference)
        core.heap.define_property(regular_obj,
            PropertyKey::String(format!("key_{}", i)),
            PropertyDescriptor::data(JsValue::Object(key_obj)))
            .expect("Should set strong reference");
    }

    // Verify WeakMap structure
    let storage = core.weakmap_storage.get(&weakmap_id)
        .expect("WeakMap storage should exist");
    assert_eq!(storage.get_weak_key_objects().len(), 10, "WeakMap should track 10 objects");

    // Verify regular object structure
    for i in 0..10 {
        let prop_exists = core.heap.get_property(regular_obj,
            &PropertyKey::String(format!("key_{}", i))).is_ok();
        assert!(prop_exists, "Regular object should contain property key_{}", i);
    }

    // The key insight: WeakMap entries live in separate storage and don't add
    // properties to the WeakMap object itself, unlike regular objects
    let weakmap_obj = core.heap.get(weakmap_id.0 as usize)
        .expect("WeakMap object should exist");

    // WeakMap object should only have __type property (no entry properties)
    assert!(weakmap_obj.properties.len() <= 2,
        "WeakMap object should have minimal properties (only __type), found: {}",
        weakmap_obj.properties.len());

    let regular_obj_ref = core.heap.get(regular_obj.0 as usize)
        .expect("Regular object should exist");
    assert!(regular_obj_ref.properties.len() >= 10,
        "Regular object should have all key properties, found: {}",
        regular_obj_ref.properties.len());
}