use frankenengine_engine::baseline_interpreter::InterpreterCore;
use frankenengine_engine::ir_contract::{Instruction, ObjectId, OpCode, RegisterAddress, Value};

#[test]
fn test_own_property_descriptor() {
    let mut interpreter = InterpreterCore::new();

    // Create an object with a property
    let obj_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    // Set a property on the object
    interpreter
        .set_object_property(obj_id, "ownProp".to_string(), Value::Number(42.0))
        .unwrap();

    // Store values in registers for the builtin call
    interpreter.reg[0] = Value::Object(obj_id);
    interpreter.reg[1] = Value::String("ownProp".to_string());

    // Call getOwnPropertyDescriptor
    let args = frankenengine_engine::baseline_interpreter::FunctionArgs { start: 0, count: 2 };
    let result = interpreter
        .builtin_function_call("builtin:ObjectGetOwnPropertyDescriptor", args)
        .unwrap();

    // Should return a descriptor object
    match result {
        Value::Object(desc_id) => {
            let value_prop = interpreter.get_object_property(desc_id, "value").unwrap();
            assert_eq!(value_prop, Value::Number(42.0));
        }
        _ => panic!("Expected descriptor object"),
    }
}

#[test]
fn test_inherited_property_descriptor() {
    let mut interpreter = InterpreterCore::new();

    // Create parent object with a property
    let parent_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });
    interpreter
        .set_object_property(
            parent_id,
            "inheritedProp".to_string(),
            Value::String("inherited".to_string()),
        )
        .unwrap();

    // Create child object with parent as prototype
    let child_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: Some(parent_id),
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    // Store values in registers
    interpreter.reg[0] = Value::Object(child_id);
    interpreter.reg[1] = Value::String("inheritedProp".to_string());

    let args = frankenengine_engine::baseline_interpreter::FunctionArgs { start: 0, count: 2 };

    // getOwnPropertyDescriptor should return undefined for inherited property
    let own_result = interpreter
        .builtin_function_call("builtin:ObjectGetOwnPropertyDescriptor", args)
        .unwrap();
    assert_eq!(own_result, Value::Undefined);

    // getPropertyDescriptor should find inherited property
    let inherited_result = interpreter
        .builtin_function_call("builtin:ObjectGetPropertyDescriptor", args)
        .unwrap();
    match inherited_result {
        Value::Object(desc_id) => {
            let value_prop = interpreter.get_object_property(desc_id, "value").unwrap();
            assert_eq!(value_prop, Value::String("inherited".to_string()));
        }
        _ => panic!("Expected descriptor object for inherited property"),
    }
}

#[test]
fn test_missing_property_up_the_chain() {
    let mut interpreter = InterpreterCore::new();

    // Create a chain: grandparent -> parent -> child
    let grandparent_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    let parent_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: Some(grandparent_id),
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    let child_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: Some(parent_id),
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    // No property set on any object in the chain
    interpreter.reg[0] = Value::Object(child_id);
    interpreter.reg[1] = Value::String("nonExistentProp".to_string());

    let args = frankenengine_engine::baseline_interpreter::FunctionArgs { start: 0, count: 2 };

    // Both should return undefined for non-existent property
    let own_result = interpreter
        .builtin_function_call("builtin:ObjectGetOwnPropertyDescriptor", args)
        .unwrap();
    assert_eq!(own_result, Value::Undefined);

    let inherited_result = interpreter
        .builtin_function_call("builtin:ObjectGetPropertyDescriptor", args)
        .unwrap();
    assert_eq!(inherited_result, Value::Undefined);
}

#[test]
fn test_accessor_property_descriptor() {
    let mut interpreter = InterpreterCore::new();

    // Create an object
    let obj_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    // Create getter function
    let getter_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Function".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    // Set getter as a property (simulating accessor descriptor)
    interpreter
        .set_object_property(
            obj_id,
            "accessorProp_getter".to_string(),
            Value::Object(getter_id),
        )
        .unwrap();

    interpreter.reg[0] = Value::Object(obj_id);
    interpreter.reg[1] = Value::String("accessorProp_getter".to_string());

    let args = frankenengine_engine::baseline_interpreter::FunctionArgs { start: 0, count: 2 };

    let result = interpreter
        .builtin_function_call("builtin:ObjectGetPropertyDescriptor", args)
        .unwrap();

    // Should return a descriptor with the getter function
    match result {
        Value::Object(desc_id) => {
            let value_prop = interpreter.get_object_property(desc_id, "value").unwrap();
            assert_eq!(value_prop, Value::Object(getter_id));
        }
        _ => panic!("Expected descriptor object for accessor property"),
    }
}

#[test]
fn test_frozen_object_descriptor_flags() {
    let mut interpreter = InterpreterCore::new();

    // Create a frozen object with a property
    let obj_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Object".to_string(),
            is_frozen: true, // Frozen object
            is_sealed: false,
        });

    interpreter
        .set_object_property(obj_id, "frozenProp".to_string(), Value::Number(123.0))
        .unwrap();

    interpreter.reg[0] = Value::Object(obj_id);
    interpreter.reg[1] = Value::String("frozenProp".to_string());

    let args = frankenengine_engine::baseline_interpreter::FunctionArgs { start: 0, count: 2 };

    let result = interpreter
        .builtin_function_call("builtin:ObjectGetPropertyDescriptor", args)
        .unwrap();

    match result {
        Value::Object(desc_id) => {
            let writable = interpreter
                .get_object_property(desc_id, "writable")
                .unwrap();
            let configurable = interpreter
                .get_object_property(desc_id, "configurable")
                .unwrap();

            // Frozen object properties should not be writable or configurable
            assert_eq!(writable, Value::Bool(false));
            assert_eq!(configurable, Value::Bool(false));
        }
        _ => panic!("Expected descriptor object for frozen property"),
    }
}

#[test]
fn test_sealed_object_descriptor_flags() {
    let mut interpreter = InterpreterCore::new();

    // Create a sealed object with a property
    let obj_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: true, // Sealed object
        });

    interpreter
        .set_object_property(obj_id, "sealedProp".to_string(), Value::Number(456.0))
        .unwrap();

    interpreter.reg[0] = Value::Object(obj_id);
    interpreter.reg[1] = Value::String("sealedProp".to_string());

    let args = frankenengine_engine::baseline_interpreter::FunctionArgs { start: 0, count: 2 };

    let result = interpreter
        .builtin_function_call("builtin:ObjectGetPropertyDescriptor", args)
        .unwrap();

    match result {
        Value::Object(desc_id) => {
            let writable = interpreter
                .get_object_property(desc_id, "writable")
                .unwrap();
            let configurable = interpreter
                .get_object_property(desc_id, "configurable")
                .unwrap();

            // Sealed object properties should be writable but not configurable
            assert_eq!(writable, Value::Bool(true));
            assert_eq!(configurable, Value::Bool(false));
        }
        _ => panic!("Expected descriptor object for sealed property"),
    }
}

#[test]
fn test_deep_prototype_chain() {
    let mut interpreter = InterpreterCore::new();

    // Create a 4-level prototype chain
    let level1_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });
    interpreter
        .set_object_property(
            level1_id,
            "deepProp".to_string(),
            Value::String("deep".to_string()),
        )
        .unwrap();

    let level2_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: Some(level1_id),
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    let level3_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: Some(level2_id),
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    let level4_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: Some(level3_id),
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });

    // Test lookup from the bottom of the chain
    interpreter.reg[0] = Value::Object(level4_id);
    interpreter.reg[1] = Value::String("deepProp".to_string());

    let args = frankenengine_engine::baseline_interpreter::FunctionArgs { start: 0, count: 2 };

    let result = interpreter
        .builtin_function_call("builtin:ObjectGetPropertyDescriptor", args)
        .unwrap();

    match result {
        Value::Object(desc_id) => {
            let value_prop = interpreter.get_object_property(desc_id, "value").unwrap();
            assert_eq!(value_prop, Value::String("deep".to_string()));
        }
        _ => panic!("Expected descriptor object for deep property"),
    }
}

#[test]
fn test_shadowed_property_descriptor() {
    let mut interpreter = InterpreterCore::new();

    // Create parent with property
    let parent_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: None,
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });
    interpreter
        .set_object_property(
            parent_id,
            "shadowProp".to_string(),
            Value::String("parent".to_string()),
        )
        .unwrap();

    // Create child with same property name (shadows parent)
    let child_id = ObjectId(interpreter.heap.len() as u32);
    interpreter
        .heap
        .push(frankenengine_engine::baseline_interpreter::HeapObject {
            properties: std::collections::BTreeMap::new(),
            prototype: Some(parent_id),
            class_name: "Object".to_string(),
            is_frozen: false,
            is_sealed: false,
        });
    interpreter
        .set_object_property(
            child_id,
            "shadowProp".to_string(),
            Value::String("child".to_string()),
        )
        .unwrap();

    interpreter.reg[0] = Value::Object(child_id);
    interpreter.reg[1] = Value::String("shadowProp".to_string());

    let args = frankenengine_engine::baseline_interpreter::FunctionArgs { start: 0, count: 2 };

    // Both methods should find the child's own property, not the parent's
    let own_result = interpreter
        .builtin_function_call("builtin:ObjectGetOwnPropertyDescriptor", args)
        .unwrap();
    let inherited_result = interpreter
        .builtin_function_call("builtin:ObjectGetPropertyDescriptor", args)
        .unwrap();

    match (own_result, inherited_result) {
        (Value::Object(own_desc), Value::Object(inherited_desc)) => {
            let own_value = interpreter.get_object_property(own_desc, "value").unwrap();
            let inherited_value = interpreter
                .get_object_property(inherited_desc, "value")
                .unwrap();

            // Both should return the child's value, not the parent's
            assert_eq!(own_value, Value::String("child".to_string()));
            assert_eq!(inherited_value, Value::String("child".to_string()));
        }
        _ => panic!("Expected descriptor objects for shadowed property"),
    }
}
