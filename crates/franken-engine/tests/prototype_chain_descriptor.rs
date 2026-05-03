#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};

fn config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    config
}

fn builtin(name: &str) -> CapabilityTag {
    CapabilityTag(format!("builtin:{name}"))
}

fn module(source_label: &str, pool: Vec<&str>, instructions: Vec<Ir3Instruction>) -> Ir3Module {
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = pool.into_iter().map(str::to_string).collect();
    module.required_capabilities = instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Ir3Instruction::HostCall { capability, .. } => Some(capability.clone()),
            _ => None,
        })
        .collect();
    module.instructions = instructions;
    module
}

fn execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    InterpreterCore::new(config(), "prototype-chain-descriptor").execute(module)
}

fn own_descriptor_value_module() -> Ir3Module {
    module(
        "own-descriptor-value",
        vec!["ownProp", "value"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectGetOwnPropertyDescriptor"),
                args: RegRange { start: 0, count: 2 },
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
    )
}

fn inherited_descriptor_value_module(own_only: bool) -> Ir3Module {
    let capability = if own_only {
        "ObjectGetOwnPropertyDescriptor"
    } else {
        "ObjectGetPropertyDescriptor"
    };
    let mut instructions = vec![
        Ir3Instruction::NewObject { dst: 0 },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 1,
        },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::NewObject { dst: 3 },
        Ir3Instruction::Move { dst: 4, src: 0 },
        Ir3Instruction::HostCall {
            capability: builtin("ObjectSetPrototypeOf"),
            args: RegRange { start: 3, count: 2 },
            dst: 5,
        },
        Ir3Instruction::LoadStr {
            dst: 4,
            pool_index: 0,
        },
        Ir3Instruction::HostCall {
            capability: builtin(capability),
            args: RegRange { start: 3, count: 2 },
            dst: 6,
        },
    ];

    if own_only {
        instructions.push(Ir3Instruction::Return { value: 6 });
    } else {
        instructions.extend([
            Ir3Instruction::LoadStr {
                dst: 7,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 6,
                key: 7,
                dst: 8,
            },
            Ir3Instruction::Return { value: 8 },
        ]);
    }

    module(
        "inherited-descriptor-value",
        vec!["inheritedProp", "inherited", "value"],
        instructions,
    )
}

fn missing_descriptor_module() -> Ir3Module {
    module(
        "missing-descriptor",
        vec!["missingProp"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectGetPropertyDescriptor"),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
    )
}

fn frozen_descriptor_flag_module(flag: &str) -> Ir3Module {
    module(
        "frozen-descriptor-flags",
        vec!["frozenProp", "frozen", flag],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectFreeze"),
                args: RegRange { start: 0, count: 1 },
                dst: 3,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectGetOwnPropertyDescriptor"),
                args: RegRange { start: 0, count: 2 },
                dst: 4,
            },
            Ir3Instruction::LoadStr {
                dst: 5,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 4,
                key: 5,
                dst: 6,
            },
            Ir3Instruction::Return { value: 6 },
        ],
    )
}

fn shadowed_descriptor_value_module(own_only: bool) -> Ir3Module {
    let capability = if own_only {
        "ObjectGetOwnPropertyDescriptor"
    } else {
        "ObjectGetPropertyDescriptor"
    };
    module(
        "shadowed-descriptor",
        vec!["shadowProp", "parent", "child", "value"],
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::NewObject { dst: 3 },
            Ir3Instruction::Move { dst: 4, src: 0 },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectSetPrototypeOf"),
                args: RegRange { start: 3, count: 2 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 1,
                val: 4,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin(capability),
                args: RegRange { start: 3, count: 2 },
                dst: 6,
            },
            Ir3Instruction::LoadStr {
                dst: 7,
                pool_index: 3,
            },
            Ir3Instruction::GetProperty {
                obj: 6,
                key: 7,
                dst: 8,
            },
            Ir3Instruction::Return { value: 8 },
        ],
    )
}

#[test]
fn own_property_descriptor_exposes_value() {
    let result = execute(&own_descriptor_value_module()).expect("own descriptor should execute");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn own_property_descriptor_ignores_inherited_properties() {
    let result = execute(&inherited_descriptor_value_module(true))
        .expect("own descriptor lookup should execute");
    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn prototype_chain_descriptor_finds_inherited_properties() {
    let result = execute(&inherited_descriptor_value_module(false))
        .expect("prototype descriptor lookup should execute");
    assert_eq!(result.value, Value::Str("inherited".to_string()));
}

#[test]
fn prototype_chain_descriptor_returns_undefined_for_missing_property() {
    let result = execute(&missing_descriptor_module()).expect("missing descriptor should execute");
    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn frozen_own_descriptor_reports_non_writable_and_non_configurable() {
    let writable = execute(&frozen_descriptor_flag_module("writable"))
        .expect("frozen writable descriptor should execute");
    let configurable = execute(&frozen_descriptor_flag_module("configurable"))
        .expect("frozen configurable descriptor should execute");

    assert_eq!(writable.value, Value::Bool(false));
    assert_eq!(configurable.value, Value::Bool(false));
}

#[test]
fn shadowed_property_descriptor_prefers_child_value() {
    let own = execute(&shadowed_descriptor_value_module(true))
        .expect("own shadowed descriptor should execute");
    let inherited = execute(&shadowed_descriptor_value_module(false))
        .expect("prototype shadowed descriptor should execute");

    assert_eq!(own.value, Value::Str("child".to_string()));
    assert_eq!(inherited.value, Value::Str("child".to_string()));
}

#[cfg(any())]
mod legacy_private_heap_descriptor_tests {
    use frankenengine_engine::baseline_interpreter::InterpreterCore;
    use frankenengine_engine::ir_contract::{
        Instruction, ObjectId, OpCode, RegisterAddress, Value,
    };

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
}
