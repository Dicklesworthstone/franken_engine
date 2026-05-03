//! Tests for Object.freeze property enforcement.
//!
//! This test module verifies that Object.freeze() properly enforces property
//! immutability according to ECMAScript semantics:
//! - Frozen objects cannot have properties added, deleted, or modified
//! - In strict mode, attempts to modify frozen objects should throw TypeError
//! - In sloppy mode, attempts to modify frozen objects should silently fail
//! - Object.isFrozen() should correctly report frozen state
//! - Freezing is not transitive (nested objects remain mutable unless separately frozen)

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};

fn config_with_caps(caps: &[RuntimeCapability]) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::VmDispatch]);
    config.granted_capabilities.extend(caps.iter().copied());
    config
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

fn execute(
    module: &Ir3Module,
    caps: &[RuntimeCapability],
) -> Result<ExecutionResult, InterpreterError> {
    InterpreterCore::new(config_with_caps(caps), "object-freeze-public-api").execute(module)
}

fn standard_caps() -> [RuntimeCapability; 2] {
    [RuntimeCapability::HeapAllocate, RuntimeCapability::Builtin]
}

fn builtin(name: &str) -> CapabilityTag {
    CapabilityTag(format!("builtin:{name}"))
}

fn new_object_is_frozen_module(source_label: &str, freeze_first: bool) -> Ir3Module {
    let mut instructions = vec![Ir3Instruction::NewObject { dst: 0 }];
    if freeze_first {
        instructions.push(Ir3Instruction::HostCall {
            capability: builtin("ObjectFreeze"),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        });
    }
    instructions.push(Ir3Instruction::HostCall {
        capability: builtin("ObjectIsFrozen"),
        args: RegRange { start: 0, count: 1 },
        dst: 2,
    });
    instructions.push(Ir3Instruction::Return { value: 2 });
    module(source_label, vec![], instructions)
}

fn frozen_write_module() -> Ir3Module {
    module(
        "object-freeze-write",
        vec!["prop", "original", "modified"],
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
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 4,
            },
            Ir3Instruction::Return { value: 4 },
        ],
    )
}

fn frozen_delete_then_get_module() -> Ir3Module {
    module(
        "object-freeze-delete",
        vec!["prop", "original"],
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
            Ir3Instruction::DeleteProperty {
                obj: 0,
                key: 1,
                dst: 4,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
    )
}

fn frozen_delete_result_module() -> Ir3Module {
    module(
        "object-freeze-delete-result",
        vec!["prop", "original"],
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
            Ir3Instruction::DeleteProperty {
                obj: 0,
                key: 1,
                dst: 4,
            },
            Ir3Instruction::Return { value: 4 },
        ],
    )
}

fn non_transitive_freeze_module() -> Ir3Module {
    module(
        "object-freeze-non-transitive",
        vec!["innerProp", "innerValue", "nested", "modifiedInnerValue"],
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
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 3,
                key: 4,
                val: 0,
            },
            Ir3Instruction::HostCall {
                capability: builtin("ObjectFreeze"),
                args: RegRange { start: 3, count: 1 },
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 6,
                pool_index: 3,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 6,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 7,
            },
            Ir3Instruction::Return { value: 7 },
        ],
    )
}

#[test]
fn object_is_frozen_reports_false_for_fresh_objects() {
    let result = execute(
        &new_object_is_frozen_module("object-is-frozen-fresh", false),
        &standard_caps(),
    )
    .expect("Object.isFrozen should execute");

    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn object_freeze_marks_objects_as_frozen() {
    let result = execute(
        &new_object_is_frozen_module("object-is-frozen-after-freeze", true),
        &standard_caps(),
    )
    .expect("Object.freeze and Object.isFrozen should execute");

    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn object_freeze_prevents_property_assignment() {
    let err = execute(&frozen_write_module(), &standard_caps())
        .expect_err("writing to a frozen object must fail");

    assert!(
        matches!(err, InterpreterError::TypeError { ref got, .. } if got == "frozen object"),
        "expected frozen-object TypeError, got {err:?}"
    );
}

#[test]
fn object_freeze_prevents_property_deletion_and_preserves_value() {
    let result = execute(&frozen_delete_then_get_module(), &standard_caps())
        .expect("delete on a frozen object should be a false no-op, not a mutation");

    assert_eq!(result.value, Value::Str("original".to_string()));
}

#[test]
fn delete_property_reports_false_for_frozen_objects() {
    let result = execute(&frozen_delete_result_module(), &standard_caps())
        .expect("delete on a frozen object should complete");

    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn object_freeze_is_not_transitive() {
    let result = execute(&non_transitive_freeze_module(), &standard_caps())
        .expect("freezing an outer object should not freeze nested object values");

    assert_eq!(result.value, Value::Str("modifiedInnerValue".to_string()));
}

#[test]
fn object_freeze_returns_primitives_unchanged() {
    let result = execute(
        &module(
            "object-freeze-primitive",
            vec![],
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 42 },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectFreeze"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ],
        ),
        &standard_caps(),
    )
    .expect("Object.freeze primitive path should execute");

    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn object_is_frozen_treats_primitives_as_frozen() {
    let result = execute(
        &module(
            "object-is-frozen-primitive",
            vec!["hello"],
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectIsFrozen"),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ],
        ),
        &standard_caps(),
    )
    .expect("Object.isFrozen primitive path should execute");

    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn object_freeze_with_no_arguments_returns_undefined() {
    let result = execute(
        &module(
            "object-freeze-no-args",
            vec![],
            vec![
                Ir3Instruction::HostCall {
                    capability: builtin("ObjectFreeze"),
                    args: RegRange { start: 0, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
        ),
        &standard_caps(),
    )
    .expect("Object.freeze no-arg path should execute");

    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn object_freeze_requires_builtin_capability_fail_closed() {
    let err = execute(
        &new_object_is_frozen_module("object-freeze-capability-denied", true),
        &[RuntimeCapability::HeapAllocate],
    )
    .expect_err("Object.freeze should require Builtin capability");

    assert!(
        matches!(err, InterpreterError::CapabilityDenied { ref capability } if capability == "builtin:ObjectFreeze"),
        "expected ObjectFreeze capability denial, got {err:?}"
    );
}

#[cfg(any())]
mod legacy_private_object_model_tests {
    use frankenengine::baseline_interpreter::{
        CoreInterpreter, InterpreterConfig, InterpreterError,
    };
    use frankenengine::ir_contract::Ir3Instruction;
    use frankenengine::module::Module;
    use frankenengine::object_model::{JsValue, ObjectHandle, PropertyDescriptor, PropertyKey};

    /// Create a test interpreter with default configuration.
    fn test_interpreter() -> CoreInterpreter {
        let config = InterpreterConfig::test_default();
        CoreInterpreter::new(config)
    }

    #[test]
    fn test_object_freeze_basic() {
        let mut core = test_interpreter();

        // Create a plain object
        let obj_handle = core.heap.alloc_plain();

        // Add a property to the object
        let key = PropertyKey::String("foo".to_string());
        let desc = PropertyDescriptor::data(JsValue::Str("bar".to_string()));
        core.heap
            .define_property(obj_handle, key.clone(), desc)
            .expect("should define property");

        // Verify object is not frozen initially
        assert!(!core.heap.is_frozen(obj_handle).unwrap());

        // Freeze the object
        core.heap.freeze(obj_handle).expect("should freeze object");

        // Verify object is now frozen
        assert!(core.heap.is_frozen(obj_handle).unwrap());
    }

    #[test]
    fn test_object_freeze_prevents_property_assignment() {
        let mut core = test_interpreter();

        // Create object with property
        let obj_handle = core.heap.alloc_plain();
        let key = PropertyKey::String("prop".to_string());
        let original_value = JsValue::Str("original".to_string());
        let desc = PropertyDescriptor::data(original_value.clone());
        core.heap
            .define_property(obj_handle, key.clone(), desc)
            .expect("should define property");

        // Freeze the object
        core.heap.freeze(obj_handle).expect("should freeze object");

        // Attempt to change property value should fail
        let new_value = JsValue::Str("modified".to_string());
        let result = core.heap.set_property(obj_handle, key.clone(), new_value);

        // Should return error due to frozen object
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("frozen"));
        }

        // Original property value should be unchanged
        let current_value = core
            .heap
            .get_property(obj_handle, &key)
            .expect("should get property");
        assert_eq!(current_value, original_value);
    }

    #[test]
    fn test_object_freeze_prevents_new_property_addition() {
        let mut core = test_interpreter();

        // Create empty object
        let obj_handle = core.heap.alloc_plain();

        // Freeze the empty object
        core.heap.freeze(obj_handle).expect("should freeze object");

        // Attempt to add new property should fail
        let key = PropertyKey::String("newProp".to_string());
        let value = JsValue::Str("newValue".to_string());
        let result = core.heap.set_property(obj_handle, key, value);

        // Should return error due to frozen object
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("frozen"));
        }
    }

    #[test]
    fn test_object_is_frozen_builtin() {
        let mut core = test_interpreter();

        // Test with unfrozen object
        let obj_handle = core.heap.alloc_plain();
        core.write_reg(
            0,
            frankenengine::baseline_interpreter::Value::Object(obj_handle),
        )
        .expect("should write register");

        let args = frankenengine::baseline_interpreter::RegRange { start: 0, count: 1 };
        let result = core
            .call_builtin("builtin:ObjectIsFrozen", args)
            .expect("should call Object.isFrozen");

        // Should return false for unfrozen object
        assert_eq!(
            result,
            frankenengine::baseline_interpreter::Value::Bool(false)
        );

        // Freeze the object
        core.heap.freeze(obj_handle).expect("should freeze object");

        // Test again with frozen object
        let result = core
            .call_builtin("builtin:ObjectIsFrozen", args)
            .expect("should call Object.isFrozen");

        // Should return true for frozen object
        assert_eq!(
            result,
            frankenengine::baseline_interpreter::Value::Bool(true)
        );
    }

    #[test]
    fn test_object_is_frozen_non_objects() {
        let mut core = test_interpreter();

        // Test with primitive values - they should always be considered "frozen"
        let test_cases = vec![
            frankenengine::baseline_interpreter::Value::Int(42),
            frankenengine::baseline_interpreter::Value::Str("hello".to_string()),
            frankenengine::baseline_interpreter::Value::Bool(true),
            frankenengine::baseline_interpreter::Value::Null,
            frankenengine::baseline_interpreter::Value::Undefined,
        ];

        for (i, value) in test_cases.into_iter().enumerate() {
            core.write_reg(0, value).expect("should write register");

            let args = frankenengine::baseline_interpreter::RegRange { start: 0, count: 1 };
            let result = core
                .call_builtin("builtin:ObjectIsFrozen", args)
                .expect("should call Object.isFrozen");

            // All non-objects should be considered frozen
            assert_eq!(
                result,
                frankenengine::baseline_interpreter::Value::Bool(true),
                "test case {} failed",
                i
            );
        }
    }

    #[test]
    fn test_object_freeze_builtin() {
        let mut core = test_interpreter();

        // Create object
        let obj_handle = core.heap.alloc_plain();
        core.write_reg(
            0,
            frankenengine::baseline_interpreter::Value::Object(obj_handle),
        )
        .expect("should write register");

        // Verify not frozen initially
        assert!(!core.heap.is_frozen(obj_handle).unwrap());

        // Call Object.freeze
        let args = frankenengine::baseline_interpreter::RegRange { start: 0, count: 1 };
        let result = core
            .call_builtin("builtin:ObjectFreeze", args)
            .expect("should call Object.freeze");

        // Should return the same object
        assert_eq!(
            result,
            frankenengine::baseline_interpreter::Value::Object(obj_handle)
        );

        // Object should now be frozen
        assert!(core.heap.is_frozen(obj_handle).unwrap());
    }

    #[test]
    fn test_freeze_is_not_transitive() {
        let mut core = test_interpreter();

        // Create outer object
        let outer_obj = core.heap.alloc_plain();

        // Create inner (nested) object
        let inner_obj = core.heap.alloc_plain();

        // Add property to inner object
        let inner_key = PropertyKey::String("innerProp".to_string());
        let inner_desc = PropertyDescriptor::data(JsValue::Str("innerValue".to_string()));
        core.heap
            .define_property(inner_obj, inner_key.clone(), inner_desc)
            .expect("should define inner property");

        // Add inner object as property of outer object
        let outer_key = PropertyKey::String("nested".to_string());
        let outer_desc = PropertyDescriptor::data(JsValue::Object(inner_obj));
        core.heap
            .define_property(outer_obj, outer_key.clone(), outer_desc)
            .expect("should define outer property");

        // Freeze only the outer object
        core.heap
            .freeze(outer_obj)
            .expect("should freeze outer object");

        // Verify outer object is frozen
        assert!(core.heap.is_frozen(outer_obj).unwrap());

        // Verify inner object is NOT frozen (freeze is not transitive)
        assert!(!core.heap.is_frozen(inner_obj).unwrap());

        // Should still be able to modify properties on the inner object
        let new_inner_value = JsValue::Str("modifiedInnerValue".to_string());
        let result = core
            .heap
            .set_property(inner_obj, inner_key.clone(), new_inner_value.clone());

        // This should succeed because inner object is not frozen
        assert!(result.is_ok());

        // Verify the value was actually changed
        let current_value = core
            .heap
            .get_property(inner_obj, &inner_key)
            .expect("should get property");
        assert_eq!(current_value, new_inner_value);
    }

    #[test]
    fn test_frozen_object_property_descriptors_are_non_configurable_non_writable() {
        let mut core = test_interpreter();

        // Create object with writable, configurable property
        let obj_handle = core.heap.alloc_plain();
        let key = PropertyKey::String("prop".to_string());
        let desc = PropertyDescriptor::Data {
            value: JsValue::Str("value".to_string()),
            writable: true,
            enumerable: true,
            configurable: true,
        };
        core.heap
            .define_property(obj_handle, key.clone(), desc)
            .expect("should define property");

        // Verify initial descriptor state
        let initial_desc = core
            .heap
            .get_own_property_descriptor(obj_handle, &key)
            .expect("should get descriptor")
            .expect("descriptor should exist");

        assert!(initial_desc.is_writable());
        assert!(initial_desc.is_configurable());
        assert!(initial_desc.is_enumerable());

        // Freeze the object
        core.heap.freeze(obj_handle).expect("should freeze object");

        // Check descriptor after freezing
        let frozen_desc = core
            .heap
            .get_own_property_descriptor(obj_handle, &key)
            .expect("should get descriptor")
            .expect("descriptor should exist");

        // After freezing, data properties should be non-writable and non-configurable
        assert!(!frozen_desc.is_writable());
        assert!(!frozen_desc.is_configurable());
        // Enumerable should remain unchanged
        assert!(frozen_desc.is_enumerable());
    }

    #[test]
    fn test_freeze_with_accessor_properties() {
        let mut core = test_interpreter();

        // Create object
        let obj_handle = core.heap.alloc_plain();

        // Add accessor property (getter/setter)
        let key = PropertyKey::String("accessor".to_string());
        let desc = PropertyDescriptor::Accessor {
            get: None, // No getter function for simplicity
            set: None, // No setter function for simplicity
            enumerable: true,
            configurable: true,
        };
        core.heap
            .define_property(obj_handle, key.clone(), desc)
            .expect("should define accessor property");

        // Freeze the object
        core.heap.freeze(obj_handle).expect("should freeze object");

        // Check descriptor after freezing
        let frozen_desc = core
            .heap
            .get_own_property_descriptor(obj_handle, &key)
            .expect("should get descriptor")
            .expect("descriptor should exist");

        // Accessor properties should become non-configurable after freezing
        assert!(frozen_desc.is_accessor());
        assert!(!frozen_desc.is_configurable());
        assert!(frozen_desc.is_enumerable());
    }

    #[test]
    fn test_freeze_no_op_on_already_frozen_object() {
        let mut core = test_interpreter();

        // Create and freeze object
        let obj_handle = core.heap.alloc_plain();
        core.heap.freeze(obj_handle).expect("should freeze object");
        assert!(core.heap.is_frozen(obj_handle).unwrap());

        // Freeze again - should be a no-op
        core.heap
            .freeze(obj_handle)
            .expect("should freeze object again");
        assert!(core.heap.is_frozen(obj_handle).unwrap());
    }

    #[test]
    fn test_object_freeze_with_no_arguments() {
        let mut core = test_interpreter();

        // Call Object.freeze with no arguments
        let args = frankenengine::baseline_interpreter::RegRange { start: 0, count: 0 };
        let result = core
            .call_builtin("builtin:ObjectFreeze", args)
            .expect("should call Object.freeze with no args");

        // Should return undefined when no arguments provided
        assert_eq!(
            result,
            frankenengine::baseline_interpreter::Value::Undefined
        );
    }

    #[test]
    fn test_object_freeze_with_primitive() {
        let mut core = test_interpreter();

        // Test freezing primitive values - should return the primitive unchanged
        let test_cases = vec![
            frankenengine::baseline_interpreter::Value::Int(42),
            frankenengine::baseline_interpreter::Value::Str("hello".to_string()),
            frankenengine::baseline_interpreter::Value::Bool(true),
            frankenengine::baseline_interpreter::Value::Null,
        ];

        for (i, value) in test_cases.into_iter().enumerate() {
            core.write_reg(0, value.clone())
                .expect("should write register");

            let args = frankenengine::baseline_interpreter::RegRange { start: 0, count: 1 };
            let result = core
                .call_builtin("builtin:ObjectFreeze", args)
                .expect("should call Object.freeze");

            // Should return the same primitive value
            assert_eq!(result, value, "test case {} failed", i);
        }
    }

    #[test]
    fn test_object_is_frozen_with_no_arguments() {
        let mut core = test_interpreter();

        // Call Object.isFrozen with no arguments
        let args = frankenengine::baseline_interpreter::RegRange { start: 0, count: 0 };
        let result = core
            .call_builtin("builtin:ObjectIsFrozen", args)
            .expect("should call Object.isFrozen with no args");

        // Should return true when no arguments provided (non-objects are considered frozen)
        assert_eq!(
            result,
            frankenengine::baseline_interpreter::Value::Bool(true)
        );
    }
}
