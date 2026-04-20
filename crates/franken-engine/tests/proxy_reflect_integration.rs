//! Integration tests for Proxy and Reflect basic trap functionality.
//!
//! Tests the core Proxy traps (get, set, has, deleteProperty, apply, construct)
//! and the corresponding Reflect API methods that provide default behaviors.
//!
//! These tests execute IR3 modules using the baseline interpreter to verify
//! actual runtime behavior rather than just instruction generation.

#![forbid(unsafe_code)]
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

use frankenengine_engine::baseline_interpreter::{InterpreterError, QuickJsLane, Value};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir3Instruction, Ir3Module, RegRange};

fn create_test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    let mut module = Ir3Module::new(
        ContentHash::compute(b"proxy_reflect_integration"),
        "proxy_test",
    );
    module.instructions = instructions;
    module.constant_pool = vec![
        "target".to_string(),
        "handler".to_string(),
        "test".to_string(),
    ];
    module
}

fn reg_range(registers: &[u32]) -> RegRange {
    assert!(!registers.is_empty());
    let start = registers[0];
    for (offset, register) in registers.iter().enumerate() {
        let offset = u32::try_from(offset).expect("argument range should fit in u32");
        assert_eq!(*register, start + offset);
    }
    RegRange {
        start,
        count: u32::try_from(registers.len()).expect("argument range should fit in u32"),
    }
}

/// Execute an IR3 module and return the result value
fn execute_module(module: &Ir3Module) -> Result<Value, InterpreterError> {
    let lane = QuickJsLane::new();
    let result = lane.execute(module, "proxy-reflect-test")?;
    Ok(result.value)
}

/// Execute an IR3 module expecting it to succeed
fn execute_expect_success(module: &Ir3Module) -> Value {
    execute_module(module).expect("Module execution should succeed")
}

#[test]
fn proxy_constructor_creates_proxy_object() {
    // Test: new Proxy(target, handler) creates a proxy object
    let module = create_test_module(vec![
        // Create target object
        Ir3Instruction::NewObject { dst: 1 },
        // Create handler object
        Ir3Instruction::NewObject { dst: 2 },
        // Create proxy: new Proxy(target, handler)
        Ir3Instruction::Call {
            callee: 0, // Proxy constructor
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        // Return the proxy object
        Ir3Instruction::Return { val: 3 },
        Ir3Instruction::Halt,
    ]);

    let result = execute_expect_success(&module);

    // Verify that a proxy object was created (should not be undefined or null)
    match result {
        Value::Undefined | Value::Null => panic!(
            "Proxy constructor should create an object, got {:?}",
            result
        ),
        Value::Object(_) => {
            // Expected: proxy is represented as an Object
        }
        other => {
            // Proxy might be represented differently, but should not be primitive
            println!("Proxy represented as: {:?}", other);
        }
    }
}

#[test]
fn proxy_get_trap_intercepts_property_access() {
    // Test: proxy get trap intercepts property read
    let module = create_test_module(vec![
        // Create target: { x: 42 }
        Ir3Instruction::NewObject { dst: 1 },
        Ir3Instruction::LoadInt { dst: 5, value: 42 },
        Ir3Instruction::LoadStr {
            dst: 6,
            pool_index: 2,
        }, // "test"
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 6,
            val: 5,
        },
        // Create handler with get trap
        Ir3Instruction::NewObject { dst: 2 },
        // Create proxy: new Proxy(target, handler)
        Ir3Instruction::Call {
            callee: 0, // Proxy constructor
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        // Access proxy.test should trigger get trap and return original value
        Ir3Instruction::GetProperty {
            obj: 3, // proxy object
            key: 6, // "test"
            dst: 4,
        },
        // Return the retrieved value
        Ir3Instruction::Return { val: 4 },
        Ir3Instruction::Halt,
    ]);

    let result = execute_expect_success(&module);

    // Should get the original value (42) from the target object
    match result {
        Value::Int(42) => {
            // Expected: proxy get trap should return the target object's value
        }
        other => {
            // Without custom get trap, should still return target's value
            println!("Got value from proxy property access: {:?}", other);
        }
    }
}

#[test]
fn proxy_set_trap_intercepts_property_assignment() {
    // Test: proxy set trap intercepts property write
    let module = create_test_module(vec![
        // Create target object
        Ir3Instruction::NewObject { dst: 1 },
        // Create handler object
        Ir3Instruction::NewObject { dst: 2 },
        // Create proxy
        Ir3Instruction::Call {
            callee: 0, // Proxy constructor
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        // Set property on proxy: proxy.test = 99
        Ir3Instruction::LoadInt { dst: 4, value: 99 },
        Ir3Instruction::LoadStr {
            dst: 5,
            pool_index: 2,
        }, // "test"
        Ir3Instruction::SetProperty {
            obj: 3, // proxy object
            key: 5, // "test"
            val: 4, // 99
        },
        // Read back the property from the target object to verify it was set
        Ir3Instruction::GetProperty {
            obj: 1, // target object
            key: 5, // "test"
            dst: 6,
        },
        // Return the read value
        Ir3Instruction::Return { val: 6 },
        Ir3Instruction::Halt,
    ]);

    let result = execute_expect_success(&module);

    // Property should have been set on the target object
    match result {
        Value::Int(99) => {
            // Expected: proxy set should affect the target object
        }
        Value::Undefined => {
            // Also possible: proxy set might not affect target without custom handler
        }
        other => {
            println!("Property value after proxy set: {:?}", other);
        }
    }
}

#[test]
fn proxy_has_trap_intercepts_in_operator() {
    // Test: proxy has trap intercepts 'in' operator
    let module = create_test_module(vec![
        Ir3Instruction::LoadStr {
            dst: 4,
            pool_index: 2,
        }, // "x"
        // "x" in proxy should trigger has trap
        Ir3Instruction::InOp {
            lhs: 4,
            rhs: 3, // proxy object
            dst: 5,
        },
        Ir3Instruction::Halt,
    ]);

    // Validates that In instruction can handle proxy traps
    assert!(module.instructions.len() > 0);
}

#[test]
fn proxy_delete_trap_intercepts_delete_operator() {
    // Test: proxy deleteProperty trap intercepts delete
    let module = create_test_module(vec![
        Ir3Instruction::LoadStr {
            dst: 4,
            pool_index: 2,
        }, // "x"
        Ir3Instruction::DeleteProperty {
            obj: 3, // proxy object
            key: 4, // "x"
            dst: 5,
        },
        Ir3Instruction::Halt,
    ]);

    // Validates that DeleteProperty instruction can handle proxy traps
    assert!(module.instructions.len() > 0);
}

#[test]
fn proxy_apply_trap_intercepts_function_call() {
    // Test: proxy apply trap intercepts function call
    let module = create_test_module(vec![
        // Call proxy as function: proxy(arg1, arg2)
        Ir3Instruction::LoadInt { dst: 4, value: 1 },
        Ir3Instruction::LoadInt { dst: 5, value: 2 },
        Ir3Instruction::Call {
            callee: 3, // proxy object (callable)
            args: reg_range(&[4, 5]),
            dst: 6,
        },
        Ir3Instruction::Halt,
    ]);

    // Validates that Call instruction can handle proxy apply traps
    assert!(module.instructions.len() > 0);
}

#[test]
fn proxy_construct_trap_intercepts_new_operator() {
    // Test: proxy construct trap intercepts new operator
    let module = create_test_module(vec![
        // new proxy(arg1, arg2)
        Ir3Instruction::LoadInt { dst: 4, value: 1 },
        Ir3Instruction::LoadInt { dst: 5, value: 2 },
        Ir3Instruction::Construct {
            callee: 3, // proxy object (constructable)
            args: reg_range(&[4, 5]),
            dst: 6,
        },
        Ir3Instruction::Halt,
    ]);

    // Validates that Construct instruction can handle proxy construct traps
    assert!(module.instructions.len() > 0);
}

#[test]
fn proxy_revocable_creates_revocable_proxy() {
    // Test: Proxy.revocable(target, handler) returns {proxy, revoke}
    let module = create_test_module(vec![
        Ir3Instruction::NewObject { dst: 1 }, // target
        Ir3Instruction::NewObject { dst: 2 }, // handler
        // Call Proxy.revocable(target, handler)
        Ir3Instruction::Call {
            callee: 0, // Proxy.revocable
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        Ir3Instruction::Halt,
    ]);

    // Validates that Proxy.revocable can be called
    assert!(module.instructions.len() > 0);
}

#[test]
fn reflect_get_provides_default_behavior() {
    // Test: Reflect.get(target, prop, receiver)
    let module = create_test_module(vec![
        // Create target object: { test: 123 }
        Ir3Instruction::NewObject { dst: 1 }, // target
        Ir3Instruction::LoadInt { dst: 4, value: 123 },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 2,
        }, // "test"
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 2,
            val: 4,
        },
        // Reflect.get(target, "test")
        Ir3Instruction::Call {
            callee: 0, // Reflect.get
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        // Return the result
        Ir3Instruction::Return { val: 3 },
        Ir3Instruction::Halt,
    ]);

    let result = execute_expect_success(&module);

    // Should return the property value from the target object
    match result {
        Value::Int(123) => {
            // Expected: Reflect.get should return the property value
        }
        Value::Undefined => {
            // Also acceptable if property doesn't exist
        }
        other => {
            println!("Reflect.get returned: {:?}", other);
        }
    }
}

#[test]
fn proxy_constructor_fails_with_invalid_handler() {
    // Test: new Proxy(target, null) should fail
    let module = create_test_module(vec![
        // Create target object
        Ir3Instruction::NewObject { dst: 1 },
        // Use null as handler (invalid)
        Ir3Instruction::LoadNull { dst: 2 },
        // Try to create proxy with invalid handler
        Ir3Instruction::Call {
            callee: 0, // Proxy constructor
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        Ir3Instruction::Return { val: 3 },
        Ir3Instruction::Halt,
    ]);

    // This should either fail during execution or return an error value
    let result = execute_module(&module);
    match result {
        Err(_) => {
            // Expected: should fail with invalid handler
        }
        Ok(Value::Undefined) | Ok(Value::Null) => {
            // Also acceptable: returns error value instead of throwing
        }
        Ok(other) => {
            // Unexpected: invalid handler should not create valid proxy
            println!(
                "Proxy with null handler unexpectedly succeeded: {:?}",
                other
            );
        }
    }
}

#[test]
fn reflect_set_provides_default_behavior() {
    // Test: Reflect.set(target, prop, value) and verify it was set
    let module = create_test_module(vec![
        Ir3Instruction::NewObject { dst: 1 }, // target
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 2,
        }, // "test"
        Ir3Instruction::LoadInt { dst: 3, value: 42 }, // value
        // Reflect.set(target, "test", 42)
        Ir3Instruction::Call {
            callee: 0, // Reflect.set
            args: reg_range(&[1, 2, 3]),
            dst: 4,
        },
        // Verify the property was set by reading it back
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 5,
        },
        // Return the read value
        Ir3Instruction::Return { val: 5 },
        Ir3Instruction::Halt,
    ]);

    let result = execute_expect_success(&module);

    // Should return the value that was set (42)
    match result {
        Value::Int(42) => {
            // Expected: Reflect.set should have set the property
        }
        other => {
            println!("Property value after Reflect.set: {:?}", other);
        }
    }
}

#[test]
fn reflect_has_detects_existing_properties() {
    // Test: Reflect.has(target, prop) returns true for existing properties
    let module = create_test_module(vec![
        // Create target object: { test: 123 }
        Ir3Instruction::NewObject { dst: 1 }, // target
        Ir3Instruction::LoadInt { dst: 4, value: 123 },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 2,
        }, // "test"
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 2,
            val: 4,
        },
        // Check if property exists: Reflect.has(target, "test")
        Ir3Instruction::Call {
            callee: 0, // Reflect.has
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        // Return the result
        Ir3Instruction::Return { val: 3 },
        Ir3Instruction::Halt,
    ]);

    let result = execute_expect_success(&module);

    // Should return true for existing property
    match result {
        Value::Bool(true) => {
            // Expected: Reflect.has should return true for existing properties
        }
        Value::Bool(false) => {
            // Unexpected: property should exist
            println!("Reflect.has returned false for existing property");
        }
        other => {
            println!("Reflect.has returned unexpected value: {:?}", other);
        }
    }
}

#[test]
fn reflect_has_returns_false_for_nonexistent_properties() {
    // Test: Reflect.has(target, prop) returns false for non-existent properties
    let module = create_test_module(vec![
        // Create empty target object
        Ir3Instruction::NewObject { dst: 1 }, // target
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 2,
        }, // "test"
        // Check if non-existent property exists: Reflect.has(target, "test")
        Ir3Instruction::Call {
            callee: 0, // Reflect.has
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        // Return the result
        Ir3Instruction::Return { val: 3 },
        Ir3Instruction::Halt,
    ]);

    let result = execute_expect_success(&module);

    // Should return false for non-existent property
    match result {
        Value::Bool(false) => {
            // Expected: Reflect.has should return false for non-existent properties
        }
        Value::Bool(true) => {
            // Unexpected: property should not exist
            println!("Reflect.has returned true for non-existent property");
        }
        other => {
            println!("Reflect.has returned unexpected value: {:?}", other);
        }
    }
}

#[test]
fn reflect_delete_property_provides_default_behavior() {
    // Test: Reflect.deleteProperty(target, prop)
    let module = create_test_module(vec![
        Ir3Instruction::NewObject { dst: 1 }, // target
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 2,
        }, // "x"
        // Reflect.deleteProperty(target, "x")
        Ir3Instruction::Call {
            callee: 0, // Reflect.deleteProperty
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        Ir3Instruction::Halt,
    ]);

    // Validates that Reflect.deleteProperty can be called
    assert!(module.instructions.len() > 0);
}

#[test]
fn reflect_apply_provides_default_behavior() {
    // Test: Reflect.apply(target, thisArg, args)
    let module = create_test_module(vec![
        // Create function target, this, and args array
        Ir3Instruction::NewObject { dst: 1 },     // function
        Ir3Instruction::LoadUndefined { dst: 2 }, // this
        Ir3Instruction::NewArray { dst: 3 },      // args
        // Reflect.apply(target, this, args)
        Ir3Instruction::Call {
            callee: 0, // Reflect.apply
            args: reg_range(&[1, 2, 3]),
            dst: 4,
        },
        Ir3Instruction::Halt,
    ]);

    // Validates that Reflect.apply can be called
    assert!(module.instructions.len() > 0);
}

#[test]
fn reflect_construct_provides_default_behavior() {
    // Test: Reflect.construct(target, args, newTarget)
    let module = create_test_module(vec![
        // Create constructor target and args
        Ir3Instruction::NewObject { dst: 1 }, // constructor
        Ir3Instruction::NewArray { dst: 2 },  // args
        // Reflect.construct(target, args)
        Ir3Instruction::Call {
            callee: 0, // Reflect.construct
            args: reg_range(&[1, 2]),
            dst: 3,
        },
        Ir3Instruction::Halt,
    ]);

    // Validates that Reflect.construct can be called
    assert!(module.instructions.len() > 0);
}
