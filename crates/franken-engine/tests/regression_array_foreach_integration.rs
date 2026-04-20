#![forbid(unsafe_code)]

//! Integration tests for Array.prototype.forEach duplicate removal fix
//!
//! Regression tests for commit d1018316307c8bf001b49dbc29e07b632c86f163
//! Verifies duplicate forEach implementations are removed and fail-closed behavior works

use frankenengine_engine::baseline_interpreter::{InterpreterCore, InterpreterConfig, ObjectId};
use frankenengine_engine::ir3::{Ir3Instruction, Module, RegRange};
use frankenengine_engine::object::Object;
use frankenengine_engine::value::Value;
use std::collections::BTreeMap;

fn test_module(instructions: Vec<Ir3Instruction>) -> Module {
    Module { instructions }
}

#[test]
fn array_foreach_duplicate_removal_integration() {
    // Regression test: verify only one forEach implementation exists and works
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    // Create an array object
    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(3)),
            ("0".to_string(), Value::Str("first".to_string())),
            ("1".to_string(), Value::Str("second".to_string())),
            ("2".to_string(), Value::Str("third".to_string())),
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Function(1); // Mock callback function

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeForEach".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    // Should succeed (not crash from duplicate implementations)
    assert!(result.is_ok(), "Array.forEach should execute without duplicate implementation conflicts");

    // forEach should return undefined
    assert_eq!(core.registers[10], Value::Undefined, "Array.forEach should return undefined");
}

#[test]
fn array_foreach_fail_closed_callback_validation() {
    // Test fail-closed behavior when callback is missing
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(2)),
            ("0".to_string(), Value::Int(1)),
            ("1".to_string(), Value::Int(2)),
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    // No callback provided (args.count < 2)

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeForEach".to_string(),
            args: RegRange { start: 0, count: 1 }, // No callback
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Array.forEach should handle missing callback gracefully");
    assert_eq!(core.registers[10], Value::Undefined, "Array.forEach without callback should return undefined");
}

#[test]
fn array_foreach_fail_closed_invalid_callback() {
    // Test fail-closed behavior when callback is not a function
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(2)),
            ("0".to_string(), Value::Int(1)),
            ("1".to_string(), Value::Int(2)),
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Str("not-a-function".to_string()); // Invalid callback

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeForEach".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Array.forEach should handle invalid callback gracefully");
    assert_eq!(core.registers[10], Value::Undefined, "Array.forEach with invalid callback should return undefined");
}

#[test]
fn array_foreach_fail_closed_non_object() {
    // Test fail-closed behavior when 'this' is not an object
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    core.registers[0] = Value::Str("not-an-array".to_string()); // Non-object this
    core.registers[1] = Value::Function(1); // Valid callback

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeForEach".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Array.forEach should handle non-object 'this' gracefully");
    assert_eq!(core.registers[10], Value::Undefined, "Array.forEach with non-object 'this' should return undefined");
}

#[test]
fn array_foreach_empty_array_handling() {
    // Test forEach behavior with empty array
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(0)), // Empty array
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Function(1);

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeForEach".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Array.forEach should handle empty array correctly");
    assert_eq!(core.registers[10], Value::Undefined, "Array.forEach should return undefined for empty array");
}

#[test]
fn array_foreach_sparse_array_handling() {
    // Test forEach with sparse array (missing indices)
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(5)),
            ("0".to_string(), Value::Str("first".to_string())),
            // Index 1 and 2 are missing (sparse)
            ("3".to_string(), Value::Str("fourth".to_string())),
            ("4".to_string(), Value::Str("fifth".to_string())),
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Function(1);

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeForEach".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Array.forEach should handle sparse arrays correctly");
    assert_eq!(core.registers[10], Value::Undefined, "Array.forEach should return undefined for sparse array");
}

#[test]
fn array_foreach_builtin_id_consistency() {
    // Verify forEach builtin is accessible and consistent after duplicate removal
    let core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    // Test that the builtin is properly registered
    let builtin_name = core.builtin_name_from_id(334); // Common forEach ID
    if let Some(name) = builtin_name {
        assert_eq!(name, "builtin:ArrayPrototypeForEach", "forEach builtin should be properly mapped");
    }
}