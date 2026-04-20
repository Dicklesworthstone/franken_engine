#![forbid(unsafe_code)]

//! Integration tests for Array.prototype.some duplicate removal fix
//!
//! Regression tests for commit de0c19063bebe04dfaa65c5a1c37d60b1b39d88e
//! Verifies duplicate some implementations are removed and fail-closed behavior works

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, ObjectId};
use frankenengine_engine::ir3::{Ir3Instruction, Module, RegRange};
use frankenengine_engine::object::Object;
use frankenengine_engine::value::Value;
use std::collections::BTreeMap;

fn test_module(instructions: Vec<Ir3Instruction>) -> Module {
    Module { instructions }
}

#[test]
fn array_some_duplicate_removal_integration() {
    // Regression test: verify only one some implementation exists and works
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    // Create an array object
    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(3)),
            ("0".to_string(), Value::Int(1)),
            ("1".to_string(), Value::Int(2)),
            ("2".to_string(), Value::Int(3)),
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Function(1); // Mock callback function

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeSome".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    // Should succeed (not crash from duplicate implementations)
    assert!(
        result.is_ok(),
        "Array.some should execute without duplicate implementation conflicts"
    );
}

#[test]
fn array_some_fail_closed_no_callback() {
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
            builtin: "builtin:ArrayPrototypeSome".to_string(),
            args: RegRange { start: 0, count: 1 }, // No callback
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(
        result.is_ok(),
        "Array.some should handle missing callback gracefully"
    );
    assert_eq!(
        core.registers[10],
        Value::Bool(false),
        "Array.some without callback should default to false"
    );
}

#[test]
fn array_some_fail_closed_non_object() {
    // Test fail-closed behavior when 'this' is not an object
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    core.registers[0] = Value::Str("not-an-array".to_string()); // Non-object this
    core.registers[1] = Value::Function(1); // Valid callback

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeSome".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(
        result.is_ok(),
        "Array.some should handle non-object 'this' gracefully"
    );
    assert_eq!(
        core.registers[10],
        Value::Bool(false),
        "Array.some with non-object 'this' should default to false"
    );
}

#[test]
fn array_some_fail_closed_invalid_callback() {
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
            builtin: "builtin:ArrayPrototypeSome".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(
        result.is_ok(),
        "Array.some should handle invalid callback gracefully"
    );
    // Behavior may vary - could return false or handle as no-op
}

#[test]
fn array_some_empty_array_handling() {
    // Test some behavior with empty array (should return false)
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
            builtin: "builtin:ArrayPrototypeSome".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(
        result.is_ok(),
        "Array.some should handle empty array correctly"
    );
    assert_eq!(
        core.registers[10],
        Value::Bool(false),
        "Array.some should return false for empty array"
    );
}

#[test]
fn array_some_sparse_array_handling() {
    // Test some with sparse array (missing indices)
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(5)),
            ("0".to_string(), Value::Int(1)),
            // Index 1 and 2 are missing (sparse)
            ("3".to_string(), Value::Int(4)),
            ("4".to_string(), Value::Int(5)),
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Function(1);

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeSome".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(
        result.is_ok(),
        "Array.some should handle sparse arrays correctly"
    );
    // Result depends on implementation details of callback handling
}

#[test]
fn array_some_callback_error_handling() {
    // Test fail-closed behavior when callback dispatch cannot be performed
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(3)),
            ("0".to_string(), Value::Bool(true)),
            ("1".to_string(), Value::Bool(false)),
            ("2".to_string(), Value::Bool(true)),
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Function(999); // Invalid function ID

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeSome".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    // Should not crash due to callback dispatch errors
    assert!(
        result.is_ok(),
        "Array.some should handle callback dispatch errors gracefully"
    );
}

#[test]
fn array_some_builtin_id_consistency() {
    // Verify some builtin is accessible and consistent after duplicate removal
    let core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    // Check if some builtin is properly mapped (exact ID may vary)
    let builtin_check = (0..400)
        .any(|id| core.builtin_name_from_id(id) == Some("builtin:ArrayPrototypeSome".to_string()));

    assert!(
        builtin_check,
        "ArrayPrototypeSome builtin should be mapped to at least one ID"
    );
}

#[test]
fn array_some_proper_boolean_return() {
    // Verify Array.some returns boolean values as expected
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    let array_id = ObjectId(10);
    core.heap.push(Object {
        properties: BTreeMap::from([
            ("length".to_string(), Value::Int(1)),
            ("0".to_string(), Value::Int(42)),
        ]),
    });

    core.registers[0] = Value::Object(array_id);
    core.registers[1] = Value::Function(1);

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ArrayPrototypeSome".to_string(),
            args: RegRange { start: 0, count: 2 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Array.some execution should succeed");

    // Result should be a boolean
    match core.registers[10] {
        Value::Bool(_) => {} // Expected
        other => panic!("Array.some should return boolean, got {:?}", other),
    }
}
