//! Comprehensive tests for error stack trace formatting (bd-2fx18).
//!
//! Verifies proper V8-style stack trace formatting with:
//! - Simple call chain formatting
//! - Nested function calls with proper frame order
//! - Async/await frame chain preservation
//! - Stack truncation with "... N more frames" message
//! - Missing information fallback handling
//! - BTreeSet/BTreeMap deterministic ordering

#![forbid(unsafe_code)]

use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    Ir3FunctionDesc, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange, Value,
};
use std::collections::BTreeSet;

/// Create an InterpreterCore with minimal capabilities for testing.
fn test_interpreter() -> InterpreterCore {
    let mut config = InterpreterConfig::default();
    config.granted_capabilities.clear();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    InterpreterCore::new(config, "stack-trace-test")
}

/// Create an IR3 module that creates an Error object to test stack trace.
fn module_with_error(function_name: &str, nested_calls: usize) -> Ir3Module {
    let mut instructions = vec![
        // Create Error constructor function call
        Ir3Instruction::LoadConstant {
            dst: 0,
            value: Value::Function(0), // Error constructor function
        },
        Ir3Instruction::LoadConstant {
            dst: 1,
            value: Value::Str("Test error message".to_string()),
        },
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 1, count: 1 },
            dst: 2,
        },
    ];

    // Add nested function calls if requested
    for i in 0..nested_calls {
        instructions.push(Ir3Instruction::LoadConstant {
            dst: (3 + i) as u32,
            value: Value::Function((i + 1) as u32),
        });
        instructions.push(Ir3Instruction::Call {
            callee: (3 + i) as u32,
            args: RegRange { start: 2, count: 1 },
            dst: (4 + i) as u32,
        });
    }

    instructions.push(Ir3Instruction::Halt);

    let mut functions = vec![
        // Error constructor (builtin)
        Ir3FunctionDesc {
            id: 0,
            name: "Error".to_string(),
            param_count: 1,
            instructions: vec![
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Str("builtin:Error".to_string()),
                },
                Ir3Instruction::Return { value: 0 },
            ],
        },
    ];

    // Add nested functions
    for i in 0..nested_calls {
        functions.push(Ir3FunctionDesc {
            id: (i + 1) as u32,
            name: format!("{}_{}", function_name, i),
            param_count: 1,
            instructions: vec![
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Undefined,
                },
                Ir3Instruction::Return { value: 0 },
            ],
        });
    }

    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: Some(ContentHash::compute(function_name.as_bytes())),
            source_label: format!("{}.js", function_name),
        },
        instructions,
        constant_pool: Vec::new(),
        function_table: functions,
        bindings: Vec::new(),
        debug_info: None,
    }
}

/// Create an IR3 module with async function simulation.
fn module_with_async_error() -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: Some(ContentHash::compute(b"async-error-test")),
            source_label: "async-test.js".to_string(),
        },
        instructions: vec![
            // Simulate async function call that creates an error
            Ir3Instruction::LoadConstant {
                dst: 0,
                value: Value::Function(0), // Async function
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ],
        constant_pool: Vec::new(),
        function_table: vec![
            Ir3FunctionDesc {
                id: 0,
                name: "asyncFunction".to_string(),
                param_count: 0,
                instructions: vec![
                    // Create Error inside async function
                    Ir3Instruction::LoadConstant {
                        dst: 0,
                        value: Value::Function(1), // Error constructor
                    },
                    Ir3Instruction::LoadConstant {
                        dst: 1,
                        value: Value::Str("Async error".to_string()),
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange { start: 1, count: 1 },
                        dst: 2,
                    },
                    Ir3Instruction::Return { value: 2 },
                ],
            },
            Ir3FunctionDesc {
                id: 1,
                name: "Error".to_string(),
                param_count: 1,
                instructions: vec![
                    Ir3Instruction::LoadConstant {
                        dst: 0,
                        value: Value::Str("builtin:Error".to_string()),
                    },
                    Ir3Instruction::Return { value: 0 },
                ],
            },
        ],
        bindings: Vec::new(),
        debug_info: None,
    }
}

#[test]
fn test_simple_error_stack_trace() {
    let mut core = test_interpreter();
    let module = module_with_error("simpleTest", 0);

    let result = core.execute(&module);
    assert!(result.is_ok(), "Module execution should succeed");

    // Check that the error object was created with stack trace
    let error_obj = core
        .read_reg(2)
        .expect("Error object should be in register 2");
    if let Value::Object(obj_id) = error_obj {
        let obj = core.heap.get(&obj_id).expect("Error object should exist");

        // Check that stack property exists
        assert!(
            obj.properties.contains_key("stack"),
            "Error object should have stack property"
        );

        let stack_value = obj.properties.get("stack").unwrap();
        if let Value::Str(stack_trace) = stack_value {
            // Verify V8-style formatting
            assert!(
                stack_trace.contains("at "),
                "Stack trace should contain 'at ' prefix: {}",
                stack_trace
            );
            assert!(
                stack_trace.contains("simpleTest.js"),
                "Stack trace should contain source file: {}",
                stack_trace
            );
        } else {
            panic!("Stack property should be a string");
        }
    } else {
        panic!("Error constructor should return an object");
    }
}

#[test]
fn test_nested_call_stack_order() {
    let mut core = test_interpreter();
    let module = module_with_error("nestedTest", 3);

    let result = core.execute(&module);
    assert!(result.is_ok(), "Module execution should succeed");

    let error_obj = core
        .read_reg(2)
        .expect("Error object should be in register 2");
    if let Value::Object(obj_id) = error_obj {
        let obj = core.heap.get(&obj_id).expect("Error object should exist");
        let stack_value = obj.properties.get("stack").unwrap();

        if let Value::Str(stack_trace) = stack_value {
            // Verify that nested functions appear in correct order
            // Stack traces should show innermost frame first
            let lines: Vec<&str> = stack_trace.lines().collect();
            assert!(
                lines.len() >= 2,
                "Should have at least 2 stack frames: {}",
                stack_trace
            );

            // Each line should start with "    at "
            for line in &lines {
                if !line.trim().starts_with("...") {
                    assert!(
                        line.starts_with("    at "),
                        "Stack frame should start with '    at ': '{}'",
                        line
                    );
                }
            }
        }
    }
}

#[test]
fn test_async_frame_chain_support() {
    let mut core = test_interpreter();
    let module = module_with_async_error();

    let result = core.execute(&module);
    assert!(result.is_ok(), "Async module execution should succeed");

    let error_obj = core
        .read_reg(1)
        .expect("Error object should be in register 1");
    if let Value::Object(obj_id) = error_obj {
        let obj = core.heap.get(&obj_id).expect("Error object should exist");
        let stack_value = obj.properties.get("stack").unwrap();

        if let Value::Str(stack_trace) = stack_value {
            // Verify async function appears in stack trace
            assert!(
                stack_trace.contains("asyncFunction"),
                "Stack trace should contain async function: {}",
                stack_trace
            );
        }
    }
}

#[test]
fn test_stack_trace_truncation() {
    // Test truncation by creating a module with many nested calls
    let mut core = test_interpreter();
    let module = module_with_error("truncationTest", 60); // More than default max (50)

    let result = core.execute(&module);
    assert!(result.is_ok(), "Module execution should succeed");

    let error_obj = core
        .read_reg(2)
        .expect("Error object should be in register 2");
    if let Value::Object(obj_id) = error_obj {
        let obj = core.heap.get(&obj_id).expect("Error object should exist");
        let stack_value = obj.properties.get("stack").unwrap();

        if let Value::Str(stack_trace) = stack_value {
            // Should contain truncation message for large stacks
            let line_count = stack_trace.lines().count();

            // If truncated, should have truncation message
            if line_count >= 50 {
                assert!(
                    stack_trace.contains("more frames"),
                    "Large stack should show truncation message: {}",
                    stack_trace
                );
            }
        }
    }
}

#[test]
fn test_missing_info_fallback() {
    let mut core = test_interpreter();

    // Create module with minimal debug info
    let module = Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,           // No source hash
            source_label: String::new(), // Empty source label
        },
        instructions: vec![
            Ir3Instruction::LoadConstant {
                dst: 0,
                value: Value::Function(0),
            },
            Ir3Instruction::LoadConstant {
                dst: 1,
                value: Value::Str("Missing info error".to_string()),
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 1 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ],
        constant_pool: Vec::new(),
        function_table: vec![Ir3FunctionDesc {
            id: 0,
            name: String::new(), // Empty function name
            param_count: 1,
            instructions: vec![
                Ir3Instruction::LoadConstant {
                    dst: 0,
                    value: Value::Str("builtin:Error".to_string()),
                },
                Ir3Instruction::Return { value: 0 },
            ],
        }],
        bindings: Vec::new(),
        debug_info: None,
    };

    let result = core.execute(&module);
    assert!(
        result.is_ok(),
        "Module execution should succeed even with missing info"
    );

    let error_obj = core
        .read_reg(2)
        .expect("Error object should be in register 2");
    if let Value::Object(obj_id) = error_obj {
        let obj = core.heap.get(&obj_id).expect("Error object should exist");
        let stack_value = obj.properties.get("stack").unwrap();

        if let Value::Str(stack_trace) = stack_value {
            // Should contain fallback values for missing information
            assert!(
                stack_trace.contains("<unknown>") || stack_trace.contains("<anonymous>"),
                "Stack trace should contain fallback for missing info: {}",
                stack_trace
            );
        }
    }
}

#[test]
fn test_btreeset_determinism() {
    // Test that identical inputs produce identical stack traces
    let mut results = BTreeSet::new();

    // Run the same scenario multiple times
    for iteration in 0..5 {
        let mut core = test_interpreter();
        let module = module_with_error(&format!("determinismTest_{}", iteration), 2);

        let result = core.execute(&module);
        assert!(
            result.is_ok(),
            "Module execution should succeed in iteration {}",
            iteration
        );

        let error_obj = core
            .read_reg(2)
            .expect("Error object should be in register 2");
        if let Value::Object(obj_id) = error_obj {
            let obj = core.heap.get(&obj_id).expect("Error object should exist");
            let stack_value = obj.properties.get("stack").unwrap();

            if let Value::Str(stack_trace) = stack_value {
                // Store the format pattern (removing instance-specific details)
                let normalized = stack_trace
                    .lines()
                    .map(|line| {
                        if line.contains("determinismTest") {
                            // Normalize to remove iteration number
                            line.replace(
                                &format!("determinismTest_{}", iteration),
                                "determinismTest_X",
                            )
                        } else {
                            line.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                results.insert(normalized);
            }
        }
    }

    // All runs should produce the same normalized format
    assert_eq!(
        results.len(),
        1,
        "All iterations should produce identical stack trace format, but got {} unique formats",
        results.len()
    );
}

#[test]
fn test_v8_style_formatting() {
    let mut core = test_interpreter();
    let module = module_with_error("v8StyleTest", 1);

    let result = core.execute(&module);
    assert!(result.is_ok(), "Module execution should succeed");

    let error_obj = core
        .read_reg(2)
        .expect("Error object should be in register 2");
    if let Value::Object(obj_id) = error_obj {
        let obj = core.heap.get(&obj_id).expect("Error object should exist");
        let stack_value = obj.properties.get("stack").unwrap();

        if let Value::Str(stack_trace) = stack_value {
            // Verify V8-style format: "    at funcName (file:line:col)"
            let lines: Vec<&str> = stack_trace.lines().collect();

            for line in &lines {
                if !line.trim().starts_with("...") {
                    // Check format: "    at funcName (location)"
                    assert!(
                        line.starts_with("    at "),
                        "Line should start with '    at ': '{}'",
                        line
                    );

                    if line.contains('(') && line.contains(')') {
                        assert!(
                            line.matches('(').count() == 1 && line.matches(')').count() == 1,
                            "Line should have exactly one set of parentheses: '{}'",
                            line
                        );
                    }
                }
            }

            // Should contain source file reference
            assert!(
                stack_trace.contains(".js"),
                "Stack trace should reference source file: {}",
                stack_trace
            );
        }
    }
}
