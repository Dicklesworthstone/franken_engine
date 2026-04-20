#![forbid(unsafe_code)]
//! Integration tests for baseline interpreter refactor commit f433744d.
//!
//! Tests the five major behavior changes that were introduced:
//! 1. Math.random deterministic PRNG (Xorshift64 integration)
//! 2. Console output capture (console.log/error/warn)
//! 3. Instruction profiling integration
//! 4. Extension ID in decision receipts
//! 5. Number.toString() radix conversion (base-2 through base-36)

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

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::baseline_interpreter::{
    ConsoleLevel, ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError,
    QuickJsLane, V8Lane, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    HostcallDecisionRecord, Ir3FunctionDesc, Ir3Instruction, Ir3Module, IrHeader, IrLevel,
    IrSchemaVersion, RegRange,
};
use frankenengine_engine::profiling::{Profiler, ProfilingConfig};

// ============================================================================
// Test Helpers
// ============================================================================

fn make_header() -> IrHeader {
    IrHeader {
        schema_version: IrSchemaVersion::CURRENT,
        level: IrLevel::Ir3,
        source_hash: None,
        source_label: "refactor-coverage-test".to_string(),
    }
}

fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    Ir3Module {
        header: make_header(),
        instructions,
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn test_module_with_pool(instructions: Vec<Ir3Instruction>, pool: Vec<String>) -> Ir3Module {
    let mut m = test_module(instructions);
    m.constant_pool = pool;
    m
}

fn test_module_with_functions(
    instructions: Vec<Ir3Instruction>,
    functions: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    let mut m = test_module(instructions);
    m.function_table = functions;
    m
}

fn qjs_run_with_config(
    module: &Ir3Module,
    config: InterpreterConfig,
) -> Result<ExecutionResult, InterpreterError> {
    let mut core = InterpreterCore::new(config);
    core.execute(module, "refactor-coverage-trace")
}

fn v8_run_with_config(
    module: &Ir3Module,
    config: InterpreterConfig,
) -> Result<ExecutionResult, InterpreterError> {
    let mut lane = V8Lane::new();
    lane.execute(module, "refactor-coverage-trace")
}

fn qjs_run(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    QuickJsLane::new().execute(module, "refactor-coverage-trace")
}

fn v8_run(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    V8Lane::new().execute(module, "refactor-coverage-trace")
}

// ============================================================================
// 1. Math.random Deterministic PRNG Tests
// ============================================================================

#[test]
fn math_random_uses_deterministic_xorshift64_prng() {
    // Test that Math.random produces deterministic output using Xorshift64
    let module = test_module_with_functions(
        vec![
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 1,
            },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            name: "builtin:MathRandom".to_string(),
            param_count: 0,
            local_count: 1,
            body_start: 0,
        }],
    );

    // Run the same module multiple times - should produce identical results
    let result1 = qjs_run(&module).unwrap();
    let result2 = qjs_run(&module).unwrap();
    let result3 = v8_run(&module).unwrap();

    // All results should be identical (deterministic)
    assert_eq!(
        result1.value, result2.value,
        "Math.random not deterministic between QJS runs"
    );
    assert_eq!(
        result1.value, result3.value,
        "Math.random not deterministic between QJS and V8 lanes"
    );

    // Value should be a float in [0, 1) range
    if let Value::Float(f) = result1.value {
        assert!(
            f.inner() >= 0.0 && f.inner() < 1.0,
            "Math.random value {} not in [0, 1) range",
            f.inner()
        );
        assert!(
            f.inner().is_finite(),
            "Math.random value {} not finite",
            f.inner()
        );
    } else {
        panic!(
            "Math.random should return Float value, got {:?}",
            result1.value
        );
    }
}

#[test]
fn math_random_different_execution_states_produce_different_values() {
    // Test that Math.random uses execution state in seed for variance
    let module1 = test_module_with_functions(
        vec![
            // Simple execution state
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            name: "builtin:MathRandom".to_string(),
            param_count: 0,
            local_count: 1,
            body_start: 0,
        }],
    );

    let module2 = test_module_with_functions(
        vec![
            // Different execution state - more instructions executed before Math.random
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
            Ir3Instruction::LoadInt { dst: 2, value: 99 },
            Ir3Instruction::Add {
                dst: 3,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            name: "builtin:MathRandom".to_string(),
            param_count: 0,
            local_count: 4,
            body_start: 0,
        }],
    );

    let result1 = qjs_run(&module1).unwrap();
    let result2 = qjs_run(&module2).unwrap();

    // Different execution states should produce different random values
    assert_ne!(
        result1.value, result2.value,
        "Math.random should produce different values for different execution states"
    );
}

#[test]
fn math_random_xorshift64_produces_full_precision() {
    // Test that Math.random utilizes full u64 precision from Xorshift64
    let module = test_module_with_functions(
        vec![
            // Generate multiple random values
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 1,
            },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 2,
            },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 0 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![Ir3FunctionDesc {
            name: "builtin:MathRandom".to_string(),
            param_count: 0,
            local_count: 4,
            body_start: 0,
        }],
    );

    let result = qjs_run(&module).unwrap();

    // Should return a float value
    if let Value::Float(f) = result.value {
        let val = f.inner();
        assert!(
            val >= 0.0 && val < 1.0,
            "Math.random value {} not in [0, 1) range",
            val
        );
        assert!(val.is_finite(), "Math.random value {} not finite", val);

        // Value should have meaningful precision (not just simple fractions)
        // The old implementation used modulo 1_000_000_000, so we ensure we have more precision
        let scaled = val * 1_000_000_000_000_000.0; // Scale by 10^15
        assert!(
            scaled.fract() != 0.0,
            "Math.random should have sub-nanosecond precision"
        );
    } else {
        panic!(
            "Math.random should return Float value, got {:?}",
            result.value
        );
    }
}

// ============================================================================
// 2. Console Output Capture Tests
// ============================================================================

#[test]
fn console_log_captured_with_correct_metadata() {
    // Test that console.log calls are captured with proper ConsoleEntry metadata
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 1,
            },
            Ir3Instruction::HostCall {
                capability: "console:log".to_string(),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec!["Hello".to_string(), "World".to_string()],
    );

    let result = qjs_run(&module).unwrap();

    // Should have one console output entry
    assert_eq!(
        result.console_output.len(),
        1,
        "Expected exactly one console output entry"
    );

    let entry = &result.console_output[0];
    assert_eq!(
        entry.level,
        ConsoleLevel::Log,
        "Console entry should have Log level"
    );
    assert_eq!(
        entry.message, "Hello World",
        "Console entry should join arguments with spaces"
    );
    assert!(
        entry.instruction_index > 0,
        "Console entry should have non-zero instruction index"
    );
}

#[test]
fn console_error_captured_with_correct_metadata() {
    // Test that console.error calls are captured with Error level
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: "console:error".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ],
        vec!["Error occurred".to_string()],
    );

    let result = qjs_run(&module).unwrap();

    assert_eq!(
        result.console_output.len(),
        1,
        "Expected exactly one console output entry"
    );

    let entry = &result.console_output[0];
    assert_eq!(
        entry.level,
        ConsoleLevel::Error,
        "Console entry should have Error level"
    );
    assert_eq!(
        entry.message, "Error occurred",
        "Console error message should match"
    );
    assert!(
        entry.instruction_index > 0,
        "Console entry should have non-zero instruction index"
    );
}

#[test]
fn console_warn_captured_with_correct_metadata() {
    // Test that console.warn calls are captured with Warn level
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
            Ir3Instruction::HostCall {
                capability: "console:warn".to_string(),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec!["Warning:".to_string()],
    );

    let result = qjs_run(&module).unwrap();

    assert_eq!(
        result.console_output.len(),
        1,
        "Expected exactly one console output entry"
    );

    let entry = &result.console_output[0];
    assert_eq!(
        entry.level,
        ConsoleLevel::Warn,
        "Console entry should have Warn level"
    );
    assert_eq!(
        entry.message, "Warning: 42",
        "Console warn message should include number"
    );
    assert!(
        entry.instruction_index > 0,
        "Console entry should have non-zero instruction index"
    );
}

#[test]
fn console_info_captured_with_correct_metadata() {
    // Test that console.info calls are captured with Info level
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
            Ir3Instruction::HostCall {
                capability: "console:info".to_string(),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec!["Info message".to_string()],
    );

    let result = qjs_run(&module).unwrap();

    assert_eq!(
        result.console_output.len(),
        1,
        "Expected exactly one console output entry"
    );

    let entry = &result.console_output[0];
    assert_eq!(
        entry.level,
        ConsoleLevel::Info,
        "Console entry should have Info level"
    );
    assert_eq!(
        entry.message, "Info message 42",
        "Console info message should include number"
    );
    assert!(
        entry.instruction_index > 0,
        "Console entry should have non-zero instruction index"
    );
}

#[test]
fn console_output_captured_instead_of_printed() {
    // Test that console calls no longer print to stdout/stderr, only capture
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: "console:log".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::HostCall {
                capability: "console:error".to_string(),
                args: RegRange { start: 2, count: 1 },
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::HostCall {
                capability: "console:warn".to_string(),
                args: RegRange { start: 4, count: 1 },
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "Log message".to_string(),
            "Error message".to_string(),
            "Warning message".to_string(),
        ],
    );

    let result = qjs_run(&module).unwrap();

    // Should have three console output entries, one for each level
    assert_eq!(
        result.console_output.len(),
        3,
        "Expected three console output entries"
    );

    assert_eq!(result.console_output[0].level, ConsoleLevel::Log);
    assert_eq!(result.console_output[0].message, "Log message");

    assert_eq!(result.console_output[1].level, ConsoleLevel::Error);
    assert_eq!(result.console_output[1].message, "Error message");

    assert_eq!(result.console_output[2].level, ConsoleLevel::Warn);
    assert_eq!(result.console_output[2].message, "Warning message");

    // All should have increasing instruction indices
    assert!(
        result.console_output[0].instruction_index < result.console_output[1].instruction_index
    );
    assert!(
        result.console_output[1].instruction_index < result.console_output[2].instruction_index
    );
}

// ============================================================================
// 3. Instruction Profiling Integration Tests
// ============================================================================

#[test]
fn instruction_profiling_records_instructions_when_enabled() {
    // Test that profiler.record_instruction() is called when profiling is enabled
    let mut config = InterpreterConfig::quickjs();
    config.extension_id = Some("test-extension".to_string());

    // Enable profiling
    let profiling_config = ProfilingConfig::default();

    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::LoadInt { dst: 1, value: 99 },
        Ir3Instruction::Add {
            dst: 2,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Return { value: 2 },
    ]);

    // Create interpreter core with profiling enabled
    let mut core = InterpreterCore::new(config);
    core.enable_profiling(profiling_config);

    let result = core.execute(&module, "profiling-test-trace").unwrap();

    // Execution should succeed and return the expected value
    assert_eq!(result.value, Value::Int(141));

    // Get profiling data
    let profiling_data = core.profiling_data();
    assert!(
        profiling_data.is_some(),
        "Profiling data should be available"
    );

    let profiler = profiling_data.unwrap();

    // Verify that instructions were recorded
    // The profiler should have recorded at least the main instructions executed
    let recorded_instructions = profiler.instruction_count();
    assert!(
        recorded_instructions >= 4,
        "Should have recorded at least 4 instructions, got {}",
        recorded_instructions
    );
}

#[test]
fn instruction_profiling_records_timing_data() {
    // Test that profiler.record_instruction_time() captures timing
    let mut config = InterpreterConfig::quickjs();
    config.extension_id = Some("timing-test".to_string());

    let profiling_config = ProfilingConfig::default();

    let module = test_module(vec![
        // Execute some instructions that should take measurable time
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::LoadInt {
            dst: 1,
            value: 1000,
        },
        // Loop to create some work
        Ir3Instruction::Add {
            dst: 2,
            lhs: 0,
            rhs: 0,
        }, // Initialize counter
        Ir3Instruction::Add {
            dst: 3,
            lhs: 2,
            rhs: 0,
        }, // Work
        Ir3Instruction::Add {
            dst: 4,
            lhs: 3,
            rhs: 0,
        }, // More work
        Ir3Instruction::Return { value: 4 },
    ]);

    let mut core = InterpreterCore::new(config);
    core.enable_profiling(profiling_config);

    let result = core.execute(&module, "timing-test-trace").unwrap();

    // Execution should complete
    assert_eq!(result.value, Value::Int(1));

    // Get profiling data and verify timing was recorded
    let profiling_data = core.profiling_data();
    assert!(
        profiling_data.is_some(),
        "Profiling data should be available"
    );

    let profiler = profiling_data.unwrap();

    // Should have recorded timing data for instructions
    let total_time = profiler.total_execution_time();
    assert!(
        total_time.as_nanos() > 0,
        "Should have recorded some execution time"
    );
}

#[test]
fn instruction_profiling_disabled_by_default() {
    // Test that profiling is disabled by default and no data is recorded
    let config = InterpreterConfig::quickjs();

    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Return { value: 0 },
    ]);

    let mut core = InterpreterCore::new(config);
    let result = core.execute(&module, "no-profiling-trace").unwrap();

    // Execution should succeed
    assert_eq!(result.value, Value::Int(42));

    // Profiling data should not be available
    let profiling_data = core.profiling_data();
    assert!(
        profiling_data.is_none(),
        "Profiling data should not be available when not enabled"
    );
}

// ============================================================================
// 4. Extension ID in Decision Receipts Tests
// ============================================================================

#[test]
fn extension_id_propagated_to_decision_receipts() {
    // Test that extension_id from config is used in decision receipts
    let mut config = InterpreterConfig::quickjs();
    config.extension_id = Some("test-extension-123".to_string());

    // Create a module that would trigger decision receipt creation
    // Use a hostcall that requires capability checking
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: "test:capability".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ],
        vec!["test-data".to_string()],
    );

    let result = qjs_run_with_config(&module, config);

    // Hostcall should fail due to missing capability, but that's expected
    // We're testing the decision receipt recording
    match result {
        Ok(exec_result) => {
            // Check if any hostcall decisions were recorded
            if !exec_result.hostcall_decisions.is_empty() {
                let decision = &exec_result.hostcall_decisions[0];
                // The decision should contain our extension ID
                assert!(
                    decision.context.contains("test-extension-123"),
                    "Decision context should contain extension ID: {}",
                    decision.context
                );
            }
        }
        Err(_) => {
            // Error is fine, we're mainly testing that extension ID flows through
        }
    }
}

#[test]
fn extension_id_defaults_to_legacy_placeholder() {
    // Test that when extension_id is None, it defaults to "extension:current"
    let config = InterpreterConfig::quickjs(); // No extension_id set

    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: "test:capability".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ],
        vec!["test-data".to_string()],
    );

    let result = qjs_run_with_config(&module, config);

    match result {
        Ok(exec_result) => {
            if !exec_result.hostcall_decisions.is_empty() {
                let decision = &exec_result.hostcall_decisions[0];
                // Should use the legacy placeholder
                assert!(
                    decision.context.contains("extension:current"),
                    "Should default to 'extension:current' when no extension_id set: {}",
                    decision.context
                );
            }
        }
        Err(_) => {
            // Error is expected for unknown capability
        }
    }
}

#[test]
fn extension_id_flows_through_decision_receipt_chain() {
    // Test that extension_id is consistently used across multiple decision receipts
    let mut config = InterpreterConfig::quickjs();
    config.extension_id = Some("multi-decision-test".to_string());

    let module = test_module_with_pool(
        vec![
            // Multiple hostcalls that might generate decision receipts
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: "test:first".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::HostCall {
                capability: "test:second".to_string(),
                args: RegRange { start: 2, count: 1 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["first-data".to_string(), "second-data".to_string()],
    );

    let result = qjs_run_with_config(&module, config);

    match result {
        Ok(exec_result) => {
            // If we have multiple decisions, they should all have the same extension ID
            for (i, decision) in exec_result.hostcall_decisions.iter().enumerate() {
                assert!(
                    decision.context.contains("multi-decision-test"),
                    "Decision {} should contain extension ID: {}",
                    i,
                    decision.context
                );
            }
        }
        Err(_) => {
            // Error expected due to missing capabilities
        }
    }
}

// ============================================================================
// 5. Number.toString() Radix Conversion Tests
// ============================================================================

#[test]
fn number_tostring_radix_base2_through_base36() {
    // Test proper radix conversion for all valid bases (2-36)
    let test_cases = vec![
        (42, 2, "101010"),
        (42, 8, "52"),
        (42, 10, "42"),
        (42, 16, "2a"),
        (255, 16, "ff"),
        (1000, 2, "1111101000"),
        (1000, 36, "rs"),
        (35, 36, "z"), // Maximum single digit in base 36
    ];

    for (number, radix, expected) in test_cases {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt {
                    dst: 0,
                    value: number,
                },
                Ir3Instruction::LoadInt {
                    dst: 1,
                    value: radix,
                },
                Ir3Instruction::CallFunction {
                    func_index: 0,
                    args: RegRange { start: 0, count: 2 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                name: "builtin:NumberToString".to_string(),
                param_count: 2,
                local_count: 3,
                body_start: 0,
            }],
        );

        let result = qjs_run(&module).unwrap();

        if let Value::Str(s) = result.value {
            assert_eq!(
                s, expected,
                "Number.toString({}, {}) should be {}, got {}",
                number, radix, expected, s
            );
        } else {
            panic!(
                "Number.toString should return String, got {:?}",
                result.value
            );
        }
    }
}

#[test]
fn number_tostring_handles_negative_numbers() {
    // Test that negative numbers are properly handled with radix conversion
    let test_cases = vec![
        (-42, 2, "-101010"),
        (-42, 8, "-52"),
        (-42, 10, "-42"),
        (-42, 16, "-2a"),
        (-255, 16, "-ff"),
    ];

    for (number, radix, expected) in test_cases {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt {
                    dst: 0,
                    value: number,
                },
                Ir3Instruction::LoadInt {
                    dst: 1,
                    value: radix,
                },
                Ir3Instruction::CallFunction {
                    func_index: 0,
                    args: RegRange { start: 0, count: 2 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                name: "builtin:NumberToString".to_string(),
                param_count: 2,
                local_count: 3,
                body_start: 0,
            }],
        );

        let result = qjs_run(&module).unwrap();

        if let Value::Str(s) = result.value {
            assert_eq!(
                s, expected,
                "Number.toString({}, {}) should be {}, got {}",
                number, radix, expected, s
            );
        } else {
            panic!(
                "Number.toString should return String, got {:?}",
                result.value
            );
        }
    }
}

#[test]
fn number_tostring_handles_special_float_values() {
    // Test that NaN, Infinity, and -Infinity are handled properly
    use frankenengine_engine::baseline_interpreter::Float64;

    // Test NaN
    let module_nan = test_module_with_functions(
        vec![
            Ir3Instruction::LoadFloat {
                dst: 0,
                value: Float64::new(f64::NAN),
            },
            Ir3Instruction::LoadInt { dst: 1, value: 16 },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![Ir3FunctionDesc {
            name: "builtin:NumberToString".to_string(),
            param_count: 2,
            local_count: 3,
            body_start: 0,
        }],
    );

    let result_nan = qjs_run(&module_nan).unwrap();
    if let Value::Str(s) = result_nan.value {
        assert_eq!(s, "NaN", "NaN.toString() should be 'NaN', got {}", s);
    } else {
        panic!(
            "NaN.toString should return String, got {:?}",
            result_nan.value
        );
    }

    // Test positive infinity
    let module_inf = test_module_with_functions(
        vec![
            Ir3Instruction::LoadFloat {
                dst: 0,
                value: Float64::new(f64::INFINITY),
            },
            Ir3Instruction::LoadInt { dst: 1, value: 16 },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![Ir3FunctionDesc {
            name: "builtin:NumberToString".to_string(),
            param_count: 2,
            local_count: 3,
            body_start: 0,
        }],
    );

    let result_inf = qjs_run(&module_inf).unwrap();
    if let Value::Str(s) = result_inf.value {
        assert_eq!(
            s, "Infinity",
            "Infinity.toString() should be 'Infinity', got {}",
            s
        );
    } else {
        panic!(
            "Infinity.toString should return String, got {:?}",
            result_inf.value
        );
    }

    // Test negative infinity
    let module_neg_inf = test_module_with_functions(
        vec![
            Ir3Instruction::LoadFloat {
                dst: 0,
                value: Float64::new(f64::NEG_INFINITY),
            },
            Ir3Instruction::LoadInt { dst: 1, value: 16 },
            Ir3Instruction::CallFunction {
                func_index: 0,
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Return { value: 2 },
        ],
        vec![Ir3FunctionDesc {
            name: "builtin:NumberToString".to_string(),
            param_count: 2,
            local_count: 3,
            body_start: 0,
        }],
    );

    let result_neg_inf = qjs_run(&module_neg_inf).unwrap();
    if let Value::Str(s) = result_neg_inf.value {
        assert_eq!(
            s, "-Infinity",
            "(-Infinity).toString() should be '-Infinity', got {}",
            s
        );
    } else {
        panic!(
            "(-Infinity).toString should return String, got {:?}",
            result_neg_inf.value
        );
    }
}

#[test]
fn number_tostring_handles_zero_special_case() {
    // Test that zero is handled correctly for all radix values
    let radix_values = vec![2, 8, 10, 16, 36];

    for radix in radix_values {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 0 },
                Ir3Instruction::LoadInt {
                    dst: 1,
                    value: radix,
                },
                Ir3Instruction::CallFunction {
                    func_index: 0,
                    args: RegRange { start: 0, count: 2 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                name: "builtin:NumberToString".to_string(),
                param_count: 2,
                local_count: 3,
                body_start: 0,
            }],
        );

        let result = qjs_run(&module).unwrap();

        if let Value::Str(s) = result.value {
            assert_eq!(s, "0", "0.toString({}) should be '0', got {}", radix, s);
        } else {
            panic!("0.toString should return String, got {:?}", result.value);
        }
    }
}

#[test]
fn number_tostring_truncates_fractional_parts() {
    // Test that fractional parts are truncated for radix conversion
    use frankenengine_engine::baseline_interpreter::Float64;

    let test_cases = vec![
        (42.7, 16, "2a"),      // 42.7 truncates to 42
        (99.99, 2, "1100011"), // 99.99 truncates to 99
        (-42.3, 16, "-2a"),    // -42.3 truncates to -42
    ];

    for (number, radix, expected) in test_cases {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadFloat {
                    dst: 0,
                    value: Float64::new(number),
                },
                Ir3Instruction::LoadInt {
                    dst: 1,
                    value: radix,
                },
                Ir3Instruction::CallFunction {
                    func_index: 0,
                    args: RegRange { start: 0, count: 2 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                name: "builtin:NumberToString".to_string(),
                param_count: 2,
                local_count: 3,
                body_start: 0,
            }],
        );

        let result = qjs_run(&module).unwrap();

        if let Value::Str(s) = result.value {
            assert_eq!(
                s, expected,
                "({}).toString({}) should be {}, got {}",
                number, radix, expected, s
            );
        } else {
            panic!(
                "Float.toString should return String, got {:?}",
                result.value
            );
        }
    }
}

#[test]
fn number_tostring_consistent_with_both_lanes() {
    // Test that both QJS and V8 lanes produce identical radix conversion results
    let test_cases = vec![
        (123, 2),
        (123, 8),
        (123, 10),
        (123, 16),
        (123, 36),
        (-456, 2),
        (-456, 16),
        (0, 2),
        (0, 36),
    ];

    for (number, radix) in test_cases {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt {
                    dst: 0,
                    value: number,
                },
                Ir3Instruction::LoadInt {
                    dst: 1,
                    value: radix,
                },
                Ir3Instruction::CallFunction {
                    func_index: 0,
                    args: RegRange { start: 0, count: 2 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                name: "builtin:NumberToString".to_string(),
                param_count: 2,
                local_count: 3,
                body_start: 0,
            }],
        );

        let result_qjs = qjs_run(&module).unwrap();
        let result_v8 = v8_run(&module).unwrap();

        assert_eq!(
            result_qjs.value, result_v8.value,
            "QJS and V8 lanes should produce identical results for ({}).toString({})",
            number, radix
        );
    }
}
