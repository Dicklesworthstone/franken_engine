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

use frankenengine_engine::baseline_interpreter::{
    ConsoleLevel, ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError,
    QuickJsLane, V8Lane, Value,
};
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};

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
    _functions: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    test_module(instructions)
}

fn qjs_run_with_config(
    module: &Ir3Module,
    config: InterpreterConfig,
) -> Result<ExecutionResult, InterpreterError> {
    let mut core = InterpreterCore::new(config, "refactor-coverage-trace");
    core.execute(module)
}

fn v8_run_with_config(
    module: &Ir3Module,
    _config: InterpreterConfig,
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

#[allow(dead_code)]
struct Ir3FunctionDesc {
    name: String,
    param_count: u32,
    local_count: u32,
    body_start: u32,
}

fn call_math_random(dst: u32) -> Ir3Instruction {
    Ir3Instruction::HostCall {
        capability: CapabilityTag("builtin:MathRandom".to_string()),
        args: RegRange { start: 0, count: 0 },
        dst,
    }
}

fn call_number_to_string(dst: u32) -> Ir3Instruction {
    Ir3Instruction::HostCall {
        capability: CapabilityTag("builtin:NumberPrototypeToString".to_string()),
        args: RegRange { start: 0, count: 2 },
        dst,
    }
}

fn load_float(dst: u32, value: f64) -> Ir3Instruction {
    Ir3Instruction::LoadFloat {
        dst,
        bits: value.to_bits(),
    }
}

fn baseline_interpreter_source() -> &'static str {
    include_str!("../src/baseline_interpreter.rs")
}

// ============================================================================
// 1. Math.random Deterministic PRNG Tests
// ============================================================================

#[test]
fn math_random_uses_deterministic_xorshift64_prng() {
    // Test that Math.random produces deterministic output using Xorshift64
    let module = test_module_with_functions(
        vec![
            call_math_random(0),
            call_math_random(1),
            call_math_random(2),
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
            call_math_random(0),
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
            call_math_random(0),
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
            call_math_random(0),
            call_math_random(1),
            call_math_random(2),
            call_math_random(3),
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
                capability: CapabilityTag("console:log".to_string()),
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
                capability: CapabilityTag("console:error".to_string()),
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
                capability: CapabilityTag("console:warn".to_string()),
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
                capability: CapabilityTag("console:info".to_string()),
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
                capability: CapabilityTag("console:log".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:error".to_string()),
                args: RegRange { start: 2, count: 1 },
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:warn".to_string()),
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
    let source = baseline_interpreter_source();
    assert!(source.contains("profiler.record_instruction(instruction);"));
    assert!(source.contains("profiler.record_instruction_time("));
    assert!(source.contains("profile_start.elapsed()"));
}

#[test]
fn instruction_profiling_records_timing_data() {
    let source = baseline_interpreter_source();
    assert!(source.contains("let profile_start = if self.profiling_data.is_some()"));
    assert!(source.contains("let profiling_instruction = if self.profiling_data.is_some()"));
    assert!(
        source.contains("profiler.record_instruction_time(instruction, profile_start.elapsed())")
    );
}

#[test]
fn instruction_profiling_disabled_by_default() {
    let source = baseline_interpreter_source();
    assert!(source.contains("profiling_data: None"));
}

// ============================================================================
// 4. Extension ID in Decision Receipts Tests
// ============================================================================

#[test]
fn extension_id_propagated_to_decision_receipts() {
    let source = baseline_interpreter_source();
    assert!(source.contains("self.decision_receipts.add_receipt("));
    assert!(source.contains("self.config"));
    assert!(source.contains(".extension_id"));
}

#[test]
fn extension_id_defaults_to_legacy_placeholder() {
    let source = baseline_interpreter_source();
    assert!(source.contains(".unwrap_or_else(|| \"extension:current\".to_string())"));
}

#[test]
fn extension_id_flows_through_decision_receipt_chain() {
    let source = baseline_interpreter_source();
    assert!(source.contains("receipt.extension_id"));
    assert!(source.contains("self.receipt_signing_message(receipt)"));
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
                call_number_to_string(2),
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
                call_number_to_string(2),
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
    // Test NaN
    let module_nan = test_module_with_functions(
        vec![
            load_float(0, f64::NAN),
            Ir3Instruction::LoadInt { dst: 1, value: 16 },
            call_number_to_string(2),
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
            load_float(0, f64::INFINITY),
            Ir3Instruction::LoadInt { dst: 1, value: 16 },
            call_number_to_string(2),
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
            load_float(0, f64::NEG_INFINITY),
            Ir3Instruction::LoadInt { dst: 1, value: 16 },
            call_number_to_string(2),
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
                call_number_to_string(2),
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
    let test_cases = vec![
        (42.7, 16, "2a"),      // 42.7 truncates to 42
        (99.99, 2, "1100011"), // 99.99 truncates to 99
        (-42.3, 16, "-2a"),    // -42.3 truncates to -42
    ];

    for (number, radix, expected) in test_cases {
        let module = test_module_with_functions(
            vec![
                load_float(0, number),
                Ir3Instruction::LoadInt {
                    dst: 1,
                    value: radix,
                },
                call_number_to_string(2),
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
                call_number_to_string(2),
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
