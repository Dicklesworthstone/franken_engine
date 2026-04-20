#![forbid(unsafe_code)]

//! Integration tests for Math.round and ConsoleLevel::Info fixes
//!
//! Regression tests for commit 5e20ceac701c03a02f70fda1966e2677c9a73f8e
//! Verifies Math.round negative half semantics and ConsoleLevel::Info dispatch

use frankenengine_engine::baseline_interpreter::{
    ConsoleLevel, InterpreterConfig, InterpreterCore,
};
use frankenengine_engine::ir3::{Ir3Instruction, Module, RegRange};
use frankenengine_engine::value::Value;

fn test_module(instructions: Vec<Ir3Instruction>) -> Module {
    Module { instructions }
}

#[test]
fn math_round_negative_half_integration() {
    // Regression test for Math.round(-0.5) -> floor(-0.5 + 0.5) = floor(0) = 0
    // Per JavaScript Math.round semantics, NOT Rust's round_away_from_zero
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    core.registers[0] = Value::Float((-0.5).into());

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:MathRound".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Math.round execution should succeed");

    let rounded_value = core.registers[10].clone();
    if let Value::Int(n) = rounded_value {
        assert_eq!(
            n, 0,
            "Math.round(-0.5) should equal 0 per JavaScript semantics"
        );
    } else if let Value::Float(f) = rounded_value {
        assert_eq!(
            f.inner(),
            0.0,
            "Math.round(-0.5) should equal 0.0 per JavaScript semantics"
        );
    } else {
        panic!(
            "Math.round should return numeric value, got {:?}",
            rounded_value
        );
    }
}

#[test]
fn math_round_positive_half_integration() {
    // Verify Math.round(0.5) -> floor(0.5 + 0.5) = floor(1) = 1
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    core.registers[0] = Value::Float(0.5.into());

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:MathRound".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Math.round execution should succeed");

    let rounded_value = core.registers[10].clone();
    if let Value::Int(n) = rounded_value {
        assert_eq!(n, 1, "Math.round(0.5) should equal 1");
    } else if let Value::Float(f) = rounded_value {
        assert_eq!(f.inner(), 1.0, "Math.round(0.5) should equal 1.0");
    } else {
        panic!(
            "Math.round should return numeric value, got {:?}",
            rounded_value
        );
    }
}

#[test]
fn math_round_edge_cases_integration() {
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    // Test Math.round(-1.5) should be -1 (not -2 like Rust round_away_from_zero)
    core.registers[0] = Value::Float((-1.5).into());

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:MathRound".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Math.round(-1.5) execution should succeed");

    let rounded_value = core.registers[10].clone();
    if let Value::Int(n) = rounded_value {
        assert_eq!(
            n, -1,
            "Math.round(-1.5) should equal -1 per JavaScript floor(x + 0.5) semantics"
        );
    } else if let Value::Float(f) = rounded_value {
        assert_eq!(
            f.inner(),
            -1.0,
            "Math.round(-1.5) should equal -1.0 per JavaScript floor(x + 0.5) semantics"
        );
    } else {
        panic!(
            "Math.round should return numeric value, got {:?}",
            rounded_value
        );
    }
}

#[test]
fn console_info_dispatch_integration() {
    // Regression test for ConsoleLevel::Info missing from match arms
    // Verify that console.info() calls work and capture output correctly
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    core.registers[0] = Value::Str("Info level message".to_string());

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ConsoleInfo".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Console.info execution should succeed");

    // Verify console output was captured
    assert!(
        !core.console_output.is_empty(),
        "Console.info should produce output"
    );

    let console_entry = &core.console_output[0];
    assert_eq!(
        console_entry.level,
        ConsoleLevel::Info,
        "Console entry should have Info level"
    );
    assert_eq!(
        console_entry.message, "Info level message",
        "Console entry should have correct message"
    );
}

#[test]
fn console_info_vs_other_levels_integration() {
    // Verify ConsoleLevel::Info works alongside other console levels
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    // Test multiple console calls with different levels
    core.console_output.clear();

    // Console.log
    core.registers[0] = Value::Str("Log message".to_string());
    let _ = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ConsoleLog".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    // Console.info
    core.registers[0] = Value::Str("Info message".to_string());
    let _ = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ConsoleInfo".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    // Console.warn
    core.registers[0] = Value::Str("Warn message".to_string());
    let _ = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ConsoleWarn".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    // Verify all three console outputs
    assert_eq!(
        core.console_output.len(),
        3,
        "Should have 3 console outputs"
    );

    assert_eq!(core.console_output[0].level, ConsoleLevel::Log);
    assert_eq!(core.console_output[0].message, "Log message");

    assert_eq!(core.console_output[1].level, ConsoleLevel::Info);
    assert_eq!(core.console_output[1].message, "Info message");

    assert_eq!(core.console_output[2].level, ConsoleLevel::Warn);
    assert_eq!(core.console_output[2].message, "Warn message");
}

#[test]
fn console_info_string_conversion_integration() {
    // Test that ConsoleLevel::Info handles different input types correctly
    let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

    // Test with number
    core.console_output.clear();
    core.registers[0] = Value::Int(42);

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ConsoleInfo".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Console.info with number should succeed");
    assert_eq!(core.console_output.len(), 1);
    assert_eq!(core.console_output[0].level, ConsoleLevel::Info);

    // Test with boolean
    core.console_output.clear();
    core.registers[0] = Value::Bool(true);

    let result = core.execute(&test_module(vec![
        Ir3Instruction::CallBuiltin {
            builtin: "builtin:ConsoleInfo".to_string(),
            args: RegRange { start: 0, count: 1 },
            dst: 10,
        },
        Ir3Instruction::Halt,
    ]));

    assert!(result.is_ok(), "Console.info with boolean should succeed");
    assert_eq!(core.console_output.len(), 1);
    assert_eq!(core.console_output[0].level, ConsoleLevel::Info);
}
