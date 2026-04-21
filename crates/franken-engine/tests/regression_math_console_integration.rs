#![forbid(unsafe_code)]
//! Integration tests for `Math.round` and `ConsoleLevel::Info` regressions.

use frankenengine_engine::baseline_interpreter::{
    ConsoleLevel, InterpreterConfig, InterpreterCore,
};
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine};

fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for `{source}`: {error:?}"))
        .value
}

fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "math-console-regression".to_string(),
        },
        instructions,
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

#[test]
fn math_round_negative_half_integration() {
    assert_eq!(eval_value("Math.round(-0.5)"), "0");
}

#[test]
fn math_round_positive_half_integration() {
    assert_eq!(eval_value("Math.round(0.5)"), "1");
}

#[test]
fn math_round_edge_cases_integration() {
    assert_eq!(eval_value("Math.round(-1.5)"), "-1");
}

#[test]
fn console_info_dispatch_integration() {
    let module = Ir3Module {
        constant_pool: vec!["Info level message".to_string()],
        ..test_module(vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleInfo".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ])
    };

    let mut core = InterpreterCore::new(
        InterpreterConfig::quickjs_defaults(),
        "console-info-dispatch-integration",
    );
    core.execute(&module)
        .expect("console.info execution should succeed");

    let console_output = core.console_output();
    assert_eq!(console_output.len(), 1);
    assert_eq!(console_output[0].level, ConsoleLevel::Info);
    assert_eq!(console_output[0].message, "Info level message");
}

#[test]
fn console_info_vs_other_levels_integration() {
    let module = Ir3Module {
        constant_pool: vec![
            "Log message".to_string(),
            "Info message".to_string(),
            "Warn message".to_string(),
        ],
        ..test_module(vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleInfo".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleWarn".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ])
    };

    let mut core = InterpreterCore::new(
        InterpreterConfig::quickjs_defaults(),
        "console-info-vs-other-levels",
    );
    core.execute(&module)
        .expect("mixed console execution should succeed");

    let console_output = core.console_output();
    assert_eq!(console_output.len(), 3);
    assert_eq!(console_output[0].level, ConsoleLevel::Log);
    assert_eq!(console_output[0].message, "Log message");
    assert_eq!(console_output[1].level, ConsoleLevel::Info);
    assert_eq!(console_output[1].message, "Info message");
    assert_eq!(console_output[2].level, ConsoleLevel::Warn);
    assert_eq!(console_output[2].message, "Warn message");
}

#[test]
fn console_info_string_conversion_integration() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ConsoleInfo".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::LoadBool {
            dst: 0,
            value: true,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ConsoleInfo".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]);

    let mut core = InterpreterCore::new(
        InterpreterConfig::quickjs_defaults(),
        "console-info-string-conversion",
    );
    core.execute(&module)
        .expect("console.info conversion execution should succeed");

    let console_output = core.console_output();
    assert_eq!(console_output.len(), 2);
    assert_eq!(console_output[0].level, ConsoleLevel::Info);
    assert_eq!(console_output[0].message, "42");
    assert_eq!(console_output[1].level, ConsoleLevel::Info);
    assert_eq!(console_output[1].message, "true");
}
