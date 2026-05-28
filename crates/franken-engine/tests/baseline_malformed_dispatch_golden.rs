#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
use serde::Serialize;

// bd-ub6x8.6.3: migrated from tests/golden_vectors/ to tests/golden/wire_vectors/.
const EXPECTED: &str =
    include_str!("golden/wire_vectors/baseline_malformed_dispatch_fail_closed.json");

#[derive(Debug, Serialize)]
struct ErrorSnapshot {
    kind: &'static str,
    expected: String,
    got: String,
}

#[derive(Debug, Serialize)]
struct ValueSnapshot {
    kind: &'static str,
    value: bool,
}

#[derive(Debug, Serialize)]
struct BaselineMalformedDispatchSnapshot {
    coverage_gap: &'static str,
    binding_kind_error: ErrorSnapshot,
    invalid_utf16_index_of: ErrorSnapshot,
    valid_utf16_includes: ValueSnapshot,
    valid_utf16_starts_with: ValueSnapshot,
}

fn test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    config
}

fn test_module(instructions: Vec<Ir3Instruction>, constant_pool: Vec<String>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "baseline-malformed-dispatch-golden".to_string(),
        },
        instructions,
        constant_pool,
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn execute_module(
    instructions: Vec<Ir3Instruction>,
    constant_pool: Vec<String>,
) -> Result<Value, InterpreterError> {
    let module = test_module(instructions, constant_pool);
    let result: ExecutionResult =
        QuickJsLane::with_config(test_config()).execute(&module, "baseline-malformed-dispatch")?;
    Ok(result.value)
}

fn type_error_snapshot(error: InterpreterError) -> ErrorSnapshot {
    match error {
        InterpreterError::TypeError { expected, got } => ErrorSnapshot {
            kind: "type_error",
            expected,
            got,
        },
        other => panic!("expected type error, got {other:?}"),
    }
}

fn bool_snapshot(value: Value) -> ValueSnapshot {
    match value {
        Value::Bool(value) => ValueSnapshot {
            kind: "bool",
            value,
        },
        other => panic!("expected bool, got {other:?}"),
    }
}

fn binding_kind_error() -> ErrorSnapshot {
    let err = execute_module(
        vec![
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: 99,
            },
            Ir3Instruction::Halt,
        ],
        vec!["future_binding".to_string()],
    )
    .expect_err("unknown binding kind must fail closed");
    type_error_snapshot(err)
}

fn string_builtin(
    capability: &str,
    haystack: &str,
    needle: &str,
    position: i64,
) -> Result<Value, InterpreterError> {
    execute_module(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 1,
            },
            Ir3Instruction::LoadInt {
                dst: 2,
                value: position,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag(capability.to_string()),
                args: RegRange { start: 0, count: 3 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec![haystack.to_string(), needle.to_string()],
    )
}

#[test]
fn baseline_malformed_dispatch_fail_closed_matches_golden() {
    let snapshot = BaselineMalformedDispatchSnapshot {
        coverage_gap: "baseline_interpreter malformed dispatch inputs",
        binding_kind_error: binding_kind_error(),
        invalid_utf16_index_of: type_error_snapshot(
            string_builtin("builtin:StringPrototypeIndexOf", "😀z", "z", 1)
                .expect_err("unpaired UTF-16 suffix must fail closed"),
        ),
        valid_utf16_includes: bool_snapshot(
            string_builtin("builtin:StringPrototypeIncludes", "😀z", "z", 2)
                .expect("valid UTF-16 position should execute"),
        ),
        valid_utf16_starts_with: bool_snapshot(
            string_builtin("builtin:StringPrototypeStartsWith", "😀z", "z", 2)
                .expect("valid UTF-16 position should execute"),
        ),
    };

    let actual = format!("{}\n", serde_json::to_string_pretty(&snapshot).unwrap());
    assert_eq!(actual, EXPECTED);
}
