#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};

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
            source_label: "baseline-object-to-string-tags".to_string(),
        },
        instructions,
        constant_pool,
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn run_value(
    instructions: Vec<Ir3Instruction>,
    constant_pool: Vec<String>,
) -> Result<Value, InterpreterError> {
    let module = test_module(instructions, constant_pool);
    let result: ExecutionResult =
        QuickJsLane::with_config(test_config()).execute(&module, "object-to-string-tags")?;
    Ok(result.value)
}

fn object_tag_instruction(value_reg: u32, dst: u32) -> Ir3Instruction {
    Ir3Instruction::HostCall {
        capability: CapabilityTag("builtin:ObjectPrototypeToString".to_string()),
        args: RegRange {
            start: value_reg,
            count: 1,
        },
        dst,
    }
}

#[test]
fn object_to_string_tag_uses_internal_metadata_metamorphic_relation() {
    let plain_object_tag = run_value(
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            object_tag_instruction(0, 0),
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    )
    .expect("plain object tag should execute");

    let array_like_object_tag = run_value(
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 2 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 3,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 4,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            object_tag_instruction(0, 0),
            Ir3Instruction::Halt,
        ],
        vec![
            "length".to_string(),
            "1".to_string(),
            "0".to_string(),
            "second".to_string(),
            "first".to_string(),
        ],
    )
    .expect("array-like object tag should execute");

    let empty_array_tag = run_value(
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            object_tag_instruction(0, 0),
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    )
    .expect("empty array tag should execute");

    let shaped_array_tag = run_value(
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 2 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 3,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 4,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            object_tag_instruction(0, 0),
            Ir3Instruction::Halt,
        ],
        vec![
            "length".to_string(),
            "1".to_string(),
            "0".to_string(),
            "second".to_string(),
            "first".to_string(),
        ],
    )
    .expect("shaped array tag should execute");

    assert_eq!(plain_object_tag, Value::str("[object Object]"));
    assert_eq!(array_like_object_tag, plain_object_tag);
    assert_eq!(empty_array_tag, Value::str("[object Array]"));
    assert_eq!(shaped_array_tag, empty_array_tag);
    assert_ne!(array_like_object_tag, shaped_array_tag);
}

#[test]
fn object_to_string_tag_covers_primitive_builtin_tags() {
    let cases = [
        (
            vec![
                Ir3Instruction::LoadUndefined { dst: 0 },
                object_tag_instruction(0, 0),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            "[object Undefined]",
        ),
        (
            vec![
                Ir3Instruction::LoadNull { dst: 0 },
                object_tag_instruction(0, 0),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            "[object Null]",
        ),
        (
            vec![
                Ir3Instruction::LoadBool {
                    dst: 0,
                    value: true,
                },
                object_tag_instruction(0, 0),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            "[object Boolean]",
        ),
        (
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                object_tag_instruction(0, 0),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            "[object Number]",
        ),
        (
            vec![
                Ir3Instruction::LoadFloat {
                    dst: 0,
                    bits: 1.5_f64.to_bits(),
                },
                object_tag_instruction(0, 0),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            "[object Number]",
        ),
        (
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                object_tag_instruction(0, 0),
                Ir3Instruction::Halt,
            ],
            vec!["tag-source".to_string()],
            "[object String]",
        ),
    ];

    for (instructions, constant_pool, expected) in cases {
        let tag = run_value(instructions, constant_pool)
            .expect("Object.prototype.toString primitive tag should execute");
        assert_eq!(tag, Value::str(expected));
    }
}
