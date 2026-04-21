#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};

const BASELINE_INTERPRETER: &str = include_str!("../src/baseline_interpreter.rs");
const DISPATCH_ARMS_GOLDEN: &str = include_str!("golden_vectors/baseline_dispatch_arms.txt");

fn render_dispatch_arm_snapshot(source: &str) -> String {
    let mut capabilities = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("\"builtin:") || !trimmed.contains("\" =>") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('"')
            && let Some((capability, _)) = rest.split_once('"')
        {
            capabilities.push(capability.to_string());
        }
    }

    capabilities.sort();
    let unique = capabilities.iter().cloned().collect::<BTreeSet<_>>().len();
    let duplicate_count = capabilities.len().saturating_sub(unique);

    let mut counts = BTreeMap::new();
    for capability in &capabilities {
        *counts.entry(capability.clone()).or_insert(0_usize) += 1;
    }

    let mut snapshot = format!(
        "total={}\nunique={unique}\nduplicates={duplicate_count}\n\n",
        capabilities.len()
    );
    for capability in &capabilities {
        snapshot.push_str(&capability);
        snapshot.push('\n');
    }

    for (capability, count) in counts {
        assert_eq!(
            count, 1,
            "duplicate baseline builtin dispatch arm for {capability}"
        );
    }

    snapshot
}

#[test]
fn baseline_dispatch_arm_snapshot_matches_golden() {
    assert_eq!(
        render_dispatch_arm_snapshot(BASELINE_INTERPRETER),
        DISPATCH_ARMS_GOLDEN
    );
}

fn test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn test_module(instructions: Vec<Ir3Instruction>, constant_pool: Vec<String>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "baseline-interpreter-conformance".to_string(),
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
        QuickJsLane::with_config(test_config()).execute(&module, "baseline-conformance")?;
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

fn array_with_three_values_prefix() -> Vec<Ir3Instruction> {
    vec![
        Ir3Instruction::NewArray { dst: 0 },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 8 },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 1,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 0 },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 2,
        },
        Ir3Instruction::LoadBool {
            dst: 2,
            value: true,
        },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 3,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 3 },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
    ]
}

#[test]
fn array_tag_survives_metamorphic_array_producer_transformations() {
    let expected = Value::Str("[object Array]".to_string());

    let shuffled_array_of = run_value(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 3 },
            Ir3Instruction::LoadInt { dst: 1, value: 1 },
            Ir3Instruction::LoadInt { dst: 2, value: 2 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayOf".to_string()),
                args: RegRange { start: 0, count: 3 },
                dst: 3,
            },
            object_tag_instruction(3, 0),
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    )
    .expect("Array.of with shuffled inputs should execute");
    assert_eq!(shuffled_array_of, expected);

    let mut filter_instructions = array_with_three_values_prefix();
    filter_instructions.extend([
        Ir3Instruction::LoadUndefined { dst: 1 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeFilter".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 3,
        },
        object_tag_instruction(3, 0),
        Ir3Instruction::Halt,
    ]);
    let filter_result = run_value(
        filter_instructions,
        vec![
            "0".to_string(),
            "1".to_string(),
            "2".to_string(),
            "length".to_string(),
        ],
    )
    .expect("Array.prototype.filter should execute");
    assert_eq!(filter_result, expected);

    let mut flat_map_instructions = array_with_three_values_prefix();
    flat_map_instructions.extend([
        Ir3Instruction::LoadUndefined { dst: 1 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ArrayPrototypeFlatMap".to_string()),
            args: RegRange { start: 0, count: 2 },
            dst: 3,
        },
        object_tag_instruction(3, 0),
        Ir3Instruction::Halt,
    ]);
    let flat_map_result = run_value(
        flat_map_instructions,
        vec![
            "0".to_string(),
            "1".to_string(),
            "2".to_string(),
            "length".to_string(),
        ],
    )
    .expect("Array.prototype.flatMap should execute");
    assert_eq!(flat_map_result, expected);

    let concat_result = run_value(
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 3, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 2,
                val: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::LoadInt { dst: 3, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 2,
                val: 3,
            },
            Ir3Instruction::NewArray { dst: 1 },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 3, value: 2 },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::LoadInt { dst: 3, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayPrototypeConcat".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 4,
            },
            object_tag_instruction(4, 0),
            Ir3Instruction::Halt,
        ],
        vec!["0".to_string(), "length".to_string()],
    )
    .expect("Array.prototype.concat should execute");
    assert_eq!(concat_result, expected);

    let entries_nested_result = run_value(
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 7 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ObjectEntries".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            object_tag_instruction(5, 0),
            Ir3Instruction::Halt,
        ],
        vec!["answer".to_string(), "0".to_string()],
    )
    .expect("Object.entries nested entry should execute");
    assert_eq!(entries_nested_result, expected);
}

#[test]
fn explicit_array_metadata_drives_array_is_array() {
    let array_result = run_value(
        vec![
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayIsArray".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ],
        Vec::new(),
    )
    .expect("Array.isArray should execute for arrays");
    assert_eq!(array_result, Value::Bool(true));

    let array_like_result = run_value(
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 1,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 99 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayIsArray".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["length".to_string(), "0".to_string()],
    )
    .expect("Array.isArray should execute for array-like objects");
    assert_eq!(array_like_result, Value::Bool(false));
}
