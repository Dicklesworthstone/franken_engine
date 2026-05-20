#![no_main]

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, QuickJsLane, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion,
    RegRange,
};
use libfuzzer_sys::fuzz_target;

fn test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn module(
    instructions: Vec<Ir3Instruction>,
    constant_pool: Vec<String>,
    function_table: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "baseline-object-to-string-fuzz".to_string(),
        },
        instructions,
        constant_pool,
        function_table,
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn tag_function_table(name: String, is_generator: bool) -> Vec<Ir3FunctionDesc> {
    vec![Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: 1,
        name: Some(name),
        is_generator,
    }]
}

fn object_tag_instruction() -> Ir3Instruction {
    Ir3Instruction::HostCall {
        capability: CapabilityTag("builtin:ObjectPrototypeToString".to_string()),
        args: RegRange { start: 0, count: 1 },
        dst: 0,
    }
}

fn execute(
    instructions: Vec<Ir3Instruction>,
    constant_pool: Vec<String>,
    function_table: Vec<Ir3FunctionDesc>,
) -> Option<Value> {
    let module = module(instructions, constant_pool, function_table);
    let result: ExecutionResult = QuickJsLane::with_config(test_config())
        .execute(&module, "baseline-object-to-string-fuzz")
        .ok()?;
    Some(result.value)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 512 {
        return;
    }

    let selector = data.first().copied().unwrap_or(0) % 12;
    let fuzz_text = String::from_utf8_lossy(data)
        .chars()
        .take(64)
        .collect::<String>();
    let (instructions, pool, functions, expected) = match selector {
        0 => (
            vec![
                Ir3Instruction::LoadUndefined { dst: 0 },
                object_tag_instruction(),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            Vec::new(),
            "[object Undefined]",
        ),
        1 => (
            vec![
                Ir3Instruction::LoadNull { dst: 0 },
                object_tag_instruction(),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            Vec::new(),
            "[object Null]",
        ),
        2 => (
            vec![
                Ir3Instruction::LoadBool {
                    dst: 0,
                    value: data.get(1).copied().unwrap_or(0) & 1 == 1,
                },
                object_tag_instruction(),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            Vec::new(),
            "[object Boolean]",
        ),
        3 => (
            vec![
                Ir3Instruction::LoadInt {
                    dst: 0,
                    value: i64::from(data.get(1).copied().unwrap_or(0)),
                },
                object_tag_instruction(),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            Vec::new(),
            "[object Number]",
        ),
        4 => (
            vec![
                Ir3Instruction::LoadFloat {
                    dst: 0,
                    bits: f64::from_bits(u64::from(data.get(1).copied().unwrap_or(0))).to_bits(),
                },
                object_tag_instruction(),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            Vec::new(),
            "[object Number]",
        ),
        5 => (
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                object_tag_instruction(),
                Ir3Instruction::Halt,
            ],
            vec![fuzz_text],
            Vec::new(),
            "[object String]",
        ),
        6 => (
            vec![
                Ir3Instruction::NewArray { dst: 0 },
                object_tag_instruction(),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            Vec::new(),
            "[object Array]",
        ),
        7 => (
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                object_tag_instruction(),
                Ir3Instruction::Halt,
            ],
            Vec::new(),
            Vec::new(),
            "[object Object]",
        ),
        8 => callable_tag_case(
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            fuzz_text,
            false,
            "[object Function]",
        ),
        9 => callable_tag_case(
            Ir3Instruction::CreateGenerator {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            fuzz_text,
            true,
            "[object GeneratorFunction]",
        ),
        10 => callable_tag_case(
            Ir3Instruction::CreateAsyncFunction {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            fuzz_text,
            false,
            "[object AsyncFunction]",
        ),
        _ => callable_tag_case(
            Ir3Instruction::CreateAsyncGenerator {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            fuzz_text,
            true,
            "[object AsyncGeneratorFunction]",
        ),
    };

    let value = execute(instructions, pool, functions)
        .expect("constructed Object.prototype.toString module should execute");
    assert_eq!(value, Value::str(expected));
});

fn callable_tag_case(
    create_instruction: Ir3Instruction,
    function_name: String,
    is_generator: bool,
    expected: &'static str,
) -> (
    Vec<Ir3Instruction>,
    Vec<String>,
    Vec<Ir3FunctionDesc>,
    &'static str,
) {
    (
        vec![
            create_instruction,
            object_tag_instruction(),
            Ir3Instruction::Halt,
        ],
        Vec::new(),
        tag_function_table(function_name, is_generator),
        expected,
    )
}
