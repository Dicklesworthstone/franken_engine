#![no_main]

use frankenengine_engine::ir_contract::{
    Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_INSTRUCTIONS: usize = 64;
const MAX_REGISTERS: u32 = 32;
const MAX_CONSTANT_POOL_SIZE: usize = 16;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let ir3_module = synthetic_ir3_module(data);

    // Test IR3 instruction creation and serialization
    test_instruction_serialization(&ir3_module);

    // Test module validation
    test_module_validation(&ir3_module);
});

fn synthetic_ir3_module(data: &[u8]) -> Ir3Module {
    let instructions = generate_adversarial_instructions(data);
    let constant_pool = generate_constant_pool(data);

    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "fuzz-ir3-adversarial".to_string(),
        },
        instructions,
        constant_pool,
        entry_point: 0,
        max_registers: MAX_REGISTERS,
    }
}

fn generate_adversarial_instructions(data: &[u8]) -> Vec<Ir3Instruction> {
    let mut instructions = Vec::new();

    // Focus on the new IR3 instruction variants from the expansion
    for (index, chunk) in data
        .chunks(4)
        .take(MAX_INSTRUCTIONS)
        .enumerate()
    {
        let opcode = byte(chunk, 0);
        let reg1 = register_from_byte(byte(chunk, 1));
        let reg2 = register_from_byte(byte(chunk, 2));
        let reg3 = register_from_byte(byte(chunk, 3));
        let value = value_from_chunk(chunk);

        let instruction = match opcode % 26 {
            // Load instructions for setup
            0 => Ir3Instruction::LoadInt { dst: reg1, value },
            1 => Ir3Instruction::LoadFloat { dst: reg1, bits: value as u64 },
            2 => Ir3Instruction::LoadBool { dst: reg1, value: value % 2 == 0 },
            3 => Ir3Instruction::LoadNull { dst: reg1 },

            // Adversarial focus: new arithmetic variants from IR3 expansion
            4 => Ir3Instruction::Mod { dst: reg1, lhs: reg2, rhs: reg3 },
            5 => Ir3Instruction::Exp { dst: reg1, lhs: reg2, rhs: reg3 },

            // Adversarial focus: new comparison variants
            6 => Ir3Instruction::Lt { dst: reg1, lhs: reg2, rhs: reg3 },
            7 => Ir3Instruction::Lte { dst: reg1, lhs: reg2, rhs: reg3 },
            8 => Ir3Instruction::Gt { dst: reg1, lhs: reg2, rhs: reg3 },
            9 => Ir3Instruction::Gte { dst: reg1, lhs: reg2, rhs: reg3 },
            10 => Ir3Instruction::Eq { dst: reg1, lhs: reg2, rhs: reg3 },
            11 => Ir3Instruction::StrictEq { dst: reg1, lhs: reg2, rhs: reg3 },
            12 => Ir3Instruction::NotEq { dst: reg1, lhs: reg2, rhs: reg3 },
            13 => Ir3Instruction::StrictNotEq { dst: reg1, lhs: reg2, rhs: reg3 },

            // Adversarial focus: new bitwise variants
            14 => Ir3Instruction::BitAnd { dst: reg1, lhs: reg2, rhs: reg3 },
            15 => Ir3Instruction::BitOr { dst: reg1, lhs: reg2, rhs: reg3 },
            16 => Ir3Instruction::BitXor { dst: reg1, lhs: reg2, rhs: reg3 },
            17 => Ir3Instruction::Shl { dst: reg1, lhs: reg2, rhs: reg3 },
            18 => Ir3Instruction::Shr { dst: reg1, lhs: reg2, rhs: reg3 },
            19 => Ir3Instruction::Ushr { dst: reg1, lhs: reg2, rhs: reg3 },

            // Adversarial focus: new relational variants
            20 => Ir3Instruction::InstanceOf { dst: reg1, lhs: reg2, rhs: reg3 },
            21 => Ir3Instruction::InOp { dst: reg1, lhs: reg2, rhs: reg3 },

            // Adversarial focus: new construction variant
            22 => Ir3Instruction::Construct {
                callee: reg2,
                args: RegRange { start: reg3, count: (value as u32 % 4) + 1 },
                dst: reg1,
            },

            // Mix in other instructions for realistic context
            23 => Ir3Instruction::Move { dst: reg1, src: reg2 },
            24 => Ir3Instruction::Add { dst: reg1, lhs: reg2, rhs: reg3 },
            _ => Ir3Instruction::Return(Some(reg1)),
        };

        instructions.push(instruction);
    }

    // Always end with a return instruction for valid termination
    if instructions.is_empty() || !matches!(instructions.last(), Some(Ir3Instruction::Return(_))) {
        instructions.push(Ir3Instruction::Return(None));
    }

    instructions
}

fn generate_constant_pool(data: &[u8]) -> Vec<String> {
    let mut pool = Vec::new();

    for i in 0..MAX_CONSTANT_POOL_SIZE.min(data.len() / 4) {
        let value = if i < data.len() {
            format!("fuzz_string_{}", data[i] % 16)
        } else {
            format!("default_string_{i}")
        };
        pool.push(value);
    }

    // Always include some adversarial strings for edge case testing
    pool.push("".to_string()); // empty string
    pool.push("undefined".to_string()); // keyword
    pool.push("null".to_string()); // keyword
    pool.push("constructor".to_string()); // prototype property

    pool
}

fn test_instruction_serialization(ir3_module: &Ir3Module) {
    // Test that IR3 instructions can be created and serialized without panics
    let _ = ir3_module.canonical_value();
    let _ = ir3_module.canonical_bytes();
    let _ = ir3_module.content_hash();

    // Test individual instruction handling
    for instruction in &ir3_module.instructions {
        // This exercises the instruction dispatch patterns in the runtime
        let _instruction_debug = format!("{:?}", instruction);

        // Test that we can match on all the new instruction variants
        match instruction {
            // Focus on new IR3 variants from expansion
            Ir3Instruction::Mod { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Exp { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Lt { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Lte { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Gt { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Gte { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Eq { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::StrictEq { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::NotEq { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::StrictNotEq { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::BitAnd { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::BitOr { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::BitXor { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Shl { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Shr { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Ushr { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::InstanceOf { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::InOp { dst: _, lhs: _, rhs: _ } => {},
            Ir3Instruction::Construct { callee: _, args: _, dst: _ } => {},
            _ => {}, // Other instructions
        }
    }
}

fn test_module_validation(ir3_module: &Ir3Module) {
    // Test basic module structure validation
    assert!(ir3_module.max_registers > 0);
    assert!(!ir3_module.instructions.is_empty());
    assert_eq!(ir3_module.header.level, IrLevel::Ir3);

    // Test register bounds validation for adversarial cases
    for instruction in &ir3_module.instructions {
        match instruction {
            Ir3Instruction::LoadInt { dst, .. } |
            Ir3Instruction::LoadFloat { dst, .. } |
            Ir3Instruction::LoadBool { dst, .. } |
            Ir3Instruction::LoadNull { dst } |
            Ir3Instruction::LoadUndefined { dst } => {
                assert!(*dst < ir3_module.max_registers, "register out of bounds: {}", dst);
            },
            Ir3Instruction::Add { dst, lhs, rhs } |
            Ir3Instruction::Sub { dst, lhs, rhs } |
            Ir3Instruction::Mul { dst, lhs, rhs } |
            Ir3Instruction::Div { dst, lhs, rhs } |
            // Test all the new instruction variants
            Ir3Instruction::Mod { dst, lhs, rhs } |
            Ir3Instruction::Exp { dst, lhs, rhs } |
            Ir3Instruction::Lt { dst, lhs, rhs } |
            Ir3Instruction::Lte { dst, lhs, rhs } |
            Ir3Instruction::Gt { dst, lhs, rhs } |
            Ir3Instruction::Gte { dst, lhs, rhs } |
            Ir3Instruction::Eq { dst, lhs, rhs } |
            Ir3Instruction::StrictEq { dst, lhs, rhs } |
            Ir3Instruction::NotEq { dst, lhs, rhs } |
            Ir3Instruction::StrictNotEq { dst, lhs, rhs } |
            Ir3Instruction::BitAnd { dst, lhs, rhs } |
            Ir3Instruction::BitOr { dst, lhs, rhs } |
            Ir3Instruction::BitXor { dst, lhs, rhs } |
            Ir3Instruction::Shl { dst, lhs, rhs } |
            Ir3Instruction::Shr { dst, lhs, rhs } |
            Ir3Instruction::Ushr { dst, lhs, rhs } |
            Ir3Instruction::InstanceOf { dst, lhs, rhs } |
            Ir3Instruction::InOp { dst, lhs, rhs } => {
                assert!(*dst < ir3_module.max_registers, "dst register out of bounds: {}", dst);
                assert!(*lhs < ir3_module.max_registers, "lhs register out of bounds: {}", lhs);
                assert!(*rhs < ir3_module.max_registers, "rhs register out of bounds: {}", rhs);
            },
            _ => {}, // Other instructions
        }
    }
}

fn register_from_byte(byte: u8) -> u32 {
    u32::from(byte) % MAX_REGISTERS
}

fn value_from_chunk(chunk: &[u8]) -> i64 {
    if chunk.len() >= 4 {
        i64::from(chunk[0])
            | (i64::from(chunk[1]) << 8)
            | (i64::from(chunk[2]) << 16)
            | (i64::from(chunk[3]) << 24)
    } else {
        0
    }
}

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    data.get(index).copied().unwrap_or(0)
}