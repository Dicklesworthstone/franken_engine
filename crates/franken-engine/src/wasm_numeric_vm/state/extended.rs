//! Bounded execution of the 0xfc instruction family.
//!
//! Decode the full u32 LEB subopcode in validation and execution. In particular,
//! a non-canonical (but valid) LEB must not be confused with a new instruction.
//! Bulk operations validate all ranges and charge work before modifying instance state.

use super::*;

const PREFIX: u8 = 0xfc;

fn conversion_signature(subopcode: u32) -> Option<(WasmValueType, WasmValueType)> {
    use WasmValueType::{F32, F64, I32, I64};
    Some(match subopcode {
        0 | 1 => (F32, I32),
        2 | 3 => (F64, I32),
        4 | 5 => (F32, I64),
        6 | 7 => (F64, I64),
        _ => return None,
    })
}

fn unsupported(function: u32, offset: usize) -> WasmNumericVmError {
    WasmNumericVmError::UnsupportedOpcode {
        function_index: function,
        opcode: PREFIX,
        offset,
    }
}

#[derive(Clone, Copy)]
enum Instruction {
    Saturating { subopcode: u32, input: WasmValueType, output: WasmValueType },
    MemoryCopy,
    MemoryFill,
    TableInit { element: u32, table: u32 },
    ElementDrop { element: u32 },
    TableCopy { destination: u32, source: u32 },
    TableSize { table: u32 },
}

fn memory_zero(reader: &mut CodeReader<'_>, function: u32) -> Result<(), WasmNumericVmError> {
    // A memory index is a u32 LEB, not a single-byte opcode. This accepts valid
    // padded encodings while still refusing a reference to any other memory.
    if reader.read_u32_leb(function)? != 0 {
        return Err(invalid("bulk memory instruction requires memory index zero"));
    }
    Ok(())
}

fn decode(reader: &mut CodeReader<'_>, function: u32) -> Result<Instruction, WasmNumericVmError> {
    let offset = reader.offset().saturating_sub(1);
    let subopcode = reader.read_u32_leb(function)?;
    if let Some((input, output)) = conversion_signature(subopcode) {
        return Ok(Instruction::Saturating { subopcode, input, output });
    }
    match subopcode {
        10 => {
            memory_zero(reader, function)?;
            memory_zero(reader, function)?;
            Ok(Instruction::MemoryCopy)
        }
        11 => {
            memory_zero(reader, function)?;
            Ok(Instruction::MemoryFill)
        }
        // The binary order is elemidx, tableidx (unlike textual table.init).
        12 => Ok(Instruction::TableInit {
            element: reader.read_u32_leb(function)?,
            table: reader.read_u32_leb(function)?,
        }),
        13 => Ok(Instruction::ElementDrop { element: reader.read_u32_leb(function)? }),
        14 => Ok(Instruction::TableCopy {
            destination: reader.read_u32_leb(function)?,
            source: reader.read_u32_leb(function)?,
        }),
        16 => Ok(Instruction::TableSize { table: reader.read_u32_leb(function)? }),
        _ => Err(unsupported(function, offset)),
    }
}

pub(super) fn validate(
    state: &ModuleState,
    reader: &mut CodeReader<'_>,
    function: u32,
) -> Result<StackEffect, WasmNumericVmError> {
    match decode(reader, function)? {
        Instruction::Saturating { input, output, .. } => Ok(StackEffect {
            pop: [Some(input), None, None],
            push: Some(output),
        }),
        Instruction::TableInit { element, table } => {
            state.tables.validate_element(element)?;
            state.validate_table(table)?;
            Ok(StackEffect { pop: [Some(WasmValueType::I32); 3], push: None })
        }
        Instruction::ElementDrop { element } => {
            state.tables.validate_element(element)?;
            Ok(StackEffect { pop: [None; 3], push: None })
        }
        Instruction::TableCopy { destination, source } => {
            state.validate_table(destination)?;
            state.validate_table(source)?;
            Ok(StackEffect { pop: [Some(WasmValueType::I32); 3], push: None })
        }
        Instruction::TableSize { table } => {
            state.validate_table(table)?;
            Ok(StackEffect { pop: [None; 3], push: Some(WasmValueType::I32) })
        }
        Instruction::MemoryCopy | Instruction::MemoryFill => {
            if state.memory.is_none() {
                return Err(invalid("bulk memory instruction requires memory zero"));
            }
            Ok(StackEffect { pop: [Some(WasmValueType::I32); 3], push: None })
        }
    }
}

fn saturate(
    subopcode: u32,
    input: WasmValueType,
    stack: &mut Vec<WasmBoundaryValue>,
    meter: &mut ExecutionMeter<'_>,
    function: u32,
) -> Result<(), WasmNumericVmError> {
    let value = pop_value(stack, function, PREFIX)?;
    ensure_same_type(function, 0, input, value.value_type())?;
    let number = match value {
        // Widening f32 to f64 is exact; it cannot introduce double rounding
        // before the integer conversion. NaN payloads do not affect trunc_sat.
        WasmBoundaryValue::F32Bits(bits) => f64::from(f32::from_bits(bits)),
        WasmBoundaryValue::F64Bits(bits) => f64::from_bits(bits),
        _ => return Err(invalid("validated saturating conversion requires a float")),
    };
    // Rust float-to-integer casts implement truncation toward zero, NaN -> 0,
    // and saturation at both integer endpoints. For unsigned Wasm results the
    // second cast only reinterprets the bits in the boundary's signed carrier.
    let result = match subopcode {
        0 | 2 => WasmBoundaryValue::I32(number as i32),
        1 | 3 => WasmBoundaryValue::I32((number as u32) as i32),
        4 | 6 => WasmBoundaryValue::I64(number as i64),
        5 | 7 => WasmBoundaryValue::I64((number as u64) as i64),
        _ => return Err(invalid("unknown validated saturating conversion")),
    };
    push_value(stack, result, meter)
}

pub(super) fn execute(
    state: &mut InstanceState,
    reader: &mut CodeReader<'_>,
    stack: &mut Vec<WasmBoundaryValue>,
    meter: &mut ExecutionMeter<'_>,
    function: u32,
) -> Result<(), WasmNumericVmError> {
    let instruction = decode(reader, function)?;
    if let Instruction::Saturating { subopcode, input, .. } = instruction {
        return saturate(subopcode, input, stack, meter, function);
    }
    if let Instruction::ElementDrop { element } = instruction {
        return state.tables.drop_element(element);
    }
    if let Instruction::TableSize { table } = instruction {
        let size = state.tables.size(table)?;
        return push_value(stack, WasmBoundaryValue::I32(size as i32), meter);
    }
    let length = expect_i32(pop_value(stack, function, PREFIX)?, function, 2)? as u32;
    let source_or_byte = expect_i32(pop_value(stack, function, PREFIX)?, function, 1)? as u32;
    let destination = expect_i32(pop_value(stack, function, PREFIX)?, function, 0)? as u32;
    if let Instruction::TableInit { element, table } = instruction {
        return state.tables.init(table, element, destination, source_or_byte, length, meter);
    }
    if let Instruction::TableCopy { destination: to, source: from } = instruction {
        return state.tables.copy(to, from, destination, source_or_byte, length, meter);
    }
    let memory = state.memory.as_mut().ok_or_else(|| invalid("missing validated memory"))?;
    let destination_range = memory.range(destination, 0, length as usize)?;
    match instruction {
        Instruction::MemoryCopy => {
            let source_range = memory.range(source_or_byte, 0, length as usize)?;
            // Charge work exactly as memory.grow does: one unit per 64 bytes,
            // in addition to the VM's opcode tick. Neither refusal nor a
            // bounds trap may expose a partially copied destination.
            meter.charge_work(u64::from(length).div_ceil(64))?;
            memory.bytes.copy_within(source_range, destination_range.start);
        }
        Instruction::MemoryFill => {
            meter.charge_work(u64::from(length).div_ceil(64))?;
            memory.bytes[destination_range].fill(source_or_byte as u8);
        }
        _ => return Err(invalid("invalid bulk memory dispatch")),
    }
    Ok(())
}

#[cfg(test)]
#[path = "extended/tests.rs"]
mod tests;
