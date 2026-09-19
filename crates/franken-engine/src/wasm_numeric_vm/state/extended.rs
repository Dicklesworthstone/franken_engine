//! Bounded execution of the 0xfc instruction family.
//!
//! Decode the full u32 LEB subopcode in validation and execution. In particular,
//! a non-canonical (but valid) LEB must not be confused with a new instruction.

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

pub(super) fn validate(
    _state: &ModuleState,
    reader: &mut CodeReader<'_>,
    function: u32,
) -> Result<StackEffect, WasmNumericVmError> {
    let offset = reader.offset().saturating_sub(1);
    let subopcode = reader.read_u32_leb(function)?;
    let (input, output) =
        conversion_signature(subopcode).ok_or_else(|| unsupported(function, offset))?;
    Ok(StackEffect {
        pop: [Some(input), None, None],
        push: Some(output),
    })
}

pub(super) fn execute(
    _state: &mut InstanceState,
    reader: &mut CodeReader<'_>,
    stack: &mut Vec<WasmBoundaryValue>,
    meter: &mut ExecutionMeter<'_>,
    function: u32,
) -> Result<(), WasmNumericVmError> {
    let offset = reader.offset().saturating_sub(1);
    let subopcode = reader.read_u32_leb(function)?;
    let (input, _) =
        conversion_signature(subopcode).ok_or_else(|| unsupported(function, offset))?;
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
        _ => return Err(unsupported(function, offset)),
    };
    push_value(stack, result, meter)
}

#[cfg(test)]
#[path = "extended/tests.rs"]
mod tests;
