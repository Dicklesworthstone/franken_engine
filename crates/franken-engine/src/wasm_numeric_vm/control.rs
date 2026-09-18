//! Validation and non-recursive structured control flow for the numeric VM.
//!
//! Every body is validated, including dead code, before a VM is published.
//! Loop labels consume block parameters; other labels consume block results.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind { Function, Block, Loop, If }

#[derive(Debug, Clone, Copy)]
enum BlockType { Empty, Value(WasmValueType), Type(u32) }

impl BlockType {
    fn params<'a>(&self, vm: &'a WasmNumericVm) -> Result<&'a [WasmValueType], WasmNumericVmError> {
        match self {
            Self::Type(index) => Ok(&vm.function_type(*index)?.params),
            _ => Ok(&[]),
        }
    }

    fn results<'a>(&'a self, vm: &'a WasmNumericVm) -> Result<&'a [WasmValueType], WasmNumericVmError> {
        match self {
            Self::Empty => Ok(&[]),
            Self::Value(value) => Ok(std::slice::from_ref(value)),
            Self::Type(index) => Ok(&vm.function_type(*index)?.results),
        }
    }
}

#[derive(Debug, Clone)]
struct Block {
    kind: Kind,
    params: usize,
    results: usize,
    body: usize,
    alternate: Option<usize>,
    end: usize,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ControlMap { blocks: BTreeMap<usize, Block> }

struct ValidationFrame {
    kind: Kind,
    signature: BlockType,
    height: usize,
    unreachable: bool,
    start: usize,
    body: usize,
    alternate: Option<usize>,
}

struct Validator<'a> {
    vm: &'a WasmNumericVm,
    function: u32,
    values: Vec<Option<WasmValueType>>,
    frames: Vec<ValidationFrame>,
}

fn invalid(detail: impl Into<String>) -> WasmNumericVmError {
    WasmNumericVmError::InvalidModule { detail: detail.into() }
}

impl Validator<'_> {
    fn pop(&mut self) -> Result<Option<WasmValueType>, WasmNumericVmError> {
        let frame = self.frames.last().ok_or_else(|| invalid("instruction after function end"))?;
        if self.values.len() == frame.height {
            if frame.unreachable { return Ok(None); }
            return Err(invalid(format!("function {} operand underflow at control boundary", self.function)));
        }
        self.values.pop().ok_or_else(|| invalid("operand stack underflow"))
    }

    fn expect(&mut self, expected: WasmValueType) -> Result<(), WasmNumericVmError> {
        if let Some(actual) = self.pop()? {
            ensure_same_type(self.function, self.values.len(), expected, actual)?;
        }
        Ok(())
    }

    fn pop_types(&mut self, types: &[WasmValueType]) -> Result<(), WasmNumericVmError> {
        for ty in types.iter().rev() { self.expect(*ty)?; }
        Ok(())
    }

    fn push(&mut self, ty: Option<WasmValueType>) -> Result<(), WasmNumericVmError> {
        if self.values.len() >= self.vm.limits.max_stack_values {
            return Err(WasmNumericVmError::StackLimitExceeded { max: self.vm.limits.max_stack_values });
        }
        self.values.push(ty);
        Ok(())
    }

    fn push_types(&mut self, types: &[WasmValueType]) -> Result<(), WasmNumericVmError> {
        for ty in types { self.push(Some(*ty))?; }
        Ok(())
    }

    fn unreachable(&mut self) {
        let frame = self.frames.last_mut().expect("validated control frame");
        self.values.truncate(frame.height);
        frame.unreachable = true;
    }

    fn label(&self, depth: u32) -> Result<(BlockType, Kind), WasmNumericVmError> {
        let index = self.frames.len().checked_sub(depth as usize).and_then(|index| index.checked_sub(1))
            .ok_or_else(|| invalid(format!("function {} invalid branch depth {depth}", self.function)))?;
        let frame = &self.frames[index];
        Ok((frame.signature, frame.kind))
    }

    fn boundary(&mut self, signature: BlockType) -> Result<(), WasmNumericVmError> {
        self.pop_types(signature.results(self.vm)?)?;
        let height = self.frames.last().expect("active control frame").height;
        if self.values.len() != height {
            return Err(invalid(format!("function {} has excess operands at control boundary", self.function)));
        }
        Ok(())
    }
}

fn label_types<'a>(signature: &'a BlockType, kind: Kind, vm: &'a WasmNumericVm)
    -> Result<&'a [WasmValueType], WasmNumericVmError>
{
    if kind == Kind::Loop { signature.params(vm) } else { signature.results(vm) }
}

fn block_type(reader: &mut CodeReader<'_>) -> Result<BlockType, WasmNumericVmError> {
    let (value, size) = read_signed_leb(&reader.bytes[reader.offset..], 33, 5)?;
    reader.offset += size;
    match value {
        -64 => Ok(BlockType::Empty),
        -1 => Ok(BlockType::Value(WasmValueType::I32)),
        -2 => Ok(BlockType::Value(WasmValueType::I64)),
        -3 => Ok(BlockType::Value(WasmValueType::F32)),
        -4 => Ok(BlockType::Value(WasmValueType::F64)),
        0..=4_294_967_295 => Ok(BlockType::Type(value as u32)),
        _ => Err(invalid(format!("unsupported block type {value}"))),
    }
}

pub(super) fn validate(vm: &WasmNumericVm, function: u32) -> Result<ControlMap, WasmNumericVmError> {
    let body = &vm.functions[(function as usize) - vm.imports.len()];
    let signature = vm.function_type(body.type_index)?;
    let mut validator = Validator {
        vm, function, values: Vec::new(),
        frames: vec![ValidationFrame {
            kind: Kind::Function, signature: BlockType::Type(body.type_index),
            height: 0, unreachable: false, start: 0, body: 0, alternate: None,
        }],
    };
    let mut map = ControlMap::default();
    let mut reader = CodeReader::new(&body.code);
    while !reader.finished() {
        let offset = reader.offset();
        let opcode = reader.read_u8(function)?;
        match opcode {
            0x00 => validator.unreachable(),
            0x01 => {},
            0x02..=0x04 => {
                if validator.frames.len() > vm.limits.max_control_depth {
                    return Err(WasmNumericVmError::ControlDepthExceeded { max: vm.limits.max_control_depth });
                }
                let signature = block_type(&mut reader)?;
                let kind = match opcode { 0x02 => Kind::Block, 0x03 => Kind::Loop, _ => Kind::If };
                if kind == Kind::If { validator.expect(WasmValueType::I32)?; }
                validator.pop_types(signature.params(vm)?)?;
                let height = validator.values.len();
                validator.frames.push(ValidationFrame {
                    kind, signature, height, unreachable: false,
                    start: offset, body: reader.offset(), alternate: None,
                });
                validator.push_types(signature.params(vm)?)?;
            }
            0x05 => {
                let frame = validator.frames.last().ok_or_else(|| invalid("else outside function"))?;
                if frame.kind != Kind::If || frame.alternate.is_some() {
                    return Err(invalid("else must match exactly one if"));
                }
                let signature = frame.signature;
                validator.boundary(signature)?;
                let frame = validator.frames.last_mut().expect("if frame");
                frame.alternate = Some(reader.offset());
                frame.unreachable = false;
                validator.push_types(signature.params(vm)?)?;
            }
            0x0b => {
                let frame = validator.frames.last().ok_or_else(|| invalid("unmatched end"))?;
                let signature = frame.signature;
                if frame.kind == Kind::If && frame.alternate.is_none()
                    && signature.params(vm)? != signature.results(vm)? {
                    return Err(invalid("if without else must preserve its parameter types"));
                }
                validator.boundary(signature)?;
                let frame = validator.frames.pop().expect("ending frame");
                if frame.kind == Kind::Function {
                    if !reader.finished() { return Err(invalid("bytes after function end")); }
                    return Ok(map);
                }
                map.blocks.insert(frame.start, Block {
                    kind: frame.kind, params: signature.params(vm)?.len(),
                    results: signature.results(vm)?.len(), body: frame.body,
                    alternate: frame.alternate, end: offset,
                });
                validator.push_types(signature.results(vm)?)?;
            }
            0x0c | 0x0d => {
                let depth = reader.read_u32_leb(function)?;
                let (signature, kind) = validator.label(depth)?;
                if opcode == 0x0d { validator.expect(WasmValueType::I32)?; }
                let types = label_types(&signature, kind, vm)?;
                validator.pop_types(types)?;
                if opcode == 0x0d { validator.push_types(types)?; } else { validator.unreachable(); }
            }
            0x0e => {
                validator.expect(WasmValueType::I32)?;
                let count = reader.read_u32_leb(function)?;
                // No count-sized allocation: hostile LEB lengths cannot reserve
                // memory before the section's actual bytes have been checked.
                let first = reader.read_u32_leb(function)?;
                let (signature, kind) = validator.label(first)?;
                let types = label_types(&signature, kind, vm)?;
                for _ in 0..count {
                    let depth = reader.read_u32_leb(function)?;
                    let (other, other_kind) = validator.label(depth)?;
                    if types != label_types(&other, other_kind, vm)? {
                        return Err(invalid("br_table targets have different label types"));
                    }
                }
                validator.pop_types(types)?;
                validator.unreachable();
            }
            0x0f => { validator.pop_types(&signature.results)?; validator.unreachable(); }
            0x10 => {
                let callee = reader.read_u32_leb(function)?;
                let callee = vm.function_signature(callee)?;
                validator.pop_types(&callee.params)?;
                validator.push_types(&callee.results)?;
            }
            0x1a => { validator.pop()?; }
            0x1b => {
                validator.expect(WasmValueType::I32)?;
                let right = validator.pop()?;
                let left = validator.pop()?;
                if let (Some(left), Some(right)) = (left, right) {
                    ensure_same_type(function, 0, left, right)?;
                }
                validator.push(left.or(right))?;
            }
            0x20..=0x22 => {
                let index = reader.read_u32_leb(function)?;
                let ty = signature.params.get(index as usize).or_else(|| {
                    (index as usize).checked_sub(signature.params.len()).and_then(|i| body.locals.get(i))
                }).copied().ok_or(WasmNumericVmError::InvalidLocal { function_index: function, local_index: index })?;
                if opcode != 0x20 { validator.expect(ty)?; }
                if opcode != 0x21 { validator.push(Some(ty))?; }
            }
            0x23..=0x40 => {
                let effect = vm.state.validate_instruction(opcode, &mut reader, function)?;
                for ty in effect.pop.into_iter().flatten() { validator.expect(ty)?; }
                if let Some(ty) = effect.push { validator.push(Some(ty))?; }
            }
            0x41 => { reader.read_i32_leb(function)?; validator.push(Some(WasmValueType::I32))?; }
            0x42 => { reader.read_i64_leb(function)?; validator.push(Some(WasmValueType::I64))?; }
            0x43 => { reader.read_u32_le(function)?; validator.push(Some(WasmValueType::F32))?; }
            0x44 => { reader.read_u64_le(function)?; validator.push(Some(WasmValueType::F64))?; }
            _ => {
                let (input, count, output) = numeric_signature(opcode).ok_or(WasmNumericVmError::UnsupportedOpcode {
                    function_index: function, opcode, offset,
                })?;
                for _ in 0..count { validator.expect(input)?; }
                validator.push(Some(output))?;
            }
        }
    }
    Err(invalid(format!("function {function} has an unterminated control frame")))
}

fn numeric_signature(opcode: u8) -> Option<(WasmValueType, usize, WasmValueType)> {
    use WasmValueType::{F32, F64, I32, I64};
    Some(match opcode {
        0x45 => (I32, 1, I32), 0x46..=0x4f => (I32, 2, I32),
        0x50 => (I64, 1, I32), 0x51..=0x5a => (I64, 2, I32),
        0x5b..=0x60 => (F32, 2, I32), 0x61..=0x66 => (F64, 2, I32),
        0x67..=0x69 | 0xc0 | 0xc1 => (I32, 1, I32),
        0x6a..=0x78 => (I32, 2, I32),
        0x79..=0x7b | 0xc2..=0xc4 => (I64, 1, I64),
        0x7c..=0x8a => (I64, 2, I64),
        0x8b..=0x91 => (F32, 1, F32), 0x92..=0x98 => (F32, 2, F32),
        0x99..=0x9f => (F64, 1, F64), 0xa0..=0xa6 => (F64, 2, F64),
        0xa7 => (I64, 1, I32), 0xac | 0xad => (I32, 1, I64),
        0xa8 | 0xa9 => (F32, 1, I32), 0xaa | 0xab => (F64, 1, I32),
        0xae | 0xaf => (F32, 1, I64), 0xb0 | 0xb1 => (F64, 1, I64),
        0xb2 | 0xb3 => (I32, 1, F32), 0xb4 | 0xb5 => (I64, 1, F32),
        0xb6 => (F64, 1, F32),
        0xb7 | 0xb8 => (I32, 1, F64), 0xb9 | 0xba => (I64, 1, F64),
        0xbb => (F32, 1, F64),
        0xbc => (F32, 1, I32), 0xbd => (F64, 1, I64),
        0xbe => (I32, 1, F32), 0xbf => (I64, 1, F64),
        _ => return None,
    })
}

pub(super) struct Frame {
    kind: Kind,
    height: usize,
    body: usize,
    end: usize,
    labels: usize,
    results: usize,
}

impl Frame {
    pub(super) fn function(results: usize, end: usize) -> Self {
        Self { kind: Kind::Function, height: 0, body: 0, end, labels: results, results }
    }
}

fn finish(stack: &mut Vec<WasmBoundaryValue>, frame: &Frame) -> Result<(), WasmNumericVmError> {
    if stack.len() != frame.height.saturating_add(frame.results) {
        return Err(invalid("validated control result stack changed shape"));
    }
    Ok(())
}

fn branch(depth: u32, frames: &mut Vec<Frame>, stack: &mut Vec<WasmBoundaryValue>, reader: &mut CodeReader<'_>)
    -> Result<bool, WasmNumericVmError>
{
    let target = frames.len().checked_sub(depth as usize).and_then(|index| index.checked_sub(1)).ok_or_else(|| invalid("invalid runtime branch depth"))?;
    let frame = &frames[target];
    let retained = stack.len().checked_sub(frame.labels).ok_or_else(|| invalid("missing branch arguments"))?;
    if retained < frame.height { return Err(invalid("branch consumed an enclosing operand")); }
    stack.drain(frame.height..retained);
    if frame.kind == Kind::Function { return Ok(true); }
    if frame.kind == Kind::Loop {
        reader.offset = frame.body;
        frames.truncate(target + 1);
    } else {
        reader.offset = frame.end + 1;
        frames.truncate(target);
    }
    Ok(false)
}

pub(super) fn execute(
    opcode: u8, map: &ControlMap, frames: &mut Vec<Frame>,
    stack: &mut Vec<WasmBoundaryValue>, reader: &mut CodeReader<'_>,
    meter: &mut ExecutionMeter<'_>, function: u32,
) -> Result<bool, WasmNumericVmError> {
    match opcode {
        0x00 => return Err(WasmNumericVmError::Unreachable { function_index: function }),
        0x01 => {},
        0x02..=0x04 => {
            let block = map.blocks.get(&(reader.offset() - 1)).ok_or_else(|| invalid("missing validated block"))?;
            let condition = if opcode == 0x04 {
                expect_i32(pop_value(stack, function, opcode)?, function, 0)? != 0
            } else { true };
            let height = stack.len().checked_sub(block.params).ok_or_else(|| invalid("missing block parameters"))?;
            frames.push(Frame { kind: block.kind, height, body: block.body, end: block.end,
                labels: if block.kind == Kind::Loop { block.params } else { block.results }, results: block.results });
            reader.offset = if condition { block.body } else { block.alternate.unwrap_or(block.end) };
        }
        0x05 | 0x0b => {
            let frame = frames.pop().ok_or_else(|| invalid("missing runtime control frame"))?;
            finish(stack, &frame)?;
            if frame.kind == Kind::Function { return Ok(true); }
            if opcode == 0x05 { reader.offset = frame.end + 1; }
        }
        0x0c | 0x0d => {
            let depth = reader.read_u32_leb(function)?;
            if opcode == 0x0c || expect_i32(pop_value(stack, function, opcode)?, function, 0)? != 0 {
                return branch(depth, frames, stack, reader);
            }
        }
        0x0e => {
            let index = expect_i32(pop_value(stack, function, opcode)?, function, 0)? as u32;
            let count = reader.read_u32_leb(function)?;
            let mut selected = None;
            for entry in 0..count {
                // Table decoding is native work too: a huge immediate must not
                // bypass the same deterministic instruction budget as a loop.
                meter.tick()?;
                let label = reader.read_u32_leb(function)?;
                if entry == index { selected = Some(label); }
            }
            meter.tick()?;
            let default = reader.read_u32_leb(function)?;
            return branch(selected.unwrap_or(default), frames, stack, reader);
        }
        0x0f => return branch((frames.len() - 1) as u32, frames, stack, reader),
        _ => return Err(invalid("non-control instruction in control dispatcher")),
    }
    Ok(false)
}

pub(super) fn execute_numeric(opcode: u8, stack: &mut Vec<WasmBoundaryValue>, function: u32)
    -> Result<(), WasmNumericVmError>
{
    match opcode {
        0x45..=0x5a => execute_integer_comparison(opcode, stack, function),
        0x5b..=0x66 => execute_float_comparison(opcode, stack, function),
        0x67..=0x69 | 0x71..=0x7b | 0x83..=0x8a | 0xbc..=0xc4 => {
            execute_bit_numeric(opcode, stack, function)
        }
        0x6a..=0x70 => execute_i32_numeric(opcode, stack, function),
        0x7c..=0x82 => execute_i64_numeric(opcode, stack, function),
        0x91..=0x95 => execute_f32_numeric(opcode, stack, function),
        0x9f..=0xa3 => execute_f64_numeric(opcode, stack, function),
        0x8b..=0x90 | 0x96..=0x9e | 0xa4..=0xa6 => {
            execute_float_scalar(opcode, stack, function)
        }
        0xa8..=0xab | 0xae..=0xbb => execute_conversion(opcode, stack, function),
        0xa7 => {
            let value = expect_i64(pop_value(stack, function, opcode)?, function, 0)?;
            stack.push(WasmBoundaryValue::I32(value as i32));
            Ok(())
        }
        0xac | 0xad => {
            let value = expect_i32(pop_value(stack, function, opcode)?, function, 0)?;
            stack.push(WasmBoundaryValue::I64(if opcode == 0xac { i64::from(value) } else { i64::from(value as u32) }));
            Ok(())
        }
        _ => Err(WasmNumericVmError::UnsupportedOpcode { function_index: function, opcode, offset: 0 }),
    }
}

/// These instructions operate on the stored bits, not on host floating-point
/// values. In particular reinterpretation must preserve signaling NaNs and
/// payloads, and shifts mask their counts even in overflow-checked builds.
fn execute_bit_numeric(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function: u32,
) -> Result<(), WasmNumericVmError> {
    use WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};
    let right = pop_value(stack, function, opcode)?;
    let result = match opcode {
        0x67..=0x69 | 0xc0 | 0xc1 => {
            let value = expect_i32(right, function, 0)?;
            I32(match opcode {
                0x67 => value.leading_zeros() as i32,
                0x68 => value.trailing_zeros() as i32,
                0x69 => value.count_ones() as i32,
                0xc0 => i32::from(value as i8),
                0xc1 => i32::from(value as i16),
                _ => unreachable!("matched i32 bit unary opcode"),
            })
        }
        0x79..=0x7b | 0xc2..=0xc4 => {
            let value = expect_i64(right, function, 0)?;
            I64(match opcode {
                0x79 => i64::from(value.leading_zeros()),
                0x7a => i64::from(value.trailing_zeros()),
                0x7b => i64::from(value.count_ones()),
                0xc2 => i64::from(value as i8),
                0xc3 => i64::from(value as i16),
                0xc4 => i64::from(value as i32),
                _ => unreachable!("matched i64 bit unary opcode"),
            })
        }
        0x71..=0x78 => {
            let right = expect_i32(right, function, 1)?;
            let left = expect_i32(pop_value(stack, function, opcode)?, function, 0)?;
            let shift = (right as u32) & 31;
            I32(match opcode {
                0x71 => left & right,
                0x72 => left | right,
                0x73 => left ^ right,
                0x74 => left.wrapping_shl(shift),
                0x75 => left >> shift,
                0x76 => ((left as u32) >> shift) as i32,
                0x77 => left.rotate_left(shift),
                0x78 => left.rotate_right(shift),
                _ => unreachable!("matched i32 bit binary opcode"),
            })
        }
        0x83..=0x8a => {
            let right = expect_i64(right, function, 1)?;
            let left = expect_i64(pop_value(stack, function, opcode)?, function, 0)?;
            let shift = (right as u32) & 63;
            I64(match opcode {
                0x83 => left & right,
                0x84 => left | right,
                0x85 => left ^ right,
                0x86 => left.wrapping_shl(shift),
                0x87 => left >> shift,
                0x88 => ((left as u64) >> shift) as i64,
                0x89 => left.rotate_left(shift),
                0x8a => left.rotate_right(shift),
                _ => unreachable!("matched i64 bit binary opcode"),
            })
        }
        0xbc => I32(expect_f32_bits(right, function, 0)? as i32),
        0xbd => I64(expect_f64_bits(right, function, 0)? as i64),
        0xbe => F32Bits(expect_i32(right, function, 0)? as u32),
        0xbf => F64Bits(expect_i64(right, function, 0)? as u64),
        _ => return Err(WasmNumericVmError::UnsupportedOpcode {
            function_index: function, opcode, offset: 0,
        }),
    };
    // Every admitted numeric opcode consumes at least one operand and produces
    // one, so it cannot increase the metered stack high-water mark.
    stack.push(result);
    Ok(())
}

/// IEEE arithmetic may canonicalize NaNs for replay, but abs, neg and
/// copysign are bit operations and must retain the payload (even signaling).
/// min/max propagate NaNs and explicitly order opposite signed zeros; Rust's
/// host min/max rules alone are not the WebAssembly contract.
fn execute_float_scalar(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function: u32,
) -> Result<(), WasmNumericVmError> {
    use WasmBoundaryValue::{F32Bits, F64Bits};
    let right = pop_value(stack, function, opcode)?;
    let result = match opcode {
        0x8b..=0x90 => {
            let bits = expect_f32_bits(right, function, 0)?;
            let value = f32::from_bits(bits);
            F32Bits(match opcode {
                0x8b => bits & 0x7fff_ffff,
                0x8c => bits ^ 0x8000_0000,
                0x8d => canonical_f32_bits(value.ceil()),
                0x8e => canonical_f32_bits(value.floor()),
                0x8f => canonical_f32_bits(value.trunc()),
                0x90 => canonical_f32_bits(value.round_ties_even()),
                _ => unreachable!("matched f32 unary opcode"),
            })
        }
        0x99..=0x9e => {
            let bits = expect_f64_bits(right, function, 0)?;
            let value = f64::from_bits(bits);
            F64Bits(match opcode {
                0x99 => bits & 0x7fff_ffff_ffff_ffff,
                0x9a => bits ^ 0x8000_0000_0000_0000,
                0x9b => canonical_f64_bits(value.ceil()),
                0x9c => canonical_f64_bits(value.floor()),
                0x9d => canonical_f64_bits(value.trunc()),
                0x9e => canonical_f64_bits(value.round_ties_even()),
                _ => unreachable!("matched f64 unary opcode"),
            })
        }
        0x96..=0x98 => {
            let right = expect_f32_bits(right, function, 1)?;
            let left = expect_f32_bits(pop_value(stack, function, opcode)?, function, 0)?;
            let a = f32::from_bits(left);
            let b = f32::from_bits(right);
            F32Bits(if opcode == 0x98 {
                (left & 0x7fff_ffff) | (right & 0x8000_0000)
            } else if a.is_nan() || b.is_nan() {
                CANONICAL_F32_NAN
            } else if a == 0.0 && b == 0.0 {
                if opcode == 0x96 { left | right } else { left & right }
            } else if (opcode == 0x96 && a < b) || (opcode == 0x97 && a > b) {
                left
            } else {
                right
            })
        }
        0xa4..=0xa6 => {
            let right = expect_f64_bits(right, function, 1)?;
            let left = expect_f64_bits(pop_value(stack, function, opcode)?, function, 0)?;
            let a = f64::from_bits(left);
            let b = f64::from_bits(right);
            F64Bits(if opcode == 0xa6 {
                (left & 0x7fff_ffff_ffff_ffff) | (right & 0x8000_0000_0000_0000)
            } else if a.is_nan() || b.is_nan() {
                CANONICAL_F64_NAN
            } else if a == 0.0 && b == 0.0 {
                if opcode == 0xa4 { left | right } else { left & right }
            } else if (opcode == 0xa4 && a < b) || (opcode == 0xa5 && a > b) {
                left
            } else {
                right
            })
        }
        _ => return Err(WasmNumericVmError::UnsupportedOpcode {
            function_index: function, opcode, offset: 0,
        }),
    };
    stack.push(result);
    Ok(())
}

fn execute_conversion(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function: u32,
) -> Result<(), WasmNumericVmError> {
    use WasmBoundaryValue::{F32Bits, F64Bits};
    let value = pop_value(stack, function, opcode)?;
    let result = match opcode {
        0xa8..=0xab | 0xae..=0xb1 => {
            let number = if matches!(opcode, 0xa8 | 0xa9 | 0xae | 0xaf) {
                f64::from(f32::from_bits(expect_f32_bits(value, function, 0)?))
            } else {
                f64::from_bits(expect_f64_bits(value, function, 0)?)
            };
            trunc_integer(number, opcode <= 0xab, opcode & 1 == 0, function)?
        }
        0xb2 | 0xb3 => {
            let value = expect_i32(value, function, 0)?;
            F32Bits((if opcode == 0xb2 { value as f32 } else { (value as u32) as f32 }).to_bits())
        }
        0xb4 | 0xb5 => {
            let value = expect_i64(value, function, 0)?;
            // A direct integer-to-f32 conversion rounds once. Going through
            // f64 first can double-round integers on an f32 midpoint boundary.
            F32Bits((if opcode == 0xb4 { value as f32 } else { (value as u64) as f32 }).to_bits())
        }
        0xb6 => F32Bits(canonical_f32_bits(f64::from_bits(expect_f64_bits(value, function, 0)?) as f32)),
        0xb7 | 0xb8 => {
            let value = expect_i32(value, function, 0)?;
            F64Bits((if opcode == 0xb7 { f64::from(value) } else { f64::from(value as u32) }).to_bits())
        }
        0xb9 | 0xba => {
            let value = expect_i64(value, function, 0)?;
            F64Bits((if opcode == 0xb9 { value as f64 } else { (value as u64) as f64 }).to_bits())
        }
        0xbb => F64Bits(canonical_f64_bits(f64::from(f32::from_bits(expect_f32_bits(value, function, 0)?)))),
        _ => return Err(WasmNumericVmError::UnsupportedOpcode {
            function_index: function, opcode, offset: 0,
        }),
    };
    stack.push(result);
    Ok(())
}

/// Check the truncated value against exact power-of-two bounds BEFORE any
/// Rust float-to-int cast, which would otherwise silently saturate. In
/// particular (i64::MAX as f64) is 2^63, not a valid inclusive upper bound.
/// NaN and out-of-range conversions use the VM's existing IntegerOverflow
/// trap channel; neither can produce a fabricated integer result.
fn trunc_integer(number: f64, i32_result: bool, signed: bool, function: u32)
    -> Result<WasmBoundaryValue, WasmNumericVmError>
{
    let truncated = number.trunc();
    let (minimum, exclusive_maximum) = match (i32_result, signed) {
        (true, true) => (-2_147_483_648.0, 2_147_483_648.0),
        (true, false) => (0.0, 4_294_967_296.0),
        (false, true) => (-9_223_372_036_854_775_808.0, 9_223_372_036_854_775_808.0),
        (false, false) => (0.0, 18_446_744_073_709_551_616.0),
    };
    if !number.is_finite() || truncated < minimum || truncated >= exclusive_maximum {
        return Err(WasmNumericVmError::IntegerOverflow { function_index: function });
    }
    Ok(match (i32_result, signed) {
        (true, true) => WasmBoundaryValue::I32(truncated as i32),
        (true, false) => WasmBoundaryValue::I32((truncated as u32) as i32),
        (false, true) => WasmBoundaryValue::I64(truncated as i64),
        (false, false) => WasmBoundaryValue::I64((truncated as u64) as i64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(mut value: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = (value & 127) as u8;
            value >>= 7;
            bytes.push(byte | if value == 0 { 0 } else { 128 });
            if value == 0 { return bytes; }
        }
    }

    fn section(module: &mut Vec<u8>, id: u8, bytes: &[u8]) {
        module.push(id);
        module.extend(leb(bytes.len()));
        module.extend(bytes);
    }

    pub(super) fn module(params: &[u8], results: &[u8], local_count: u8, code: &[u8], extra_types: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        let mut types = leb(1 + extra_types.len());
        for (params, results) in std::iter::once((params, results)).chain(extra_types.iter().copied()) {
            types.push(0x60);
            types.extend(leb(params.len()));
            types.extend(params);
            types.extend(leb(results.len()));
            types.extend(results);
        }
        section(&mut module, 1, &types);
        section(&mut module, 3, &[1, 0]);
        section(&mut module, 7, &[1, 1, b'f', 0, 0]);
        let mut body = if local_count == 0 { vec![0] } else { vec![1, local_count, 0x7f] };
        body.extend(code);
        let mut bodies = vec![1];
        bodies.extend(leb(body.len()));
        bodies.extend(body);
        section(&mut module, 10, &bodies);
        module
    }

    fn run(bytes: &[u8], args: &[WasmBoundaryValue]) -> Vec<WasmBoundaryValue> {
        WasmNumericVm::parse(bytes, WasmNumericLimits::default()).unwrap()
            .call_export("f", args).unwrap().results
    }

    fn numeric_module(opcode: u8, params: &[u8], result: u8) -> Vec<u8> {
        let mut code = Vec::new();
        for index in 0..params.len() {
            code.push(0x20);
            code.extend(leb(index));
        }
        code.extend([opcode, 0x0b]);
        module(params, &[result], 0, &code, &[])
    }

    #[test]
    fn f32_rounding_is_ties_even_and_preserves_zero_sign() {
        for (value, expected) in [
            (-0.0_f32, [-0.0, -0.0, -0.0, -0.0]),
            (-0.25, [-0.0, -1.0, -0.0, -0.0]),
            (0.25, [1.0, 0.0, 0.0, 0.0]),
            (-0.5, [-0.0, -1.0, -0.0, -0.0]),
            (0.5, [1.0, 0.0, 0.0, 0.0]),
            (-1.5, [-1.0, -2.0, -1.0, -2.0]),
            (1.5, [2.0, 1.0, 1.0, 2.0]),
            (-2.5, [-2.0, -3.0, -2.0, -2.0]),
            (2.5, [3.0, 2.0, 2.0, 2.0]),
        ] {
            for (opcode, expected) in (0x8d..=0x90).zip(expected) {
                let expected: f32 = expected;
                assert_eq!(run(&numeric_module(opcode, &[0x7d], 0x7d), &[WasmBoundaryValue::F32Bits(value.to_bits())]), [WasmBoundaryValue::F32Bits(expected.to_bits())]);
            }
        }
        for opcode in 0x8d..=0x90 {
            for value in [f32::INFINITY, f32::NEG_INFINITY, 16_777_216.0] {
                assert_eq!(run(&numeric_module(opcode, &[0x7d], 0x7d), &[WasmBoundaryValue::F32Bits(value.to_bits())]), [WasmBoundaryValue::F32Bits(value.to_bits())]);
            }
            assert_eq!(run(&numeric_module(opcode, &[0x7d], 0x7d), &[WasmBoundaryValue::F32Bits(0xff80_0001)]), [WasmBoundaryValue::F32Bits(CANONICAL_F32_NAN)]);
        }
    }

    #[test]
    fn f64_rounding_is_ties_even_and_preserves_zero_sign() {
        for (value, expected) in [
            (-0.0_f64, [-0.0, -0.0, -0.0, -0.0]),
            (-0.25, [-0.0, -1.0, -0.0, -0.0]),
            (0.25, [1.0, 0.0, 0.0, 0.0]),
            (-0.5, [-0.0, -1.0, -0.0, -0.0]),
            (0.5, [1.0, 0.0, 0.0, 0.0]),
            (-1.5, [-1.0, -2.0, -1.0, -2.0]),
            (1.5, [2.0, 1.0, 1.0, 2.0]),
            (-2.5, [-2.0, -3.0, -2.0, -2.0]),
            (2.5, [3.0, 2.0, 2.0, 2.0]),
        ] {
            for (opcode, expected) in (0x9b..=0x9e).zip(expected) {
                let expected: f64 = expected;
                assert_eq!(run(&numeric_module(opcode, &[0x7c], 0x7c), &[WasmBoundaryValue::F64Bits(value.to_bits())]), [WasmBoundaryValue::F64Bits(expected.to_bits())]);
            }
        }
        for opcode in 0x9b..=0x9e {
            for value in [f64::INFINITY, f64::NEG_INFINITY, 4_503_599_627_370_496.0] {
                assert_eq!(run(&numeric_module(opcode, &[0x7c], 0x7c), &[WasmBoundaryValue::F64Bits(value.to_bits())]), [WasmBoundaryValue::F64Bits(value.to_bits())]);
            }
            assert_eq!(run(&numeric_module(opcode, &[0x7c], 0x7c), &[WasmBoundaryValue::F64Bits(0xfff0_0000_0000_0001)]), [WasmBoundaryValue::F64Bits(CANONICAL_F64_NAN)]);
        }
    }

    #[test]
    fn min_max_order_signed_zeros_and_propagate_either_nan() {
        for (op32, op64, minimum) in [(0x96, 0xa4, true), (0x97, 0xa5, false)] {
            for (left, right) in [(0.0_f64, -0.0_f64), (-0.0, 0.0), (-0.0, -0.0), (0.0, 0.0), (3.0, -2.0), (-2.0, 3.0), (f64::INFINITY, f64::NEG_INFINITY)] {
                let expected = if minimum {
                    if left == 0.0 && right == 0.0 {
                        f64::from_bits(left.to_bits() | right.to_bits())
                    } else if left < right { left } else { right }
                } else if left == 0.0 && right == 0.0 {
                    f64::from_bits(left.to_bits() & right.to_bits())
                } else if left > right { left } else { right };
                assert_eq!(run(&numeric_module(op32, &[0x7d, 0x7d], 0x7d), &[WasmBoundaryValue::F32Bits((left as f32).to_bits()), WasmBoundaryValue::F32Bits((right as f32).to_bits())]), [WasmBoundaryValue::F32Bits((expected as f32).to_bits())]);
                assert_eq!(run(&numeric_module(op64, &[0x7c, 0x7c], 0x7c), &[WasmBoundaryValue::F64Bits(left.to_bits()), WasmBoundaryValue::F64Bits(right.to_bits())]), [WasmBoundaryValue::F64Bits(expected.to_bits())]);
            }
            for (left, right) in [(0x7f80_0001, 0), (0, 0xffc1_2345), (0x7fc0_0000, 0xffc1_2345)] {
                assert_eq!(run(&numeric_module(op32, &[0x7d, 0x7d], 0x7d), &[WasmBoundaryValue::F32Bits(left), WasmBoundaryValue::F32Bits(right)]), [WasmBoundaryValue::F32Bits(CANONICAL_F32_NAN)]);
            }
            for (left, right) in [(0x7ff0_0000_0000_0001, 0), (0, 0xfff8_1234_5678_9abc), (0x7ff8_0000_0000_0000, 0xfff8_1234_5678_9abc)] {
                assert_eq!(run(&numeric_module(op64, &[0x7c, 0x7c], 0x7c), &[WasmBoundaryValue::F64Bits(left), WasmBoundaryValue::F64Bits(right)]), [WasmBoundaryValue::F64Bits(CANONICAL_F64_NAN)]);
            }
        }
    }

    #[test]
    fn float_sign_instructions_do_not_canonicalize_nan_payloads() {
        for bits in [0_u32, 0x8000_0000, 0x7f80_0001, 0xffc1_2345] {
            assert_eq!(run(&numeric_module(0x8b, &[0x7d], 0x7d), &[WasmBoundaryValue::F32Bits(bits)]), [WasmBoundaryValue::F32Bits(bits & 0x7fff_ffff)]);
            assert_eq!(run(&numeric_module(0x8c, &[0x7d], 0x7d), &[WasmBoundaryValue::F32Bits(bits)]), [WasmBoundaryValue::F32Bits(bits ^ 0x8000_0000)]);
            for sign in [0_u32, 0x8000_0000, 0xff80_0001] {
                assert_eq!(run(&numeric_module(0x98, &[0x7d, 0x7d], 0x7d), &[WasmBoundaryValue::F32Bits(bits), WasmBoundaryValue::F32Bits(sign)]), [WasmBoundaryValue::F32Bits((bits & 0x7fff_ffff) | (sign & 0x8000_0000))]);
            }
        }
        for bits in [0_u64, 0x8000_0000_0000_0000, 0x7ff0_0000_0000_0001, 0xfff8_1234_5678_9abc] {
            assert_eq!(run(&numeric_module(0x99, &[0x7c], 0x7c), &[WasmBoundaryValue::F64Bits(bits)]), [WasmBoundaryValue::F64Bits(bits & 0x7fff_ffff_ffff_ffff)]);
            assert_eq!(run(&numeric_module(0x9a, &[0x7c], 0x7c), &[WasmBoundaryValue::F64Bits(bits)]), [WasmBoundaryValue::F64Bits(bits ^ 0x8000_0000_0000_0000)]);
            for sign in [0_u64, 0x8000_0000_0000_0000, 0xfff0_0000_0000_0001] {
                assert_eq!(run(&numeric_module(0xa6, &[0x7c, 0x7c], 0x7c), &[WasmBoundaryValue::F64Bits(bits), WasmBoundaryValue::F64Bits(sign)]), [WasmBoundaryValue::F64Bits((bits & 0x7fff_ffff_ffff_ffff) | (sign & 0x8000_0000_0000_0000))]);
            }
        }
    }

    #[test]
    fn integer_to_float_conversions_respect_signedness() {
        use WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};
        for (opcode, input_type, output_type, input, expected) in [
            (0xb2, 0x7f, 0x7d, I32(-1), F32Bits(0xbf80_0000)),
            (0xb3, 0x7f, 0x7d, I32(-1), F32Bits(0x4f80_0000)),
            (0xb4, 0x7e, 0x7d, I64(-1), F32Bits(0xbf80_0000)),
            (0xb5, 0x7e, 0x7d, I64(-1), F32Bits(0x5f80_0000)),
            (0xb7, 0x7f, 0x7c, I32(-1), F64Bits(0xbff0_0000_0000_0000)),
            (0xb8, 0x7f, 0x7c, I32(-1), F64Bits(0x41ef_ffff_ffe0_0000)),
            (0xb9, 0x7e, 0x7c, I64(-1), F64Bits(0xbff0_0000_0000_0000)),
            (0xba, 0x7e, 0x7c, I64(-1), F64Bits(0x43f0_0000_0000_0000)),
        ] {
            assert_eq!(run(&numeric_module(opcode, &[input_type], output_type), &[input]), [expected]);
        }
    }

    #[test]
    fn integer_to_float_rounds_once_at_precision_boundaries() {
        use WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};
        for (opcode, input_type, output_type, input, expected) in [
            (0xb2, 0x7f, 0x7d, I32(16_777_217), F32Bits(0x4b80_0000)),
            (0xb2, 0x7f, 0x7d, I32(16_777_219), F32Bits(0x4b80_0002)),
            (0xb4, 0x7e, 0x7d, I64((1_i64 << 62) + (1_i64 << 38) + 1), F32Bits(0x5e80_0001)),
            (0xb5, 0x7e, 0x7d, I64(((1_u64 << 63) + (1_u64 << 39) + 1) as i64), F32Bits(0x5f00_0001)),
            (0xb9, 0x7e, 0x7c, I64(9_007_199_254_740_993), F64Bits(0x4340_0000_0000_0000)),
        ] {
            assert_eq!(run(&numeric_module(opcode, &[input_type], output_type), &[input]), [expected]);
        }
    }

    #[test]
    fn demotion_and_promotion_handle_underflow_overflow_and_nan() {
        for (value, expected) in [
            (-0.0_f64, 0x8000_0000), (1.5, 0x3fc0_0000),
            (f64::MAX, 0x7f80_0000), (-f64::MAX, 0xff80_0000),
            (f64::from_bits(1), 0), (-f64::from_bits(1), 0x8000_0000),
            (f64::from(f32::from_bits(1)), 1),
            (1.0 + 2_f64.powi(-24), 0x3f80_0000),
            (f64::NAN, CANONICAL_F32_NAN),
        ] {
            assert_eq!(run(&numeric_module(0xb6, &[0x7c], 0x7d), &[WasmBoundaryValue::F64Bits(value.to_bits())]), [WasmBoundaryValue::F32Bits(expected)]);
        }
        for (bits, expected) in [
            (0_u32, 0_u64), (0x8000_0000, 0x8000_0000_0000_0000),
            (0x3fc0_0000, 0x3ff8_0000_0000_0000), (1, 0x36a0_0000_0000_0000),
            (0x7f80_0000, 0x7ff0_0000_0000_0000),
            (0xff80_0001, CANONICAL_F64_NAN),
        ] {
            assert_eq!(run(&numeric_module(0xbb, &[0x7d], 0x7c), &[WasmBoundaryValue::F32Bits(bits)]), [WasmBoundaryValue::F64Bits(expected)]);
        }
    }

    #[test]
    fn truncation_to_i32_checks_truncated_not_original_value() {
        for (opcode, input_type) in [(0xa8, 0x7d), (0xa9, 0x7d), (0xaa, 0x7c), (0xab, 0x7c)] {
            let bytes = numeric_module(opcode, &[input_type], 0x7f);
            let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
            for (value, expected) in [(-0.0_f64, 0), (-0.75, 0), (0.75, 0), (42.75, 42)] {
                let value = if input_type == 0x7d { WasmBoundaryValue::F32Bits((value as f32).to_bits()) } else { WasmBoundaryValue::F64Bits(value.to_bits()) };
                assert_eq!(vm.call_export("f", &[value]).unwrap().results, [WasmBoundaryValue::I32(expected)]);
            }
        }
        for (opcode, value, expected) in [
            (0xaa, -2_147_483_648.75_f64, i32::MIN),
            (0xaa, 2_147_483_647.75, i32::MAX),
            (0xab, 4_294_967_295.75, -1),
        ] {
            assert_eq!(run(&numeric_module(opcode, &[0x7c], 0x7f), &[WasmBoundaryValue::F64Bits(value.to_bits())]), [WasmBoundaryValue::I32(expected)]);
        }
        for (opcode, bits, expected) in [
            (0xa8, 0xcf00_0000, i32::MIN),
            (0xa8, 0x4eff_ffff, i32::MAX - 127),
            (0xa9, 0x4f7f_ffff, -256),
        ] {
            assert_eq!(run(&numeric_module(opcode, &[0x7d], 0x7f), &[WasmBoundaryValue::F32Bits(bits)]), [WasmBoundaryValue::I32(expected)]);
        }
        for (opcode, bits) in [(0xa8, 0xcf00_0001), (0xa8, 0x4f00_0000), (0xa9, 0xbf80_0000), (0xa9, 0x4f80_0000)] {
            let vm = WasmNumericVm::parse(&numeric_module(opcode, &[0x7d], 0x7f), WasmNumericLimits::default()).unwrap();
            assert!(matches!(vm.call_export("f", &[WasmBoundaryValue::F32Bits(bits)]), Err(WasmNumericVmError::IntegerOverflow { .. })));
        }
        for (opcode, value) in [(0xaa, -2_147_483_649.0_f64), (0xaa, 2_147_483_648.0), (0xab, -1.0), (0xab, 4_294_967_296.0)] {
            let vm = WasmNumericVm::parse(&numeric_module(opcode, &[0x7c], 0x7f), WasmNumericLimits::default()).unwrap();
            assert!(matches!(vm.call_export("f", &[WasmBoundaryValue::F64Bits(value.to_bits())]), Err(WasmNumericVmError::IntegerOverflow { .. })));
        }
    }

    #[test]
    fn truncation_to_i64_uses_exclusive_exact_power_of_two_bounds() {
        for (opcode, input_type) in [(0xae, 0x7d), (0xaf, 0x7d), (0xb0, 0x7c), (0xb1, 0x7c)] {
            let vm = WasmNumericVm::parse(&numeric_module(opcode, &[input_type], 0x7e), WasmNumericLimits::default()).unwrap();
            let unsigned = opcode & 1 != 0;
            let upper = if unsigned { 18_446_744_073_709_551_616.0_f64 } else { 9_223_372_036_854_775_808.0 };
            let at_upper = if input_type == 0x7d { WasmBoundaryValue::F32Bits((upper as f32).to_bits()) } else { WasmBoundaryValue::F64Bits(upper.to_bits()) };
            assert!(matches!(vm.call_export("f", &[at_upper]), Err(WasmNumericVmError::IntegerOverflow { .. })));
            let (below_upper, expected) = match (input_type, unsigned) {
                (0x7d, false) => (WasmBoundaryValue::F32Bits(0x5eff_ffff), i64::MAX - (1_i64 << 39) + 1),
                (0x7d, true) => (WasmBoundaryValue::F32Bits(0x5f7f_ffff), -(1_i64 << 40)),
                (0x7c, false) => (WasmBoundaryValue::F64Bits(0x43df_ffff_ffff_ffff), i64::MAX - 1023),
                (0x7c, true) => (WasmBoundaryValue::F64Bits(0x43ef_ffff_ffff_ffff), -2048),
                _ => unreachable!(),
            };
            assert_eq!(vm.call_export("f", &[below_upper]).unwrap().results, [WasmBoundaryValue::I64(expected)]);
            let lower = if unsigned { -0.75_f64 } else { -9_223_372_036_854_775_808.0 };
            let lower = if input_type == 0x7d { WasmBoundaryValue::F32Bits((lower as f32).to_bits()) } else { WasmBoundaryValue::F64Bits(lower.to_bits()) };
            assert_eq!(vm.call_export("f", &[lower]).unwrap().results, [WasmBoundaryValue::I64(if unsigned { 0 } else { i64::MIN })]);
            let below_lower = match (input_type, unsigned) {
                (0x7d, false) => WasmBoundaryValue::F32Bits(0xdf00_0001),
                (0x7d, true) => WasmBoundaryValue::F32Bits((-1.0_f32).to_bits()),
                (0x7c, false) => WasmBoundaryValue::F64Bits(0xc3e0_0000_0000_0001),
                (0x7c, true) => WasmBoundaryValue::F64Bits((-1.0_f64).to_bits()),
                _ => unreachable!(),
            };
            assert!(matches!(vm.call_export("f", &[below_lower]), Err(WasmNumericVmError::IntegerOverflow { .. })));
        }
    }

    #[test]
    fn all_trapping_conversions_reject_nan_and_infinity_without_saturation() {
        for (opcode, input_type, output_type) in [
            (0xa8, 0x7d, 0x7f), (0xa9, 0x7d, 0x7f), (0xaa, 0x7c, 0x7f), (0xab, 0x7c, 0x7f),
            (0xae, 0x7d, 0x7e), (0xaf, 0x7d, 0x7e), (0xb0, 0x7c, 0x7e), (0xb1, 0x7c, 0x7e),
        ] {
            let vm = WasmNumericVm::parse(&numeric_module(opcode, &[input_type], output_type), WasmNumericLimits::default()).unwrap();
            for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                let input = if input_type == 0x7d { WasmBoundaryValue::F32Bits((number as f32).to_bits()) } else { WasmBoundaryValue::F64Bits(number.to_bits()) };
                assert!(matches!(vm.call_export("f", &[input]), Err(WasmNumericVmError::IntegerOverflow { .. })));
            }
            let input = if input_type == 0x7d { WasmBoundaryValue::F32Bits(42.75_f32.to_bits()) } else { WasmBoundaryValue::F64Bits(42.75_f64.to_bits()) };
            assert_eq!(vm.call_export("f", &[input]).unwrap().results, [if output_type == 0x7f { WasmBoundaryValue::I32(42) } else { WasmBoundaryValue::I64(42) }]);
        }
    }

    #[test]
    fn numeric_validation_covers_all_unprefixed_scalar_opcodes() {
        for opcode in 0x45..=0xc4 {
            let (input, count, output) = numeric_signature(opcode).expect("unprefixed scalar opcode");
            let encode = |ty| match ty { WasmValueType::I32 => 0x7f, WasmValueType::I64 => 0x7e, WasmValueType::F32 => 0x7d, WasmValueType::F64 => 0x7c };
            let bytes = numeric_module(opcode, &vec![encode(input); count], encode(output));
            let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
            let one = match input { WasmValueType::I32 => WasmBoundaryValue::I32(1), WasmValueType::I64 => WasmBoundaryValue::I64(1), WasmValueType::F32 => WasmBoundaryValue::F32Bits(1.0_f32.to_bits()), WasmValueType::F64 => WasmBoundaryValue::F64Bits(1.0_f64.to_bits()) };
            let result = vm.call_export("f", &vec![one; count]).unwrap();
            assert_eq!(result.results.len(), 1, "opcode {opcode:#x}");
            assert_eq!(result.results[0].value_type(), output);
            assert_eq!(result.instructions_executed, count as u64 + 2);
        }
        for code in [vec![0x00,0x41,1,0x90,0x0b], vec![0x00,0x42,1,0xaa,0x0b], vec![0x41,1,0xbb,0x0b]] {
            assert!(WasmNumericVm::parse(&module(&[], &[0x7f], 0, &code, &[]), WasmNumericLimits::default()).is_err());
        }
    }

    #[test]
    fn conversion_is_metered_before_it_can_trap() {
        let bytes = numeric_module(0xaa, &[0x7c], 0x7f);
        let limits = WasmNumericLimits { max_instructions: 1, ..WasmNumericLimits::default() };
        let vm = WasmNumericVm::parse(&bytes, limits).unwrap();
        assert_eq!(vm.call_export("f", &[WasmBoundaryValue::F64Bits(f64::NAN.to_bits())]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 1 }));
        let limits = WasmNumericLimits { max_instructions: 3, ..WasmNumericLimits::default() };
        let vm = WasmNumericVm::parse(&bytes, limits).unwrap();
        let result = vm.call_export("f", &[WasmBoundaryValue::F64Bits(42.75_f64.to_bits())]).unwrap();
        assert_eq!(result.instructions_executed, 3);
        assert_eq!(result.results, [WasmBoundaryValue::I32(42)]);
    }

    #[test]
    fn i32_bit_counts_cover_zero_sign_bit_and_all_ones() {
        for (value, expected) in [
            (0, [32, 32, 0]), (1, [31, 0, 1]),
            (i32::MIN, [0, 31, 1]), (-1, [0, 0, 32]),
        ] {
            for (opcode, expected) in (0x67..=0x69).zip(expected) {
                assert_eq!(run(&numeric_module(opcode, &[0x7f], 0x7f), &[WasmBoundaryValue::I32(value)]), [WasmBoundaryValue::I32(expected)]);
            }
        }
    }

    #[test]
    fn i64_bit_counts_return_i64_not_i32() {
        for (value, expected) in [
            (0, [64, 64, 0]), (1, [63, 0, 1]),
            (i64::MIN, [0, 63, 1]), (-1, [0, 0, 64]),
        ] {
            for (opcode, expected) in (0x79..=0x7b).zip(expected) {
                assert_eq!(run(&numeric_module(opcode, &[0x7e], 0x7e), &[WasmBoundaryValue::I64(value)]), [WasmBoundaryValue::I64(expected)]);
            }
        }
    }

    #[test]
    fn i32_bitwise_shift_and_rotate_preserve_width_and_mask_counts() {
        let left = 0x8000_0003_u32 as i32;
        let expected = [1_u32, 0x8000_0003, 0x8000_0002, 6, 0xc000_0001, 0x4000_0001, 7, 0xc000_0001];
        for (opcode, expected) in (0x71..=0x78).zip(expected) {
            let bytes = numeric_module(opcode, &[0x7f, 0x7f], 0x7f);
            assert_eq!(run(&bytes, &[WasmBoundaryValue::I32(left), WasmBoundaryValue::I32(1)]), [WasmBoundaryValue::I32(expected as i32)]);
        }
        for count in [0, 32, 64, i32::MIN] {
            for opcode in 0x74..=0x78 {
                let bytes = numeric_module(opcode, &[0x7f, 0x7f], 0x7f);
                assert_eq!(run(&bytes, &[WasmBoundaryValue::I32(left), WasmBoundaryValue::I32(count)]), [WasmBoundaryValue::I32(left)]);
            }
        }
        for (opcode, expected) in (0x74..=0x78).zip([0x8000_0000_u32, 0xffff_ffff, 1, 0xc000_0001, 7]) {
            let bytes = numeric_module(opcode, &[0x7f, 0x7f], 0x7f);
            assert_eq!(run(&bytes, &[WasmBoundaryValue::I32(left), WasmBoundaryValue::I32(-1)]), [WasmBoundaryValue::I32(expected as i32)]);
        }
    }

    #[test]
    fn i64_bitwise_shift_and_rotate_preserve_high_bits() {
        let left = 0x8000_0000_0000_0003_u64 as i64;
        let expected = [1_u64, 0x8000_0000_0000_0003, 0x8000_0000_0000_0002, 6, 0xc000_0000_0000_0001, 0x4000_0000_0000_0001, 7, 0xc000_0000_0000_0001];
        for (opcode, expected) in (0x83..=0x8a).zip(expected) {
            let bytes = numeric_module(opcode, &[0x7e, 0x7e], 0x7e);
            assert_eq!(run(&bytes, &[WasmBoundaryValue::I64(left), WasmBoundaryValue::I64(1)]), [WasmBoundaryValue::I64(expected as i64)]);
        }
        for count in [0, 64, 128, i64::MIN, 1_i64 << 32] {
            for opcode in 0x86..=0x8a {
                let bytes = numeric_module(opcode, &[0x7e, 0x7e], 0x7e);
                assert_eq!(run(&bytes, &[WasmBoundaryValue::I64(left), WasmBoundaryValue::I64(count)]), [WasmBoundaryValue::I64(left)]);
            }
        }
        for (opcode, expected) in (0x86..=0x8a).zip([0x8000_0000_0000_0000_u64, u64::MAX, 1, 0xc000_0000_0000_0001, 7]) {
            let bytes = numeric_module(opcode, &[0x7e, 0x7e], 0x7e);
            assert_eq!(run(&bytes, &[WasmBoundaryValue::I64(left), WasmBoundaryValue::I64(-1)]), [WasmBoundaryValue::I64(expected as i64)]);
        }
    }

    #[test]
    fn narrow_sign_extensions_discard_high_bits() {
        for (opcode, value, expected) in [
            (0xc0, 0x1234_ff80, -128), (0xc0, 0x1234_ff7f, 127),
            (0xc1, 0x1234_8000, -32768), (0xc1, 0x1234_7fff, 32767),
        ] {
            assert_eq!(run(&numeric_module(opcode, &[0x7f], 0x7f), &[WasmBoundaryValue::I32(value)]), [WasmBoundaryValue::I32(expected)]);
        }
        for (opcode, value, expected) in [
            (0xc2, 0x1234_5678_ffff_ff80, -128), (0xc2, 0x1234_5678_ffff_ff7f, 127),
            (0xc3, 0x1234_5678_ffff_8000, -32768), (0xc3, 0x1234_5678_ffff_7fff, 32767),
            (0xc4, 0x1234_5678_8000_0000, -2_147_483_648), (0xc4, 0x1234_5678_7fff_ffff, 2_147_483_647),
        ] {
            assert_eq!(run(&numeric_module(opcode, &[0x7e], 0x7e), &[WasmBoundaryValue::I64(value)]), [WasmBoundaryValue::I64(expected)]);
        }
    }

    #[test]
    fn reinterpretation_keeps_exact_nan_payloads_and_signed_zero() {
        for bits in [0_u32, 0x8000_0000, 1, 0x7f80_0000, 0xff80_0000, 0x7f80_0001, 0xffc1_2345] {
            assert_eq!(run(&numeric_module(0xbc, &[0x7d], 0x7f), &[WasmBoundaryValue::F32Bits(bits)]), [WasmBoundaryValue::I32(bits as i32)]);
            assert_eq!(run(&numeric_module(0xbe, &[0x7f], 0x7d), &[WasmBoundaryValue::I32(bits as i32)]), [WasmBoundaryValue::F32Bits(bits)]);
        }
        for bits in [0_u64, 0x8000_0000_0000_0000, 1, 0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000, 0x7ff0_0000_0000_0001, 0xfff8_1234_5678_9abc] {
            assert_eq!(run(&numeric_module(0xbd, &[0x7c], 0x7e), &[WasmBoundaryValue::F64Bits(bits)]), [WasmBoundaryValue::I64(bits as i64)]);
            assert_eq!(run(&numeric_module(0xbf, &[0x7e], 0x7c), &[WasmBoundaryValue::I64(bits as i64)]), [WasmBoundaryValue::F64Bits(bits)]);
        }
    }

    #[test]
    fn xorshift_workload_executes_and_replays_under_the_instruction_meter() {
        let bytes = module(&[0x7f], &[0x7f], 0, &[
            0x20,0,0x20,0,0x41,13,0x74,0x73,0x21,0,
            0x20,0,0x20,0,0x41,17,0x76,0x73,0x21,0,
            0x20,0,0x20,0,0x41,5,0x74,0x73,0x0b,
        ], &[]);
        let limits = WasmNumericLimits { max_instructions: 18, ..WasmNumericLimits::default() };
        let vm = WasmNumericVm::parse(&bytes, limits).unwrap();
        let mut value = 1;
        for expected in [270369_u32, 67634689, 2647435461, 307599695, 2398689233] {
            let args = [WasmBoundaryValue::I32(value)];
            let result = vm.call_export("f", &args).unwrap();
            assert_eq!(result, vm.call_export("f", &args).unwrap());
            assert_eq!(result.results, [WasmBoundaryValue::I32(expected as i32)]);
            assert_eq!(result.instructions_executed, 18);
            value = expected as i32;
        }
        let limits = WasmNumericLimits { max_instructions: 17, ..WasmNumericLimits::default() };
        let vm = WasmNumericVm::parse(&bytes, limits).unwrap();
        assert_eq!(vm.call_export("f", &[WasmBoundaryValue::I32(1)]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 17 }));
    }

    #[test]
    fn bit_opcodes_validate_operand_types_in_dead_and_live_code() {
        for code in [
            vec![0x42,1,0x67,0x0b],
            vec![0x00,0x42,1,0x67,0x0b],
            vec![0x41,1,0x79,0x0b],
            vec![0x00,0x41,1,0xbd,0x0b],
            vec![0x41,1,0x41,1,0x86,0x0b],
            vec![0x00,0xc5,0x0b],
        ] {
            assert!(WasmNumericVm::parse(&module(&[], &[0x7f], 0, &code, &[]), WasmNumericLimits::default()).is_err(), "{code:?}");
        }
    }

    #[test]
    fn factorial_executes_nested_loop_and_conditional_exit() {
        let bytes = module(&[0x7f], &[0x7f], 1, &[
            0x41,1,0x21,1,0x02,0x40,0x03,0x40,
            0x20,0,0x45,0x0d,1,0x20,1,0x20,0,0x6c,0x21,1,
            0x20,0,0x41,1,0x6b,0x21,0,0x0c,0,0x0b,0x0b,0x20,1,0x0b,
        ], &[]);
        for (argument, expected) in [(0,1), (1,1), (5,120), (10,3_628_800)] {
            assert_eq!(run(&bytes, &[WasmBoundaryValue::I32(argument)]), [WasmBoundaryValue::I32(expected)]);
        }
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
        let a = vm.call_export("f", &[WasmBoundaryValue::I32(5)]).unwrap();
        assert_eq!(a, vm.call_export("f", &[WasmBoundaryValue::I32(5)]).unwrap());
    }

    #[test]
    fn if_else_selects_exactly_one_result_arm() {
        let bytes = module(&[0x7f], &[0x7f], 0,
            &[0x20,0,0x04,0x7f,0x41,11,0x05,0x41,22,0x0b,0x0b], &[]);
        for (condition, expected) in [(0,22), (1,11), (-1,11)] {
            assert_eq!(run(&bytes, &[WasmBoundaryValue::I32(condition)]), [WasmBoundaryValue::I32(expected)]);
        }
    }

    #[test]
    fn branch_preserves_outer_prefix_and_only_label_results() {
        let bytes = module(&[], &[0x7f], 0,
            &[0x41,10,0x02,0x7f,0x41,7,0x41,9,0x0c,0,0x0b,0x6a,0x0b], &[]);
        assert_eq!(run(&bytes, &[]), [WasmBoundaryValue::I32(19)]);
    }

    #[test]
    fn return_discards_non_result_operands() {
        let bytes = module(&[], &[0x7f], 0, &[0x41,10,0x41,42,0x0f,0x0b], &[]);
        assert_eq!(run(&bytes, &[]), [WasmBoundaryValue::I32(42)]);
    }

    #[test]
    fn branch_table_handles_index_and_unsigned_default() {
        let bytes = module(&[0x7f], &[0x7f], 0, &[
            0x02,0x7f,0x02,0x7f,0x41,42,0x20,0,0x0e,1,0,1,
            0x0b,0x41,1,0x6a,0x0b,0x0b,
        ], &[]);
        for (index, expected) in [(0,43), (1,42), (-1,42)] {
            assert_eq!(run(&bytes, &[WasmBoundaryValue::I32(index)]), [WasmBoundaryValue::I32(expected)]);
        }
    }

    #[test]
    fn indexed_block_types_preserve_multiple_values() {
        let bytes = module(&[], &[0x7f,0x7e], 0,
            &[0x41,7,0x42,9,0x02,1,0x0c,0,0x0b,0x0b], &[(&[0x7f,0x7e], &[0x7f,0x7e])]);
        assert_eq!(run(&bytes, &[]), [WasmBoundaryValue::I32(7), WasmBoundaryValue::I64(9)]);
    }

    #[test]
    fn loop_branches_carry_parameters_not_results() {
        let bytes = module(&[], &[0x7e], 1,
            &[0x41,3,0x03,1,0x41,1,0x6b,0x22,0,0x20,0,0x0d,0,0x1a,0x42,9,0x0b,0x0b], &[(&[0x7f], &[0x7e])]);
        assert_eq!(run(&bytes, &[]), [WasmBoundaryValue::I64(9)]);
    }

    #[test]
    fn if_without_else_preserves_block_parameters() {
        let bytes = module(&[0x7f], &[0x7f], 0,
            &[0x41,7,0x20,0,0x04,1,0x41,1,0x6a,0x0b,0x0b], &[(&[0x7f], &[0x7f])]);
        assert_eq!(run(&bytes, &[WasmBoundaryValue::I32(0)]), [WasmBoundaryValue::I32(7)]);
        assert_eq!(run(&bytes, &[WasmBoundaryValue::I32(1)]), [WasmBoundaryValue::I32(8)]);
    }

    #[test]
    fn unreachable_is_polymorphic_but_traps_when_executed() {
        let bytes = module(&[], &[0x7f], 0, &[0x00,0x6a,0x0b], &[]);
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
        assert!(matches!(vm.call_export("f", &[]), Err(WasmNumericVmError::Unreachable { .. })));
    }

    #[test]
    fn invalid_dead_code_and_bad_control_boundaries_are_rejected() {
        for code in [
            vec![0x41,42,0x0f,0x42,1,0x0b], // concrete i64 result in dead code
            vec![0x00,0x20,99,0x0b], // invalid local in dead code
            vec![0x41,1,0x0c,1,0x0b], // label beyond the function
            vec![0x41,1,0x04,0x7f,0x41,2,0x0b,0x0b], // missing result-producing else
            vec![0x41,1,0x02,0x7f,0x0b,0x0b], // block consumes enclosing operand
            vec![0x41,1,0x0b,0x0b], // instructions after function end
            vec![0x05,0x41,1,0x0b], // unmatched else
            vec![0x02,0x40,0x00,0x0b], // missing function end
            vec![0x41,0,0x04,0x7f,0x41,1,0x05,0x42,2,0x0b,0x0b], // wrong untaken arm type
        ] {
            assert!(WasmNumericVm::parse(&module(&[], &[0x7f], 0, &code, &[]), WasmNumericLimits::default()).is_err(), "{code:?}");
        }
    }

    #[test]
    fn branch_table_rejects_mismatched_label_types() {
        let bytes = module(&[], &[0x7f], 0,
            &[0x02,0x7f,0x02,0x7e,0x42,1,0x41,0,0x0e,1,0,1,0x0b,0x1a,0x41,1,0x0b,0x0b], &[]);
        assert!(WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).is_err());
    }

    #[test]
    fn loop_instruction_and_control_depth_limits_fail_closed() {
        let bytes = module(&[], &[], 0, &[0x03,0x40,0x0c,0,0x0b,0x0b], &[]);
        let limits = WasmNumericLimits { max_instructions: 17, ..WasmNumericLimits::default() };
        let vm = WasmNumericVm::parse(&bytes, limits).unwrap();
        assert_eq!(vm.call_export("f", &[]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 17 }));
        let limits = WasmNumericLimits { max_control_depth: 0, ..WasmNumericLimits::default() };
        assert!(matches!(WasmNumericVm::parse(&bytes, limits), Err(WasmNumericVmError::ControlDepthExceeded { max: 0 })));
    }

    #[test]
    fn signed_full_width_and_padded_block_immediates_decode() {
        assert_eq!(read_i32_leb(&[0x80,0x80,0x80,0x80,0x78]).unwrap(), (i32::MIN,5));
        assert_eq!(read_i64_leb(&[0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x7f]).unwrap(), (i64::MIN,10));
        let bytes = module(&[], &[], 0, &[0x02,0xc0,0xff,0xff,0xff,0x7f,0x0b,0x0b], &[]);
        assert!(run(&bytes, &[]).is_empty());
        assert!(read_signed_leb(&[0xff,0xff,0xff,0xff,0x1f],33,5).is_err());
    }
}
