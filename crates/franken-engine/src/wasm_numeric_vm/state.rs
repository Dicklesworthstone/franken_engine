//! Bounded, instance-owned WebAssembly linear memory.
//!
//! The compiled module is immutable. Instantiation validates every active data
//! segment before allocating or publishing state; calls on one instance share
//! writes, while independently instantiated modules never share memory. Failed
//! stores and growth do not partially mutate memory. Earlier completed guest
//! writes are deliberately retained when a later instruction traps.

use super::*;

const PAGE_BYTES: u64 = 65_536;
const MEMORY32_MAX_PAGES: u32 = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmStateError {
    LimitExceeded { resource: String, actual: u64, max: u64 },
    AllocationFailed { bytes: u64 },
    MemoryOutOfBounds { address: u64, width: u64, memory_bytes: u64 },
    DataSegmentOutOfBounds { segment: usize, offset: u32, length: usize, memory_bytes: u64 },
}

impl fmt::Display for WasmStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded { resource, actual, max } => write!(f, "wasm {resource} {actual} exceeds limit {max}"),
            Self::AllocationFailed { bytes } => write!(f, "cannot allocate {bytes} bytes of wasm memory"),
            Self::MemoryOutOfBounds { address, width, memory_bytes } => write!(f, "wasm memory access [{address}, +{width}) exceeds {memory_bytes} bytes"),
            Self::DataSegmentOutOfBounds { segment, offset, length, memory_bytes } => write!(f, "wasm data segment {segment} at {offset} with {length} bytes exceeds {memory_bytes}-byte memory"),
        }
    }
}

impl std::error::Error for WasmStateError {}

impl From<WasmStateError> for WasmNumericVmError {
    fn from(error: WasmStateError) -> Self { Self::State(error) }
}

fn invalid(detail: impl Into<String>) -> WasmNumericVmError {
    WasmNumericVmError::InvalidModule { detail: detail.into() }
}

#[derive(Debug, Clone)]
struct MemoryType { minimum: u32, maximum: u32 }

#[derive(Debug, Clone)]
struct DataSegment { offset: u32, bytes: Vec<u8> }

#[derive(Debug, Clone, Default)]
pub(super) struct ModuleState {
    memory: Option<MemoryType>,
    data: Vec<DataSegment>,
    exports: BTreeMap<String, u8>,
}

pub(super) struct StackEffect {
    /// Types consumed in pop order (value before address for stores).
    pub(super) pop: [Option<WasmValueType>; 2],
    pub(super) push: Option<WasmValueType>,
}

impl ModuleState {
    pub(super) fn parse_section(&mut self, id: u8, reader: &mut ByteReader<'_>, limits: &WasmNumericLimits) -> Result<(), WasmNumericVmError> {
        match id {
            5 => self.parse_memory(reader),
            11 => self.parse_data(reader, limits),
            _ => Err(WasmNumericVmError::UnsupportedSection { section_id: id }),
        }
    }

    fn parse_memory(&mut self, reader: &mut ByteReader<'_>) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()?;
        if count > 1 { return Err(invalid("only one unshared memory32 is supported")); }
        if count == 0 { return Ok(()); }
        let flags = reader.read_u8()?;
        if flags > 1 { return Err(invalid("shared, memory64 and extended memory limits are unsupported")); }
        let minimum = reader.read_u32_leb()?;
        let maximum = if flags == 1 { reader.read_u32_leb()? } else { MEMORY32_MAX_PAGES };
        if minimum > maximum || maximum > MEMORY32_MAX_PAGES {
            return Err(invalid("invalid memory32 limits"));
        }
        self.memory = Some(MemoryType { minimum, maximum });
        Ok(())
    }

    fn parse_data(&mut self, reader: &mut ByteReader<'_>, limits: &WasmNumericLimits) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()? as usize;
        if count > limits.max_state_entries {
            return Err(WasmStateError::LimitExceeded { resource: "data segment count".into(), actual: count as u64, max: limits.max_state_entries as u64 }.into());
        }
        for _ in 0..count {
            let mode = reader.read_u32_leb()?;
            match mode {
                0 => {},
                2 if reader.read_u32_leb()? == 0 => {},
                _ => return Err(invalid("only active data segments for memory zero are supported")),
            }
            if self.memory.is_none() { return Err(invalid("active data segment requires memory zero")); }
            if reader.read_u8()? != 0x41 { return Err(invalid("data offset must be an i32.const expression")); }
            let (offset, consumed) = read_i32_leb(reader.remaining())?;
            reader.offset += consumed;
            if reader.read_u8()? != 0x0b { return Err(invalid("data offset expression has trailing instructions")); }
            let length = reader.read_u32_leb()? as usize;
            // The module byte limit bounds payload storage. Never reserve from
            // a hostile declared length before checking the section boundary.
            let bytes = reader.read_bytes(length)?.to_vec();
            self.data.push(DataSegment { offset: offset as u32, bytes });
        }
        Ok(())
    }

    pub(super) fn export_kind(&self, name: &str) -> Option<u8> { self.exports.get(name).copied() }

    pub(super) fn parse_export(&mut self, name: String, kind: u8, index: u32) -> Result<(), WasmNumericVmError> {
        if kind != 2 { return Err(WasmNumericVmError::ExportIsNotFunction { name, kind }); }
        if index != 0 || self.memory.is_none() { return Err(invalid("memory export references missing memory")); }
        self.exports.insert(name, kind);
        Ok(())
    }

    pub(super) fn validate_instruction(&self, opcode: u8, reader: &mut CodeReader<'_>, function: u32) -> Result<StackEffect, WasmNumericVmError> {
        use WasmValueType::I32;
        let offset = reader.offset().saturating_sub(1);
        let Some((ty, width, store)) = memory_access(opcode) else {
            if matches!(opcode, 0x3f | 0x40) {
                if self.memory.is_none() { return Err(invalid("memory instruction requires memory zero")); }
                memory_index(reader, function)?;
                return Ok(StackEffect { pop: [if opcode == 0x40 { Some(I32) } else { None }, None], push: Some(I32) });
            }
            return Err(WasmNumericVmError::UnsupportedOpcode { function_index: function, opcode, offset });
        };
        if self.memory.is_none() { return Err(invalid("memory instruction requires memory zero")); }
        memarg(reader, function, width)?;
        Ok(StackEffect {
            pop: if store { [Some(ty), Some(I32)] } else { [Some(I32), None] },
            push: if store { None } else { Some(ty) },
        })
    }

    fn instantiate(&self, limits: &WasmNumericLimits) -> Result<InstanceState, WasmNumericVmError> {
        let memory = if let Some(ty) = &self.memory {
            let maximum = ty.maximum.min(limits.max_memory_pages);
            if ty.minimum > maximum {
                return Err(WasmStateError::LimitExceeded { resource: "initial memory pages".into(), actual: u64::from(ty.minimum), max: u64::from(maximum) }.into());
            }
            let bytes = u64::from(ty.minimum) * PAGE_BYTES;
            for (segment, data) in self.data.iter().enumerate() {
                if u64::from(data.offset).checked_add(data.bytes.len() as u64).is_none_or(|end| end > bytes) {
                    return Err(WasmStateError::DataSegmentOutOfBounds { segment, offset: data.offset, length: data.bytes.len(), memory_bytes: bytes }.into());
                }
            }
            let length = usize::try_from(bytes).map_err(|_| WasmStateError::AllocationFailed { bytes })?;
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(length).map_err(|_| WasmStateError::AllocationFailed { bytes })?;
            buffer.resize(length, 0);
            // Active segments apply in source order, so later overlaps win.
            for data in &self.data {
                let start = data.offset as usize;
                buffer[start..start + data.bytes.len()].copy_from_slice(&data.bytes);
            }
            Some(LinearMemory { bytes: buffer, maximum })
        } else { None };
        Ok(InstanceState { memory })
    }
}

#[derive(Debug)]
struct LinearMemory { bytes: Vec<u8>, maximum: u32 }

#[derive(Debug)]
pub(super) struct InstanceState { memory: Option<LinearMemory> }

/// A separately instantiated module. Repeated calls share only this instance's
/// memory; traps do not roll back writes by previously completed instructions.
#[derive(Debug)]
pub struct WasmNumericInstance<'a> { vm: &'a WasmNumericVm, state: InstanceState }

impl WasmNumericVm {
    pub fn instantiate(&self) -> Result<WasmNumericInstance<'_>, WasmNumericVmError> {
        Ok(WasmNumericInstance { vm: self, state: self.state.instantiate(&self.limits)? })
    }
}

impl WasmNumericInstance<'_> {
    pub fn call_export(&mut self, name: &str, arguments: &[WasmBoundaryValue]) -> Result<WasmNumericExecution, WasmNumericVmError> {
        self.vm.call_export_in_instance(name, arguments, &mut self.state)
    }

    /// Read only a declared memory export. No memory is exposed under an
    /// undeclared name, and inspection grants no imported host capabilities.
    pub fn memory_export(&self, name: &str) -> Option<&[u8]> {
        if self.vm.state.export_kind(name) != Some(2) { return None; }
        self.state.memory.as_ref().map(|memory| memory.bytes.as_slice())
    }
}

fn memory_index(reader: &mut CodeReader<'_>, function: u32) -> Result<(), WasmNumericVmError> {
    // The single-memory encoding requires the literal reserved zero byte.
    if reader.read_u8(function)? != 0 { return Err(invalid("memory index must be the reserved zero byte")); }
    Ok(())
}

fn memarg(reader: &mut CodeReader<'_>, function: u32, width: usize) -> Result<u32, WasmNumericVmError> {
    let alignment = reader.read_u32_leb(function)?;
    let offset = reader.read_u32_leb(function)?;
    if alignment > width.trailing_zeros() { return Err(invalid("memory alignment exceeds natural alignment")); }
    Ok(offset)
}

fn memory_access(opcode: u8) -> Option<(WasmValueType, usize, bool)> {
    use WasmValueType::{F32, F64, I32, I64};
    Some(match opcode {
        0x28 => (I32, 4, false), 0x29 => (I64, 8, false),
        0x2a => (F32, 4, false), 0x2b => (F64, 8, false),
        0x2c | 0x2d => (I32, 1, false), 0x2e | 0x2f => (I32, 2, false),
        0x30 | 0x31 => (I64, 1, false), 0x32 | 0x33 => (I64, 2, false),
        0x34 | 0x35 => (I64, 4, false),
        0x36 => (I32, 4, true), 0x37 => (I64, 8, true),
        0x38 => (F32, 4, true), 0x39 => (F64, 8, true),
        0x3a => (I32, 1, true), 0x3b => (I32, 2, true),
        0x3c => (I64, 1, true), 0x3d => (I64, 2, true), 0x3e => (I64, 4, true),
        _ => return None,
    })
}

impl LinearMemory {
    fn pages(&self) -> u32 { (self.bytes.len() as u64 / PAGE_BYTES) as u32 }

    fn range(&self, address: u32, offset: u32, width: usize) -> Result<std::ops::Range<usize>, WasmNumericVmError> {
        // The effective address is a 33-bit sum, NOT a wrapping i32 addition.
        let start = u64::from(address) + u64::from(offset);
        let end = start + width as u64;
        if end > self.bytes.len() as u64 {
            return Err(WasmStateError::MemoryOutOfBounds { address: start, width: width as u64, memory_bytes: self.bytes.len() as u64 }.into());
        }
        Ok(start as usize..end as usize)
    }

    fn grow(&mut self, pages: u32, meter: &mut ExecutionMeter<'_>) -> Result<i32, WasmNumericVmError> {
        let old = self.pages();
        let Some(new) = old.checked_add(pages).filter(|new| *new <= self.maximum) else { return Ok(-1); };
        let Some(length) = u64::from(new).checked_mul(PAGE_BYTES).and_then(|n| usize::try_from(n).ok()) else { return Ok(-1); };
        let additional = length - self.bytes.len();
        // Charge zero-initialization work before allocating or changing size.
        // Budget refusal is an embedding fault, not guest-catchable grow -1.
        meter.charge_work((additional as u64).div_ceil(64))?;
        if self.bytes.try_reserve_exact(additional).is_err() { return Ok(-1); }
        self.bytes.resize(length, 0);
        Ok(old as i32)
    }
}

impl InstanceState {
    pub(super) fn execute(&mut self, opcode: u8, reader: &mut CodeReader<'_>, stack: &mut Vec<WasmBoundaryValue>, meter: &mut ExecutionMeter<'_>, function: u32) -> Result<(), WasmNumericVmError> {
        let memory = self.memory.as_mut().ok_or_else(|| invalid("missing validated memory"))?;
        if matches!(opcode, 0x3f | 0x40) {
            memory_index(reader, function)?;
            let result = if opcode == 0x3f { memory.pages() as i32 } else {
                let pages = expect_i32(pop_value(stack, function, opcode)?, function, 0)? as u32;
                memory.grow(pages, meter)?
            };
            return push_value(stack, WasmBoundaryValue::I32(result), meter);
        }
        let (ty, width, store) = memory_access(opcode).ok_or_else(|| invalid("unknown validated state instruction"))?;
        let offset = memarg(reader, function, width)?;
        if store {
            let value = pop_value(stack, function, opcode)?;
            ensure_same_type(function, 1, ty, value.value_type())?;
            let address = expect_i32(pop_value(stack, function, opcode)?, function, 0)? as u32;
            let range = memory.range(address, offset, width)?;
            let bits = match value {
                WasmBoundaryValue::I32(n) => u64::from(n as u32),
                WasmBoundaryValue::I64(n) => n as u64,
                WasmBoundaryValue::F32Bits(n) => u64::from(n),
                WasmBoundaryValue::F64Bits(n) => n,
            };
            // The entire range is checked before the first byte changes.
            memory.bytes[range].copy_from_slice(&bits.to_le_bytes()[..width]);
        } else {
            let address = expect_i32(pop_value(stack, function, opcode)?, function, 0)? as u32;
            let range = memory.range(address, offset, width)?;
            let mut bytes = [0_u8; 8];
            bytes[..width].copy_from_slice(&memory.bytes[range]);
            let unsigned = u64::from_le_bytes(bytes);
            let signed = match opcode {
                0x2c | 0x30 => (unsigned as i8) as i64,
                0x2e | 0x32 => (unsigned as i16) as i64,
                0x34 => (unsigned as i32) as i64,
                _ => unsigned as i64,
            };
            let value = match ty {
                WasmValueType::I32 => WasmBoundaryValue::I32(signed as i32),
                WasmValueType::I64 => WasmBoundaryValue::I64(signed),
                WasmValueType::F32 => WasmBoundaryValue::F32Bits(unsigned as u32),
                WasmValueType::F64 => WasmBoundaryValue::F64Bits(unsigned),
            };
            push_value(stack, value, meter)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(mut n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = (n & 127) as u8;
            n >>= 7;
            bytes.push(byte | if n == 0 { 0 } else { 128 });
            if n == 0 { return bytes; }
        }
    }

    fn signed(mut n: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = (n & 127) as u8;
            n >>= 7;
            let done = (n == 0 && byte & 64 == 0) || (n == -1 && byte & 64 != 0);
            bytes.push(byte | if done { 0 } else { 128 });
            if done { return bytes; }
        }
    }

    fn section(module: &mut Vec<u8>, id: u8, bytes: &[u8]) {
        module.push(id);
        module.extend(leb(bytes.len()));
        module.extend(bytes);
    }

    fn data(segments: &[(i32, &[u8])]) -> Vec<u8> {
        let mut bytes = leb(segments.len());
        for (index, (offset, contents)) in segments.iter().enumerate() {
            // Exercise both active-segment encodings, including explicit zero.
            if index % 2 == 0 { bytes.push(0); } else { bytes.extend([2, 0]); }
            bytes.push(0x41);
            bytes.extend(signed(*offset));
            bytes.push(0x0b);
            bytes.extend(leb(contents.len()));
            bytes.extend(*contents);
        }
        bytes
    }

    fn module(params: &[u8], results: &[u8], code: &[u8], memory: Option<&[u8]>, data: Option<&[u8]>) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        let mut types = vec![1, 0x60];
        types.extend(leb(params.len()));
        types.extend(params);
        types.extend(leb(results.len()));
        types.extend(results);
        section(&mut bytes, 1, &types);
        section(&mut bytes, 3, &[1, 0]);
        if let Some(memory) = memory { section(&mut bytes, 5, memory); }
        let exports = if memory.is_some() {
            vec![2, 1, b'f', 0, 0, 1, b'm', 2, 0]
        } else { vec![1, 1, b'f', 0, 0] };
        section(&mut bytes, 7, &exports);
        let mut bodies = vec![1];
        bodies.extend(leb(code.len() + 1));
        bodies.push(0); // no additional locals
        bodies.extend(code);
        section(&mut bytes, 10, &bodies);
        if let Some(data) = data { section(&mut bytes, 11, data); }
        bytes
    }

    fn parse(bytes: &[u8]) -> WasmNumericVm {
        WasmNumericVm::parse(bytes, WasmNumericLimits::default()).unwrap()
    }

    #[test]
    fn every_load_width_and_signedness_executes() {
        use WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};
        for (opcode, result_type, expected) in [
            (0x28, 0x7f, I32(-1)), (0x29, 0x7e, I64(-1)),
            (0x2a, 0x7d, F32Bits(u32::MAX)), (0x2b, 0x7c, F64Bits(u64::MAX)),
            (0x2c, 0x7f, I32(-1)), (0x2d, 0x7f, I32(255)),
            (0x2e, 0x7f, I32(-1)), (0x2f, 0x7f, I32(65_535)),
            (0x30, 0x7e, I64(-1)), (0x31, 0x7e, I64(255)),
            (0x32, 0x7e, I64(-1)), (0x33, 0x7e, I64(65_535)),
            (0x34, 0x7e, I64(-1)), (0x35, 0x7e, I64(4_294_967_295)),
        ] {
            let bytes = module(&[0x7f], &[result_type], &[0x20, 0, opcode, 0, 1, 0x0b], Some(&[1, 1, 1, 2]), Some(&data(&[(1, &[255; 8])])));
            let vm = parse(&bytes);
            let result = vm.call_export("f", &[I32(0)]).unwrap();
            assert_eq!(result.results, [expected], "opcode {opcode:#x}");
        }
    }

    #[test]
    fn every_store_width_preserves_exact_bits_and_adjacent_bytes() {
        use WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};
        for (opcode, parameter_type, value, width, bits) in [
            (0x36, 0x7f, I32(0x1234_5678), 4, 0x1234_5678_u64),
            (0x37, 0x7e, I64(0x0123_4567_89ab_cdef), 8, 0x0123_4567_89ab_cdef),
            (0x38, 0x7d, F32Bits(0x7fa1_2345), 4, 0x7fa1_2345),
            (0x39, 0x7c, F64Bits(0x7ff0_0000_0000_0042), 8, 0x7ff0_0000_0000_0042),
            (0x3a, 0x7f, I32(0x1234_5678), 1, 0x1234_5678),
            (0x3b, 0x7f, I32(0x1234_5678), 2, 0x1234_5678),
            (0x3c, 0x7e, I64(0x0123_4567_89ab_cdef), 1, 0x0123_4567_89ab_cdef),
            (0x3d, 0x7e, I64(0x0123_4567_89ab_cdef), 2, 0x0123_4567_89ab_cdef),
            (0x3e, 0x7e, I64(0x0123_4567_89ab_cdef), 4, 0x0123_4567_89ab_cdef),
        ] {
            let bytes = module(&[0x7f, parameter_type], &[], &[0x20, 0, 0x20, 1, opcode, 0, 1, 0x0b], Some(&[1, 1, 1, 2]), Some(&data(&[(0, &[0xaa; 16])])));
            let vm = parse(&bytes);
            let mut instance = vm.instantiate().unwrap();
            assert!(instance.call_export("f", &[I32(0), value]).unwrap().results.is_empty());
            let memory = instance.memory_export("m").unwrap();
            assert_eq!(&memory[1..1 + width], &bits.to_le_bytes()[..width], "opcode {opcode:#x}");
            assert_eq!(memory[0], 0xaa);
            assert_eq!(memory[1 + width], 0xaa);
            assert!(instance.memory_export("undeclared").is_none());
        }
    }

    #[test]
    fn calls_share_instance_memory_but_instances_are_isolated() {
        let bytes = module(&[0x7f], &[0x7f], &[
            0x41, 0, 0x41, 0, 0x28, 2, 0, 0x20, 0, 0x6a, 0x36, 2, 0,
            0x41, 0, 0x28, 2, 0, 0x0b,
        ], Some(&[1, 1, 1, 2]), None);
        let vm = parse(&bytes);
        let mut a = vm.instantiate().unwrap();
        let mut b = vm.instantiate().unwrap();
        assert_eq!(a.call_export("f", &[WasmBoundaryValue::I32(1)]).unwrap().results, [WasmBoundaryValue::I32(1)]);
        assert_eq!(a.call_export("f", &[WasmBoundaryValue::I32(2)]).unwrap().results, [WasmBoundaryValue::I32(3)]);
        assert_eq!(b.call_export("f", &[WasmBoundaryValue::I32(2)]).unwrap().results, [WasmBoundaryValue::I32(2)]);
        assert_eq!(vm.call_export("f", &[WasmBoundaryValue::I32(1)]).unwrap(), vm.call_export("f", &[WasmBoundaryValue::I32(1)]).unwrap());
        assert!(matches!(a.call_export("m", &[]), Err(WasmNumericVmError::ExportIsNotFunction { kind: 2, .. })));
    }

    #[test]
    fn data_segments_initialize_in_order_and_allow_empty_end_boundary() {
        let bytes = module(&[], &[], &[0x0b], Some(&[1, 0, 1]), Some(&data(&[(0, b"abcd"), (1, b"XY"), (65_536, b"")])));
        let vm = parse(&bytes);
        let instance = vm.instantiate().unwrap();
        let memory = instance.memory_export("m").unwrap();
        assert_eq!(&memory[..5], b"aXYd\0");
        assert_eq!(memory.len(), 65_536);
        assert!(memory[4..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn invalid_data_bounds_fail_at_instantiation_not_validation() {
        for (offset, contents) in [(65_535, b"XY".as_slice()), (65_537, b"".as_slice()), (-1, b"".as_slice())] {
            let bytes = module(&[], &[], &[0x0b], Some(&[1, 0, 1]), Some(&data(&[(offset, contents)])));
            let vm = parse(&bytes);
            assert!(matches!(vm.instantiate(), Err(WasmNumericVmError::State(WasmStateError::DataSegmentOutOfBounds { .. }))));
        }
    }

    #[test]
    fn failed_store_is_atomic_and_effective_addresses_do_not_wrap() {
        for (address, offset) in [(65_534, 0), (-1, 1), (1, u32::MAX)] {
            let mut code = vec![0x20, 0, 0x41, 9, 0x36, 0];
            code.extend(leb(offset as usize));
            code.push(0x0b);
            let bytes = module(&[0x7f], &[], &code, Some(&[1, 0, 1]), Some(&data(&[(0, b"sentinel")])));
            let vm = parse(&bytes);
            let mut instance = vm.instantiate().unwrap();
            let before = instance.memory_export("m").unwrap().to_vec();
            assert!(matches!(instance.call_export("f", &[WasmBoundaryValue::I32(address)]), Err(WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. }))));
            assert_eq!(instance.memory_export("m").unwrap(), before);
        }
    }

    #[test]
    fn later_trap_does_not_roll_back_completed_guest_stores() {
        let bytes = module(&[0x7f], &[], &[0x41, 0, 0x41, 7, 0x36, 2, 0, 0x20, 0, 0x41, 9, 0x36, 2, 0, 0x0b], Some(&[1, 0, 1]), None);
        let vm = parse(&bytes);
        let mut instance = vm.instantiate().unwrap();
        assert!(instance.call_export("f", &[WasmBoundaryValue::I32(65_535)]).is_err());
        assert_eq!(&instance.memory_export("m").unwrap()[..4], &7_i32.to_le_bytes());
    }

    #[test]
    fn growth_preserves_prefix_zeroes_tail_and_refuses_without_mutation() {
        let bytes = module(&[0x7f], &[0x7f], &[0x20, 0, 0x40, 0, 0x0b], Some(&[1, 1, 1, 2]), Some(&data(&[(0, b"keep")])));
        let vm = parse(&bytes);
        let mut instance = vm.instantiate().unwrap();
        for (delta, expected, length) in [(1, 1, 131_072), (1, -1, 131_072), (-1, -1, 131_072), (0, 2, 131_072)] {
            assert_eq!(instance.call_export("f", &[WasmBoundaryValue::I32(delta)]).unwrap().results, [WasmBoundaryValue::I32(expected)]);
            let memory = instance.memory_export("m").unwrap();
            assert_eq!(memory.len(), length);
            assert_eq!(&memory[..4], b"keep");
            assert!(memory[4..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn memory_size_and_zero_initial_memory_are_supported() {
        let bytes = module(&[], &[0x7f], &[0x3f, 0, 0x0b], Some(&[1, 0, 0]), None);
        let vm = parse(&bytes);
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(instance.call_export("f", &[]).unwrap().results, [WasmBoundaryValue::I32(0)]);
        assert_eq!(instance.memory_export("m"), Some([].as_slice()));
    }

    #[test]
    fn embedding_memory_and_work_limits_are_enforced_before_mutation() {
        let bytes = module(&[0x7f], &[0x7f], &[0x20, 0, 0x40, 0, 0x0b], Some(&[1, 1, 1, 2]), None);
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits { max_memory_pages: 1, ..WasmNumericLimits::default() }).unwrap();
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(instance.call_export("f", &[WasmBoundaryValue::I32(1)]).unwrap().results, [WasmBoundaryValue::I32(-1)]);
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits { max_memory_pages: 0, ..WasmNumericLimits::default() }).unwrap();
        assert!(matches!(vm.instantiate(), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { .. }))));
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits { max_instructions: 3, ..WasmNumericLimits::default() }).unwrap();
        let mut instance = vm.instantiate().unwrap();
        assert!(matches!(instance.call_export("f", &[WasmBoundaryValue::I32(1)]), Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
        assert_eq!(instance.memory_export("m").unwrap().len(), 65_536);
    }

    #[test]
    fn malformed_memory_immediates_are_rejected_even_in_dead_code() {
        for code in [
            vec![0x00, 0x28, 3, 0, 0x0b], // excessive i32 alignment
            vec![0x00, 0x3f, 1, 0x0b], // unsupported memory index
            vec![0x00, 0x3f, 0x80, 0, 0x0b], // reserved byte is not padded LEB
            vec![0x00, 0x28, 0, 0x80, 0x80, 0x80, 0x80, 0x10, 0x0b], // offset overflow
            vec![0x41, 0, 0x42, 1, 0x36, 2, 0, 0x0b], // i64 supplied to i32.store
        ] {
            assert!(WasmNumericVm::parse(&module(&[], &[], &code, Some(&[1, 0, 1]), None), WasmNumericLimits::default()).is_err(), "{code:?}");
        }
        assert!(WasmNumericVm::parse(&module(&[], &[0x7f], &[0x3f, 0, 0x0b], None, None), WasmNumericLimits::default()).is_err());
    }

    #[test]
    fn invalid_memory_declarations_and_unsupported_state_fail_closed() {
        for memory in [vec![2], vec![1, 2, 0, 1], vec![1, 4, 0], vec![1, 1, 2, 1], vec![1, 0, 0x81, 0x80, 4]] {
            assert!(WasmNumericVm::parse(&module(&[], &[], &[0x0b], Some(&memory), None), WasmNumericLimits::default()).is_err(), "{memory:?}");
        }
        let bytes = module(&[], &[], &[0x0b], Some(&[1, 0, 1]), Some(&data(&[(0, b"x")])));
        assert!(matches!(WasmNumericVm::parse(&bytes, WasmNumericLimits { max_state_entries: 0, ..WasmNumericLimits::default() }), Err(WasmNumericVmError::State(WasmStateError::LimitExceeded { .. }))));
        let passive = module(&[], &[], &[0x0b], Some(&[1, 0, 1]), Some(&[1, 1, 1, 42]));
        assert!(WasmNumericVm::parse(&passive, WasmNumericLimits::default()).is_err());
    }
}
