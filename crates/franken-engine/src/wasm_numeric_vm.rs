#![forbid(unsafe_code)]

//! Deterministic bounded execution for straight-line numeric WebAssembly.
//!
//! This is deliberately not a general WASM VM. It executes a useful native
//! subset that closes the gap between the existing binary parser's
//! constant-return support and real parameterized functions while keeping every
//! unsupported semantic fail-closed. Supported operations include numeric
//! constants, locals, direct local-function calls, drop/select, integer and
//! floating arithmetic, comparisons, and a small conversion set. Structured
//! control flow, memory, globals, tables, indirect calls, SIMD, atomics, and
//! imported-function execution are rejected.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::wasm_runtime_lane::{WasmBoundaryValue, WasmValueType};

pub const WASM_NUMERIC_VM_COMPONENT: &str = "wasm_numeric_vm";
pub const WASM_NUMERIC_VM_SCHEMA_VERSION: &str = "franken-engine.wasm-numeric-vm.v1";

const CANONICAL_F32_NAN: u32 = 0x7fc0_0000;
const CANONICAL_F64_NAN: u64 = 0x7ff8_0000_0000_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmNumericLimits {
    pub max_module_bytes: usize,
    pub max_functions: usize,
    pub max_locals_per_call: usize,
    pub max_stack_values: usize,
    pub max_call_depth: u32,
    pub max_instructions: u64,
}

impl Default for WasmNumericLimits {
    fn default() -> Self {
        Self {
            max_module_bytes: 16 * 1024 * 1024,
            max_functions: 65_536,
            max_locals_per_call: 65_536,
            max_stack_values: 65_536,
            max_call_depth: 256,
            max_instructions: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmNumericExecution {
    pub results: Vec<WasmBoundaryValue>,
    pub instructions_executed: u64,
    pub peak_stack_values: usize,
    pub max_call_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmNumericVmError {
    ModuleTooLarge { actual: usize, max: usize },
    InvalidModule { detail: String },
    UnsupportedSection { section_id: u8 },
    UnsupportedImportKind { kind: u8 },
    UnsupportedValueType { byte: u8 },
    UnknownExport { name: String },
    ExportIsNotFunction { name: String, kind: u8 },
    DuplicateExport { name: String },
    FunctionLimitExceeded { actual: usize, max: usize },
    LocalLimitExceeded { actual: usize, max: usize },
    StackLimitExceeded { max: usize },
    CallDepthExceeded { max: u32 },
    InstructionBudgetExceeded { max: u64 },
    ArityMismatch { function_index: u32, expected: usize, actual: usize },
    TypeMismatch {
        function_index: u32,
        value_index: usize,
        expected: WasmValueType,
        actual: WasmValueType,
    },
    UnknownFunction { function_index: u32 },
    ImportedFunctionUnsupported { function_index: u32, module: String, name: String },
    UnsupportedOpcode { function_index: u32, opcode: u8, offset: usize },
    InvalidLocal { function_index: u32, local_index: u32 },
    StackUnderflow { function_index: u32, opcode: u8 },
    ResultStackMismatch { function_index: u32, expected: usize, actual: usize },
    IntegerDivideByZero { function_index: u32 },
    IntegerOverflow { function_index: u32 },
}

impl fmt::Display for WasmNumericVmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleTooLarge { actual, max } => {
                write!(f, "wasm module has {actual} bytes; limit is {max}")
            }
            Self::InvalidModule { detail } => write!(f, "invalid wasm module: {detail}"),
            Self::UnsupportedSection { section_id } => {
                write!(f, "unsupported wasm section {section_id}")
            }
            Self::UnsupportedImportKind { kind } => {
                write!(f, "unsupported wasm import kind 0x{kind:02x}")
            }
            Self::UnsupportedValueType { byte } => {
                write!(f, "unsupported wasm value type 0x{byte:02x}")
            }
            Self::UnknownExport { name } => write!(f, "unknown wasm export '{name}'"),
            Self::ExportIsNotFunction { name, kind } => {
                write!(f, "wasm export '{name}' has unsupported kind 0x{kind:02x}")
            }
            Self::DuplicateExport { name } => write!(f, "duplicate wasm export '{name}'"),
            Self::FunctionLimitExceeded { actual, max } => {
                write!(f, "wasm function count {actual} exceeds limit {max}")
            }
            Self::LocalLimitExceeded { actual, max } => {
                write!(f, "wasm local count {actual} exceeds limit {max}")
            }
            Self::StackLimitExceeded { max } => write!(f, "wasm value stack exceeds limit {max}"),
            Self::CallDepthExceeded { max } => write!(f, "wasm call depth exceeds limit {max}"),
            Self::InstructionBudgetExceeded { max } => {
                write!(f, "wasm instruction budget {max} exhausted")
            }
            Self::ArityMismatch {
                function_index,
                expected,
                actual,
            } => write!(
                f,
                "wasm function {function_index} expects {expected} argument(s), got {actual}"
            ),
            Self::TypeMismatch {
                function_index,
                value_index,
                expected,
                actual,
            } => write!(
                f,
                "wasm function {function_index} value {value_index} expects {expected}, got {actual}"
            ),
            Self::UnknownFunction { function_index } => {
                write!(f, "unknown wasm function index {function_index}")
            }
            Self::ImportedFunctionUnsupported {
                function_index,
                module,
                name,
            } => write!(
                f,
                "imported wasm function {function_index} ({module}.{name}) has no authorized host binding"
            ),
            Self::UnsupportedOpcode {
                function_index,
                opcode,
                offset,
            } => write!(
                f,
                "wasm function {function_index} uses unsupported opcode 0x{opcode:02x} at body offset {offset}"
            ),
            Self::InvalidLocal {
                function_index,
                local_index,
            } => write!(
                f,
                "wasm function {function_index} references missing local {local_index}"
            ),
            Self::StackUnderflow {
                function_index,
                opcode,
            } => write!(
                f,
                "wasm function {function_index} stack underflow at opcode 0x{opcode:02x}"
            ),
            Self::ResultStackMismatch {
                function_index,
                expected,
                actual,
            } => write!(
                f,
                "wasm function {function_index} expected {expected} result value(s), stack has {actual}"
            ),
            Self::IntegerDivideByZero { function_index } => {
                write!(f, "wasm function {function_index} trapped on integer divide by zero")
            }
            Self::IntegerOverflow { function_index } => {
                write!(f, "wasm function {function_index} trapped on integer division overflow")
            }
        }
    }
}

impl std::error::Error for WasmNumericVmError {}

#[derive(Debug, Clone)]
struct FunctionType {
    params: Vec<WasmValueType>,
    results: Vec<WasmValueType>,
}

#[derive(Debug, Clone)]
struct FunctionImport {
    module: String,
    name: String,
    type_index: u32,
}

#[derive(Debug, Clone)]
struct FunctionBody {
    type_index: u32,
    locals: Vec<WasmValueType>,
    code: Vec<u8>,
}

#[derive(Debug, Clone)]
struct FunctionExport {
    function_index: u32,
}

#[derive(Debug, Clone)]
pub struct WasmNumericVm {
    types: Vec<FunctionType>,
    imports: Vec<FunctionImport>,
    functions: Vec<FunctionBody>,
    exports: BTreeMap<String, FunctionExport>,
    limits: WasmNumericLimits,
}

impl WasmNumericVm {
    pub fn parse(bytes: &[u8], limits: WasmNumericLimits) -> Result<Self, WasmNumericVmError> {
        if bytes.len() > limits.max_module_bytes {
            return Err(WasmNumericVmError::ModuleTooLarge {
                actual: bytes.len(),
                max: limits.max_module_bytes,
            });
        }
        let mut parser = ModuleParser::new(bytes, limits.clone());
        parser.parse()?;
        Ok(Self {
            types: parser.types,
            imports: parser.imports,
            functions: parser.functions,
            exports: parser.exports,
            limits,
        })
    }

    pub fn call_export(
        &self,
        name: &str,
        arguments: &[WasmBoundaryValue],
    ) -> Result<WasmNumericExecution, WasmNumericVmError> {
        let export = self
            .exports
            .get(name)
            .ok_or_else(|| WasmNumericVmError::UnknownExport {
                name: name.to_string(),
            })?;
        let mut meter = ExecutionMeter::new(&self.limits);
        let results = self.invoke(export.function_index, arguments, 1, &mut meter)?;
        Ok(WasmNumericExecution {
            results,
            instructions_executed: meter.instructions,
            peak_stack_values: meter.peak_stack_values,
            max_call_depth: meter.max_call_depth,
        })
    }

    pub fn export_names(&self) -> impl Iterator<Item = &str> {
        self.exports.keys().map(String::as_str)
    }

    fn invoke(
        &self,
        function_index: u32,
        arguments: &[WasmBoundaryValue],
        depth: u32,
        meter: &mut ExecutionMeter<'_>,
    ) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> {
        meter.enter_call(depth)?;
        if function_index < self.imports.len() as u32 {
            let import = &self.imports[function_index as usize];
            return Err(WasmNumericVmError::ImportedFunctionUnsupported {
                function_index,
                module: import.module.clone(),
                name: import.name.clone(),
            });
        }
        let local_index = function_index
            .checked_sub(self.imports.len() as u32)
            .ok_or(WasmNumericVmError::UnknownFunction { function_index })?
            as usize;
        let body = self
            .functions
            .get(local_index)
            .ok_or(WasmNumericVmError::UnknownFunction { function_index })?;
        let signature = self.function_type(body.type_index)?;
        validate_arguments(function_index, signature, arguments)?;

        let local_count = arguments.len().saturating_add(body.locals.len());
        if local_count > self.limits.max_locals_per_call {
            return Err(WasmNumericVmError::LocalLimitExceeded {
                actual: local_count,
                max: self.limits.max_locals_per_call,
            });
        }
        let mut locals = Vec::with_capacity(local_count);
        locals.extend_from_slice(arguments);
        locals.extend(body.locals.iter().copied().map(zero_value));

        let mut stack = Vec::<WasmBoundaryValue>::new();
        let mut reader = CodeReader::new(&body.code);
        let mut returned = false;
        while !reader.finished() {
            let opcode_offset = reader.offset();
            let opcode = reader.read_u8(function_index)?;
            meter.tick()?;
            match opcode {
                0x0b => break,
                0x0f => {
                    returned = true;
                    break;
                }
                0x1a => {
                    pop_value(&mut stack, function_index, opcode)?;
                }
                0x1b => execute_select(&mut stack, function_index, opcode)?,
                0x20 => {
                    let index = reader.read_u32_leb(function_index)?;
                    let value = locals.get(index as usize).cloned().ok_or(
                        WasmNumericVmError::InvalidLocal {
                            function_index,
                            local_index: index,
                        },
                    )?;
                    push_value(&mut stack, value, meter)?;
                }
                0x21 => {
                    let index = reader.read_u32_leb(function_index)?;
                    let value = pop_value(&mut stack, function_index, opcode)?;
                    let slot = locals.get_mut(index as usize).ok_or(
                        WasmNumericVmError::InvalidLocal {
                            function_index,
                            local_index: index,
                        },
                    )?;
                    ensure_same_type(function_index, index as usize, slot.value_type(), value.value_type())?;
                    *slot = value;
                }
                0x22 => {
                    let index = reader.read_u32_leb(function_index)?;
                    let value = stack.last().cloned().ok_or(WasmNumericVmError::StackUnderflow {
                        function_index,
                        opcode,
                    })?;
                    let slot = locals.get_mut(index as usize).ok_or(
                        WasmNumericVmError::InvalidLocal {
                            function_index,
                            local_index: index,
                        },
                    )?;
                    ensure_same_type(function_index, index as usize, slot.value_type(), value.value_type())?;
                    *slot = value;
                }
                0x10 => {
                    let callee = reader.read_u32_leb(function_index)?;
                    let callee_type = self.function_signature(callee)?;
                    let mut call_args = Vec::with_capacity(callee_type.params.len());
                    for _ in 0..callee_type.params.len() {
                        call_args.push(pop_value(&mut stack, function_index, opcode)?);
                    }
                    call_args.reverse();
                    validate_arguments(callee, callee_type, &call_args)?;
                    let results = self.invoke(callee, &call_args, depth.saturating_add(1), meter)?;
                    for value in results {
                        push_value(&mut stack, value, meter)?;
                    }
                }
                0x41 => push_value(
                    &mut stack,
                    WasmBoundaryValue::I32(reader.read_i32_leb(function_index)?),
                    meter,
                )?,
                0x42 => push_value(
                    &mut stack,
                    WasmBoundaryValue::I64(reader.read_i64_leb(function_index)?),
                    meter,
                )?,
                0x43 => push_value(
                    &mut stack,
                    WasmBoundaryValue::F32Bits(reader.read_u32_le(function_index)?),
                    meter,
                )?,
                0x44 => push_value(
                    &mut stack,
                    WasmBoundaryValue::F64Bits(reader.read_u64_le(function_index)?),
                    meter,
                )?,
                0x45..=0x5a => execute_integer_comparison(opcode, &mut stack, function_index)?,
                0x5b..=0x66 => execute_float_comparison(opcode, &mut stack, function_index)?,
                0x6a..=0x78 => execute_i32_numeric(opcode, &mut stack, function_index)?,
                0x7c..=0x8a => execute_i64_numeric(opcode, &mut stack, function_index)?,
                0x8b..=0x98 => execute_f32_numeric(opcode, &mut stack, function_index)?,
                0x99..=0xa6 => execute_f64_numeric(opcode, &mut stack, function_index)?,
                0xa7 => {
                    let value = expect_i64(pop_value(&mut stack, function_index, opcode)?, function_index, 0)?;
                    push_value(&mut stack, WasmBoundaryValue::I32(value as i32), meter)?;
                }
                0xac => {
                    let value = expect_i32(pop_value(&mut stack, function_index, opcode)?, function_index, 0)?;
                    push_value(&mut stack, WasmBoundaryValue::I64(i64::from(value)), meter)?;
                }
                0xad => {
                    let value = expect_i32(pop_value(&mut stack, function_index, opcode)?, function_index, 0)?;
                    push_value(&mut stack, WasmBoundaryValue::I64(u32::from_ne_bytes(value.to_ne_bytes()) as i64), meter)?;
                }
                _ => {
                    return Err(WasmNumericVmError::UnsupportedOpcode {
                        function_index,
                        opcode,
                        offset: opcode_offset,
                    });
                }
            }
        }

        if !returned && !reader.finished() {
            return Err(WasmNumericVmError::InvalidModule {
                detail: format!("function {function_index} did not terminate with end"),
            });
        }
        if stack.len() != signature.results.len() {
            return Err(WasmNumericVmError::ResultStackMismatch {
                function_index,
                expected: signature.results.len(),
                actual: stack.len(),
            });
        }
        for (index, (expected, actual)) in signature
            .results
            .iter()
            .zip(stack.iter().map(WasmBoundaryValue::value_type))
            .enumerate()
        {
            ensure_same_type(function_index, index, *expected, actual)?;
        }
        Ok(stack)
    }

    fn function_type(&self, type_index: u32) -> Result<&FunctionType, WasmNumericVmError> {
        self.types
            .get(type_index as usize)
            .ok_or_else(|| WasmNumericVmError::InvalidModule {
                detail: format!("type index {type_index} is out of bounds"),
            })
    }

    fn function_signature(&self, function_index: u32) -> Result<&FunctionType, WasmNumericVmError> {
        if function_index < self.imports.len() as u32 {
            return self.function_type(self.imports[function_index as usize].type_index);
        }
        let local_index = function_index
            .checked_sub(self.imports.len() as u32)
            .ok_or(WasmNumericVmError::UnknownFunction { function_index })?
            as usize;
        let body = self
            .functions
            .get(local_index)
            .ok_or(WasmNumericVmError::UnknownFunction { function_index })?;
        self.function_type(body.type_index)
    }
}

struct ModuleParser<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: WasmNumericLimits,
    types: Vec<FunctionType>,
    imports: Vec<FunctionImport>,
    function_type_indices: Vec<u32>,
    functions: Vec<FunctionBody>,
    exports: BTreeMap<String, FunctionExport>,
    last_non_custom_section: u8,
}

impl<'a> ModuleParser<'a> {
    fn new(bytes: &'a [u8], limits: WasmNumericLimits) -> Self {
        Self {
            bytes,
            offset: 0,
            limits,
            types: Vec::new(),
            imports: Vec::new(),
            function_type_indices: Vec::new(),
            functions: Vec::new(),
            exports: BTreeMap::new(),
            last_non_custom_section: 0,
        }
    }

    fn parse(&mut self) -> Result<(), WasmNumericVmError> {
        if self.read_bytes(4)? != [0x00, 0x61, 0x73, 0x6d] {
            return self.invalid("missing wasm magic");
        }
        if self.read_bytes(4)? != [0x01, 0x00, 0x00, 0x00] {
            return self.invalid("unsupported wasm version");
        }
        while self.offset < self.bytes.len() {
            let section_id = self.read_u8()?;
            let section_len = self.read_u32_leb()? as usize;
            let section = self.read_bytes(section_len)?;
            if section_id != 0 {
                if section_id <= self.last_non_custom_section {
                    return self.invalid(format!(
                        "wasm section {section_id} is duplicated or out of order"
                    ));
                }
                self.last_non_custom_section = section_id;
            }
            let mut reader = ByteReader::new(section);
            match section_id {
                0 => {}
                1 => self.parse_types(&mut reader)?,
                2 => self.parse_imports(&mut reader)?,
                3 => self.parse_functions(&mut reader)?,
                4 | 5 | 6 => {
                    // Tables, memories, and globals are allowed to exist but no
                    // instruction that can access them is executable in this VM.
                    continue;
                }
                7 => self.parse_exports(&mut reader)?,
                8 | 9 => return Err(WasmNumericVmError::UnsupportedSection { section_id }),
                10 => self.parse_code(&mut reader)?,
                11 | 12 => {
                    // Data/count sections are inert because memory opcodes are
                    // unsupported. They remain part of the validated envelope.
                    continue;
                }
                _ => return Err(WasmNumericVmError::UnsupportedSection { section_id }),
            }
            reader.ensure_finished()?;
        }
        if self.functions.len() != self.function_type_indices.len() {
            return self.invalid(format!(
                "function section declares {} local function(s), code section provides {}",
                self.function_type_indices.len(),
                self.functions.len()
            ));
        }
        let total = self.imports.len().saturating_add(self.functions.len());
        if total > self.limits.max_functions {
            return Err(WasmNumericVmError::FunctionLimitExceeded {
                actual: total,
                max: self.limits.max_functions,
            });
        }
        Ok(())
    }

    fn parse_types(&mut self, reader: &mut ByteReader<'_>) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()? as usize;
        for _ in 0..count {
            if reader.read_u8()? != 0x60 {
                return self.invalid("unsupported non-function wasm type");
            }
            let param_count = reader.read_u32_leb()? as usize;
            let mut params = Vec::with_capacity(param_count);
            for _ in 0..param_count {
                params.push(read_value_type(reader.read_u8()?)?);
            }
            let result_count = reader.read_u32_leb()? as usize;
            let mut results = Vec::with_capacity(result_count);
            for _ in 0..result_count {
                results.push(read_value_type(reader.read_u8()?)?);
            }
            self.types.push(FunctionType { params, results });
        }
        Ok(())
    }

    fn parse_imports(&mut self, reader: &mut ByteReader<'_>) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()? as usize;
        for _ in 0..count {
            let module = reader.read_name()?;
            let name = reader.read_name()?;
            let kind = reader.read_u8()?;
            if kind != 0x00 {
                return Err(WasmNumericVmError::UnsupportedImportKind { kind });
            }
            let type_index = reader.read_u32_leb()?;
            self.type_at(type_index)?;
            self.imports.push(FunctionImport {
                module,
                name,
                type_index,
            });
        }
        Ok(())
    }

    fn parse_functions(&mut self, reader: &mut ByteReader<'_>) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()? as usize;
        if self.imports.len().saturating_add(count) > self.limits.max_functions {
            return Err(WasmNumericVmError::FunctionLimitExceeded {
                actual: self.imports.len().saturating_add(count),
                max: self.limits.max_functions,
            });
        }
        self.function_type_indices.reserve(count);
        for _ in 0..count {
            let type_index = reader.read_u32_leb()?;
            self.type_at(type_index)?;
            self.function_type_indices.push(type_index);
        }
        Ok(())
    }

    fn parse_exports(&mut self, reader: &mut ByteReader<'_>) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()? as usize;
        for _ in 0..count {
            let name = reader.read_name()?;
            let kind = reader.read_u8()?;
            let index = reader.read_u32_leb()?;
            if kind != 0x00 {
                return Err(WasmNumericVmError::ExportIsNotFunction { name, kind });
            }
            if self.exports.contains_key(&name) {
                return Err(WasmNumericVmError::DuplicateExport { name });
            }
            self.function_type_index(index)?;
            self.exports.insert(name, FunctionExport { function_index: index });
        }
        Ok(())
    }

    fn parse_code(&mut self, reader: &mut ByteReader<'_>) -> Result<(), WasmNumericVmError> {
        let count = reader.read_u32_leb()? as usize;
        if count != self.function_type_indices.len() {
            return self.invalid(format!(
                "code section has {count} bodies but function section has {} entries",
                self.function_type_indices.len()
            ));
        }
        for local_function_index in 0..count {
            let body_len = reader.read_u32_leb()? as usize;
            let body_bytes = reader.read_bytes(body_len)?;
            let mut body_reader = ByteReader::new(body_bytes);
            let local_group_count = body_reader.read_u32_leb()? as usize;
            let mut locals = Vec::new();
            for _ in 0..local_group_count {
                let local_count = body_reader.read_u32_leb()? as usize;
                let value_type = read_value_type(body_reader.read_u8()?)?;
                let new_len = locals.len().checked_add(local_count).ok_or_else(|| {
                    WasmNumericVmError::LocalLimitExceeded {
                        actual: usize::MAX,
                        max: self.limits.max_locals_per_call,
                    }
                })?;
                if new_len > self.limits.max_locals_per_call {
                    return Err(WasmNumericVmError::LocalLimitExceeded {
                        actual: new_len,
                        max: self.limits.max_locals_per_call,
                    });
                }
                locals.resize(new_len, value_type);
            }
            let code = body_reader.remaining().to_vec();
            if code.last().copied() != Some(0x0b) {
                return self.invalid(format!(
                    "function {local_function_index} body does not end with opcode 0x0b"
                ));
            }
            self.functions.push(FunctionBody {
                type_index: self.function_type_indices[local_function_index],
                locals,
                code,
            });
        }
        Ok(())
    }

    fn function_type_index(&self, function_index: u32) -> Result<u32, WasmNumericVmError> {
        if function_index < self.imports.len() as u32 {
            return Ok(self.imports[function_index as usize].type_index);
        }
        self.function_type_indices
            .get((function_index - self.imports.len() as u32) as usize)
            .copied()
            .ok_or(WasmNumericVmError::UnknownFunction { function_index })
    }

    fn type_at(&self, type_index: u32) -> Result<&FunctionType, WasmNumericVmError> {
        self.types
            .get(type_index as usize)
            .ok_or_else(|| WasmNumericVmError::InvalidModule {
                detail: format!("type index {type_index} is out of bounds"),
            })
    }

    fn read_u8(&mut self) -> Result<u8, WasmNumericVmError> {
        let byte = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or_else(|| WasmNumericVmError::InvalidModule {
                detail: "unexpected end of module".to_string(),
            })?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], WasmNumericVmError> {
        let end = self.offset.checked_add(len).ok_or_else(|| WasmNumericVmError::InvalidModule {
            detail: "module offset overflow".to_string(),
        })?;
        if end > self.bytes.len() {
            return self.invalid("section exceeds module length");
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn read_u32_leb(&mut self) -> Result<u32, WasmNumericVmError> {
        let (value, consumed) = read_u32_leb(&self.bytes[self.offset..])?;
        self.offset += consumed;
        Ok(value)
    }

    fn invalid<T>(&self, detail: impl Into<String>) -> Result<T, WasmNumericVmError> {
        Err(WasmNumericVmError::InvalidModule {
            detail: detail.into(),
        })
    }
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, WasmNumericVmError> {
        let byte = self.bytes.get(self.offset).copied().ok_or_else(|| {
            WasmNumericVmError::InvalidModule {
                detail: "unexpected end of wasm section".to_string(),
            }
        })?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], WasmNumericVmError> {
        let end = self.offset.checked_add(len).ok_or_else(|| WasmNumericVmError::InvalidModule {
            detail: "wasm section offset overflow".to_string(),
        })?;
        if end > self.bytes.len() {
            return Err(WasmNumericVmError::InvalidModule {
                detail: "wasm subsection exceeds section length".to_string(),
            });
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn read_u32_leb(&mut self) -> Result<u32, WasmNumericVmError> {
        let (value, consumed) = read_u32_leb(&self.bytes[self.offset..])?;
        self.offset += consumed;
        Ok(value)
    }

    fn read_name(&mut self) -> Result<String, WasmNumericVmError> {
        let len = self.read_u32_leb()? as usize;
        let bytes = self.read_bytes(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|_| WasmNumericVmError::InvalidModule {
                detail: "wasm name is not utf-8".to_string(),
            })
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn ensure_finished(&self) -> Result<(), WasmNumericVmError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WasmNumericVmError::InvalidModule {
                detail: format!("section has {} trailing byte(s)", self.bytes.len() - self.offset),
            })
        }
    }
}

struct CodeReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CodeReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn finished(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn read_u8(&mut self, function_index: u32) -> Result<u8, WasmNumericVmError> {
        let byte = self.bytes.get(self.offset).copied().ok_or_else(|| {
            WasmNumericVmError::InvalidModule {
                detail: format!("function {function_index} body ended unexpectedly"),
            }
        })?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_u32_leb(&mut self, function_index: u32) -> Result<u32, WasmNumericVmError> {
        let (value, consumed) = read_u32_leb(&self.bytes[self.offset..])?;
        self.offset += consumed;
        if self.offset > self.bytes.len() {
            return Err(WasmNumericVmError::InvalidModule {
                detail: format!("function {function_index} has truncated u32 immediate"),
            });
        }
        Ok(value)
    }

    fn read_i32_leb(&mut self, _function_index: u32) -> Result<i32, WasmNumericVmError> {
        let (value, consumed) = read_i32_leb(&self.bytes[self.offset..])?;
        self.offset += consumed;
        Ok(value)
    }

    fn read_i64_leb(&mut self, _function_index: u32) -> Result<i64, WasmNumericVmError> {
        let (value, consumed) = read_i64_leb(&self.bytes[self.offset..])?;
        self.offset += consumed;
        Ok(value)
    }

    fn read_u32_le(&mut self, function_index: u32) -> Result<u32, WasmNumericVmError> {
        let bytes = self.read_fixed::<4>(function_index)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64_le(&mut self, function_index: u32) -> Result<u64, WasmNumericVmError> {
        let bytes = self.read_fixed::<8>(function_index)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_fixed<const N: usize>(&mut self, function_index: u32) -> Result<[u8; N], WasmNumericVmError> {
        let end = self.offset.checked_add(N).ok_or_else(|| WasmNumericVmError::InvalidModule {
            detail: format!("function {function_index} immediate offset overflow"),
        })?;
        let slice = self.bytes.get(self.offset..end).ok_or_else(|| WasmNumericVmError::InvalidModule {
            detail: format!("function {function_index} has truncated immediate"),
        })?;
        self.offset = end;
        slice.try_into().map_err(|_| WasmNumericVmError::InvalidModule {
            detail: format!("function {function_index} immediate has wrong width"),
        })
    }
}

struct ExecutionMeter<'a> {
    limits: &'a WasmNumericLimits,
    instructions: u64,
    peak_stack_values: usize,
    max_call_depth: u32,
}

impl<'a> ExecutionMeter<'a> {
    fn new(limits: &'a WasmNumericLimits) -> Self {
        Self {
            limits,
            instructions: 0,
            peak_stack_values: 0,
            max_call_depth: 0,
        }
    }

    fn tick(&mut self) -> Result<(), WasmNumericVmError> {
        self.instructions = self.instructions.saturating_add(1);
        if self.instructions > self.limits.max_instructions {
            return Err(WasmNumericVmError::InstructionBudgetExceeded {
                max: self.limits.max_instructions,
            });
        }
        Ok(())
    }

    fn enter_call(&mut self, depth: u32) -> Result<(), WasmNumericVmError> {
        if depth > self.limits.max_call_depth {
            return Err(WasmNumericVmError::CallDepthExceeded {
                max: self.limits.max_call_depth,
            });
        }
        self.max_call_depth = self.max_call_depth.max(depth);
        Ok(())
    }

    fn observe_stack(&mut self, len: usize) -> Result<(), WasmNumericVmError> {
        if len > self.limits.max_stack_values {
            return Err(WasmNumericVmError::StackLimitExceeded {
                max: self.limits.max_stack_values,
            });
        }
        self.peak_stack_values = self.peak_stack_values.max(len);
        Ok(())
    }
}

fn read_value_type(byte: u8) -> Result<WasmValueType, WasmNumericVmError> {
    match byte {
        0x7f => Ok(WasmValueType::I32),
        0x7e => Ok(WasmValueType::I64),
        0x7d => Ok(WasmValueType::F32),
        0x7c => Ok(WasmValueType::F64),
        byte => Err(WasmNumericVmError::UnsupportedValueType { byte }),
    }
}

fn zero_value(value_type: WasmValueType) -> WasmBoundaryValue {
    match value_type {
        WasmValueType::I32 => WasmBoundaryValue::I32(0),
        WasmValueType::I64 => WasmBoundaryValue::I64(0),
        WasmValueType::F32 => WasmBoundaryValue::F32Bits(0),
        WasmValueType::F64 => WasmBoundaryValue::F64Bits(0),
    }
}

fn validate_arguments(
    function_index: u32,
    signature: &FunctionType,
    arguments: &[WasmBoundaryValue],
) -> Result<(), WasmNumericVmError> {
    if arguments.len() != signature.params.len() {
        return Err(WasmNumericVmError::ArityMismatch {
            function_index,
            expected: signature.params.len(),
            actual: arguments.len(),
        });
    }
    for (index, (expected, actual)) in signature
        .params
        .iter()
        .zip(arguments.iter().map(WasmBoundaryValue::value_type))
        .enumerate()
    {
        ensure_same_type(function_index, index, *expected, actual)?;
    }
    Ok(())
}

fn ensure_same_type(
    function_index: u32,
    value_index: usize,
    expected: WasmValueType,
    actual: WasmValueType,
) -> Result<(), WasmNumericVmError> {
    if expected == actual {
        Ok(())
    } else {
        Err(WasmNumericVmError::TypeMismatch {
            function_index,
            value_index,
            expected,
            actual,
        })
    }
}

fn push_value(
    stack: &mut Vec<WasmBoundaryValue>,
    value: WasmBoundaryValue,
    meter: &mut ExecutionMeter<'_>,
) -> Result<(), WasmNumericVmError> {
    stack.push(value);
    if let Err(error) = meter.observe_stack(stack.len()) {
        stack.pop();
        return Err(error);
    }
    Ok(())
}

fn pop_value(
    stack: &mut Vec<WasmBoundaryValue>,
    function_index: u32,
    opcode: u8,
) -> Result<WasmBoundaryValue, WasmNumericVmError> {
    stack.pop().ok_or(WasmNumericVmError::StackUnderflow {
        function_index,
        opcode,
    })
}

fn expect_i32(value: WasmBoundaryValue, function_index: u32, index: usize) -> Result<i32, WasmNumericVmError> {
    match value {
        WasmBoundaryValue::I32(value) => Ok(value),
        other => Err(WasmNumericVmError::TypeMismatch {
            function_index,
            value_index: index,
            expected: WasmValueType::I32,
            actual: other.value_type(),
        }),
    }
}

fn expect_i64(value: WasmBoundaryValue, function_index: u32, index: usize) -> Result<i64, WasmNumericVmError> {
    match value {
        WasmBoundaryValue::I64(value) => Ok(value),
        other => Err(WasmNumericVmError::TypeMismatch {
            function_index,
            value_index: index,
            expected: WasmValueType::I64,
            actual: other.value_type(),
        }),
    }
}

fn expect_f32_bits(value: WasmBoundaryValue, function_index: u32, index: usize) -> Result<u32, WasmNumericVmError> {
    match value {
        WasmBoundaryValue::F32Bits(value) => Ok(value),
        other => Err(WasmNumericVmError::TypeMismatch {
            function_index,
            value_index: index,
            expected: WasmValueType::F32,
            actual: other.value_type(),
        }),
    }
}

fn expect_f64_bits(value: WasmBoundaryValue, function_index: u32, index: usize) -> Result<u64, WasmNumericVmError> {
    match value {
        WasmBoundaryValue::F64Bits(value) => Ok(value),
        other => Err(WasmNumericVmError::TypeMismatch {
            function_index,
            value_index: index,
            expected: WasmValueType::F64,
            actual: other.value_type(),
        }),
    }
}

fn execute_select(
    stack: &mut Vec<WasmBoundaryValue>,
    function_index: u32,
    opcode: u8,
) -> Result<(), WasmNumericVmError> {
    let condition = expect_i32(pop_value(stack, function_index, opcode)?, function_index, 2)?;
    let rhs = pop_value(stack, function_index, opcode)?;
    let lhs = pop_value(stack, function_index, opcode)?;
    ensure_same_type(function_index, 0, lhs.value_type(), rhs.value_type())?;
    stack.push(if condition != 0 { lhs } else { rhs });
    Ok(())
}

fn execute_integer_comparison(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function_index: u32,
) -> Result<(), WasmNumericVmError> {
    let result = if opcode == 0x45 {
        expect_i32(pop_value(stack, function_index, opcode)?, function_index, 0)? == 0
    } else if opcode == 0x50 {
        expect_i64(pop_value(stack, function_index, opcode)?, function_index, 0)? == 0
    } else if (0x46..=0x4f).contains(&opcode) {
        let b = expect_i32(pop_value(stack, function_index, opcode)?, function_index, 1)?;
        let a = expect_i32(pop_value(stack, function_index, opcode)?, function_index, 0)?;
        match opcode {
            0x46 => a == b,
            0x47 => a != b,
            0x48 => a < b,
            0x49 => (a as u32) < (b as u32),
            0x4a => a > b,
            0x4b => (a as u32) > (b as u32),
            0x4c => a <= b,
            0x4d => (a as u32) <= (b as u32),
            0x4e => a >= b,
            0x4f => (a as u32) >= (b as u32),
            _ => unreachable!(),
        }
    } else {
        let b = expect_i64(pop_value(stack, function_index, opcode)?, function_index, 1)?;
        let a = expect_i64(pop_value(stack, function_index, opcode)?, function_index, 0)?;
        match opcode {
            0x51 => a == b,
            0x52 => a != b,
            0x53 => a < b,
            0x54 => (a as u64) < (b as u64),
            0x55 => a > b,
            0x56 => (a as u64) > (b as u64),
            0x57 => a <= b,
            0x58 => (a as u64) <= (b as u64),
            0x59 => a >= b,
            0x5a => (a as u64) >= (b as u64),
            _ => unreachable!(),
        }
    };
    stack.push(WasmBoundaryValue::I32(i32::from(result)));
    Ok(())
}

fn execute_float_comparison(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function_index: u32,
) -> Result<(), WasmNumericVmError> {
    let result = if opcode <= 0x60 {
        let b = f32::from_bits(expect_f32_bits(pop_value(stack, function_index, opcode)?, function_index, 1)?);
        let a = f32::from_bits(expect_f32_bits(pop_value(stack, function_index, opcode)?, function_index, 0)?);
        match opcode {
            0x5b => a == b,
            0x5c => a != b,
            0x5d => a < b,
            0x5e => a > b,
            0x5f => a <= b,
            0x60 => a >= b,
            _ => unreachable!(),
        }
    } else {
        let b = f64::from_bits(expect_f64_bits(pop_value(stack, function_index, opcode)?, function_index, 1)?);
        let a = f64::from_bits(expect_f64_bits(pop_value(stack, function_index, opcode)?, function_index, 0)?);
        match opcode {
            0x61 => a == b,
            0x62 => a != b,
            0x63 => a < b,
            0x64 => a > b,
            0x65 => a <= b,
            0x66 => a >= b,
            _ => unreachable!(),
        }
    };
    stack.push(WasmBoundaryValue::I32(i32::from(result)));
    Ok(())
}

fn execute_i32_numeric(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function_index: u32,
) -> Result<(), WasmNumericVmError> {
    if opcode < 0x6a || opcode > 0x70 {
        return Err(WasmNumericVmError::UnsupportedOpcode {
            function_index,
            opcode,
            offset: 0,
        });
    }
    let b = expect_i32(pop_value(stack, function_index, opcode)?, function_index, 1)?;
    let a = expect_i32(pop_value(stack, function_index, opcode)?, function_index, 0)?;
    let result = match opcode {
        0x6a => a.wrapping_add(b),
        0x6b => a.wrapping_sub(b),
        0x6c => a.wrapping_mul(b),
        0x6d => {
            if b == 0 {
                return Err(WasmNumericVmError::IntegerDivideByZero { function_index });
            }
            if a == i32::MIN && b == -1 {
                return Err(WasmNumericVmError::IntegerOverflow { function_index });
            }
            a / b
        }
        0x6e => {
            let ub = b as u32;
            if ub == 0 {
                return Err(WasmNumericVmError::IntegerDivideByZero { function_index });
            }
            ((a as u32) / ub) as i32
        }
        0x6f => {
            if b == 0 {
                return Err(WasmNumericVmError::IntegerDivideByZero { function_index });
            }
            a.wrapping_rem(b)
        }
        0x70 => {
            let ub = b as u32;
            if ub == 0 {
                return Err(WasmNumericVmError::IntegerDivideByZero { function_index });
            }
            ((a as u32) % ub) as i32
        }
        _ => unreachable!(),
    };
    stack.push(WasmBoundaryValue::I32(result));
    Ok(())
}

fn execute_i64_numeric(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function_index: u32,
) -> Result<(), WasmNumericVmError> {
    if opcode < 0x7c || opcode > 0x82 {
        return Err(WasmNumericVmError::UnsupportedOpcode {
            function_index,
            opcode,
            offset: 0,
        });
    }
    let b = expect_i64(pop_value(stack, function_index, opcode)?, function_index, 1)?;
    let a = expect_i64(pop_value(stack, function_index, opcode)?, function_index, 0)?;
    let result = match opcode {
        0x7c => a.wrapping_add(b),
        0x7d => a.wrapping_sub(b),
        0x7e => a.wrapping_mul(b),
        0x7f => {
            if b == 0 {
                return Err(WasmNumericVmError::IntegerDivideByZero { function_index });
            }
            if a == i64::MIN && b == -1 {
                return Err(WasmNumericVmError::IntegerOverflow { function_index });
            }
            a / b
        }
        0x80 => {
            let ub = b as u64;
            if ub == 0 {
                return Err(WasmNumericVmError::IntegerDivideByZero { function_index });
            }
            ((a as u64) / ub) as i64
        }
        0x81 => {
            if b == 0 {
                return Err(WasmNumericVmError::IntegerDivideByZero { function_index });
            }
            a.wrapping_rem(b)
        }
        0x82 => {
            let ub = b as u64;
            if ub == 0 {
                return Err(WasmNumericVmError::IntegerDivideByZero { function_index });
            }
            ((a as u64) % ub) as i64
        }
        _ => unreachable!(),
    };
    stack.push(WasmBoundaryValue::I64(result));
    Ok(())
}

fn execute_f32_numeric(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function_index: u32,
) -> Result<(), WasmNumericVmError> {
    let unary = matches!(opcode, 0x8b | 0x8c | 0x91);
    let result = if unary {
        let a = f32::from_bits(expect_f32_bits(pop_value(stack, function_index, opcode)?, function_index, 0)?);
        match opcode {
            0x8b => a.abs(),
            0x8c => -a,
            0x91 => a.sqrt(),
            _ => unreachable!(),
        }
    } else if (0x92..=0x95).contains(&opcode) {
        let b = f32::from_bits(expect_f32_bits(pop_value(stack, function_index, opcode)?, function_index, 1)?);
        let a = f32::from_bits(expect_f32_bits(pop_value(stack, function_index, opcode)?, function_index, 0)?);
        match opcode {
            0x92 => a + b,
            0x93 => a - b,
            0x94 => a * b,
            0x95 => a / b,
            _ => unreachable!(),
        }
    } else {
        return Err(WasmNumericVmError::UnsupportedOpcode {
            function_index,
            opcode,
            offset: 0,
        });
    };
    stack.push(WasmBoundaryValue::F32Bits(canonical_f32_bits(result)));
    Ok(())
}

fn execute_f64_numeric(
    opcode: u8,
    stack: &mut Vec<WasmBoundaryValue>,
    function_index: u32,
) -> Result<(), WasmNumericVmError> {
    let unary = matches!(opcode, 0x99 | 0x9a | 0x9f);
    let result = if unary {
        let a = f64::from_bits(expect_f64_bits(pop_value(stack, function_index, opcode)?, function_index, 0)?);
        match opcode {
            0x99 => a.abs(),
            0x9a => -a,
            0x9f => a.sqrt(),
            _ => unreachable!(),
        }
    } else if (0xa0..=0xa3).contains(&opcode) {
        let b = f64::from_bits(expect_f64_bits(pop_value(stack, function_index, opcode)?, function_index, 1)?);
        let a = f64::from_bits(expect_f64_bits(pop_value(stack, function_index, opcode)?, function_index, 0)?);
        match opcode {
            0xa0 => a + b,
            0xa1 => a - b,
            0xa2 => a * b,
            0xa3 => a / b,
            _ => unreachable!(),
        }
    } else {
        return Err(WasmNumericVmError::UnsupportedOpcode {
            function_index,
            opcode,
            offset: 0,
        });
    };
    stack.push(WasmBoundaryValue::F64Bits(canonical_f64_bits(result)));
    Ok(())
}

fn canonical_f32_bits(value: f32) -> u32 {
    if value.is_nan() {
        CANONICAL_F32_NAN
    } else {
        value.to_bits()
    }
}

fn canonical_f64_bits(value: f64) -> u64 {
    if value.is_nan() {
        CANONICAL_F64_NAN
    } else {
        value.to_bits()
    }
}

fn read_u32_leb(bytes: &[u8]) -> Result<(u32, usize), WasmNumericVmError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index >= 5 {
            return Err(WasmNumericVmError::InvalidModule {
                detail: "u32 leb128 is too long".to_string(),
            });
        }
        let payload = u32::from(byte & 0x7f);
        if shift == 28 && payload > 0x0f {
            return Err(WasmNumericVmError::InvalidModule {
                detail: "u32 leb128 overflows".to_string(),
            });
        }
        result |= payload << shift;
        if byte & 0x80 == 0 {
            return Ok((result, index + 1));
        }
        shift += 7;
    }
    Err(WasmNumericVmError::InvalidModule {
        detail: "unterminated u32 leb128".to_string(),
    })
}

fn read_i32_leb(bytes: &[u8]) -> Result<(i32, usize), WasmNumericVmError> {
    let (value, consumed) = read_signed_leb(bytes, 32, 5)?;
    Ok((value as i32, consumed))
}

fn read_i64_leb(bytes: &[u8]) -> Result<(i64, usize), WasmNumericVmError> {
    read_signed_leb(bytes, 64, 10)
}

fn read_signed_leb(
    bytes: &[u8],
    bits: u32,
    max_bytes: usize,
) -> Result<(i64, usize), WasmNumericVmError> {
    let mut result = 0i64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index >= max_bytes {
            return Err(WasmNumericVmError::InvalidModule {
                detail: format!("i{bits} leb128 is too long"),
            });
        }
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < bits && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            return Ok((result, index + 1));
        }
    }
    Err(WasmNumericVmError::InvalidModule {
        detail: format!("unterminated i{bits} leb128"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADD_I32_MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, b'a', b'd', b'd', 0x00, 0x00,
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
    ];

    const DIV_I32_MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, b'd', b'i', b'v', 0x00, 0x00,
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6d, 0x0b,
    ];

    #[test]
    fn executes_parameterized_i32_add() {
        let vm = WasmNumericVm::parse(ADD_I32_MODULE, WasmNumericLimits::default()).unwrap();
        let execution = vm
            .call_export("add", &[WasmBoundaryValue::I32(20), WasmBoundaryValue::I32(22)])
            .unwrap();
        assert_eq!(execution.results, vec![WasmBoundaryValue::I32(42)]);
        assert_eq!(execution.instructions_executed, 4);
        assert_eq!(execution.max_call_depth, 1);
    }

    #[test]
    fn validates_export_argument_types() {
        let vm = WasmNumericVm::parse(ADD_I32_MODULE, WasmNumericLimits::default()).unwrap();
        assert!(matches!(
            vm.call_export(
                "add",
                &[WasmBoundaryValue::I32(1), WasmBoundaryValue::I64(2)]
            )
            .unwrap_err(),
            WasmNumericVmError::TypeMismatch { .. }
        ));
    }

    #[test]
    fn traps_integer_divide_by_zero() {
        let vm = WasmNumericVm::parse(DIV_I32_MODULE, WasmNumericLimits::default()).unwrap();
        assert!(matches!(
            vm.call_export("div", &[WasmBoundaryValue::I32(1), WasmBoundaryValue::I32(0)])
                .unwrap_err(),
            WasmNumericVmError::IntegerDivideByZero { .. }
        ));
    }

    #[test]
    fn instruction_budget_fails_closed() {
        let limits = WasmNumericLimits {
            max_instructions: 2,
            ..WasmNumericLimits::default()
        };
        let vm = WasmNumericVm::parse(ADD_I32_MODULE, limits).unwrap();
        assert!(matches!(
            vm.call_export("add", &[WasmBoundaryValue::I32(1), WasmBoundaryValue::I32(2)])
                .unwrap_err(),
            WasmNumericVmError::InstructionBudgetExceeded { .. }
        ));
    }

    #[test]
    fn unsupported_control_flow_fails_closed() {
        let mut module = ADD_I32_MODULE.to_vec();
        let opcode = module.iter_mut().find(|byte| **byte == 0x6a).unwrap();
        *opcode = 0x04;
        let vm = WasmNumericVm::parse(&module, WasmNumericLimits::default()).unwrap();
        assert!(matches!(
            vm.call_export("add", &[WasmBoundaryValue::I32(1), WasmBoundaryValue::I32(2)])
                .unwrap_err(),
            WasmNumericVmError::UnsupportedOpcode { opcode: 0x04, .. }
        ));
    }

    #[test]
    fn module_size_limit_fails_before_parse() {
        let limits = WasmNumericLimits {
            max_module_bytes: ADD_I32_MODULE.len() - 1,
            ..WasmNumericLimits::default()
        };
        assert!(matches!(
            WasmNumericVm::parse(ADD_I32_MODULE, limits).unwrap_err(),
            WasmNumericVmError::ModuleTooLarge { .. }
        ));
    }
}
