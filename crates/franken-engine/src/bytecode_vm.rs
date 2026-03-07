//! Deterministic bytecode VM substrate with inline-cache support.
//!
//! This module provides a compact, replay-stable VM that can execute a small
//! instruction set, plus a deterministic inline-cache surface for property
//! loads. It is designed as a dependency-safe foundation for RGC-601.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const COMPONENT: &str = "bytecode_vm";

/// Register index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Register(pub u16);

impl Register {
    fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// Heap object handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub u32);

/// VM value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Value {
    Undefined,
    Bool(bool),
    Int(i64),
    Object(ObjectId),
}

impl Value {
    fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined => false,
            Self::Bool(v) => *v,
            Self::Int(v) => *v != 0,
            Self::Object(_) => true,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Object(_) => "object",
        }
    }
}

/// Instruction set for the deterministic bytecode VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    LoadConst {
        dst: Register,
        const_index: u16,
    },
    Move {
        dst: Register,
        src: Register,
    },
    Add {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    Sub {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    Mul {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    Div {
        dst: Register,
        lhs: Register,
        rhs: Register,
    },
    NewObject {
        dst: Register,
    },
    StoreProp {
        object: Register,
        property_index: u16,
        value: Register,
    },
    LoadPropCached {
        dst: Register,
        object: Register,
        property_index: u16,
    },
    Jump {
        target: u32,
    },
    JumpIfFalse {
        condition: Register,
        target: u32,
    },
    Return {
        src: Register,
    },
}

impl Instruction {
    fn opcode_name(&self) -> &'static str {
        match self {
            Self::LoadConst { .. } => "load_const",
            Self::Move { .. } => "move",
            Self::Add { .. } => "add",
            Self::Sub { .. } => "sub",
            Self::Mul { .. } => "mul",
            Self::Div { .. } => "div",
            Self::NewObject { .. } => "new_object",
            Self::StoreProp { .. } => "store_prop",
            Self::LoadPropCached { .. } => "load_prop_cached",
            Self::Jump { .. } => "jump",
            Self::JumpIfFalse { .. } => "jump_if_false",
            Self::Return { .. } => "return",
        }
    }
}

/// Bytecode program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Program {
    pub constants: Vec<Value>,
    pub property_pool: Vec<String>,
    pub instructions: Vec<Instruction>,
}

/// VM execution failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmError {
    RegisterOutOfBounds {
        register: u16,
        register_count: usize,
    },
    ConstantOutOfBounds {
        const_index: u16,
        constant_count: usize,
    },
    PropertyIndexOutOfBounds {
        property_index: u16,
        property_count: usize,
    },
    ObjectNotFound {
        object_id: u32,
    },
    TypeMismatch {
        expected: &'static str,
        got: &'static str,
    },
    DivisionByZero,
    InvalidJumpTarget {
        target: u32,
        instruction_count: usize,
    },
    MissingReturn,
    BudgetExhausted {
        executed_steps: u64,
        step_budget: u64,
    },
}

impl VmError {
    fn code(&self) -> &'static str {
        match self {
            Self::RegisterOutOfBounds { .. } => "register_oob",
            Self::ConstantOutOfBounds { .. } => "constant_oob",
            Self::PropertyIndexOutOfBounds { .. } => "property_oob",
            Self::ObjectNotFound { .. } => "object_not_found",
            Self::TypeMismatch { .. } => "type_mismatch",
            Self::DivisionByZero => "division_by_zero",
            Self::InvalidJumpTarget { .. } => "invalid_jump_target",
            Self::MissingReturn => "missing_return",
            Self::BudgetExhausted { .. } => "budget_exhausted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeapObject {
    shape_id: u64,
    keys: Vec<String>,
    slots: Vec<Value>,
    key_to_slot: BTreeMap<String, usize>,
}

impl HeapObject {
    fn new(shape_id: u64) -> Self {
        Self {
            shape_id,
            keys: Vec::new(),
            slots: Vec::new(),
            key_to_slot: BTreeMap::new(),
        }
    }

    fn load(&self, key: &str) -> Option<(usize, Value)> {
        self.key_to_slot
            .get(key)
            .and_then(|slot| self.slots.get(*slot).map(|value| (*slot, value.clone())))
    }

    fn load_slot(&self, slot_index: usize) -> Option<Value> {
        self.slots.get(slot_index).cloned()
    }

    fn store(&mut self, key: &str, value: Value, next_shape_id: &mut u64) {
        if let Some(slot) = self.key_to_slot.get(key).copied() {
            self.slots[slot] = value;
            return;
        }

        let slot = self.slots.len();
        self.keys.push(key.to_string());
        self.slots.push(value);
        self.key_to_slot.insert(key.to_string(), slot);
        self.shape_id = *next_shape_id;
        *next_shape_id += 1;
    }
}

/// Inline cache entry keyed by instruction pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InlineCacheEntry {
    pub shape_id: u64,
    pub property_index: u16,
    pub slot_index: usize,
    pub hits: u64,
    pub misses: u64,
}

/// Aggregate cache statistics for one VM execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InlineCacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
}

/// Structured execution event for deterministic replay and triage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmEvent {
    pub trace_id: String,
    pub component: String,
    pub step: u64,
    pub ip: u32,
    pub opcode: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub cache_hit: Option<bool>,
}

/// Final execution report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub trace_id: String,
    pub result: Value,
    pub steps: u64,
    pub cache_stats: InlineCacheStats,
    pub state_hash: String,
    pub events: Vec<VmEvent>,
}

enum ControlFlow {
    Continue {
        next_ip: usize,
        cache_hit: Option<bool>,
    },
    Return {
        value: Value,
        cache_hit: Option<bool>,
    },
}

struct EventRecord<'a> {
    step: u64,
    ip: u32,
    opcode: &'a str,
    event: &'a str,
    outcome: &'a str,
    error_code: Option<String>,
    cache_hit: Option<bool>,
}

/// Deterministic bytecode VM.
#[derive(Debug, Clone)]
pub struct BytecodeVm {
    trace_id: String,
    registers: Vec<Value>,
    heap: Vec<HeapObject>,
    inline_cache: BTreeMap<u32, InlineCacheEntry>,
    step_budget: u64,
    next_shape_id: u64,
    events: Vec<VmEvent>,
}

impl BytecodeVm {
    /// Create a VM with explicit register and step budgets.
    pub fn new(trace_id: impl Into<String>, register_count: usize, step_budget: u64) -> Self {
        Self {
            trace_id: trace_id.into(),
            registers: vec![Value::Undefined; register_count],
            heap: Vec::new(),
            inline_cache: BTreeMap::new(),
            step_budget,
            next_shape_id: 1,
            events: Vec::new(),
        }
    }

    /// Execute a program deterministically.
    pub fn execute(&mut self, program: &Program) -> Result<ExecutionReport, VmError> {
        self.events.clear();
        self.inline_cache.clear();
        self.heap.clear();
        self.registers.fill(Value::Undefined);
        self.next_shape_id = 1;

        let mut ip = 0usize;
        let mut steps = 0u64;

        loop {
            if steps >= self.step_budget {
                let error = VmError::BudgetExhausted {
                    executed_steps: steps,
                    step_budget: self.step_budget,
                };
                self.record_event(EventRecord {
                    step: steps,
                    ip: ip as u32,
                    opcode: "budget",
                    event: "instruction",
                    outcome: "error",
                    error_code: Some(error.code().to_string()),
                    cache_hit: None,
                });
                return Err(error);
            }

            let instruction = match program.instructions.get(ip).cloned() {
                Some(value) => value,
                None => {
                    let error = VmError::MissingReturn;
                    self.record_event(EventRecord {
                        step: steps,
                        ip: ip as u32,
                        opcode: "eof",
                        event: "instruction",
                        outcome: "error",
                        error_code: Some(error.code().to_string()),
                        cache_hit: None,
                    });
                    return Err(error);
                }
            };

            steps += 1;
            let opcode = instruction.opcode_name().to_string();

            match self.execute_instruction(program, ip, instruction) {
                Ok(ControlFlow::Continue { next_ip, cache_hit }) => {
                    self.record_event(EventRecord {
                        step: steps,
                        ip: ip as u32,
                        opcode: &opcode,
                        event: "instruction",
                        outcome: "ok",
                        error_code: None,
                        cache_hit,
                    });
                    ip = next_ip;
                }
                Ok(ControlFlow::Return { value, cache_hit }) => {
                    self.record_event(EventRecord {
                        step: steps,
                        ip: ip as u32,
                        opcode: &opcode,
                        event: "return",
                        outcome: "ok",
                        error_code: None,
                        cache_hit,
                    });

                    let cache_stats = self.cache_stats();
                    let state_hash = self.compute_state_hash(&value, steps, &cache_stats);

                    return Ok(ExecutionReport {
                        trace_id: self.trace_id.clone(),
                        result: value,
                        steps,
                        cache_stats,
                        state_hash,
                        events: self.events.clone(),
                    });
                }
                Err(error) => {
                    self.record_event(EventRecord {
                        step: steps,
                        ip: ip as u32,
                        opcode: &opcode,
                        event: "instruction",
                        outcome: "error",
                        error_code: Some(error.code().to_string()),
                        cache_hit: None,
                    });
                    return Err(error);
                }
            }
        }
    }

    fn execute_instruction(
        &mut self,
        program: &Program,
        ip: usize,
        instruction: Instruction,
    ) -> Result<ControlFlow, VmError> {
        match instruction {
            Instruction::LoadConst { dst, const_index } => {
                let constant = program
                    .constants
                    .get(usize::from(const_index))
                    .cloned()
                    .ok_or(VmError::ConstantOutOfBounds {
                        const_index,
                        constant_count: program.constants.len(),
                    })?;
                self.write_register(dst, constant)?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Move { dst, src } => {
                let value = self.read_register(src)?.clone();
                self.write_register(dst, value)?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Add { dst, lhs, rhs } => {
                let value = self.binary_int_op(lhs, rhs, |l, r| l.wrapping_add(r))?;
                self.write_register(dst, Value::Int(value))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Sub { dst, lhs, rhs } => {
                let value = self.binary_int_op(lhs, rhs, |l, r| l.wrapping_sub(r))?;
                self.write_register(dst, Value::Int(value))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Mul { dst, lhs, rhs } => {
                let value = self.binary_int_op(lhs, rhs, |l, r| l.wrapping_mul(r))?;
                self.write_register(dst, Value::Int(value))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::Div { dst, lhs, rhs } => {
                let left = self.read_int(lhs)?;
                let right = self.read_int(rhs)?;
                if right == 0 {
                    return Err(VmError::DivisionByZero);
                }
                self.write_register(dst, Value::Int(left.wrapping_div(right)))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::NewObject { dst } => {
                let object_id = ObjectId(self.heap.len() as u32);
                let object = HeapObject::new(self.next_shape_id);
                self.next_shape_id += 1;
                self.heap.push(object);
                self.write_register(dst, Value::Object(object_id))?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::StoreProp {
                object,
                property_index,
                value,
            } => {
                let object_id = self.read_object_id(object)?;
                let property_name = program
                    .property_pool
                    .get(usize::from(property_index))
                    .ok_or(VmError::PropertyIndexOutOfBounds {
                        property_index,
                        property_count: program.property_pool.len(),
                    })?
                    .clone();
                let stored_value = self.read_register(value)?.clone();
                let heap_object =
                    self.heap
                        .get_mut(object_id.0 as usize)
                        .ok_or(VmError::ObjectNotFound {
                            object_id: object_id.0,
                        })?;
                heap_object.store(&property_name, stored_value, &mut self.next_shape_id);

                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: None,
                })
            }
            Instruction::LoadPropCached {
                dst,
                object,
                property_index,
            } => {
                let object_id = self.read_object_id(object)?;
                let property_name = program
                    .property_pool
                    .get(usize::from(property_index))
                    .ok_or(VmError::PropertyIndexOutOfBounds {
                        property_index,
                        property_count: program.property_pool.len(),
                    })?;

                let object_ref =
                    self.heap
                        .get(object_id.0 as usize)
                        .ok_or(VmError::ObjectNotFound {
                            object_id: object_id.0,
                        })?;
                let object_shape = object_ref.shape_id;

                let cache_key = ip as u32;
                let mut cache_hit = false;
                let mut loaded = Value::Undefined;

                if let Some(entry) = self.inline_cache.get_mut(&cache_key)
                    && entry.shape_id == object_shape
                    && entry.property_index == property_index
                    && let Some(value) = object_ref.load_slot(entry.slot_index)
                {
                    entry.hits += 1;
                    cache_hit = true;
                    loaded = value;
                }

                if !cache_hit {
                    let (slot_index, value) = object_ref
                        .load(property_name)
                        .unwrap_or((usize::MAX, Value::Undefined));
                    loaded = value;

                    let entry = self.inline_cache.entry(cache_key).or_default();
                    entry.shape_id = object_shape;
                    entry.property_index = property_index;
                    entry.slot_index = slot_index;
                    entry.misses += 1;
                }

                self.write_register(dst, loaded)?;
                Ok(ControlFlow::Continue {
                    next_ip: ip + 1,
                    cache_hit: Some(cache_hit),
                })
            }
            Instruction::Jump { target } => {
                let target_index = target as usize;
                if target_index >= program.instructions.len() {
                    return Err(VmError::InvalidJumpTarget {
                        target,
                        instruction_count: program.instructions.len(),
                    });
                }
                Ok(ControlFlow::Continue {
                    next_ip: target_index,
                    cache_hit: None,
                })
            }
            Instruction::JumpIfFalse { condition, target } => {
                let condition_value = self.read_register(condition)?.clone();
                if condition_value.is_truthy() {
                    return Ok(ControlFlow::Continue {
                        next_ip: ip + 1,
                        cache_hit: None,
                    });
                }

                let target_index = target as usize;
                if target_index >= program.instructions.len() {
                    return Err(VmError::InvalidJumpTarget {
                        target,
                        instruction_count: program.instructions.len(),
                    });
                }
                Ok(ControlFlow::Continue {
                    next_ip: target_index,
                    cache_hit: None,
                })
            }
            Instruction::Return { src } => Ok(ControlFlow::Return {
                value: self.read_register(src)?.clone(),
                cache_hit: None,
            }),
        }
    }

    fn read_register(&self, register: Register) -> Result<&Value, VmError> {
        self.registers
            .get(register.index())
            .ok_or(VmError::RegisterOutOfBounds {
                register: register.0,
                register_count: self.registers.len(),
            })
    }

    fn write_register(&mut self, register: Register, value: Value) -> Result<(), VmError> {
        let register_count = self.registers.len();
        let slot =
            self.registers
                .get_mut(register.index())
                .ok_or(VmError::RegisterOutOfBounds {
                    register: register.0,
                    register_count,
                })?;
        *slot = value;
        Ok(())
    }

    fn read_int(&self, register: Register) -> Result<i64, VmError> {
        match self.read_register(register)? {
            Value::Int(value) => Ok(*value),
            other => Err(VmError::TypeMismatch {
                expected: "int",
                got: other.kind(),
            }),
        }
    }

    fn read_object_id(&self, register: Register) -> Result<ObjectId, VmError> {
        match self.read_register(register)? {
            Value::Object(object_id) => Ok(*object_id),
            other => Err(VmError::TypeMismatch {
                expected: "object",
                got: other.kind(),
            }),
        }
    }

    fn binary_int_op<F>(&self, lhs: Register, rhs: Register, operation: F) -> Result<i64, VmError>
    where
        F: FnOnce(i64, i64) -> i64,
    {
        let left = self.read_int(lhs)?;
        let right = self.read_int(rhs)?;
        Ok(operation(left, right))
    }

    fn cache_stats(&self) -> InlineCacheStats {
        let hits = self
            .inline_cache
            .values()
            .map(|entry| entry.hits)
            .sum::<u64>();
        let misses = self
            .inline_cache
            .values()
            .map(|entry| entry.misses)
            .sum::<u64>();

        InlineCacheStats {
            entries: self.inline_cache.len(),
            hits,
            misses,
        }
    }

    fn compute_state_hash(
        &self,
        result: &Value,
        steps: u64,
        cache_stats: &InlineCacheStats,
    ) -> String {
        #[derive(Serialize)]
        struct HashEnvelope<'a> {
            trace_id: &'a str,
            result: &'a Value,
            steps: u64,
            cache_stats: &'a InlineCacheStats,
            registers: &'a [Value],
            cache_entries: &'a BTreeMap<u32, InlineCacheEntry>,
            heap: &'a [HeapObject],
        }

        let envelope = HashEnvelope {
            trace_id: &self.trace_id,
            result,
            steps,
            cache_stats,
            registers: &self.registers,
            cache_entries: &self.inline_cache,
            heap: &self.heap,
        };

        let payload =
            serde_json::to_vec(&envelope).expect("bytecode-vm hash envelope must be serializable");
        let digest = Sha256::digest(payload);
        hex::encode(digest)
    }

    fn record_event(&mut self, event: EventRecord<'_>) {
        self.events.push(VmEvent {
            trace_id: self.trace_id.clone(),
            component: COMPONENT.to_string(),
            step: event.step,
            ip: event.ip,
            opcode: event.opcode.to_string(),
            event: event.event.to_string(),
            outcome: event.outcome.to_string(),
            error_code: event.error_code,
            cache_hit: event.cache_hit,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BytecodeVm, ExecutionReport, InlineCacheEntry, InlineCacheStats, Instruction, ObjectId,
        Program, Register, Value, VmError, VmEvent,
    };

    fn r(index: u16) -> Register {
        Register(index)
    }

    #[test]
    fn executes_arithmetic_program_deterministically() {
        let program = Program {
            constants: vec![Value::Int(6), Value::Int(7)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Mul {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };

        let mut vm = BytecodeVm::new("trace-arithmetic", 8, 128);
        let report = vm.execute(&program).expect("program should execute");

        assert_eq!(report.result, Value::Int(42));
        assert_eq!(report.steps, 4);
        assert_eq!(
            report.cache_stats,
            InlineCacheStats {
                entries: 0,
                hits: 0,
                misses: 0
            }
        );
        assert!(!report.state_hash.is_empty());
    }

    #[test]
    fn inline_cache_accumulates_hits_on_repeated_property_loads() {
        let program = Program {
            constants: vec![Value::Int(41), Value::Int(3), Value::Int(1)],
            property_pool: vec!["answer".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(1),
                },
                Instruction::LoadConst {
                    dst: r(2),
                    const_index: 1,
                },
                Instruction::LoadPropCached {
                    dst: r(3),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(4),
                    const_index: 2,
                },
                Instruction::Sub {
                    dst: r(2),
                    lhs: r(2),
                    rhs: r(4),
                },
                Instruction::JumpIfFalse {
                    condition: r(2),
                    target: 9,
                },
                Instruction::Jump { target: 4 },
                Instruction::Return { src: r(3) },
            ],
        };

        let mut vm = BytecodeVm::new("trace-cache-hit", 12, 256);
        let report = vm.execute(&program).expect("program should execute");

        assert_eq!(report.result, Value::Int(41));
        assert_eq!(report.cache_stats.entries, 1);
        assert_eq!(report.cache_stats.misses, 1);
        assert_eq!(report.cache_stats.hits, 2);
        assert!(
            report
                .events
                .iter()
                .any(|event| event.opcode == "load_prop_cached" && event.cache_hit == Some(true))
        );
    }

    #[test]
    fn inline_cache_misses_when_shape_changes() {
        let program = Program {
            constants: vec![Value::Int(10), Value::Int(20), Value::Int(2), Value::Int(1)],
            property_pool: vec!["a".to_string(), "b".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(1),
                },
                Instruction::LoadConst {
                    dst: r(4),
                    const_index: 2,
                },
                Instruction::LoadPropCached {
                    dst: r(2),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(3),
                    const_index: 1,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 1,
                    value: r(3),
                },
                Instruction::LoadConst {
                    dst: r(5),
                    const_index: 3,
                },
                Instruction::Sub {
                    dst: r(4),
                    lhs: r(4),
                    rhs: r(5),
                },
                Instruction::JumpIfFalse {
                    condition: r(4),
                    target: 11,
                },
                Instruction::Jump { target: 4 },
                Instruction::Return { src: r(2) },
            ],
        };

        let mut vm = BytecodeVm::new("trace-shape-change", 16, 256);
        let report = vm.execute(&program).expect("program should execute");

        assert_eq!(report.result, Value::Int(10));
        assert_eq!(report.cache_stats.entries, 1);
        assert_eq!(report.cache_stats.misses, 2);
        assert_eq!(report.cache_stats.hits, 0);
        assert!(
            report
                .events
                .iter()
                .filter(|event| event.opcode == "load_prop_cached")
                .all(|event| event.cache_hit == Some(false))
        );
    }

    #[test]
    fn returns_error_for_invalid_jump_target() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Jump { target: 9_999 },
            ],
        };

        let mut vm = BytecodeVm::new("trace-invalid-jump", 8, 32);
        let error = vm.execute(&program).expect_err("jump should fail");
        assert_eq!(
            error,
            VmError::InvalidJumpTarget {
                target: 9_999,
                instruction_count: 2
            }
        );
    }

    #[test]
    fn value_object_round_trip_preserves_identity() {
        let object_id = ObjectId(7);
        let value = Value::Object(object_id);
        assert_eq!(value, Value::Object(ObjectId(7)));
    }

    // -- Value tests ---------------------------------------------------------

    #[test]
    fn value_is_truthy_undefined() {
        assert!(!Value::Undefined.is_truthy());
    }

    #[test]
    fn value_is_truthy_bool() {
        assert!(Value::Bool(true).is_truthy());
        assert!(!Value::Bool(false).is_truthy());
    }

    #[test]
    fn value_is_truthy_int() {
        assert!(Value::Int(1).is_truthy());
        assert!(Value::Int(-1).is_truthy());
        assert!(!Value::Int(0).is_truthy());
    }

    #[test]
    fn value_is_truthy_object() {
        assert!(Value::Object(ObjectId(0)).is_truthy());
    }

    #[test]
    fn value_kind_names() {
        assert_eq!(Value::Undefined.kind(), "undefined");
        assert_eq!(Value::Bool(true).kind(), "bool");
        assert_eq!(Value::Int(42).kind(), "int");
        assert_eq!(Value::Object(ObjectId(0)).kind(), "object");
    }

    // -- Instruction opcode_name tests ---------------------------------------

    #[test]
    fn instruction_opcode_names() {
        assert_eq!(
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0
            }
            .opcode_name(),
            "load_const"
        );
        assert_eq!(
            Instruction::Move {
                dst: r(0),
                src: r(1)
            }
            .opcode_name(),
            "move"
        );
        assert_eq!(
            Instruction::Add {
                dst: r(0),
                lhs: r(1),
                rhs: r(2)
            }
            .opcode_name(),
            "add"
        );
        assert_eq!(
            Instruction::Sub {
                dst: r(0),
                lhs: r(1),
                rhs: r(2)
            }
            .opcode_name(),
            "sub"
        );
        assert_eq!(
            Instruction::Mul {
                dst: r(0),
                lhs: r(1),
                rhs: r(2)
            }
            .opcode_name(),
            "mul"
        );
        assert_eq!(
            Instruction::Div {
                dst: r(0),
                lhs: r(1),
                rhs: r(2)
            }
            .opcode_name(),
            "div"
        );
        assert_eq!(
            Instruction::NewObject { dst: r(0) }.opcode_name(),
            "new_object"
        );
        assert_eq!(Instruction::Return { src: r(0) }.opcode_name(), "return");
    }

    // -- Error case tests ----------------------------------------------------

    #[test]
    fn division_by_zero_returns_error() {
        let program = Program {
            constants: vec![Value::Int(10), Value::Int(0)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Div {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-divzero", 8, 64);
        let error = vm.execute(&program).expect_err("should error");
        assert_eq!(error, VmError::DivisionByZero);
    }

    #[test]
    fn constant_out_of_bounds() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 99,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-const-oob", 8, 64);
        let error = vm.execute(&program).expect_err("should error");
        assert!(matches!(error, VmError::ConstantOutOfBounds { .. }));
    }

    #[test]
    fn budget_exhausted_error() {
        let program = Program {
            constants: vec![],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::Jump { target: 0 }, // infinite loop
            ],
        };
        let mut vm = BytecodeVm::new("trace-budget", 4, 10);
        let error = vm.execute(&program).expect_err("should exhaust budget");
        assert!(matches!(error, VmError::BudgetExhausted { .. }));
    }

    #[test]
    fn missing_return_error() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                // No return instruction
            ],
        };
        let mut vm = BytecodeVm::new("trace-no-return", 4, 64);
        let error = vm
            .execute(&program)
            .expect_err("should error on missing return");
        assert_eq!(error, VmError::MissingReturn);
    }

    // -- Arithmetic tests ----------------------------------------------------

    #[test]
    fn add_two_values() {
        let program = Program {
            constants: vec![Value::Int(100), Value::Int(200)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Add {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-add", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(300));
    }

    #[test]
    fn sub_two_values() {
        let program = Program {
            constants: vec![Value::Int(50), Value::Int(30)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Sub {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-sub", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(20));
    }

    #[test]
    fn div_two_values() {
        let program = Program {
            constants: vec![Value::Int(100), Value::Int(5)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Div {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-div", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(20));
    }

    // -- Move instruction test -----------------------------------------------

    #[test]
    fn move_copies_value() {
        let program = Program {
            constants: vec![Value::Int(42)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Move {
                    dst: r(1),
                    src: r(0),
                },
                Instruction::Return { src: r(1) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-move", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(42));
    }

    // -- Conditional jump tests ----------------------------------------------

    #[test]
    fn jump_if_false_skips_when_falsy() {
        let program = Program {
            constants: vec![Value::Bool(false), Value::Int(1), Value::Int(2)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                }, // false
                Instruction::JumpIfFalse {
                    condition: r(0),
                    target: 3,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                }, // skipped
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 2,
                }, // target
                Instruction::Return { src: r(1) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-jif-false", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(2));
    }

    #[test]
    fn jump_if_false_continues_when_truthy() {
        let program = Program {
            constants: vec![Value::Bool(true), Value::Int(1), Value::Int(2)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                }, // true
                Instruction::JumpIfFalse {
                    condition: r(0),
                    target: 3,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                }, // not skipped
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 2,
                }, // also executes
                Instruction::Return { src: r(1) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-jif-true", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(2)); // both const loads run
    }

    // -- Object property tests -----------------------------------------------

    #[test]
    fn new_object_and_store_load_prop() {
        let program = Program {
            constants: vec![Value::Int(99)],
            property_pool: vec!["x".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(1),
                },
                Instruction::LoadPropCached {
                    dst: r(2),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-prop", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(99));
        assert_eq!(report.cache_stats.misses, 1);
    }

    // -- Determinism tests ---------------------------------------------------

    #[test]
    fn execution_is_deterministic_across_runs() {
        let program = Program {
            constants: vec![Value::Int(3), Value::Int(4)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Add {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };

        let mut vm1 = BytecodeVm::new("trace-det", 8, 64);
        let r1 = vm1.execute(&program).unwrap();
        let mut vm2 = BytecodeVm::new("trace-det", 8, 64);
        let r2 = vm2.execute(&program).unwrap();

        assert_eq!(r1.result, r2.result);
        assert_eq!(r1.state_hash, r2.state_hash);
        assert_eq!(r1.steps, r2.steps);
    }

    // -- Serde roundtrip tests -----------------------------------------------

    #[test]
    fn program_serde_roundtrip() {
        let program = Program {
            constants: vec![Value::Int(42), Value::Bool(true)],
            property_pool: vec!["key".to_string()],
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let json = serde_json::to_string(&program).unwrap();
        let restored: Program = serde_json::from_str(&json).unwrap();
        assert_eq!(program, restored);
    }

    #[test]
    fn vm_error_serializes() {
        let errors = vec![
            VmError::DivisionByZero,
            VmError::MissingReturn,
            VmError::BudgetExhausted {
                executed_steps: 100,
                step_budget: 50,
            },
            VmError::RegisterOutOfBounds {
                register: 10,
                register_count: 8,
            },
        ];
        for error in &errors {
            let json = serde_json::to_string(error).unwrap();
            assert!(!json.is_empty());
            // Verify JSON parses as valid
            let _: serde_json::Value = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn value_serde_roundtrip() {
        let values = vec![
            Value::Undefined,
            Value::Bool(true),
            Value::Int(42),
            Value::Object(ObjectId(7)),
        ];
        for val in &values {
            let json = serde_json::to_string(val).unwrap();
            let restored: Value = serde_json::from_str(&json).unwrap();
            assert_eq!(*val, restored);
        }
    }

    // -- VmError code tests --------------------------------------------------

    #[test]
    fn vm_error_codes_are_distinct() {
        let codes: Vec<&str> = vec![
            VmError::RegisterOutOfBounds {
                register: 0,
                register_count: 0,
            }
            .code(),
            VmError::ConstantOutOfBounds {
                const_index: 0,
                constant_count: 0,
            }
            .code(),
            VmError::PropertyIndexOutOfBounds {
                property_index: 0,
                property_count: 0,
            }
            .code(),
            VmError::ObjectNotFound { object_id: 0 }.code(),
            VmError::TypeMismatch {
                expected: "int",
                got: "bool",
            }
            .code(),
            VmError::DivisionByZero.code(),
            VmError::InvalidJumpTarget {
                target: 0,
                instruction_count: 0,
            }
            .code(),
            VmError::MissingReturn.code(),
            VmError::BudgetExhausted {
                executed_steps: 0,
                step_budget: 0,
            }
            .code(),
        ];
        let unique_count = {
            let mut sorted = codes.clone();
            sorted.sort();
            sorted.dedup();
            sorted.len()
        };
        assert_eq!(
            codes.len(),
            unique_count,
            "all error codes should be distinct"
        );
    }

    // -- Event generation tests ----------------------------------------------

    #[test]
    fn events_contain_instruction_entries() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-events", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert!(!report.events.is_empty());
        assert!(report.events.iter().all(|e| e.trace_id == "trace-events"));
        assert!(report.events.iter().all(|e| e.component == "bytecode_vm"));
        assert!(report.events.iter().any(|e| e.opcode == "load_const"));
        assert!(report.events.iter().any(|e| e.opcode == "return"));
    }

    // -- Register boundary tests (enrichment) --------------------------------

    #[test]
    fn register_out_of_bounds_on_write() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(99),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-reg-oob-write", 4, 64);
        let error = vm.execute(&program).expect_err("should fail on OOB write");
        assert!(matches!(
            error,
            VmError::RegisterOutOfBounds {
                register: 99,
                register_count: 4
            }
        ));
    }

    #[test]
    fn register_out_of_bounds_on_read() {
        let program = Program {
            constants: vec![],
            property_pool: Vec::new(),
            instructions: vec![Instruction::Return { src: r(50) }],
        };
        let mut vm = BytecodeVm::new("trace-reg-oob-read", 4, 64);
        let error = vm.execute(&program).expect_err("should fail on OOB read");
        assert!(matches!(
            error,
            VmError::RegisterOutOfBounds { register: 50, .. }
        ));
    }

    // -- Property index OOB (enrichment) -------------------------------------

    #[test]
    fn property_index_out_of_bounds_on_store() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: vec!["a".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 99,
                    value: r(1),
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-prop-oob-store", 8, 64);
        let error = vm.execute(&program).expect_err("should fail on prop OOB");
        assert!(matches!(
            error,
            VmError::PropertyIndexOutOfBounds {
                property_index: 99,
                ..
            }
        ));
    }

    #[test]
    fn property_index_out_of_bounds_on_load() {
        let program = Program {
            constants: vec![],
            property_pool: vec!["a".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadPropCached {
                    dst: r(1),
                    object: r(0),
                    property_index: 50,
                },
                Instruction::Return { src: r(1) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-prop-oob-load", 8, 64);
        let error = vm.execute(&program).expect_err("should fail on prop OOB");
        assert!(matches!(
            error,
            VmError::PropertyIndexOutOfBounds {
                property_index: 50,
                ..
            }
        ));
    }

    // -- Object not found (enrichment) ---------------------------------------

    #[test]
    fn object_not_found_on_store_prop() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: vec!["x".to_string()],
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                // r(0) is Int, not Object; but let's use a fake Object handle
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(0),
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-obj-not-found-store", 8, 64);
        let error = vm.execute(&program).expect_err("should fail");
        assert!(matches!(
            error,
            VmError::TypeMismatch {
                expected: "object",
                got: "int"
            }
        ));
    }

    #[test]
    fn object_not_found_on_load_prop_cached() {
        let program = Program {
            constants: vec![Value::Bool(true)],
            property_pool: vec!["x".to_string()],
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadPropCached {
                    dst: r(1),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::Return { src: r(1) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-obj-not-found-load", 8, 64);
        let error = vm.execute(&program).expect_err("should fail");
        assert!(matches!(
            error,
            VmError::TypeMismatch {
                expected: "object",
                got: "bool"
            }
        ));
    }

    // -- Type mismatch in arithmetic (enrichment) ----------------------------

    #[test]
    fn type_mismatch_add_bool_to_int() {
        let program = Program {
            constants: vec![Value::Bool(true), Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Add {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-type-mismatch", 8, 64);
        let error = vm
            .execute(&program)
            .expect_err("should fail on type mismatch");
        assert!(matches!(
            error,
            VmError::TypeMismatch {
                expected: "int",
                got: "bool"
            }
        ));
    }

    #[test]
    fn type_mismatch_mul_undefined() {
        let program = Program {
            constants: vec![Value::Int(5)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                // r(1) is Undefined by default
                Instruction::Mul {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-type-mismatch-undefined", 8, 64);
        let error = vm
            .execute(&program)
            .expect_err("should fail on type mismatch");
        assert!(matches!(
            error,
            VmError::TypeMismatch {
                expected: "int",
                got: "undefined"
            }
        ));
    }

    // -- Negative integer arithmetic (enrichment) ----------------------------

    #[test]
    fn negative_integer_arithmetic() {
        let program = Program {
            constants: vec![Value::Int(-10), Value::Int(3)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Mul {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-negative", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(-30));
    }

    #[test]
    fn integer_subtraction_yields_negative() {
        let program = Program {
            constants: vec![Value::Int(5), Value::Int(100)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Sub {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-sub-negative", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(-95));
    }

    #[test]
    fn negative_division_truncates_toward_zero() {
        let program = Program {
            constants: vec![Value::Int(-7), Value::Int(2)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Div {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-neg-div", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(-3)); // -7 / 2 = -3 (truncated)
    }

    // -- Multiple objects (enrichment) ---------------------------------------

    #[test]
    fn multiple_objects_independent_properties() {
        let program = Program {
            constants: vec![Value::Int(10), Value::Int(20)],
            property_pool: vec!["val".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::NewObject { dst: r(1) },
                Instruction::LoadConst {
                    dst: r(2),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(2),
                },
                Instruction::LoadConst {
                    dst: r(3),
                    const_index: 1,
                },
                Instruction::StoreProp {
                    object: r(1),
                    property_index: 0,
                    value: r(3),
                },
                Instruction::LoadPropCached {
                    dst: r(4),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::LoadPropCached {
                    dst: r(5),
                    object: r(1),
                    property_index: 0,
                },
                Instruction::Add {
                    dst: r(6),
                    lhs: r(4),
                    rhs: r(5),
                },
                Instruction::Return { src: r(6) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-multi-obj", 12, 128);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(30));
    }

    // -- Load missing property returns Undefined (enrichment) ----------------

    #[test]
    fn load_missing_property_returns_undefined() {
        let program = Program {
            constants: vec![],
            property_pool: vec!["missing".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadPropCached {
                    dst: r(1),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::Return { src: r(1) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-missing-prop", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Undefined);
    }

    // -- Property overwrite (enrichment) -------------------------------------

    #[test]
    fn store_prop_overwrites_existing_value() {
        let program = Program {
            constants: vec![Value::Int(1), Value::Int(2)],
            property_pool: vec!["x".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(1),
                },
                Instruction::LoadConst {
                    dst: r(2),
                    const_index: 1,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(2),
                },
                Instruction::LoadPropCached {
                    dst: r(3),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::Return { src: r(3) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-overwrite", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(2));
    }

    // -- Jump boundary condition (enrichment) --------------------------------

    #[test]
    fn jump_to_last_valid_instruction() {
        let program = Program {
            constants: vec![Value::Int(42)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::Jump { target: 1 },
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-jump-boundary", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(42));
    }

    #[test]
    fn jump_if_false_to_exact_boundary() {
        let program = Program {
            constants: vec![Value::Int(0), Value::Int(99)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                }, // 0 is falsy
                Instruction::JumpIfFalse {
                    condition: r(0),
                    target: 2,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Return { src: r(1) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-jif-boundary", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(99));
    }

    #[test]
    fn jump_if_false_invalid_target() {
        let program = Program {
            constants: vec![Value::Int(0)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::JumpIfFalse {
                    condition: r(0),
                    target: 999,
                },
            ],
        };
        let mut vm = BytecodeVm::new("trace-jif-invalid", 4, 64);
        let error = vm.execute(&program).expect_err("should fail");
        assert!(matches!(
            error,
            VmError::InvalidJumpTarget { target: 999, .. }
        ));
    }

    // -- State hash uniqueness (enrichment) ----------------------------------

    #[test]
    fn different_programs_produce_different_state_hashes() {
        let program_a = Program {
            constants: vec![Value::Int(1), Value::Int(2)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Add {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let program_b = Program {
            constants: vec![Value::Int(1), Value::Int(2)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Mul {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };

        let mut vm_a = BytecodeVm::new("trace-hash-a", 8, 64);
        let report_a = vm_a.execute(&program_a).unwrap();
        let mut vm_b = BytecodeVm::new("trace-hash-b", 8, 64);
        let report_b = vm_b.execute(&program_b).unwrap();

        assert_ne!(report_a.result, report_b.result);
        assert_ne!(report_a.state_hash, report_b.state_hash);
    }

    // -- Complex control flow (enrichment) -----------------------------------

    #[test]
    fn countdown_loop_with_accumulator() {
        // Computes: accumulator = 0; counter = 5; while(counter) { accumulator += counter; counter -= 1; }
        let program = Program {
            constants: vec![Value::Int(0), Value::Int(5), Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                // r(0) = accumulator = 0
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                // r(1) = counter = 5
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                // r(2) = 1 (decrement constant)
                Instruction::LoadConst {
                    dst: r(2),
                    const_index: 2,
                },
                // loop: if (!counter) goto end
                Instruction::JumpIfFalse {
                    condition: r(1),
                    target: 7,
                },
                // accumulator += counter
                Instruction::Add {
                    dst: r(0),
                    lhs: r(0),
                    rhs: r(1),
                },
                // counter -= 1
                Instruction::Sub {
                    dst: r(1),
                    lhs: r(1),
                    rhs: r(2),
                },
                // goto loop
                Instruction::Jump { target: 3 },
                // end: return accumulator
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-countdown", 8, 256);
        let report = vm.execute(&program).unwrap();
        // 5 + 4 + 3 + 2 + 1 = 15
        assert_eq!(report.result, Value::Int(15));
        // 3 init + 5 * (jif + add + sub + jump) + 1 final_jif + 1 return = 3 + 20 + 1 + 1 = 25
        assert_eq!(report.steps, 25);
    }

    // -- VM reuse across executions (enrichment) -----------------------------

    #[test]
    fn vm_resets_state_on_reexecution() {
        let program_a = Program {
            constants: vec![Value::Int(100)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let program_b = Program {
            constants: vec![Value::Int(200)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };

        let mut vm = BytecodeVm::new("trace-reuse", 4, 64);
        let report_a = vm.execute(&program_a).unwrap();
        assert_eq!(report_a.result, Value::Int(100));

        let report_b = vm.execute(&program_b).unwrap();
        assert_eq!(report_b.result, Value::Int(200));
        // Events should only contain entries from the second run
        assert!(report_b.events.iter().all(|e| e.step <= 2));
    }

    // -- Bool constant loading (enrichment) ----------------------------------

    #[test]
    fn load_and_return_bool_constant() {
        let program = Program {
            constants: vec![Value::Bool(true)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-bool", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Bool(true));
    }

    // -- Undefined default register value (enrichment) -----------------------

    #[test]
    fn default_register_is_undefined() {
        let program = Program {
            constants: vec![],
            property_pool: Vec::new(),
            instructions: vec![Instruction::Return { src: r(0) }],
        };
        let mut vm = BytecodeVm::new("trace-default-reg", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Undefined);
    }

    // -- Empty program (enrichment) ------------------------------------------

    #[test]
    fn empty_program_returns_missing_return() {
        let program = Program::default();
        let mut vm = BytecodeVm::new("trace-empty", 4, 64);
        let error = vm.execute(&program).expect_err("should fail");
        assert_eq!(error, VmError::MissingReturn);
    }

    // -- Budget boundary (enrichment) ----------------------------------------

    #[test]
    fn budget_exactly_sufficient() {
        let program = Program {
            constants: vec![Value::Int(42)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        // Budget of exactly 2 steps (load + return)
        let mut vm = BytecodeVm::new("trace-budget-exact", 4, 2);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(42));
        assert_eq!(report.steps, 2);
    }

    #[test]
    fn budget_one_short_fails() {
        let program = Program {
            constants: vec![Value::Int(42)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        // Budget of 1 step — load succeeds but return hits the budget check
        let mut vm = BytecodeVm::new("trace-budget-short", 4, 1);
        let error = vm.execute(&program).expect_err("should exhaust budget");
        assert!(matches!(
            error,
            VmError::BudgetExhausted {
                executed_steps: 1,
                step_budget: 1
            }
        ));
    }

    // -- Execution report events count (enrichment) --------------------------

    #[test]
    fn event_count_matches_steps() {
        let program = Program {
            constants: vec![Value::Int(1), Value::Int(2)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Add {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-event-count", 8, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.events.len() as u64, report.steps);
    }

    // -- Inline cache with multiple properties (enrichment) ------------------

    #[test]
    fn cache_entries_per_instruction_pointer() {
        let program = Program {
            constants: vec![Value::Int(10), Value::Int(20)],
            property_pool: vec!["a".to_string(), "b".to_string()],
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 0,
                    value: r(1),
                },
                Instruction::LoadConst {
                    dst: r(2),
                    const_index: 1,
                },
                Instruction::StoreProp {
                    object: r(0),
                    property_index: 1,
                    value: r(2),
                },
                // Two different LoadPropCached at different IPs
                Instruction::LoadPropCached {
                    dst: r(3),
                    object: r(0),
                    property_index: 0,
                },
                Instruction::LoadPropCached {
                    dst: r(4),
                    object: r(0),
                    property_index: 1,
                },
                Instruction::Add {
                    dst: r(5),
                    lhs: r(3),
                    rhs: r(4),
                },
                Instruction::Return { src: r(5) },
            ],
        };
        let mut vm = BytecodeVm::new("trace-multi-cache", 12, 128);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(30));
        assert_eq!(report.cache_stats.entries, 2);
        assert_eq!(report.cache_stats.misses, 2);
    }

    // -- Enrichment tests ---------------------------------------------------

    #[test]
    fn value_ordering_undefined_lt_bool_lt_int_lt_object() {
        let vals = vec![
            Value::Object(ObjectId(0)),
            Value::Int(0),
            Value::Bool(false),
            Value::Undefined,
        ];
        let mut sorted = vals.clone();
        sorted.sort();
        assert_eq!(sorted[0], Value::Undefined);
        assert!(matches!(sorted[1], Value::Bool(_)));
        assert!(matches!(sorted[2], Value::Int(_)));
        assert!(matches!(sorted[3], Value::Object(_)));
    }

    #[test]
    fn register_index_conversion() {
        assert_eq!(Register(0).index(), 0);
        assert_eq!(Register(255).index(), 255);
    }

    #[test]
    fn object_id_equality_and_ordering() {
        assert!(ObjectId(0) < ObjectId(1));
        assert_eq!(ObjectId(42), ObjectId(42));
    }

    #[test]
    fn instruction_serde_roundtrip_all_variants() {
        let instructions = vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 1,
            },
            Instruction::Move {
                dst: r(0),
                src: r(1),
            },
            Instruction::Add {
                dst: r(0),
                lhs: r(1),
                rhs: r(2),
            },
            Instruction::Sub {
                dst: r(0),
                lhs: r(1),
                rhs: r(2),
            },
            Instruction::Mul {
                dst: r(0),
                lhs: r(1),
                rhs: r(2),
            },
            Instruction::Div {
                dst: r(0),
                lhs: r(1),
                rhs: r(2),
            },
            Instruction::NewObject { dst: r(0) },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadPropCached {
                dst: r(0),
                object: r(1),
                property_index: 0,
            },
            Instruction::Jump { target: 0 },
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 0,
            },
            Instruction::Return { src: r(0) },
        ];
        for instr in &instructions {
            let json = serde_json::to_string(instr).unwrap();
            let back: Instruction = serde_json::from_str(&json).unwrap();
            assert_eq!(*instr, back);
        }
    }

    #[test]
    fn vm_error_code_all_distinct() {
        let errors: Vec<VmError> = vec![
            VmError::RegisterOutOfBounds {
                register: 0,
                register_count: 0,
            },
            VmError::ConstantOutOfBounds {
                const_index: 0,
                constant_count: 0,
            },
            VmError::PropertyIndexOutOfBounds {
                property_index: 0,
                property_count: 0,
            },
            VmError::ObjectNotFound { object_id: 0 },
            VmError::TypeMismatch {
                expected: "int",
                got: "bool",
            },
            VmError::DivisionByZero,
            VmError::InvalidJumpTarget {
                target: 0,
                instruction_count: 0,
            },
            VmError::MissingReturn,
            VmError::BudgetExhausted {
                executed_steps: 0,
                step_budget: 0,
            },
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(codes.len(), unique.len());
    }

    #[test]
    fn vm_error_serde_roundtrip_all_variants() {
        let errors: Vec<VmError> = vec![
            VmError::RegisterOutOfBounds {
                register: 5,
                register_count: 4,
            },
            VmError::ConstantOutOfBounds {
                const_index: 3,
                constant_count: 2,
            },
            VmError::PropertyIndexOutOfBounds {
                property_index: 1,
                property_count: 0,
            },
            VmError::ObjectNotFound { object_id: 99 },
            VmError::TypeMismatch {
                expected: "int",
                got: "bool",
            },
            VmError::DivisionByZero,
            VmError::InvalidJumpTarget {
                target: 10,
                instruction_count: 5,
            },
            VmError::MissingReturn,
            VmError::BudgetExhausted {
                executed_steps: 100,
                step_budget: 50,
            },
        ];
        let variants = [
            "RegisterOutOfBounds",
            "ConstantOutOfBounds",
            "PropertyIndexOutOfBounds",
            "ObjectNotFound",
            "TypeMismatch",
            "DivisionByZero",
            "InvalidJumpTarget",
            "MissingReturn",
            "BudgetExhausted",
        ];

        for (err, variant) in errors.iter().zip(variants) {
            let json = serde_json::to_string(err).unwrap();
            let payload: serde_json::Value = serde_json::from_str(&json).unwrap();
            if let Some(object) = payload.as_object() {
                assert!(
                    object.contains_key(variant),
                    "serialized VmError should include variant `{variant}`: {json}"
                );
            } else if let Some(s) = payload.as_str() {
                assert_eq!(
                    s, variant,
                    "serialized unit VmError should match variant `{variant}`: {json}"
                );
            } else {
                panic!("VmError serialization should be an object or string: {json}");
            }
        }
    }

    #[test]
    fn execution_report_serde_roundtrip() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("serde-rt", 4, 64);
        let report = vm.execute(&program).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: ExecutionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn inline_cache_stats_default_is_zero() {
        let stats = InlineCacheStats::default();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn inline_cache_entry_default_is_zero() {
        let entry = InlineCacheEntry::default();
        assert_eq!(entry.shape_id, 0);
        assert_eq!(entry.hits, 0);
        assert_eq!(entry.misses, 0);
    }

    #[test]
    fn program_default_is_empty() {
        let p = Program::default();
        assert!(p.constants.is_empty());
        assert!(p.property_pool.is_empty());
        assert!(p.instructions.is_empty());
    }

    #[test]
    fn mul_by_zero_returns_zero() {
        let program = Program {
            constants: vec![Value::Int(42), Value::Int(0)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Mul {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("mul-zero", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(0));
    }

    #[test]
    fn add_negative_integers() {
        let program = Program {
            constants: vec![Value::Int(-10), Value::Int(-20)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Add {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("add-neg", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(-30));
    }

    #[test]
    fn type_mismatch_div_object_by_int() {
        let program = Program {
            constants: vec![Value::Int(2)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 0,
                },
                Instruction::Div {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("div-obj", 4, 64);
        let err = vm.execute(&program).unwrap_err();
        assert_eq!(err.code(), "type_mismatch");
    }

    #[test]
    fn type_mismatch_sub_bool_from_int() {
        let program = Program {
            constants: vec![Value::Int(5), Value::Bool(true)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Sub {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("sub-type", 4, 64);
        let err = vm.execute(&program).unwrap_err();
        assert_eq!(err.code(), "type_mismatch");
    }

    #[test]
    fn new_object_returns_object_value() {
        let program = Program {
            constants: Vec::new(),
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::NewObject { dst: r(0) },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("new-obj", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert!(matches!(report.result, Value::Object(_)));
    }

    #[test]
    fn events_trace_id_matches_vm() {
        let program = Program {
            constants: vec![Value::Int(1)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("my-trace-id", 4, 64);
        let report = vm.execute(&program).unwrap();
        for event in &report.events {
            assert_eq!(event.trace_id, "my-trace-id");
            assert_eq!(event.component, "bytecode_vm");
        }
    }

    #[test]
    fn events_step_is_monotonically_increasing() {
        let program = Program {
            constants: vec![Value::Int(1), Value::Int(2)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::LoadConst {
                    dst: r(1),
                    const_index: 1,
                },
                Instruction::Add {
                    dst: r(2),
                    lhs: r(0),
                    rhs: r(1),
                },
                Instruction::Return { src: r(2) },
            ],
        };
        let mut vm = BytecodeVm::new("steps", 4, 64);
        let report = vm.execute(&program).unwrap();
        for window in report.events.windows(2) {
            assert!(window[1].step > window[0].step);
        }
    }

    #[test]
    fn return_bool_constant() {
        let program = Program {
            constants: vec![Value::Bool(true)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm = BytecodeVm::new("bool-ret", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Bool(true));
    }

    #[test]
    fn state_hash_is_deterministic() {
        let program = Program {
            constants: vec![Value::Int(42)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Return { src: r(0) },
            ],
        };
        let mut vm1 = BytecodeVm::new("hash-det", 4, 64);
        let mut vm2 = BytecodeVm::new("hash-det", 4, 64);
        let r1 = vm1.execute(&program).unwrap();
        let r2 = vm2.execute(&program).unwrap();
        assert_eq!(r1.state_hash, r2.state_hash);
    }

    #[test]
    fn inline_cache_stats_serde_roundtrip() {
        let stats = InlineCacheStats {
            entries: 3,
            hits: 10,
            misses: 2,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: InlineCacheStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }

    #[test]
    fn inline_cache_entry_serde_roundtrip() {
        let entry = InlineCacheEntry {
            shape_id: 5,
            property_index: 2,
            slot_index: 1,
            hits: 100,
            misses: 3,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: InlineCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn vm_event_serde_roundtrip() {
        let event = VmEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            step: 1,
            ip: 0,
            opcode: "add".to_string(),
            event: "instruction".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            cache_hit: Some(true),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: VmEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn move_preserves_value_type() {
        let program = Program {
            constants: vec![Value::Bool(false)],
            property_pool: Vec::new(),
            instructions: vec![
                Instruction::LoadConst {
                    dst: r(0),
                    const_index: 0,
                },
                Instruction::Move {
                    dst: r(1),
                    src: r(0),
                },
                Instruction::Return { src: r(1) },
            ],
        };
        let mut vm = BytecodeVm::new("move-bool", 4, 64);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Bool(false));
    }
}
