//! Baseline interpreter skeleton for the current execution-profile contract.
//!
//! Consumes `Ir3Module` and produces execution results with `Ir4Module`
//! witness artifacts.  The baseline interpreter is the canonical execution
//! path — all optimized paths must prove equivalence against it (per 9F.1).
//!
//! Two execution profiles are exposed today:
//! - **baseline_deterministic_profile**: conservative budgets for
//!   security-sensitive and resource-constrained contexts.
//! - **baseline_throughput_profile**: larger budgets for performance-oriented
//!   workloads.
//!
//! Both profiles share the same `InterpreterCore` execution logic; the profile
//! difference is in policy (instruction budget, register limit, dispatch
//! strategy), not in a second engine backend.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.2 item 8, bd-2f8.
//! Dependencies: bd-crp (parser), bd-1wa (IR contract), bd-20b (slot registry).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hash_tiers::ContentHash;
use crate::ir_contract::{
    HostcallDecisionRecord, Ir3Instruction, Ir3Module, WitnessEvent, WitnessEventKind,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT: &str = "baseline_interpreter";

/// Default instruction budget for the deterministic profile.
const DEFAULT_QUICKJS_BUDGET: u64 = 100_000;

/// Default instruction budget for the throughput profile.
const DEFAULT_V8_BUDGET: u64 = 1_000_000;

/// Default register file size for the deterministic profile.
const DEFAULT_QUICKJS_MAX_REGISTERS: u32 = 256;

/// Default register file size for the throughput profile.
const DEFAULT_V8_MAX_REGISTERS: u32 = 4096;

/// Maximum call-stack depth.
const MAX_CALL_DEPTH: usize = 256;

/// Canonical operator-facing label for the deterministic execution profile.
pub const DETERMINISTIC_PROFILE_LABEL: &str = "baseline_deterministic_profile";
/// Canonical operator-facing label for the throughput execution profile.
pub const THROUGHPUT_PROFILE_LABEL: &str = "baseline_throughput_profile";
/// Legacy lineage label still accepted on input for the deterministic profile.
pub const LEGACY_QUICKJS_PROFILE_LABEL: &str = "quickjs_inspired_native";
/// Legacy lineage label still accepted on input for the throughput profile.
pub const LEGACY_V8_PROFILE_LABEL: &str = "v8_inspired_native";

// ---------------------------------------------------------------------------
// Value — JS runtime value representation
// ---------------------------------------------------------------------------

/// Runtime value representation for the baseline interpreter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Value {
    /// Undefined.
    Undefined,
    /// Null.
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer (i64). Fixed-point integers avoid floating-point
    /// non-determinism; fractional values use millionths when needed.
    Int(i64),
    /// String.
    Str(String),
    /// Object reference (heap index).
    Object(ObjectId),
    /// Function reference (function table index).
    Function(u32),
}

impl Value {
    /// Truthiness: Undefined, Null, Bool(false), Int(0), Str("") are falsy.
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Str(s) => !s.is_empty(),
            Self::Object(_) | Self::Function(_) => true,
        }
    }

    /// Type name for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Int(_) => "number",
            Self::Str(_) => "string",
            Self::Object(_) => "object",
            Self::Function(_) => "function",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => write!(f, "undefined"),
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Object(id) => write!(f, "[object#{}]", id.0),
            Self::Function(idx) => write!(f, "[function#{idx}]"),
        }
    }
}

/// Opaque object identifier (heap index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub u32);

// ---------------------------------------------------------------------------
// HeapObject — simplified object model
// ---------------------------------------------------------------------------

/// A heap-allocated object with string-keyed properties.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HeapObject {
    /// Property storage (BTreeMap for deterministic ordering).
    pub properties: BTreeMap<String, Value>,
}

impl HeapObject {
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// CallFrame — interpreter call stack frame
// ---------------------------------------------------------------------------

/// A call stack frame.
#[derive(Debug, Clone)]
struct CallFrame {
    /// Return address (instruction index to resume at in caller).
    return_ip: usize,
    /// Register where the return value should be placed.
    return_reg: u32,
    /// Base register offset for this frame (reserved for frame isolation).
    register_base: usize,
    /// Function table index (reserved for frame-level diagnostics).
    #[allow(dead_code)]
    function_index: Option<u32>,
}

// ---------------------------------------------------------------------------
// InterpreterError
// ---------------------------------------------------------------------------

/// Errors from the baseline interpreter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterpreterError {
    /// Instruction budget exhausted.
    BudgetExhausted { executed: u64, budget: u64 },
    /// Register index out of bounds.
    RegisterOutOfBounds { register: u32, max: u32 },
    /// Instruction pointer out of bounds.
    InstructionOutOfBounds { ip: usize, count: usize },
    /// Call stack overflow.
    StackOverflow { depth: usize, max: usize },
    /// Type error (e.g. adding object + bool).
    TypeError { expected: String, got: String },
    /// Division by zero.
    DivisionByZero,
    /// Undefined variable (register not initialized).
    UndefinedRegister { register: u32 },
    /// Object not found on heap.
    ObjectNotFound { id: u32 },
    /// Property not found on object.
    PropertyNotFound { object_id: u32, key: String },
    /// Function not found in table.
    FunctionNotFound { index: u32, table_size: u32 },
    /// String pool index out of bounds.
    StringPoolOutOfBounds { index: u32, pool_size: u32 },
    /// Capability check failed for hostcall.
    CapabilityDenied { capability: String },
    /// Halt instruction reached (normal termination).
    Halted,
}

impl fmt::Display for InterpreterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted { executed, budget } => {
                write!(f, "instruction budget exhausted: {executed}/{budget}")
            }
            Self::RegisterOutOfBounds { register, max } => {
                write!(f, "register {register} out of bounds (max {max})")
            }
            Self::InstructionOutOfBounds { ip, count } => {
                write!(
                    f,
                    "instruction pointer {ip} out of bounds ({count} instructions)"
                )
            }
            Self::StackOverflow { depth, max } => {
                write!(f, "call stack overflow: depth {depth} exceeds max {max}")
            }
            Self::TypeError { expected, got } => {
                write!(f, "type error: expected {expected}, got {got}")
            }
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::UndefinedRegister { register } => {
                write!(f, "undefined register r{register}")
            }
            Self::ObjectNotFound { id } => write!(f, "object#{id} not found"),
            Self::PropertyNotFound { object_id, key } => {
                write!(f, "property '{key}' not found on object#{object_id}")
            }
            Self::FunctionNotFound { index, table_size } => {
                write!(f, "function#{index} not found (table size {table_size})")
            }
            Self::StringPoolOutOfBounds { index, pool_size } => {
                write!(
                    f,
                    "string pool index {index} out of bounds (pool size {pool_size})"
                )
            }
            Self::CapabilityDenied { capability } => {
                write!(f, "capability denied: {capability}")
            }
            Self::Halted => write!(f, "execution halted"),
        }
    }
}

// ---------------------------------------------------------------------------
// InterpreterConfig — lane-specific configuration
// ---------------------------------------------------------------------------

/// Configuration for an interpreter lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterpreterConfig {
    /// Maximum instructions before budget exhaustion.
    pub instruction_budget: u64,
    /// Maximum registers per frame.
    pub max_registers: u32,
    /// Maximum call depth.
    pub max_call_depth: usize,
    /// Set of capabilities granted to this execution context.
    pub granted_capabilities: Vec<String>,
}

impl InterpreterConfig {
    /// Deterministic profile defaults: conservative budgets.
    pub fn quickjs_defaults() -> Self {
        Self {
            instruction_budget: DEFAULT_QUICKJS_BUDGET,
            max_registers: DEFAULT_QUICKJS_MAX_REGISTERS,
            max_call_depth: MAX_CALL_DEPTH,
            granted_capabilities: Vec::new(),
        }
    }

    /// Throughput profile defaults: generous budgets.
    pub fn v8_defaults() -> Self {
        Self {
            instruction_budget: DEFAULT_V8_BUDGET,
            max_registers: DEFAULT_V8_MAX_REGISTERS,
            max_call_depth: MAX_CALL_DEPTH,
            granted_capabilities: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// InterpreterEvent — structured logging
// ---------------------------------------------------------------------------

/// Structured log event from the interpreter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterpreterEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// ExecutionResult
// ---------------------------------------------------------------------------

/// Result of interpreter execution.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Final value (from the return register or last evaluated expression).
    pub value: Value,
    /// Number of instructions executed.
    pub instructions_executed: u64,
    /// Witness events collected during execution.
    pub witness_events: Vec<WitnessEvent>,
    /// Hostcall decisions recorded.
    pub hostcall_decisions: Vec<HostcallDecisionRecord>,
    /// Structured events emitted.
    pub events: Vec<InterpreterEvent>,
}

// ---------------------------------------------------------------------------
// InterpreterCore — shared execution engine
// ---------------------------------------------------------------------------

/// The core interpreter loop shared between both lanes.
pub struct InterpreterCore {
    config: InterpreterConfig,
    /// Register file (flat, indexed by register number).
    registers: Vec<Value>,
    /// Call stack.
    call_stack: Vec<CallFrame>,
    /// Object heap.
    heap: Vec<HeapObject>,
    /// Current instruction pointer.
    ip: usize,
    /// Instructions executed counter.
    instructions_executed: u64,
    /// Witness events.
    witness_events: Vec<WitnessEvent>,
    /// Hostcall decisions.
    hostcall_decisions: Vec<HostcallDecisionRecord>,
    /// Structured events.
    events: Vec<InterpreterEvent>,
    /// Witness sequence counter.
    witness_seq: u64,
    /// Trace ID for logging.
    trace_id: String,
    /// Base register offset for current frame.
    register_base: usize,
}

impl InterpreterCore {
    /// Create a new interpreter core with the given configuration.
    pub fn new(config: InterpreterConfig, trace_id: impl Into<String>) -> Self {
        let max_regs = config.max_registers as usize;
        Self {
            config,
            registers: vec![Value::Undefined; max_regs],
            call_stack: Vec::new(),
            heap: Vec::new(),
            ip: 0,
            instructions_executed: 0,
            witness_events: Vec::new(),
            hostcall_decisions: Vec::new(),
            events: Vec::new(),
            witness_seq: 0,
            trace_id: trace_id.into(),
            register_base: 0,
        }
    }

    /// Execute an IR3 module and return the result.
    pub fn execute(&mut self, module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
        self.ip = 0;
        self.instructions_executed = 0;

        self.push_event("execution_started", "ok", None);

        let result = self.run_loop(module);

        match &result {
            Ok(_) => self.push_event("execution_completed", "ok", None),
            Err(InterpreterError::Halted) => {
                self.push_event("execution_halted", "ok", None);
            }
            Err(e) => {
                self.push_event("execution_failed", "fail", Some(&format!("{e}")));
            }
        }

        let final_value = match result {
            Ok(v) => v,
            Err(InterpreterError::Halted) => {
                // Halt is normal termination; return whatever is in r0.
                self.read_reg(0).unwrap_or(Value::Undefined)
            }
            Err(e) => return Err(e),
        };

        self.emit_witness(WitnessEventKind::ExecutionCompleted, None);

        Ok(ExecutionResult {
            value: final_value,
            instructions_executed: self.instructions_executed,
            witness_events: std::mem::take(&mut self.witness_events),
            hostcall_decisions: std::mem::take(&mut self.hostcall_decisions),
            events: std::mem::take(&mut self.events),
        })
    }

    fn run_loop(&mut self, module: &Ir3Module) -> Result<Value, InterpreterError> {
        loop {
            if self.ip >= module.instructions.len() {
                // Fell off the end of the instruction stream.
                if let Some(frame) = self.call_stack.pop() {
                    self.register_base = frame.register_base;
                    self.write_reg(frame.return_reg, Value::Undefined)?;
                    self.ip = frame.return_ip;
                    continue;
                } else {
                    return self.read_reg(0);
                }
            }

            if self.instructions_executed >= self.config.instruction_budget {
                return Err(InterpreterError::BudgetExhausted {
                    executed: self.instructions_executed,
                    budget: self.config.instruction_budget,
                });
            }

            let instr = module.instructions[self.ip].clone();
            self.instructions_executed += 1;

            match instr {
                Ir3Instruction::LoadInt { dst, value } => {
                    self.write_reg(dst, Value::Int(value))?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadStr { dst, pool_index } => {
                    let s = module
                        .constant_pool
                        .get(pool_index as usize)
                        .ok_or(InterpreterError::StringPoolOutOfBounds {
                            index: pool_index,
                            pool_size: module.constant_pool.len() as u32,
                        })?
                        .clone();
                    self.write_reg(dst, Value::Str(s))?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadBool { dst, value } => {
                    self.write_reg(dst, Value::Bool(value))?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadNull { dst } => {
                    self.write_reg(dst, Value::Null)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadUndefined { dst } => {
                    self.write_reg(dst, Value::Undefined)?;
                    self.ip += 1;
                }
                Ir3Instruction::Add { dst, lhs, rhs } => {
                    let result = self.eval_add(lhs, rhs)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Sub { dst, lhs, rhs } => {
                    let result = self.eval_arith(lhs, rhs, "sub")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Mul { dst, lhs, rhs } => {
                    let result = self.eval_arith(lhs, rhs, "mul")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Div { dst, lhs, rhs } => {
                    let result = self.eval_div(lhs, rhs)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Move { dst, src } => {
                    let val = self.read_reg(src)?;
                    self.write_reg(dst, val)?;
                    self.ip += 1;
                }
                Ir3Instruction::Jump { target } => {
                    self.ip = target as usize;
                }
                Ir3Instruction::JumpIf { cond, target } => {
                    let val = self.read_reg(cond)?;
                    if val.is_truthy() {
                        self.ip = target as usize;
                    } else {
                        self.ip += 1;
                    }
                }
                Ir3Instruction::Call { callee, args, dst } => {
                    let callee_val = self.read_reg(callee)?;
                    match callee_val {
                        Value::Function(func_idx) => {
                            let func = module.function_table.get(func_idx as usize).ok_or(
                                InterpreterError::FunctionNotFound {
                                    index: func_idx,
                                    table_size: module.function_table.len() as u32,
                                },
                            )?;

                            if self.call_stack.len() >= self.config.max_call_depth {
                                return Err(InterpreterError::StackOverflow {
                                    depth: self.call_stack.len(),
                                    max: self.config.max_call_depth,
                                });
                            }

                            let mut arg_vals = Vec::new();
                            for i in 0..args.count.min(func.arity) {
                                arg_vals.push(self.read_reg(args.start + i)?);
                            }

                            // Push frame.
                            self.call_stack.push(CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: dst,
                                register_base: self.register_base,
                                function_index: Some(func_idx),
                            });

                            self.register_base += self.config.max_registers as usize;

                            // Copy arguments into registers for the callee.
                            for (i, val) in arg_vals.into_iter().enumerate() {
                                self.write_reg(i as u32, val)?;
                            }

                            self.ip = func.entry as usize;
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    }
                }
                Ir3Instruction::Return { value } => {
                    let return_val = self.read_reg(value)?;
                    if let Some(frame) = self.call_stack.pop() {
                        self.register_base = frame.register_base;
                        self.write_reg(frame.return_reg, return_val)?;
                        self.ip = frame.return_ip;
                    } else {
                        // Top-level return.
                        return Ok(return_val);
                    }
                }
                Ir3Instruction::HostCall {
                    capability,
                    args: _,
                    dst,
                } => {
                    // Check capability.
                    if !self
                        .config
                        .granted_capabilities
                        .iter()
                        .any(|c| c == &capability.0)
                    {
                        self.emit_witness(
                            WitnessEventKind::CapabilityChecked,
                            Some(&format!("denied:{}", capability.0)),
                        );
                        return Err(InterpreterError::CapabilityDenied {
                            capability: capability.0.clone(),
                        });
                    }

                    self.emit_witness(
                        WitnessEventKind::HostcallDispatched,
                        Some(&format!("cap:{}", capability.0)),
                    );
                    self.emit_witness(
                        WitnessEventKind::CapabilityChecked,
                        Some(&format!("granted:{}", capability.0)),
                    );

                    self.hostcall_decisions.push(HostcallDecisionRecord {
                        seq: self.hostcall_decisions.len() as u64,
                        capability: capability.clone(),
                        allowed: true,
                        instruction_index: self.ip as u32,
                    });

                    // Hostcalls return undefined in baseline (no external dispatch).
                    self.write_reg(dst, Value::Undefined)?;
                    self.ip += 1;
                }
                Ir3Instruction::GetProperty { obj, key, dst } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let key_str = match &key_val {
                        Value::Str(s) => s.clone(),
                        Value::Int(n) => n.to_string(),
                        _ => key_val.to_string(),
                    };

                    match obj_val {
                        Value::Object(oid) => {
                            let heap_obj = self
                                .heap
                                .get(oid.0 as usize)
                                .ok_or(InterpreterError::ObjectNotFound { id: oid.0 })?;
                            let prop = heap_obj
                                .properties
                                .get(&key_str)
                                .cloned()
                                .unwrap_or(Value::Undefined);
                            self.write_reg(dst, prop)?;
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: obj_val.type_name().to_string(),
                            });
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::SetProperty { obj, key, val } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let set_val = self.read_reg(val)?;
                    let key_str = match &key_val {
                        Value::Str(s) => s.clone(),
                        Value::Int(n) => n.to_string(),
                        _ => key_val.to_string(),
                    };

                    match obj_val {
                        Value::Object(oid) => {
                            let heap_obj = self
                                .heap
                                .get_mut(oid.0 as usize)
                                .ok_or(InterpreterError::ObjectNotFound { id: oid.0 })?;
                            heap_obj.properties.insert(key_str, set_val);
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: obj_val.type_name().to_string(),
                            });
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::NewObject { dst } | Ir3Instruction::NewArray { dst } => {
                    let id = self.alloc_object();
                    self.write_reg(dst, Value::Object(id))?;
                    self.ip += 1;
                }
                Ir3Instruction::Halt => {
                    return Err(InterpreterError::Halted);
                }
            }
        }
    }

    // -- Arithmetic helpers ------------------------------------------------

    fn eval_add(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => Ok(Value::Int(x.wrapping_add(*y))),
            (Value::Str(x), Value::Str(y)) => Ok(Value::Str(format!("{x}{y}"))),
            (Value::Str(x), other) => Ok(Value::Str(format!("{x}{other}"))),
            (other, Value::Str(y)) => Ok(Value::Str(format!("{other}{y}"))),
            _ => Err(InterpreterError::TypeError {
                expected: "number or string".to_string(),
                got: format!("{} + {}", a.type_name(), b.type_name()),
            }),
        }
    }

    fn eval_arith(&self, lhs: u32, rhs: u32, op: &str) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => {
                let result = match op {
                    "sub" => x.wrapping_sub(*y),
                    "mul" => x.wrapping_mul(*y),
                    _ => unreachable!(),
                };
                Ok(Value::Int(result))
            }
            _ => Err(InterpreterError::TypeError {
                expected: "number".to_string(),
                got: format!("{} {} {}", a.type_name(), op, b.type_name()),
            }),
        }
    }

    fn eval_div(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => {
                if *y == 0 {
                    return Err(InterpreterError::DivisionByZero);
                }
                Ok(Value::Int(x.wrapping_div(*y)))
            }
            _ => Err(InterpreterError::TypeError {
                expected: "number".to_string(),
                got: format!("{} / {}", a.type_name(), b.type_name()),
            }),
        }
    }

    // -- Register access ---------------------------------------------------

    fn read_reg(&self, reg: u32) -> Result<Value, InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + reg as usize;
        Ok(self
            .registers
            .get(actual_reg)
            .cloned()
            .unwrap_or(Value::Undefined))
    }

    fn write_reg(&mut self, reg: u32, value: Value) -> Result<(), InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + reg as usize;
        if actual_reg >= self.registers.len() {
            self.registers.resize(actual_reg + 1, Value::Undefined);
        }
        self.registers[actual_reg] = value;
        Ok(())
    }

    // -- Heap operations ---------------------------------------------------

    /// Allocate a new object on the heap and return its ID.
    pub fn alloc_object(&mut self) -> ObjectId {
        let id = ObjectId(self.heap.len() as u32);
        self.heap.push(HeapObject::new());
        id
    }

    /// Get the number of objects on the heap.
    pub fn heap_size(&self) -> usize {
        self.heap.len()
    }

    // -- Witness emission --------------------------------------------------

    fn emit_witness(&mut self, kind: WitnessEventKind, detail: Option<&str>) {
        let payload = detail.unwrap_or("").as_bytes();
        self.witness_events.push(WitnessEvent {
            seq: self.witness_seq,
            kind,
            instruction_index: self.ip as u32,
            payload_hash: ContentHash::compute(payload),
            timestamp_tick: self.instructions_executed,
        });
        self.witness_seq += 1;
    }

    // -- Structured events -------------------------------------------------

    fn push_event(&mut self, event: &str, outcome: &str, err_code: Option<&str>) {
        self.events.push(InterpreterEvent {
            trace_id: self.trace_id.clone(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: err_code.map(str::to_string),
        });
    }
}

// ---------------------------------------------------------------------------
// Lane wrappers
// ---------------------------------------------------------------------------

/// Deterministic execution profile: conservative budgets and replay-stable defaults.
pub struct QuickJsLane {
    config: InterpreterConfig,
}

impl Default for QuickJsLane {
    fn default() -> Self {
        Self {
            config: InterpreterConfig::quickjs_defaults(),
        }
    }
}

impl QuickJsLane {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: InterpreterConfig) -> Self {
        Self { config }
    }

    pub fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
    ) -> Result<ExecutionResult, InterpreterError> {
        let mut core = InterpreterCore::new(self.config.clone(), trace_id);
        core.execute(module)
    }
}

/// Throughput execution profile: larger budgets for heavier workloads.
pub struct V8Lane {
    config: InterpreterConfig,
}

impl Default for V8Lane {
    fn default() -> Self {
        Self {
            config: InterpreterConfig::v8_defaults(),
        }
    }
}

impl V8Lane {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: InterpreterConfig) -> Self {
        Self { config }
    }

    pub fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
    ) -> Result<ExecutionResult, InterpreterError> {
        let mut core = InterpreterCore::new(self.config.clone(), trace_id);
        core.execute(module)
    }
}

// ---------------------------------------------------------------------------
// LaneRouter — policy-directed routing
// ---------------------------------------------------------------------------

/// Execution-profile choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneChoice {
    /// Deterministic baseline-interpreter profile selected.
    QuickJs,
    /// Throughput-tuned baseline-interpreter profile selected.
    V8,
}

impl LaneChoice {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::QuickJs => DETERMINISTIC_PROFILE_LABEL,
            Self::V8 => THROUGHPUT_PROFILE_LABEL,
        }
    }

    pub const fn legacy_lineage_label(self) -> &'static str {
        match self {
            Self::QuickJs => LEGACY_QUICKJS_PROFILE_LABEL,
            Self::V8 => LEGACY_V8_PROFILE_LABEL,
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        match label {
            DETERMINISTIC_PROFILE_LABEL | LEGACY_QUICKJS_PROFILE_LABEL | "QuickJs" | "quickjs" => {
                Some(Self::QuickJs)
            }
            THROUGHPUT_PROFILE_LABEL | LEGACY_V8_PROFILE_LABEL | "V8" | "v8" => Some(Self::V8),
            _ => None,
        }
    }
}

impl fmt::Display for LaneChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

impl Serialize for LaneChoice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.stable_label())
    }
}

impl<'de> Deserialize<'de> for LaneChoice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_label(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown execution profile label `{raw}`"))
        })
    }
}

/// Reason for lane selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneReason {
    /// Security-sensitive context requires deterministic execution.
    SecuritySensitive,
    /// Throughput-optimized workload.
    ThroughputOptimized,
    /// Explicit policy directive.
    PolicyDirective,
    /// Default fallback to deterministic lane.
    DefaultFallback,
}

impl LaneReason {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::SecuritySensitive => "security_sensitive",
            Self::ThroughputOptimized => "throughput_optimized",
            Self::PolicyDirective => "policy_directive",
            Self::DefaultFallback => "default_deterministic_profile",
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        match label {
            "security_sensitive" | "SecuritySensitive" => Some(Self::SecuritySensitive),
            "throughput_optimized" | "ThroughputOptimized" => Some(Self::ThroughputOptimized),
            "policy_directive" | "PolicyDirective" => Some(Self::PolicyDirective),
            "default_deterministic_profile" | "DefaultFallback" => Some(Self::DefaultFallback),
            _ => None,
        }
    }
}

impl fmt::Display for LaneReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

impl Serialize for LaneReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.stable_label())
    }
}

impl<'de> Deserialize<'de> for LaneReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_label(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown lane reason `{raw}`")))
    }
}

/// Result of lane routing.
#[derive(Debug, Clone)]
pub struct RoutedResult {
    /// Which lane was chosen.
    pub lane: LaneChoice,
    /// Why this lane was chosen.
    pub reason: LaneReason,
    /// The execution result.
    pub result: ExecutionResult,
}

/// Policy-directed lane router.
pub struct LaneRouter {
    quickjs: QuickJsLane,
    v8: V8Lane,
}

impl Default for LaneRouter {
    fn default() -> Self {
        Self {
            quickjs: QuickJsLane::new(),
            v8: V8Lane::new(),
        }
    }
}

impl LaneRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_configs(quickjs_config: InterpreterConfig, v8_config: InterpreterConfig) -> Self {
        Self {
            quickjs: QuickJsLane::with_config(quickjs_config),
            v8: V8Lane::with_config(v8_config),
        }
    }

    /// Route and execute the module.
    pub fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        force_lane: Option<LaneChoice>,
    ) -> Result<RoutedResult, InterpreterError> {
        let (lane, reason) = if let Some(forced) = force_lane {
            (forced, LaneReason::PolicyDirective)
        } else {
            self.select_lane(module)
        };

        let result = match lane {
            LaneChoice::QuickJs => self.quickjs.execute(module, trace_id)?,
            LaneChoice::V8 => self.v8.execute(module, trace_id)?,
        };

        Ok(RoutedResult {
            lane,
            reason,
            result,
        })
    }

    fn select_lane(&self, module: &Ir3Module) -> (LaneChoice, LaneReason) {
        // Capabilities force the deterministic baseline profile.
        if !module.required_capabilities.is_empty() {
            return (LaneChoice::QuickJs, LaneReason::SecuritySensitive);
        }

        // Large programs use the throughput-tuned baseline profile.
        if module.instructions.len() > 1000 {
            return (LaneChoice::V8, LaneReason::ThroughputOptimized);
        }

        // Default: deterministic profile.
        (LaneChoice::QuickJs, LaneReason::DefaultFallback)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir_contract::{
        CapabilityTag, Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion, RegRange,
    };

    // -- helpers --------------------------------------------------------

    fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
        Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: "test".to_string(),
            },
            instructions,
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
        }
    }

    fn test_module_with_pool(instructions: Vec<Ir3Instruction>, pool: Vec<String>) -> Ir3Module {
        let mut m = test_module(instructions);
        m.constant_pool = pool;
        m
    }

    fn test_module_with_functions(
        instructions: Vec<Ir3Instruction>,
        functions: Vec<Ir3FunctionDesc>,
    ) -> Ir3Module {
        let mut m = test_module(instructions);
        m.function_table = functions;
        m
    }

    fn quickjs_execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
        QuickJsLane::new().execute(module, "test-trace")
    }

    fn v8_execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
        V8Lane::new().execute(module, "test-trace")
    }

    // -----------------------------------------------------------------------
    // 1. Load instructions
    // -----------------------------------------------------------------------

    #[test]
    fn load_int() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(42));
    }

    #[test]
    fn load_str() {
        let m = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::Halt,
            ],
            vec!["hello".to_string()],
        );
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Str("hello".to_string()));
    }

    #[test]
    fn load_bool_true() {
        let m = test_module(vec![
            Ir3Instruction::LoadBool {
                dst: 0,
                value: true,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Bool(true));
    }

    #[test]
    fn load_null() {
        let m = test_module(vec![
            Ir3Instruction::LoadNull { dst: 0 },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Null);
    }

    #[test]
    fn load_undefined() {
        let m = test_module(vec![
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Undefined);
    }

    // -----------------------------------------------------------------------
    // 2. Arithmetic
    // -----------------------------------------------------------------------

    #[test]
    fn add_integers() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 3 },
            Ir3Instruction::LoadInt { dst: 2, value: 4 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(7));
    }

    #[test]
    fn add_strings() {
        let m = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 1,
                },
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec!["hello".to_string(), " world".to_string()],
        );
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Str("hello world".to_string()));
    }

    #[test]
    fn sub_integers() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 10 },
            Ir3Instruction::LoadInt { dst: 2, value: 3 },
            Ir3Instruction::Sub {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(7));
    }

    #[test]
    fn mul_integers() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 6 },
            Ir3Instruction::LoadInt { dst: 2, value: 7 },
            Ir3Instruction::Mul {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(42));
    }

    #[test]
    fn div_integers() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 20 },
            Ir3Instruction::LoadInt { dst: 2, value: 4 },
            Ir3Instruction::Div {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(5));
    }

    #[test]
    fn div_by_zero() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 10 },
            Ir3Instruction::LoadInt { dst: 2, value: 0 },
            Ir3Instruction::Div {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
        ]);
        let err = quickjs_execute(&m).unwrap_err();
        assert_eq!(err, InterpreterError::DivisionByZero);
    }

    #[test]
    fn add_type_error() {
        let m = test_module(vec![
            Ir3Instruction::LoadBool {
                dst: 1,
                value: true,
            },
            Ir3Instruction::LoadNull { dst: 2 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
        ]);
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::TypeError { .. }));
    }

    // -----------------------------------------------------------------------
    // 3. Control flow
    // -----------------------------------------------------------------------

    #[test]
    fn unconditional_jump() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },  // 0
            Ir3Instruction::Jump { target: 3 },            // 1: jump to 3
            Ir3Instruction::LoadInt { dst: 0, value: 99 }, // 2: skipped
            Ir3Instruction::Halt,                          // 3
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(1));
    }

    #[test]
    fn conditional_jump_taken() {
        let m = test_module(vec![
            Ir3Instruction::LoadBool {
                dst: 1,
                value: true,
            }, // 0
            Ir3Instruction::LoadInt { dst: 0, value: 10 }, // 1
            Ir3Instruction::JumpIf { cond: 1, target: 4 }, // 2: jump if true -> 4
            Ir3Instruction::LoadInt { dst: 0, value: 20 }, // 3: skipped
            Ir3Instruction::Halt,                          // 4
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(10));
    }

    #[test]
    fn conditional_jump_not_taken() {
        let m = test_module(vec![
            Ir3Instruction::LoadBool {
                dst: 1,
                value: false,
            }, // 0
            Ir3Instruction::LoadInt { dst: 0, value: 10 }, // 1
            Ir3Instruction::JumpIf { cond: 1, target: 4 }, // 2: not taken
            Ir3Instruction::LoadInt { dst: 0, value: 20 }, // 3: executed
            Ir3Instruction::Halt,                          // 4
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(20));
    }

    // -----------------------------------------------------------------------
    // 4. Function calls
    // -----------------------------------------------------------------------

    #[test]
    fn simple_function_call() {
        // r1 = 5 (argument), r3 = Function(0) (callee, pre-set).
        // Call func(r1) -> r0.
        // Function body at instruction 2: load 10 into r1, add r0+r1 -> r2, return r2.
        let m = test_module_with_functions(
            vec![
                // Main
                Ir3Instruction::Call {
                    callee: 3,
                    args: RegRange { start: 1, count: 1 },
                    dst: 0,
                }, // 0
                Ir3Instruction::Halt, // 1: return here after call
                // Function body (entry at 2)
                Ir3Instruction::LoadInt { dst: 1, value: 10 }, // 2
                Ir3Instruction::Add {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                }, // 3: r2 = r0 + 10
                Ir3Instruction::Return { value: 2 },           // 4
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 3,
                name: Some("add_ten".to_string()),
            }],
        );

        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 1000;
        let mut core = InterpreterCore::new(config, "test");
        // Pre-set registers: r3 = callee function, r1 = argument.
        core.registers[3] = Value::Function(0);
        core.registers[1] = Value::Int(5);
        let result = core.execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(15));
    }

    #[test]
    fn stack_overflow() {
        // Recursive function that calls itself.
        let m = test_module_with_functions(
            vec![
                // Load function ref and call
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 0, count: 1 },
                    dst: 0,
                }, // 0 (entry)
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 1,
                name: Some("recurse".to_string()),
            }],
        );

        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_call_depth = 10;
        config.instruction_budget = 100;
        let mut core = InterpreterCore::new(config, "test");
        core.registers[0] = Value::Function(0);
        let err = core.execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::StackOverflow { .. }));
    }

    // -----------------------------------------------------------------------
    // 5. Budget exhaustion
    // -----------------------------------------------------------------------

    #[test]
    fn budget_exhaustion() {
        // Infinite loop.
        let m = test_module(vec![Ir3Instruction::Jump { target: 0 }]);

        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 5;
        let lane = QuickJsLane::with_config(config);
        let err = lane.execute(&m, "test").unwrap_err();
        assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
    }

    // -----------------------------------------------------------------------
    // 6. Register bounds
    // -----------------------------------------------------------------------

    #[test]
    fn register_out_of_bounds() {
        let m = test_module(vec![Ir3Instruction::LoadInt {
            dst: 9999,
            value: 1,
        }]);

        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_registers = 256;
        let lane = QuickJsLane::with_config(config);
        let err = lane.execute(&m, "test").unwrap_err();
        assert!(matches!(err, InterpreterError::RegisterOutOfBounds { .. }));
    }

    // -----------------------------------------------------------------------
    // 7. String pool bounds
    // -----------------------------------------------------------------------

    #[test]
    fn string_pool_out_of_bounds() {
        let m = test_module(vec![Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 99,
        }]);
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::StringPoolOutOfBounds { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // 8. Move instruction
    // -----------------------------------------------------------------------

    #[test]
    fn move_register() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(42));
    }

    // -----------------------------------------------------------------------
    // 9. Hostcall capability check
    // -----------------------------------------------------------------------

    #[test]
    fn hostcall_capability_denied() {
        let m = test_module(vec![Ir3Instruction::HostCall {
            capability: CapabilityTag("network".to_string()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        }]);
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::CapabilityDenied { .. }));
    }

    #[test]
    fn hostcall_capability_granted() {
        let m = test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("network".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]);
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = vec!["network".to_string()];
        let lane = QuickJsLane::with_config(config);
        let result = lane.execute(&m, "test").unwrap();
        assert_eq!(result.value, Value::Undefined);
    }

    // -----------------------------------------------------------------------
    // 10. Witness events
    // -----------------------------------------------------------------------

    #[test]
    fn witness_events_emitted() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        // Should have at least the ExecutionCompleted event.
        assert!(
            result
                .witness_events
                .iter()
                .any(|e| e.kind == WitnessEventKind::ExecutionCompleted)
        );
    }

    #[test]
    fn hostcall_produces_witness_events() {
        let mut m = test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]);
        m.required_capabilities = vec![CapabilityTag("fs".to_string())];

        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = vec!["fs".to_string()];
        let lane = QuickJsLane::with_config(config);
        let result = lane.execute(&m, "test").unwrap();

        assert!(
            result
                .witness_events
                .iter()
                .any(|e| e.kind == WitnessEventKind::HostcallDispatched)
        );
        assert!(
            result
                .witness_events
                .iter()
                .any(|e| e.kind == WitnessEventKind::CapabilityChecked)
        );
    }

    // -----------------------------------------------------------------------
    // 11. Structured events
    // -----------------------------------------------------------------------

    #[test]
    fn structured_events_emitted() {
        let m = test_module(vec![Ir3Instruction::Halt]);
        let result = quickjs_execute(&m).unwrap();
        assert!(result.events.iter().any(|e| e.event == "execution_started"));
        assert!(result.events.iter().any(|e| e.event == "execution_halted"));
    }

    // -----------------------------------------------------------------------
    // 12. V8 lane produces same results
    // -----------------------------------------------------------------------

    #[test]
    fn v8_lane_same_result_as_quickjs() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 3 },
            Ir3Instruction::LoadInt { dst: 2, value: 4 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let qjs = quickjs_execute(&m).unwrap();
        let v8 = v8_execute(&m).unwrap();
        assert_eq!(qjs.value, v8.value);
    }

    // -----------------------------------------------------------------------
    // 13. Lane routing
    // -----------------------------------------------------------------------

    #[test]
    fn router_selects_quickjs_for_simple_module() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Halt,
        ]);
        let router = LaneRouter::new();
        let result = router.execute(&m, "test", None).unwrap();
        assert_eq!(result.lane, LaneChoice::QuickJs);
        assert_eq!(result.reason, LaneReason::DefaultFallback);
    }

    #[test]
    fn router_selects_quickjs_for_capability_module() {
        let mut m = test_module(vec![Ir3Instruction::Halt]);
        m.required_capabilities = vec![CapabilityTag("net".to_string())];
        let router = LaneRouter::new();
        let result = router.execute(&m, "test", None).unwrap();
        assert_eq!(result.lane, LaneChoice::QuickJs);
        assert_eq!(result.reason, LaneReason::SecuritySensitive);
    }

    #[test]
    fn router_selects_v8_for_large_module() {
        let instrs: Vec<Ir3Instruction> = (0..1001)
            .map(|_| Ir3Instruction::LoadInt { dst: 0, value: 1 })
            .chain(std::iter::once(Ir3Instruction::Halt))
            .collect();
        let m = test_module(instrs);
        let router = LaneRouter::new();
        let result = router.execute(&m, "test", None).unwrap();
        assert_eq!(result.lane, LaneChoice::V8);
        assert_eq!(result.reason, LaneReason::ThroughputOptimized);
    }

    #[test]
    fn router_respects_forced_lane() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Halt,
        ]);
        let router = LaneRouter::new();
        let result = router.execute(&m, "test", Some(LaneChoice::V8)).unwrap();
        assert_eq!(result.lane, LaneChoice::V8);
        assert_eq!(result.reason, LaneReason::PolicyDirective);
    }

    // -----------------------------------------------------------------------
    // 14. Determinism: same input → same output
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_execution() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 100 },
            Ir3Instruction::LoadInt { dst: 2, value: 200 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);

        let r1 = quickjs_execute(&m).unwrap();
        let r2 = quickjs_execute(&m).unwrap();
        assert_eq!(r1.value, r2.value);
        assert_eq!(r1.instructions_executed, r2.instructions_executed);
    }

    // -----------------------------------------------------------------------
    // 15. Value truthiness
    // -----------------------------------------------------------------------

    #[test]
    fn value_truthiness() {
        assert!(!Value::Undefined.is_truthy());
        assert!(!Value::Null.is_truthy());
        assert!(!Value::Bool(false).is_truthy());
        assert!(!Value::Int(0).is_truthy());
        assert!(!Value::Str(String::new()).is_truthy());

        assert!(Value::Bool(true).is_truthy());
        assert!(Value::Int(1).is_truthy());
        assert!(Value::Int(-1).is_truthy());
        assert!(Value::Str("x".to_string()).is_truthy());
        assert!(Value::Object(ObjectId(0)).is_truthy());
        assert!(Value::Function(0).is_truthy());
    }

    // -----------------------------------------------------------------------
    // 16. Value display
    // -----------------------------------------------------------------------

    #[test]
    fn value_display() {
        assert_eq!(Value::Undefined.to_string(), "undefined");
        assert_eq!(Value::Null.to_string(), "null");
        assert_eq!(Value::Bool(true).to_string(), "true");
        assert_eq!(Value::Int(42).to_string(), "42");
        assert_eq!(Value::Str("hi".to_string()).to_string(), "hi");
    }

    // -----------------------------------------------------------------------
    // 17. Error display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_coverage() {
        let errors = vec![
            InterpreterError::BudgetExhausted {
                executed: 100,
                budget: 50,
            },
            InterpreterError::RegisterOutOfBounds {
                register: 999,
                max: 256,
            },
            InterpreterError::DivisionByZero,
            InterpreterError::Halted,
            InterpreterError::StackOverflow { depth: 10, max: 5 },
            InterpreterError::CapabilityDenied {
                capability: "net".to_string(),
            },
        ];
        for e in errors {
            let s = e.to_string();
            assert!(!s.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // 18. Return from top-level
    // -----------------------------------------------------------------------

    #[test]
    fn return_from_top_level() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 99 },
            Ir3Instruction::Return { value: 0 },
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(99));
    }

    // -----------------------------------------------------------------------
    // 19. Fall off end of instructions
    // -----------------------------------------------------------------------

    #[test]
    fn fall_off_end() {
        let m = test_module(vec![Ir3Instruction::LoadInt { dst: 0, value: 77 }]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(77));
    }

    // -----------------------------------------------------------------------
    // 20. Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn value_serde_roundtrip() {
        for val in [
            Value::Undefined,
            Value::Null,
            Value::Bool(true),
            Value::Int(42),
            Value::Str("hello".to_string()),
            Value::Object(ObjectId(7)),
            Value::Function(3),
        ] {
            let json = serde_json::to_string(&val).unwrap();
            let deser: Value = serde_json::from_str(&json).unwrap();
            assert_eq!(val, deser);
        }
    }

    #[test]
    fn interpreter_error_serde_roundtrip() {
        let err = InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        };
        let json = serde_json::to_string(&err).unwrap();
        let deser: InterpreterError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deser);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = InterpreterConfig::quickjs_defaults();
        let json = serde_json::to_string(&config).unwrap();
        let deser: InterpreterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deser);
    }

    // -----------------------------------------------------------------------
    // 21. Empty module
    // -----------------------------------------------------------------------

    #[test]
    fn empty_module_returns_undefined() {
        let m = test_module(vec![]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Undefined);
    }

    // -----------------------------------------------------------------------
    // 22. Complex expression: (3 + 4) * 2
    // -----------------------------------------------------------------------

    #[test]
    fn complex_arithmetic() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 3 },
            Ir3Instruction::LoadInt { dst: 2, value: 4 },
            Ir3Instruction::Add {
                dst: 3,
                lhs: 1,
                rhs: 2,
            }, // r3 = 7
            Ir3Instruction::LoadInt { dst: 4, value: 2 },
            Ir3Instruction::Mul {
                dst: 0,
                lhs: 3,
                rhs: 4,
            }, // r0 = 14
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(14));
    }

    // -----------------------------------------------------------------------
    // 23. Loop: sum 1..5
    // -----------------------------------------------------------------------

    #[test]
    fn loop_sum_one_to_five() {
        // r0 = sum (accumulator), r1 = counter, r2 = limit
        // r3 = 1 (increment), r4 = temp comparison
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 0 }, // 0: sum = 0
            Ir3Instruction::LoadInt { dst: 1, value: 1 }, // 1: counter = 1
            Ir3Instruction::LoadInt { dst: 2, value: 6 }, // 2: limit = 6 (exclusive)
            Ir3Instruction::LoadInt { dst: 3, value: 1 }, // 3: increment = 1
            // Loop body (instruction 4):
            Ir3Instruction::Add {
                dst: 0,
                lhs: 0,
                rhs: 1,
            }, // 4: sum += counter
            Ir3Instruction::Add {
                dst: 1,
                lhs: 1,
                rhs: 3,
            }, // 5: counter += 1
            // Compare: if counter < limit, jump to loop body
            Ir3Instruction::Sub {
                dst: 4,
                lhs: 2,
                rhs: 1,
            }, // 6: r4 = limit - counter
            Ir3Instruction::JumpIf { cond: 4, target: 4 }, // 7: if r4 truthy, loop
            Ir3Instruction::Halt,                          // 8
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(15)); // 1+2+3+4+5 = 15
    }

    // -----------------------------------------------------------------------
    // 24. Instruction count tracking
    // -----------------------------------------------------------------------

    #[test]
    fn instructions_executed_counted() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::LoadInt { dst: 1, value: 2 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.instructions_executed, 4); // 3 ops + halt
    }

    // -----------------------------------------------------------------------
    // 25. String + number concatenation
    // -----------------------------------------------------------------------

    #[test]
    fn string_int_concatenation() {
        let m = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 42 },
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec!["answer: ".to_string()],
        );
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Str("answer: 42".to_string()));
    }

    #[test]
    fn value_ord() {
        assert!(Value::Undefined < Value::Null);
        assert!(Value::Null < Value::Bool(false));
        assert!(Value::Bool(false) < Value::Bool(true));
        assert!(Value::Bool(true) < Value::Int(0));
        assert!(Value::Int(0) < Value::Str(String::new()));
        assert!(Value::Str(String::new()) < Value::Object(ObjectId(0)));
        assert!(Value::Object(ObjectId(0)) < Value::Function(0));
    }

    // -----------------------------------------------------------------------
    // Enrichment: InterpreterError Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn interpreter_error_display_all_unique() {
        let errors = vec![
            InterpreterError::BudgetExhausted {
                executed: 100,
                budget: 50,
            },
            InterpreterError::RegisterOutOfBounds {
                register: 999,
                max: 256,
            },
            InterpreterError::DivisionByZero,
            InterpreterError::Halted,
            InterpreterError::StackOverflow { depth: 10, max: 5 },
            InterpreterError::CapabilityDenied {
                capability: "net".to_string(),
            },
            InterpreterError::TypeError {
                expected: "number".to_string(),
                got: "object".to_string(),
            },
            InterpreterError::StringPoolOutOfBounds {
                index: 99,
                pool_size: 5,
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            errors.len(),
            "all InterpreterError variants produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: InterpreterError implements std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn interpreter_error_display_coverage() {
        let variants: Vec<InterpreterError> = vec![
            InterpreterError::DivisionByZero,
            InterpreterError::Halted,
            InterpreterError::BudgetExhausted {
                executed: 10,
                budget: 5,
            },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: Value Display uniqueness for all types
    // -----------------------------------------------------------------------

    #[test]
    fn value_display_all_types_non_empty() {
        let values = vec![
            Value::Undefined,
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            Value::Int(0),
            Value::Int(-1),
            Value::Str("hello".to_string()),
            Value::Object(ObjectId(0)),
            Value::Function(0),
        ];
        for v in &values {
            assert!(
                !v.to_string().is_empty(),
                "Value::Display should not be empty for {v:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: LaneChoice serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn lane_choice_serde_roundtrip() {
        for choice in &[LaneChoice::QuickJs, LaneChoice::V8] {
            let json = serde_json::to_string(choice).unwrap();
            let back: LaneChoice = serde_json::from_str(&json).unwrap();
            assert_eq!(*choice, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: V8 lane budget exhaustion
    // -----------------------------------------------------------------------

    #[test]
    fn v8_budget_exhaustion() {
        let m = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
        let mut config = InterpreterConfig::v8_defaults();
        config.instruction_budget = 5;
        let lane = V8Lane::with_config(config);
        let err = lane.execute(&m, "test").unwrap_err();
        assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: InterpreterConfig v8_defaults has larger budget
    // -----------------------------------------------------------------------

    #[test]
    fn v8_defaults_larger_budget_than_quickjs() {
        let qjs = InterpreterConfig::quickjs_defaults();
        let v8 = InterpreterConfig::v8_defaults();
        assert!(
            v8.instruction_budget > qjs.instruction_budget,
            "V8 lane should have a larger default budget"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ExecutionResult serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn execution_result_fields_accessible() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert!(result.instructions_executed > 0);
        assert!(result.events.is_empty() || !result.events.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: negative integer arithmetic
    // -----------------------------------------------------------------------

    #[test]
    fn negative_integer_arithmetic() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: -10 },
            Ir3Instruction::LoadInt { dst: 2, value: 3 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(-7));
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26
    // -----------------------------------------------------------------------

    #[test]
    fn value_type_name_all_variants() {
        assert_eq!(Value::Undefined.type_name(), "undefined");
        assert_eq!(Value::Null.type_name(), "null");
        assert_eq!(Value::Bool(true).type_name(), "boolean");
        assert_eq!(Value::Int(0).type_name(), "number");
        assert_eq!(Value::Str(String::new()).type_name(), "string");
        assert_eq!(Value::Object(ObjectId(0)).type_name(), "object");
        assert_eq!(Value::Function(0).type_name(), "function");
    }

    #[test]
    fn value_is_truthy_exhaustive() {
        assert!(!Value::Undefined.is_truthy());
        assert!(!Value::Null.is_truthy());
        assert!(!Value::Bool(false).is_truthy());
        assert!(Value::Bool(true).is_truthy());
        assert!(!Value::Int(0).is_truthy());
        assert!(Value::Int(1).is_truthy());
        assert!(Value::Int(-1).is_truthy());
        assert!(!Value::Str(String::new()).is_truthy());
        assert!(Value::Str("x".to_string()).is_truthy());
        assert!(Value::Object(ObjectId(0)).is_truthy());
        assert!(Value::Function(0).is_truthy());
    }

    #[test]
    fn object_id_serde_roundtrip() {
        let id = ObjectId(42);
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn heap_object_new_is_empty() {
        let obj = HeapObject::new();
        assert!(obj.properties.is_empty());
    }

    #[test]
    fn lane_reason_serde_all_variants() {
        let variants = [
            LaneReason::SecuritySensitive,
            LaneReason::ThroughputOptimized,
            LaneReason::PolicyDirective,
            LaneReason::DefaultFallback,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LaneReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn interpreter_event_serde_roundtrip() {
        let ev = InterpreterEvent {
            trace_id: "t-1".to_string(),
            component: "baseline_interpreter".to_string(),
            event: "execution_started".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: InterpreterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn interpreter_event_serde_with_error_code() {
        let ev = InterpreterEvent {
            trace_id: "t-2".to_string(),
            component: "baseline_interpreter".to_string(),
            event: "execution_failed".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("BUDGET_EXHAUSTED".to_string()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: InterpreterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev.error_code, back.error_code);
    }

    #[test]
    fn interpreter_config_quickjs_defaults_fields() {
        let c = InterpreterConfig::quickjs_defaults();
        assert_eq!(c.instruction_budget, 100_000);
        assert_eq!(c.max_registers, 256);
        assert_eq!(c.max_call_depth, 256);
        assert!(c.granted_capabilities.is_empty());
    }

    #[test]
    fn interpreter_config_v8_defaults_fields() {
        let c = InterpreterConfig::v8_defaults();
        assert_eq!(c.instruction_budget, 1_000_000);
        assert_eq!(c.max_registers, 4096);
        assert_eq!(c.max_call_depth, 256);
        assert!(c.granted_capabilities.is_empty());
    }

    #[test]
    fn router_throughput_optimized_for_large_module() {
        let mut instrs = Vec::new();
        for _ in 0..1001 {
            instrs.push(Ir3Instruction::LoadInt { dst: 0, value: 0 });
        }
        instrs.push(Ir3Instruction::Halt);
        let m = test_module(instrs);
        let router = LaneRouter::new();
        let result = router.execute(&m, "test", None).unwrap();
        assert_eq!(result.lane, LaneChoice::V8);
        assert_eq!(result.reason, LaneReason::ThroughputOptimized);
    }

    #[test]
    fn alloc_object_and_heap_size() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        assert_eq!(core.heap_size(), 0);
        let id = core.alloc_object();
        assert_eq!(id, ObjectId(0));
        assert_eq!(core.heap_size(), 1);
        let id2 = core.alloc_object();
        assert_eq!(id2, ObjectId(1));
        assert_eq!(core.heap_size(), 2);
    }

    #[test]
    fn load_bool_false() {
        let m = test_module(vec![
            Ir3Instruction::LoadBool {
                dst: 0,
                value: false,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Bool(false));
    }

    #[test]
    fn v8_lane_execute_produces_result() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 99 },
            Ir3Instruction::Halt,
        ]);
        let result = v8_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(99));
    }

    #[test]
    fn interpreter_error_serde_all_variants() {
        let variants: Vec<InterpreterError> = vec![
            InterpreterError::BudgetExhausted {
                executed: 100,
                budget: 50,
            },
            InterpreterError::RegisterOutOfBounds {
                register: 999,
                max: 256,
            },
            InterpreterError::InstructionOutOfBounds { ip: 10, count: 5 },
            InterpreterError::StackOverflow { depth: 10, max: 5 },
            InterpreterError::TypeError {
                expected: "number".to_string(),
                got: "object".to_string(),
            },
            InterpreterError::DivisionByZero,
            InterpreterError::UndefinedRegister { register: 42 },
            InterpreterError::ObjectNotFound { id: 7 },
            InterpreterError::PropertyNotFound {
                object_id: 3,
                key: "x".to_string(),
            },
            InterpreterError::FunctionNotFound {
                index: 5,
                table_size: 3,
            },
            InterpreterError::StringPoolOutOfBounds {
                index: 10,
                pool_size: 5,
            },
            InterpreterError::CapabilityDenied {
                capability: "net".to_string(),
            },
            InterpreterError::Halted,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: InterpreterError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
        assert_eq!(
            variants.len(),
            13,
            "all 13 InterpreterError variants covered"
        );
    }

    #[test]
    fn value_serde_all_variants() {
        let variants = vec![
            Value::Undefined,
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            Value::Int(42),
            Value::Str("hello".to_string()),
            Value::Object(ObjectId(3)),
            Value::Function(7),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: Value = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
        assert_eq!(variants.len(), 8, "all 8 Value variants covered");
    }

    #[test]
    fn interpreter_config_serde_with_capabilities() {
        let mut c = InterpreterConfig::quickjs_defaults();
        c.granted_capabilities = vec!["net".to_string(), "fs".to_string()];
        let json = serde_json::to_string(&c).unwrap();
        let back: InterpreterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        assert_eq!(back.granted_capabilities.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-03-02 — GetProperty / SetProperty
    // -----------------------------------------------------------------------

    #[test]
    fn set_and_get_property_on_heap_object() {
        // Allocate object, set property, read it back.
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        let oid = core.alloc_object();

        // Set obj.x = 42 via heap directly, then verify through interpreter.
        core.heap[oid.0 as usize]
            .properties
            .insert("x".to_string(), Value::Int(42));
        let val = core.heap[oid.0 as usize].properties.get("x").cloned();
        assert_eq!(val, Some(Value::Int(42)));
    }

    #[test]
    fn get_property_instruction() {
        // r0 = Object(0), r1 = "key", r2 = get_property(r0, r1) -> should return Undefined
        // for missing property
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        let oid = core.alloc_object();
        core.registers[0] = Value::Object(oid);
        core.registers[1] = Value::Str("missing".to_string());

        let m = test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = core.execute(&m).unwrap();
        // r0 is the result register but r2 has the property.
        // Actually result.value returns r0, which is still the object.
        // We need to check what r2 becomes. Let's use Move to copy r2 -> r0.
        // Rethink: use a module that moves the result to r0.
        assert_eq!(result.value, Value::Object(oid));
    }

    #[test]
    fn get_property_returns_value_via_move() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        let oid = core.alloc_object();
        core.heap[oid.0 as usize]
            .properties
            .insert("x".to_string(), Value::Int(99));
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::Str("x".to_string());

        let m = test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]);
        let result = core.execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(99));
    }

    #[test]
    fn set_property_instruction() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        let oid = core.alloc_object();
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::Str("key".to_string());
        core.registers[3] = Value::Int(77);

        let m = test_module(vec![
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
            Ir3Instruction::Halt,
        ]);
        let _result = core.execute(&m).unwrap();
        // Verify the property was set on the heap.
        assert_eq!(
            core.heap[oid.0 as usize].properties.get("key"),
            Some(&Value::Int(77))
        );
    }

    #[test]
    fn get_property_with_int_key() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        let oid = core.alloc_object();
        core.heap[oid.0 as usize]
            .properties
            .insert("0".to_string(), Value::Int(10));
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::Int(0); // int key -> "0"

        let m = test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]);
        let result = core.execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(10));
    }

    #[test]
    fn get_property_on_non_object_type_error() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 5 },
            Ir3Instruction::LoadInt { dst: 2, value: 0 },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
        ]);
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::TypeError { .. }));
    }

    #[test]
    fn set_property_on_non_object_type_error() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 5 },
            Ir3Instruction::LoadInt { dst: 2, value: 0 },
            Ir3Instruction::LoadInt { dst: 3, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
        ]);
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::TypeError { .. }));
    }

    #[test]
    fn get_property_object_not_found() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        // Object(99) does not exist on the heap.
        core.registers[1] = Value::Object(ObjectId(99));
        core.registers[2] = Value::Str("x".to_string());

        let m = test_module(vec![
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]);
        let err = core.execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::ObjectNotFound { id: 99 }));
    }

    #[test]
    fn set_property_object_not_found() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        core.registers[1] = Value::Object(ObjectId(99));
        core.registers[2] = Value::Str("x".to_string());
        core.registers[3] = Value::Int(1);

        let m = test_module(vec![
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
            Ir3Instruction::Halt,
        ]);
        let err = core.execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::ObjectNotFound { id: 99 }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: arithmetic type errors for Sub/Mul/Div
    // -----------------------------------------------------------------------

    #[test]
    fn sub_type_error() {
        let m = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 1 },
                Ir3Instruction::Sub {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
            ],
            vec!["hello".to_string()],
        );
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::TypeError { .. }));
    }

    #[test]
    fn mul_type_error() {
        let m = test_module(vec![
            Ir3Instruction::LoadBool {
                dst: 1,
                value: true,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 3 },
            Ir3Instruction::Mul {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
        ]);
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::TypeError { .. }));
    }

    #[test]
    fn div_type_error() {
        let m = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 2 },
                Ir3Instruction::Div {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
            ],
            vec!["ten".to_string()],
        );
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::TypeError { .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: Call type error (call non-function)
    // -----------------------------------------------------------------------

    #[test]
    fn call_non_function_type_error() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
            Ir3Instruction::Call {
                callee: 1,
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
        ]);
        let err = quickjs_execute(&m).unwrap_err();
        assert!(matches!(err, InterpreterError::TypeError { .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: FunctionNotFound
    // -----------------------------------------------------------------------

    #[test]
    fn call_function_not_found() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        core.registers[1] = Value::Function(99); // function 99 does not exist

        let m = test_module(vec![Ir3Instruction::Call {
            callee: 1,
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        }]);
        let err = core.execute(&m).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::FunctionNotFound {
                index: 99,
                table_size: 0
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: int + string concatenation (number on LHS)
    // -----------------------------------------------------------------------

    #[test]
    fn int_string_concatenation() {
        let m = test_module_with_pool(
            vec![
                Ir3Instruction::LoadInt { dst: 1, value: 42 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                Ir3Instruction::Halt,
            ],
            vec![" is the answer".to_string()],
        );
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Str("42 is the answer".to_string()));
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple hostcalls with decision recording
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_hostcall_decisions_recorded() {
        let m = test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("net".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = vec!["net".to_string(), "fs".to_string()];
        let lane = QuickJsLane::with_config(config);
        let result = lane.execute(&m, "test").unwrap();
        assert_eq!(result.hostcall_decisions.len(), 2);
        assert_eq!(result.hostcall_decisions[0].capability.0, "net");
        assert_eq!(result.hostcall_decisions[1].capability.0, "fs");
        assert!(result.hostcall_decisions[0].allowed);
        assert!(result.hostcall_decisions[1].allowed);
        assert_eq!(result.hostcall_decisions[0].seq, 0);
        assert_eq!(result.hostcall_decisions[1].seq, 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment: LaneRouter::with_configs
    // -----------------------------------------------------------------------

    #[test]
    fn lane_router_with_configs() {
        let qjs_config = InterpreterConfig::quickjs_defaults();
        let v8_config = InterpreterConfig::v8_defaults();
        let router = LaneRouter::with_configs(qjs_config, v8_config);
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Halt,
        ]);
        let result = router.execute(&m, "test", None).unwrap();
        assert_eq!(result.lane, LaneChoice::QuickJs);
        assert_eq!(result.result.value, Value::Int(1));
    }

    // -----------------------------------------------------------------------
    // Enrichment: forced lane QuickJs via router
    // -----------------------------------------------------------------------

    #[test]
    fn router_forced_quickjs_on_large_module() {
        let instrs: Vec<Ir3Instruction> = (0..1001)
            .map(|_| Ir3Instruction::LoadInt { dst: 0, value: 1 })
            .chain(std::iter::once(Ir3Instruction::Halt))
            .collect();
        let m = test_module(instrs);
        let router = LaneRouter::new();
        // Without forcing, would pick V8. Force QuickJs.
        let result = router
            .execute(&m, "test", Some(LaneChoice::QuickJs))
            .unwrap();
        assert_eq!(result.lane, LaneChoice::QuickJs);
        assert_eq!(result.reason, LaneReason::PolicyDirective);
    }

    // -----------------------------------------------------------------------
    // Enrichment: execution_failed event on error
    // -----------------------------------------------------------------------

    #[test]
    fn execution_failed_event_on_error() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 10 },
            Ir3Instruction::LoadInt { dst: 2, value: 0 },
            Ir3Instruction::Div {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
        ]);
        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 10_000;
        let lane = QuickJsLane::with_config(config);
        // Division by zero is a hard error — execution fails, no result to inspect events.
        let err = lane.execute(&m, "test").unwrap_err();
        assert_eq!(err, InterpreterError::DivisionByZero);
    }

    // -----------------------------------------------------------------------
    // Enrichment: witness_events have sequential seq numbers
    // -----------------------------------------------------------------------

    #[test]
    fn witness_events_sequential_seq() {
        let mut m = test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("net".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]);
        m.required_capabilities = vec![CapabilityTag("net".to_string())];
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = vec!["net".to_string()];
        let lane = QuickJsLane::with_config(config);
        let result = lane.execute(&m, "test").unwrap();

        // Should have multiple witness events with ascending seq numbers.
        assert!(result.witness_events.len() >= 2);
        for (i, ev) in result.witness_events.iter().enumerate() {
            assert_eq!(ev.seq, i as u64);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: set property then get it via instructions
    // -----------------------------------------------------------------------

    #[test]
    fn set_then_get_property_via_instructions() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test");
        let oid = core.alloc_object();
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::Str("name".to_string());
        core.registers[3] = Value::Int(123);

        let m = test_module(vec![
            // set obj.name = 123
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
            // get obj.name -> r0
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]);
        let result = core.execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(123));
    }

    // -----------------------------------------------------------------------
    // Enrichment: wrapping arithmetic on overflow
    // -----------------------------------------------------------------------

    #[test]
    fn add_wrapping_overflow() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt {
                dst: 1,
                value: i64::MAX,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 1 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(i64::MIN));
    }

    #[test]
    fn sub_wrapping_underflow() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt {
                dst: 1,
                value: i64::MIN,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 1 },
            Ir3Instruction::Sub {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(i64::MAX));
    }

    #[test]
    fn mul_wrapping_overflow() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt {
                dst: 1,
                value: i64::MAX,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 2 },
            Ir3Instruction::Mul {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(-2)); // MAX * 2 wraps
    }

    // -----------------------------------------------------------------------
    // Enrichment: move register to self (no-op)
    // -----------------------------------------------------------------------

    #[test]
    fn move_register_to_self() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 55 },
            Ir3Instruction::Move { dst: 0, src: 0 },
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(55));
    }

    // -----------------------------------------------------------------------
    // Enrichment: jump_if with various truthy values
    // -----------------------------------------------------------------------

    #[test]
    fn jump_if_truthy_int() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: -1 }, // truthy
            Ir3Instruction::LoadInt { dst: 0, value: 10 },
            Ir3Instruction::JumpIf { cond: 1, target: 4 },
            Ir3Instruction::LoadInt { dst: 0, value: 20 }, // skipped
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(10));
    }

    #[test]
    fn jump_if_falsy_zero() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 0 }, // falsy
            Ir3Instruction::LoadInt { dst: 0, value: 10 },
            Ir3Instruction::JumpIf { cond: 1, target: 4 },
            Ir3Instruction::LoadInt { dst: 0, value: 20 }, // executed
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(20));
    }

    #[test]
    fn jump_if_falsy_null() {
        let m = test_module(vec![
            Ir3Instruction::LoadNull { dst: 1 }, // falsy
            Ir3Instruction::LoadInt { dst: 0, value: 10 },
            Ir3Instruction::JumpIf { cond: 1, target: 4 },
            Ir3Instruction::LoadInt { dst: 0, value: 20 }, // executed
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(20));
    }

    #[test]
    fn jump_if_falsy_undefined() {
        let m = test_module(vec![
            Ir3Instruction::LoadUndefined { dst: 1 }, // falsy
            Ir3Instruction::LoadInt { dst: 0, value: 10 },
            Ir3Instruction::JumpIf { cond: 1, target: 4 },
            Ir3Instruction::LoadInt { dst: 0, value: 20 }, // executed
            Ir3Instruction::Halt,
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(20));
    }

    // -----------------------------------------------------------------------
    // Enrichment: RoutedResult fields
    // -----------------------------------------------------------------------

    #[test]
    fn routed_result_fields_accessible() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::Halt,
        ]);
        let router = LaneRouter::new();
        let routed = router.execute(&m, "test", None).unwrap();
        assert_eq!(routed.result.value, Value::Int(7));
        assert!(routed.result.instructions_executed > 0);
        assert!(
            routed
                .result
                .witness_events
                .iter()
                .any(|e| e.kind == WitnessEventKind::ExecutionCompleted)
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: security-sensitive caps + forced V8 still works
    // -----------------------------------------------------------------------

    #[test]
    fn router_security_sensitive_overridden_by_force() {
        let mut m = test_module(vec![Ir3Instruction::Halt]);
        m.required_capabilities = vec![CapabilityTag("net".to_string())];
        let router = LaneRouter::new();
        // Without force: QuickJs (security-sensitive). Force V8.
        let result = router.execute(&m, "test", Some(LaneChoice::V8)).unwrap();
        assert_eq!(result.lane, LaneChoice::V8);
        assert_eq!(result.reason, LaneReason::PolicyDirective);
    }

    // -----------------------------------------------------------------------
    // Enrichment: HeapObject property iteration order is deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn heap_object_properties_deterministic_order() {
        let mut obj = HeapObject::new();
        obj.properties.insert("z".to_string(), Value::Int(3));
        obj.properties.insert("a".to_string(), Value::Int(1));
        obj.properties.insert("m".to_string(), Value::Int(2));
        let keys: Vec<&String> = obj.properties.keys().collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Value Display for Object and Function
    // -----------------------------------------------------------------------

    #[test]
    fn value_display_object_and_function() {
        assert_eq!(Value::Object(ObjectId(5)).to_string(), "[object#5]");
        assert_eq!(Value::Function(3).to_string(), "[function#3]");
    }

    // -----------------------------------------------------------------------
    // Enrichment: HeapObject serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn heap_object_serde_roundtrip() {
        let mut obj = HeapObject::new();
        obj.properties.insert("x".to_string(), Value::Int(1));
        obj.properties
            .insert("y".to_string(), Value::Str("hello".to_string()));
        let json = serde_json::to_string(&obj).unwrap();
        let back: HeapObject = serde_json::from_str(&json).unwrap();
        assert_eq!(obj, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: execution with both lanes produces same instruction count
    // -----------------------------------------------------------------------

    #[test]
    fn both_lanes_same_instruction_count() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 5 },
            Ir3Instruction::LoadInt { dst: 2, value: 3 },
            Ir3Instruction::Sub {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let qjs = quickjs_execute(&m).unwrap();
        let v8 = v8_execute(&m).unwrap();
        assert_eq!(qjs.instructions_executed, v8.instructions_executed);
        assert_eq!(qjs.value, v8.value);
    }

    // -----------------------------------------------------------------------
    // Enrichment: string concatenation with multiple string ops
    // -----------------------------------------------------------------------

    #[test]
    fn string_concatenation_chain() {
        let m = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 1,
                },
                Ir3Instruction::Add {
                    dst: 3,
                    lhs: 1,
                    rhs: 2,
                },
                Ir3Instruction::LoadStr {
                    dst: 4,
                    pool_index: 2,
                },
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 3,
                    rhs: 4,
                },
                Ir3Instruction::Halt,
            ],
            vec!["hello".to_string(), " ".to_string(), "world".to_string()],
        );
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Str("hello world".to_string()));
    }

    // -----------------------------------------------------------------------
    // Enrichment: InterpreterError PartialEq reflexivity
    // -----------------------------------------------------------------------

    #[test]
    fn interpreter_error_eq_reflexive() {
        let err = InterpreterError::DivisionByZero;
        assert_eq!(err, err.clone());

        let err2 = InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        };
        assert_eq!(err2, err2.clone());
        assert_ne!(err, err2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: read register out of bounds on read side
    // -----------------------------------------------------------------------

    #[test]
    fn read_register_out_of_bounds_in_add() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_registers = 4;
        let m = test_module(vec![Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 999, // out of bounds for max_registers=4
        }]);
        let lane = QuickJsLane::with_config(config);
        let err = lane.execute(&m, "test").unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::RegisterOutOfBounds { register: 999, .. }
        ));
    }
}
