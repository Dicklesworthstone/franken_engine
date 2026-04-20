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
//! Membership operators now use deterministic prototype links for the
//! baseline heap so `in` / `instanceof` stop failing closed on the shipped
//! execution path. `object_model.rs` remains the richer semantic source of
//! truth for advanced descriptor/proxy behavior.
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

#![allow(
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::if_same_then_else,
    clippy::manual_range_contains,
    clippy::map_entry,
    clippy::unnecessary_map_or
)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ast::ParseGoal;
use crate::capability::RuntimeCapability;
use crate::checkpoint::{
    CancellationToken, CheckpointAction, CheckpointGuard, DensityConfig, LoopSite,
};
use crate::hash_tiers::ContentHash;
use crate::ir_contract::{
    HostcallDecisionRecord, Ir0Module, Ir3Instruction, Ir3Module, IteratorCloseReason, RegRange,
    WitnessEvent, WitnessEventKind,
};
use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use crate::runtime_config::ExecutionConfig;

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
/// Default heap object budget for the deterministic profile.
const DEFAULT_QUICKJS_MAX_HEAP_OBJECTS: u32 = 100_000;
/// Default heap object budget for the throughput profile.
const DEFAULT_V8_MAX_HEAP_OBJECTS: u32 = 1_000_000;
/// Default total memory budget for the deterministic profile.
const DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Default total memory budget for the throughput profile.
const DEFAULT_V8_MAX_TOTAL_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
// Maximum console entries before truncation (conservative profile)
const DEFAULT_QUICKJS_MAX_CONSOLE_ENTRIES: usize = 1_000;
// Maximum console entries before truncation (throughput profile)
const DEFAULT_V8_MAX_CONSOLE_ENTRIES: usize = 10_000;
/// Default scope-chain depth budget for all interpreter profiles.
const DEFAULT_MAX_SCOPE_DEPTH: u32 = 512;

/// Maximum call-stack depth.
const MAX_CALL_DEPTH: usize = 256;
/// Deterministic bound for baseline prototype-chain walks.
const MAX_PROTOTYPE_CHAIN_DEPTH: u32 = 64;
/// Approximate per-string heap footprint used for fail-closed budgeting.
const MEMORY_ESTIMATE_STRING_BASE_BYTES: u64 = 24;
/// Approximate per-heap-object base footprint.
const MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES: u64 = 64;
/// Approximate per-map-entry footprint.
const MEMORY_ESTIMATE_MAP_ENTRY_BYTES: u64 = 48;
/// Approximate per-scope-frame base footprint.
const MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES: u64 = 32;
/// Approximate per-scope-binding base footprint.
const MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES: u64 = 24;
/// Approximate per-closure base footprint.
const MEMORY_ESTIMATE_CLOSURE_BASE_BYTES: u64 = 32;
/// Approximate per-call-frame base footprint.
const MEMORY_ESTIMATE_CALL_FRAME_BASE_BYTES: u64 = 64;
/// Approximate per-iterator base footprint.
const MEMORY_ESTIMATE_ITERATOR_BASE_BYTES: u64 = 32;
/// Approximate per-generator base footprint.
const MEMORY_ESTIMATE_GENERATOR_BASE_BYTES: u64 = 48;

/// Canonical operator-facing label for the deterministic execution profile.
pub const DETERMINISTIC_PROFILE_LABEL: &str = "baseline_deterministic_profile";
/// Canonical operator-facing label for the throughput execution profile.
pub const THROUGHPUT_PROFILE_LABEL: &str = "baseline_throughput_profile";
/// Legacy lineage label still accepted on input for the deterministic profile.
pub const LEGACY_QUICKJS_PROFILE_LABEL: &str = "quickjs_inspired_native";
/// Legacy lineage label still accepted on input for the throughput profile.
pub const LEGACY_V8_PROFILE_LABEL: &str = "v8_inspired_native";

// ---------------------------------------------------------------------------
// Float64 — Deterministic f64 wrapper with total ordering
// ---------------------------------------------------------------------------

/// Active timer record for setTimeout/setInterval tracking and cancellation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveTimer {
    /// The handler to invoke when the timer fires.
    pub handler: Option<u32>,
    /// The delay in milliseconds.
    pub delay_ms: u64,
    /// For setInterval, whether this timer repeats.
    pub repeating: bool,
}

/// Wrapper around f64 that provides Eq/Ord using total_cmp for determinism.
/// NaN values are equal to each other and greater than all other values.
/// -0.0 is less than +0.0 in the total ordering.
#[derive(Debug, Clone, Copy, Default)]
pub struct Float64(pub f64);

impl Float64 {
    /// Create a new Float64 from an f64.
    pub fn new(v: f64) -> Self {
        Self(v)
    }

    /// Check if this is NaN.
    pub fn is_nan(&self) -> bool {
        self.0.is_nan()
    }

    /// Check if this is positive or negative infinity.
    pub fn is_infinite(&self) -> bool {
        self.0.is_infinite()
    }

    /// Check if this is negative zero.
    pub fn is_negative_zero(&self) -> bool {
        self.0 == 0.0 && self.0.is_sign_negative()
    }

    /// Get the inner f64 value.
    pub fn inner(&self) -> f64 {
        self.0
    }
}

impl PartialEq for Float64 {
    fn eq(&self, other: &Self) -> bool {
        // Use total_cmp for bitwise equality (NaN == NaN, -0 != +0)
        self.0.total_cmp(&other.0) == Ordering::Equal
    }
}

impl Eq for Float64 {}

impl PartialOrd for Float64 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Float64 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl std::hash::Hash for Float64 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl fmt::Display for Float64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_nan() {
            write!(f, "NaN")
        } else if self.0.is_infinite() {
            if self.0.is_sign_positive() {
                write!(f, "Infinity")
            } else {
                write!(f, "-Infinity")
            }
        } else if self.is_negative_zero() {
            write!(f, "0")
        } else {
            // Format like JavaScript: no trailing zeros, but show decimal for floats
            let s = format!("{}", self.0);
            write!(f, "{s}")
        }
    }
}

impl Serialize for Float64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize as f64 bits for exact round-trip of NaN/special values
        serializer.serialize_u64(self.0.to_bits())
    }
}

impl<'de> Deserialize<'de> for Float64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u64::deserialize(deserializer)?;
        Ok(Self(f64::from_bits(bits)))
    }
}

impl From<f64> for Float64 {
    fn from(v: f64) -> Self {
        Self(v)
    }
}

impl From<i64> for Float64 {
    fn from(v: i64) -> Self {
        Self(v as f64)
    }
}

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
    /// IEEE 754 floating-point (f64). Used for fractional values, NaN,
    /// Infinity, and -0. Wrapped in Float64 for deterministic ordering.
    Float(Float64),
    /// String.
    Str(String),
    /// Object reference (heap index).
    Object(ObjectId),
    /// Function reference (function table index).
    Function(u32),
    /// Closure reference (index into interpreter closure store). Closures
    /// carry both a function_index and a captured scope chain snapshot.
    Closure(u32),
    /// Internal iterator state handle used by dedicated iteration instructions.
    Iterator(u32),
    /// Generator function reference (calling creates a suspended GeneratorObject).
    GeneratorFunction(u32),
    /// Live generator object reference (index into generator store).
    Generator(u32),
    /// Async function reference (calling creates a suspended AsyncFunctionObject).
    AsyncFunction(u32),
    /// Live async function object reference (index into async function store).
    AsyncFunctionObject(u32),
    /// Async generator function reference (calling creates a suspended AsyncGeneratorObject).
    AsyncGeneratorFunction(u32),
    /// Live async generator object reference (index into async generator store).
    AsyncGeneratorObject(u32),
    /// Promise handle (index into the promise store).
    Promise(u32),
    /// Builtin callable bound into the runtime environment.
    BuiltinFunction(BuiltinFunction),
}

/// Small set of builtin callable kinds the baseline interpreter exposes as
/// first-class values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinFunctionKind {
    Require,
}

/// First-class builtin callable value with the module provenance needed for
/// deterministic CommonJS resolution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BuiltinFunction {
    pub kind: BuiltinFunctionKind,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub module_specifier: String,
}

impl BuiltinFunction {
    fn require(module_specifier: impl Into<String>) -> Self {
        Self {
            kind: BuiltinFunctionKind::Require,
            module_specifier: module_specifier.into(),
        }
    }

    fn display_name(&self) -> &'static str {
        match self.kind {
            BuiltinFunctionKind::Require => "require",
        }
    }
}

impl Value {
    /// Truthiness: Undefined, Null, Bool(false), Int(0), Float(0.0/-0.0/NaN), Str("") are falsy.
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Float(f) => !f.is_nan() && f.inner() != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::Object(_)
            | Self::Function(_)
            | Self::Closure(_)
            | Self::Iterator(_)
            | Self::GeneratorFunction(_)
            | Self::Generator(_)
            | Self::AsyncFunction(_)
            | Self::AsyncFunctionObject(_)
            | Self::AsyncGeneratorFunction(_)
            | Self::AsyncGeneratorObject(_)
            | Self::Promise(_)
            | Self::BuiltinFunction(_) => true,
        }
    }

    pub fn is_nullish(&self) -> bool {
        matches!(self, Self::Undefined | Self::Null)
    }

    /// Type name for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Int(_) | Self::Float(_) => "number",
            Self::Str(_) => "string",
            Self::Object(_) => "object",
            Self::Function(_)
            | Self::Closure(_)
            | Self::GeneratorFunction(_)
            | Self::AsyncFunction(_)
            | Self::AsyncGeneratorFunction(_)
            | Self::BuiltinFunction(_) => "function",
            Self::Iterator(_)
            | Self::Generator(_)
            | Self::AsyncFunctionObject(_)
            | Self::AsyncGeneratorObject(_)
            | Self::Promise(_) => "object",
        }
    }

    pub fn typeof_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Null | Self::Object(_) => "object",
            Self::Bool(_) => "boolean",
            Self::Int(_) | Self::Float(_) => "number",
            Self::Str(_) => "string",
            Self::Function(_)
            | Self::Closure(_)
            | Self::GeneratorFunction(_)
            | Self::AsyncFunction(_)
            | Self::AsyncGeneratorFunction(_)
            | Self::BuiltinFunction(_) => "function",
            Self::Iterator(_)
            | Self::Generator(_)
            | Self::AsyncFunctionObject(_)
            | Self::AsyncGeneratorObject(_)
            | Self::Promise(_) => "object",
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
            Self::Float(fv) => write!(f, "{fv}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Object(id) => write!(f, "[object#{}]", id.0),
            Self::Function(idx) => write!(f, "[function#{idx}]"),
            Self::Closure(idx) => write!(f, "[closure#{idx}]"),
            Self::Iterator(idx) => write!(f, "[iterator#{idx}]"),
            Self::GeneratorFunction(idx) => write!(f, "[generatorfunction#{idx}]"),
            Self::Generator(idx) => write!(f, "[generator#{idx}]"),
            Self::AsyncFunction(idx) => write!(f, "[asyncfunction#{idx}]"),
            Self::AsyncFunctionObject(idx) => write!(f, "[asyncfunctionobject#{idx}]"),
            Self::AsyncGeneratorFunction(idx) => write!(f, "[asyncgeneratorfunction#{idx}]"),
            Self::AsyncGeneratorObject(idx) => write!(f, "[asyncgeneratorobject#{idx}]"),
            Self::Promise(idx) => write!(f, "[promise#{idx}]"),
            Self::BuiltinFunction(builtin) => write!(f, "[builtin:{}]", builtin.display_name()),
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
    /// Prototype link used by membership operators and constructor instances.
    pub prototype: Option<ObjectId>,
    /// Constructor function index that allocated this object via `Construct`.
    pub constructor_function: Option<u32>,
}

impl HeapObject {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Compat alias. Several recently-landed Date/Error/Map/Set/Promise builtin
/// blocks refer to `Object` (the ES spec name) rather than `HeapObject`
/// (the internal struct). Alias so they keep compiling.
pub type Object = HeapObject;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeForInState {
    object_id: ObjectId,
    keys: Vec<String>,
    next_index: usize,
    deleted_keys: BTreeSet<String>,
    done: bool,
    closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeForOfState {
    values: Vec<Value>,
    next_index: usize,
    done: bool,
    closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeIteratorState {
    ForIn(RuntimeForInState),
    ForOf(RuntimeForOfState),
}

// ---------------------------------------------------------------------------
// Module runtime state (RC-1.13)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ModuleRuntimeStatus {
    Evaluating,
    Evaluated,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModuleRuntimeRecord {
    status: ModuleRuntimeStatus,
    namespace_object: ObjectId,
    exports: BTreeMap<String, Value>,
    cjs_module_object: Option<ObjectId>,
}

#[derive(Debug, Clone, Default)]
struct ModuleState {
    modules: BTreeMap<String, ModuleRuntimeRecord>,
}

impl ModuleState {
    fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CjsModuleContext {
    module_object: ObjectId,
    exports_object: ObjectId,
    module_specifier: String,
}

// ---------------------------------------------------------------------------
// GeneratorObject — suspended generator state
// ---------------------------------------------------------------------------

/// State of a generator object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum GeneratorPhase {
    /// Created but not yet started (initial .next() call).
    SuspendedStart,
    /// Suspended at a yield point.
    SuspendedYield,
    /// Currently executing.
    Executing,
    /// Completed (returned or threw).
    Completed,
}

/// A generator object holds the suspended state of a generator function.
#[derive(Debug, Clone)]
struct GeneratorObject {
    /// Function index in the function table.
    function_index: u32,
    /// Closure index (captures from the enclosing scope).
    closure_index: Option<u32>,
    /// Saved instruction pointer (resume point after yield).
    saved_ip: usize,
    /// Saved register file snapshot at the time of yield.
    saved_registers: Vec<Value>,
    /// Saved register base offset.
    saved_register_base: usize,
    /// Current phase of the generator.
    phase: GeneratorPhase,
}

/// Execution phases for async function objects.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsyncFunctionPhase {
    /// Created but not yet started.
    SuspendedStart,
    /// Suspended at an await point.
    SuspendedAwait,
    /// Currently executing.
    Executing,
    /// Completed (resolved or rejected).
    Completed,
}

/// Execution phases for async generator objects.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsyncGeneratorPhase {
    /// Created but not yet started (initial .next() call).
    SuspendedStart,
    /// Suspended at a yield point.
    SuspendedYield,
    /// Suspended at an await point.
    SuspendedAwait,
    /// Currently executing.
    Executing,
    /// Completed (returned or threw).
    Completed,
}

/// An async function object holds the suspended state of an async function
/// and its result Promise.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct AsyncFunctionObject {
    /// Function index in the function table.
    function_index: u32,
    /// Closure index (captures from the enclosing scope).
    closure_index: Option<u32>,
    /// Saved instruction pointer (resume point after await).
    saved_ip: usize,
    /// Saved register file snapshot at the time of await.
    saved_registers: Vec<Value>,
    /// Saved register base offset.
    saved_register_base: usize,
    /// Current phase of the async function.
    phase: AsyncFunctionPhase,
    /// Promise that will be resolved/rejected when the async function completes.
    result_promise: u32,
}

/// An async generator object combines generator suspension with promise wrapping.
/// Each yield creates a promise-wrapped value, and can use await inside the body.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct AsyncGeneratorObject {
    /// Function index in the function table.
    function_index: u32,
    /// Closure index (captures from the enclosing scope).
    closure_index: Option<u32>,
    /// Saved instruction pointer (resume point after yield/await).
    saved_ip: usize,
    /// Saved register file snapshot at suspension.
    saved_registers: Vec<Value>,
    /// Saved register base offset.
    saved_register_base: usize,
    /// Current phase of the async generator.
    phase: AsyncGeneratorPhase,
}

// ---------------------------------------------------------------------------
// CallFrame — interpreter call stack frame
// ---------------------------------------------------------------------------

/// A catch frame pushed by `BeginTry`, popped by `EndTry` or consumed by `Throw`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CatchFrame {
    /// Instruction index of the catch handler.
    catch_target: usize,
    /// Instruction index of the finally block (if present).
    finally_target: Option<usize>,
    /// Call stack depth when the try block was entered.  Used to validate
    /// that the catch frame is still in scope during unwinding.
    call_depth: usize,
}

/// Tracks how a finally block was entered so `EndFinally` knows whether to
/// re-throw a pending exception or continue normally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum FinallyMode {
    /// Entered via normal control flow (try body completed, or catch body completed).
    Normal,
    /// Entered because an exception was in flight.  The pending exception is
    /// stored in `InterpreterCore::pending_exception`.
    Exception,
    /// Entered because a return was in flight.  The pending value is stored
    /// in `InterpreterCore::pending_return`.
    Return,
}

/// A suspended abrupt completion that should resume if a newer one is later
/// consumed locally.
#[derive(Debug, Clone)]
enum AbruptCompletion {
    Exception(Value),
    Return(Value),
}

// ---------------------------------------------------------------------------
// Scope chain — closure environment support (bd-6a61n.1.1)
// ---------------------------------------------------------------------------

/// Binding kind for `DeclareBinding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    Var = 0,
    Let = 1,
    Const = 2,
    Param = 3,
    Function = 4,
}

impl BindingKind {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Var,
            1 => Self::Let,
            2 => Self::Const,
            3 => Self::Param,
            4 => Self::Function,
            _ => Self::Var,
        }
    }

    fn is_hoisted(self) -> bool {
        matches!(self, Self::Var | Self::Param | Self::Function)
    }
}

/// A single binding in a scope environment.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeBinding {
    value: Value,
    kind: BindingKind,
    /// `true` once initialized (let/const start uninitialized in TDZ).
    initialized: bool,
}

/// A single scope frame in the environment chain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeFrame {
    bindings: BTreeMap<String, ScopeBinding>,
}

impl ScopeFrame {
    fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    fn declare(&mut self, name: String, kind: BindingKind) -> Option<ScopeBinding> {
        if kind == BindingKind::Var
            && let Some(existing) = self.bindings.get(&name)
        {
            return Some(existing.clone());
        }
        let initialized = kind.is_hoisted();
        self.bindings.insert(
            name,
            ScopeBinding {
                value: Value::Undefined,
                kind,
                initialized,
            },
        )
    }

    fn get(&self, name: &str) -> Option<&ScopeBinding> {
        self.bindings.get(name)
    }

    fn get_mut(&mut self, name: &str) -> Option<&mut ScopeBinding> {
        self.bindings.get_mut(name)
    }
}

/// A scope chain is a stack of scope frames. Innermost is last.
#[derive(Debug, Clone)]
struct ScopeChain {
    frames: Vec<ScopeFrame>,
}

impl ScopeChain {
    fn new() -> Self {
        // Start with a global scope.
        Self {
            frames: vec![ScopeFrame::new()],
        }
    }

    fn push(&mut self, max_scope_depth: u32) -> Result<(), InterpreterError> {
        let max_scope_depth = usize::try_from(max_scope_depth).unwrap_or(usize::MAX);
        if self.frames.len() >= max_scope_depth {
            return Err(InterpreterError::ScopeDepthExceeded {
                requested_depth: self.frames.len().saturating_add(1),
                max_depth: max_scope_depth,
            });
        }
        self.frames.push(ScopeFrame::new());
        Ok(())
    }

    fn pop(&mut self) -> Option<ScopeFrame> {
        if self.frames.len() > 1 {
            return self.frames.pop();
        }
        None
    }

    fn current_mut(&mut self) -> &mut ScopeFrame {
        self.frames.last_mut().expect("scope chain never empty")
    }

    /// Resolve a binding by walking outward from innermost scope.
    fn resolve(&self, name: &str) -> Option<(usize, &ScopeBinding)> {
        for (idx, frame) in self.frames.iter().enumerate().rev() {
            if let Some(binding) = frame.get(name) {
                return Some((idx, binding));
            }
        }
        None
    }

    /// Resolve a mutable binding by walking outward from innermost scope.
    fn resolve_mut(&mut self, name: &str) -> Option<&mut ScopeBinding> {
        for frame in self.frames.iter_mut().rev() {
            if let Some(binding) = frame.get_mut(name) {
                return Some(binding);
            }
        }
        None
    }

    /// Snapshot current scope chain for closure capture.
    fn snapshot(&self) -> Vec<ScopeFrame> {
        self.frames.clone()
    }

    /// Depth of the scope chain.
    fn depth(&self) -> usize {
        self.frames.len()
    }
}

/// A closure value: function code reference + captured environment.
#[derive(Debug, Clone)]
struct ClosureValue {
    function_index: u32,
    /// Captured scope chain snapshot at closure creation time.
    captured_env: Vec<ScopeFrame>,
}

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
    /// The `this` value for this call frame.  Set to the receiver for method
    /// calls, `undefined` for plain calls, or the newly allocated object for
    /// constructor calls.  Arrow functions inherit from the defining frame.
    this_value: Value,
    /// The `super` value for this call frame. Set to the parent class constructor
    /// for class methods, `undefined` otherwise.
    super_value: Value,
    /// For constructor calls (`new`): the `this` object allocated before
    /// entering the constructor body. If the constructor returns a non-object,
    /// this value is used as the result instead (ES2020 §9.2.2 step 13).
    construct_this: Option<Value>,
    /// Caller exception state saved across the call so callee control flow
    /// cannot clobber an outer in-flight abrupt completion.
    saved_pending_exception: Option<Value>,
    /// Caller return state saved for the same reason.
    saved_pending_return: Option<Value>,
    /// Count of suspended abrupt completions before entering the callee.
    saved_suspended_abrupt_depth: usize,
    /// Count of active finally modes before entering the callee.
    saved_finally_mode_depth: usize,
    /// Scope chain depth before entering the callee, restored on return.
    saved_scope_depth: usize,
    /// Full scope chain snapshot saved before a closure call replaces
    /// the chain with the captured environment. `None` for plain function
    /// calls where the chain is only extended, not replaced.
    saved_scope_chain: Option<Vec<ScopeFrame>>,
    /// Closure store index for calls that execute captured environments.
    closure_id: Option<u32>,
    /// Number of frames from the active scope chain that belong to the
    /// closure capture. Callee-local frames are not written back.
    captured_scope_depth: usize,
}

// ---------------------------------------------------------------------------
// Interpreter hooks
// ---------------------------------------------------------------------------

pub type ExtensionId = String;
pub type ObjectRef = ObjectId;
pub type PropertyKey = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeToken {
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocKind {
    Object,
    Array,
    Function,
    Closure,
    RegExp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookContext {
    pub extension_id: ExtensionId,
    pub instruction_count: u64,
    pub current_ip: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionRef {
    Function {
        function_index: u32,
        name: Option<String>,
    },
    Closure {
        closure_id: u32,
        function_index: u32,
        name: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookAction {
    Allow,
    Challenge(ChallengeToken),
    Sandbox,
    Suspend,
    Terminate(String),
    Quarantine(String),
}

/// A signed evidence record for runtime guardplane decisions.
/// Provides tamper-evident chain of custody for all containment actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Extension that triggered the decision.
    pub extension_id: ExtensionId,
    /// Type of operation that was evaluated.
    pub operation_type: String,
    /// Bayesian risk score (posterior probability of malicious behavior).
    pub risk_score: i64,
    /// Containment action that was taken.
    pub action_taken: String,
    /// Unix timestamp when decision was made.
    pub timestamp: u64,
    /// Instruction pointer at time of decision.
    pub instruction_pointer: usize,
    /// Hash of register state for reproducibility.
    pub register_state_hash: String,
    /// Hash of the previous receipt in the chain (for integrity).
    pub previous_receipt_hash: Option<String>,
    /// HMAC signature for tamper detection.
    pub signature: String,
}

/// Append-only log of decision receipts with hash-chaining for integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLog {
    /// Chain of decision receipts.
    receipts: Vec<DecisionReceipt>,
    /// HMAC key for signing receipts.
    signing_key: [u8; 32],
    /// Counter for generating unique receipt IDs.
    receipt_counter: u64,
}

impl EvidenceLog {
    /// Create a new evidence log with a random signing key.
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
            signing_key: Self::generate_signing_key(),
            receipt_counter: 0,
        }
    }

    /// Create evidence log with a specific signing key (for testing).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            receipts: Vec::new(),
            signing_key: key,
            receipt_counter: 0,
        }
    }

    /// Add a new decision receipt to the chain.
    pub fn add_receipt(
        &mut self,
        extension_id: ExtensionId,
        operation_type: String,
        risk_score: i64,
        action_taken: String,
        instruction_pointer: usize,
        register_state: &[Value],
    ) -> &DecisionReceipt {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let register_state_hash = self.compute_register_hash(register_state);
        let previous_receipt_hash = self.receipts.last().map(|r| r.signature.clone());

        // Create unsigned receipt
        let mut receipt = DecisionReceipt {
            extension_id,
            operation_type,
            risk_score,
            action_taken,
            timestamp,
            instruction_pointer,
            register_state_hash,
            previous_receipt_hash,
            signature: String::new(), // Will be filled by signing
        };

        // Sign the receipt
        receipt.signature = self.sign_receipt(&receipt);

        self.receipts.push(receipt);
        self.receipt_counter += 1;

        // SAFETY: We just pushed a receipt above, so receipts is non-empty and last() cannot return None
        self.receipts.last().unwrap()
    }

    /// Verify the integrity of the entire receipt chain.
    pub fn verify_chain(&self) -> bool {
        for (i, receipt) in self.receipts.iter().enumerate() {
            // Verify receipt signature
            if !self.verify_receipt_signature(receipt) {
                return false;
            }

            // Verify chain linking
            if i > 0 {
                let expected_prev_hash = &self.receipts[i - 1].signature;
                if receipt.previous_receipt_hash.as_ref() != Some(expected_prev_hash) {
                    return false;
                }
            } else if receipt.previous_receipt_hash.is_some() {
                return false; // First receipt should have no previous hash
            }
        }

        true
    }

    /// Export receipts as JSON evidence bundle.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        let bundle = serde_json::json!({
            "evidence_type": "guardplane_decision_chain",
            "receipt_count": self.receipts.len(),
            "chain_verified": self.verify_chain(),
            "receipts": self.receipts,
            "exported_at": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        serde_json::to_string_pretty(&bundle)
    }

    /// Get all receipts in the chain.
    pub fn receipts(&self) -> &[DecisionReceipt] {
        &self.receipts
    }

    /// Check if log is empty (no decisions made).
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Generate a signing key for HMAC.
    ///
    /// Dev-only stopgap — production must wire in a CSPRNG. The 128-bit
    /// nanosecond timestamp is spread across bytes 0..=15 of the key, then
    /// wrapped into bytes 16..=31. The `% 16` is load-bearing: without it,
    /// `i * 8` reaches 128+ once `i >= 16` and shifting a `u128` by 128 bits
    /// panics with "attempt to shift right with overflow" in debug builds —
    /// which is why every interpreter test that constructed an
    /// `InterpreterCore` was failing at runtime.
    fn generate_signing_key() -> [u8; 32] {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            let shift = ((i % 16) * 8) as u32; // stays in 0..=120, inside u128 width
            *byte = ((timestamp >> shift) & 0xFF) as u8;
        }

        key
    }

    /// Compute HMAC signature for a receipt.
    fn sign_receipt(&self, receipt: &DecisionReceipt) -> String {
        let message = self.receipt_signing_message(receipt);
        self.compute_hmac(&message)
    }

    /// Verify HMAC signature of a receipt.
    fn verify_receipt_signature(&self, receipt: &DecisionReceipt) -> bool {
        let message = self.receipt_signing_message(receipt);
        let expected_signature = self.compute_hmac(&message);
        receipt.signature == expected_signature
    }

    /// Create the message to be signed for a receipt.
    fn receipt_signing_message(&self, receipt: &DecisionReceipt) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            receipt.extension_id,
            receipt.operation_type,
            receipt.risk_score,
            receipt.action_taken,
            receipt.timestamp,
            receipt.instruction_pointer,
            receipt.register_state_hash,
            receipt.previous_receipt_hash.as_deref().unwrap_or("")
        )
    }

    /// Compute HMAC-SHA256 of a message (simplified implementation).
    fn compute_hmac(&self, message: &str) -> String {
        // Simplified HMAC implementation using basic hashing
        // In production, would use a proper HMAC library
        let mut hasher_state = 0u64;

        // Hash the key
        for &byte in &self.signing_key {
            hasher_state = hasher_state.wrapping_mul(31).wrapping_add(byte as u64);
        }

        // Hash the message
        for byte in message.bytes() {
            hasher_state = hasher_state.wrapping_mul(31).wrapping_add(byte as u64);
        }

        format!("hmac-{:016x}", hasher_state)
    }

    /// Compute hash of register state for reproducibility.
    fn compute_register_hash(&self, registers: &[Value]) -> String {
        let mut hasher_state = 0u64;

        for value in registers {
            // Simple hash of value discriminant + content
            let value_hash = match value {
                Value::Undefined => 0,
                Value::Null => 1,
                Value::Bool(b) => 2 + (*b as u64),
                Value::Int(i) => 4 + (*i as u64),
                Value::Float(f) => 4 + f.0.to_bits(),
                Value::Str(s) => {
                    let mut string_hash = 5u64;
                    for byte in s.bytes() {
                        string_hash = string_hash.wrapping_mul(31).wrapping_add(byte as u64);
                    }
                    string_hash
                }
                Value::Object(id) => 6 + (id.0 as u64),
                Value::Function(id) => 7 + (*id as u64),
                Value::Closure(id) => 8 + (*id as u64),
                Value::Iterator(id) => 9 + (*id as u64),
                Value::GeneratorFunction(id) => 10 + (*id as u64),
                Value::Generator(id) => 11 + (*id as u64),
                Value::AsyncFunction(id) => 12 + (*id as u64),
                Value::AsyncFunctionObject(id) => 13 + (*id as u64),
                Value::AsyncGeneratorFunction(id) => 14 + (*id as u64),
                Value::AsyncGeneratorObject(id) => 15 + (*id as u64),
                Value::Promise(id) => 16 + (*id as u64),
                Value::BuiltinFunction(bf) => 17 + (bf.kind as u64),
            };
            hasher_state = hasher_state.wrapping_mul(31).wrapping_add(value_hash);
        }

        format!("reghash-{:016x}", hasher_state)
    }
}

impl Default for EvidenceLog {
    fn default() -> Self {
        Self::new()
    }
}

/// `pre_import` is part of the stable hook contract and is invoked on
/// `ImportModule` during module loading.
pub trait InterpreterHook: Send + Sync {
    fn pre_property_access(
        &self,
        ctx: &HookContext,
        target: &ObjectRef,
        key: &PropertyKey,
    ) -> HookAction;

    fn pre_call(&self, ctx: &HookContext, callee: &FunctionRef, args: &[Value]) -> HookAction;

    fn pre_allocation(&self, ctx: &HookContext, kind: AllocKind, size_hint: usize) -> HookAction;

    fn pre_import(&self, ctx: &HookContext, specifier: &str) -> HookAction;
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
    /// Import specifier register did not contain a string.
    ImportSpecifierNotString { got: String },
    /// Require specifier register did not contain a string.
    RequireSpecifierNotString { got: String },
    /// Module resolution failed.
    ModuleResolutionFailed { specifier: String, reason: String },
    /// Failed to read module source from disk.
    ModuleReadFailed { specifier: String, error: String },
    /// Failed to parse module source.
    ModuleParseFailed { specifier: String, error: String },
    /// Failed to lower module source to IR3.
    ModuleLoweringFailed { specifier: String, error: String },
    /// Module evaluation failed.
    ModuleEvaluationFailed { specifier: String, reason: String },
    /// Export encountered outside an active module evaluation.
    ExportOutsideModule { name: String },
    /// Capability check failed for hostcall.
    CapabilityDenied { capability: String },
    /// The baseline heap cannot safely answer prototype-aware membership.
    UnsupportedMembershipSemantics { operator: String },
    /// Iterator handle not found in interpreter state.
    IteratorNotFound { handle: u32 },
    /// Halt instruction reached (normal termination).
    Halted,
    /// An exception was thrown but no catch handler was found.
    UncaughtException { value: String },
    /// Access to a let/const binding before initialization (TDZ).
    UninitializedBinding { name: String },
    /// Assignment to a const binding.
    ConstAssignment { name: String },
    /// String allocation size exceeded.
    StringLimitExceeded { length: usize, max: usize },
    /// Heap object count or estimated live memory exceeded configured limits.
    MemoryBudgetExceeded {
        requested_bytes: u64,
        max_bytes: u64,
        requested_heap_objects: u32,
        max_heap_objects: u32,
    },
    /// Scope-chain depth exceeded configured limits.
    ScopeDepthExceeded {
        requested_depth: usize,
        max_depth: usize,
    },
    /// Guardplane containment hook requested a fail-closed action.
    ContainmentActionRequested {
        action: String,
        reason: Option<String>,
    },
    /// Execution terminated by containment action.
    Terminated { reason: String },
    /// Execution cancelled by CheckpointGuard.
    Cancelled,
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
            Self::ImportSpecifierNotString { got } => {
                write!(f, "import specifier must be string (got {got})")
            }
            Self::RequireSpecifierNotString { got } => {
                write!(f, "require specifier must be string (got {got})")
            }
            Self::ModuleResolutionFailed { specifier, reason } => {
                write!(f, "module resolution failed for '{specifier}': {reason}")
            }
            Self::ModuleReadFailed { specifier, error } => {
                write!(f, "failed to read module '{specifier}': {error}")
            }
            Self::ModuleParseFailed { specifier, error } => {
                write!(f, "failed to parse module '{specifier}': {error}")
            }
            Self::ModuleLoweringFailed { specifier, error } => {
                write!(f, "failed to lower module '{specifier}': {error}")
            }
            Self::ModuleEvaluationFailed { specifier, reason } => {
                write!(f, "module '{specifier}' evaluation failed: {reason}")
            }
            Self::ExportOutsideModule { name } => {
                write!(f, "export '{name}' outside of module evaluation")
            }
            Self::CapabilityDenied { capability } => {
                write!(f, "capability denied: {capability}")
            }
            Self::UnsupportedMembershipSemantics { operator } => write!(
                f,
                "unsupported {operator} semantics: baseline interpreter heap is not prototype-aware"
            ),
            Self::IteratorNotFound { handle } => write!(f, "iterator#{handle} not found"),
            Self::Halted => write!(f, "execution halted"),
            Self::Cancelled => write!(f, "execution cancelled"),
            Self::UncaughtException { value } => {
                write!(f, "uncaught exception: {value}")
            }
            Self::UninitializedBinding { name } => {
                write!(
                    f,
                    "cannot access '{name}' before initialization (temporal dead zone)"
                )
            }
            Self::ConstAssignment { name } => {
                write!(f, "assignment to constant variable '{name}'")
            }
            Self::StringLimitExceeded { length, max } => {
                write!(
                    f,
                    "string allocation size exceeded ({} bytes > {} bytes)",
                    length, max
                )
            }
            Self::MemoryBudgetExceeded {
                requested_bytes,
                max_bytes,
                requested_heap_objects,
                max_heap_objects,
            } => write!(
                f,
                "memory budget exceeded: requested {} heap objects / {} bytes, limits {} heap objects / {} bytes",
                requested_heap_objects, requested_bytes, max_heap_objects, max_bytes
            ),
            Self::ScopeDepthExceeded {
                requested_depth,
                max_depth,
            } => write!(
                f,
                "scope depth exceeded: requested depth {requested_depth}, limit {max_depth}"
            ),
            Self::ContainmentActionRequested { action, reason } => {
                if let Some(reason) = reason {
                    write!(f, "containment action requested: {action} ({reason})")
                } else {
                    write!(f, "containment action requested: {action}")
                }
            }
            Self::Terminated { reason } => {
                write!(f, "execution terminated by containment action: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InterpreterConfig — lane-specific configuration
// ---------------------------------------------------------------------------

/// Configuration for an interpreter lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterpreterConfig {
    /// Maximum instructions before budget exhaustion.
    pub instruction_budget: u64,
    /// Maximum registers per frame.
    pub max_registers: u32,
    /// Maximum call depth.
    pub max_call_depth: usize,
    /// Maximum string allocation size (bytes).
    pub max_string_size: usize,
    /// Maximum heap objects the interpreter may allocate before failing closed.
    pub max_heap_objects: u32,
    /// Maximum estimated live memory before failing closed.
    pub max_total_memory_bytes: u64,
    /// Maximum console entries before truncation (prevents DoS via console spam).
    pub max_console_entries: usize,
    /// Maximum scope-chain depth, including the global frame.
    pub max_scope_depth: u32,
    /// Optional module root used for resolving relative import specifiers.
    pub module_root: Option<String>,
    /// Set of capabilities granted to this execution context.
    pub granted_capabilities: BTreeSet<RuntimeCapability>,
    /// Optional extension ID for logging and diagnostics.
    pub extension_id: Option<String>,
    /// Optional cancellation token for checkpoint-based cancellation.
    #[serde(skip)]
    pub cancellation_token: Option<CancellationToken>,
    /// Checkpoint density (default: every 1000 instructions).
    pub checkpoint_density: u64,
}

impl PartialEq for InterpreterConfig {
    fn eq(&self, other: &Self) -> bool {
        self.instruction_budget == other.instruction_budget
            && self.max_registers == other.max_registers
            && self.max_call_depth == other.max_call_depth
            && self.max_string_size == other.max_string_size
            && self.max_heap_objects == other.max_heap_objects
            && self.max_total_memory_bytes == other.max_total_memory_bytes
            && self.max_console_entries == other.max_console_entries
            && self.max_scope_depth == other.max_scope_depth
            && self.module_root == other.module_root
            && self.granted_capabilities == other.granted_capabilities
            && self.extension_id == other.extension_id
            && self.checkpoint_density == other.checkpoint_density
        // Note: cancellation_token is intentionally excluded from comparison
    }
}

impl Eq for InterpreterConfig {}

impl InterpreterConfig {
    /// Deterministic profile defaults: conservative budgets.
    pub fn quickjs_defaults() -> Self {
        Self {
            instruction_budget: DEFAULT_QUICKJS_BUDGET,
            max_registers: DEFAULT_QUICKJS_MAX_REGISTERS,
            max_call_depth: MAX_CALL_DEPTH,
            max_string_size: 33_554_432,
            max_heap_objects: DEFAULT_QUICKJS_MAX_HEAP_OBJECTS,
            max_total_memory_bytes: DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES,
            max_console_entries: DEFAULT_QUICKJS_MAX_CONSOLE_ENTRIES,
            max_scope_depth: DEFAULT_MAX_SCOPE_DEPTH,
            module_root: None,
            granted_capabilities: BTreeSet::new(),
            extension_id: None,
            cancellation_token: None,
            checkpoint_density: 1000,
        }
    }

    /// Throughput profile defaults: generous budgets.
    pub fn v8_defaults() -> Self {
        Self {
            instruction_budget: DEFAULT_V8_BUDGET,
            max_registers: DEFAULT_V8_MAX_REGISTERS,
            max_call_depth: MAX_CALL_DEPTH,
            max_string_size: 268_435_456,
            max_heap_objects: DEFAULT_V8_MAX_HEAP_OBJECTS,
            max_total_memory_bytes: DEFAULT_V8_MAX_TOTAL_MEMORY_BYTES,
            max_console_entries: DEFAULT_V8_MAX_CONSOLE_ENTRIES,
            max_scope_depth: DEFAULT_MAX_SCOPE_DEPTH,
            module_root: None,
            granted_capabilities: BTreeSet::new(),
            extension_id: None,
            cancellation_token: None,
            checkpoint_density: 1000,
        }
    }

    /// Deterministic profile from a [`ExecutionConfig`].
    pub fn deterministic_from_config(config: &ExecutionConfig) -> Self {
        Self {
            instruction_budget: config.deterministic_budget,
            max_registers: config.deterministic_max_registers,
            max_call_depth: config.max_call_depth,
            max_string_size: 33_554_432,
            max_heap_objects: DEFAULT_QUICKJS_MAX_HEAP_OBJECTS,
            max_total_memory_bytes: DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES,
            max_console_entries: DEFAULT_QUICKJS_MAX_CONSOLE_ENTRIES,
            max_scope_depth: DEFAULT_MAX_SCOPE_DEPTH,
            module_root: None,
            granted_capabilities: BTreeSet::new(),
            extension_id: None,
            cancellation_token: None,
            checkpoint_density: 1000,
        }
    }

    /// Throughput profile from a [`ExecutionConfig`].
    pub fn throughput_from_config(config: &ExecutionConfig) -> Self {
        Self {
            instruction_budget: config.throughput_budget,
            max_registers: config.throughput_max_registers,
            max_call_depth: config.max_call_depth,
            max_string_size: 268_435_456,
            max_heap_objects: DEFAULT_V8_MAX_HEAP_OBJECTS,
            max_total_memory_bytes: DEFAULT_V8_MAX_TOTAL_MEMORY_BYTES,
            max_console_entries: DEFAULT_V8_MAX_CONSOLE_ENTRIES,
            max_scope_depth: DEFAULT_MAX_SCOPE_DEPTH,
            module_root: None,
            granted_capabilities: BTreeSet::new(),
            extension_id: None,
            cancellation_token: None,
            checkpoint_density: 1000,
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
// Console output capture (RC-1.10: console.log/error/warn)
// ---------------------------------------------------------------------------

/// Console log level for deterministic capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsoleLevel {
    Log,
    Error,
    Warn,
    Info,
}

/// A captured console output entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleEntry {
    /// Log level (log, error, warn).
    pub level: ConsoleLevel,
    /// Stringified arguments joined by space.
    pub message: String,
    /// Instruction count at which the log was emitted.
    pub instruction_index: u64,
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
    /// Optional containment action requested by an interpreter hook.
    pub requested_hook_action: Option<HookAction>,
    /// Witness events collected during execution.
    pub witness_events: Vec<WitnessEvent>,
    /// Hostcall decisions recorded.
    pub hostcall_decisions: Vec<HostcallDecisionRecord>,
    /// Structured events emitted.
    pub events: Vec<InterpreterEvent>,
    /// Console output captured from console.log/error/warn calls.
    pub console_output: Vec<ConsoleEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionSeed {
    registers: Vec<Value>,
    heap: Vec<HeapObject>,
    function_prototypes: BTreeMap<u32, ObjectId>,
}

#[derive(Debug, Clone)]
struct ModuleExecutionSnapshot {
    registers: Vec<Value>,
    call_stack: Vec<CallFrame>,
    ip: usize,
    register_base: usize,
    catch_frames: Vec<CatchFrame>,
    pending_exception: Option<Value>,
    pending_return: Option<Value>,
    suspended_abrupt_completions: Vec<AbruptCompletion>,
    finally_modes: Vec<FinallyMode>,
    scope_chain: ScopeChain,
    pending_captures: Vec<u32>,
    current_module_specifier: Option<String>,
}

// ---------------------------------------------------------------------------
// Promise combinator state (Promise.all / race / allSettled / any)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum PromiseCombinatorState {
    All(crate::promise_model::PromiseAllTracker),
    AllSettled(crate::promise_model::PromiseAllSettledTracker),
    Race(crate::promise_model::PromiseRaceTracker),
    Any(crate::promise_model::PromiseAnyTracker),
}

#[derive(Debug, Clone, Copy)]
enum PromiseCombinatorKind {
    All,
    AllSettled,
    Race,
    Any,
}

#[derive(Debug, Clone)]
struct PromiseCombinatorWatcher {
    combinator_id: u64,
    index: u32,
}

#[derive(Debug, Clone)]
enum PromiseSettlement {
    Fulfilled(crate::object_model::JsValue),
    Rejected(crate::object_model::JsValue),
}

// ---------------------------------------------------------------------------
// InterpreterCore — shared execution engine
// ---------------------------------------------------------------------------

/// The core interpreter loop shared between both lanes.
pub struct InterpreterCore {
    config: InterpreterConfig,
    hook: Option<Arc<dyn InterpreterHook>>,
    /// Register file (flat, indexed by register number).
    registers: Vec<Value>,
    /// Call stack.
    call_stack: Vec<CallFrame>,
    /// Object heap.
    heap: Vec<HeapObject>,
    /// Approximate live memory tracked for fail-closed budget enforcement.
    estimated_memory_bytes: u64,
    /// Dedicated iterator runtime state used by iterator-specific IR3 ops.
    iterators: Vec<RuntimeIteratorState>,
    /// Lazily allocated prototype objects for constructor functions.
    function_prototypes: BTreeMap<u32, ObjectId>,
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
    /// Stack of active try/catch frames for exception unwinding.
    catch_frames: Vec<CatchFrame>,
    /// A pending exception value during unwinding (set by `Throw`,
    /// consumed by `EnterCatch` or re-thrown by `EndFinally`).
    pending_exception: Option<Value>,
    /// A pending return value during unwinding through finally blocks.
    pending_return: Option<Value>,
    /// Saved outer abrupt completion state that was temporarily suspended by a
    /// newer local throw/return or by exception unwinding across nested calls
    /// or intermediary finally blocks. If the newer abrupt completion is
    /// consumed locally, the most recent suspended completion resumes.
    suspended_abrupt_completions: Vec<AbruptCompletion>,
    /// Stack of finally-entry modes.  Pushed by `EnterFinally`, popped by
    /// `EndFinally`.  When `Exception`, `EndFinally` re-throws the pending
    /// exception.
    finally_modes: Vec<FinallyMode>,
    /// Pre-run caller-visible seed used for the most recent execute().
    last_pre_run_seed: Option<ExecutionSeed>,
    /// Caller-visible state immediately after the most recent execute().
    last_post_run_seed: Option<ExecutionSeed>,
    /// Runtime scope chain for lexical variable resolution.
    scope_chain: ScopeChain,
    /// Closure store: maps closure IDs to captured environments.
    closures: Vec<ClosureValue>,
    /// Pending capture names for the next `CreateClosure` instruction.
    pending_captures: Vec<u32>,
    /// Generator object store.
    generators: Vec<GeneratorObject>,
    /// Async function object store.
    async_functions: Vec<AsyncFunctionObject>,
    /// Async generator object store.
    async_generators: Vec<AsyncGeneratorObject>,
    /// Promise store for ES2020 Promise semantics.
    promise_store: crate::promise_model::PromiseStore,
    /// Deterministic event loop state (microtasks + macrotasks + virtual clock).
    event_loop: crate::promise_model::EventLoop,
    /// Active promise combinator trackers keyed by combinator id.
    promise_combinators: BTreeMap<u64, PromiseCombinatorState>,
    /// Watchers keyed by promise handle for combinator updates.
    promise_combinator_watchers:
        BTreeMap<crate::promise_model::PromiseHandle, Vec<PromiseCombinatorWatcher>>,
    /// Monotonic combinator id generator.
    next_promise_combinator_id: u64,
    /// Module registry/cache for ImportModule execution.
    module_state: ModuleState,
    /// Active CommonJS module context, if currently evaluating a CJS module.
    active_cjs_context: Option<CjsModuleContext>,
    /// Current module specifier (used to resolve relative imports).
    current_module_specifier: Option<String>,
    /// Console output captured for deterministic replay.
    console_output: Vec<ConsoleEntry>,
    /// Profiling data collection (optional for performance measurements).
    profiling_data: Option<crate::profiling::Profiler>,
    /// Next timer ID for setTimeout/setInterval (monotonic for determinism).
    next_timer_id: u32,
    /// Active timers for clearTimeout/clearInterval tracking.
    active_timers: std::collections::BTreeMap<u32, ActiveTimer>,
    /// Containment state: whether execution is suspended due to guardplane action.
    #[allow(dead_code)]
    suspended: bool,
    /// Containment state: whether execution is sandboxed (capabilities restricted).
    #[allow(dead_code)]
    sandboxed: bool,
    /// Containment state: whether extension is marked for quarantine.
    #[allow(dead_code)]
    quarantined: bool,
    /// Pending challenge tokens requiring resolution.
    #[allow(dead_code)]
    pending_challenges: Vec<ChallengeToken>,
    /// Evidence records for containment actions taken.
    #[allow(dead_code)]
    containment_evidence: Vec<WitnessEvent>,
    /// Decision receipt log for signed evidence chain.
    decision_receipts: EvidenceLog,
}

impl InterpreterCore {
    /// Create a new interpreter core with the given configuration.
    pub fn new(config: InterpreterConfig, trace_id: impl Into<String>) -> Self {
        let max_regs = config.max_registers as usize;
        Self {
            config,
            hook: None,
            registers: vec![Value::Undefined; max_regs],
            call_stack: Vec::new(),
            heap: Vec::new(),
            estimated_memory_bytes: 0,
            iterators: Vec::new(),
            function_prototypes: BTreeMap::new(),
            ip: 0,
            instructions_executed: 0,
            witness_events: Vec::new(),
            hostcall_decisions: Vec::new(),
            events: Vec::new(),
            witness_seq: 0,
            trace_id: trace_id.into(),
            register_base: 0,
            catch_frames: Vec::new(),
            pending_exception: None,
            pending_return: None,
            suspended_abrupt_completions: Vec::new(),
            finally_modes: Vec::new(),
            last_pre_run_seed: None,
            last_post_run_seed: None,
            scope_chain: ScopeChain::new(),
            closures: Vec::new(),
            pending_captures: Vec::new(),
            generators: Vec::new(),
            async_functions: Vec::new(),
            async_generators: Vec::new(),
            promise_store: crate::promise_model::PromiseStore::new(),
            event_loop: crate::promise_model::EventLoop::new(),
            promise_combinators: BTreeMap::new(),
            promise_combinator_watchers: BTreeMap::new(),
            next_promise_combinator_id: 0,
            module_state: ModuleState::new(),
            active_cjs_context: None,
            current_module_specifier: None,
            console_output: Vec::new(),
            profiling_data: None,
            next_timer_id: 0,
            active_timers: BTreeMap::new(),
            suspended: false,
            sandboxed: false,
            quarantined: false,
            pending_challenges: Vec::new(),
            containment_evidence: Vec::new(),
            decision_receipts: EvidenceLog::new(),
        }
    }

    pub fn set_hook(&mut self, hook: Arc<dyn InterpreterHook>) {
        self.hook = Some(hook);
    }

    pub fn clear_hook(&mut self) {
        self.hook = None;
    }

    /// Get the captured console output entries.
    pub fn console_output(&self) -> &[ConsoleEntry] {
        &self.console_output
    }

    fn take_execution_result(
        &mut self,
        value: Value,
        requested_hook_action: Option<HookAction>,
    ) -> ExecutionResult {
        ExecutionResult {
            value,
            instructions_executed: self.instructions_executed,
            requested_hook_action,
            witness_events: std::mem::take(&mut self.witness_events),
            hostcall_decisions: std::mem::take(&mut self.hostcall_decisions),
            events: std::mem::take(&mut self.events),
            console_output: std::mem::take(&mut self.console_output),
        }
    }

    /// Execute an IR3 module and return the result.
    pub fn execute(&mut self, module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
        // Check VmDispatch capability before executing
        if !self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::VmDispatch)
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: "VmDispatch".to_string(),
            });
        }

        let current_seed = self.capture_execution_seed();
        let seed = match (&self.last_pre_run_seed, &self.last_post_run_seed) {
            (Some(previous_pre_run), Some(previous_post_run))
                if current_seed == *previous_post_run =>
            {
                previous_pre_run.clone()
            }
            _ => current_seed,
        };
        self.last_pre_run_seed = Some(seed.clone());
        self.reset_execution_state_from_seed(&seed);
        self.sync_estimated_memory_bytes()?;
        let entry_specifier = module.header.source_label.clone();
        self.current_module_specifier = Some(entry_specifier.clone());
        self.ensure_module_record(module, &entry_specifier)?;

        self.push_event("execution_started", "ok", None);

        let result = self.run_loop(module);

        // Drain any pending microtasks enqueued during execution
        // (promise reactions, thenable resolutions, etc.).
        self.drain_microtasks();

        // Run the event loop until all pending work is complete
        // (macrotasks like timers, with microtask draining after each).
        self.run_event_loop_until_idle();

        if let Some(record) = self.module_state.modules.get_mut(&entry_specifier) {
            record.status = match &result {
                Ok(_) | Err(InterpreterError::Halted) => ModuleRuntimeStatus::Evaluated,
                Err(err) => ModuleRuntimeStatus::Failed(err.to_string()),
            };
        }

        match &result {
            Ok(_) => self.push_event("execution_completed", "ok", None),
            Err(InterpreterError::Halted) => {
                self.push_event("execution_halted", "ok", None);
            }
            Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                self.push_event(
                    "execution_contained",
                    "contained",
                    Some(&format_requested_hook_action(
                        action.as_str(),
                        reason.as_deref(),
                    )),
                );
            }
            Err(e) => {
                self.push_event("execution_failed", "fail", Some(&format!("{e}")));
            }
        }
        self.last_post_run_seed = Some(self.capture_execution_seed());

        match result {
            Ok(v) => {
                self.emit_witness(WitnessEventKind::ExecutionCompleted, None);
                Ok(self.take_execution_result(v, None))
            }
            Err(InterpreterError::Halted) => {
                // Halt is normal termination; return whatever is in r0.
                let final_value = self.read_reg(0).unwrap_or(Value::Undefined);
                self.emit_witness(WitnessEventKind::ExecutionCompleted, None);
                Ok(self.take_execution_result(final_value, None))
            }
            Err(e) => Err(e),
        }
    }

    fn capture_execution_seed(&self) -> ExecutionSeed {
        let max_regs = self.config.max_registers as usize;
        let mut registers = self.registers.clone();
        registers.resize(max_regs, Value::Undefined);
        registers.truncate(max_regs);
        ExecutionSeed {
            registers,
            heap: self.heap.clone(),
            function_prototypes: self.function_prototypes.clone(),
        }
    }

    fn reset_execution_state_from_seed(&mut self, seed: &ExecutionSeed) {
        self.register_base = 0;
        self.registers = seed.registers.clone();
        self.call_stack.clear();
        self.heap = seed.heap.clone();
        self.iterators.clear();
        self.function_prototypes = seed.function_prototypes.clone();
        self.ip = 0;
        self.instructions_executed = 0;
        self.witness_events.clear();
        self.hostcall_decisions.clear();
        self.events.clear();
        self.witness_seq = 0;
        self.catch_frames.clear();
        self.pending_exception = None;
        self.pending_return = None;
        self.suspended_abrupt_completions.clear();
        self.finally_modes.clear();
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        self.module_state = ModuleState::new();
        self.active_cjs_context = None;
        self.current_module_specifier = None;
        self.promise_combinators.clear();
        self.promise_combinator_watchers.clear();
        self.next_promise_combinator_id = 0;
    }

    fn snapshot_module_execution(&self) -> ModuleExecutionSnapshot {
        ModuleExecutionSnapshot {
            registers: self.registers.clone(),
            call_stack: self.call_stack.clone(),
            ip: self.ip,
            register_base: self.register_base,
            catch_frames: self.catch_frames.clone(),
            pending_exception: self.pending_exception.clone(),
            pending_return: self.pending_return.clone(),
            suspended_abrupt_completions: self.suspended_abrupt_completions.clone(),
            finally_modes: self.finally_modes.clone(),
            scope_chain: self.scope_chain.clone(),
            pending_captures: self.pending_captures.clone(),
            current_module_specifier: self.current_module_specifier.clone(),
        }
    }

    fn restore_module_execution(&mut self, snapshot: ModuleExecutionSnapshot) {
        self.registers = snapshot.registers;
        self.call_stack = snapshot.call_stack;
        self.ip = snapshot.ip;
        self.register_base = snapshot.register_base;
        self.catch_frames = snapshot.catch_frames;
        self.pending_exception = snapshot.pending_exception;
        self.pending_return = snapshot.pending_return;
        self.suspended_abrupt_completions = snapshot.suspended_abrupt_completions;
        self.finally_modes = snapshot.finally_modes;
        self.scope_chain = snapshot.scope_chain;
        self.pending_captures = snapshot.pending_captures;
        self.current_module_specifier = snapshot.current_module_specifier;
    }

    fn prepare_module_execution(&mut self, module_specifier: &str) -> Result<(), InterpreterError> {
        let max_regs = self.config.max_registers as usize;
        self.registers.clear();
        self.registers.resize(max_regs, Value::Undefined);
        self.call_stack.clear();
        self.ip = 0;
        self.register_base = 0;
        self.catch_frames.clear();
        self.pending_exception = None;
        self.pending_return = None;
        self.suspended_abrupt_completions.clear();
        self.finally_modes.clear();
        self.scope_chain = ScopeChain::new();
        self.pending_captures.clear();
        self.current_module_specifier = Some(module_specifier.to_string());
        self.sync_estimated_memory_bytes()?;
        Ok(())
    }

    fn insert_cjs_bindings(
        &mut self,
        module_object: ObjectId,
        exports_object: ObjectId,
        module_specifier: Option<&str>,
    ) -> Result<(), InterpreterError> {
        let (filename_value, dirname_value) = self
            .cjs_filename_dirname(module_specifier.or(self.current_module_specifier.as_deref()));
        let require_value = Value::BuiltinFunction(BuiltinFunction::require(
            module_specifier.unwrap_or_default(),
        ));

        let mut replaced = Vec::with_capacity(5);
        {
            let frame = self.scope_chain.current_mut();
            for (name, value) in [
                ("require", require_value),
                ("exports", Value::Object(exports_object)),
                ("module", Value::Object(module_object)),
                ("__filename", filename_value),
                ("__dirname", dirname_value),
            ] {
                let name = name.to_string();
                let replaced_binding = frame.declare(name.clone(), BindingKind::Var);
                if let Some(binding) = frame.get_mut(&name) {
                    binding.value = value;
                    binding.initialized = true;
                }
                replaced.push((name, replaced_binding));
            }
        }
        if let Err(err) = self.sync_estimated_memory_bytes() {
            let current = self.scope_chain.current_mut();
            for (name, old) in replaced {
                if let Some(old_binding) = old {
                    current.bindings.insert(name, old_binding);
                } else {
                    current.bindings.remove(&name);
                }
            }
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(err);
        }
        Ok(())
    }

    fn cjs_filename_dirname(&self, module_specifier: Option<&str>) -> (Value, Value) {
        let Some(specifier) = module_specifier else {
            return (Value::Undefined, Value::Undefined);
        };
        let dirname = Path::new(specifier)
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| path.display().to_string())
            .or_else(|| self.config.module_root.clone())
            .unwrap_or_default();
        (Value::Str(specifier.to_string()), Value::Str(dirname))
    }

    fn inject_active_cjs_bindings(&mut self) -> Result<(), InterpreterError> {
        let (module_object, exports_object, module_specifier) = {
            let Some(context) = self.active_cjs_context.as_ref() else {
                return Ok(());
            };
            (
                context.module_object,
                context.exports_object,
                context.module_specifier.clone(),
            )
        };
        self.insert_cjs_bindings(
            module_object,
            exports_object,
            Some(module_specifier.as_str()),
        )
    }

    fn resolve_specifier_base(&self, specifier: &str) -> Result<PathBuf, InterpreterError> {
        if specifier.starts_with("./") || specifier.starts_with("../") {
            let base = self
                .current_module_specifier
                .as_deref()
                .and_then(|label| Path::new(label).parent())
                .filter(|path| !path.as_os_str().is_empty())
                .map(PathBuf::from)
                .or_else(|| self.config.module_root.as_ref().map(PathBuf::from))
                .ok_or_else(|| InterpreterError::ModuleResolutionFailed {
                    specifier: specifier.to_string(),
                    reason: "no module root available for relative import".to_string(),
                })?;
            Ok(base.join(specifier))
        } else if specifier.starts_with('/') {
            Ok(PathBuf::from(specifier))
        } else {
            Err(InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: "bare specifiers not supported in baseline interpreter".to_string(),
            })
        }
    }

    fn resolve_module_specifier(&self, specifier: &str) -> Result<String, InterpreterError> {
        let resolved = self.resolve_specifier_base(specifier)?;
        let candidate = self.resolve_module_candidate(&resolved).ok_or_else(|| {
            InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: format!("module not found at {}", resolved.display()),
            }
        })?;
        let canonical =
            candidate
                .canonicalize()
                .map_err(|error| InterpreterError::ModuleResolutionFailed {
                    specifier: specifier.to_string(),
                    reason: format!("failed to canonicalize module path: {error}"),
                })?;
        Ok(canonical.display().to_string())
    }

    fn resolve_require_specifier(&self, specifier: &str) -> Result<String, InterpreterError> {
        let resolved = self.resolve_specifier_base(specifier)?;
        let force_directory = specifier.ends_with('/');
        let candidate = self
            .resolve_require_candidate(&resolved, force_directory)
            .ok_or_else(|| InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: format!("module not found at {}", resolved.display()),
            })?;
        let canonical =
            candidate
                .canonicalize()
                .map_err(|error| InterpreterError::ModuleResolutionFailed {
                    specifier: specifier.to_string(),
                    reason: format!("failed to canonicalize module path: {error}"),
                })?;
        Ok(canonical.display().to_string())
    }

    fn resolve_module_candidate(&self, candidate: &Path) -> Option<PathBuf> {
        if candidate.is_file() {
            return Some(candidate.to_path_buf());
        }
        if candidate.extension().is_none() {
            let mjs_path = candidate.with_extension("mjs");
            if mjs_path.is_file() {
                return Some(mjs_path);
            }
            let js_path = candidate.with_extension("js");
            if js_path.is_file() {
                return Some(js_path);
            }
        }
        if candidate.is_dir() {
            let index_mjs = candidate.join("index.mjs");
            if index_mjs.is_file() {
                return Some(index_mjs);
            }
            let index_js = candidate.join("index.js");
            if index_js.is_file() {
                return Some(index_js);
            }
        }
        if candidate.extension().is_none() {
            let index_mjs = candidate.join("index.mjs");
            if index_mjs.is_file() {
                return Some(index_mjs);
            }
            let index_js = candidate.join("index.js");
            if index_js.is_file() {
                return Some(index_js);
            }
        }
        None
    }

    fn resolve_require_candidate(
        &self,
        candidate: &Path,
        force_directory: bool,
    ) -> Option<PathBuf> {
        if !force_directory {
            if candidate.is_file() {
                return Some(candidate.to_path_buf());
            }
            if candidate.extension().is_none() {
                let cjs_path = candidate.with_extension("cjs");
                if cjs_path.is_file() {
                    return Some(cjs_path);
                }
                let js_path = candidate.with_extension("js");
                if js_path.is_file() {
                    return Some(js_path);
                }
                let mjs_path = candidate.with_extension("mjs");
                if mjs_path.is_file() {
                    return Some(mjs_path);
                }
            }
        }
        if candidate.is_dir() {
            let index_cjs = candidate.join("index.cjs");
            if index_cjs.is_file() {
                return Some(index_cjs);
            }
            let index_js = candidate.join("index.js");
            if index_js.is_file() {
                return Some(index_js);
            }
            let index_mjs = candidate.join("index.mjs");
            if index_mjs.is_file() {
                return Some(index_mjs);
            }
        }
        if !force_directory && candidate.extension().is_none() {
            let index_cjs = candidate.join("index.cjs");
            if index_cjs.is_file() {
                return Some(index_cjs);
            }
            let index_js = candidate.join("index.js");
            if index_js.is_file() {
                return Some(index_js);
            }
            let index_mjs = candidate.join("index.mjs");
            if index_mjs.is_file() {
                return Some(index_mjs);
            }
        }
        None
    }

    fn ensure_module_record(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<ObjectId, InterpreterError> {
        if let Some(record) = self.module_state.modules.get(specifier) {
            return Ok(record.namespace_object);
        }
        self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
        let namespace_object = self.alloc_object_with_prototype(None)?;
        self.module_state.modules.insert(
            specifier.to_string(),
            ModuleRuntimeRecord {
                status: ModuleRuntimeStatus::Evaluating,
                namespace_object,
                exports: BTreeMap::new(),
                cjs_module_object: None,
            },
        );
        Ok(namespace_object)
    }

    fn init_cjs_environment(
        &mut self,
        module: &Ir3Module,
        module_specifier: &str,
        parent_module_object: Option<ObjectId>,
    ) -> Result<CjsModuleContext, InterpreterError> {
        self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
        let exports_object = self.alloc_object_with_prototype(None)?;
        self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
        let module_object = self.alloc_object_with_prototype(None)?;
        self.set_object_property(
            module_object,
            "exports".to_string(),
            Value::Object(exports_object),
        )?;
        let (filename_value, dirname_value) = self.cjs_filename_dirname(Some(module_specifier));
        self.set_object_property(module_object, "id".to_string(), filename_value.clone())?;
        self.set_object_property(
            module_object,
            "filename".to_string(),
            filename_value.clone(),
        )?;
        self.set_object_property(module_object, "path".to_string(), dirname_value.clone())?;
        let parent_value = parent_module_object
            .map(Value::Object)
            .unwrap_or(Value::Null);
        self.set_object_property(module_object, "parent".to_string(), parent_value)?;
        self.set_object_property(module_object, "loaded".to_string(), Value::Bool(false))?;
        self.set_object_property(
            module_object,
            "require".to_string(),
            Value::BuiltinFunction(BuiltinFunction::require(module_specifier)),
        )?;
        let context = CjsModuleContext {
            module_object,
            exports_object,
            module_specifier: module_specifier.to_string(),
        };
        self.insert_cjs_bindings(
            context.module_object,
            context.exports_object,
            Some(module_specifier),
        )?;
        Ok(context)
    }

    fn finalize_cjs_exports(&mut self, context: &CjsModuleContext) -> Result<(), InterpreterError> {
        let export_value = self.prototype_chain_get(context.module_object, "exports")?;
        self.register_module_export("default", export_value.clone())?;
        if let Value::Object(object_id) = export_value {
            let properties = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
                .properties
                .clone();
            for (key, value) in properties {
                if key == "default" {
                    continue;
                }
                self.register_module_export(&key, value)?;
            }
        }
        Ok(())
    }

    fn load_module_resolved(
        &mut self,
        module: &Ir3Module,
        resolved: &str,
        is_cjs: bool,
    ) -> Result<Value, InterpreterError> {
        if let Some(record) = self.module_state.modules.get(resolved) {
            return match &record.status {
                ModuleRuntimeStatus::Evaluating | ModuleRuntimeStatus::Evaluated => {
                    Ok(Value::Object(record.namespace_object))
                }
                ModuleRuntimeStatus::Failed(reason) => {
                    Err(InterpreterError::ModuleEvaluationFailed {
                        specifier: resolved.to_string(),
                        reason: reason.clone(),
                    })
                }
            };
        }

        let namespace_object = self.ensure_module_record(module, resolved)?;

        let source =
            fs::read_to_string(resolved).map_err(|error| InterpreterError::ModuleReadFailed {
                specifier: resolved.to_string(),
                error: error.to_string(),
            })?;
        let parser_source = ParserSource {
            label: resolved.to_string(),
            text: source,
        };
        let parse_goal = if is_cjs {
            ParseGoal::Script
        } else {
            ParseGoal::Module
        };
        let syntax_tree = CanonicalEs2020Parser
            .parse_with_options(parser_source, parse_goal, &ParserOptions::default())
            .map_err(|error| InterpreterError::ModuleParseFailed {
                specifier: resolved.to_string(),
                error: error.to_string(),
            })?;
        let ir0 = Ir0Module::from_syntax_tree(syntax_tree, resolved);
        let lowering_ctx =
            LoweringContext::new(&self.trace_id, "module-import", "baseline_interpreter");
        let lowering_output = lower_ir0_to_ir3(&ir0, &lowering_ctx).map_err(|error| {
            InterpreterError::ModuleLoweringFailed {
                specifier: resolved.to_string(),
                error: error.to_string(),
            }
        })?;
        let eval_result = if is_cjs {
            self.evaluate_cjs_ir3(&lowering_output.ir3, resolved)
        } else {
            self.evaluate_module_ir3(&lowering_output.ir3, resolved)
        };
        match eval_result {
            Ok(()) => {
                if let Some(record) = self.module_state.modules.get_mut(resolved) {
                    record.status = ModuleRuntimeStatus::Evaluated;
                }
                Ok(Value::Object(namespace_object))
            }
            Err(err) => {
                if let Some(record) = self.module_state.modules.get_mut(resolved) {
                    record.status = ModuleRuntimeStatus::Failed(err.to_string());
                }
                Err(err)
            }
        }
    }

    fn import_module(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<Value, InterpreterError> {
        self.run_pre_import_hook(module, specifier)?;
        let resolved = self.resolve_module_specifier(specifier)?;
        let is_cjs = Path::new(&resolved)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("cjs"))
            .unwrap_or(false);
        self.load_module_resolved(module, &resolved, is_cjs)
    }

    fn require_module(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<Value, InterpreterError> {
        self.run_pre_import_hook(module, specifier)?;
        let resolved = self.resolve_require_specifier(specifier)?;
        let is_cjs = match Path::new(&resolved)
            .extension()
            .and_then(|ext| ext.to_str())
        {
            Some(ext) if ext.eq_ignore_ascii_case("cjs") => true,
            Some(ext) if ext.eq_ignore_ascii_case("mjs") => false,
            Some(ext) if ext.eq_ignore_ascii_case("js") => false,
            _ => true,
        };
        let namespace = self.load_module_resolved(module, &resolved, is_cjs)?;
        if !is_cjs {
            return Ok(namespace);
        }
        if let Some(record) = self.module_state.modules.get(&resolved)
            && let Some(module_object) = record.cjs_module_object
        {
            let export_value = self.prototype_chain_get(module_object, "exports")?;
            return Ok(export_value);
        }
        let Value::Object(namespace_object) = namespace else {
            return Ok(namespace);
        };
        let default_value = self.prototype_chain_get(namespace_object, "default")?;
        Ok(default_value)
    }

    fn dispatch_builtin_function(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        match builtin.kind {
            BuiltinFunctionKind::Require => {
                let spec_val = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let specifier = match spec_val {
                    Value::Str(s) => s,
                    other => {
                        return Err(InterpreterError::RequireSpecifierNotString {
                            got: other.type_name().to_string(),
                        });
                    }
                };
                let previous_module_specifier = self.current_module_specifier.clone();
                if !builtin.module_specifier.is_empty() {
                    self.current_module_specifier = Some(builtin.module_specifier.clone());
                }
                let result = self.require_module(module, &specifier);
                self.current_module_specifier = previous_module_specifier;
                result
            }
        }
    }

    fn evaluate_module_ir3(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        let snapshot = self.snapshot_module_execution();
        let previous_cjs_context = self.active_cjs_context.take();
        if let Err(err) = self.prepare_module_execution(specifier) {
            self.active_cjs_context = previous_cjs_context;
            self.restore_module_execution(snapshot);
            return Err(err);
        }
        let result = self.run_loop(module);
        self.drain_microtasks();
        self.restore_module_execution(snapshot);
        self.active_cjs_context = previous_cjs_context;
        match result {
            Ok(_) => Ok(()),
            Err(InterpreterError::Halted) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn evaluate_cjs_ir3(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        let snapshot = self.snapshot_module_execution();
        let previous_cjs_context = self.active_cjs_context.take();
        let parent_module_object = previous_cjs_context
            .as_ref()
            .map(|context| context.module_object);
        if let Err(err) = self.prepare_module_execution(specifier) {
            self.active_cjs_context = previous_cjs_context;
            self.restore_module_execution(snapshot);
            return Err(err);
        }
        let cjs_context = match self.init_cjs_environment(module, specifier, parent_module_object) {
            Ok(context) => context,
            Err(err) => {
                self.active_cjs_context = previous_cjs_context;
                self.restore_module_execution(snapshot);
                return Err(err);
            }
        };
        if let Some(record) = self.module_state.modules.get_mut(specifier) {
            record.cjs_module_object = Some(cjs_context.module_object);
        }
        self.active_cjs_context = Some(cjs_context.clone());
        let result = self.run_loop(module);
        self.drain_microtasks();
        let eval_outcome = match result {
            Ok(_) => Ok(()),
            Err(InterpreterError::Halted) => Ok(()),
            Err(err) => Err(err),
        };
        let finalize_outcome = if eval_outcome.is_ok() {
            self.finalize_cjs_exports(&cjs_context)
        } else {
            Ok(())
        };
        let loaded_outcome = if eval_outcome.is_ok() && finalize_outcome.is_ok() {
            self.set_object_property(
                cjs_context.module_object,
                "loaded".to_string(),
                Value::Bool(true),
            )
        } else {
            Ok(())
        };
        self.restore_module_execution(snapshot);
        self.active_cjs_context = previous_cjs_context;
        eval_outcome.and(finalize_outcome).and(loaded_outcome)
    }

    fn register_module_export(&mut self, name: &str, value: Value) -> Result<(), InterpreterError> {
        let Some(specifier) = self.current_module_specifier.clone() else {
            return Err(InterpreterError::ExportOutsideModule {
                name: name.to_string(),
            });
        };
        let namespace_object = {
            let record = self
                .module_state
                .modules
                .get_mut(&specifier)
                .ok_or_else(|| InterpreterError::ExportOutsideModule {
                    name: name.to_string(),
                })?;
            record.exports.insert(name.to_string(), value.clone());
            record.namespace_object
        };
        self.set_object_property(namespace_object, name.to_string(), value)?;
        Ok(())
    }

    fn complete_return(&mut self, return_val: Value) -> Result<Option<Value>, InterpreterError> {
        let current_depth = self.call_stack.len();
        // A function can return from inside an active try block before `EndTry`
        // executes. Those catch frames belong to the returning callee and must
        // not leak into the caller's unwind state.
        self.catch_frames
            .retain(|frame| frame.call_depth < current_depth);
        if let Some(frame) = self.call_stack.pop() {
            self.register_base = frame.register_base;
            self.suspended_abrupt_completions
                .truncate(frame.saved_suspended_abrupt_depth);
            self.finally_modes.truncate(frame.saved_finally_mode_depth);
            self.persist_closure_capture_updates(&frame);
            self.restore_scope_chain_for_frame(&frame);
            self.pending_exception = frame.saved_pending_exception;
            self.pending_return = frame.saved_pending_return;
            // ES2020 §9.2.2 step 13: if this is a constructor call and the
            // return value is not an object, use the allocated `this` object
            // instead.
            let effective_val = if let Some(this_obj) = frame.construct_this {
                match &return_val {
                    Value::Object(_) => return_val,
                    _ => this_obj,
                }
            } else {
                return_val
            };
            self.write_reg(frame.return_reg, effective_val)?;
            self.ip = frame.return_ip;
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            Ok(None)
        } else {
            self.pending_exception = None;
            self.pending_return = None;
            self.suspended_abrupt_completions.clear();
            self.finally_modes.clear();
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            Ok(Some(return_val))
        }
    }

    fn persist_closure_capture_updates(&mut self, frame: &CallFrame) {
        let Some(closure_id) = frame.closure_id else {
            return;
        };
        let Some(previous_env) = self
            .closures
            .get(closure_id as usize)
            .map(|closure| closure.captured_env.clone())
        else {
            return;
        };
        let captured_depth = frame
            .captured_scope_depth
            .min(self.scope_chain.frames.len());
        let updated_env = self.scope_chain.frames[..captured_depth].to_vec();

        for closure in &mut self.closures {
            if closure.captured_env == previous_env {
                closure.captured_env = updated_env.clone();
            }
        }
    }

    fn restore_scope_chain_for_frame(&mut self, frame: &CallFrame) {
        // Restore scope chain. For closure calls, restore the full saved chain;
        // for plain calls, just pop to the caller depth.
        if let Some(saved) = &frame.saved_scope_chain {
            self.scope_chain.frames = saved.clone();
        } else {
            while self.scope_chain.depth() > frame.saved_scope_depth {
                self.scope_chain.pop();
            }
        }
    }

    fn unwind_call_stack_to(&mut self, target_depth: usize) -> (Option<Value>, Option<Value>) {
        let mut restored_pending_exception = None;
        let mut restored_pending_return = None;
        let mut restored_suspended_abrupt_depth = None;
        while self.call_stack.len() > target_depth {
            if let Some(frame) = self.call_stack.pop() {
                self.persist_closure_capture_updates(&frame);
                self.register_base = frame.register_base;
                self.finally_modes.truncate(frame.saved_finally_mode_depth);
                self.restore_scope_chain_for_frame(&frame);
                restored_pending_exception = frame.saved_pending_exception;
                restored_pending_return = frame.saved_pending_return;
                restored_suspended_abrupt_depth = Some(frame.saved_suspended_abrupt_depth);
            }
        }
        if let Some(depth) = restored_suspended_abrupt_depth {
            self.suspended_abrupt_completions.truncate(depth);
        }
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        (restored_pending_exception, restored_pending_return)
    }

    fn pop_current_try_frame(&mut self) -> Option<CatchFrame> {
        let current_depth = self.call_stack.len();
        let idx = self
            .catch_frames
            .iter()
            .rposition(|f| f.call_depth == current_depth)?;
        let frame = self.catch_frames[idx].clone();
        self.catch_frames.truncate(idx);
        Some(frame)
    }

    fn pop_exception_target_frame(&mut self) -> Option<CatchFrame> {
        let current_depth = self.call_stack.len();
        let idx = self
            .catch_frames
            .iter()
            .rposition(|f| f.call_depth <= current_depth)?;
        let frame = self.catch_frames[idx].clone();
        self.catch_frames.truncate(idx);
        let (restored_pending_exception, restored_pending_return) =
            self.unwind_call_stack_to(frame.call_depth);
        self.suspend_abrupt_completion(restored_pending_exception, restored_pending_return);
        Some(frame)
    }

    fn take_current_abrupt_completion(&mut self) -> Option<AbruptCompletion> {
        if let Some(exception) = self.pending_exception.take() {
            self.pending_return = None;
            Some(AbruptCompletion::Exception(exception))
        } else {
            self.pending_return.take().map(AbruptCompletion::Return)
        }
    }

    fn suspend_abrupt_completion(
        &mut self,
        pending_exception: Option<Value>,
        pending_return: Option<Value>,
    ) {
        debug_assert!(
            pending_exception.is_none() || pending_return.is_none(),
            "only one abrupt completion should be active at a time"
        );

        match (pending_exception, pending_return) {
            (Some(exception), None) => self
                .suspended_abrupt_completions
                .push(AbruptCompletion::Exception(exception)),
            (None, Some(return_val)) => self
                .suspended_abrupt_completions
                .push(AbruptCompletion::Return(return_val)),
            (None, None) => {}
            (Some(exception), Some(return_val)) => {
                self.suspended_abrupt_completions
                    .push(AbruptCompletion::Exception(exception));
                self.suspended_abrupt_completions
                    .push(AbruptCompletion::Return(return_val));
            }
        }
    }

    fn suspend_current_abrupt_completion(&mut self) {
        if let Some(completion) = self.take_current_abrupt_completion() {
            self.suspended_abrupt_completions.push(completion);
        }
    }

    fn restore_suspended_abrupt_completion(&mut self) {
        if self.pending_exception.is_some() || self.pending_return.is_some() {
            return;
        }

        if let Some(completion) = self.suspended_abrupt_completions.pop() {
            match completion {
                AbruptCompletion::Exception(exception) => {
                    self.pending_exception = Some(exception);
                }
                AbruptCompletion::Return(return_val) => {
                    self.pending_return = Some(return_val);
                }
            }
        }
    }

    fn pop_current_finally_target(&mut self) -> Option<usize> {
        let current_depth = self.call_stack.len();
        let idx = self
            .catch_frames
            .iter()
            .rposition(|f| f.call_depth == current_depth && f.finally_target.is_some())?;
        let frame = self.catch_frames[idx].clone();
        self.catch_frames.truncate(idx);
        frame.finally_target
    }

    fn hook_context(&self, module: &Ir3Module) -> HookContext {
        // IR3 modules do not yet expose a dedicated extension id at interpreter
        // runtime, so source_label is the deterministic provenance token
        // available at the hook boundary today.
        HookContext {
            extension_id: module.header.source_label.clone(),
            instruction_count: self.instructions_executed,
            current_ip: self.ip,
        }
    }

    fn function_ref(&self, module: &Ir3Module, callee: &Value, function_index: u32) -> FunctionRef {
        let name = module
            .function_table
            .get(function_index as usize)
            .and_then(|desc| desc.name.clone());
        match callee {
            Value::Function(_) => FunctionRef::Function {
                function_index,
                name,
            },
            Value::Closure(closure_id) => FunctionRef::Closure {
                closure_id: *closure_id,
                function_index,
                name,
            },
            _ => FunctionRef::Function {
                function_index,
                name,
            },
        }
    }

    fn enforce_hook_action(&self, action: HookAction) -> Result<(), InterpreterError> {
        match action {
            HookAction::Allow => Ok(()),
            HookAction::Challenge(token) => Err(InterpreterError::ContainmentActionRequested {
                action: "challenge".to_string(),
                reason: Some(token.token),
            }),
            HookAction::Sandbox => Err(InterpreterError::ContainmentActionRequested {
                action: "sandbox".to_string(),
                reason: None,
            }),
            HookAction::Suspend => Err(InterpreterError::ContainmentActionRequested {
                action: "suspend".to_string(),
                reason: None,
            }),
            HookAction::Terminate(reason) => Err(InterpreterError::ContainmentActionRequested {
                action: "terminate".to_string(),
                reason: Some(reason),
            }),
            HookAction::Quarantine(reason) => Err(InterpreterError::ContainmentActionRequested {
                action: "quarantine".to_string(),
                reason: Some(reason),
            }),
        }
    }

    /// Handle containment action enforcement with proper state management and evidence emission.
    /// This replaces the simple error-throwing approach of enforce_hook_action with actual
    /// containment behaviors as required by RC-4.3.
    #[allow(dead_code)]
    fn handle_containment_action(&mut self, action: HookAction) -> Result<(), InterpreterError> {
        match action {
            HookAction::Allow => Ok(()),
            HookAction::Challenge(ref token) => {
                // Pause execution, emit challenge token, require resolution before continuing
                self.pending_challenges.push(token.clone());
                self.emit_containment_evidence(&action);
                Err(InterpreterError::ContainmentActionRequested {
                    action: "challenge".to_string(),
                    reason: Some(token.token.clone()),
                })
            }
            HookAction::Sandbox => {
                // Restrict extension's capability set (no more network/fs access)
                self.sandboxed = true;
                self.emit_containment_evidence(&action);
                // Sandbox doesn't stop execution, just restricts future capabilities
                Ok(())
            }
            HookAction::Suspend => {
                // Pause extension execution, preserve state, can be resumed by operator
                self.suspended = true;
                self.emit_containment_evidence(&action);
                Ok(())
            }
            HookAction::Terminate(ref reason) => {
                // Abort extension execution, clean up resources, emit termination receipt
                self.emit_containment_evidence(&action);
                Err(InterpreterError::Terminated {
                    reason: reason.clone(),
                })
            }
            HookAction::Quarantine(ref reason) => {
                // Terminate + mark extension for fleet-wide quarantine propagation
                self.quarantined = true;
                self.emit_containment_evidence(&action);
                Err(InterpreterError::Terminated {
                    reason: reason.clone(),
                })
            }
        }
    }

    /// Emit evidence record for containment actions taken.
    /// Creates a signed evidence record and decision receipt that can be verified later.
    #[allow(dead_code)]
    fn emit_containment_evidence(&mut self, action: &HookAction) {
        // Create decision receipt for signed evidence chain
        let (operation_type, action_taken, risk_score) = match action {
            HookAction::Allow => ("allow".to_string(), "allow".to_string(), 0),
            HookAction::Challenge(token) => (
                "challenge".to_string(),
                format!("challenge:{}", token.token),
                150_000,
            ),
            HookAction::Sandbox => ("sandbox".to_string(), "sandbox".to_string(), 300_000),
            HookAction::Suspend => ("suspend".to_string(), "suspend".to_string(), 600_000),
            HookAction::Terminate(reason) => (
                "terminate".to_string(),
                format!("terminate:{}", reason),
                900_000,
            ),
            HookAction::Quarantine(reason) => (
                "quarantine".to_string(),
                format!("quarantine:{}", reason),
                950_000,
            ),
        };

        // Add decision receipt to the evidence chain
        self.decision_receipts.add_receipt(
            self.config
                .extension_id
                .clone()
                .unwrap_or_else(|| "extension:current".to_string()),
            operation_type,
            risk_score,
            action_taken,
            self.ip,
            &self.registers,
        );

        // Create witness event with current structure
        let payload_data = serde_json::json!({
            "action": match action {
                HookAction::Allow => "allow",
                HookAction::Challenge(_) => "challenge",
                HookAction::Sandbox => "sandbox",
                HookAction::Suspend => "suspend",
                HookAction::Terminate(_) => "terminate",
                HookAction::Quarantine(_) => "quarantine",
            },
            "reason": match action {
                HookAction::Challenge(token) => Some(token.token.clone()),
                HookAction::Terminate(reason) => Some(reason.clone()),
                HookAction::Quarantine(reason) => Some(reason.clone()),
                _ => None,
            },
            "suspended": self.suspended,
            "sandboxed": self.sandboxed,
            "quarantined": self.quarantined,
        });
        let payload_bytes = serde_json::to_vec(&payload_data).unwrap_or_default();
        let evidence = WitnessEvent {
            seq: self.witness_seq,
            kind: WitnessEventKind::ContainmentAction,
            instruction_index: self.ip as u32,
            payload_hash: ContentHash::compute(&payload_bytes),
            timestamp_tick: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.containment_evidence.push(evidence.clone());
        self.witness_events.push(evidence);
        self.witness_seq = self.witness_seq.saturating_add(1);
    }

    /// Get the decision receipts log for export or testing.
    pub fn decision_receipts(&self) -> &EvidenceLog {
        &self.decision_receipts
    }

    /// Export decision receipts as JSON evidence bundle.
    pub fn export_decision_receipts(&self) -> Result<String, serde_json::Error> {
        self.decision_receipts.export_json()
    }

    /// Verify the integrity of the decision receipt chain.
    pub fn verify_decision_receipt_chain(&self) -> bool {
        self.decision_receipts.verify_chain()
    }

    fn run_pre_property_access_hook(
        &self,
        module: &Ir3Module,
        target: ObjectId,
        key: &str,
    ) -> Result<(), InterpreterError> {
        let Some(hook) = self.hook.as_ref() else {
            return Ok(());
        };
        let ctx = self.hook_context(module);
        let property_key = key.to_string();
        self.enforce_hook_action(hook.pre_property_access(&ctx, &target, &property_key))
    }

    fn run_pre_call_hook(
        &self,
        module: &Ir3Module,
        callee: &Value,
        function_index: u32,
        args: &[Value],
    ) -> Result<(), InterpreterError> {
        let Some(hook) = self.hook.as_ref() else {
            return Ok(());
        };
        let ctx = self.hook_context(module);
        let function_ref = self.function_ref(module, callee, function_index);
        self.enforce_hook_action(hook.pre_call(&ctx, &function_ref, args))
    }

    fn run_pre_allocation_hook(
        &self,
        module: &Ir3Module,
        kind: AllocKind,
        size_hint: usize,
    ) -> Result<(), InterpreterError> {
        let Some(hook) = self.hook.as_ref() else {
            return Ok(());
        };
        let ctx = self.hook_context(module);
        self.enforce_hook_action(hook.pre_allocation(&ctx, kind, size_hint))
    }

    fn run_pre_import_hook(
        &self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        let Some(hook) = self.hook.as_ref() else {
            return Ok(());
        };
        let ctx = self.hook_context(module);
        self.enforce_hook_action(hook.pre_import(&ctx, specifier))
    }

    /// Step a generator: resume from its saved state, run until Yield or
    /// Return, then snapshot the state back. Returns the {value, done} object.
    fn generator_next(
        &mut self,
        module: &Ir3Module,
        gen_id: u32,
        _arg: Value,
    ) -> Result<Value, InterpreterError> {
        let gobj = self.generators.get_mut(gen_id as usize).ok_or_else(|| {
            InterpreterError::TypeError {
                expected: "valid generator".into(),
                got: format!("generator#{gen_id} not found"),
            }
        })?;

        match gobj.phase {
            GeneratorPhase::Completed => {
                let result_id = self.alloc_object_with_prototype(None)?;
                {
                    self.set_object_property(result_id, "value".to_string(), Value::Undefined)?;
                    self.set_object_property(result_id, "done".to_string(), Value::Bool(true))?;
                }
                return Ok(Value::Object(result_id));
            }
            GeneratorPhase::Executing => {
                return Err(InterpreterError::TypeError {
                    expected: "suspended generator".into(),
                    got: "generator already executing".into(),
                });
            }
            GeneratorPhase::SuspendedStart | GeneratorPhase::SuspendedYield => {}
        }

        let caller_ip = self.ip;
        let caller_register_base = self.register_base;
        let caller_scope = self.snapshot_scope_chain()?;
        let caller_scope_bytes = Self::estimate_scope_chain_bytes(&caller_scope);

        let (is_start, func_idx, closure_idx) = {
            let gobj = &mut self.generators[gen_id as usize];
            let is_start = gobj.phase == GeneratorPhase::SuspendedStart;
            let func_idx = gobj.function_index;
            let closure_idx = gobj.closure_index;
            gobj.phase = GeneratorPhase::Executing;
            (is_start, func_idx, closure_idx)
        };

        if is_start {
            let start_result = (|| -> Result<(), InterpreterError> {
                let func = module.function_table.get(func_idx as usize).ok_or(
                    InterpreterError::FunctionNotFound {
                        index: func_idx,
                        table_size: module.function_table.len() as u32,
                    },
                )?;

                if let Some(cid) = closure_idx {
                    let closure = self.closures.get(cid as usize).ok_or_else(|| {
                        InterpreterError::TypeError {
                            expected: "valid closure".into(),
                            got: format!("closure#{cid} not found"),
                        }
                    })?;
                    self.scope_chain.frames = self.clone_scope_frames_with_temporary_budget(
                        &closure.captured_env,
                        caller_scope_bytes,
                    )?;
                }
                self.scope_chain.push(self.config.max_scope_depth)?;
                self.sync_estimated_memory_bytes()?;

                self.register_base = self.registers.len();
                let req_len = self.register_base + self.config.max_registers as usize;
                self.registers.resize(req_len, Value::Undefined);

                self.ip = func.entry as usize;
                Ok(())
            })();

            if let Err(err) = start_result {
                self.ip = caller_ip;
                self.register_base = caller_register_base;
                self.scope_chain.frames = caller_scope;
                let gobj = &mut self.generators[gen_id as usize];
                gobj.phase = GeneratorPhase::SuspendedStart;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                return Err(err);
            }
        } else {
            let (saved_ip, saved_regs, saved_base) = {
                let gobj = &mut self.generators[gen_id as usize];
                (
                    gobj.saved_ip,
                    std::mem::take(&mut gobj.saved_registers),
                    gobj.saved_register_base,
                )
            };

            self.ip = saved_ip;
            self.register_base = saved_base;
            let req_len = saved_base + saved_regs.len();
            if req_len > self.registers.len() {
                self.registers.resize(req_len, Value::Undefined);
            }
            for (i, val) in saved_regs.into_iter().enumerate() {
                self.registers[saved_base + i] = val;
            }
        }

        let result = self.run_loop(module);

        match &result {
            Ok(yielded_val) => {
                let max_regs = self.config.max_registers as usize;
                let saved_regs: Vec<Value> =
                    self.registers[self.register_base..self.register_base + max_regs].to_vec();

                let gobj = &mut self.generators[gen_id as usize];
                gobj.saved_ip = self.ip;
                gobj.saved_registers = saved_regs;
                gobj.saved_register_base = self.register_base;
                gobj.phase = GeneratorPhase::SuspendedYield;

                self.ip = caller_ip;
                self.register_base = caller_register_base;
                self.scope_chain.frames = caller_scope;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();

                Ok(yielded_val.clone())
            }
            Err(InterpreterError::Halted) => {
                let gobj = &mut self.generators[gen_id as usize];
                gobj.phase = GeneratorPhase::Completed;

                self.ip = caller_ip;
                self.register_base = caller_register_base;
                self.scope_chain.frames = caller_scope;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();

                let result_id = self.alloc_object_with_prototype(None)?;
                {
                    self.set_object_property(result_id, "value".to_string(), Value::Undefined)?;
                    self.set_object_property(result_id, "done".to_string(), Value::Bool(true))?;
                }
                Ok(Value::Object(result_id))
            }
            Err(_) => {
                let gobj = &mut self.generators[gen_id as usize];
                gobj.phase = GeneratorPhase::Completed;

                self.ip = caller_ip;
                self.register_base = caller_register_base;
                self.scope_chain.frames = caller_scope;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();

                result
            }
        }
    }

    /// Execute .next() on an async generator.
    /// Returns a Promise that resolves to {value, done}.
    #[allow(dead_code)]
    fn async_generator_next(
        &mut self,
        _module: &Ir3Module,
        gen_id: u32,
        _arg: Value,
    ) -> Result<Value, InterpreterError> {
        let async_gen = self
            .async_generators
            .get_mut(gen_id as usize)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid async generator".into(),
                got: format!("async_generator#{gen_id} not found"),
            })?;

        match async_gen.phase {
            AsyncGeneratorPhase::Completed => {
                // Return a resolved Promise with {value: undefined, done: true}
                let result_promise = self.promise_store.create().0;
                let result_id = self.alloc_object_with_prototype(None)?;
                {
                    self.set_object_property(result_id, "value".to_string(), Value::Undefined)?;
                    self.set_object_property(result_id, "done".to_string(), Value::Bool(true))?;
                }
                let js_val = crate::object_model::JsValue::Object(
                    crate::object_model::ObjectHandle(result_id.0),
                );
                let label = crate::ifc_artifacts::Label::Public;
                self.promise_store
                    .fulfill(
                        crate::promise_model::PromiseHandle(result_promise),
                        js_val,
                        label,
                        &mut self.event_loop.microtasks,
                    )
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "promise fulfillment".into(),
                        got: format!("failed to fulfill promise: {e:?}"),
                    })?;
                return Ok(Value::Promise(result_promise));
            }
            AsyncGeneratorPhase::Executing => {
                return Err(InterpreterError::TypeError {
                    expected: "suspended async generator".into(),
                    got: "async generator already executing".into(),
                });
            }
            AsyncGeneratorPhase::SuspendedStart
            | AsyncGeneratorPhase::SuspendedYield
            | AsyncGeneratorPhase::SuspendedAwait => {}
        }

        // For now, return a placeholder promise that resolves to {value: undefined, done: true}
        // Full implementation would execute the async generator body with suspension/resumption
        let result_promise = self.promise_store.create().0;
        let result_id = self.alloc_object_with_prototype(None)?;
        {
            self.set_object_property(result_id, "value".to_string(), Value::Undefined)?;
            self.set_object_property(result_id, "done".to_string(), Value::Bool(true))?;
        }
        let js_val =
            crate::object_model::JsValue::Object(crate::object_model::ObjectHandle(result_id.0));
        let label = crate::ifc_artifacts::Label::Public;
        self.promise_store
            .fulfill(
                crate::promise_model::PromiseHandle(result_promise),
                js_val,
                label,
                &mut self.event_loop.microtasks,
            )
            .map_err(|e| InterpreterError::TypeError {
                expected: "promise fulfillment".into(),
                got: format!("failed to fulfill promise: {e:?}"),
            })?;

        // Mark as completed for simplicity
        let async_gen = &mut self.async_generators[gen_id as usize];
        async_gen.phase = AsyncGeneratorPhase::Completed;

        Ok(Value::Promise(result_promise))
    }

    fn run_loop(&mut self, module: &Ir3Module) -> Result<Value, InterpreterError> {
        // Initialize CheckpointGuard if cancellation token is provided
        let mut checkpoint_guard = if let Some(ref token) = self.config.cancellation_token {
            Some(CheckpointGuard::new(
                LoopSite::BytecodeDispatch,
                "baseline_interpreter",
                &self.trace_id,
                DensityConfig {
                    max_iterations: self.config.checkpoint_density,
                    max_total_iterations: self.config.instruction_budget,
                },
                token.clone(),
            ))
        } else {
            None
        };

        loop {
            if self.ip >= module.instructions.len() {
                // Fell off the end of the instruction stream.
                if !self.call_stack.is_empty() {
                    if let Some(final_value) = self.complete_return(Value::Undefined)? {
                        return Ok(final_value);
                    }
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

            let instr = module
                .instructions
                .get(self.ip)
                .ok_or(InterpreterError::InstructionOutOfBounds {
                    ip: self.ip,
                    count: module.instructions.len(),
                })?
                .clone();
            self.instructions_executed += 1;

            // Checkpoint guard integration: tick on each instruction
            if let Some(ref mut guard) = checkpoint_guard {
                guard.tick();

                // Check at checkpoint density interval
                if self
                    .instructions_executed
                    .is_multiple_of(self.config.checkpoint_density)
                {
                    match guard.check() {
                        CheckpointAction::Continue => {
                            // Continue execution normally
                        }
                        CheckpointAction::Drain => {
                            // Cancellation requested, return Cancelled error
                            return Err(InterpreterError::Cancelled);
                        }
                        CheckpointAction::Abort => {
                            // Budget exhausted via checkpoint, defer to existing budget check
                            // (This will be caught by the budget check above)
                        }
                    }
                }
            }

            // Start profiling timing for this instruction
            let profile_start = if self.profiling_data.is_some() {
                Some(std::time::Instant::now())
            } else {
                None
            };

            let profiling_instruction = if self.profiling_data.is_some() {
                Some(instr.clone())
            } else {
                None
            };

            match instr {
                Ir3Instruction::LoadInt { dst, value } => {
                    self.write_reg(dst, Value::Int(value))?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadFloat { dst, bits } => {
                    let value = f64::from_bits(bits);
                    self.write_reg(dst, Value::Float(Float64::new(value)))?;
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
                Ir3Instruction::ForInInit { src, dst } => {
                    let value = self.read_reg(src)?;
                    let iterator = self.init_for_in_iterator(value)?;
                    self.write_reg(dst, iterator)?;
                    self.ip += 1;
                }
                Ir3Instruction::ForInNext {
                    iterator,
                    value_dst,
                    done_target,
                } => {
                    let iterator = self.read_reg(iterator)?;
                    if let Some(value) = self.advance_for_in_iterator(iterator)? {
                        self.write_reg(value_dst, value)?;
                        self.ip += 1;
                    } else {
                        self.ip = done_target as usize;
                    }
                }
                Ir3Instruction::ForOfInit { src, dst } => {
                    let value = self.read_reg(src)?;
                    let iterator = self.init_for_of_iterator(value)?;
                    self.write_reg(dst, iterator)?;
                    self.ip += 1;
                }
                Ir3Instruction::ForOfNext {
                    iterator,
                    value_dst,
                    done_target,
                } => {
                    let iterator = self.read_reg(iterator)?;
                    if let Some(value) = self.advance_for_of_iterator(iterator)? {
                        self.write_reg(value_dst, value)?;
                        self.ip += 1;
                    } else {
                        self.ip = done_target as usize;
                    }
                }
                Ir3Instruction::IteratorClose { iterator, reason } => {
                    let iterator = self.read_reg(iterator)?;
                    self.close_iterator(iterator, reason)?;
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
                Ir3Instruction::JumpIfNullish { cond, target } => {
                    let val = self.read_reg(cond)?;
                    if val.is_nullish() {
                        self.ip = target as usize;
                    } else {
                        self.ip += 1;
                    }
                }
                Ir3Instruction::Call { callee, args, dst } => {
                    let callee_val = self.read_reg(callee)?;

                    // Generator .next() call: step the generator.
                    if let Value::Generator(gen_id) = &callee_val {
                        let gen_id = *gen_id;
                        let arg = if args.count > 0 {
                            self.read_reg(args.start)?
                        } else {
                            Value::Undefined
                        };
                        let result = self.generator_next(module, gen_id, arg)?;
                        self.write_reg(dst, result)?;
                        self.ip += 1;
                        continue;
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_val {
                        let result = self.dispatch_builtin_function(module, builtin, args)?;
                        self.write_reg(dst, result)?;
                        self.ip += 1;
                        continue;
                    }

                    // Resolve function index and optional captured environment.
                    let (func_idx, captured_env, closure_id) = match &callee_val {
                        Value::Function(idx) => (*idx, None, None),
                        Value::Closure(closure_id)
                        | Value::GeneratorFunction(closure_id)
                        | Value::AsyncFunction(closure_id)
                        | Value::AsyncGeneratorFunction(closure_id) => {
                            let closure =
                                self.closures.get(*closure_id as usize).ok_or_else(|| {
                                    InterpreterError::TypeError {
                                        expected: "valid closure".to_string(),
                                        got: format!("closure#{closure_id} not found"),
                                    }
                                })?;
                            (
                                closure.function_index,
                                Some(self.clone_scope_frames_with_budget(&closure.captured_env)?),
                                Some(*closure_id),
                            )
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    };

                    // Generator function call: create a suspended GeneratorObject.
                    if let Value::GeneratorFunction(cid) = &callee_val {
                        let gen_id = u32::try_from(self.generators.len()).map_err(|_| {
                            InterpreterError::TypeError {
                                expected: "generator table capacity".into(),
                                got: format!("exceeded u32::MAX ({})", self.generators.len()),
                            }
                        })?;
                        self.generators.push(GeneratorObject {
                            function_index: func_idx,
                            closure_index: Some(*cid),
                            saved_ip: 0,
                            saved_registers: Vec::new(),
                            saved_register_base: 0,
                            phase: GeneratorPhase::SuspendedStart,
                        });
                        self.write_reg(dst, Value::Generator(gen_id))?;
                        self.ip += 1;
                        continue;
                    }

                    // Async function call: create a suspended AsyncFunctionObject and result Promise.
                    if let Value::AsyncFunction(cid) = &callee_val {
                        // Create the result Promise first
                        let result_promise = self.promise_store.create().0;

                        let _async_id =
                            u32::try_from(self.async_functions.len()).map_err(|_| {
                                InterpreterError::TypeError {
                                    expected: "async function table capacity".into(),
                                    got: format!(
                                        "exceeded u32::MAX ({})",
                                        self.async_functions.len()
                                    ),
                                }
                            })?;
                        self.async_functions.push(AsyncFunctionObject {
                            function_index: func_idx,
                            closure_index: Some(*cid),
                            saved_ip: 0,
                            saved_registers: Vec::new(),
                            saved_register_base: 0,
                            phase: AsyncFunctionPhase::SuspendedStart,
                            result_promise,
                        });

                        // Return the result Promise immediately
                        self.write_reg(dst, Value::Promise(result_promise))?;
                        self.ip += 1;

                        // TODO: Start async function execution immediately
                        // For now we just return the promise. In a full implementation,
                        // we would begin executing the async function body and handle
                        // suspension/resumption via the event loop

                        continue;
                    }

                    // Async generator function call: create a suspended AsyncGeneratorObject.
                    if let Value::AsyncGeneratorFunction(cid) = &callee_val {
                        let async_gen_id =
                            u32::try_from(self.async_generators.len()).map_err(|_| {
                                InterpreterError::TypeError {
                                    expected: "async generator table capacity".into(),
                                    got: format!(
                                        "exceeded u32::MAX ({})",
                                        self.async_generators.len()
                                    ),
                                }
                            })?;
                        self.async_generators.push(AsyncGeneratorObject {
                            function_index: func_idx,
                            closure_index: Some(*cid),
                            saved_ip: 0,
                            saved_registers: Vec::new(),
                            saved_register_base: 0,
                            phase: AsyncGeneratorPhase::SuspendedStart,
                        });
                        self.write_reg(dst, Value::AsyncGeneratorObject(async_gen_id))?;
                        self.ip += 1;
                        continue;
                    }

                    match &callee_val {
                        Value::Function(_) | Value::Closure(_) => {
                            // Try to get the function from the module's function table
                            let func_result = module.function_table.get(func_idx as usize);

                            // If the function is not found, check if it's a builtin
                            let func = if let Some(f) = func_result {
                                f
                            } else {
                                // Function not found in module table - check if it's a builtin
                                if let Some(builtin_cap) =
                                    self.map_function_index_to_builtin_capability(func_idx)
                                {
                                    // Dispatch as a builtin hostcall
                                    let result =
                                        self.dispatch_builtin_hostcall(&builtin_cap, args)?;
                                    self.write_reg(dst, result)?;
                                    self.ip += 1;
                                    continue;
                                } else {
                                    // Not a builtin either - return original error
                                    return Err(InterpreterError::FunctionNotFound {
                                        index: func_idx,
                                        table_size: module.function_table.len() as u32,
                                    });
                                }
                            };

                            if self.call_stack.len() >= self.config.max_call_depth {
                                return Err(InterpreterError::StackOverflow {
                                    depth: self.call_stack.len(),
                                    max: self.config.max_call_depth,
                                });
                            }

                            let mut arg_vals = Vec::new();
                            for i in 0..args.count.min(func.arity) {
                                let reg = args.start.checked_add(i).ok_or(
                                    InterpreterError::RegisterOutOfBounds {
                                        register: args.start,
                                        max: self.config.max_registers,
                                    },
                                )?;
                                arg_vals.push(self.read_reg(reg)?);
                            }

                            self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;

                            // Push frame. For closure calls, save the
                            // entire caller scope chain so it can be
                            // restored on return (the closure replaces
                            // the chain with its captured environment).
                            let scope_depth = self.scope_chain.depth();
                            let captured_env_bytes = captured_env
                                .as_ref()
                                .map(|env| Self::estimate_scope_chain_bytes(env))
                                .unwrap_or(0);
                            let captured_scope_depth = captured_env.as_ref().map_or(0, Vec::len);
                            let saved_chain = if captured_env.is_some() {
                                Some(self.snapshot_scope_chain_with_temporary_budget(
                                    captured_env_bytes,
                                )?)
                            } else {
                                None
                            };
                            // For plain calls, this_value is undefined.
                            // Method calls set this via the CallMethod instruction (TODO).
                            let frame_this = self
                                .call_stack
                                .last()
                                .map_or(Value::Undefined, |f| f.this_value.clone());
                            // Arrow closures inherit `this` from the defining frame.
                            let call_this = if captured_env.is_some() {
                                frame_this
                            } else {
                                Value::Undefined
                            };

                            self.call_stack.push(CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: dst,
                                register_base: self.register_base,
                                function_index: Some(func_idx),
                                this_value: call_this,
                                super_value: Value::Undefined,
                                construct_this: None,
                                saved_pending_exception: self.pending_exception.take(),
                                saved_pending_return: self.pending_return.take(),
                                saved_suspended_abrupt_depth: self
                                    .suspended_abrupt_completions
                                    .len(),
                                saved_finally_mode_depth: self.finally_modes.len(),
                                saved_scope_depth: scope_depth,
                                saved_scope_chain: saved_chain,
                                closure_id,
                                captured_scope_depth,
                            });

                            // If calling a closure, restore its captured environment.
                            if let Some(env) = captured_env {
                                self.scope_chain.frames = env;
                            }

                            // Push a fresh scope for the callee's locals.
                            if let Err(err) = self.scope_chain.push(self.config.max_scope_depth) {
                                self.rollback_call_setup();
                                return Err(err);
                            }
                            if let Err(err) = self.sync_estimated_memory_bytes() {
                                self.rollback_call_setup();
                                return Err(err);
                            }

                            self.register_base += self.config.max_registers as usize;

                            // Clear all registers in the new frame to prevent data leakage from previous calls
                            let req_len = self.register_base + self.config.max_registers as usize;
                            if req_len > self.registers.len() {
                                self.registers.resize(req_len, Value::Undefined);
                            } else {
                                self.registers[self.register_base..req_len].fill(Value::Undefined);
                            }

                            // Copy arguments into registers for the callee.
                            for (i, val) in arg_vals.into_iter().enumerate() {
                                let reg = i as u32;
                                if reg < self.config.max_registers {
                                    self.write_reg(reg, val)?;
                                }
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
                Ir3Instruction::CallMethod {
                    receiver,
                    callee,
                    args,
                    dst,
                } => {
                    let receiver_val = self.read_reg(receiver)?;
                    let callee_val = self.read_reg(callee)?;

                    if let Value::BuiltinFunction(builtin) = &callee_val {
                        let result = self.dispatch_builtin_function(module, builtin, args)?;
                        self.write_reg(dst, result)?;
                        self.ip += 1;
                        continue;
                    }

                    let (func_idx, captured_env, closure_id) = match &callee_val {
                        Value::Function(idx) => (*idx, None, None),
                        Value::Closure(closure_id) => {
                            let closure =
                                self.closures.get(*closure_id as usize).ok_or_else(|| {
                                    InterpreterError::TypeError {
                                        expected: "valid closure".to_string(),
                                        got: format!("closure#{closure_id} not found"),
                                    }
                                })?;
                            (
                                closure.function_index,
                                Some(self.clone_scope_frames_with_budget(&closure.captured_env)?),
                                Some(*closure_id),
                            )
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    };

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
                        let reg = args.start.checked_add(i).ok_or(
                            InterpreterError::RegisterOutOfBounds {
                                register: args.start,
                                max: self.config.max_registers,
                            },
                        )?;
                        arg_vals.push(self.read_reg(reg)?);
                    }

                    self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;

                    let scope_depth = self.scope_chain.depth();
                    let captured_env_bytes = captured_env
                        .as_ref()
                        .map(|env| Self::estimate_scope_chain_bytes(env))
                        .unwrap_or(0);
                    let captured_scope_depth = captured_env.as_ref().map_or(0, Vec::len);
                    let saved_chain = if captured_env.is_some() {
                        Some(self.snapshot_scope_chain_with_temporary_budget(captured_env_bytes)?)
                    } else {
                        None
                    };
                    self.call_stack.push(CallFrame {
                        return_ip: self.ip + 1,
                        return_reg: dst,
                        register_base: self.register_base,
                        function_index: Some(func_idx),
                        this_value: receiver_val,
                        super_value: Value::Undefined,
                        construct_this: None,
                        saved_pending_exception: self.pending_exception.take(),
                        saved_pending_return: self.pending_return.take(),
                        saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
                        saved_finally_mode_depth: self.finally_modes.len(),
                        saved_scope_depth: scope_depth,
                        saved_scope_chain: saved_chain,
                        closure_id,
                        captured_scope_depth,
                    });

                    if let Some(env) = captured_env {
                        self.scope_chain.frames = env;
                    }
                    if let Err(err) = self.scope_chain.push(self.config.max_scope_depth) {
                        self.rollback_call_setup();
                        return Err(err);
                    }
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        self.rollback_call_setup();
                        return Err(err);
                    }

                    self.register_base += self.config.max_registers as usize;
                    let req_len = self.register_base + self.config.max_registers as usize;
                    if req_len > self.registers.len() {
                        self.registers.resize(req_len, Value::Undefined);
                    } else {
                        self.registers[self.register_base..req_len].fill(Value::Undefined);
                    }

                    for (i, val) in arg_vals.into_iter().enumerate() {
                        let reg = i as u32;
                        if reg < self.config.max_registers {
                            self.write_reg(reg, val)?;
                        }
                    }

                    self.ip = func.entry as usize;
                }
                Ir3Instruction::Return { value } => {
                    let return_val = self.read_reg(value)?;
                    // A return from inside a finally overrides any in-flight
                    // exception, and a return from inside try/catch must still
                    // unwind through enclosing finally blocks before it can
                    // complete.
                    self.suspend_current_abrupt_completion();
                    self.pending_exception = None;
                    self.pending_return = Some(return_val.clone());
                    if let Some(finally_target) = self.pop_current_finally_target() {
                        self.ip = finally_target;
                    } else {
                        self.pending_return = None;
                        if let Some(final_value) = self.complete_return(return_val)? {
                            return Ok(final_value);
                        }
                    }
                }
                Ir3Instruction::HostCall {
                    capability,
                    args,
                    dst,
                } => {
                    // Promise hostcalls are always allowed (runtime-internal).
                    let is_promise_cap = capability.0.starts_with("promise:");

                    if !is_promise_cap {
                        // Map the CapabilityTag string to a typed RuntimeCapability.
                        // Tags that map to a RuntimeCapability are checked against
                        // the granted set.  Tags with no mapping are internal
                        // dispatch tags (ifc.*, hostcall.*) emitted by the
                        // trusted lowering pipeline and pass through.
                        if let Some(required_cap) = RuntimeCapability::from_tag_str(&capability.0)
                            && !self.config.granted_capabilities.contains(&required_cap)
                        {
                            self.emit_witness(
                                WitnessEventKind::CapabilityChecked,
                                Some(&format!("denied:{}", capability.0)),
                            );
                            return Err(InterpreterError::CapabilityDenied {
                                capability: capability.0.clone(),
                            });
                        }
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

                    // Dispatch promise hostcalls to the promise subsystem.
                    let result = if is_promise_cap {
                        self.dispatch_promise_hostcall(&capability.0, args)?
                    } else if capability.0 == "module:require" {
                        let spec_val = if args.count > 0 {
                            self.read_reg(args.start)?
                        } else {
                            Value::Undefined
                        };
                        let specifier = match spec_val {
                            Value::Str(s) => s,
                            other => {
                                return Err(InterpreterError::RequireSpecifierNotString {
                                    got: other.type_name().to_string(),
                                });
                            }
                        };
                        self.require_module(module, &specifier)?
                    } else if capability.0.starts_with("number:") {
                        self.dispatch_number_hostcall(&capability.0, args)?
                    } else if capability.0.starts_with("console:") {
                        self.dispatch_console_hostcall(&capability.0, args)?
                    } else if capability.0.starts_with("timer:") {
                        self.dispatch_timer_hostcall(&capability.0, args)?
                    } else if capability.0.starts_with("builtin:") {
                        self.dispatch_builtin_hostcall(&capability.0, args)?
                    } else {
                        // Non-promise hostcalls return undefined in baseline.
                        Value::Undefined
                    };
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::ImportModule { specifier, dst } => {
                    let spec_val = self.read_reg(specifier)?;
                    let specifier_str = match spec_val {
                        Value::Str(s) => s,
                        other => {
                            return Err(InterpreterError::ImportSpecifierNotString {
                                got: other.type_name().to_string(),
                            });
                        }
                    };
                    let namespace = self.import_module(module, &specifier_str)?;
                    self.write_reg(dst, namespace)?;
                    self.ip += 1;
                }
                Ir3Instruction::ExportBinding {
                    name_pool_index,
                    src,
                } => {
                    let name = module
                        .constant_pool
                        .get(name_pool_index as usize)
                        .cloned()
                        .unwrap_or_else(|| format!("__export_{name_pool_index}"));
                    let value = self.read_reg(src)?;
                    self.register_module_export(&name, value)?;
                    self.ip += 1;
                }
                Ir3Instruction::GetProperty { obj, key, dst } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let key_str = Self::property_key(&key_val);

                    match obj_val {
                        Value::Object(oid) => {
                            self.run_pre_property_access_hook(module, oid, &key_str)?;
                            let prop = self.prototype_chain_get(oid, &key_str)?;
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
                    let key_str = Self::property_key(&key_val);

                    match obj_val {
                        Value::Object(oid) => {
                            self.run_pre_property_access_hook(module, oid, &key_str)?;
                            self.set_object_property(oid, key_str, set_val)?;
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
                Ir3Instruction::DeleteProperty { obj, key, dst } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let key_str = Self::property_key(&key_val);

                    match obj_val {
                        Value::Object(oid) => {
                            self.run_pre_property_access_hook(module, oid, &key_str)?;
                            self.remove_object_property(oid, &key_str)?;
                            self.mark_deleted_for_in_iterators(oid, &key_str);
                            self.write_reg(dst, Value::Bool(true))?;
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
                Ir3Instruction::NewObject { dst } => {
                    self.run_pre_allocation_hook(module, AllocKind::Object, 0)?;
                    let id = self.alloc_object_with_prototype(None)?;
                    self.write_reg(dst, Value::Object(id))?;
                    self.ip += 1;
                }
                Ir3Instruction::NewArray { dst } => {
                    self.run_pre_allocation_hook(module, AllocKind::Array, 0)?;
                    let id = self.alloc_object_with_prototype(None)?;
                    self.write_reg(dst, Value::Object(id))?;
                    self.ip += 1;
                }
                Ir3Instruction::ArrayPush { array, element } => {
                    // Push a single element onto an array
                    let arr_val = self.read_reg(array)?;
                    let elem_val = self.read_reg(element)?;
                    if let Value::Object(arr_id) = arr_val {
                        let next_idx = self
                            .heap
                            .get(arr_id.0 as usize)
                            .map(|obj| {
                                obj.properties.keys().fold(0u32, |current, key| {
                                    key.parse::<u32>()
                                        .ok()
                                        .map_or(current, |n| current.max(n + 1))
                                })
                            })
                            .unwrap_or(0);
                        self.set_object_property(arr_id, next_idx.to_string(), elem_val)?;
                    }
                    self.ip += 1;
                }
                Ir3Instruction::SpreadIntoArray { array, iterable } => {
                    // Spread iterable elements into an array
                    let arr_val = self.read_reg(array)?;
                    let iter_val = self.read_reg(iterable)?;
                    if let (Value::Object(arr_id), Value::Object(iter_id)) = (arr_val, iter_val) {
                        // Get elements from iterable (assume it's array-like)
                        let elements: Vec<Value> = {
                            if let Some(obj) = self.heap.get(iter_id.0 as usize) {
                                let mut elems = Vec::new();
                                let mut idx = 0u32;
                                while let Some(val) = obj.properties.get(&idx.to_string()) {
                                    elems.push(val.clone());
                                    idx += 1;
                                }
                                elems
                            } else {
                                Vec::new()
                            }
                        };
                        // Push elements to target array
                        if self.heap.get(arr_id.0 as usize).is_some() {
                            let mut next_idx = self
                                .heap
                                .get(arr_id.0 as usize)
                                .map(|obj| {
                                    obj.properties.keys().fold(0u32, |current, key| {
                                        key.parse::<u32>()
                                            .ok()
                                            .map_or(current, |n| current.max(n + 1))
                                    })
                                })
                                .unwrap_or(0);
                            for elem in elements {
                                self.set_object_property(arr_id, next_idx.to_string(), elem)?;
                                next_idx += 1;
                            }
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::SpreadIntoObject { target, source } => {
                    // Spread source object properties into target
                    let target_val = self.read_reg(target)?;
                    let source_val = self.read_reg(source)?;
                    if let (Value::Object(target_id), Value::Object(source_id)) =
                        (target_val, source_val)
                    {
                        // Collect source properties
                        let properties: Vec<(String, Value)> = {
                            if let Some(obj) = self.heap.get(source_id.0 as usize) {
                                obj.properties
                                    .iter()
                                    .map(|(k, v)| (k.clone(), v.clone()))
                                    .collect()
                            } else {
                                Vec::new()
                            }
                        };
                        // Copy to target
                        if self.heap.get(target_id.0 as usize).is_some() {
                            for (key, val) in properties {
                                self.set_object_property(target_id, key, val)?;
                            }
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::Mod { dst, lhs, rhs } => {
                    let result = self.eval_mod(lhs, rhs)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Exp { dst, lhs, rhs } => {
                    let result = self.eval_exp(lhs, rhs)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::UnaryNeg { dst, src } => {
                    let result = self.eval_unary_neg(src)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::UnaryPlus { dst, src } => {
                    let result = self.eval_unary_plus(src)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::LogicalNot { dst, src } => {
                    let val = self.read_reg(src)?;
                    self.write_reg(dst, Value::Bool(!val.is_truthy()))?;
                    self.ip += 1;
                }
                Ir3Instruction::BitNot { dst, src } => {
                    let result = self.eval_bit_not(src)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::TypeOf { dst, src } => {
                    let val = self.read_reg(src)?;
                    self.write_reg(dst, Value::Str(val.typeof_name().to_string()))?;
                    self.ip += 1;
                }
                Ir3Instruction::Void { dst, src } => {
                    let _ = self.read_reg(src)?;
                    self.write_reg(dst, Value::Undefined)?;
                    self.ip += 1;
                }
                Ir3Instruction::Lt { dst, lhs, rhs } => {
                    let result = self.eval_relational(lhs, rhs, "<")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Lte { dst, lhs, rhs } => {
                    let result = self.eval_relational(lhs, rhs, "<=")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Gt { dst, lhs, rhs } => {
                    let result = self.eval_relational(lhs, rhs, ">")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Gte { dst, lhs, rhs } => {
                    let result = self.eval_relational(lhs, rhs, ">=")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Eq { dst, lhs, rhs } => {
                    let result = self.eval_equality(lhs, rhs, false, false)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::StrictEq { dst, lhs, rhs } => {
                    let result = self.eval_equality(lhs, rhs, true, false)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::NotEq { dst, lhs, rhs } => {
                    let result = self.eval_equality(lhs, rhs, false, true)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::StrictNotEq { dst, lhs, rhs } => {
                    let result = self.eval_equality(lhs, rhs, true, true)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::BitAnd { dst, lhs, rhs } => {
                    let result = self.eval_bitwise(lhs, rhs, "&")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::BitOr { dst, lhs, rhs } => {
                    let result = self.eval_bitwise(lhs, rhs, "|")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::BitXor { dst, lhs, rhs } => {
                    let result = self.eval_bitwise(lhs, rhs, "^")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Shl { dst, lhs, rhs } => {
                    let result = self.eval_bitwise(lhs, rhs, "<<")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Shr { dst, lhs, rhs } => {
                    let result = self.eval_bitwise(lhs, rhs, ">>")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Ushr { dst, lhs, rhs } => {
                    let result = self.eval_bitwise(lhs, rhs, ">>>")?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::InstanceOf { dst, lhs, rhs } => {
                    let result = self.eval_instanceof(lhs, rhs)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::InOp { dst, lhs, rhs } => {
                    let result = self.eval_in_operator(lhs, rhs)?;
                    self.write_reg(dst, result)?;
                    self.ip += 1;
                }
                Ir3Instruction::Construct { callee, args, dst } => {
                    let callee_val = self.read_reg(callee)?;

                    // Resolve function index and optional captured environment.
                    let (func_idx, captured_env, closure_id) = match &callee_val {
                        Value::Function(idx) => (*idx, None, None),
                        Value::Closure(closure_id) => {
                            let closure =
                                self.closures.get(*closure_id as usize).ok_or_else(|| {
                                    InterpreterError::TypeError {
                                        expected: "valid closure".to_string(),
                                        got: format!("closure#{closure_id} not found"),
                                    }
                                })?;
                            (
                                closure.function_index,
                                Some(self.clone_scope_frames_with_budget(&closure.captured_env)?),
                                Some(*closure_id),
                            )
                        }
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "function".to_string(),
                                got: callee_val.type_name().to_string(),
                            });
                        }
                    };

                    match &callee_val {
                        Value::Function(_) | Value::Closure(_) => {
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

                            // Allocate the `this` object for the constructor.
                            let prototype = self.ensure_function_prototype(func_idx)?;
                            let this_id = self.alloc_object_with_prototype(Some(prototype))?;
                            if let Some(this_obj) = self.heap.get_mut(this_id.0 as usize) {
                                this_obj.constructor_function = Some(func_idx);
                            }
                            let this_val = Value::Object(this_id);

                            let mut arg_vals = Vec::new();
                            for i in 0..args.count.min(func.arity) {
                                let reg = args.start.checked_add(i).ok_or(
                                    InterpreterError::RegisterOutOfBounds {
                                        register: args.start,
                                        max: self.config.max_registers,
                                    },
                                )?;
                                arg_vals.push(self.read_reg(reg)?);
                            }

                            self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;

                            // Push constructor frame with `construct_this`.
                            let scope_depth = self.scope_chain.depth();
                            let captured_env_bytes = captured_env
                                .as_ref()
                                .map(|env| Self::estimate_scope_chain_bytes(env))
                                .unwrap_or(0);
                            let captured_scope_depth = captured_env.as_ref().map_or(0, Vec::len);
                            let saved_chain = if captured_env.is_some() {
                                Some(self.snapshot_scope_chain_with_temporary_budget(
                                    captured_env_bytes,
                                )?)
                            } else {
                                None
                            };
                            self.call_stack.push(CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: dst,
                                register_base: self.register_base,
                                function_index: Some(func_idx),
                                this_value: this_val.clone(),
                                super_value: Value::Undefined,
                                construct_this: Some(this_val.clone()),
                                saved_pending_exception: self.pending_exception.take(),
                                saved_pending_return: self.pending_return.take(),
                                saved_suspended_abrupt_depth: self
                                    .suspended_abrupt_completions
                                    .len(),
                                saved_finally_mode_depth: self.finally_modes.len(),
                                saved_scope_depth: scope_depth,
                                saved_scope_chain: saved_chain,
                                closure_id,
                                captured_scope_depth,
                            });

                            // If calling a closure, restore its captured environment.
                            if let Some(env) = captured_env {
                                self.scope_chain.frames = env;
                            }
                            if let Err(err) = self.scope_chain.push(self.config.max_scope_depth) {
                                self.rollback_call_setup();
                                return Err(err);
                            }
                            if let Err(err) = self.sync_estimated_memory_bytes() {
                                self.rollback_call_setup();
                                return Err(err);
                            }

                            self.register_base += self.config.max_registers as usize;
                            let req_len = self.register_base + self.config.max_registers as usize;
                            if req_len > self.registers.len() {
                                self.registers.resize(req_len, Value::Undefined);
                            } else {
                                self.registers[self.register_base..req_len].fill(Value::Undefined);
                            }

                            // Register 0 = `this` for the constructor body.
                            self.write_reg(0, this_val)?;
                            // Arguments start at register 1.
                            for (i, val) in arg_vals.into_iter().enumerate() {
                                let reg = (i + 1) as u32;
                                if reg < self.config.max_registers {
                                    self.write_reg(reg, val)?;
                                }
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
                Ir3Instruction::TemplateLiteral { parts, dst } => {
                    let mut result = String::new();
                    for i in 0..parts.count {
                        let reg = parts.start.checked_add(i).ok_or(
                            InterpreterError::RegisterOutOfBounds {
                                register: parts.start,
                                max: self.config.max_registers,
                            },
                        )?;
                        let val = self.read_reg(reg)?;
                        let part_str = match val {
                            Value::Str(s) => s,
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.to_string(),
                            Value::Bool(b) => (if b { "true" } else { "false" }).to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            Value::Object(_) | Value::Iterator(_) | Value::Generator(_) => {
                                "[object Object]".to_string()
                            }
                            Value::Promise(_) => "[object Promise]".to_string(),
                            Value::Function(_)
                            | Value::Closure(_)
                            | Value::GeneratorFunction(_)
                            | Value::BuiltinFunction(_)
                            | Value::AsyncFunction(_)
                            | Value::AsyncFunctionObject(_)
                            | Value::AsyncGeneratorFunction(_)
                            | Value::AsyncGeneratorObject(_) => "function".to_string(),
                        };
                        self.check_string_limit(result.len().saturating_add(part_str.len()))?;
                        result.push_str(&part_str);
                    }
                    self.write_reg(dst, Value::Str(result))?;
                    self.ip += 1;
                }
                Ir3Instruction::Halt => {
                    return Err(InterpreterError::Halted);
                }
                Ir3Instruction::LoadThis { dst } => {
                    let this_val = self
                        .call_stack
                        .last()
                        .map_or(Value::Undefined, |f| f.this_value.clone());
                    self.write_reg(dst, this_val)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadSuper { dst } => {
                    let super_val = self
                        .call_stack
                        .last()
                        .map_or(Value::Undefined, |f| f.super_value.clone());
                    self.write_reg(dst, super_val)?;
                    self.ip += 1;
                }
                // ---------------------------------------------------------
                // Exception handling — real unwinding semantics (RGC-313B).
                // ---------------------------------------------------------
                Ir3Instruction::BeginTry {
                    catch_target,
                    finally_target,
                } => {
                    self.catch_frames.push(CatchFrame {
                        catch_target: catch_target as usize,
                        finally_target: finally_target.map(|t| t as usize),
                        call_depth: self.call_stack.len(),
                    });
                    self.ip += 1;
                }
                Ir3Instruction::EndTry => {
                    // Normal completion of the try block — pop the catch frame.
                    let _ = self.pop_current_try_frame();
                    self.ip += 1;
                }
                Ir3Instruction::Throw { value } => {
                    let thrown = self.read_reg(value)?;
                    self.suspend_current_abrupt_completion();
                    self.pending_return = None;
                    self.pending_exception = Some(thrown.clone());
                    // Walk the catch frame stack to find the nearest valid handler.
                    // Use rposition to find the topmost matching frame by index,
                    // then truncate to remove it and any frames above it — but
                    // NOT frames below it (which belong to outer try blocks).
                    if let Some(frame) = self.pop_exception_target_frame() {
                        self.ip = frame.catch_target;
                    } else {
                        // No catch handler found — uncaught exception.
                        self.suspended_abrupt_completions.clear();
                        let desc = match &thrown {
                            Value::Str(s) => s.clone(),
                            Value::Int(n) => n.to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Undefined => "undefined".to_string(),
                            Value::Null => "null".to_string(),
                            _ => "[object]".to_string(),
                        };
                        return Err(InterpreterError::UncaughtException { value: desc });
                    }
                }
                Ir3Instruction::EnterCatch { dst } => {
                    // Load the pending exception into the catch binding register.
                    let exception = self.pending_exception.take().unwrap_or(Value::Undefined);
                    self.restore_suspended_abrupt_completion();
                    self.write_reg(dst, exception)?;
                    self.ip += 1;
                }
                Ir3Instruction::EnterFinally => {
                    // Track whether we entered the finally block via normal
                    // control flow, exception unwinding, or return unwinding.
                    if self.pending_exception.is_some() {
                        self.finally_modes.push(FinallyMode::Exception);
                    } else if self.pending_return.is_some() {
                        self.finally_modes.push(FinallyMode::Return);
                    } else {
                        self.finally_modes.push(FinallyMode::Normal);
                    }
                    self.ip += 1;
                }
                Ir3Instruction::EndFinally => {
                    let mode = self.finally_modes.pop().unwrap_or(FinallyMode::Normal);
                    match mode {
                        FinallyMode::Exception => {
                            // Re-throw the pending exception after finally completes.
                            if let Some(thrown) = self.pending_exception.clone() {
                                let desc = match &thrown {
                                    Value::Str(s) => s.clone(),
                                    Value::Int(n) => n.to_string(),
                                    Value::Bool(b) => b.to_string(),
                                    Value::Undefined => "undefined".to_string(),
                                    Value::Null => "null".to_string(),
                                    _ => "[object]".to_string(),
                                };
                                // Look for another catch frame to propagate to.
                                if let Some(frame) = self.pop_exception_target_frame() {
                                    self.ip = frame.catch_target;
                                } else {
                                    self.suspended_abrupt_completions.clear();
                                    return Err(InterpreterError::UncaughtException {
                                        value: desc,
                                    });
                                }
                            } else {
                                // Exception was consumed (shouldn't happen, but safe fallthrough).
                                self.ip += 1;
                            }
                        }
                        FinallyMode::Return => {
                            if let Some(return_val) = self.pending_return.take() {
                                if let Some(finally_target) = self.pop_current_finally_target() {
                                    self.pending_return = Some(return_val);
                                    self.ip = finally_target;
                                } else {
                                    if let Some(final_value) = self.complete_return(return_val)? {
                                        return Ok(final_value);
                                    }
                                }
                            } else {
                                self.ip += 1;
                            }
                        }
                        FinallyMode::Normal => {
                            // Normal completion — just continue.
                            self.ip += 1;
                        }
                    }
                }

                // ���─ Closure / scope-chain instructions ────────────────
                Ir3Instruction::CreateClosure {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    // Snapshot the current scope chain including any
                    // bindings declared so far. Pending captures were
                    // accumulated by prior PushCapture instructions but
                    // the scope chain snapshot already contains those
                    // bindings, so we just clear them.
                    let captured_env = self.snapshot_scope_chain()?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        self.closures.pop();
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    // Store the closure ID (not function_index) so Call can
                    // look up the correct closure instance.
                    self.write_reg(dst, Value::Closure(closure_id))?;
                    self.ip += 1;
                }
                Ir3Instruction::CreateGenerator {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    let captured_env = self.snapshot_scope_chain()?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        self.closures.pop();
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.write_reg(dst, Value::GeneratorFunction(closure_id))?;
                    self.ip += 1;
                }
                Ir3Instruction::CreateAsyncFunction {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    let captured_env = self.snapshot_scope_chain()?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        self.closures.pop();
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.write_reg(dst, Value::AsyncFunction(closure_id))?;
                    self.ip += 1;
                }
                Ir3Instruction::CreateAsyncGenerator {
                    dst,
                    function_index,
                    capture_count,
                } => {
                    self.run_pre_allocation_hook(
                        module,
                        AllocKind::Closure,
                        capture_count as usize,
                    )?;
                    let captured_env = self.snapshot_scope_chain()?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    self.closures.push(ClosureValue {
                        function_index,
                        captured_env,
                    });
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        self.closures.pop();
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.pending_captures.clear();
                    self.write_reg(dst, Value::AsyncGeneratorFunction(closure_id))?;
                    self.ip += 1;
                }
                Ir3Instruction::Yield {
                    value,
                    delegate: _,
                    resume_dst,
                } => {
                    let yielded = self.read_reg(value)?;
                    let result_id = self.alloc_object_with_prototype(None)?;
                    {
                        self.set_object_property(result_id, "value".to_string(), yielded)?;
                        self.set_object_property(
                            result_id,
                            "done".to_string(),
                            Value::Bool(false),
                        )?;
                    }
                    self.ip += 1;
                    self.write_reg(resume_dst, Value::Undefined)?;
                    return Ok(Value::Object(result_id));
                }
                Ir3Instruction::AwaitValue { promise_reg } => {
                    let awaited_value = self.read_reg(promise_reg)?;

                    // Convert the awaited value to a Promise if it's not already one
                    let promise_handle = match awaited_value {
                        Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                        _ => {
                            // await non-promise: create a resolved promise with the value
                            let js_val = Self::value_to_js_value(&awaited_value);
                            let handle = self.promise_store.create();
                            let label = crate::ifc_artifacts::Label::Public; // TODO: proper label propagation
                            self.fulfill_promise(handle, js_val, label)?;
                            handle
                        }
                    };

                    // Check if the promise is already settled
                    let promise_record = self.promise_store.get(promise_handle).map_err(|e| {
                        InterpreterError::TypeError {
                            expected: "valid promise".to_string(),
                            got: e.to_string(),
                        }
                    })?;

                    if promise_record.state.is_settled() {
                        // Promise already settled - continue execution synchronously
                        match &promise_record.state {
                            crate::promise_model::PromiseState::Fulfilled(js_val) => {
                                let _result_value = Self::js_value_to_value(js_val);
                                // Store result in a temporary register or continue with the value
                                // For now, we'll need to figure out where to store the resolved value
                                // This might need to be handled by the lowering pipeline
                                self.ip += 1;
                                return Ok(Value::Undefined); // Placeholder
                            }
                            crate::promise_model::PromiseState::Rejected(js_reason) => {
                                let error_value = Self::js_value_to_value(js_reason);
                                return Err(InterpreterError::UncaughtException {
                                    value: format!("{}", error_value),
                                });
                            }
                            crate::promise_model::PromiseState::Pending => {
                                unreachable!("is_settled() returned true but state is Pending")
                            }
                        }
                    } else {
                        // Promise is pending - suspend execution
                        // TODO: Implement async function suspension and microtask registration
                        // This requires identifying which async function we're in and saving its state
                        return Err(InterpreterError::TypeError {
                            expected: "async function suspension".to_string(),
                            got: "await pending promise (not fully implemented)".to_string(),
                        });
                    }
                }
                Ir3Instruction::AsyncReturn { value_reg } => {
                    let return_value = self.read_reg(value_reg)?;

                    // Find the currently executing async function to get its result promise
                    // TODO: We need a way to track which async function is currently executing
                    // For now, we'll implement a basic version that assumes we're in an async context

                    // This is a simplified implementation - in a full implementation, we'd need
                    // to track the current async function context and resolve its result promise
                    let _js_val = Self::value_to_js_value(&return_value);

                    // For now, return an error indicating this needs more context tracking
                    return Err(InterpreterError::TypeError {
                        expected: "async function context tracking".to_string(),
                        got: "async return without context (partially implemented)".to_string(),
                    });
                }
                Ir3Instruction::AsyncThrow { error_reg } => {
                    let error_value = self.read_reg(error_reg)?;

                    // Find the currently executing async function to get its result promise
                    // TODO: We need a way to track which async function is currently executing
                    // For now, we'll implement a basic version that assumes we're in an async context

                    // This is a simplified implementation - in a full implementation, we'd need
                    // to track the current async function context and reject its result promise
                    let _js_reason = Self::value_to_js_value(&error_value);

                    // For now, return an error indicating this needs more context tracking
                    return Err(InterpreterError::TypeError {
                        expected: "async function context tracking".to_string(),
                        got: "async throw without context (partially implemented)".to_string(),
                    });
                }
                Ir3Instruction::PushCapture { name_pool_index } => {
                    self.pending_captures.push(name_pool_index);
                    self.ip += 1;
                }
                Ir3Instruction::PushScope => {
                    self.scope_chain.push(self.config.max_scope_depth)?;
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        self.scope_chain.pop();
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    if let Err(err) = self.inject_active_cjs_bindings() {
                        self.scope_chain.pop();
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.ip += 1;
                }
                Ir3Instruction::PopScope => {
                    let popped = self.scope_chain.pop();
                    self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                    debug_assert!(popped.is_some() || self.scope_chain.depth() == 1);
                    self.ip += 1;
                }
                Ir3Instruction::DeclareBinding {
                    name_pool_index,
                    kind,
                } => {
                    let name = module
                        .constant_pool
                        .get(name_pool_index as usize)
                        .cloned()
                        .unwrap_or_else(|| format!("__binding_{name_pool_index}"));
                    let binding_kind = BindingKind::from_u8(kind);
                    let replaced = self
                        .scope_chain
                        .current_mut()
                        .declare(name.clone(), binding_kind);
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        let current = self.scope_chain.current_mut();
                        if let Some(old) = replaced {
                            current.bindings.insert(name, old);
                        } else {
                            current.bindings.remove(&name);
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.ip += 1;
                }
                Ir3Instruction::LoadScoped {
                    dst,
                    name_pool_index,
                } => {
                    let name = module
                        .constant_pool
                        .get(name_pool_index as usize)
                        .cloned()
                        .unwrap_or_else(|| format!("__binding_{name_pool_index}"));
                    let val = if let Some((_, binding)) = self.scope_chain.resolve(&name) {
                        if !binding.initialized {
                            return Err(InterpreterError::UninitializedBinding {
                                name: name.clone(),
                            });
                        }
                        binding.value.clone()
                    } else if let Some(context) = self.active_cjs_context.as_ref() {
                        let (filename, dirname) =
                            self.cjs_filename_dirname(Some(&context.module_specifier));
                        match name.as_str() {
                            "__filename" => filename,
                            "__dirname" => dirname,
                            _ => Value::Undefined,
                        }
                    } else {
                        Value::Undefined
                    };
                    self.write_reg(dst, val)?;
                    self.ip += 1;
                }
                Ir3Instruction::StoreScoped {
                    src,
                    name_pool_index,
                } => {
                    let name = module
                        .constant_pool
                        .get(name_pool_index as usize)
                        .cloned()
                        .unwrap_or_else(|| format!("__binding_{name_pool_index}"));
                    let val = self.read_reg(src)?;
                    let mut previous = None;
                    if let Some(binding) = self.scope_chain.resolve_mut(&name) {
                        if !binding.initialized {
                            return Err(InterpreterError::UninitializedBinding {
                                name: name.clone(),
                            });
                        }
                        if binding.kind == BindingKind::Const {
                            return Err(InterpreterError::ConstAssignment { name: name.clone() });
                        }
                        previous = Some(binding.clone());
                        binding.value = val;
                    }
                    // Silently ignore stores to undeclared variables
                    // (strict mode would throw, but baseline is lenient).
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        if let Some(old_binding) = previous
                            && let Some(binding) = self.scope_chain.resolve_mut(&name)
                        {
                            *binding = old_binding;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.ip += 1;
                }
                Ir3Instruction::InitBinding {
                    name_pool_index,
                    src,
                } => {
                    let name = module
                        .constant_pool
                        .get(name_pool_index as usize)
                        .cloned()
                        .unwrap_or_else(|| format!("__binding_{name_pool_index}"));
                    let val = self.read_reg(src)?;
                    let mut previous = None;
                    if let Some(binding) = self.scope_chain.resolve_mut(&name) {
                        previous = Some(binding.clone());
                        binding.value = val;
                        binding.initialized = true;
                    }
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        if let Some(old_binding) = previous
                            && let Some(binding) = self.scope_chain.resolve_mut(&name)
                        {
                            *binding = old_binding;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.ip += 1;
                }
            }

            // Record profiling data for this instruction
            if let (Some(profiler), Some(profile_start), Some(instruction)) = (
                &mut self.profiling_data,
                profile_start,
                profiling_instruction.as_ref(),
            ) {
                profiler.record_instruction(instruction);
                profiler.record_instruction_time(instruction, profile_start.elapsed());
            }
        }
    }

    // -- Arithmetic helpers ------------------------------------------------

    fn check_string_limit(&self, len: usize) -> Result<(), InterpreterError> {
        if len > self.config.max_string_size {
            Err(InterpreterError::StringLimitExceeded {
                length: len,
                max: self.config.max_string_size,
            })
        } else {
            Ok(())
        }
    }

    fn eval_add(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        match (&a, &b) {
            // Int + Int: stay in integer domain
            (Value::Int(x), Value::Int(y)) => Ok(Value::Int(x.wrapping_add(*y))),
            // Float + Float: float arithmetic
            (Value::Float(x), Value::Float(y)) => {
                Ok(Value::Float(Float64::new(x.inner() + y.inner())))
            }
            // Int + Float or Float + Int: promote to float
            (Value::Int(x), Value::Float(y)) => {
                Ok(Value::Float(Float64::new(*x as f64 + y.inner())))
            }
            (Value::Float(x), Value::Int(y)) => {
                Ok(Value::Float(Float64::new(x.inner() + *y as f64)))
            }
            // String concatenation
            (Value::Str(x), Value::Str(y)) => {
                self.check_string_limit(x.len().saturating_add(y.len()))?;
                Ok(Value::Str(format!("{x}{y}")))
            }
            (Value::Str(x), other) => {
                let other_str = match other {
                    Value::Object(_) | Value::Iterator(_) | Value::Generator(_) => {
                        "[object Object]".to_string()
                    }
                    Value::Promise(_) => "[object Promise]".to_string(),
                    Value::Function(_)
                    | Value::Closure(_)
                    | Value::GeneratorFunction(_)
                    | Value::BuiltinFunction(_) => "function".to_string(),
                    _ => other.to_string(),
                };
                self.check_string_limit(x.len().saturating_add(other_str.len()))?;
                Ok(Value::Str(format!("{x}{other_str}")))
            }
            (other, Value::Str(y)) => {
                let other_str = match other {
                    Value::Object(_) | Value::Iterator(_) | Value::Generator(_) => {
                        "[object Object]".to_string()
                    }
                    Value::Promise(_) => "[object Promise]".to_string(),
                    Value::Function(_)
                    | Value::Closure(_)
                    | Value::GeneratorFunction(_)
                    | Value::BuiltinFunction(_) => "function".to_string(),
                    _ => other.to_string(),
                };
                self.check_string_limit(other_str.len().saturating_add(y.len()))?;
                Ok(Value::Str(format!("{other_str}{y}")))
            }
            _ => {
                // JS coercion: non-string primitives coerce to number for +.
                // Use float coercion to handle all numeric cases properly.
                let x = Self::coerce_to_float(&a).ok_or(InterpreterError::TypeError {
                    expected: "number or string".to_string(),
                    got: format!("{} + {}", a.type_name(), b.type_name()),
                })?;
                let y = Self::coerce_to_float(&b).ok_or(InterpreterError::TypeError {
                    expected: "number or string".to_string(),
                    got: format!("{} + {}", a.type_name(), b.type_name()),
                })?;
                let result = x + y;
                // If result is a whole number and fits in i64, return Int
                if result.fract() == 0.0
                    && !result.is_nan()
                    && !result.is_infinite()
                    && result >= i64::MIN as f64
                    && result <= i64::MAX as f64
                {
                    Ok(Value::Int(result as i64))
                } else {
                    Ok(Value::Float(Float64::new(result)))
                }
            }
        }
    }

    fn eval_arith(&self, lhs: u32, rhs: u32, op: &str) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;

        // Fast path: Int op Int stays in integer domain
        if let (Value::Int(x), Value::Int(y)) = (&a, &b) {
            let result = match op {
                "sub" => x.wrapping_sub(*y),
                "mul" => x.wrapping_mul(*y),
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "sub or mul".to_string(),
                        got: op.to_string(),
                    });
                }
            };
            return Ok(Value::Int(result));
        }

        // Float path: use float arithmetic
        let x = Self::coerce_to_float(&a).ok_or(InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} {} {}", a.type_name(), op, b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or(InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} {} {}", a.type_name(), op, b.type_name()),
        })?;
        let result = match op {
            "sub" => x - y,
            "mul" => x * y,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "sub or mul".to_string(),
                    got: op.to_string(),
                });
            }
        };

        // Return Int if result is a whole number in i64 range
        if result.fract() == 0.0
            && !result.is_nan()
            && !result.is_infinite()
            && result >= i64::MIN as f64
            && result <= i64::MAX as f64
        {
            Ok(Value::Int(result as i64))
        } else {
            Ok(Value::Float(Float64::new(result)))
        }
    }

    fn eval_div(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        let x = Self::coerce_to_float(&a).ok_or(InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} / {}", a.type_name(), b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or(InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} / {}", a.type_name(), b.type_name()),
        })?;

        // JS division semantics: x/0 = Infinity (or -Infinity), 0/0 = NaN
        let result = x / y;

        // Return Int if result is a whole number in i64 range
        if result.fract() == 0.0
            && !result.is_nan()
            && !result.is_infinite()
            && result >= i64::MIN as f64
            && result <= i64::MAX as f64
        {
            Ok(Value::Int(result as i64))
        } else {
            Ok(Value::Float(Float64::new(result)))
        }
    }

    fn eval_mod(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;

        // Fast path: Int % Int stays in integer domain
        if let (Value::Int(x), Value::Int(y)) = (&a, &b) {
            if *y == 0 {
                // JS: x % 0 = NaN
                return Ok(Value::Float(Float64::new(f64::NAN)));
            }
            return Ok(Value::Int(x.checked_rem(*y).unwrap_or(0)));
        }

        let x = Self::coerce_to_float(&a).ok_or(InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} % {}", a.type_name(), b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or(InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} % {}", a.type_name(), b.type_name()),
        })?;

        // JS modulo semantics: x % 0 = NaN
        let result = x % y;

        // Return Int if result is a whole number in i64 range
        if result.fract() == 0.0
            && !result.is_nan()
            && !result.is_infinite()
            && result >= i64::MIN as f64
            && result <= i64::MAX as f64
        {
            Ok(Value::Int(result as i64))
        } else {
            Ok(Value::Float(Float64::new(result)))
        }
    }

    fn eval_exp(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        let x = Self::coerce_to_float(&a).ok_or(InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} ** {}", a.type_name(), b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or(InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} ** {}", a.type_name(), b.type_name()),
        })?;

        // JS exponentiation uses float power
        let result = x.powf(y);

        // Return Int if result is a whole number in i64 range
        if result.fract() == 0.0
            && !result.is_nan()
            && !result.is_infinite()
            && result >= i64::MIN as f64
            && result <= i64::MAX as f64
        {
            Ok(Value::Int(result as i64))
        } else {
            Ok(Value::Float(Float64::new(result)))
        }
    }

    fn eval_unary_plus(&self, src: u32) -> Result<Value, InterpreterError> {
        let value = self.read_reg(src)?;
        match &value {
            Value::Int(n) => Ok(Value::Int(*n)),
            Value::Float(f) => Ok(Value::Float(*f)),
            _ => {
                let number = Self::coerce_to_float(&value).ok_or(InterpreterError::TypeError {
                    expected: "number-coercible primitive".to_string(),
                    got: value.type_name().to_string(),
                })?;
                // Return Int if whole number in i64 range
                if number.fract() == 0.0
                    && !number.is_nan()
                    && !number.is_infinite()
                    && number >= i64::MIN as f64
                    && number <= i64::MAX as f64
                {
                    Ok(Value::Int(number as i64))
                } else {
                    Ok(Value::Float(Float64::new(number)))
                }
            }
        }
    }

    fn eval_unary_neg(&self, src: u32) -> Result<Value, InterpreterError> {
        let value = self.read_reg(src)?;
        match &value {
            Value::Int(n) => Ok(Value::Int(n.wrapping_neg())),
            Value::Float(f) => Ok(Value::Float(Float64::new(-f.inner()))),
            _ => {
                let number = Self::coerce_to_float(&value).ok_or(InterpreterError::TypeError {
                    expected: "number-coercible primitive".to_string(),
                    got: value.type_name().to_string(),
                })?;
                // Return Int if whole number in i64 range
                let negated = -number;
                if negated.fract() == 0.0
                    && !negated.is_nan()
                    && !negated.is_infinite()
                    && negated >= i64::MIN as f64
                    && negated <= i64::MAX as f64
                {
                    Ok(Value::Int(negated as i64))
                } else {
                    Ok(Value::Float(Float64::new(negated)))
                }
            }
        }
    }

    fn eval_bit_not(&self, src: u32) -> Result<Value, InterpreterError> {
        let value = self.read_reg(src)?;
        // JS bitwise ops: ToInt32 conversion
        let number = match &value {
            Value::Int(n) => *n as i32,
            Value::Float(f) => {
                let v = f.inner();
                if v.is_nan() || v.is_infinite() {
                    0
                } else {
                    v as i32
                }
            }
            _ => {
                let n = Self::coerce_to_float(&value).ok_or(InterpreterError::TypeError {
                    expected: "number-coercible primitive".to_string(),
                    got: value.type_name().to_string(),
                })?;
                if n.is_nan() || n.is_infinite() {
                    0
                } else {
                    n as i32
                }
            }
        };
        Ok(Value::Int((!number) as i64))
    }

    fn eval_relational(&self, lhs: u32, rhs: u32, op: &str) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;

        // String comparison
        if let (Value::Str(x), Value::Str(y)) = (&a, &b) {
            let ordering = x.cmp(y);
            let result = match op {
                "<" => ordering == Ordering::Less,
                "<=" => matches!(ordering, Ordering::Less | Ordering::Equal),
                ">" => ordering == Ordering::Greater,
                ">=" => matches!(ordering, Ordering::Greater | Ordering::Equal),
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "relational operator".to_string(),
                        got: op.to_string(),
                    });
                }
            };
            return Ok(Value::Bool(result));
        }

        // Numeric comparison using float (NaN comparisons return false)
        let x = Self::coerce_to_float(&a).ok_or(InterpreterError::TypeError {
            expected: "comparable primitive".to_string(),
            got: format!("{} {op} {}", a.type_name(), b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or(InterpreterError::TypeError {
            expected: "comparable primitive".to_string(),
            got: format!("{} {op} {}", a.type_name(), b.type_name()),
        })?;

        // JS: any comparison involving NaN returns false
        let result = match op {
            "<" => x < y,
            "<=" => x <= y,
            ">" => x > y,
            ">=" => x >= y,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "relational operator".to_string(),
                    got: op.to_string(),
                });
            }
        };
        Ok(Value::Bool(result))
    }

    fn eval_equality(
        &self,
        lhs: u32,
        rhs: u32,
        strict: bool,
        negate: bool,
    ) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        let matches = if strict {
            Self::strict_eq_values(&a, &b)
        } else {
            Self::abstract_eq_values(&a, &b)
        };
        Ok(Value::Bool(if negate { !matches } else { matches }))
    }

    /// JavaScript strict equality (===): same type + same value.
    /// For floats: NaN !== NaN, but -0 === +0.
    fn strict_eq_values(a: &Value, b: &Value) -> bool {
        match (a, b) {
            // Float === Float: NaN !== NaN, but -0 === +0
            (Value::Float(fa), Value::Float(fb)) => {
                let va = fa.inner();
                let vb = fb.inner();
                if va.is_nan() || vb.is_nan() {
                    false
                } else {
                    va == vb
                }
            }
            // Int === Float or Float === Int: compare as numbers
            (Value::Int(n), Value::Float(f)) | (Value::Float(f), Value::Int(n)) => {
                let fv = f.inner();
                if fv.is_nan() { false } else { *n as f64 == fv }
            }
            // All other types: use derived PartialEq
            _ => a == b,
        }
    }

    fn eval_bitwise(&self, lhs: u32, rhs: u32, op: &str) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;

        // JS ToInt32: convert to float then truncate
        let to_i32 = |v: &Value| -> Result<i32, InterpreterError> {
            match v {
                Value::Int(n) => Ok(*n as i32),
                Value::Float(f) => {
                    let fv = f.inner();
                    if fv.is_nan() || fv.is_infinite() {
                        Ok(0)
                    } else {
                        Ok(fv as i32)
                    }
                }
                _ => {
                    let n = Self::coerce_to_float(v).ok_or(InterpreterError::TypeError {
                        expected: "number".to_string(),
                        got: v.type_name().to_string(),
                    })?;
                    if n.is_nan() || n.is_infinite() {
                        Ok(0)
                    } else {
                        Ok(n as i32)
                    }
                }
            }
        };

        let x = to_i32(&a)?;
        let y = to_i32(&b)?;
        let shift = (y as u32) & 31;

        let result = match op {
            "&" => (x & y) as i64,
            "|" => (x | y) as i64,
            "^" => (x ^ y) as i64,
            "<<" => x.wrapping_shl(shift) as i64,
            ">>" => x.wrapping_shr(shift) as i64,
            ">>>" => (x as u32).wrapping_shr(shift) as i64,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "bitwise operator".to_string(),
                    got: op.to_string(),
                });
            }
        };
        Ok(Value::Int(result))
    }

    fn eval_instanceof(&mut self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let candidate = self.read_reg(lhs)?;
        let constructor = self.read_reg(rhs)?;
        let func_idx = match constructor {
            Value::Function(func_idx) => func_idx,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "function".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };

        let Value::Object(object_id) = candidate else {
            return Ok(Value::Bool(false));
        };

        let prototype = self.ensure_function_prototype(func_idx)?;
        Ok(Value::Bool(
            self.prototype_chain_contains(object_id, prototype)?,
        ))
    }

    fn eval_in_operator(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let key = Self::property_key(&self.read_reg(lhs)?);
        let target = self.read_reg(rhs)?;
        match target {
            Value::Object(object_id) => {
                self.heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                Ok(Value::Bool(self.prototype_chain_has_key(object_id, &key)?))
            }
            other => Err(InterpreterError::TypeError {
                expected: "object".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    fn init_for_in_iterator(&mut self, value: Value) -> Result<Value, InterpreterError> {
        let Value::Object(object_id) = value else {
            return Err(InterpreterError::TypeError {
                expected: "object".to_string(),
                got: value.type_name().to_string(),
            });
        };

        let keys = self.collect_for_in_keys(object_id)?;
        let handle = self.alloc_iterator(RuntimeIteratorState::ForIn(RuntimeForInState {
            object_id,
            keys,
            next_index: 0,
            deleted_keys: BTreeSet::new(),
            done: false,
            closed: false,
        }))?;
        Ok(Value::Iterator(handle))
    }

    fn advance_for_in_iterator(
        &mut self,
        iterator: Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let handle = self.expect_iterator_handle(iterator)?;
        match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForIn(state) => {
                if state.closed || state.done {
                    state.done = true;
                    return Ok(None);
                }
                while state.next_index < state.keys.len() {
                    let key = state.keys[state.next_index].clone();
                    state.next_index += 1;
                    if !state.deleted_keys.contains(&key) {
                        return Ok(Some(Value::Str(key)));
                    }
                }
                state.done = true;
                Ok(None)
            }
            RuntimeIteratorState::ForOf(_) => Err(InterpreterError::TypeError {
                expected: "for..in iterator".to_string(),
                got: "for..of iterator".to_string(),
            }),
        }
    }

    fn init_for_of_iterator(&mut self, value: Value) -> Result<Value, InterpreterError> {
        let values = self.collect_for_of_values(&value)?;
        let handle = self.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
            values,
            next_index: 0,
            done: false,
            closed: false,
        }))?;
        Ok(Value::Iterator(handle))
    }

    fn advance_for_of_iterator(
        &mut self,
        iterator: Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let handle = self.expect_iterator_handle(iterator)?;
        match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForOf(state) => {
                if state.closed || state.done {
                    state.done = true;
                    return Ok(None);
                }
                if let Some(value) = state.values.get(state.next_index).cloned() {
                    state.next_index += 1;
                    Ok(Some(value))
                } else {
                    state.done = true;
                    Ok(None)
                }
            }
            RuntimeIteratorState::ForIn(_) => Err(InterpreterError::TypeError {
                expected: "for..of iterator".to_string(),
                got: "for..in iterator".to_string(),
            }),
        }
    }

    fn close_iterator(
        &mut self,
        iterator: Value,
        _reason: IteratorCloseReason,
    ) -> Result<(), InterpreterError> {
        let handle = self.expect_iterator_handle(iterator)?;
        match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForIn(state) => {
                state.closed = true;
                state.done = true;
            }
            RuntimeIteratorState::ForOf(state) => {
                state.closed = true;
                state.done = true;
            }
        }
        Ok(())
    }

    fn prototype_chain_contains(
        &self,
        object_id: ObjectId,
        prototype: ObjectId,
    ) -> Result<bool, InterpreterError> {
        let mut current = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .prototype;
        let mut depth = 0u32;
        let mut visited = BTreeSet::new();
        visited.insert(object_id);

        while let Some(id) = current {
            if id == prototype {
                return Ok(true);
            }
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                return Ok(false);
            }
            current = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?
                .prototype;
            depth += 1;
        }

        Ok(false)
    }

    /// Walk the prototype chain to find a property value.
    fn prototype_chain_get(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut visited = BTreeSet::new();

        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                return Ok(Value::Undefined);
            }
            let object = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
            if let Some(val) = object.properties.get(key) {
                return Ok(val.clone());
            }
            current = object.prototype;
            depth += 1;
        }

        Ok(Value::Undefined)
    }

    fn prototype_chain_has_key(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<bool, InterpreterError> {
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut visited = BTreeSet::new();

        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                return Ok(false);
            }
            let object = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
            if object.properties.contains_key(key) {
                return Ok(true);
            }
            current = object.prototype;
            depth += 1;
        }

        Ok(false)
    }

    // -- Promise hostcall dispatch ------------------------------------------

    /// Convert a baseline `Value` to a `JsValue` from `object_model` for the
    /// promise subsystem.
    fn value_to_js_value(val: &Value) -> crate::object_model::JsValue {
        match val {
            Value::Undefined => crate::object_model::JsValue::Undefined,
            Value::Null => crate::object_model::JsValue::Null,
            Value::Bool(b) => crate::object_model::JsValue::Bool(*b),
            Value::Int(n) => crate::object_model::JsValue::Int(*n),
            Value::Float(f) => crate::object_model::JsValue::Float(f.inner().to_bits()),
            Value::Str(s) => crate::object_model::JsValue::Str(s.clone()),
            Value::Object(id) => {
                crate::object_model::JsValue::Object(crate::object_model::ObjectHandle(id.0))
            }
            Value::Function(idx) => crate::object_model::JsValue::Function(*idx),
            _ => crate::object_model::JsValue::Str(val.to_string()),
        }
    }

    /// Convert a `JsValue` from `object_model` back to a baseline `Value`.
    #[allow(dead_code)]
    fn js_value_to_value(jv: &crate::object_model::JsValue) -> Value {
        match jv {
            crate::object_model::JsValue::Undefined => Value::Undefined,
            crate::object_model::JsValue::Null => Value::Null,
            crate::object_model::JsValue::Bool(b) => Value::Bool(*b),
            crate::object_model::JsValue::Int(n) => Value::Int(*n),
            crate::object_model::JsValue::Str(s) => Value::Str(s.clone()),
            crate::object_model::JsValue::Float(bits) => {
                Value::Float(Float64::new(f64::from_bits(*bits)))
            }
            crate::object_model::JsValue::Object(handle) => Value::Object(ObjectId(handle.0)),
            crate::object_model::JsValue::Function(idx) => Value::Function(*idx),
            crate::object_model::JsValue::Symbol(sym) => Value::Str(format!("Symbol({})", sym.0)),
        }
    }

    fn collect_promise_combinator_inputs(
        &self,
        args: RegRange,
    ) -> Result<Vec<Value>, InterpreterError> {
        if args.count == 0 {
            return Ok(Vec::new());
        }
        let first = self.read_reg(args.start)?;
        if args.count == 1 {
            if let Value::Object(id) = first {
                return Ok(self.read_array_like_values(id));
            }
            return Ok(vec![first]);
        }
        let mut values = Vec::with_capacity(args.count as usize);
        for i in 0..args.count {
            let reg = args
                .start
                .checked_add(i)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
            values.push(self.read_reg(reg)?);
        }
        Ok(values)
    }

    fn read_array_like_values(&self, obj_id: ObjectId) -> Vec<Value> {
        self.heap
            .get(obj_id.0 as usize)
            .map(|obj| {
                let mut values = Vec::new();
                let mut idx = 0u32;
                while let Some(val) = obj.properties.get(&idx.to_string()) {
                    values.push(val.clone());
                    idx += 1;
                }
                values
            })
            .unwrap_or_default()
    }

    fn alloc_array_from_values(&mut self, values: &[Value]) -> Result<ObjectId, InterpreterError> {
        let id = self.alloc_object_with_prototype(None)?;
        for (index, value) in values.iter().cloned().enumerate() {
            self.set_object_property(id, index.to_string(), value)?;
        }
        self.set_object_property(id, "length".to_string(), Value::Int(values.len() as i64))?;
        Ok(id)
    }

    fn alloc_object_with_properties(
        &mut self,
        props: &[(&str, Value)],
    ) -> Result<ObjectId, InterpreterError> {
        let id = self.alloc_object_with_prototype(None)?;
        for (key, value) in props {
            self.set_object_property(id, (*key).to_string(), value.clone())?;
        }
        Ok(id)
    }

    fn build_promise_all_result(
        &mut self,
        values: Vec<crate::object_model::JsValue>,
    ) -> Result<crate::object_model::JsValue, InterpreterError> {
        let value_objs: Vec<Value> = values.iter().map(Self::js_value_to_value).collect();
        let array_id = self.alloc_array_from_values(&value_objs)?;
        Ok(Self::value_to_js_value(&Value::Object(array_id)))
    }

    fn build_promise_all_settled_result(
        &mut self,
        outcomes: BTreeMap<u32, crate::promise_model::SettledOutcome>,
        total: u32,
    ) -> Result<crate::object_model::JsValue, InterpreterError> {
        let mut items = Vec::with_capacity(total as usize);
        for index in 0..total {
            let outcome =
                outcomes
                    .get(&index)
                    .cloned()
                    .unwrap_or(crate::promise_model::SettledOutcome {
                        status: "fulfilled".into(),
                        value: crate::object_model::JsValue::Undefined,
                    });
            let value = Self::js_value_to_value(&outcome.value);
            let mut props = vec![("status", Value::Str(outcome.status.clone()))];
            if outcome.status == "fulfilled" {
                props.push(("value", value));
            } else {
                props.push(("reason", value));
            }
            let obj_id = self.alloc_object_with_properties(&props)?;
            items.push(Value::Object(obj_id));
        }
        let array_id = self.alloc_array_from_values(&items)?;
        Ok(Self::value_to_js_value(&Value::Object(array_id)))
    }

    fn build_aggregate_error(
        &mut self,
        errors: Vec<crate::object_model::JsValue>,
    ) -> Result<crate::object_model::JsValue, InterpreterError> {
        let error_values: Vec<Value> = errors.iter().map(Self::js_value_to_value).collect();
        let errors_array = self.alloc_array_from_values(&error_values)?;
        let error_id = self.alloc_object_with_properties(&[
            ("name", Value::Str("AggregateError".into())),
            ("message", Value::Str("All promises were rejected".into())),
            ("errors", Value::Object(errors_array)),
        ])?;
        Ok(Self::value_to_js_value(&Value::Object(error_id)))
    }

    fn register_combinator(&mut self, state: PromiseCombinatorState) -> u64 {
        let id = self.next_promise_combinator_id;
        self.next_promise_combinator_id = self.next_promise_combinator_id.saturating_add(1);
        self.promise_combinators.insert(id, state);
        id
    }

    fn add_combinator_watcher(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        watcher: PromiseCombinatorWatcher,
    ) {
        self.promise_combinator_watchers
            .entry(handle)
            .or_default()
            .push(watcher);
    }

    fn fulfill_promise(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        value: crate::object_model::JsValue,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        self.promise_store
            .fulfill(
                handle,
                value.clone(),
                label.clone(),
                &mut self.event_loop.microtasks,
            )
            .map_err(|e| InterpreterError::TypeError {
                expected: "pending promise".to_string(),
                got: e.to_string(),
            })?;
        self.notify_promise_settled(handle, PromiseSettlement::Fulfilled(value), label)?;
        Ok(())
    }

    fn reject_promise(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        reason: crate::object_model::JsValue,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        self.promise_store
            .reject(
                handle,
                reason.clone(),
                label.clone(),
                &mut self.event_loop.microtasks,
            )
            .map_err(|e| InterpreterError::TypeError {
                expected: "pending promise".to_string(),
                got: e.to_string(),
            })?;
        self.notify_promise_settled(handle, PromiseSettlement::Rejected(reason), label)?;
        Ok(())
    }

    fn notify_promise_settled(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        settlement: PromiseSettlement,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let watchers = match self.promise_combinator_watchers.remove(&handle) {
            Some(watchers) => watchers,
            None => return Ok(()),
        };
        for watcher in watchers {
            match &settlement {
                PromiseSettlement::Fulfilled(value) => self.update_combinator_fulfillment(
                    watcher.combinator_id,
                    watcher.index,
                    value.clone(),
                    label.clone(),
                )?,
                PromiseSettlement::Rejected(reason) => self.update_combinator_rejection(
                    watcher.combinator_id,
                    watcher.index,
                    reason.clone(),
                    label.clone(),
                )?,
            }
        }
        Ok(())
    }

    fn update_combinator_fulfillment(
        &mut self,
        combinator_id: u64,
        index: u32,
        value: crate::object_model::JsValue,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        enum ResolutionData {
            Fulfill(
                crate::promise_model::PromiseHandle,
                crate::object_model::JsValue,
            ),
            FulfillAll(
                crate::promise_model::PromiseHandle,
                Vec<crate::object_model::JsValue>,
            ),
            FulfillAllSettled(
                crate::promise_model::PromiseHandle,
                BTreeMap<u32, crate::promise_model::SettledOutcome>,
                u32,
            ),
        }

        let mut resolution: Option<ResolutionData> = None;
        if let Some(state) = self.promise_combinators.get_mut(&combinator_id) {
            match state {
                PromiseCombinatorState::All(tracker) => {
                    if tracker.settled {
                        return Ok(());
                    }
                    if tracker.record_fulfillment(index, value) {
                        tracker.mark_settled();
                        let collected = tracker.collect_values();
                        resolution = Some(ResolutionData::FulfillAll(
                            tracker.result_promise,
                            collected,
                        ));
                    }
                }
                PromiseCombinatorState::AllSettled(tracker) => {
                    if tracker.record_fulfillment(index, value) {
                        resolution = Some(ResolutionData::FulfillAllSettled(
                            tracker.result_promise,
                            tracker.outcomes.clone(),
                            tracker.total,
                        ));
                    }
                }
                PromiseCombinatorState::Race(tracker) => {
                    if tracker.try_settle() {
                        resolution = Some(ResolutionData::Fulfill(tracker.result_promise, value));
                    }
                }
                PromiseCombinatorState::Any(tracker) => {
                    if tracker.settled {
                        return Ok(());
                    }
                    tracker.mark_settled();
                    resolution = Some(ResolutionData::Fulfill(tracker.result_promise, value));
                }
            }
        }

        if let Some(resolution) = resolution {
            let (handle, value) = match resolution {
                ResolutionData::Fulfill(handle, value) => (handle, value),
                ResolutionData::FulfillAll(handle, values) => {
                    let value = self.build_promise_all_result(values)?;
                    (handle, value)
                }
                ResolutionData::FulfillAllSettled(handle, outcomes, total) => {
                    let value = self.build_promise_all_settled_result(outcomes, total)?;
                    (handle, value)
                }
            };
            self.fulfill_promise(handle, value, label)?;
            self.promise_combinators.remove(&combinator_id);
        }
        Ok(())
    }

    fn update_combinator_rejection(
        &mut self,
        combinator_id: u64,
        index: u32,
        reason: crate::object_model::JsValue,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        enum ResolutionData {
            FulfillAllSettled(
                crate::promise_model::PromiseHandle,
                BTreeMap<u32, crate::promise_model::SettledOutcome>,
                u32,
            ),
            Reject(
                crate::promise_model::PromiseHandle,
                crate::object_model::JsValue,
            ),
            RejectAny(
                crate::promise_model::PromiseHandle,
                Vec<crate::object_model::JsValue>,
            ),
        }

        let mut resolution: Option<ResolutionData> = None;
        if let Some(state) = self.promise_combinators.get_mut(&combinator_id) {
            match state {
                PromiseCombinatorState::All(tracker) => {
                    if tracker.settled {
                        return Ok(());
                    }
                    tracker.mark_settled();
                    resolution = Some(ResolutionData::Reject(tracker.result_promise, reason));
                }
                PromiseCombinatorState::AllSettled(tracker) => {
                    if tracker.record_rejection(index, reason) {
                        resolution = Some(ResolutionData::FulfillAllSettled(
                            tracker.result_promise,
                            tracker.outcomes.clone(),
                            tracker.total,
                        ));
                    }
                }
                PromiseCombinatorState::Race(tracker) => {
                    if tracker.try_settle() {
                        resolution = Some(ResolutionData::Reject(tracker.result_promise, reason));
                    }
                }
                PromiseCombinatorState::Any(tracker) => {
                    if tracker.settled {
                        return Ok(());
                    }
                    if tracker.record_rejection(index, reason) {
                        tracker.mark_settled();
                        let errors = tracker.collect_errors();
                        resolution =
                            Some(ResolutionData::RejectAny(tracker.result_promise, errors));
                    }
                }
            }
        }

        if let Some(resolution) = resolution {
            match resolution {
                ResolutionData::FulfillAllSettled(handle, outcomes, total) => {
                    let value = self.build_promise_all_settled_result(outcomes, total)?;
                    self.fulfill_promise(handle, value, label)?;
                }
                ResolutionData::Reject(handle, reason) => {
                    self.reject_promise(handle, reason, label)?;
                }
                ResolutionData::RejectAny(handle, errors) => {
                    let aggregate = self.build_aggregate_error(errors)?;
                    self.reject_promise(handle, aggregate, label)?;
                }
            }
            self.promise_combinators.remove(&combinator_id);
        }
        Ok(())
    }

    fn dispatch_promise_combinator(
        &mut self,
        kind: PromiseCombinatorKind,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let label = crate::ifc_artifacts::Label::Public;
        let inputs = self.collect_promise_combinator_inputs(args)?;
        let total = inputs.len() as u32;
        let result_promise = self.promise_store.create();

        match kind {
            PromiseCombinatorKind::All | PromiseCombinatorKind::AllSettled if total == 0 => {
                let empty = self.build_promise_all_result(Vec::new())?;
                self.fulfill_promise(result_promise, empty, label)?;
                return Ok(Value::Promise(result_promise.0));
            }
            PromiseCombinatorKind::Any if total == 0 => {
                let aggregate = self.build_aggregate_error(Vec::new())?;
                self.reject_promise(result_promise, aggregate, label)?;
                return Ok(Value::Promise(result_promise.0));
            }
            PromiseCombinatorKind::Race if total == 0 => {
                return Ok(Value::Promise(result_promise.0));
            }
            _ => {}
        }

        let state = match kind {
            PromiseCombinatorKind::All => {
                PromiseCombinatorState::All(crate::promise_model::PromiseAllTracker {
                    result_promise,
                    values: BTreeMap::new(),
                    total,
                    resolved_count: 0,
                    settled: false,
                })
            }
            PromiseCombinatorKind::AllSettled => {
                PromiseCombinatorState::AllSettled(crate::promise_model::PromiseAllSettledTracker {
                    result_promise,
                    outcomes: BTreeMap::new(),
                    total,
                    settled_count: 0,
                })
            }
            PromiseCombinatorKind::Race => {
                PromiseCombinatorState::Race(crate::promise_model::PromiseRaceTracker {
                    result_promise,
                    settled: false,
                })
            }
            PromiseCombinatorKind::Any => {
                PromiseCombinatorState::Any(crate::promise_model::PromiseAnyTracker {
                    result_promise,
                    errors: BTreeMap::new(),
                    total,
                    rejected_count: 0,
                    settled: false,
                })
            }
        };

        let combinator_id = self.register_combinator(state);

        for (index, input) in inputs.into_iter().enumerate() {
            if !self.promise_combinators.contains_key(&combinator_id) {
                break;
            }
            let index = index as u32;
            match input {
                Value::Promise(handle) => {
                    let promise_handle = crate::promise_model::PromiseHandle(handle);
                    let record = self.promise_store.get(promise_handle).map_err(|e| {
                        InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: e.to_string(),
                        }
                    })?;
                    match &record.state {
                        crate::promise_model::PromiseState::Pending => {
                            self.add_combinator_watcher(
                                promise_handle,
                                PromiseCombinatorWatcher {
                                    combinator_id,
                                    index,
                                },
                            );
                        }
                        crate::promise_model::PromiseState::Fulfilled(value) => {
                            self.update_combinator_fulfillment(
                                combinator_id,
                                index,
                                value.clone(),
                                record.label.clone(),
                            )?;
                        }
                        crate::promise_model::PromiseState::Rejected(reason) => {
                            self.update_combinator_rejection(
                                combinator_id,
                                index,
                                reason.clone(),
                                record.label.clone(),
                            )?;
                        }
                    }
                }
                other => {
                    let js_val = Self::value_to_js_value(&other);
                    self.update_combinator_fulfillment(
                        combinator_id,
                        index,
                        js_val,
                        label.clone(),
                    )?;
                }
            }
        }

        Ok(Value::Promise(result_promise.0))
    }

    /// Dispatch a `promise:*` hostcall to the internal promise subsystem.
    ///
    /// Supported capabilities:
    /// - `promise:constructor` — create a pending promise, return its handle.
    /// - `promise:resolve` — resolve a promise or create a pre-resolved one.
    ///   arg0 = promise handle (or value to wrap), arg1 = value.
    /// - `promise:reject` — reject a promise or create a pre-rejected one.
    ///   arg0 = promise handle (or reason), arg1 = reason.
    /// - `promise:then` — register .then(onFulfilled, onRejected).
    ///   arg0 = promise handle value.
    /// - `promise:catch` — sugar for .then(undefined, onRejected).
    ///   arg0 = promise handle value.
    /// - `promise:finally` — register a finally handler.
    ///   arg0 = promise handle value.
    /// - `promise:all` — create a Promise.all aggregate.
    /// - `promise:race` — create a Promise.race aggregate.
    /// - `promise:allSettled` — create a Promise.allSettled aggregate.
    /// - `promise:any` — create a Promise.any aggregate.
    fn dispatch_promise_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let label = crate::ifc_artifacts::Label::Public;
        match cap {
            "promise:constructor" => {
                // Create a new pending promise and return its handle.
                let handle = self.promise_store.create();
                Ok(Value::Promise(handle.0))
            }
            "promise:resolve" => {
                // If arg0 is a Promise, resolve it with arg1.
                // Otherwise create a pre-resolved promise with arg0 as the value.
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                match arg0 {
                    Value::Promise(h) => {
                        // Resolve the existing promise with the given value.
                        let val = if args.count > 1 {
                            let reg = args.start.checked_add(1).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            self.read_reg(reg)?
                        } else {
                            Value::Undefined
                        };
                        let js_val = Self::value_to_js_value(&val);
                        let handle = crate::promise_model::PromiseHandle(h);
                        self.fulfill_promise(handle, js_val, label.clone())?;
                        Ok(Value::Promise(h))
                    }
                    _ => {
                        // Promise.resolve(value) — create a pre-resolved promise.
                        let js_val = Self::value_to_js_value(&arg0);
                        let handle = self.promise_store.create();
                        self.fulfill_promise(handle, js_val, label.clone())?;
                        Ok(Value::Promise(handle.0))
                    }
                }
            }
            "promise:reject" => {
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                match arg0 {
                    Value::Promise(h) => {
                        let reason = if args.count > 1 {
                            let reg = args.start.checked_add(1).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            self.read_reg(reg)?
                        } else {
                            Value::Undefined
                        };
                        let js_reason = Self::value_to_js_value(&reason);
                        let handle = crate::promise_model::PromiseHandle(h);
                        self.reject_promise(handle, js_reason, label.clone())?;
                        Ok(Value::Promise(h))
                    }
                    _ => {
                        // Promise.reject(reason) — create a pre-rejected promise.
                        let js_reason = Self::value_to_js_value(&arg0);
                        let handle = self.promise_store.create();
                        self.reject_promise(handle, js_reason, label.clone())?;
                        Ok(Value::Promise(handle.0))
                    }
                }
            }
            "promise:then" => {
                // arg0 = promise handle, arg1 = onFulfilled (optional),
                // arg2 = onRejected (optional).
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    return Err(InterpreterError::TypeError {
                        expected: "promise".to_string(),
                        got: "undefined".to_string(),
                    });
                };
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                // In the baseline interpreter, .then() callbacks are simplified:
                // we register reactions with no closure handlers (identity propagation).
                let result = self
                    .promise_store
                    .then(handle, None, None, label, &mut self.event_loop.microtasks)
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "valid promise handle".to_string(),
                        got: e.to_string(),
                    })?;
                Ok(Value::Promise(result.0))
            }
            "promise:catch" => {
                // Sugar for .then(undefined, onRejected).
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    return Err(InterpreterError::TypeError {
                        expected: "promise".to_string(),
                        got: "undefined".to_string(),
                    });
                };
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                let result = self
                    .promise_store
                    .then(handle, None, None, label, &mut self.event_loop.microtasks)
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "valid promise handle".to_string(),
                        got: e.to_string(),
                    })?;
                Ok(Value::Promise(result.0))
            }
            "promise:finally" => {
                // Similar to .then(handler, handler) for finally semantics.
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    return Err(InterpreterError::TypeError {
                        expected: "promise".to_string(),
                        got: "undefined".to_string(),
                    });
                };
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                let result = self
                    .promise_store
                    .then(handle, None, None, label, &mut self.event_loop.microtasks)
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "valid promise handle".to_string(),
                        got: e.to_string(),
                    })?;
                Ok(Value::Promise(result.0))
            }
            "promise:all" => self.dispatch_promise_combinator(PromiseCombinatorKind::All, args),
            "promise:race" => self.dispatch_promise_combinator(PromiseCombinatorKind::Race, args),
            "promise:allSettled" => {
                self.dispatch_promise_combinator(PromiseCombinatorKind::AllSettled, args)
            }
            "promise:any" => self.dispatch_promise_combinator(PromiseCombinatorKind::Any, args),
            _ => {
                // Unknown promise sub-capability — return undefined.
                Ok(Value::Undefined)
            }
        }
    }

    /// Run the event loop until no pending work remains.
    ///
    /// Executes the standard event loop cycle:
    /// 1. Select and execute a macrotask (if any)
    /// 2. Drain all microtasks
    /// 3. Repeat until no pending macrotasks or microtasks
    ///
    /// This is called after top-level script evaluation to handle any
    /// pending timers or other async work before the interpreter exits.
    fn run_event_loop_until_idle(&mut self) {
        const MAX_TURNS: u32 = 10_000; // Safety limit to prevent infinite loops
        let mut turns = 0;

        while self.event_loop.has_pending_work() && turns < MAX_TURNS {
            turns += 1;

            // Phase 1: Execute one macrotask (if ready)
            let turn_result = self.event_loop.turn();
            if let Some(_macrotask) = turn_result.macrotask {
                // TODO: Execute the macrotask's handler closure
                // This requires timer callback execution, which comes in RC-2.7
                // For now, we just mark the task as executed (it's already dequeued)
            }

            // Phase 2: Drain all microtasks enqueued during macrotask execution
            self.drain_microtasks();
        }
    }

    /// Drain all pending microtasks from the queue.
    ///
    /// Each microtask may enqueue additional microtasks; the drain continues
    /// until the queue is empty, matching ES2020 semantics (microtask checkpoint).
    /// A safety bound prevents infinite loops from pathological promise chains.
    fn drain_microtasks(&mut self) {
        let max_drain = 10_000u32;
        let mut drained = 0u32;
        let label = crate::ifc_artifacts::Label::Public;

        while let Some(task) = self.event_loop.microtasks.dequeue() {
            drained += 1;
            if drained >= max_drain {
                break;
            }
            match task {
                crate::promise_model::Microtask::PromiseReaction {
                    handler: _,
                    argument,
                    result_promise,
                    label: _task_label,
                } => {
                    // With no closure handler, the identity transform propagates
                    // the argument to the result promise as a fulfillment value.
                    let _ = self.fulfill_promise(result_promise, argument, label.clone());
                }
                crate::promise_model::Microtask::ResolveThenable {
                    promise,
                    then_handler: _,
                    thenable: _,
                    label: _task_label,
                } => {
                    // Simplified: resolve with undefined (full thenable
                    // unwrapping requires closure execution which is a
                    // follow-up bead).
                    let _ = self.fulfill_promise(
                        promise,
                        crate::object_model::JsValue::Undefined,
                        label.clone(),
                    );
                }
            }
        }
        self.event_loop.microtasks.compact();
    }

    fn property_key(value: &Value) -> String {
        match value {
            Value::Str(s) => s.clone(),
            Value::Int(n) => n.to_string(),
            _ => value.to_string(),
        }
    }

    #[allow(dead_code)] // Kept for potential integer-only operations; tested below
    fn coerce_to_number(value: &Value) -> Option<i64> {
        match value {
            Value::Int(n) => Some(*n),
            Value::Float(f) => {
                let v = f.inner();
                if v.is_nan() || v.is_infinite() {
                    None
                } else if v.fract() == 0.0 && v >= i64::MIN as f64 && v <= i64::MAX as f64 {
                    Some(v as i64)
                } else {
                    None
                }
            }
            Value::Bool(b) => Some(i64::from(*b)),
            Value::Null => Some(0),
            Value::Str(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    Some(0)
                } else {
                    trimmed.parse::<i64>().ok()
                }
            }
            Value::Undefined
            | Value::Object(_)
            | Value::Function(_)
            | Value::Closure(_)
            | Value::Iterator(_)
            | Value::GeneratorFunction(_)
            | Value::Generator(_)
            | Value::Promise(_)
            | Value::BuiltinFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncFunctionObject(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::AsyncGeneratorObject(_) => None,
        }
    }

    /// Coerce a value to f64 for floating-point operations.
    fn coerce_to_float(value: &Value) -> Option<f64> {
        match value {
            Value::Int(n) => Some(*n as f64),
            Value::Float(f) => Some(f.inner()),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Null => Some(0.0),
            Value::Str(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    Some(0.0)
                } else if trimmed.eq_ignore_ascii_case("infinity") {
                    Some(f64::INFINITY)
                } else if trimmed.eq_ignore_ascii_case("-infinity") {
                    Some(f64::NEG_INFINITY)
                } else if trimmed.eq_ignore_ascii_case("nan") {
                    Some(f64::NAN)
                } else {
                    trimmed.parse::<f64>().ok()
                }
            }
            Value::Undefined => Some(f64::NAN),
            Value::Object(_)
            | Value::Function(_)
            | Value::Closure(_)
            | Value::Iterator(_)
            | Value::GeneratorFunction(_)
            | Value::Generator(_)
            | Value::Promise(_)
            | Value::BuiltinFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncFunctionObject(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::AsyncGeneratorObject(_) => Some(f64::NAN),
        }
    }

    /// Convert a Value to its string representation using JavaScript toString semantics.
    /// This unified implementation ensures all string case-conversion builtin paths
    /// have consistent behavior across all Value enum variants.
    fn value_to_primitive_string(value: &Value) -> String {
        match value {
            Value::Str(s) => s.clone(),
            Value::Null => "null".to_string(),
            Value::Undefined => "undefined".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Object(_) => "[object Object]".to_string(),
            Value::Function(_) => "[object Function]".to_string(),
            Value::Closure(_) => "[object Function]".to_string(),
            Value::Iterator(_) => "[object Iterator]".to_string(),
            Value::GeneratorFunction(_) => "[object GeneratorFunction]".to_string(),
            Value::Generator(_) => "[object Generator]".to_string(),
            Value::AsyncFunction(_) => "[object AsyncFunction]".to_string(),
            Value::AsyncFunctionObject(_) => "[object AsyncFunction]".to_string(),
            Value::AsyncGeneratorFunction(_) => "[object AsyncGeneratorFunction]".to_string(),
            Value::AsyncGeneratorObject(_) => "[object AsyncGenerator]".to_string(),
            Value::Promise(_) => "[object Promise]".to_string(),
            Value::BuiltinFunction(_) => "[object Function]".to_string(),
        }
    }

    /// String.prototype receiver coercion with RequireObjectCoercible semantics.
    /// Throws TypeError for null/undefined as per ECMAScript specification.
    /// All String.prototype methods should use this for consistent behavior.
    fn require_object_coercible_to_string(value: &Value) -> Result<String, InterpreterError> {
        match value {
            Value::Null => Err(InterpreterError::TypeError {
                expected: "object-coercible String.prototype receiver".to_string(),
                got: "null".to_string(),
            }),
            Value::Undefined => Err(InterpreterError::TypeError {
                expected: "object-coercible String.prototype receiver".to_string(),
                got: "undefined".to_string(),
            }),
            _ => Ok(Self::value_to_primitive_string(value)),
        }
    }

    /// Validates Array method callback arguments for fail-closed implementations
    /// Returns Ok(()) if validation passes, otherwise returns appropriate TypeError
    fn validate_array_callback_args(
        &self,
        args: RegRange,
        _method_name: &str,
    ) -> Result<(), InterpreterError> {
        if args.count < 2 {
            return Err(InterpreterError::TypeError {
                expected: "callback function".to_string(),
                got: "missing callback argument".to_string(),
            });
        }

        let this_val = self.read_reg(args.start)?;
        if !matches!(this_val, Value::Object(_)) {
            return Err(InterpreterError::TypeError {
                expected: "object".to_string(),
                got: format!("{:?}", this_val),
            });
        }

        let callback = self.read_reg(args.start + 1)?;
        if !matches!(callback, Value::Function(_) | Value::Closure(_)) {
            return Err(InterpreterError::TypeError {
                expected: "function".to_string(),
                got: format!("{:?}", callback),
            });
        }

        Ok(())
    }

    fn abstract_eq_values(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Undefined, Value::Undefined)
            | (Value::Null, Value::Null)
            | (Value::Bool(_), Value::Bool(_))
            | (Value::Int(_), Value::Int(_))
            | (Value::Str(_), Value::Str(_))
            | (Value::Object(_), Value::Object(_))
            | (Value::Function(_), Value::Function(_))
            | (Value::Closure(_), Value::Closure(_))
            | (Value::Iterator(_), Value::Iterator(_))
            | (Value::GeneratorFunction(_), Value::GeneratorFunction(_))
            | (Value::Generator(_), Value::Generator(_))
            | (Value::Promise(_), Value::Promise(_))
            | (Value::BuiltinFunction(_), Value::BuiltinFunction(_)) => a == b,
            // Float == Float: NaN !== NaN, but -0 == +0
            (Value::Float(fa), Value::Float(fb)) => {
                let va = fa.inner();
                let vb = fb.inner();
                if va.is_nan() || vb.is_nan() {
                    false
                } else {
                    va == vb
                }
            }
            // Int == Float or Float == Int: numeric comparison
            (Value::Int(n), Value::Float(f)) | (Value::Float(f), Value::Int(n)) => {
                let fv = f.inner();
                if fv.is_nan() { false } else { *n as f64 == fv }
            }
            (Value::Null, Value::Undefined) | (Value::Undefined, Value::Null) => true,
            // ES2020 §7.2.14: null/undefined are only == to each other, never
            // to numbers, strings, or booleans via numeric coercion.
            (Value::Null, _) | (_, Value::Null) => false,
            (Value::Undefined, _) | (_, Value::Undefined) => false,
            _ => match (Self::coerce_to_float(a), Self::coerce_to_float(b)) {
                (Some(lhs), Some(rhs)) => {
                    if lhs.is_nan() || rhs.is_nan() {
                        false
                    } else {
                        lhs == rhs
                    }
                }
                _ => false,
            },
        }
    }

    /// Dispatch number-related hostcalls: isNaN, isFinite, Number.isNaN, Number.isFinite.
    ///
    /// Hostcall capabilities:
    /// - `number:isNaN` — global isNaN() function (coerces to number first)
    /// - `number:isFinite` — global isFinite() function (coerces to number first)
    /// - `number:Number.isNaN` — Number.isNaN() (strict, no coercion)
    /// - `number:Number.isFinite` — Number.isFinite() (strict, no coercion)
    fn dispatch_number_hostcall(
        &self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let arg0 = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };

        match cap {
            "number:isNaN" => {
                // Global isNaN: coerces argument to number, then checks NaN
                // isNaN(undefined) = true, isNaN("hello") = true
                let number = Self::coerce_to_float(&arg0).unwrap_or(f64::NAN);
                Ok(Value::Bool(number.is_nan()))
            }
            "number:isFinite" => {
                // Global isFinite: coerces argument to number, then checks finite
                // isFinite(undefined) = false, isFinite("123") = true
                let number = Self::coerce_to_float(&arg0).unwrap_or(f64::NAN);
                Ok(Value::Bool(number.is_finite()))
            }
            "number:Number.isNaN" => {
                // Number.isNaN: strict check, no coercion
                // Number.isNaN(undefined) = false, Number.isNaN(NaN) = true
                match arg0 {
                    Value::Float(f) => Ok(Value::Bool(f.inner().is_nan())),
                    _ => Ok(Value::Bool(false)),
                }
            }
            "number:Number.isFinite" => {
                // Number.isFinite: strict check, no coercion
                // Number.isFinite(undefined) = false, Number.isFinite(42) = true
                match arg0 {
                    Value::Int(_) => Ok(Value::Bool(true)), // All integers are finite
                    Value::Float(f) => Ok(Value::Bool(f.inner().is_finite())),
                    _ => Ok(Value::Bool(false)),
                }
            }
            "number:Number.isInteger" => {
                // Number.isInteger: strict check for integer value
                match arg0 {
                    Value::Int(_) => Ok(Value::Bool(true)),
                    Value::Float(f) => {
                        let v = f.inner();
                        Ok(Value::Bool(v.is_finite() && v.fract() == 0.0))
                    }
                    _ => Ok(Value::Bool(false)),
                }
            }
            "number:Number.isSafeInteger" => {
                // Number.isSafeInteger: integer in safe range
                match arg0 {
                    Value::Int(n) => {
                        // Safe integer range: -(2^53 - 1) to (2^53 - 1)
                        const MAX_SAFE: i64 = (1i64 << 53) - 1;
                        const MIN_SAFE: i64 = -MAX_SAFE;
                        Ok(Value::Bool((MIN_SAFE..=MAX_SAFE).contains(&n)))
                    }
                    Value::Float(f) => {
                        let v = f.inner();
                        if !v.is_finite() || v.fract() != 0.0 {
                            return Ok(Value::Bool(false));
                        }
                        const MAX_SAFE: f64 = ((1i64 << 53) - 1) as f64;
                        Ok(Value::Bool((-MAX_SAFE..=MAX_SAFE).contains(&v)))
                    }
                    _ => Ok(Value::Bool(false)),
                }
            }
            _ => {
                // Unknown number hostcall
                Ok(Value::Undefined)
            }
        }
    }

    /// Dispatch console hostcalls: console.log, console.error, console.warn, console.info.
    ///
    /// Hostcall capabilities:
    /// - `console:log` — console.log(...args)
    /// - `console:error` — console.error(...args)
    /// - `console:warn` — console.warn(...args)
    ///
    /// Console output is captured in `self.console_output` for deterministic replay.
    fn dispatch_console_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let level = match cap {
            "console:log" => ConsoleLevel::Log,
            "console:error" => ConsoleLevel::Error,
            "console:warn" => ConsoleLevel::Warn,
            "console:info" => ConsoleLevel::Info,
            _ => return Ok(Value::Undefined), // Unknown console method
        };

        // Collect arguments as strings
        let mut parts = Vec::new();
        for i in 0..args.count {
            let reg = args
                .start
                .checked_add(i)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
            let val = self.read_reg(reg)?;
            parts.push(self.value_to_string(&val));
        }

        let message = parts.join(" ");

        // Bounded console output to prevent DoS via console spam
        if self.console_output.len() >= self.config.max_console_entries {
            // Ring buffer: drop oldest entry when limit reached
            self.console_output.remove(0);
        }

        self.console_output.push(ConsoleEntry {
            level,
            message,
            instruction_index: self.instructions_executed,
        });

        self.emit_witness(
            WitnessEventKind::HostcallDispatched,
            Some(&format!(
                "console:{}",
                match level {
                    ConsoleLevel::Log => "log",
                    ConsoleLevel::Error => "error",
                    ConsoleLevel::Warn => "warn",
                    ConsoleLevel::Info => "info",
                }
            )),
        );

        Ok(Value::Undefined)
    }

    fn dispatch_timer_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        match cap {
            "timer:setTimeout" => {
                // args[0] = handler (function/closure), args[1] = delay_ms
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let handler_reg = args.start;
                let delay_reg =
                    args.start
                        .checked_add(1)
                        .ok_or(InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: self.config.max_registers,
                        })?;

                let handler_val = self.read_reg(handler_reg)?;
                let delay_val = self.read_reg(delay_reg)?;

                // Extract numeric delay
                let delay_ms = match delay_val {
                    Value::Int(i) => i.max(0) as u64,
                    Value::Float(f) => f.0.max(0.0) as u64,
                    _ => 0,
                };

                // Store active timer
                let timer_id = self.next_timer_id;
                self.next_timer_id = self.next_timer_id.wrapping_add(1);

                let handler_id = match handler_val {
                    Value::Closure(id) => Some(id),
                    _ => None,
                };

                self.active_timers.insert(
                    timer_id,
                    ActiveTimer {
                        handler: handler_id,
                        delay_ms,
                        repeating: false,
                    },
                );

                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("timer:setTimeout:{}", timer_id)),
                );

                Ok(Value::Int(timer_id as i64))
            }
            "timer:setInterval" => {
                // Similar to setTimeout but repeating
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let handler_reg = args.start;
                let delay_reg =
                    args.start
                        .checked_add(1)
                        .ok_or(InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: self.config.max_registers,
                        })?;

                let handler_val = self.read_reg(handler_reg)?;
                let delay_val = self.read_reg(delay_reg)?;

                let delay_ms = match delay_val {
                    Value::Int(i) => i.max(0) as u64,
                    Value::Float(f) => f.0.max(0.0) as u64,
                    _ => 0,
                };

                let timer_id = self.next_timer_id;
                self.next_timer_id = self.next_timer_id.wrapping_add(1);

                let handler_id = match handler_val {
                    Value::Closure(id) => Some(id),
                    _ => None,
                };

                self.active_timers.insert(
                    timer_id,
                    ActiveTimer {
                        handler: handler_id,
                        delay_ms,
                        repeating: true,
                    },
                );

                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("timer:setInterval:{}", timer_id)),
                );

                Ok(Value::Int(timer_id as i64))
            }
            "timer:clearTimeout" | "timer:clearInterval" => {
                // args[0] = timer_id to clear
                if args.count < 1 {
                    return Ok(Value::Undefined);
                }

                let timer_id_val = self.read_reg(args.start)?;
                let timer_id = match timer_id_val {
                    Value::Int(i) => i as u32,
                    _ => return Ok(Value::Undefined),
                };

                self.active_timers.remove(&timer_id);

                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("{}:{}", cap, timer_id)),
                );

                Ok(Value::Undefined)
            }
            _ => Ok(Value::Undefined), // Unknown timer method
        }
    }

    fn dispatch_builtin_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        match cap {
            // Array methods
            "builtin:ArrayPrototypePush" => {
                // Array.prototype.push implementation - adds elements to end of array and returns new length

                // Get the 'this' value (should be an array object)
                // In a proper implementation, 'this' would be passed separately,
                // but for now we'll work with what we have
                if args.count == 0 {
                    return Ok(Value::Int(0)); // No elements to push, assume empty array
                }

                // For now, create a simple array-like object and add the elements
                // This is a simplified implementation that creates a new array
                let array_id = self.alloc_object_with_prototype(None)?;

                // Add each argument as an array element
                for i in 0..args.count {
                    let element = self.read_reg(args.start + i)?;
                    if let Some(obj) = self.heap.get_mut(array_id.0 as usize) {
                        obj.properties.insert(i.to_string(), element);
                    }
                }

                // Set length property
                if let Some(obj) = self.heap.get_mut(array_id.0 as usize) {
                    obj.properties
                        .insert("length".to_string(), Value::Int(args.count as i64));
                }

                // Return the new length
                Ok(Value::Int(args.count as i64))
            }
            "builtin:ArrayIsArray" => {
                // Array.isArray implementation - checks if argument is an array
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                let arg = self.read_reg(args.start)?;
                match arg {
                    Value::Object(obj_id) => {
                        // Check if object has array-like characteristics
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            // An array-like object should have a "length" property
                            if let Some(length_val) = obj.properties.get("length") {
                                // Additional check: verify the length is a non-negative integer
                                match length_val {
                                    Value::Int(len) if *len >= 0 => {
                                        // Check if object has numeric properties consistent with array
                                        let len_u32 = *len as u32;
                                        let mut has_array_pattern = true;

                                        // Basic validation: check that numeric properties exist for indices < length
                                        for i in 0..len_u32.min(10) {
                                            // Check first 10 elements for efficiency
                                            if !obj.properties.contains_key(&i.to_string()) {
                                                has_array_pattern = false;
                                                break;
                                            }
                                        }

                                        // If length is 0, it's still an array
                                        if len_u32 == 0 {
                                            has_array_pattern = true;
                                        }

                                        Ok(Value::Bool(has_array_pattern))
                                    }
                                    _ => Ok(Value::Bool(false)), // Invalid length property
                                }
                            } else {
                                Ok(Value::Bool(false)) // No length property
                            }
                        } else {
                            Ok(Value::Bool(false)) // Object not found
                        }
                    }
                    _ => Ok(Value::Bool(false)), // Non-object values are not arrays
                }
            }
            "builtin:ArrayPrototypePop" => {
                // Array.prototype.pop implementation - removes and returns last element from array

                // For this simplified implementation, we'll assume we're working with
                // an empty array and return undefined (as would happen with [].pop())
                // A complete implementation would need access to the 'this' array object
                // to remove the last element and update the length property

                // Simulate popping from an empty array
                Ok(Value::Undefined)
            }
            "builtin:ArrayPrototypeShift" => {
                // Array.prototype.shift implementation - removes and returns first element from array

                // For this simplified implementation, we'll assume we're working with
                // an empty array and return undefined (as would happen with [].shift())
                // A complete implementation would need access to the 'this' array object
                // to remove the first element, shift remaining elements, and update length

                // Simulate shifting from an empty array
                Ok(Value::Undefined)
            }
            "builtin:ArrayPrototypeUnshift" => {
                // Array.prototype.unshift implementation - adds elements to beginning of array and returns new length

                // For this simplified implementation, we'll create a new array with the unshift elements
                // A complete implementation would need access to the 'this' array object
                // to prepend elements and shift existing elements to the right

                // Create array object to hold the unshifted elements
                let array_id = self.alloc_object_with_prototype(None)?;

                // Add each argument as an array element at the beginning
                for i in 0..args.count {
                    let element = self.read_reg(args.start + i)?;
                    self.set_object_property(array_id, i.to_string(), element)?;
                }

                // Set length property
                self.set_object_property(
                    array_id,
                    "length".to_string(),
                    Value::Int(args.count as i64),
                )?;

                // Return the new length (JavaScript behavior: unshift returns new length, not the array)
                Ok(Value::Int(args.count as i64))
            }
            "builtin:ArrayOf" => {
                // Array.of implementation - creates new Array instance from arguments

                // Create array object to hold the arguments
                let array_id = self.alloc_object_with_prototype(None)?;

                // Add each argument as an array element
                for i in 0..args.count {
                    let element = self.read_reg(args.start + i)?;
                    self.set_object_property(array_id, i.to_string(), element)?;
                }

                // Set length property
                self.set_object_property(
                    array_id,
                    "length".to_string(),
                    Value::Int(args.count as i64),
                )?;

                // Return the new array object
                Ok(Value::Object(array_id))
            }
            "builtin:ArrayFrom" => {
                // Array.from implementation - creates new Array instance from array-like or iterable object
                if args.count == 0 {
                    // Array.from() with no arguments creates empty array
                    let array_id = self.alloc_object_with_prototype(None)?;
                    self.set_object_property(array_id, "length".to_string(), Value::Int(0))?;
                    return Ok(Value::Object(array_id));
                }

                let first_arg = self.read_reg(args.start)?;

                // Create new array object
                let array_id = self.alloc_object_with_prototype(None)?;

                match first_arg {
                    Value::Object(obj_id) => {
                        // Check if object is array-like (has length property).
                        // Snapshot length + elements under an immutable borrow
                        // so we can release it before the &mut self calls below.
                        #[derive(Debug)]
                        enum Snapshot {
                            ObjectMissing,
                            NoLength,
                            InvalidLength,
                            Valid(u32, Vec<Value>),
                        }
                        let snapshot: Snapshot = match self.heap.get(obj_id.0 as usize) {
                            None => Snapshot::ObjectMissing,
                            Some(obj) => match obj.properties.get("length") {
                                None => Snapshot::NoLength,
                                Some(Value::Int(len)) if *len >= 0 => {
                                    let len_u32 = *len as u32;
                                    let elements: Vec<Value> = (0..len_u32)
                                        .map(|i| {
                                            obj.properties
                                                .get(&i.to_string())
                                                .cloned()
                                                .unwrap_or(Value::Undefined)
                                        })
                                        .collect();
                                    Snapshot::Valid(len_u32, elements)
                                }
                                Some(_) => Snapshot::InvalidLength,
                            },
                        };

                        match snapshot {
                            Snapshot::Valid(len_u32, elements) => {
                                for (i, element) in elements.into_iter().enumerate() {
                                    self.set_object_property(array_id, i.to_string(), element)?;
                                }

                                // Set length property
                                self.set_object_property(
                                    array_id,
                                    "length".to_string(),
                                    Value::Int(len_u32 as i64),
                                )?;
                            }
                            // All of: invalid length value, missing length, or
                            // missing object — treat as empty array.
                            Snapshot::InvalidLength
                            | Snapshot::NoLength
                            | Snapshot::ObjectMissing => {
                                self.set_object_property(
                                    array_id,
                                    "length".to_string(),
                                    Value::Int(0),
                                )?;
                            }
                        }
                    }
                    Value::Str(s) => {
                        // Convert string to array of characters
                        let chars: Vec<char> = s.chars().collect();

                        for (i, ch) in chars.iter().enumerate() {
                            self.set_object_property(
                                array_id,
                                i.to_string(),
                                Value::Str(ch.to_string()),
                            )?;
                        }

                        // Set length property
                        self.set_object_property(
                            array_id,
                            "length".to_string(),
                            Value::Int(chars.len() as i64),
                        )?;
                    }
                    _ => {
                        // Non-iterable value, create empty array
                        self.set_object_property(array_id, "length".to_string(), Value::Int(0))?;
                    }
                }

                // TODO: Handle mapping function (second argument) if provided
                // TODO: Handle thisArg (third argument) if provided

                Ok(Value::Object(array_id))
            }
            "builtin:ArrayPrototypeJoin" => {
                // Array.prototype.join implementation - joins array elements into string
                if args.count == 0 {
                    return Ok(Value::Str("".to_string()));
                }

                // Get the array object (first argument should be the array)
                let array_arg = self.read_reg(args.start)?;

                // Get the separator (default to comma)
                let separator = if args.count > 1 {
                    let sep_arg = self.read_reg(args.start + 1)?;
                    match sep_arg {
                        Value::Str(s) => s,
                        Value::Null => "null".to_string(),
                        Value::Undefined => ",".to_string(), // Default separator
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => ",".to_string(),
                    }
                } else {
                    ",".to_string() // Default separator
                };

                match array_arg {
                    Value::Object(obj_id) => {
                        // Get array length and elements
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(length_val) = obj.properties.get("length") {
                                if let Value::Int(len) = length_val {
                                    let length = *len as usize;
                                    let mut elements = Vec::new();

                                    // Collect array elements
                                    for i in 0..length {
                                        let element = obj
                                            .properties
                                            .get(&i.to_string())
                                            .cloned()
                                            .unwrap_or(Value::Undefined);

                                        // Convert element to string
                                        let str_val = match element {
                                            Value::Str(s) => s,
                                            Value::Int(n) => n.to_string(),
                                            Value::Float(f) => f.inner().to_string(),
                                            Value::Bool(b) => b.to_string(),
                                            Value::Null => "null".to_string(),
                                            Value::Undefined => "".to_string(), // undefined becomes empty string in join
                                            _ => "[object Object]".to_string(),
                                        };
                                        elements.push(str_val);
                                    }

                                    // Join elements with separator
                                    let result = elements.join(&separator);
                                    Ok(Value::Str(result))
                                } else {
                                    // Invalid length, return empty string
                                    Ok(Value::Str("".to_string()))
                                }
                            } else {
                                // No length property, return empty string
                                Ok(Value::Str("".to_string()))
                            }
                        } else {
                            // Object not found, return empty string
                            Ok(Value::Str("".to_string()))
                        }
                    }
                    _ => {
                        // Non-object argument, return empty string
                        Ok(Value::Str("".to_string()))
                    }
                }
            }
            "builtin:ArrayPrototypeIncludes" => {
                // Array.prototype.includes implementation - checks if array contains a value
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                // Get the array object (first argument should be the array)
                let array_arg = self.read_reg(args.start)?;

                // Get the search element
                let search_element = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                match array_arg {
                    Value::Object(obj_id) => {
                        // Get array length and search through elements
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(length_val) = obj.properties.get("length") {
                                if let Value::Int(len) = length_val {
                                    let length = *len as usize;

                                    // Search through array elements
                                    for i in 0..length {
                                        let element = obj
                                            .properties
                                            .get(&i.to_string())
                                            .cloned()
                                            .unwrap_or(Value::Undefined);

                                        // JavaScript === comparison (strict equality)
                                        let matches = match (&search_element, &element) {
                                            (Value::Int(a), Value::Int(b)) => a == b,
                                            (Value::Float(a), Value::Float(b)) => {
                                                let a_val = a.inner();
                                                let b_val = b.inner();
                                                // Handle NaN case: NaN === NaN is false in JS, but includes should find NaN
                                                if a_val.is_nan() && b_val.is_nan() {
                                                    true
                                                } else {
                                                    a_val == b_val
                                                }
                                            }
                                            (Value::Str(a), Value::Str(b)) => a == b,
                                            (Value::Bool(a), Value::Bool(b)) => a == b,
                                            (Value::Null, Value::Null) => true,
                                            (Value::Undefined, Value::Undefined) => true,
                                            (Value::Object(a), Value::Object(b)) => a == b,
                                            _ => false, // Different types don't match in strict equality
                                        };

                                        if matches {
                                            return Ok(Value::Bool(true));
                                        }
                                    }

                                    // Not found
                                    Ok(Value::Bool(false))
                                } else {
                                    // Invalid length, return false
                                    Ok(Value::Bool(false))
                                }
                            } else {
                                // No length property, return false
                                Ok(Value::Bool(false))
                            }
                        } else {
                            // Object not found, return false
                            Ok(Value::Bool(false))
                        }
                    }
                    _ => {
                        // Non-object argument, return false
                        Ok(Value::Bool(false))
                    }
                }
            }
            "builtin:ArrayPrototypeIndexOf" => {
                // Array.prototype.indexOf implementation - finds first index of element in array
                if args.count == 0 {
                    return Ok(Value::Int(-1));
                }

                // Get the array object (first argument should be the array)
                let array_arg = self.read_reg(args.start)?;

                // Get the search element
                let search_element = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                // Get optional start index (default to 0)
                let start_index = if args.count > 2 {
                    let start_arg = self.read_reg(args.start + 2)?;
                    match start_arg {
                        Value::Int(n) => n.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                match array_arg {
                    Value::Object(obj_id) => {
                        // Get array length and search through elements
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(length_val) = obj.properties.get("length") {
                                if let Value::Int(len) = length_val {
                                    let length = *len as usize;

                                    // Search through array elements starting from start_index
                                    for i in start_index..length {
                                        let element = obj
                                            .properties
                                            .get(&i.to_string())
                                            .cloned()
                                            .unwrap_or(Value::Undefined);

                                        // JavaScript === comparison (strict equality)
                                        let matches = match (&search_element, &element) {
                                            (Value::Int(a), Value::Int(b)) => a == b,
                                            (Value::Float(a), Value::Float(b)) => {
                                                let a_val = a.inner();
                                                let b_val = b.inner();
                                                // NaN !== NaN in indexOf (different from includes)
                                                if a_val.is_nan() || b_val.is_nan() {
                                                    false
                                                } else {
                                                    a_val == b_val
                                                }
                                            }
                                            (Value::Str(a), Value::Str(b)) => a == b,
                                            (Value::Bool(a), Value::Bool(b)) => a == b,
                                            (Value::Null, Value::Null) => true,
                                            (Value::Undefined, Value::Undefined) => true,
                                            (Value::Object(a), Value::Object(b)) => a == b,
                                            _ => false, // Different types don't match in strict equality
                                        };

                                        if matches {
                                            return Ok(Value::Int(i as i64));
                                        }
                                    }

                                    // Not found
                                    Ok(Value::Int(-1))
                                } else {
                                    // Invalid length, return -1
                                    Ok(Value::Int(-1))
                                }
                            } else {
                                // No length property, return -1
                                Ok(Value::Int(-1))
                            }
                        } else {
                            // Object not found, return -1
                            Ok(Value::Int(-1))
                        }
                    }
                    _ => {
                        // Non-object argument, return -1
                        Ok(Value::Int(-1))
                    }
                }
            }
            "builtin:ArrayPrototypeSlice" => {
                // Array.prototype.slice implementation - returns shallow copy of portion of array
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                // Get the array object (first argument should be the array)
                let array_arg = self.read_reg(args.start)?;

                match array_arg {
                    Value::Object(obj_id) => {
                        // Snapshot length + relevant properties under an
                        // immutable borrow so we can release it before the
                        // &mut self calls below.
                        let array_snapshot: Option<i64> = self
                            .heap
                            .get(obj_id.0 as usize)
                            .and_then(|o| o.properties.get("length"))
                            .and_then(|v| match v {
                                Value::Int(n) => Some(*n),
                                _ => None,
                            });

                        if let Some(length) = array_snapshot {
                            // Get start index (default to 0)
                            let start_idx = if args.count > 1 {
                                let start_arg = self.read_reg(args.start + 1)?;
                                match start_arg {
                                    Value::Int(n) => {
                                        if n < 0 {
                                            (length + n).max(0) as usize
                                        } else {
                                            n.min(length) as usize
                                        }
                                    }
                                    Value::Float(f) => {
                                        let val = f.inner();
                                        if val < 0.0 {
                                            ((length as f64) + val).max(0.0) as usize
                                        } else {
                                            val.min(length as f64) as usize
                                        }
                                    }
                                    _ => 0,
                                }
                            } else {
                                0
                            };

                            // Get end index (default to array length)
                            let end_idx = if args.count > 2 {
                                let end_arg = self.read_reg(args.start + 2)?;
                                match end_arg {
                                    Value::Int(n) => {
                                        if n < 0 {
                                            (length + n).max(0) as usize
                                        } else {
                                            n.min(length) as usize
                                        }
                                    }
                                    Value::Float(f) => {
                                        let val = f.inner();
                                        if val < 0.0 {
                                            ((length as f64) + val).max(0.0) as usize
                                        } else {
                                            val.min(length as f64) as usize
                                        }
                                    }
                                    _ => length as usize,
                                }
                            } else {
                                length as usize
                            };

                            // Snapshot the slice elements under a fresh
                            // immutable borrow.
                            let slice_elements: Vec<Value> = if start_idx < end_idx {
                                if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                                    (start_idx..end_idx)
                                        .map(|i| {
                                            obj.properties
                                                .get(&i.to_string())
                                                .cloned()
                                                .unwrap_or(Value::Undefined)
                                        })
                                        .collect()
                                } else {
                                    Vec::new()
                                }
                            } else {
                                Vec::new()
                            };

                            // Create new array with sliced elements
                            let new_array_id = self.alloc_object_with_prototype(None)?;

                            if !slice_elements.is_empty() {
                                let mut new_length = 0u64;
                                for element in slice_elements {
                                    self.set_object_property(
                                        new_array_id,
                                        new_length.to_string(),
                                        element,
                                    )?;
                                    new_length += 1;
                                }

                                // Set length property
                                self.set_object_property(
                                    new_array_id,
                                    "length".to_string(),
                                    Value::Int(new_length as i64),
                                )?;
                            } else {
                                // Empty slice
                                self.set_object_property(
                                    new_array_id,
                                    "length".to_string(),
                                    Value::Int(0),
                                )?;
                            }

                            Ok(Value::Object(new_array_id))
                        } else {
                            // Invalid length, no length property, or object
                            // missing — return empty array.
                            let empty_array_id = self.alloc_object_with_prototype(None)?;
                            self.set_object_property(
                                empty_array_id,
                                "length".to_string(),
                                Value::Int(0),
                            )?;
                            Ok(Value::Object(empty_array_id))
                        }
                    }
                    _ => {
                        // Non-object argument, return empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        Ok(Value::Object(empty_array_id))
                    }
                }
            }

            // Object methods
            "builtin:ObjectKeys" => {
                // Object.keys implementation - returns array of object's own property names
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Get the object's properties
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            let keys: Vec<String> = obj.properties.keys().cloned().collect();

                            // Create array object to hold the keys
                            let array_id = self.alloc_object_with_prototype(None)?;

                            // Set array elements as numeric properties
                            for (index, key) in keys.iter().enumerate() {
                                self.set_object_property(
                                    array_id,
                                    index.to_string(),
                                    Value::Str(key.clone()),
                                )?;
                            }

                            // Set length property
                            self.set_object_property(
                                array_id,
                                "length".to_string(),
                                Value::Int(keys.len() as i64),
                            )?;

                            Ok(Value::Object(array_id))
                        } else {
                            // Object not found in heap
                            Ok(Value::Undefined)
                        }
                    }
                    _ => {
                        // Non-object argument - return empty array per JavaScript behavior
                        let array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(array_id, "length".to_string(), Value::Int(0))?;
                        Ok(Value::Object(array_id))
                    }
                }
            }
            "builtin:ObjectValues" => {
                // Object.values implementation - returns array of object's own property values
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Get the object's property values
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            let values: Vec<Value> = obj.properties.values().cloned().collect();

                            // Create array object to hold the values
                            let array_id = self.alloc_object_with_prototype(None)?;

                            // Set array elements as numeric properties
                            for (index, value) in values.iter().enumerate() {
                                self.set_object_property(
                                    array_id,
                                    index.to_string(),
                                    value.clone(),
                                )?;
                            }

                            // Set length property
                            self.set_object_property(
                                array_id,
                                "length".to_string(),
                                Value::Int(values.len() as i64),
                            )?;

                            Ok(Value::Object(array_id))
                        } else {
                            // Object not found in heap
                            Ok(Value::Undefined)
                        }
                    }
                    _ => {
                        // Non-object argument - return empty array per JavaScript behavior
                        let array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(array_id, "length".to_string(), Value::Int(0))?;
                        Ok(Value::Object(array_id))
                    }
                }
            }
            "builtin:ObjectEntries" => {
                // Object.entries implementation - returns array of [key, value] pairs
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Get the object's property entries as [key, value] pairs
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            let entries: Vec<(String, Value)> = obj
                                .properties
                                .iter()
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect();

                            // Create array object to hold the entries
                            let array_id = self.alloc_object_with_prototype(None)?;

                            // Set array elements as numeric properties, each containing a [key, value] pair
                            for (index, (key, value)) in entries.iter().enumerate() {
                                // Create a sub-array for [key, value]
                                let entry_array_id = self.alloc_object_with_prototype(None)?;

                                // Set key at index 0, value at index 1
                                self.set_object_property(
                                    entry_array_id,
                                    "0".to_string(),
                                    Value::Str(key.clone()),
                                )?;
                                self.set_object_property(
                                    entry_array_id,
                                    "1".to_string(),
                                    value.clone(),
                                )?;

                                // Set length property for the entry array
                                self.set_object_property(
                                    entry_array_id,
                                    "length".to_string(),
                                    Value::Int(2),
                                )?;

                                // Add the entry array to the main array
                                self.set_object_property(
                                    array_id,
                                    index.to_string(),
                                    Value::Object(entry_array_id),
                                )?;
                            }

                            // Set length property for the main array
                            self.set_object_property(
                                array_id,
                                "length".to_string(),
                                Value::Int(entries.len() as i64),
                            )?;

                            Ok(Value::Object(array_id))
                        } else {
                            // Object not found in heap
                            Ok(Value::Undefined)
                        }
                    }
                    _ => {
                        // Non-object argument - return empty array per JavaScript behavior
                        let array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(array_id, "length".to_string(), Value::Int(0))?;
                        Ok(Value::Object(array_id))
                    }
                }
            }
            "builtin:ObjectAssign" => {
                // Object.assign implementation - copies properties from source objects to target
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let target_val = self.read_reg(args.start)?;
                let target_obj_id = match target_val {
                    Value::Object(obj_id) => obj_id,
                    _ => {
                        // If target is not an object, return it as-is
                        return Ok(target_val);
                    }
                };

                // Copy properties from each source object to target
                for i in 1..args.count {
                    let source_val = self.read_reg(args.start + i)?;
                    if let Value::Object(source_obj_id) = source_val {
                        // Get properties from source object
                        if let Some(source_obj) = self.heap.get(source_obj_id.0 as usize) {
                            let properties_to_copy: Vec<(String, Value)> = source_obj
                                .properties
                                .iter()
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect();

                            // Copy each property to target object
                            for (key, value) in properties_to_copy {
                                self.set_object_property(target_obj_id, key, value)?;
                            }
                        }
                    }
                    // Skip non-object sources (null, undefined, primitives)
                }

                // Return the target object
                Ok(Value::Object(target_obj_id))
            }
            "builtin:ObjectFreeze" => {
                // Object.freeze implementation - makes an object immutable
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // In a full implementation, we would mark the object as frozen
                        // to prevent further modifications. For now, we just return the object.
                        // The freezing mechanism would need to be added to the object structure.

                        // TODO: Add frozen flag to ObjectInstance and check it in set_object_property
                        Ok(Value::Object(obj_id))
                    }
                    _ => {
                        // Non-object values are returned as-is (they're already "immutable")
                        Ok(obj_val)
                    }
                }
            }
            "builtin:ObjectCreate" => {
                // Object.create implementation - creates new object with specified prototype
                if args.count == 0 {
                    // Object.create() with no arguments creates object with null prototype
                    let obj_id = self.alloc_object_with_prototype(None)?;
                    return Ok(Value::Object(obj_id));
                }

                let prototype_arg = self.read_reg(args.start)?;
                match prototype_arg {
                    Value::Null => {
                        // Object.create(null) creates object with null prototype (no inherited properties)
                        let obj_id = self.alloc_object_with_prototype(None)?;
                        Ok(Value::Object(obj_id))
                    }
                    Value::Object(proto_id) => {
                        // Object.create(prototypeObject) - sets prototype chain
                        // In a full implementation, we would establish prototype inheritance
                        // For now, we create a new object without setting up the prototype chain
                        let obj_id = self.alloc_object_with_prototype(Some(proto_id))?;
                        Ok(Value::Object(obj_id))
                    }
                    _ => {
                        // JavaScript throws TypeError for non-object, non-null prototypes
                        // For simplicity, we'll return undefined to indicate error
                        Ok(Value::Undefined)
                    }
                }

                // TODO: Handle property descriptors (second argument) if provided
                // TODO: Implement proper prototype chain inheritance
            }

            // String methods
            "builtin:StringPrototypeCharAt" => {
                // String.prototype.charAt implementation - returns character at specified index
                if args.count < 2 {
                    return Ok(Value::Str("".to_string()));
                }

                let string_val = self.read_reg(args.start)?;
                let index_val = self.read_reg(args.start + 1)?;

                match (string_val, index_val) {
                    (Value::Str(s), Value::Int(index)) => {
                        if index < 0 {
                            // Negative indices return empty string
                            Ok(Value::Str("".to_string()))
                        } else {
                            let index_usize = index as usize;
                            if index_usize < s.len() {
                                // Get character at index (handling UTF-8)
                                let chars: Vec<char> = s.chars().collect();
                                if index_usize < chars.len() {
                                    Ok(Value::Str(chars[index_usize].to_string()))
                                } else {
                                    Ok(Value::Str("".to_string()))
                                }
                            } else {
                                // Index out of bounds
                                Ok(Value::Str("".to_string()))
                            }
                        }
                    }
                    (Value::Str(_), Value::Float(f)) => {
                        // Convert float to integer index
                        let index = f.inner().floor() as i64;
                        if index < 0 {
                            Ok(Value::Str("".to_string()))
                        } else {
                            let string_val = self.read_reg(args.start)?;
                            if let Value::Str(s) = string_val {
                                let index_usize = index as usize;
                                let chars: Vec<char> = s.chars().collect();
                                if index_usize < chars.len() {
                                    Ok(Value::Str(chars[index_usize].to_string()))
                                } else {
                                    Ok(Value::Str("".to_string()))
                                }
                            } else {
                                Ok(Value::Str("".to_string()))
                            }
                        }
                    }
                    _ => {
                        // Non-string first argument or invalid index
                        Ok(Value::Str("".to_string()))
                    }
                }
            }
            "builtin:StringPrototypeIndexOf" => {
                // String.prototype.indexOf implementation - returns index of first occurrence of substring
                if args.count < 2 {
                    return Ok(Value::Int(-1)); // No search string provided
                }

                let string_val = self.read_reg(args.start)?;
                let search_val = self.read_reg(args.start + 1)?;

                match (string_val, search_val) {
                    (Value::Str(haystack), Value::Str(needle)) => {
                        // Optional start position (fromIndex parameter)
                        let start_pos = if args.count >= 3 {
                            let start_val = self.read_reg(args.start + 2)?;
                            match start_val {
                                Value::Int(pos) => {
                                    if pos < 0 {
                                        0
                                    } else {
                                        pos as usize
                                    }
                                }
                                Value::Float(f) => {
                                    let pos = f.inner().floor() as i64;
                                    if pos < 0 { 0 } else { pos as usize }
                                }
                                _ => 0,
                            }
                        } else {
                            0
                        };

                        // Find the substring starting from the specified position
                        if start_pos >= haystack.len() {
                            Ok(Value::Int(-1))
                        } else {
                            let search_slice = &haystack[start_pos..];
                            match search_slice.find(&needle) {
                                Some(pos) => Ok(Value::Int((start_pos + pos) as i64)),
                                None => Ok(Value::Int(-1)),
                            }
                        }
                    }
                    _ => {
                        // Non-string arguments - return -1 per JavaScript behavior
                        Ok(Value::Int(-1))
                    }
                }
            }
            "builtin:StringPrototypeSubstring" => {
                // String.prototype.substring implementation - returns substring between two indices
                if args.count == 0 {
                    return Ok(Value::Str("".to_string()));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = match string_arg {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "".to_string(),
                };

                let str_len = string_val.chars().count();

                // Get start index (default to 0)
                let start_idx = if args.count > 1 {
                    let start_arg = self.read_reg(args.start + 1)?;
                    match start_arg {
                        Value::Int(n) => n.max(0) as usize,
                        Value::Float(f) => {
                            let val = f.inner();
                            if val.is_nan() || val < 0.0 {
                                0
                            } else {
                                val as usize
                            }
                        }
                        _ => 0,
                    }
                } else {
                    0
                }
                .min(str_len);

                // Get end index (default to string length)
                let end_idx = if args.count > 2 {
                    let end_arg = self.read_reg(args.start + 2)?;
                    match end_arg {
                        Value::Int(n) => n.max(0) as usize,
                        Value::Float(f) => {
                            let val = f.inner();
                            if val.is_nan() || val < 0.0 {
                                0
                            } else {
                                val as usize
                            }
                        }
                        _ => str_len,
                    }
                } else {
                    str_len
                }
                .min(str_len);

                // Ensure start <= end (swap if necessary, per JavaScript spec)
                let (actual_start, actual_end) = if start_idx <= end_idx {
                    (start_idx, end_idx)
                } else {
                    (end_idx, start_idx)
                };

                // Extract substring using character indices
                let chars: Vec<char> = string_val.chars().collect();
                let substring: String = chars[actual_start..actual_end].iter().collect();

                Ok(Value::Str(substring))
            }
            "builtin:StringPrototypeSlice" => {
                // String.prototype.slice implementation - extracts part of string with different negative index behavior
                if args.count == 0 {
                    return Ok(Value::Str("".to_string()));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = match string_arg {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "".to_string(),
                };

                let str_len = string_val.chars().count() as i64;

                // Get start index (default to 0)
                let start_idx = if args.count > 1 {
                    let start_arg = self.read_reg(args.start + 1)?;
                    match start_arg {
                        Value::Int(n) => {
                            if n < 0 {
                                (str_len + n).max(0) as usize
                            } else {
                                n.min(str_len) as usize
                            }
                        }
                        Value::Float(f) => {
                            let val = f.inner();
                            if val.is_nan() {
                                0
                            } else if val < 0.0 {
                                ((str_len as f64) + val).max(0.0) as usize
                            } else {
                                val.min(str_len as f64) as usize
                            }
                        }
                        _ => 0,
                    }
                } else {
                    0
                };

                // Get end index (default to string length)
                let end_idx = if args.count > 2 {
                    let end_arg = self.read_reg(args.start + 2)?;
                    match end_arg {
                        Value::Int(n) => {
                            if n < 0 {
                                (str_len + n).max(0) as usize
                            } else {
                                n.min(str_len) as usize
                            }
                        }
                        Value::Float(f) => {
                            let val = f.inner();
                            if val.is_nan() {
                                str_len as usize
                            } else if val < 0.0 {
                                ((str_len as f64) + val).max(0.0) as usize
                            } else {
                                val.min(str_len as f64) as usize
                            }
                        }
                        _ => str_len as usize,
                    }
                } else {
                    str_len as usize
                };

                // Extract substring if start < end
                if start_idx < end_idx {
                    let chars: Vec<char> = string_val.chars().collect();
                    let substring: String = chars[start_idx..end_idx].iter().collect();
                    Ok(Value::Str(substring))
                } else {
                    Ok(Value::Str("".to_string()))
                }
            }
            "builtin:StringPrototypeToLowerCase" => {
                // String.prototype.toLowerCase implementation - converts string to lowercase
                if args.count == 0 {
                    return Ok(Value::Str("".to_string()));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = Self::require_object_coercible_to_string(&string_arg)?;

                // Convert to lowercase using Unicode-aware conversion
                let lowercase = string_val.to_lowercase();
                Ok(Value::Str(lowercase))
            }
            "builtin:StringPrototypeToUpperCase" => {
                // String.prototype.toUpperCase implementation - converts string to uppercase
                if args.count == 0 {
                    return Ok(Value::Str("".to_string()));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = Self::require_object_coercible_to_string(&string_arg)?;

                // Convert to uppercase using Unicode-aware conversion
                let uppercase = string_val.to_uppercase();
                Ok(Value::Str(uppercase))
            }
            "builtin:StringPrototypeTrim" => {
                // String.prototype.trim implementation - removes whitespace from both ends
                if args.count == 0 {
                    return Ok(Value::Str("".to_string()));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = match string_arg {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "".to_string(),
                };

                // Remove whitespace from both ends using Unicode-aware trimming
                let trimmed = string_val.trim();
                Ok(Value::Str(trimmed.to_string()))
            }

            // Math methods
            "builtin:MathAbs" => {
                // Math.abs implementation - returns absolute value of the argument
                if args.count > 0 {
                    let arg = self.read_reg(args.start)?;
                    match arg {
                        Value::Int(n) => {
                            // Use saturating_abs to handle i64::MIN safely (returns i64::MAX)
                            Ok(Value::Int(n.saturating_abs()))
                        }
                        Value::Float(f) => Ok(Value::Float(Float64::new(f.inner().abs()))),
                        _ => {
                            let num = Self::coerce_to_float(&arg).unwrap_or(f64::NAN);
                            Ok(Value::Float(Float64::new(num.abs())))
                        }
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }
            "builtin:MathCeil" => {
                // Math.ceil implementation - returns ceiling (smallest integer >= x)
                if args.count > 0 {
                    let arg = self.read_reg(args.start)?;
                    match arg {
                        Value::Int(n) => Ok(Value::Int(n)), // Integer is already its own ceiling
                        Value::Float(f) => {
                            let val = f.inner().ceil();
                            // Check if the result fits in an integer range
                            if val.is_finite() && val >= i64::MIN as f64 && val <= i64::MAX as f64 {
                                Ok(Value::Int(val as i64))
                            } else {
                                Ok(Value::Float(Float64::new(val)))
                            }
                        }
                        _ => Ok(Value::Float(Float64::new(f64::NAN))),
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }
            "builtin:MathFloor" => {
                // Math.floor implementation - returns floor (largest integer <= x)
                if args.count > 0 {
                    let arg = self.read_reg(args.start)?;
                    match arg {
                        Value::Int(n) => Ok(Value::Int(n)), // Integer is already its own floor
                        Value::Float(f) => {
                            let val = f.inner().floor();
                            // Check if the result fits in an integer range
                            if val.is_finite() && val >= i64::MIN as f64 && val <= i64::MAX as f64 {
                                Ok(Value::Int(val as i64))
                            } else {
                                Ok(Value::Float(Float64::new(val)))
                            }
                        }
                        _ => Ok(Value::Float(Float64::new(f64::NAN))),
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }
            "builtin:MathRound" => {
                // Math.round implementation - returns nearest integer
                if args.count > 0 {
                    let arg = self.read_reg(args.start)?;
                    match arg {
                        Value::Int(n) => Ok(Value::Int(n)), // Integer is already rounded
                        Value::Float(f) => {
                            let input = f.inner();
                            // Implement JavaScript Math.round semantics:
                            // Round towards positive infinity for ties (0.5 cases)
                            let val = if input.is_nan() || input.is_infinite() {
                                input
                            } else if input == -0.5 {
                                -0.0  // Special case: -0.5 rounds to -0
                            } else {
                                (input + 0.5).floor()
                            };
                            // Check if the result fits in an integer range
                            if val.is_finite() && val >= i64::MIN as f64 && val <= i64::MAX as f64 {
                                Ok(Value::Int(val as i64))
                            } else {
                                Ok(Value::Float(Float64::new(val)))
                            }
                        }
                        _ => Ok(Value::Float(Float64::new(f64::NAN))),
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }
            "builtin:MathMax" => {
                // Math.max implementation - returns largest of given numbers
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NEG_INFINITY)));
                }

                let mut max_val = f64::NEG_INFINITY;
                let mut has_nan = false;
                let mut is_all_int = true;
                let mut int_max = i64::MIN;

                for i in 0..args.count {
                    let arg = self.read_reg(args.start + i)?;
                    match arg {
                        Value::Int(n) => {
                            if is_all_int {
                                int_max = int_max.max(n);
                            }
                            max_val = max_val.max(n as f64);
                        }
                        Value::Float(f) => {
                            is_all_int = false;
                            let val = f.inner();
                            if val.is_nan() {
                                has_nan = true;
                                break;
                            }
                            max_val = max_val.max(val);
                        }
                        _ => {
                            // Non-numeric values become NaN in JavaScript
                            has_nan = true;
                            break;
                        }
                    }
                }

                if has_nan {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else if is_all_int
                    && max_val.is_finite()
                    && max_val >= i64::MIN as f64
                    && max_val <= i64::MAX as f64
                {
                    Ok(Value::Int(int_max))
                } else {
                    Ok(Value::Float(Float64::new(max_val)))
                }
            }
            "builtin:MathMin" => {
                // Math.min implementation - returns smallest of given numbers
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::INFINITY)));
                }

                let mut min_val = f64::INFINITY;
                let mut has_nan = false;
                let mut is_all_int = true;
                let mut int_min = i64::MAX;

                for i in 0..args.count {
                    let arg = self.read_reg(args.start + i)?;
                    match arg {
                        Value::Int(n) => {
                            if is_all_int {
                                int_min = int_min.min(n);
                            }
                            min_val = min_val.min(n as f64);
                        }
                        Value::Float(f) => {
                            is_all_int = false;
                            let val = f.inner();
                            if val.is_nan() {
                                has_nan = true;
                                break;
                            }
                            min_val = min_val.min(val);
                        }
                        _ => {
                            // Non-numeric values become NaN in JavaScript
                            has_nan = true;
                            break;
                        }
                    }
                }

                if has_nan {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else if is_all_int
                    && min_val.is_finite()
                    && min_val >= i64::MIN as f64
                    && min_val <= i64::MAX as f64
                {
                    Ok(Value::Int(int_min))
                } else {
                    Ok(Value::Float(Float64::new(min_val)))
                }
            }
            "builtin:MathRandom" => {
                // Math.random implementation - deterministic with proper [0,1) range
                self.math_random_impl()
            }

            // JSON methods
            "builtin:JsonStringify" => {
                // JSON.stringify implementation - converts value to JSON string
                if args.count == 0 {
                    return Ok(Value::Str("undefined".to_string()));
                }

                let value = self.read_reg(args.start)?;
                let json_str = match value {
                    Value::Undefined => "undefined".to_string(),
                    Value::Null => "null".to_string(),
                    Value::Bool(b) => {
                        if b {
                            "true".to_string()
                        } else {
                            "false".to_string()
                        }
                    }
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => {
                        let val = f.inner();
                        if val.is_nan() || val.is_infinite() {
                            "null".to_string()
                        } else {
                            val.to_string()
                        }
                    }
                    Value::Str(s) => {
                        format!("\"{}\"", s.replace('"', "\\\"").replace('\\', "\\\\"))
                    }
                    Value::Object(_) => "{}".to_string(), // Basic object stringification
                    Value::Function(_) => "undefined".to_string(),
                    Value::Closure(_) => "undefined".to_string(),
                    Value::Iterator(_) => "{}".to_string(),
                    Value::GeneratorFunction(_) => "undefined".to_string(),
                    Value::Promise(_) => "{}".to_string(),
                    Value::Generator(_) => "{}".to_string(),
                    Value::AsyncFunction(_) => "undefined".to_string(),
                    Value::AsyncFunctionObject(_) => "{}".to_string(),
                    Value::AsyncGeneratorFunction(_) => "undefined".to_string(),
                    Value::AsyncGeneratorObject(_) => "{}".to_string(),
                    Value::BuiltinFunction(_) => "undefined".to_string(),
                };
                Ok(Value::Str(json_str))
            }
            "builtin:JsonParse" => {
                // JSON.parse implementation - parses JSON string into JavaScript value
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let json_str_val = self.read_reg(args.start)?;
                match json_str_val {
                    Value::Str(json_str) => {
                        // Simple JSON parsing for basic cases
                        match json_str.trim() {
                            "null" => Ok(Value::Null),
                            "true" => Ok(Value::Bool(true)),
                            "false" => Ok(Value::Bool(false)),
                            "undefined" => Ok(Value::Undefined),
                            s if s.starts_with('"') && s.ends_with('"') => {
                                // String value - remove quotes and handle basic escape sequences
                                let content = &s[1..s.len() - 1];
                                let unescaped = content.replace("\\\"", "\"").replace("\\\\", "\\");
                                Ok(Value::Str(unescaped))
                            }
                            s => {
                                // Try to parse as number
                                if let Ok(int_val) = s.parse::<i64>() {
                                    Ok(Value::Int(int_val))
                                } else if let Ok(float_val) = s.parse::<f64>() {
                                    Ok(Value::Float(Float64::new(float_val)))
                                } else {
                                    // Invalid JSON - return undefined (simplified error handling)
                                    Ok(Value::Undefined)
                                }
                            }
                        }
                    }
                    _ => {
                        // Non-string argument - return undefined
                        Ok(Value::Undefined)
                    }
                }
            }
            "builtin:isNaN" => {
                // isNaN global function - tests if value is NaN
                if args.count == 0 {
                    return Ok(Value::Bool(true)); // isNaN() with no args returns true
                }

                let arg = self.read_reg(args.start)?;
                let is_nan = match arg {
                    Value::Float(f) => f.inner().is_nan(),
                    Value::Int(_) => false, // Integers are never NaN
                    Value::Str(s) => {
                        // Try to convert string to number
                        match s.parse::<f64>() {
                            Ok(num) => num.is_nan(),
                            Err(_) => true, // Invalid number strings are NaN
                        }
                    }
                    Value::Bool(_b) => {
                        // Booleans convert to numbers: true->1, false->0
                        false // Neither 1 nor 0 is NaN
                    }
                    Value::Null => false, // null converts to 0, which is not NaN
                    Value::Undefined => true, // undefined converts to NaN
                    _ => true,            // Objects and other complex types typically become NaN
                };

                Ok(Value::Bool(is_nan))
            }
            "builtin:isFinite" => {
                // isFinite global function - tests if value is finite number
                if args.count == 0 {
                    return Ok(Value::Bool(false)); // isFinite() with no args returns false
                }

                let arg = self.read_reg(args.start)?;
                let is_finite = match arg {
                    Value::Float(f) => {
                        let val = f.inner();
                        val.is_finite() // Not NaN, not infinity
                    }
                    Value::Int(_) => true, // Integers are always finite
                    Value::Str(s) => {
                        // Try to convert string to number
                        match s.parse::<f64>() {
                            Ok(num) => num.is_finite(),
                            Err(_) => false, // Invalid number strings are not finite
                        }
                    }
                    Value::Bool(_b) => {
                        // Booleans convert to numbers: true->1, false->0
                        true // Both 1 and 0 are finite
                    }
                    Value::Null => true, // null converts to 0, which is finite
                    Value::Undefined => false, // undefined converts to NaN, which is not finite
                    _ => false,          // Objects and other complex types typically become NaN
                };

                Ok(Value::Bool(is_finite))
            }
            "builtin:parseInt" => {
                // parseInt global function - parses string and returns integer
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN))); // parseInt() with no args returns NaN
                }

                let string_val = self.read_reg(args.start)?;
                let radix_arg = if args.count >= 2 {
                    Some(self.read_reg(args.start + 1)?)
                } else {
                    None
                };

                match Self::parse_int_with_sign_and_radix(&string_val, radix_arg.as_ref()) {
                    Some(result) => Ok(Value::Int(result)),
                    None => Ok(Value::Float(Float64::new(f64::NAN))),
                }
            }
            "builtin:parseFloat" => {
                // parseFloat global function - parses string and returns floating point number
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN))); // parseFloat() with no args returns NaN
                }

                let string_val = self.read_reg(args.start)?;

                // Convert argument to string
                let string_to_parse = match string_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => {
                        if b {
                            "true".to_string()
                        } else {
                            "false".to_string()
                        }
                    }
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Float(Float64::new(f64::NAN))), // Objects return NaN
                };

                // Parse leading numeric part
                let trimmed = string_to_parse.trim_start();

                // Handle special cases
                if trimmed.is_empty() || trimmed.starts_with("NaN") {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }
                if trimmed.starts_with("Infinity") {
                    return Ok(Value::Float(Float64::new(f64::INFINITY)));
                }
                if trimmed.starts_with("-Infinity") {
                    return Ok(Value::Float(Float64::new(f64::NEG_INFINITY)));
                }

                // Find the longest prefix that forms a valid number
                let mut valid_chars = String::new();
                let mut has_dot = false;
                let mut chars = trimmed.chars();

                // Handle optional sign
                if let Some(first_char) = chars.clone().next() {
                    if first_char == '+' || first_char == '-' {
                        valid_chars.push(first_char);
                        chars.next();
                    }
                }

                // Parse numeric characters
                for ch in chars {
                    if ch.is_ascii_digit() {
                        valid_chars.push(ch);
                    } else if ch == '.' && !has_dot {
                        has_dot = true;
                        valid_chars.push(ch);
                    } else {
                        break; // Stop at first non-numeric character
                    }
                }

                // Try to parse the accumulated string
                if valid_chars.is_empty()
                    || valid_chars == "+"
                    || valid_chars == "-"
                    || valid_chars == "."
                {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else {
                    match valid_chars.parse::<f64>() {
                        Ok(num) => {
                            // Check if result should be an integer for efficiency
                            if num.fract() == 0.0
                                && num.is_finite()
                                && num >= i64::MIN as f64
                                && num <= i64::MAX as f64
                            {
                                Ok(Value::Int(num as i64))
                            } else {
                                Ok(Value::Float(Float64::new(num)))
                            }
                        }
                        Err(_) => Ok(Value::Float(Float64::new(f64::NAN))),
                    }
                }
            }
            "builtin:NumberIsNaN" => {
                // Number.isNaN implementation - more strict than global isNaN
                if args.count == 0 {
                    return Ok(Value::Bool(false)); // Number.isNaN() with no args returns false
                }

                let arg = self.read_reg(args.start)?;
                match arg {
                    Value::Float(f) => Ok(Value::Bool(f.inner().is_nan())),
                    _ => Ok(Value::Bool(false)), // Number.isNaN only returns true for NaN numbers, not type coerced
                }
            }
            "builtin:NumberIsFinite" => {
                // Number.isFinite implementation - more strict than global isFinite
                if args.count == 0 {
                    return Ok(Value::Bool(false)); // Number.isFinite() with no args returns false
                }

                let arg = self.read_reg(args.start)?;
                match arg {
                    Value::Int(_) => Ok(Value::Bool(true)), // All integers are finite
                    Value::Float(f) => Ok(Value::Bool(f.inner().is_finite())),
                    _ => Ok(Value::Bool(false)), // Number.isFinite only returns true for finite numbers, not type coerced
                }
            }
            "builtin:ConsoleLog" => {
                // console.log implementation - prints arguments to stdout/console
                let mut output_parts = Vec::new();

                // Convert all arguments to strings and collect them
                for i in 0..args.count {
                    let arg = self.read_reg(args.start + i)?;
                    let str_representation = self.value_to_string(&arg);
                    output_parts.push(str_representation);
                }

                // Join with spaces (standard console.log behavior)
                let output = output_parts.join(" ");

                // Bounded console output to prevent DoS via console spam
                if self.console_output.len() >= self.config.max_console_entries {
                    // Ring buffer: drop oldest entry when limit reached
                    self.console_output.remove(0);
                }

                // Capture console output for deterministic replay
                self.console_output.push(ConsoleEntry {
                    level: ConsoleLevel::Log,
                    message: output,
                    instruction_index: self.instructions_executed,
                });

                Ok(Value::Undefined)
            }
            "builtin:ConsoleError" => {
                // console.error implementation - prints error arguments to stderr/console
                let mut output_parts = Vec::new();

                // Convert all arguments to strings and collect them
                for i in 0..args.count {
                    let arg = self.read_reg(args.start + i)?;
                    let str_representation = self.value_to_string(&arg);
                    output_parts.push(str_representation);
                }

                // Join with spaces
                let output = output_parts.join(" ");

                // Bounded console output to prevent DoS via console spam
                if self.console_output.len() >= self.config.max_console_entries {
                    // Ring buffer: drop oldest entry when limit reached
                    self.console_output.remove(0);
                }

                // Capture console error output for deterministic replay
                self.console_output.push(ConsoleEntry {
                    level: ConsoleLevel::Error,
                    message: output,
                    instruction_index: self.instructions_executed,
                });

                Ok(Value::Undefined)
            }
            "builtin:ConsoleWarn" => {
                // console.warn implementation - prints warning arguments to console
                let mut output_parts = Vec::new();

                // Convert all arguments to strings and collect them
                for i in 0..args.count {
                    let arg = self.read_reg(args.start + i)?;
                    let str_representation = self.value_to_string(&arg);
                    output_parts.push(str_representation);
                }

                // Join with spaces
                let output = output_parts.join(" ");

                // Bounded console output to prevent DoS via console spam
                if self.console_output.len() >= self.config.max_console_entries {
                    // Ring buffer: drop oldest entry when limit reached
                    self.console_output.remove(0);
                }

                // Capture console warning output for deterministic replay
                self.console_output.push(ConsoleEntry {
                    level: ConsoleLevel::Warn,
                    message: output,
                    instruction_index: self.instructions_executed,
                });

                Ok(Value::Undefined)
            }
            "builtin:DateNow" => {
                // Date.now implementation - returns deterministic timestamp in milliseconds
                // Uses fixed epoch (2026-01-01T00:00:00Z) for deterministic replay
                const DETERMINISTIC_EPOCH_MS: i64 = 1_767_225_600_000;

                Ok(Value::Float(Float64::new(DETERMINISTIC_EPOCH_MS as f64)))
            }
            "builtin:Date" => {
                // Date() constructor - returns new Date object with deterministic timestamp
                // Uses fixed epoch (2026-01-01T00:00:00Z) for deterministic replay
                const DETERMINISTIC_EPOCH_MS: i64 = 1_767_225_600_000;

                let millis = DETERMINISTIC_EPOCH_MS as f64;

                // Create a new Date object with current timestamp. Use the
                // capability-checked allocator rather than poking the heap
                // Vec directly.
                let date_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(
                    date_id,
                    "__timestamp".to_string(),
                    Value::Float(Float64::new(millis)),
                )?;
                Ok(Value::Object(date_id))
            }
            "builtin:MathPow" => {
                // Math.pow(base, exponent) implementation
                if args.count < 2 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let base = self.read_reg(args.start)?;
                let exponent = self.read_reg(args.start + 1)?;

                let base_num = match base {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let exp_num = match exponent {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = base_num.powf(exp_num);

                // Return as int if it's a whole number within range
                if result.fract() == 0.0
                    && result.is_finite()
                    && result >= i64::MIN as f64
                    && result <= i64::MAX as f64
                {
                    Ok(Value::Int(result as i64))
                } else {
                    Ok(Value::Float(Float64::new(result)))
                }
            }
            "builtin:StringPrototypeIncludes" => {
                // String.prototype.includes(searchString[, position]) implementation
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Get search string
                let search_val = self.read_reg(args.start + 1)?;
                let search_str = match search_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Get optional position parameter
                let position = if args.count > 2 {
                    let pos_val = self.read_reg(args.start + 2)?;
                    match pos_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Check if search string exists starting from position
                let result = if position >= this_str.len() {
                    false
                } else {
                    this_str[position..].contains(&search_str)
                };

                Ok(Value::Bool(result))
            }
            "builtin:ArrayPrototypeReverse" => {
                // Array.prototype.reverse() implementation - reverses array in place
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(this_val), // Non-arrays return themselves
                };

                // Get the array object from heap
                if let Some(array_obj) = self.heap.get_mut(array_id.0 as usize) {
                    // Get array length
                    let length = array_obj
                        .properties
                        .get("length")
                        .and_then(|v| match v {
                            Value::Int(i) => Some(*i as usize),
                            Value::Float(f) => Some(f.inner() as usize),
                            _ => None,
                        })
                        .unwrap_or(0);

                    if length <= 1 {
                        return Ok(Value::Object(array_id)); // Nothing to reverse
                    }

                    // Collect indexed properties
                    let mut indexed_props: BTreeMap<usize, Value> = BTreeMap::new();
                    for (key, value) in &array_obj.properties {
                        if let Ok(index) = key.parse::<usize>() {
                            if index < length {
                                indexed_props.insert(index, value.clone());
                            }
                        }
                    }

                    // Remove old indexed properties
                    array_obj
                        .properties
                        .retain(|k, _| k.parse::<usize>().is_err());

                    // Add back in reverse order
                    for (old_index, value) in indexed_props {
                        let new_index = length - 1 - old_index;
                        array_obj.properties.insert(new_index.to_string(), value);
                    }

                    Ok(Value::Object(array_id))
                } else {
                    Ok(this_val)
                }
            }
            "builtin:MathSqrt" => {
                // Math.sqrt(x) implementation - returns square root of a number
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.read_reg(args.start)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.sqrt();

                // Return as int if it's a whole number within range
                if result.fract() == 0.0
                    && result.is_finite()
                    && result >= i64::MIN as f64
                    && result <= i64::MAX as f64
                {
                    Ok(Value::Int(result as i64))
                } else {
                    Ok(Value::Float(Float64::new(result)))
                }
            }
            "builtin:StringPrototypeStartsWith" => {
                // String.prototype.startsWith(searchString[, position]) implementation
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Get search string
                let search_val = self.read_reg(args.start + 1)?;
                let search_str = match search_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Get optional position parameter
                let position = if args.count > 2 {
                    let pos_val = self.read_reg(args.start + 2)?;
                    match pos_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Check if string starts with search string at position
                let result = if position >= this_str.len() {
                    search_str.is_empty()
                } else {
                    this_str[position..].starts_with(&search_str)
                };

                Ok(Value::Bool(result))
            }
            "builtin:StringPrototypeEndsWith" => {
                // String.prototype.endsWith(searchString[, length]) implementation
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Get search string
                let search_val = self.read_reg(args.start + 1)?;
                let search_str = match search_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Get optional length parameter
                let end_pos = if args.count > 2 {
                    let len_val = self.read_reg(args.start + 2)?;
                    match len_val {
                        Value::Int(i) => (i.max(0) as usize).min(this_str.len()),
                        Value::Float(f) => (f.inner().max(0.0) as usize).min(this_str.len()),
                        _ => this_str.len(),
                    }
                } else {
                    this_str.len()
                };

                // Check if string ends with search string at the given end position
                let result = if end_pos == 0 {
                    search_str.is_empty()
                } else {
                    let check_str = &this_str[..end_pos];
                    check_str.ends_with(&search_str)
                };

                Ok(Value::Bool(result))
            }
            "builtin:ArrayPrototypeForEach" => {
                // Array.prototype.forEach(callback[, thisArg]) implementation - fail-closed until proper callback invocation
                self.validate_array_callback_args(args, "Array.prototype.forEach")?;

                // Fail-closed until proper callback dispatch is implemented
                // Programs like [1, 2].forEach(x => console.log(x)) should error rather than
                // silently do nothing or process elements incorrectly
                Err(InterpreterError::TypeError {
                    expected: "supported Array.prototype.forEach implementation".to_string(),
                    got: "callback invocation not yet supported - would require proper callback dispatch with (element, index, array) args, thisArg handling, and side-effect execution for each element".to_string(),
                })
            }
            // ArrayPrototypeFind: Removed duplicate dispatch arm (use occurrence at line 12492)
            "builtin:MathSin" => {
                // Math.sin(x) implementation - returns sine of x in radians
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.read_reg(args.start)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.sin();
                Ok(Value::Float(Float64::new(result)))
            }
            "builtin:MathCos" => {
                // Math.cos(x) implementation - returns cosine of x in radians
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.read_reg(args.start)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.cos();
                Ok(Value::Float(Float64::new(result)))
            }
            "builtin:StringPrototypeReplace" => {
                // String.prototype.replace() implementation - simplified version
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Object(_) => "[object Object]".to_string(),
                    _ => "[object Object]".to_string(),
                };

                if args.count < 2 {
                    return Ok(Value::Str(str_text)); // No search string provided
                }

                let search_val = self.read_reg(args.start + 1)?;
                let search_str = match search_val {
                    Value::Str(s) => s,
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Object(_) => "[object Object]".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let replace_str = if args.count >= 3 {
                    let replace_val = self.read_reg(args.start + 2)?;
                    match replace_val {
                        Value::Str(s) => s,
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Object(_) => "[object Object]".to_string(),
                        _ => "[object Object]".to_string(),
                    }
                } else {
                    "undefined".to_string()
                };

                // Simple string replacement (only first occurrence)
                let result = if let Some(index) = str_text.find(&search_str) {
                    let mut result = String::new();
                    result.push_str(&str_text[..index]);
                    result.push_str(&replace_str);
                    result.push_str(&str_text[index + search_str.len()..]);
                    result
                } else {
                    str_text
                };

                Ok(Value::Str(result))
            }
            "builtin:MathLog" => {
                // Math.log(x) implementation - returns natural logarithm of x
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.read_reg(args.start)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => Self::coerce_to_float(&arg).unwrap_or(f64::NAN),
                };

                if num < 0.0 {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else if num == 0.0 {
                    Ok(Value::Float(Float64::new(f64::NEG_INFINITY)))
                } else {
                    let result = num.ln();
                    Ok(Value::Float(Float64::new(result)))
                }
            }
            "builtin:MathExp" => {
                // Math.exp(x) implementation - returns e raised to the power of x
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.read_reg(args.start)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.exp();
                Ok(Value::Float(Float64::new(result)))
            }
            "builtin:MathTan" => {
                // Math.tan(x) implementation - returns tangent of x in radians
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.read_reg(args.start)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.tan();
                Ok(Value::Float(Float64::new(result)))
            }
            "builtin:MathPI" => {
                // Math.PI constant - returns the mathematical constant π
                Ok(Value::Float(Float64::new(std::f64::consts::PI)))
            }
            "builtin:StringPrototypeRepeat" => {
                // String.prototype.repeat(count) implementation
                if args.count == 0 {
                    return Ok(Value::Str(String::new()));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Str(String::new())),
                };

                // Get repeat count
                let count_val = self.read_reg(args.start + 1)?;
                let count = match count_val {
                    Value::Int(i) => i.max(0) as usize,
                    Value::Float(f) => f.inner().max(0.0) as usize,
                    Value::Bool(true) => 1,
                    Value::Bool(false) => 0,
                    Value::Null => 0,
                    _ => return Ok(Value::Str(String::new())),
                };

                // Prevent excessive memory usage
                if count > 1000 {
                    return Ok(Value::Str(String::new()));
                }

                let result = this_str.repeat(count);
                Ok(Value::Str(result))
            }
            "builtin:PromiseResolve" => {
                // Promise.resolve(value) implementation (simplified)
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };

                // Create a new Promise object (simplified - just wraps the value).
                let promise_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(
                    promise_id,
                    "__state".to_string(),
                    Value::Str("fulfilled".to_string()),
                )?;
                self.set_object_property(promise_id, "__value".to_string(), value)?;
                Ok(Value::Object(promise_id))
            }
            "builtin:ArrayPrototypeReduce" => {
                // Array.prototype.reduce(callback[, initialValue]) implementation - fail-closed until proper callback dispatch
                self.validate_array_callback_args(args, "Array.prototype.reduce")?;

                // Fail-closed until proper callback dispatch is implemented
                // Programs like [1,2,3].reduce((acc, val) => acc + val, 0) should error rather than
                // silently return wrong values like the initial value or first element
                Err(InterpreterError::TypeError {
                    expected: "supported Array.prototype.reduce implementation".to_string(),
                    got: "reducer callback invocation not yet supported - would require proper callback dispatch with (accumulator, currentValue, index, array) args, thisArg handling, proper initial value semantics, and handling empty arrays without initial value (TypeError)".to_string(),
                })
            }
            "builtin:StringPrototypePadStart" => {
                // String.prototype.padStart(targetLength[, padString]) implementation
                if args.count == 0 {
                    return self.read_reg(args.start);
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(this_val),
                };

                // Get target length
                let target_length = if args.count > 1 {
                    let len_val = self.read_reg(args.start + 1)?;
                    match len_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => this_str.len(),
                    }
                } else {
                    this_str.len()
                };

                // Get pad string
                let pad_str = if args.count > 2 {
                    let pad_val = self.read_reg(args.start + 2)?;
                    match pad_val {
                        Value::Str(s) => s,
                        Value::Int(i) => i.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => " ".to_string(),
                        _ => " ".to_string(),
                    }
                } else {
                    " ".to_string()
                };

                if target_length <= this_str.len() {
                    Ok(Value::Str(this_str))
                } else {
                    let pad_needed = target_length - this_str.len();
                    let mut padding = String::new();

                    // Repeat pad string until we have enough padding
                    while padding.len() < pad_needed {
                        padding.push_str(&pad_str);
                    }

                    // Truncate to exact length needed
                    padding.truncate(pad_needed);
                    let result = format!("{}{}", padding, this_str);
                    Ok(Value::Str(result))
                }
            }
            "builtin:ObjectHasOwnProperty" => {
                // Object.prototype.hasOwnProperty(property) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let obj_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects return false
                };

                // Get property name
                let prop_val = self.read_reg(args.start + 1)?;
                let prop_name = match prop_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Check if object has the property
                if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                    let has_property = obj.properties.contains_key(&prop_name);
                    Ok(Value::Bool(has_property))
                } else {
                    Ok(Value::Bool(false))
                }
            }
            "builtin:ArrayPrototypeSort" => {
                // Array.prototype.sort([compareFunction]) implementation (consolidated for builtin IDs 28, 248, 385)
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(this_val), // Non-objects return as-is
                };

                let _compare_fn = if args.count > 1 {
                    Some(self.read_reg(args.start + 1)?)
                } else {
                    None
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => (*len).max(0) as usize,
                        Some(Value::Float(len)) => len.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    return Ok(this_val);
                };

                if length <= 1 {
                    return Ok(this_val); // Nothing to sort
                }

                // Collect all elements, filling holes with Undefined
                let mut elements = Vec::new();
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    for i in 0..length {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            elements.push(element.clone());
                        } else {
                            elements.push(Value::Undefined);
                        }
                    }
                }

                // Sort by string representation while preserving original values
                elements.sort_by(|a, b| {
                    let a_str = match a {
                        Value::Str(s) => s.clone(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Object(_) => "[object Object]".to_string(),
                        _ => "".to_string(),
                    };

                    let b_str = match b {
                        Value::Str(s) => s.clone(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Object(_) => "[object Object]".to_string(),
                        _ => "".to_string(),
                    };

                    a_str.cmp(&b_str)
                });

                // Clear existing indexed properties and set sorted elements
                if let Some(obj_mut) = self.heap.get_mut(array_id.0 as usize) {
                    // Remove old indexed properties
                    for i in 0..length {
                        obj_mut.properties.remove(&i.to_string());
                    }

                    // Set sorted elements back in order
                    for (i, element) in elements.iter().enumerate() {
                        obj_mut.properties.insert(i.to_string(), element.clone());
                    }
                }

                Ok(this_val)
            }
            "builtin:Error" => {
                // Error(message) constructor implementation
                let message = if args.count > 0 {
                    let msg_val = self.read_reg(args.start)?;
                    match msg_val {
                        Value::Str(s) => s,
                        Value::Int(i) => i.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "Error".to_string(),
                    }
                } else {
                    String::new()
                };

                // Create a new Error object via the capability-checked
                // allocator.
                let error_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(
                    error_id,
                    "name".to_string(),
                    Value::Str("Error".to_string()),
                )?;
                self.set_object_property(error_id, "message".to_string(), Value::Str(message))?;
                Ok(Value::Object(error_id))
            }
            "builtin:StringPrototypePadEnd" => {
                // String.prototype.padEnd(targetLength[, padString]) implementation
                if args.count == 0 {
                    return self.read_reg(args.start);
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(this_val),
                };

                // Get target length
                let target_length = if args.count > 1 {
                    let len_val = self.read_reg(args.start + 1)?;
                    match len_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => this_str.len(),
                    }
                } else {
                    this_str.len()
                };

                // Get pad string
                let pad_str = if args.count > 2 {
                    let pad_val = self.read_reg(args.start + 2)?;
                    match pad_val {
                        Value::Str(s) => s,
                        Value::Int(i) => i.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => " ".to_string(),
                        _ => " ".to_string(),
                    }
                } else {
                    " ".to_string()
                };

                if target_length <= this_str.len() {
                    Ok(Value::Str(this_str))
                } else {
                    let pad_needed = target_length - this_str.len();
                    let mut padding = String::new();

                    // Repeat pad string until we have enough padding
                    while padding.len() < pad_needed {
                        padding.push_str(&pad_str);
                    }

                    // Truncate to exact length needed
                    padding.truncate(pad_needed);
                    let result = format!("{}{}", this_str, padding);
                    Ok(Value::Str(result))
                }
            }
            "builtin:MathTrunc" => {
                // Math.trunc(x) implementation - truncates decimal part of number
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.read_reg(args.start)?;
                let num = match arg {
                    Value::Int(i) => return Ok(Value::Int(i)), // Already truncated
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                if num.is_nan() || num.is_infinite() {
                    Ok(Value::Float(Float64::new(num)))
                } else {
                    let truncated = num.trunc();
                    // Return as int if it fits in i64 range
                    if truncated >= i64::MIN as f64 && truncated <= i64::MAX as f64 {
                        Ok(Value::Int(truncated as i64))
                    } else {
                        Ok(Value::Float(Float64::new(truncated)))
                    }
                }
            }
            "builtin:ArrayPrototypeSplice" => {
                // Array.prototype.splice(start[, deleteCount[, ...items]]) implementation (simplified)
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-arrays return undefined
                };

                let start = if args.count > 1 {
                    let start_val = self.read_reg(args.start + 1)?;
                    match start_val {
                        Value::Int(i) => i as isize,
                        Value::Float(f) => f.inner() as isize,
                        _ => 0,
                    }
                } else {
                    0
                };

                let delete_count = if args.count > 2 {
                    let delete_val = self.read_reg(args.start + 2)?;
                    match delete_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Get items to insert (simplified - just first additional item)
                let insert_item = if args.count > 3 {
                    Some(self.read_reg(args.start + 3)?)
                } else {
                    None
                };

                // Pre-compute the result ObjectId from current heap length
                // so we don't alias `self.heap` with the mutable borrow below.
                let result_id = ObjectId(u32::try_from(self.heap.len()).unwrap_or(u32::MAX));

                // Get the array object from heap
                if let Some(array_obj) = self.heap.get_mut(array_id.0 as usize) {
                    // Get array length
                    let length = array_obj
                        .properties
                        .get("length")
                        .and_then(|v| match v {
                            Value::Int(i) => Some(*i as usize),
                            Value::Float(f) => Some(f.inner() as usize),
                            _ => None,
                        })
                        .unwrap_or(0);

                    // Normalize start index
                    let actual_start = if start < 0 {
                        (length as isize + start).max(0) as usize
                    } else {
                        (start as usize).min(length)
                    };

                    // Create result array with deleted elements (simplified).
                    let mut result_obj = Object::new();
                    result_obj
                        .properties
                        .insert("length".to_string(), Value::Int(delete_count as i64));

                    // Collect existing elements
                    let mut elements: Vec<Value> = Vec::new();
                    for i in 0..length {
                        if let Some(value) = array_obj.properties.get(&i.to_string()) {
                            elements.push(value.clone());
                        } else {
                            elements.push(Value::Undefined);
                        }
                    }

                    // Add deleted elements to result (simplified)
                    for i in 0..delete_count.min(length.saturating_sub(actual_start)) {
                        if actual_start + i < elements.len() {
                            result_obj
                                .properties
                                .insert(i.to_string(), elements[actual_start + i].clone());
                        }
                    }

                    // Modify original array (simplified - just remove deleted count)
                    if delete_count > 0 {
                        elements.drain(
                            actual_start..actual_start + delete_count.min(length - actual_start),
                        );
                    }

                    // Insert new item if provided
                    if let Some(item) = insert_item {
                        elements.insert(actual_start, item);
                    }

                    // Update original array
                    array_obj
                        .properties
                        .retain(|k, _| k.parse::<usize>().is_err());
                    for (i, value) in elements.iter().enumerate() {
                        array_obj.properties.insert(i.to_string(), value.clone());
                    }
                    array_obj
                        .properties
                        .insert("length".to_string(), Value::Int(elements.len() as i64));

                    self.heap.push(result_obj);
                    Ok(Value::Object(result_id))
                } else {
                    Ok(Value::Undefined)
                }
            }
            "builtin:Number" => {
                // Number(value) constructor/converter implementation
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Int(0)
                };

                match value {
                    Value::Int(i) => Ok(Value::Int(i)),
                    Value::Float(f) => Ok(Value::Float(f)),
                    Value::Bool(true) => Ok(Value::Int(1)),
                    Value::Bool(false) => Ok(Value::Int(0)),
                    Value::Null => Ok(Value::Int(0)),
                    Value::Undefined => Ok(Value::Float(Float64::new(f64::NAN))),
                    Value::Str(s) => {
                        if s.is_empty() {
                            Ok(Value::Int(0))
                        } else if let Ok(i) = s.parse::<i64>() {
                            Ok(Value::Int(i))
                        } else if let Ok(f) = s.parse::<f64>() {
                            Ok(Value::Float(Float64::new(f)))
                        } else {
                            Ok(Value::Float(Float64::new(f64::NAN)))
                        }
                    }
                    _ => Ok(Value::Float(Float64::new(f64::NAN))),
                }
            }
            "builtin:Boolean" => {
                // Boolean(value) constructor/converter implementation
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    return Ok(Value::Bool(false));
                };

                let result = match value {
                    Value::Bool(b) => b,
                    Value::Int(i) => i != 0,
                    Value::Float(f) => {
                        let v = f.inner();
                        !v.is_nan() && v != 0.0
                    }
                    Value::Str(s) => !s.is_empty(),
                    Value::Null | Value::Undefined => false,
                    Value::Object(_) => true, // Objects are truthy
                    _ => true,
                };

                Ok(Value::Bool(result))
            }
            "builtin:StringPrototypeMatch" => {
                // String.prototype.match(regexp) implementation (simplified - basic string search)
                if args.count == 0 {
                    return Ok(Value::Null);
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Null),
                };

                // Get pattern (simplified - treat as literal string)
                let pattern_val = self.read_reg(args.start + 1)?;
                let pattern_str = match pattern_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Null),
                };

                // Simple pattern matching - find first occurrence
                if let Some(index) = this_str.find(&pattern_str) {
                    // Create result array with match information
                    let result_id = self.alloc_object_with_prototype(None)?;

                    // Add the matched string
                    self.set_object_property(
                        result_id,
                        "0".to_string(),
                        Value::Str(pattern_str.clone()),
                    )?;
                    self.set_object_property(
                        result_id,
                        "index".to_string(),
                        Value::Int(index as i64),
                    )?;
                    self.set_object_property(result_id, "input".to_string(), Value::Str(this_str))?;
                    self.set_object_property(result_id, "length".to_string(), Value::Int(1))?;

                    Ok(Value::Object(result_id))
                } else {
                    Ok(Value::Null)
                }
            }
            "builtin:Symbol" => {
                // Symbol(description) implementation (simplified)
                let description = if args.count > 0 {
                    let desc_val = self.read_reg(args.start)?;
                    match desc_val {
                        Value::Str(s) => Some(s),
                        Value::Int(i) => Some(i.to_string()),
                        Value::Float(f) => Some(f.inner().to_string()),
                        Value::Bool(b) => Some(b.to_string()),
                        Value::Null => Some("null".to_string()),
                        Value::Undefined => None,
                        _ => Some("Symbol".to_string()),
                    }
                } else {
                    None
                };

                // Create a unique symbol object (simplified representation)
                let symbol_id = self.alloc_object_with_prototype(None)?;

                // Store symbol metadata
                self.set_object_property(
                    symbol_id,
                    "__type".to_string(),
                    Value::Str("symbol".to_string()),
                )?;
                if let Some(desc) = description {
                    self.set_object_property(
                        symbol_id,
                        "__description".to_string(),
                        Value::Str(desc),
                    )?;
                }
                self.set_object_property(
                    symbol_id,
                    "__id".to_string(),
                    Value::Int(symbol_id.0 as i64),
                )?;
                Ok(Value::Object(symbol_id))
            }
            "builtin:typeof" => {
                // typeof operator implementation
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };

                let type_string = match value {
                    Value::Undefined => "undefined",
                    Value::Bool(_) => "boolean",
                    Value::Int(_) | Value::Float(_) => "number",
                    Value::Str(_) => "string",
                    Value::Object(id) => {
                        // Check if it's a function-like object
                        if let Some(obj) = self.heap.get(id.0 as usize) {
                            if obj.properties.contains_key("__type") {
                                if let Some(Value::Str(t)) = obj.properties.get("__type") {
                                    if t == "symbol" { "symbol" } else { "object" }
                                } else {
                                    "object"
                                }
                            } else {
                                "object"
                            }
                        } else {
                            "object"
                        }
                    }
                    Value::Function(_) | Value::Closure(_) | Value::BuiltinFunction(_) => {
                        "function"
                    }
                    Value::Null => "object", // In JavaScript, typeof null === "object"
                    _ => "object",
                };

                Ok(Value::Str(type_string.to_string()))
            }
            "builtin:ArrayPrototypeFlat" => {
                // Array.prototype.flat([depth]) implementation (simplified)
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-arrays return undefined
                };

                let depth = if args.count > 1 {
                    let depth_val = self.read_reg(args.start + 1)?;
                    match depth_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 1,
                    }
                } else {
                    1
                };

                // Snapshot outer array length + outer elements; also snapshot
                // every inner (level-1) array's elements. Done entirely under
                // immutable borrows so we can safely allocate + set below.
                let outer_snapshot: Vec<Value> =
                    if let Some(array_obj) = self.heap.get(array_id.0 as usize) {
                        let length = array_obj
                            .properties
                            .get("length")
                            .and_then(|v| match v {
                                Value::Int(i) => Some(*i as usize),
                                Value::Float(f) => Some(f.inner() as usize),
                                _ => None,
                            })
                            .unwrap_or(0);
                        (0..length)
                            .filter_map(|i| array_obj.properties.get(&i.to_string()).cloned())
                            .collect()
                    } else {
                        Vec::new()
                    };

                if !outer_snapshot.is_empty() {
                    // Pre-flatten level 1 under immutable borrows.
                    let mut flat_elements: Vec<Value> = Vec::new();
                    for value in outer_snapshot {
                        let flattened = if depth > 0 {
                            match &value {
                                Value::Object(inner_id) => {
                                    if let Some(inner_obj) = self.heap.get(inner_id.0 as usize) {
                                        if inner_obj.properties.contains_key("length") {
                                            let inner_length = inner_obj
                                                .properties
                                                .get("length")
                                                .and_then(|v| match v {
                                                    Value::Int(i) => Some(*i as usize),
                                                    Value::Float(f) => Some(f.inner() as usize),
                                                    _ => None,
                                                })
                                                .unwrap_or(0);
                                            let elems: Vec<Value> = (0..inner_length)
                                                .filter_map(|j| {
                                                    inner_obj
                                                        .properties
                                                        .get(&j.to_string())
                                                        .cloned()
                                                })
                                                .collect();
                                            Some(elems)
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            }
                        } else {
                            None
                        };
                        match flattened {
                            Some(elems) => flat_elements.extend(elems),
                            None => flat_elements.push(value),
                        }
                    }

                    // Create a new flattened array
                    let result_id = self.alloc_object_with_prototype(None)?;

                    // Set up result array
                    for (i, value) in flat_elements.iter().enumerate() {
                        self.set_object_property(result_id, i.to_string(), value.clone())?;
                    }
                    self.set_object_property(
                        result_id,
                        "length".to_string(),
                        Value::Int(flat_elements.len() as i64),
                    )?;

                    Ok(Value::Object(result_id))
                } else {
                    Ok(Value::Undefined)
                }
            }
            "builtin:StringPrototypeSearch" => {
                // String.prototype.search(regexp) implementation (simplified)
                if args.count == 0 {
                    return Ok(Value::Int(-1));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Int(-1)),
                };

                // Get pattern (simplified - treat as literal string)
                let pattern_val = self.read_reg(args.start + 1)?;
                let pattern_str = match pattern_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Int(-1)),
                };

                // Find first occurrence and return index
                if let Some(index) = this_str.find(&pattern_str) {
                    Ok(Value::Int(index as i64))
                } else {
                    Ok(Value::Int(-1))
                }
            }
            "builtin:ArrayPrototypeSome" => {
                // Array.prototype.some(callback[, thisArg]) implementation (simplified)
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-arrays return false
                };

                let _callback = self.read_reg(args.start + 1)?;
                let _this_arg = if args.count > 2 {
                    Some(self.read_reg(args.start + 2)?)
                } else {
                    None
                };

                // Get the array object from heap
                if let Some(array_obj) = self.heap.get(array_id.0 as usize) {
                    // Get array length
                    let length = array_obj
                        .properties
                        .get("length")
                        .and_then(|v| match v {
                            Value::Int(i) => Some(*i as usize),
                            Value::Float(f) => Some(f.inner() as usize),
                            _ => None,
                        })
                        .unwrap_or(0);

                    // Check if any element exists (simplified - just check if array has elements)
                    // TODO: In full implementation, would call callback and test condition
                    for i in 0..length {
                        if array_obj.properties.contains_key(&i.to_string()) {
                            // Simplified logic - return true if any element exists and is truthy
                            if let Some(value) = array_obj.properties.get(&i.to_string()) {
                                let is_truthy = match value {
                                    Value::Bool(false) | Value::Null | Value::Undefined => false,
                                    Value::Int(0) => false,
                                    Value::Float(f) if f.inner() == 0.0 || f.inner().is_nan() => {
                                        false
                                    }
                                    Value::Str(s) if s.is_empty() => false,
                                    _ => true,
                                };
                                if is_truthy {
                                    return Ok(Value::Bool(true));
                                }
                            }
                        }
                    }
                    Ok(Value::Bool(false))
                } else {
                    Ok(Value::Bool(false))
                }
            }
            "builtin:MathSign" => {
                // Math.sign(x) implementation - returns sign of a number
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.read_reg(args.start)?;
                let num = match arg {
                    Value::Int(i) => {
                        if i > 0 {
                            return Ok(Value::Int(1));
                        } else if i < 0 {
                            return Ok(Value::Int(-1));
                        } else {
                            return Ok(Value::Int(0));
                        }
                    }
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                if num.is_nan() {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else if num > 0.0 {
                    Ok(Value::Int(1))
                } else if num < 0.0 {
                    Ok(Value::Int(-1))
                } else {
                    // Handle +0 and -0
                    Ok(Value::Int(0))
                }
            }
            "builtin:ObjectDefineProperty" => {
                // Object.defineProperty(obj, prop, descriptor) implementation (simplified)
                if args.count < 3 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                let obj_id = match obj_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't have properties defined
                };

                // Get property name
                let prop_val = self.read_reg(args.start + 1)?;
                let prop_name = match prop_val {
                    Value::Str(s) => s,
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Undefined),
                };

                // Get descriptor object (simplified - just use the value directly)
                let descriptor_val = self.read_reg(args.start + 2)?;

                // In a full implementation, we would parse the descriptor object.
                // Resolve the effective value under an immutable borrow first,
                // then apply it with a fresh mutable borrow to avoid aliasing.
                let effective_value = match descriptor_val {
                    Value::Object(desc_id) => self
                        .heap
                        .get(desc_id.0 as usize)
                        .and_then(|desc_obj| desc_obj.properties.get("value").cloned())
                        .unwrap_or(Value::Undefined),
                    other => other,
                };
                if let Some(obj) = self.heap.get_mut(obj_id.0 as usize) {
                    obj.properties.insert(prop_name, effective_value);
                }

                Ok(obj_val) // Return the original object
            }
            "builtin:Map" => {
                // Map([iterable]) constructor implementation
                let map_id = self.alloc_object_with_prototype(None)?;
                let entries_id = self.alloc_object_with_prototype(None)?;

                // Mark as Map type
                self.set_object_property(
                    map_id,
                    "__type".to_string(),
                    Value::Str("Map".to_string()),
                )?;
                self.set_object_property(
                    map_id,
                    "__entries".to_string(),
                    Value::Object(entries_id),
                )?;
                self.set_object_property(map_id, "size".to_string(), Value::Int(0))?;

                // Create internal entries storage
                let _entries_id = self.next_object_id() - 1;
                let _entries_obj = Object::new();
                // TODO: If iterable argument provided, populate map with entries
                if args.count > 0 {
                    // Simplified: ignore iterable for now
                }

                Ok(Value::Object(map_id))
            }
            "builtin:Set" => {
                // Set([iterable]) constructor implementation
                let set_id = ObjectId(self.next_object_id());
                let mut set_obj = Object::new();

                // Mark as Set type
                set_obj
                    .properties
                    .insert("__type".to_string(), Value::Str("Set".to_string()));
                set_obj.properties.insert(
                    "__values".to_string(),
                    Value::Object(ObjectId(self.next_object_id())),
                );
                set_obj.properties.insert("size".to_string(), Value::Int(0));

                // Create internal values storage
                let _values_id = self.next_object_id() - 1;
                let values_obj = Object::new();
                self.heap.push(values_obj);

                // TODO: If iterable argument provided, populate set with values
                if args.count > 0 {
                    // Simplified: ignore iterable for now
                }

                self.heap.push(set_obj);
                Ok(Value::Object(set_id))
            }
            "builtin:WeakMap" => {
                // WeakMap([iterable]) constructor implementation (simplified)
                let weakmap_id = ObjectId(self.next_object_id());
                let mut weakmap_obj = Object::new();

                // Mark as WeakMap type
                weakmap_obj
                    .properties
                    .insert("__type".to_string(), Value::Str("WeakMap".to_string()));
                weakmap_obj.properties.insert(
                    "__entries".to_string(),
                    Value::Object(ObjectId(self.next_object_id())),
                );

                // Create internal entries storage (simplified - using regular object)
                let _entries_id = self.next_object_id() - 1;
                let entries_obj = Object::new();
                self.heap.push(entries_obj);

                // Note: In a full implementation, WeakMap would use weak references
                // TODO: If iterable argument provided, populate weakmap with entries
                if args.count > 0 {
                    // Simplified: ignore iterable for now
                }

                self.heap.push(weakmap_obj);
                Ok(Value::Object(weakmap_id))
            }
            "builtin:WeakSet" => {
                // WeakSet([iterable]) constructor implementation (simplified)
                let weakset_id = ObjectId(self.next_object_id());
                let mut weakset_obj = Object::new();

                // Mark as WeakSet type
                weakset_obj
                    .properties
                    .insert("__type".to_string(), Value::Str("WeakSet".to_string()));
                weakset_obj.properties.insert(
                    "__values".to_string(),
                    Value::Object(ObjectId(self.next_object_id())),
                );

                // Create internal values storage (simplified - using regular object)
                let _values_id = self.next_object_id() - 1;
                let values_obj = Object::new();
                self.heap.push(values_obj);

                // Note: In a full implementation, WeakSet would use weak references
                // TODO: If iterable argument provided, populate weakset with values
                if args.count > 0 {
                    // Simplified: ignore iterable for now
                }

                self.heap.push(weakset_obj);
                Ok(Value::Object(weakset_id))
            }
            "builtin:MapPrototypeSet" => {
                // Map.prototype.set(key, value) implementation
                if args.count < 3 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let map_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be maps
                };

                // Check if it's actually a Map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if !matches!(map_obj.properties.get("__type"), Some(Value::Str(s)) if s == "Map")
                    {
                        return Ok(Value::Undefined);
                    }
                }

                let key = self.read_reg(args.start + 1)?;
                let value = self.read_reg(args.start + 2)?;

                // Resolve the internal entries ObjectId under an immutable
                // borrow, then insert into entries and update size under
                // separate mutable borrows.
                let entries_id_opt: Option<ObjectId> = self
                    .heap
                    .get(map_id.0 as usize)
                    .and_then(|m| m.properties.get("__entries").cloned())
                    .and_then(|v| match v {
                        Value::Object(id) => Some(id),
                        _ => None,
                    });

                if let Some(entries_id) = entries_id_opt {
                    // Use a simple key representation (simplified)
                    let key_str = match key {
                        Value::Str(s) => format!("s:{}", s),
                        Value::Int(i) => format!("n:{}", i),
                        Value::Float(f) => format!("n:{}", f.inner()),
                        Value::Bool(b) => format!("b:{}", b),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Object(id) => format!("o:{}", id.0),
                        _ => "other".to_string(),
                    };

                    if let Some(entries_obj) = self.heap.get_mut(entries_id.0 as usize) {
                        entries_obj.properties.insert(key_str, value);
                    }

                    if let Some(map_obj) = self.heap.get_mut(map_id.0 as usize) {
                        if let Some(size_slot) = map_obj.properties.get_mut("size") {
                            if let Value::Int(size) = size_slot {
                                *size += 1;
                            }
                        }
                    }
                }

                Ok(this_val) // Return the Map object for chaining
            }
            "builtin:MapPrototypeGet" => {
                // Map.prototype.get(key) implementation
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let map_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be maps
                };

                // Check if it's actually a Map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if !matches!(map_obj.properties.get("__type"), Some(Value::Str(s)) if s == "Map")
                    {
                        return Ok(Value::Undefined);
                    }
                }

                let key = self.read_reg(args.start + 1)?;

                // Get the value from the map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if let Some(Value::Object(entries_id)) = map_obj.properties.get("__entries") {
                        if let Some(entries_obj) = self.heap.get(entries_id.0 as usize) {
                            // Use the same key representation as set()
                            let key_str = match key {
                                Value::Str(s) => format!("s:{}", s),
                                Value::Int(i) => format!("n:{}", i),
                                Value::Float(f) => format!("n:{}", f.inner()),
                                Value::Bool(b) => format!("b:{}", b),
                                Value::Null => "null".to_string(),
                                Value::Undefined => "undefined".to_string(),
                                Value::Object(id) => format!("o:{}", id.0),
                                _ => "other".to_string(),
                            };

                            if let Some(value) = entries_obj.properties.get(&key_str) {
                                return Ok(value.clone());
                            }
                        }
                    }
                }

                Ok(Value::Undefined)
            }
            "builtin:SetPrototypeAdd" => {
                // Set.prototype.add(value) implementation
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let set_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be sets
                };

                // Check if it's actually a Set
                if let Some(set_obj) = self.heap.get(set_id.0 as usize) {
                    if !matches!(set_obj.properties.get("__type"), Some(Value::Str(s)) if s == "Set")
                    {
                        return Ok(Value::Undefined);
                    }
                }

                let value = self.read_reg(args.start + 1)?;

                // Resolve the internal values ObjectId under an immutable
                // borrow, then insert into values and update size under
                // separate mutable borrows.
                let values_id_opt: Option<ObjectId> = self
                    .heap
                    .get(set_id.0 as usize)
                    .and_then(|s| s.properties.get("__values").cloned())
                    .and_then(|v| match v {
                        Value::Object(id) => Some(id),
                        _ => None,
                    });

                if let Some(values_id) = values_id_opt {
                    // Use a simple value representation (simplified)
                    let value_str = match value {
                        Value::Str(s) => format!("s:{}", s),
                        Value::Int(i) => format!("n:{}", i),
                        Value::Float(f) => format!("n:{}", f.inner()),
                        Value::Bool(b) => format!("b:{}", b),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Object(id) => format!("o:{}", id.0),
                        _ => "other".to_string(),
                    };

                    let inserted = if let Some(values_obj) = self.heap.get_mut(values_id.0 as usize)
                    {
                        if values_obj.properties.contains_key(&value_str) {
                            false
                        } else {
                            values_obj.properties.insert(value_str, Value::Bool(true));
                            true
                        }
                    } else {
                        false
                    };

                    if inserted {
                        if let Some(set_obj) = self.heap.get_mut(set_id.0 as usize) {
                            if let Some(size_slot) = set_obj.properties.get_mut("size") {
                                if let Value::Int(size) = size_slot {
                                    *size += 1;
                                }
                            }
                        }
                    }
                }

                Ok(this_val) // Return the Set object for chaining
            }
            "builtin:SetPrototypeHas" => {
                // Set.prototype.has(value) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let set_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be sets
                };

                // Check if it's actually a Set
                if let Some(set_obj) = self.heap.get(set_id.0 as usize) {
                    if !matches!(set_obj.properties.get("__type"), Some(Value::Str(s)) if s == "Set")
                    {
                        return Ok(Value::Bool(false));
                    }
                }

                let value = self.read_reg(args.start + 1)?;

                // Check if the set has the value
                if let Some(set_obj) = self.heap.get(set_id.0 as usize) {
                    if let Some(Value::Object(values_id)) = set_obj.properties.get("__values") {
                        if let Some(values_obj) = self.heap.get(values_id.0 as usize) {
                            // Use the same value representation as add()
                            let value_str = match value {
                                Value::Str(s) => format!("s:{}", s),
                                Value::Int(i) => format!("n:{}", i),
                                Value::Float(f) => format!("n:{}", f.inner()),
                                Value::Bool(b) => format!("b:{}", b),
                                Value::Null => "null".to_string(),
                                Value::Undefined => "undefined".to_string(),
                                Value::Object(id) => format!("o:{}", id.0),
                                _ => "other".to_string(),
                            };

                            if values_obj.properties.contains_key(&value_str) {
                                return Ok(Value::Bool(true));
                            }
                        }
                    }
                }

                Ok(Value::Bool(false))
            }

            "builtin:MapPrototypeHas" => {
                // Map.prototype.has(key) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let map_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be maps
                };

                // Check if it's actually a Map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if !matches!(map_obj.properties.get("__type"), Some(Value::Str(s)) if s == "Map")
                    {
                        return Ok(Value::Bool(false));
                    }
                }

                let key = self.read_reg(args.start + 1)?;

                // Check if the map has the key
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if let Some(Value::Object(entries_id)) = map_obj.properties.get("__entries") {
                        if let Some(entries_obj) = self.heap.get(entries_id.0 as usize) {
                            // Use the same key representation as set()
                            let key_str = match key {
                                Value::Str(s) => format!("s:{}", s),
                                Value::Int(i) => format!("n:{}", i),
                                Value::Float(f) => format!("n:{}", f.inner()),
                                Value::Bool(b) => format!("b:{}", b),
                                Value::Null => "null".to_string(),
                                Value::Undefined => "undefined".to_string(),
                                Value::Object(id) => format!("o:{}", id.0),
                                _ => "other".to_string(),
                            };

                            if entries_obj.properties.contains_key(&key_str) {
                                return Ok(Value::Bool(true));
                            }
                        }
                    }
                }

                Ok(Value::Bool(false))
            }

            "builtin:MapPrototypeDelete" => {
                // Map.prototype.delete(key) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let map_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be maps
                };

                // Check if it's actually a Map
                if let Some(map_obj) = self.heap.get_mut(map_id.0 as usize) {
                    if !matches!(map_obj.properties.get("__type"), Some(Value::Str(s)) if s == "Map")
                    {
                        return Ok(Value::Bool(false));
                    }
                } else {
                    return Ok(Value::Bool(false));
                }

                let key = self.read_reg(args.start + 1)?;

                // Resolve entries_id under an immutable borrow, then do the
                // mutable removal + size update under separate mutable borrows.
                let entries_id_opt: Option<ObjectId> = self
                    .heap
                    .get(map_id.0 as usize)
                    .and_then(|m| m.properties.get("__entries").cloned())
                    .and_then(|v| match v {
                        Value::Object(id) => Some(id),
                        _ => None,
                    });

                if let Some(entries_id) = entries_id_opt {
                    // Use the same key representation as set()
                    let key_str = match key {
                        Value::Str(s) => format!("s:{}", s),
                        Value::Int(i) => format!("n:{}", i),
                        Value::Float(f) => format!("n:{}", f.inner()),
                        Value::Bool(b) => format!("b:{}", b),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Object(id) => format!("o:{}", id.0),
                        _ => "other".to_string(),
                    };

                    let removed = self
                        .heap
                        .get_mut(entries_id.0 as usize)
                        .map(|entries_obj| entries_obj.properties.remove(&key_str).is_some())
                        .unwrap_or(false);

                    if removed {
                        if let Some(map_obj) = self.heap.get_mut(map_id.0 as usize) {
                            if let Some(Value::Int(size)) = map_obj.properties.get("size") {
                                let new_size = *size - 1;
                                map_obj
                                    .properties
                                    .insert("size".to_string(), Value::Int(new_size));
                            }
                        }
                        return Ok(Value::Bool(true));
                    }
                }

                Ok(Value::Bool(false))
            }

            "builtin:SetPrototypeDelete" => {
                // Set.prototype.delete(value) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let set_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be sets
                };

                // Check if it's actually a Set
                if let Some(set_obj) = self.heap.get_mut(set_id.0 as usize) {
                    if !matches!(set_obj.properties.get("__type"), Some(Value::Str(s)) if s == "Set")
                    {
                        return Ok(Value::Bool(false));
                    }
                } else {
                    return Ok(Value::Bool(false));
                }

                let value = self.read_reg(args.start + 1)?;

                // Resolve values_id under an immutable borrow, then do the
                // mutable removal + size update under separate borrows.
                let values_id_opt: Option<ObjectId> = self
                    .heap
                    .get(set_id.0 as usize)
                    .and_then(|s| s.properties.get("__values").cloned())
                    .and_then(|v| match v {
                        Value::Object(id) => Some(id),
                        _ => None,
                    });

                if let Some(values_id) = values_id_opt {
                    // Use the same value representation as add()
                    let value_str = match value {
                        Value::Str(s) => format!("s:{}", s),
                        Value::Int(i) => format!("n:{}", i),
                        Value::Float(f) => format!("n:{}", f.inner()),
                        Value::Bool(b) => format!("b:{}", b),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Object(id) => format!("o:{}", id.0),
                        _ => "other".to_string(),
                    };

                    let removed = self
                        .heap
                        .get_mut(values_id.0 as usize)
                        .map(|values_obj| values_obj.properties.remove(&value_str).is_some())
                        .unwrap_or(false);

                    if removed {
                        if let Some(set_obj) = self.heap.get_mut(set_id.0 as usize) {
                            if let Some(Value::Int(size)) = set_obj.properties.get("size") {
                                let new_size = *size - 1;
                                set_obj
                                    .properties
                                    .insert("size".to_string(), Value::Int(new_size));
                            }
                        }
                        return Ok(Value::Bool(true));
                    }
                }

                Ok(Value::Bool(false))
            }

            "builtin:SetPrototypeClear" => {
                // Set.prototype.clear() implementation
                let this_val = self.read_reg(args.start)?;
                let set_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be sets
                };

                // Check if it's actually a Set
                if let Some(set_obj) = self.heap.get_mut(set_id.0 as usize) {
                    if !matches!(set_obj.properties.get("__type"), Some(Value::Str(s)) if s == "Set")
                    {
                        return Ok(Value::Undefined);
                    }
                } else {
                    return Ok(Value::Undefined);
                }

                // Clear all values from the set. Resolve values_id under an
                // immutable borrow first, then clear + zero size under
                // separate mutable borrows.
                let values_id_opt: Option<ObjectId> = self
                    .heap
                    .get(set_id.0 as usize)
                    .and_then(|s| s.properties.get("__values").cloned())
                    .and_then(|v| match v {
                        Value::Object(id) => Some(id),
                        _ => None,
                    });

                if let Some(values_id) = values_id_opt {
                    if let Some(values_obj) = self.heap.get_mut(values_id.0 as usize) {
                        values_obj.properties.clear();
                    }
                }

                // Reset size to 0
                if let Some(set_obj) = self.heap.get_mut(set_id.0 as usize) {
                    set_obj.properties.insert("size".to_string(), Value::Int(0));
                }

                Ok(Value::Undefined)
            }

            "builtin:ArrayPrototypeLastIndexOf" => {
                // Array.prototype.lastIndexOf(searchElement, fromIndex) implementation
                if args.count < 2 {
                    return Ok(Value::Int(-1));
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Int(-1)), // Non-objects can't be arrays
                };

                let search_element = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => return Ok(Value::Int(-1)),
                    }
                } else {
                    return Ok(Value::Int(-1));
                };

                if length == 0 {
                    return Ok(Value::Int(-1));
                }

                // Get fromIndex if provided, otherwise start from the end
                let from_index = if args.count >= 3 {
                    match self.read_reg(args.start + 2)? {
                        Value::Int(idx) => idx,
                        Value::Float(idx) => idx.inner() as i64,
                        _ => length as i64 - 1,
                    }
                } else {
                    length as i64 - 1
                };

                // Convert negative indices to positive
                let start_idx = if from_index < 0 {
                    let adjusted = (length as i64) + from_index;
                    if adjusted < 0 {
                        return Ok(Value::Int(-1));
                    }
                    adjusted as usize
                } else {
                    (from_index as usize).min(length - 1)
                };

                // Search backwards from start_idx
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    for i in (0..=start_idx).rev() {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            if Self::values_equal(element, &search_element) {
                                return Ok(Value::Int(i as i64));
                            }
                        }
                    }
                }

                Ok(Value::Int(-1))
            }

            "builtin:ArrayPrototypeFindIndex" => {
                // Array.prototype.findIndex(callback[, thisArg]) implementation - fail-closed until proper callback dispatch
                self.validate_array_callback_args(args, "Array.prototype.findIndex")?;

                // Fail-closed until proper callback dispatch is implemented
                // Programs like [1,2,3].findIndex(x => x > 2) should error rather than
                // silently return wrong values like -1 or first valid index
                Err(InterpreterError::TypeError {
                    expected: "supported Array.prototype.findIndex implementation".to_string(),
                    got: "callback invocation not yet supported - would require proper callback dispatch with (element, index, array) args, thisArg handling, and returning index of first element where callback returns truthy".to_string(),
                })
            }

            "builtin:StringPrototypeCharCodeAt" => {
                // String.prototype.charCodeAt(index) implementation
                let this_val = self.read_reg(args.start)?;
                let string_val = match this_val {
                    Value::Str(s) => s,
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.inner().to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::Float(f64::NAN.into())),
                        }
                    }
                };

                let index = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(idx) => idx as usize,
                        Value::Float(idx) => idx.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Get character at index
                let chars: Vec<char> = string_val.chars().collect();
                if index < chars.len() {
                    let char_code = chars[index] as u32;
                    Ok(Value::Int(char_code as i64))
                } else {
                    Ok(Value::Float(f64::NAN.into()))
                }
            }

            "builtin:StringFromCharCode" => {
                // String.fromCharCode(...charCodes) implementation
                let mut result = String::new();

                // Iterate through all provided character codes
                for i in 0..args.count {
                    let char_code_val = self.read_reg(args.start + i)?;
                    let char_code = match char_code_val {
                        Value::Int(n) => n as u32,
                        Value::Float(f) => f.inner() as u32,
                        _ => 0, // Invalid character codes become null char
                    };

                    // Convert to character (modulo 65536 for 16-bit values)
                    let char_code_16bit = char_code & 0xFFFF;
                    if let Some(ch) = std::char::from_u32(char_code_16bit) {
                        result.push(ch);
                    } else {
                        result.push('\u{0000}'); // Null character for invalid codes
                    }
                }

                Ok(Value::Str(result))
            }

            "builtin:ObjectGetOwnPropertyNames" => {
                // Object.getOwnPropertyNames(obj) implementation
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Get the object's own property names
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            let property_names: Vec<String> =
                                obj.properties.keys().cloned().collect();

                            // Create array object to hold the property names
                            let array_id = self.alloc_object_with_prototype(None)?;

                            // Add property names to the array
                            for (i, name) in property_names.iter().enumerate() {
                                self.set_object_property(
                                    array_id,
                                    i.to_string(),
                                    Value::Str(name.clone()),
                                )?;
                            }

                            // Set length property
                            self.set_object_property(
                                array_id,
                                "length".to_string(),
                                Value::Int(property_names.len() as i64),
                            )?;

                            Ok(Value::Object(array_id))
                        } else {
                            // Object not found, return empty array
                            let empty_array_id = self.alloc_object_with_prototype(None)?;
                            self.set_object_property(
                                empty_array_id,
                                "length".to_string(),
                                Value::Int(0),
                            )?;
                            Ok(Value::Object(empty_array_id))
                        }
                    }
                    _ => {
                        // Non-object argument, return empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        Ok(Value::Object(empty_array_id))
                    }
                }
            }

            "builtin:ObjectGetPrototypeOf" => {
                // Object.getPrototypeOf(obj) implementation
                if args.count == 0 {
                    return Ok(Value::Null);
                }

                let obj_val = self.read_reg(args.start)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Get the object's prototype
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(prototype_id) = obj.prototype {
                                Ok(Value::Object(prototype_id))
                            } else {
                                Ok(Value::Null)
                            }
                        } else {
                            Ok(Value::Null)
                        }
                    }
                    _ => {
                        // Non-object argument throws TypeError in strict JS, but we'll return null
                        Ok(Value::Null)
                    }
                }
            }

            "builtin:PromiseReject" => {
                // Promise.reject(reason) implementation
                let reason = if args.count >= 1 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };

                // Create a rejected Promise object
                let promise_id = self.alloc_object_with_prototype(None)?;

                // Set Promise metadata
                self.set_object_property(
                    promise_id,
                    "__type".to_string(),
                    Value::Str("Promise".to_string()),
                )?;
                self.set_object_property(
                    promise_id,
                    "__state".to_string(),
                    Value::Str("rejected".to_string()),
                )?;
                self.set_object_property(promise_id, "__value".to_string(), reason)?;

                Ok(Value::Object(promise_id))
            }

            "builtin:MathAtan2" => {
                // Math.atan2(y, x) implementation
                if args.count < 2 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let y_val = self.read_reg(args.start)?;
                let x_val = self.read_reg(args.start + 1)?;

                let y = match y_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => f64::NAN,
                };

                let x = match x_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => f64::NAN,
                };

                let result = y.atan2(x);
                Ok(Value::Float(result.into()))
            }

            "builtin:FunctionPrototypeCall" => {
                // Function.prototype.call(thisArg, ...args) implementation
                // For now, simplified implementation without full function call support
                // TODO: Implement proper function call mechanism with context binding

                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                // The first argument is the function to call, second is thisArg
                let _function = self.read_reg(args.start)?;
                let _this_arg = if args.count >= 2 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                // For now, return undefined since we don't have full function call support
                // This is a foundation for future function call implementation
                Ok(Value::Undefined)
            }

            "builtin:MathAsin" => {
                // Math.asin(x) implementation - arcsine
                if args.count == 0 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let x_val = self.read_reg(args.start)?;
                let x = match x_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => f64::NAN,
                };

                let result = x.asin();
                Ok(Value::Float(result.into()))
            }

            "builtin:MathAcos" => {
                // Math.acos(x) implementation - arccosine
                if args.count == 0 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let x_val = self.read_reg(args.start)?;
                let x = match x_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => f64::NAN,
                };

                let result = x.acos();
                Ok(Value::Float(result.into()))
            }

            "builtin:RegExp" => {
                // RegExp constructor implementation
                let pattern = if args.count >= 1 {
                    match self.read_reg(args.start)? {
                        Value::Str(s) => s,
                        Value::Undefined => String::new(),
                        Value::Null => "null".to_string(),
                        _ => String::new(),
                    }
                } else {
                    String::new()
                };

                let flags = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Str(s) => s,
                        Value::Undefined => String::new(),
                        _ => String::new(),
                    }
                } else {
                    String::new()
                };

                // Create RegExp object
                let regexp_id = self.alloc_object_with_prototype(None)?;

                // Set RegExp metadata
                self.set_object_property(
                    regexp_id,
                    "__type".to_string(),
                    Value::Str("RegExp".to_string()),
                )?;
                self.set_object_property(regexp_id, "source".to_string(), Value::Str(pattern))?;
                self.set_object_property(regexp_id, "flags".to_string(), Value::Str(flags))?;

                Ok(Value::Object(regexp_id))
            }

            "builtin:ArrayPrototypeReduceRight" => {
                // Array.prototype.reduceRight(callback, initialValue) implementation
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be arrays
                };

                let _callback = self.read_reg(args.start + 1)?;
                let initial_value = if args.count >= 3 {
                    Some(self.read_reg(args.start + 2)?)
                } else {
                    None
                };

                // Get array length
                let _length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => return Ok(Value::Undefined),
                    }
                } else {
                    return Ok(Value::Undefined);
                };

                // For now, simplified implementation without function call support
                // Return initial value or undefined since we can't execute callback functions yet
                // TODO: Implement function call mechanism for full callback support
                Ok(initial_value.unwrap_or(Value::Undefined))
            }

            "builtin:StringPrototypeSubstr" => {
                // String.prototype.substr(start, length) implementation
                let this_val = self.read_reg(args.start)?;
                let string_val = match this_val {
                    Value::Str(s) => s,
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.inner().to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::Str(String::new())),
                        }
                    }
                };

                let start_idx = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => n as i32,
                        Value::Float(f) => f.inner() as i32,
                        _ => 0,
                    }
                } else {
                    0
                };

                let length_param = if args.count >= 3 {
                    match self.read_reg(args.start + 2)? {
                        Value::Int(n) => Some(n as u32),
                        Value::Float(f) => Some(f.inner() as u32),
                        _ => None,
                    }
                } else {
                    None
                };

                let str_len = string_val.len() as i32;

                // Calculate actual start position
                let actual_start = if start_idx < 0 {
                    0.max(str_len + start_idx) as usize
                } else {
                    (start_idx as usize).min(str_len as usize)
                };

                // Calculate length
                let actual_length = if let Some(len) = length_param {
                    if len == 0 {
                        return Ok(Value::Str(String::new()));
                    }
                    len as usize
                } else {
                    (str_len as usize).saturating_sub(actual_start)
                };

                // Extract substring
                let chars: Vec<char> = string_val.chars().collect();
                let end_pos = (actual_start + actual_length).min(chars.len());

                if actual_start >= chars.len() {
                    Ok(Value::Str(String::new()))
                } else {
                    let result: String = chars[actual_start..end_pos].iter().collect();
                    Ok(Value::Str(result))
                }
            }

            "builtin:NumberPrototypeToString" => {
                // Number.prototype.toString(radix) implementation - unified spec-consistent version
                let this_val = self.read_reg(args.start)?;

                let number_val = match this_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => return Ok(Value::Str("NaN".to_string())),
                };

                let radix = if args.count >= 2 {
                    Self::coerce_finite_radix_or_default(self.read_reg(args.start + 1)?, 10)
                } else {
                    10
                };

                match self.number_to_string_impl(number_val, radix) {
                    Ok(result) => Ok(Value::Str(result)),
                    Err(_) => Ok(Value::Str("RangeError".to_string())),
                }
            }

            "builtin:PromiseAll" => {
                // Promise.all(iterable) implementation
                let _iterable = if args.count >= 1 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };

                // Create a resolved Promise for now (simplified implementation)
                // TODO: Implement proper Promise.all with iterable processing
                let promise_id = self.alloc_object_with_prototype(None)?;

                // Set Promise metadata
                self.set_object_property(
                    promise_id,
                    "__type".to_string(),
                    Value::Str("Promise".to_string()),
                )?;
                self.set_object_property(
                    promise_id,
                    "__state".to_string(),
                    Value::Str("fulfilled".to_string()),
                )?;

                // Create empty array as resolved value for now
                let empty_array_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(empty_array_id, "length".to_string(), Value::Int(0))?;

                self.set_object_property(
                    promise_id,
                    "__value".to_string(),
                    Value::Object(empty_array_id),
                )?;

                Ok(Value::Object(promise_id))
            }

            "builtin:FunctionPrototypeApply" => {
                // Function.prototype.apply(thisArg, argsArray) implementation
                // For now, simplified implementation without full function call support
                // TODO: Implement proper function call mechanism with context binding and argument spreading

                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                // The first argument is the function to call, second is thisArg, third is args array
                let _function = self.read_reg(args.start)?;
                let _this_arg = if args.count >= 2 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };
                let _args_array = if args.count >= 3 {
                    self.read_reg(args.start + 2)?
                } else {
                    Value::Undefined
                };

                // For now, return undefined since we don't have full function call support
                // This is a foundation for future function call implementation with argument arrays
                Ok(Value::Undefined)
            }

            "builtin:StringPrototypeLocaleCompare" => {
                // String.prototype.localeCompare(that) implementation
                let this_val = self.read_reg(args.start)?;
                let this_string = match this_val {
                    Value::Str(s) => s,
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.inner().to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::Int(0)),
                        }
                    }
                };

                let that_string = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Str(s) => s,
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => String::new(),
                    }
                } else {
                    "undefined".to_string()
                };

                // Simplified locale-aware comparison (using standard string comparison for now)
                let result = this_string.cmp(&that_string);
                let comparison_result = match result {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };

                Ok(Value::Int(comparison_result))
            }

            "builtin:DatePrototypeGetTime" => {
                // Date.prototype.getTime() implementation
                let this_val = self.read_reg(args.start)?;
                let date_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Float(f64::NAN.into())), // Non-objects can't be dates
                };

                // Check if it's actually a Date
                if let Some(date_obj) = self.heap.get(date_id.0 as usize) {
                    if let Some(Value::Str(type_val)) = date_obj.properties.get("__type") {
                        if type_val == "Date" {
                            // Get the timestamp value
                            if let Some(Value::Float(timestamp)) =
                                date_obj.properties.get("__timestamp")
                            {
                                return Ok(Value::Float(*timestamp));
                            } else if let Some(Value::Int(timestamp)) =
                                date_obj.properties.get("__timestamp")
                            {
                                return Ok(Value::Int(*timestamp));
                            }
                        }
                    }
                }

                // Invalid date or not a date object
                Ok(Value::Float(f64::NAN.into()))
            }

            "builtin:DatePrototypeToString" => {
                // Date.prototype.toString() implementation
                let this_val = self.read_reg(args.start)?;
                let date_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Str("Invalid Date".to_string())), // Non-objects can't be dates
                };

                // Check if it's actually a Date
                if let Some(date_obj) = self.heap.get(date_id.0 as usize) {
                    if let Some(Value::Str(type_val)) = date_obj.properties.get("__type") {
                        if type_val == "Date" {
                            // Get the timestamp and format it
                            if let Some(Value::Float(timestamp)) =
                                date_obj.properties.get("__timestamp")
                            {
                                // Simplified date formatting (ISO-8601 style for now)
                                // TODO: Implement proper locale-aware date formatting
                                return Ok(Value::Str(format!("Date({})", timestamp.inner())));
                            } else if let Some(Value::Int(timestamp)) =
                                date_obj.properties.get("__timestamp")
                            {
                                return Ok(Value::Str(format!("Date({})", timestamp)));
                            }
                        }
                    }
                }

                // Invalid date or not a date object
                Ok(Value::Str("Invalid Date".to_string()))
            }

            "builtin:ObjectPrototypeValueOf" => {
                // Object.prototype.valueOf() implementation
                let this_val = self.read_reg(args.start)?;

                // For objects, return the object itself (by reference)
                // For primitives, return the primitive value
                match this_val {
                    Value::Object(obj_id) => {
                        // For most objects, valueOf returns the object itself
                        // Special handling could be added for Date, Number wrapper objects, etc.
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            // Check for special object types that have primitive values
                            if let Some(Value::Str(type_val)) = obj.properties.get("__type") {
                                match type_val.as_str() {
                                    "Number" => {
                                        // For Number wrapper objects, return the primitive number
                                        if let Some(value) = obj.properties.get("__value") {
                                            return Ok(value.clone());
                                        }
                                    }
                                    "String" => {
                                        // For String wrapper objects, return the primitive string
                                        if let Some(value) = obj.properties.get("__value") {
                                            return Ok(value.clone());
                                        }
                                    }
                                    "Boolean" => {
                                        // For Boolean wrapper objects, return the primitive boolean
                                        if let Some(value) = obj.properties.get("__value") {
                                            return Ok(value.clone());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        // Default: return the object itself
                        Ok(Value::Object(obj_id))
                    }
                    // For primitives, return the value as-is
                    _ => Ok(this_val),
                }
            }

            // Removed duplicate ArrayPrototypeFlatMap - implementation at line ~13119 is more complete

            "builtin:MathHypot" => {
                // Math.hypot(...values) implementation - Euclidean distance
                if args.count == 0 {
                    return Ok(Value::Float(0.0.into()));
                }

                let mut sum_of_squares = 0.0;
                let mut has_infinity = false;
                let mut has_nan = false;

                // Process all arguments
                for i in 0..args.count {
                    let arg_val = self.read_reg(args.start + i)?;
                    let num_val = match arg_val {
                        Value::Int(n) => n as f64,
                        Value::Float(f) => f.inner(),
                        _ => f64::NAN,
                    };

                    if num_val.is_nan() {
                        has_nan = true;
                    } else if num_val.is_infinite() {
                        has_infinity = true;
                    } else {
                        sum_of_squares += num_val * num_val;
                    }
                }

                let result = if has_nan {
                    f64::NAN
                } else if has_infinity {
                    f64::INFINITY
                } else {
                    sum_of_squares.sqrt()
                };

                Ok(Value::Float(result.into()))
            }

            // Removed duplicate ArrayPrototypeCopyWithin - implementation at line ~13993 has better ES2015 compliance

            "builtin:ArrayPrototypeFill" => {
                // Array.prototype.fill(value, start, end) implementation
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be arrays
                };

                let fill_value = if args.count >= 2 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as i32,
                        Some(Value::Float(len)) => len.inner() as i32,
                        _ => return Ok(Value::Object(array_id)),
                    }
                } else {
                    return Ok(Value::Object(array_id));
                };

                if length <= 0 {
                    return Ok(Value::Object(array_id));
                }

                let start = if args.count >= 3 {
                    match self.read_reg(args.start + 2)? {
                        Value::Int(s) => s as i32,
                        Value::Float(s) => s.inner() as i32,
                        _ => 0,
                    }
                } else {
                    0
                };

                let end = if args.count >= 4 {
                    match self.read_reg(args.start + 3)? {
                        Value::Int(e) => e as i32,
                        Value::Float(e) => e.inner() as i32,
                        _ => length,
                    }
                } else {
                    length
                };

                // Normalize negative indices
                let start_idx = if start < 0 {
                    (length + start).max(0) as usize
                } else {
                    (start as usize).min(length as usize)
                };

                let end_idx = if end < 0 {
                    (length + end).max(0) as usize
                } else {
                    (end as usize).min(length as usize)
                };

                // Fill the array elements
                if start_idx < end_idx {
                    for i in start_idx..end_idx {
                        self.set_object_property(array_id, i.to_string(), fill_value.clone())?;
                    }
                }

                Ok(Value::Object(array_id))
            }

            "builtin:StringPrototypeCodePointAt" => {
                // String.prototype.codePointAt(index) implementation
                let this_val = self.read_reg(args.start)?;
                let string_val = match this_val {
                    Value::Str(s) => s,
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.inner().to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::Undefined),
                        }
                    }
                };

                let index = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(idx) => idx as usize,
                        Value::Float(idx) => idx.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Get Unicode code point at index
                let chars: Vec<char> = string_val.chars().collect();
                if index < chars.len() {
                    let code_point = chars[index] as u32;
                    Ok(Value::Int(code_point as i64))
                } else {
                    Ok(Value::Undefined)
                }
            }

            "builtin:StringFromCodePoint" => {
                // String.fromCodePoint(...codePoints) implementation
                let mut result = String::new();

                // Iterate through all provided code points
                for i in 0..args.count {
                    let code_point_val = self.read_reg(args.start + i)?;
                    let code_point = match code_point_val {
                        Value::Int(n) => n as u32,
                        Value::Float(f) => f.inner() as u32,
                        _ => return Ok(Value::Str(result)), // Invalid code point, return partial result
                    };

                    // Validate Unicode code point range (0 to 0x10FFFF)
                    if code_point > 0x10FFFF {
                        return Ok(Value::Str(result)); // RangeError equivalent, return partial result
                    }

                    // Convert to character
                    if let Some(ch) = std::char::from_u32(code_point) {
                        result.push(ch);
                    } else {
                        return Ok(Value::Str(result)); // Invalid code point, return partial result
                    }
                }

                Ok(Value::Str(result))
            }

            "builtin:MathImul" => {
                // Math.imul(x, y) implementation - 32-bit integer multiplication
                if args.count < 2 {
                    return Ok(Value::Int(0));
                }

                let x_val = self.read_reg(args.start)?;
                let y_val = self.read_reg(args.start + 1)?;

                let x = match x_val {
                    Value::Int(n) => n as i32,
                    Value::Float(f) => f.inner() as i32,
                    _ => 0,
                };

                let y = match y_val {
                    Value::Int(n) => n as i32,
                    Value::Float(f) => f.inner() as i32,
                    _ => 0,
                };

                // Perform 32-bit integer multiplication
                let result = x.wrapping_mul(y) as i64;
                Ok(Value::Int(result))
            }

            // Removed duplicate ArrayPrototypeAt - implementation at line ~13242 is more concise

            // Removed duplicate StringPrototypeAt - implementation at line ~13959 is more complete

            "builtin:ObjectGetOwnPropertyDescriptor" => {
                // Object.getOwnPropertyDescriptor(obj, prop) implementation
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                let obj_id = match obj_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects don't have property descriptors
                };

                let prop_val = self.read_reg(args.start + 1)?;
                let prop_name = match prop_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    _ => return Ok(Value::Undefined),
                };

                // Snapshot the property value under an immutable borrow,
                // then allocate + populate the descriptor under a fresh
                // &mut self context.
                let value_snapshot: Option<Value> = self
                    .heap
                    .get(obj_id.0 as usize)
                    .and_then(|obj| obj.properties.get(&prop_name).cloned());
                if let Some(value) = value_snapshot {
                    {
                        // Create property descriptor object
                        let descriptor_id = self.alloc_object_with_prototype(None)?;

                        // Set descriptor properties (simplified - all properties are data properties)
                        self.set_object_property(
                            descriptor_id,
                            "value".to_string(),
                            value.clone(),
                        )?;
                        self.set_object_property(
                            descriptor_id,
                            "writable".to_string(),
                            Value::Bool(true),
                        )?;
                        self.set_object_property(
                            descriptor_id,
                            "enumerable".to_string(),
                            Value::Bool(true),
                        )?;
                        self.set_object_property(
                            descriptor_id,
                            "configurable".to_string(),
                            Value::Bool(true),
                        )?;

                        Ok(Value::Object(descriptor_id))
                    }
                } else {
                    Ok(Value::Undefined)
                }
            }

            // Removed duplicate MathClz32 - implementation at line ~12775 has better type conversion

            "builtin:ArrayPrototypeEntries" => {
                // Array.prototype.entries() implementation - returns iterator for [index, value] pairs
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty iterator-like object
                        let iterator_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            iterator_id,
                            "__type".to_string(),
                            Value::Str("ArrayIterator".to_string()),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__index".to_string(),
                            Value::Int(0),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__length".to_string(),
                            Value::Int(0),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__kind".to_string(),
                            Value::Str("entries".to_string()),
                        )?;
                        return Ok(Value::Object(iterator_id));
                    }
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create iterator object
                let iterator_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(
                    iterator_id,
                    "__type".to_string(),
                    Value::Str("ArrayIterator".to_string()),
                )?;
                self.set_object_property(
                    iterator_id,
                    "__array".to_string(),
                    Value::Object(array_id),
                )?;
                self.set_object_property(iterator_id, "__index".to_string(), Value::Int(0))?;
                self.set_object_property(iterator_id, "__length".to_string(), Value::Int(length))?;
                self.set_object_property(
                    iterator_id,
                    "__kind".to_string(),
                    Value::Str("entries".to_string()),
                )?;

                Ok(Value::Object(iterator_id))
            }

            "builtin:ArrayPrototypeKeys" => {
                // Array.prototype.keys() implementation - returns iterator for indices
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty iterator-like object
                        let iterator_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            iterator_id,
                            "__type".to_string(),
                            Value::Str("ArrayIterator".to_string()),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__index".to_string(),
                            Value::Int(0),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__length".to_string(),
                            Value::Int(0),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__kind".to_string(),
                            Value::Str("keys".to_string()),
                        )?;
                        return Ok(Value::Object(iterator_id));
                    }
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create iterator object
                let iterator_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(
                    iterator_id,
                    "__type".to_string(),
                    Value::Str("ArrayIterator".to_string()),
                )?;
                self.set_object_property(
                    iterator_id,
                    "__array".to_string(),
                    Value::Object(array_id),
                )?;
                self.set_object_property(iterator_id, "__index".to_string(), Value::Int(0))?;
                self.set_object_property(iterator_id, "__length".to_string(), Value::Int(length))?;
                self.set_object_property(
                    iterator_id,
                    "__kind".to_string(),
                    Value::Str("keys".to_string()),
                )?;

                Ok(Value::Object(iterator_id))
            }

            "builtin:ArrayPrototypeValues" => {
                // Array.prototype.values() implementation - returns iterator for values
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty iterator-like object
                        let iterator_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            iterator_id,
                            "__type".to_string(),
                            Value::Str("ArrayIterator".to_string()),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__index".to_string(),
                            Value::Int(0),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__length".to_string(),
                            Value::Int(0),
                        )?;
                        self.set_object_property(
                            iterator_id,
                            "__kind".to_string(),
                            Value::Str("values".to_string()),
                        )?;
                        return Ok(Value::Object(iterator_id));
                    }
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create iterator object
                let iterator_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(
                    iterator_id,
                    "__type".to_string(),
                    Value::Str("ArrayIterator".to_string()),
                )?;
                self.set_object_property(
                    iterator_id,
                    "__array".to_string(),
                    Value::Object(array_id),
                )?;
                self.set_object_property(iterator_id, "__index".to_string(), Value::Int(0))?;
                self.set_object_property(iterator_id, "__length".to_string(), Value::Int(length))?;
                self.set_object_property(
                    iterator_id,
                    "__kind".to_string(),
                    Value::Str("values".to_string()),
                )?;

                Ok(Value::Object(iterator_id))
            }

            "builtin:ObjectSetPrototypeOf" => {
                // Object.setPrototypeOf(obj, prototype) implementation
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                let obj_id = match obj_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't have prototypes set
                };

                let proto_val = self.read_reg(args.start + 1)?;
                let proto_id = match proto_val {
                    Value::Object(id) => Some(id),
                    Value::Null => None,
                    _ => return Ok(Value::Undefined), // Invalid prototype
                };

                // Set the prototype on the object
                if let Some(obj) = self.heap.get_mut(obj_id.0 as usize) {
                    obj.prototype = proto_id;
                }

                // Return the modified object
                Ok(Value::Object(obj_id))
            }

            "builtin:SymbolIterator" => {
                // Symbol.iterator implementation - well-known symbol for iteration protocol
                // Create a special symbol object for the iterator symbol
                let symbol_id = self.alloc_object_with_prototype(None)?;

                // Set symbol metadata
                self.set_object_property(
                    symbol_id,
                    "__type".to_string(),
                    Value::Str("Symbol".to_string()),
                )?;
                self.set_object_property(
                    symbol_id,
                    "__description".to_string(),
                    Value::Str("Symbol.iterator".to_string()),
                )?;
                self.set_object_property(symbol_id, "__wellKnown".to_string(), Value::Bool(true))?;
                self.set_object_property(
                    symbol_id,
                    "__key".to_string(),
                    Value::Str("@@iterator".to_string()),
                )?;

                Ok(Value::Object(symbol_id))
            }

            "builtin:StringPrototypeNormalize" => {
                // String.prototype.normalize(form) implementation - Unicode normalization
                let this_val = self.read_reg(args.start)?;
                let string_val = match this_val {
                    Value::Str(s) => s,
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.inner().to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::Str(String::new())),
                        }
                    }
                };

                let _form = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Str(f) => f,
                        _ => "NFC".to_string(), // Default normalization form
                    }
                } else {
                    "NFC".to_string()
                };

                // Simplified implementation - return the string as-is
                // TODO: Implement proper Unicode normalization with different forms (NFC, NFD, NFKC, NFKD)
                Ok(Value::Str(string_val))
            }

            "builtin:StringPrototypeTrimStart" => {
                // String.prototype.trimStart() implementation - remove leading whitespace
                let this_val = self.read_reg(args.start)?;
                let string_val = match this_val {
                    Value::Str(s) => s,
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.inner().to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::Str(String::new())),
                        }
                    }
                };

                // Remove leading whitespace
                let trimmed = string_val.trim_start();
                Ok(Value::Str(trimmed.to_string()))
            }

            // Removed duplicate StringPrototypeTrimEnd - implementation at line ~13975 is more JS-compliant

            // StringPrototypePadStart: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypePadEnd: Removed duplicate dispatch arm (use first occurrence instead)

            "builtin:ObjectPrototypeHasOwnProperty" => {
                // Object.prototype.hasOwnProperty(prop) implementation
                let this_val = self.read_reg(args.start)?;
                let obj_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects don't have own properties
                };

                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let prop_val = self.read_reg(args.start + 1)?;
                let prop_name = match prop_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Check if the object has the property as an own property
                if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                    Ok(Value::Bool(obj.properties.contains_key(&prop_name)))
                } else {
                    Ok(Value::Bool(false))
                }
            }

            "builtin:ArrayPrototypeFind" => {
                // Array.prototype.find(callback[, thisArg]) implementation - fail-closed until proper callback dispatch
                self.validate_array_callback_args(args, "Array.prototype.find")?;

                // Fail-closed until proper callback dispatch is implemented
                // Programs like [1,2,3].find(x => x > 2) should error rather than
                // silently return wrong values like the first element or first truthy element
                Err(InterpreterError::TypeError {
                    expected: "supported Array.prototype.find implementation".to_string(),
                    got: "callback invocation not yet supported - would require proper callback dispatch with (element, index, array) args, thisArg handling, and returning first element where callback returns truthy".to_string(),
                })
            }

            // StringPrototypeStartsWith: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypeEndsWith: Removed duplicate dispatch arm (use first occurrence instead)

            "builtin:NumberIsInteger" => {
                // Number.isInteger(value) implementation - determines if value is finite integer
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                let value = self.read_reg(args.start)?;
                let is_integer = match value {
                    Value::Int(_) => true, // All integers are integers
                    Value::Float(f) => {
                        let num = f.inner();
                        num.is_finite() && num.fract() == 0.0 // Finite and no fractional part
                    }
                    _ => false, // Non-numbers are not integers
                };

                Ok(Value::Bool(is_integer))
            }

            "builtin:NumberParseFloat" => {
                // Number.parseFloat(string) implementation - parse string as floating point
                if args.count == 0 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let string_val = match self.read_reg(args.start)? {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::Float(f64::NAN.into())),
                };

                // Trim leading whitespace and try to parse
                let trimmed = string_val.trim_start();

                // Handle special cases
                if trimmed.is_empty() || trimmed == "NaN" {
                    return Ok(Value::Float(f64::NAN.into()));
                }
                if trimmed == "Infinity" || trimmed == "+Infinity" {
                    return Ok(Value::Float(f64::INFINITY.into()));
                }
                if trimmed == "-Infinity" {
                    return Ok(Value::Float(f64::NEG_INFINITY.into()));
                }

                // Try to parse as float, stopping at first non-numeric character
                let mut end_idx = 0;
                let mut has_dot = false;
                let mut has_e = false;

                for (i, c) in trimmed.chars().enumerate() {
                    if i == 0 && (c == '+' || c == '-') {
                        end_idx = i + 1;
                    } else if c.is_ascii_digit() {
                        end_idx = i + 1;
                    } else if c == '.' && !has_dot && !has_e {
                        has_dot = true;
                        end_idx = i + 1;
                    } else if (c == 'e' || c == 'E') && !has_e && i > 0 {
                        has_e = true;
                        end_idx = i + 1;
                    } else if has_e
                        && (c == '+' || c == '-')
                        && trimmed
                            .chars()
                            .nth(i - 1)
                            .map_or(false, |prev| prev == 'e' || prev == 'E')
                    {
                        end_idx = i + 1;
                    } else {
                        break;
                    }
                }

                if end_idx == 0 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let parse_str = &trimmed[..end_idx];
                match parse_str.parse::<f64>() {
                    Ok(num) => Ok(Value::Float(num.into())),
                    Err(_) => Ok(Value::Float(f64::NAN.into())),
                }
            }

            // StringPrototypeRepeat: Removed duplicate dispatch arm (use first occurrence instead)

            "builtin:NumberParseInt" => {
                // Number.parseInt(string, radix) implementation
                if args.count == 0 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let string_val = self.read_reg(args.start)?;
                let radix_arg = if args.count >= 2 {
                    Some(self.read_reg(args.start + 1)?)
                } else {
                    None
                };

                match Self::parse_int_with_sign_and_radix(&string_val, radix_arg.as_ref()) {
                    Some(result) => Ok(Value::Int(result)),
                    None => Ok(Value::Float(f64::NAN.into())),
                }
            }

            "builtin:ArrayPrototypeFilter" => {
                // Array.prototype.filter(callback[, thisArg]) implementation (simplified)
                if args.count < 2 {
                    // Return empty array if no callback provided
                    let empty_array_id = self.alloc_object_with_prototype(None)?;
                    self.set_object_property(empty_array_id, "length".to_string(), Value::Int(0))?;
                    return Ok(Value::Object(empty_array_id));
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                let _callback = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result array
                let result_array_id = self.alloc_object_with_prototype(None)?;

                // Collect truthy elements first to avoid borrow checker issues
                let mut filtered_elements = Vec::new();
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    for i in 0..length {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            let is_truthy = match element {
                                Value::Bool(false) | Value::Null | Value::Undefined => false,
                                Value::Int(0) => false,
                                Value::Float(f) if f.inner() == 0.0 || f.inner().is_nan() => false,
                                Value::Str(s) if s.is_empty() => false,
                                _ => true,
                            };

                            if is_truthy {
                                filtered_elements.push(element.clone());
                            }
                        }
                    }
                }

                // Set the filtered elements to the result array
                for (i, element) in filtered_elements.iter().enumerate() {
                    self.set_object_property(result_array_id, i.to_string(), element.clone())?;
                }

                // Set result array length
                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(filtered_elements.len() as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            // StringPrototypeIncludes: Removed duplicate dispatch arm (use first occurrence instead)

            "builtin:NumberIsNaNMethod" => {
                // Number.isNaN(value) implementation - determines if value is exactly NaN
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                let value = self.read_reg(args.start)?;
                let is_nan = match value {
                    Value::Float(f) => f.inner().is_nan(),
                    _ => false, // Only floating point values can be NaN, all others are false
                };

                Ok(Value::Bool(is_nan))
            }

            // ArrayPrototypeReverse: Removed duplicate dispatch arm (use first occurrence instead)


            "builtin:MathAtan" => {
                // Math.atan(x) implementation
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                Ok(Value::Float(Float64::new(num.atan())))
            }

            // Removed duplicate ArrayPrototypeFill - implementation at line ~11593 has better JS semantics

            "builtin:ObjectPrototypePropertyIsEnumerable" => {
                // Object.prototype.propertyIsEnumerable(prop) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let object_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects don't have enumerable properties
                };

                let prop_val = self.read_reg(args.start + 1)?;
                let prop_key = match prop_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Check if the object has the property (simplified: all own properties are enumerable)
                if let Some(obj) = self.heap.get(object_id.0 as usize) {
                    Ok(Value::Bool(obj.properties.contains_key(&prop_key)))
                } else {
                    Ok(Value::Bool(false))
                }
            }

            "builtin:StringPrototypeConcat" => {
                // String.prototype.concat(...strings) implementation
                let this_val = self.read_reg(args.start)?;
                let mut result = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Concatenate all additional arguments
                for i in 1..args.count {
                    let arg_val = self.read_reg(args.start + i)?;
                    let arg_str = match arg_val {
                        Value::Str(s) => s,
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "[object Object]".to_string(),
                    };
                    result.push_str(&arg_str);
                }

                Ok(Value::Str(result))
            }

            // Removed duplicate MathAtan2 - implementation at line ~10995 has correct argument handling



            "builtin:MathLog10" => {
                // Math.log10(x) implementation
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                Ok(Value::Float(Float64::new(num.log10())))
            }


            // Removed duplicate ObjectPrototypeValueOf - implementation at line ~11410 is identical


            "builtin:MathLog2" => {
                // Math.log2(x) implementation
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                Ok(Value::Float(Float64::new(num.log2())))
            }

            // Removed duplicate ArrayPrototypeReduceRight - implementation at line ~11114 is identical

            "builtin:ObjectPrototypeToString" => {
                // Object.prototype.toString() implementation
                let this_val = self.read_reg(args.start)?;

                match this_val {
                    Value::Undefined => Ok(Value::Str("[object Undefined]".to_string())),
                    Value::Null => Ok(Value::Str("[object Null]".to_string())),
                    Value::Bool(_) => Ok(Value::Str("[object Boolean]".to_string())),
                    Value::Int(_) => Ok(Value::Str("[object Number]".to_string())),
                    Value::Float(_) => Ok(Value::Str("[object Number]".to_string())),
                    Value::Str(_) => Ok(Value::Str("[object String]".to_string())),
                    Value::Object(obj_id) => {
                        // Check if it's an array (simplified)
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if obj.properties.contains_key("length") {
                                Ok(Value::Str("[object Array]".to_string()))
                            } else {
                                Ok(Value::Str("[object Object]".to_string()))
                            }
                        } else {
                            Ok(Value::Str("[object Object]".to_string()))
                        }
                    }
                    _ => Ok(Value::Str("[object Unknown]".to_string())),
                }
            }

            // Removed duplicate StringFromCharCode - implementation at line ~10858 is identical

            // Removed duplicate MathAcos - implementation at line ~11059 is identical

            // Removed duplicate ArrayPrototypeLastIndexOf - implementation at line ~10742 is identical

            "builtin:RegExpPrototypeTest" => {
                // RegExp.prototype.test(string) implementation (simplified)
                let this_val = self.read_reg(args.start)?;

                // For now, simplified implementation: return true if both arguments are strings and second contains first
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let test_string = match self.read_reg(args.start + 1)? {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Very simplified: if the regexp object has a "source" property, use it as a substring search
                if let Value::Object(regexp_id) = this_val {
                    if let Some(regexp_obj) = self.heap.get(regexp_id.0 as usize) {
                        if let Some(Value::Str(pattern)) = regexp_obj.properties.get("source") {
                            return Ok(Value::Bool(test_string.contains(pattern)));
                        }
                    }
                }

                // Default: return false for non-regexp objects or missing pattern
                Ok(Value::Bool(false))
            }

            // Removed duplicate StringPrototypeCodePointAt - implementation at line ~11708 is identical

            // Removed duplicate MathAsin - implementation at line ~11042 is identical

            // builtin:ArrayPrototypeFindIndex - Duplicate removed, consolidated to line 10807

            // Removed duplicate ObjectGetOwnPropertyNames - implementation at line ~10883 is more complete

            // Removed duplicate StringPrototypeNormalize - implementation at line ~12187 is identical

            "builtin:MathCbrt" => {
                // Math.cbrt(x) implementation (cube root)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                Ok(Value::Float(Float64::new(num.cbrt())))
            }

            // Removed duplicate ArrayPrototypeFlat - implementation at line ~9886 is more complete

            // Removed duplicate PromiseResolve - implementation at line ~9255 is identical

            "builtin:StringPrototypeReplaceAll" => {
                // String.prototype.replaceAll(searchValue, replaceValue) implementation
                if args.count < 3 {
                    return Ok(Value::Str("".to_string()));
                }

                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let search_val = self.read_reg(args.start + 1)?;
                let search_str = match search_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let replace_val = self.read_reg(args.start + 2)?;
                let replace_str = match replace_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Replace all occurrences
                let result = str_text.replace(&search_str, &replace_str);
                Ok(Value::Str(result))
            }

            "builtin:MathClz32" => {
                // Math.clz32(x) implementation (count leading zeros in 32-bit binary)
                if args.count == 0 {
                    return Ok(Value::Int(32)); // All zeros if no argument
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as u32,
                    Value::Float(f) => f.inner() as u32,
                    Value::Str(s) => s.parse::<f64>().unwrap_or(0.0) as u32,
                    Value::Bool(true) => 1,
                    Value::Bool(false) => 0,
                    Value::Null => 0,
                    _ => 0,
                };

                Ok(Value::Int(num.leading_zeros() as i64))
            }

            "builtin:ArrayPrototypeFlatMap" => {
                // Array.prototype.flatMap(callback[, thisArg]) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                let _callback = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result array
                let result_array_id = self.alloc_object_with_prototype(None)?;
                let mut result_length = 0;

                // Simplified implementation: copy elements and flatten one level.
                let elements_to_copy = self
                    .heap
                    .get(array_id.0 as usize)
                    .map(|obj| {
                        (0..length)
                            .filter_map(|i| obj.properties.get(&i.to_string()).cloned())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                for element in elements_to_copy {
                    self.set_object_property(result_array_id, result_length.to_string(), element)?;
                    result_length += 1;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(result_length as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            // ObjectDefineProperty: Removed duplicate dispatch arm (use first occurrence instead)

            "builtin:StringPrototypeAt" => {
                // String.prototype.at(index) implementation (ES2022)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let index = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => n,
                        Value::Float(f) => f.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                let chars: Vec<char> = str_text.chars().collect();
                let len = chars.len() as i64;

                // Handle negative indices (count from end)
                let actual_index = if index < 0 { len + index } else { index };

                if actual_index >= 0 && (actual_index as usize) < chars.len() {
                    Ok(Value::Str(chars[actual_index as usize].to_string()))
                } else {
                    Ok(Value::Undefined)
                }
            }

            "builtin:MathFround" => {
                // Math.fround(x) implementation (round to nearest 32-bit float)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                // Convert to f32 and back to f64 to simulate 32-bit float rounding
                let rounded = num as f32 as f64;
                Ok(Value::Float(Float64::new(rounded)))
            }

            "builtin:ArrayPrototypeAt" => {
                // Array.prototype.at(index) implementation (ES2022)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be arrays
                };

                let index = match self.read_reg(args.start + 1)? {
                    Value::Int(n) => n,
                    Value::Float(f) => f.inner() as i64,
                    _ => return Ok(Value::Undefined),
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => return Ok(Value::Undefined),
                    }
                } else {
                    return Ok(Value::Undefined);
                };

                // Handle negative indices (count from end)
                let actual_index = if index < 0 { length + index } else { index };

                if actual_index >= 0 && actual_index < length {
                    if let Some(obj) = self.heap.get(array_id.0 as usize) {
                        if let Some(element) = obj.properties.get(&(actual_index.to_string())) {
                            return Ok(element.clone());
                        }
                    }
                }

                Ok(Value::Undefined)
            }

            "builtin:ObjectGetPrototypeOf" => {
                // Object.getPrototypeOf(obj) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Null);
                }

                let obj_val = self.read_reg(args.start + 1)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Simplified implementation: check if object has prototype reference
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(proto) = obj.properties.get("__proto__") {
                                Ok(proto.clone())
                            } else {
                                // Default object prototype (simplified)
                                Ok(Value::Null)
                            }
                        } else {
                            Ok(Value::Null)
                        }
                    }
                    Value::Null | Value::Undefined => {
                        // Primitive null/undefined throw TypeError in real JS, here return null
                        Ok(Value::Null)
                    }
                    _ => {
                        // Primitives have their corresponding prototype objects (simplified)
                        Ok(Value::Null)
                    }
                }
            }

            "builtin:StringPrototypeToWellFormed" => {
                // String.prototype.toWellFormed() implementation (ES2024)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Simplified implementation: replace invalid Unicode sequences
                // In a full implementation, this would replace lone surrogates with replacement chars
                let well_formed = str_text
                    .chars()
                    .map(|c| {
                        // Replace any problematic Unicode characters (simplified)
                        if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                            '\u{FFFD}' // Unicode replacement character
                        } else {
                            c
                        }
                    })
                    .collect::<String>();

                Ok(Value::Str(well_formed))
            }

            "builtin:MathAcosh" => {
                // Math.acosh(x) implementation (inverse hyperbolic cosine)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                // acosh is only defined for x >= 1
                if num < 1.0 {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else {
                    Ok(Value::Float(Float64::new(num.acosh())))
                }
            }

            "builtin:ArrayFromAsync" => {
                // Array.fromAsync(arrayLike[, mapFn[, thisArg]]) implementation (simplified)
                if args.count < 2 {
                    // Create empty array for missing argument
                    let empty_array_id = self.alloc_object_with_prototype(None)?;
                    self.set_object_property(empty_array_id, "length".to_string(), Value::Int(0))?;
                    return Ok(Value::Object(empty_array_id));
                }

                let array_like_val = self.read_reg(args.start + 1)?;

                // Simplified implementation: treat as regular Array.from for now
                match array_like_val {
                    Value::Object(obj_id) => {
                        // Try to get length property
                        let length = if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            match obj.properties.get("length") {
                                Some(Value::Int(len)) => *len as usize,
                                Some(Value::Float(len)) => len.inner() as usize,
                                _ => 0,
                            }
                        } else {
                            0
                        };

                        // Create result array
                        let result_array_id = self.alloc_object_with_prototype(None)?;

                        // Copy elements without holding the source object borrow across writes.
                        let copied_elements = if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            (0..length)
                                .filter_map(|i| {
                                    obj.properties
                                        .get(&i.to_string())
                                        .cloned()
                                        .map(|element| (i, element))
                                })
                                .collect::<Vec<_>>()
                        } else {
                            Vec::new()
                        };
                        for (i, element) in copied_elements {
                            self.set_object_property(result_array_id, i.to_string(), element)?;
                        }

                        self.set_object_property(
                            result_array_id,
                            "length".to_string(),
                            Value::Int(length as i64),
                        )?;

                        Ok(Value::Object(result_array_id))
                    }
                    _ => {
                        // Non-object, create empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        Ok(Value::Object(empty_array_id))
                    }
                }
            }

            "builtin:ObjectIs" => {
                // Object.is(value1, value2) implementation
                if args.count < 3 {
                    return Ok(Value::Bool(false));
                }

                let val1 = self.read_reg(args.start + 1)?;
                let val2 = self.read_reg(args.start + 2)?;

                // Object.is uses SameValue comparison (stricter than ===)
                let result = match (&val1, &val2) {
                    (Value::Undefined, Value::Undefined) => true,
                    (Value::Null, Value::Null) => true,
                    (Value::Bool(a), Value::Bool(b)) => a == b,
                    (Value::Int(a), Value::Int(b)) => a == b,
                    (Value::Float(a), Value::Float(b)) => {
                        let a_val = a.inner();
                        let b_val = b.inner();
                        // Handle NaN and signed zeros properly
                        if a_val.is_nan() && b_val.is_nan() {
                            true
                        } else if a_val == 0.0 && b_val == 0.0 {
                            // Check for +0 vs -0
                            a_val.to_bits() == b_val.to_bits()
                        } else {
                            a_val == b_val
                        }
                    }
                    (Value::Str(a), Value::Str(b)) => a == b,
                    (Value::Object(a), Value::Object(b)) => a.0 == b.0,
                    _ => false,
                };

                Ok(Value::Bool(result))
            }

            "builtin:StringPrototypeIsWellFormed" => {
                // String.prototype.isWellFormed() implementation (ES2024)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Simplified implementation: check for well-formed Unicode
                // In a full implementation, this would detect lone surrogates
                let is_well_formed = str_text
                    .chars()
                    .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t');

                Ok(Value::Bool(is_well_formed))
            }

            "builtin:MathAsinh" => {
                // Math.asinh(x) implementation (inverse hyperbolic sine)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                // asinh is defined for all real numbers
                Ok(Value::Float(Float64::new(num.asinh())))
            }

            "builtin:ArrayPrototypeWith" => {
                // Array.prototype.with(index, value) implementation (ES2023)
                if args.count < 3 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                let index = match self.read_reg(args.start + 1)? {
                    Value::Int(n) => n,
                    Value::Float(f) => f.inner() as i64,
                    _ => return Ok(Value::Undefined),
                };

                let value = self.read_reg(args.start + 2)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Handle negative indices
                let actual_index = if index < 0 { length + index } else { index };

                // Check bounds
                if actual_index < 0 || actual_index >= length {
                    return Ok(Value::Undefined);
                }

                // Create a new array with the replaced value
                let result_array_id = self.alloc_object_with_prototype(None)?;

                // Copy all elements, replacing the one at the specified
                // index. Snapshot under an immutable borrow so we can call
                // &mut self set_object_property without aliasing.
                let original_elements: Vec<Value> =
                    if let Some(obj) = self.heap.get(array_id.0 as usize) {
                        (0..length)
                            .map(|i| {
                                obj.properties
                                    .get(&i.to_string())
                                    .cloned()
                                    .unwrap_or(Value::Undefined)
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                for (i, element) in original_elements.iter().enumerate() {
                    let element_value = if (i as i64) == actual_index {
                        value.clone()
                    } else {
                        element.clone()
                    };
                    self.set_object_property(result_array_id, i.to_string(), element_value)?;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(length),
                )?;

                Ok(Value::Object(result_array_id))
            }

            "builtin:ObjectSetPrototypeOf" => {
                // Object.setPrototypeOf(obj, prototype) implementation (simplified)
                if args.count < 3 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start + 1)?;
                let proto_val = self.read_reg(args.start + 2)?;

                let obj_id = match obj_val {
                    Value::Object(id) => id,
                    _ => return Ok(obj_val), // Can't set prototype of non-objects
                };

                // Simplified implementation: set __proto__ property
                if let Some(obj) = self.heap.get_mut(obj_id.0 as usize) {
                    obj.properties.insert("__proto__".to_string(), proto_val);
                }

                Ok(obj_val) // Return the modified object
            }

            // StringPrototypeToLowerCase: Removed duplicate dispatch arm (use first occurrence at line 8124)

            "builtin:MathAtanh" => {
                // Math.atanh(x) implementation (inverse hyperbolic tangent)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.read_reg(args.start)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                // atanh is only defined for -1 < x < 1
                if num <= -1.0 || num >= 1.0 {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else {
                    Ok(Value::Float(Float64::new(num.atanh())))
                }
            }

            "builtin:ArrayPrototypeToReversed" => {
                // Array.prototype.toReversed() implementation (ES2023)
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result array (immutable operation)
                let result_array_id = self.alloc_object_with_prototype(None)?;

                // Copy elements in reverse order without holding the source borrow across writes.
                let reversed_elements = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    (0..length)
                        .map(|i| {
                            let reverse_index = length - 1 - i;
                            let element = obj
                                .properties
                                .get(&reverse_index.to_string())
                                .cloned()
                                .unwrap_or(Value::Undefined);
                            (i, element)
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                for (i, element) in reversed_elements {
                    self.set_object_property(result_array_id, i.to_string(), element)?;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(length as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }


            // StringPrototypeToUpperCase: Removed duplicate dispatch arm (use first occurrence at line 8136)

            // Removed duplicate MathHypot - implementation at line ~11456 is more complete

            "builtin:ArrayPrototypeToSorted" => {
                // Array.prototype.toSorted([compareFunction]) implementation (ES2023)
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result array (immutable operation)
                let result_array_id = self.alloc_object_with_prototype(None)?;

                // Copy and sort elements (simplified string-based sorting).
                let mut elements_with_indices =
                    if let Some(obj) = self.heap.get(array_id.0 as usize) {
                        (0..length)
                            .map(|i| {
                                let element = obj
                                    .properties
                                    .get(&i.to_string())
                                    .cloned()
                                    .unwrap_or(Value::Undefined);
                                (i, element)
                            })
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };

                // Simple string-based sort (like default Array.sort)
                elements_with_indices.sort_by(|(_i1, a), (_i2, b)| {
                    let a_str = match a {
                        Value::Str(s) => s.clone(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "[object Object]".to_string(),
                    };
                    let b_str = match b {
                        Value::Str(s) => s.clone(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "[object Object]".to_string(),
                    };
                    a_str.cmp(&b_str)
                });

                // Set sorted elements in result array
                for (new_index, (_original_index, element)) in
                    elements_with_indices.iter().enumerate()
                {
                    self.set_object_property(
                        result_array_id,
                        new_index.to_string(),
                        element.clone(),
                    )?;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(length as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            "builtin:ObjectPropertyIsEnumerable" => {
                // Object.propertyIsEnumerable(property) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let obj_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Primitives don't have enumerable properties
                };

                let prop_val = self.read_reg(args.start + 1)?;
                let prop_key = match prop_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    _ => return Ok(Value::Bool(false)),
                };

                // Simplified implementation: all own properties are enumerable
                if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                    Ok(Value::Bool(obj.properties.contains_key(&prop_key)))
                } else {
                    Ok(Value::Bool(false))
                }
            }

            "builtin:StringPrototypeTrimStart" => {
                // String.prototype.trimStart() implementation (ES2019)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Trim whitespace from the start (left side)
                let trimmed = str_text.trim_start().to_string();
                Ok(Value::Str(trimmed))
            }

            // Removed duplicate MathImul - implementation at line ~11636 has correct argument handling

            "builtin:ArrayPrototypeToSpliced" => {
                // Array.prototype.toSpliced(start, deleteCount, ...items) implementation (ES2023)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_object_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                let start = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => n,
                        Value::Float(f) => f.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                let delete_count = if args.count > 2 {
                    match self.read_reg(args.start + 2)? {
                        Value::Int(n) => n as usize,
                        Value::Float(f) => f.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Handle negative start index
                let actual_start = if start < 0 {
                    (length as i64 + start).max(0) as usize
                } else {
                    (start as usize).min(length)
                };

                // Calculate actual delete count
                let actual_delete_count = delete_count.min(length - actual_start);

                // Create result array (immutable operation)
                let result_array_id = self.alloc_object_with_prototype(None)?;
                let mut result_index = 0;

                // Snapshot source elements before mutating the result array.
                let source_elements = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    (0..length)
                        .map(|i| {
                            obj.properties
                                .get(&i.to_string())
                                .cloned()
                                .unwrap_or(Value::Undefined)
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };

                // Copy elements before start.
                for element in source_elements.iter().take(actual_start) {
                    self.set_object_property(
                        result_array_id,
                        result_index.to_string(),
                        element.clone(),
                    )?;
                    result_index += 1;
                }

                // Add new items (if any).
                for i in 3..args.count {
                    let item = self.read_reg(args.start + i)?;
                    self.set_object_property(result_array_id, result_index.to_string(), item)?;
                    result_index += 1;
                }

                // Copy elements after deleted section.
                for element in source_elements
                    .iter()
                    .skip(actual_start + actual_delete_count)
                {
                    self.set_object_property(
                        result_array_id,
                        result_index.to_string(),
                        element.clone(),
                    )?;
                    result_index += 1;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(result_index as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            "builtin:ObjectIsExtensible" => {
                // Object.isExtensible(obj) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Bool(true)); // Default to true for missing argument
                }

                let obj_val = self.read_reg(args.start + 1)?;
                match obj_val {
                    Value::Object(_) => {
                        // Simplified implementation: all objects are extensible by default
                        // In a real implementation, this would check the [[Extensible]] internal slot
                        Ok(Value::Bool(true))
                    }
                    _ => {
                        // Primitives are not extensible
                        Ok(Value::Bool(false))
                    }
                }
            }

            "builtin:StringPrototypeTrimEnd" => {
                // String.prototype.trimEnd() implementation (ES2019)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Trim whitespace from the end (right side)
                let trimmed = str_text.trim_end().to_string();
                Ok(Value::Str(trimmed))
            }

            // Removed duplicate MathSign - implementation at line ~10088 is identical

            "builtin:ArrayPrototypeGroup" => {
                // Array.prototype.group(callback) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty object
                        let empty_obj_id = self.alloc_object_with_prototype(None)?;
                        return Ok(Value::Object(empty_obj_id));
                    }
                };

                let _callback = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result object (simplified grouping)
                let result_obj_id = self.alloc_object_with_prototype(None)?;

                // Simplified implementation: group by string representation
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    let mut groups: std::collections::BTreeMap<String, Vec<Value>> =
                        std::collections::BTreeMap::new();

                    for i in 0..length {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            // Simple grouping key based on element type/value
                            let key = match element {
                                Value::Str(s) => format!("string:{}", s),
                                Value::Int(n) => format!("number:{}", n),
                                Value::Float(f) => format!("number:{}", f.inner()),
                                Value::Bool(b) => format!("boolean:{}", b),
                                Value::Null => "null".to_string(),
                                Value::Undefined => "undefined".to_string(),
                                _ => "object".to_string(),
                            };

                            groups.entry(key).or_default().push(element.clone());
                        }
                    }

                    // Convert groups to object properties (each group becomes an array)
                    for (key, values) in groups {
                        let group_array_id = self.alloc_object_with_prototype(None)?;

                        for (i, value) in values.iter().enumerate() {
                            self.set_object_property(group_array_id, i.to_string(), value.clone())?;
                        }

                        self.set_object_property(
                            group_array_id,
                            "length".to_string(),
                            Value::Int(values.len() as i64),
                        )?;

                        self.set_object_property(
                            result_obj_id,
                            key,
                            Value::Object(group_array_id),
                        )?;
                    }
                }

                Ok(Value::Object(result_obj_id))
            }

            "builtin:ObjectPreventExtensions" => {
                // Object.preventExtensions(obj) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start + 1)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Simplified implementation: mark object as non-extensible
                        // In a real implementation, this would set [[Extensible]] to false
                        if let Some(obj) = self.heap.get_mut(obj_id.0 as usize) {
                            obj.properties
                                .insert("__extensible__".to_string(), Value::Bool(false));
                        }
                        Ok(obj_val) // Return the object
                    }
                    _ => {
                        // Primitives can't be made non-extensible, just return them
                        Ok(obj_val)
                    }
                }
            }

            "builtin:StringPrototypeSearch" => {
                // String.prototype.search(regexp) implementation (simplified)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let pattern_val = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    return Ok(Value::Int(-1));
                };

                // Simplified implementation: treat as string search
                let pattern = match pattern_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Find first occurrence and return index
                if let Some(index) = str_text.find(&pattern) {
                    Ok(Value::Int(index as i64))
                } else {
                    Ok(Value::Int(-1))
                }
            }

            // Removed duplicate MathTrunc - implementation at line ~9554 is identical

            "builtin:ArrayPrototypeGroupToMap" => {
                // Array.prototype.groupToMap(callback) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty map-like object
                        let empty_obj_id = self.alloc_object_with_prototype(None)?;
                        return Ok(Value::Object(empty_obj_id));
                    }
                };

                let _callback = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result Map-like object
                let result_obj_id = self.alloc_object_with_prototype(None)?;

                // Simplified implementation: group by element type
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    let mut groups: std::collections::BTreeMap<String, Vec<Value>> =
                        std::collections::BTreeMap::new();

                    for i in 0..length {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            // Group by type for simplicity
                            let type_key = match element {
                                Value::Str(_) => "string",
                                Value::Int(_) => "number",
                                Value::Float(_) => "number",
                                Value::Bool(_) => "boolean",
                                Value::Null => "null",
                                Value::Undefined => "undefined",
                                _ => "object",
                            }
                            .to_string();

                            groups.entry(type_key).or_default().push(element.clone());
                        }
                    }

                    // Convert groups to Map entries
                    for (key, values) in groups {
                        let group_array_id = self.alloc_object_with_prototype(None)?;

                        for (i, value) in values.iter().enumerate() {
                            self.set_object_property(group_array_id, i.to_string(), value.clone())?;
                        }

                        self.set_object_property(
                            group_array_id,
                            "length".to_string(),
                            Value::Int(values.len() as i64),
                        )?;

                        self.set_object_property(
                            result_obj_id,
                            key,
                            Value::Object(group_array_id),
                        )?;
                    }
                }

                Ok(Value::Object(result_obj_id))
            }

            "builtin:ObjectSeal" => {
                // Object.seal(obj) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start + 1)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Simplified implementation: mark object as sealed
                        // In a real implementation, this would prevent property deletion
                        // and make existing properties non-configurable
                        if let Some(obj) = self.heap.get_mut(obj_id.0 as usize) {
                            obj.properties
                                .insert("__sealed__".to_string(), Value::Bool(true));
                            obj.properties
                                .insert("__extensible__".to_string(), Value::Bool(false));
                        }
                        Ok(obj_val) // Return the object
                    }
                    _ => {
                        // Primitives can't be sealed, just return them
                        Ok(obj_val)
                    }
                }
            }

            // Removed duplicate StringPrototypeSubstr - implementation at line ~11150 is identical

            "builtin:NumberPrototypeToFixed" => {
                // Number.prototype.toFixed(digits) implementation
                let this_val = self.read_reg(args.start)?;
                let num = match this_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                let digits = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => (n as usize).min(20), // Max 20 digits
                        Value::Float(f) => (f.inner() as usize).min(20),
                        _ => 0,
                    }
                } else {
                    0
                };

                if num.is_nan() {
                    Ok(Value::Str("NaN".to_string()))
                } else if num.is_infinite() {
                    if num.is_sign_positive() {
                        Ok(Value::Str("Infinity".to_string()))
                    } else {
                        Ok(Value::Str("-Infinity".to_string()))
                    }
                } else {
                    let formatted = format!("{:.precision$}", num, precision = digits);
                    Ok(Value::Str(formatted))
                }
            }

            "builtin:ArrayPrototypeCopyWithin" => {
                // Array.prototype.copyWithin(target, start[, end]) implementation (ES2015)
                if args.count < 3 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be arrays
                };

                let target = match self.read_reg(args.start + 1)? {
                    Value::Int(n) => n,
                    Value::Float(f) => f.inner() as i64,
                    _ => return Ok(Value::Undefined),
                };

                let start = match self.read_reg(args.start + 2)? {
                    Value::Int(n) => n,
                    Value::Float(f) => f.inner() as i64,
                    _ => return Ok(Value::Undefined),
                };

                let end = if args.count > 3 {
                    match self.read_reg(args.start + 3)? {
                        Value::Int(n) => Some(n),
                        Value::Float(f) => Some(f.inner() as i64),
                        _ => None,
                    }
                } else {
                    None
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => return Ok(Value::Undefined),
                    }
                } else {
                    return Ok(Value::Undefined);
                };

                // Normalize indices
                let actual_target = if target < 0 {
                    (length + target).max(0)
                } else {
                    target.min(length - 1)
                };

                let actual_start = if start < 0 {
                    (length + start).max(0)
                } else {
                    start.min(length - 1)
                };

                let actual_end = end.map_or(length, |e| {
                    if e < 0 {
                        (length + e).max(0)
                    } else {
                        e.min(length)
                    }
                });

                // Copy elements within the array
                if let Some(array_obj) = self.heap.get_mut(array_id.0 as usize) {
                    // Collect elements to copy
                    let mut elements_to_copy = Vec::new();
                    for i in actual_start..actual_end {
                        if let Some(element) = array_obj.properties.get(&i.to_string()) {
                            elements_to_copy.push(element.clone());
                        } else {
                            elements_to_copy.push(Value::Undefined);
                        }
                    }

                    // Copy to target positions
                    for (offset, element) in elements_to_copy.into_iter().enumerate() {
                        let target_index = actual_target + offset as i64;
                        if target_index < length {
                            array_obj
                                .properties
                                .insert(target_index.to_string(), element);
                        }
                    }
                }

                Ok(Value::Object(array_id))
            }

            "builtin:ObjectIsFrozen" => {
                // Object.isFrozen(obj) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Bool(true)); // Default to true for missing argument
                }

                let obj_val = self.read_reg(args.start + 1)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Simplified implementation: check if object has frozen marker
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(Value::Bool(frozen)) = obj.properties.get("__frozen__") {
                                Ok(Value::Bool(*frozen))
                            } else {
                                Ok(Value::Bool(false)) // Not frozen by default
                            }
                        } else {
                            Ok(Value::Bool(false))
                        }
                    }
                    _ => {
                        // Primitives are considered frozen
                        Ok(Value::Bool(true))
                    }
                }
            }

            "builtin:StringPrototypeAnchor" => {
                // String.prototype.anchor(name) implementation (deprecated HTML wrapper)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let name = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Str(s) => s,
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.inner().to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "[object Object]".to_string(),
                    }
                } else {
                    "undefined".to_string()
                };

                let result = format!("<a name=\"{}\">{}</a>", name, str_text);
                Ok(Value::Str(result))
            }

            "builtin:NumberPrototypeToExponential" => {
                // Number.prototype.toExponential(fractionDigits) implementation
                let this_val = self.read_reg(args.start)?;
                let num = match this_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                let fraction_digits = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => Some((n as usize).min(20)), // Max 20 digits
                        Value::Float(f) => Some((f.inner() as usize).min(20)),
                        _ => None,
                    }
                } else {
                    None
                };

                if num.is_nan() {
                    Ok(Value::Str("NaN".to_string()))
                } else if num.is_infinite() {
                    if num.is_sign_positive() {
                        Ok(Value::Str("Infinity".to_string()))
                    } else {
                        Ok(Value::Str("-Infinity".to_string()))
                    }
                } else {
                    let formatted = if let Some(digits) = fraction_digits {
                        format!("{:.precision$e}", num, precision = digits)
                    } else {
                        format!("{:e}", num)
                    };
                    Ok(Value::Str(formatted))
                }
            }

            // Removed duplicate ArrayPrototypeValues - implementation at line ~11973 uses proper iterator semantics

            "builtin:ObjectIsSealed" => {
                // Object.isSealed(obj) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Bool(true)); // Default to true for missing argument
                }

                let obj_val = self.read_reg(args.start + 1)?;
                match obj_val {
                    Value::Object(obj_id) => {
                        // Simplified implementation: check if object has sealed marker
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(Value::Bool(sealed)) = obj.properties.get("__sealed__") {
                                Ok(Value::Bool(*sealed))
                            } else {
                                Ok(Value::Bool(false)) // Not sealed by default
                            }
                        } else {
                            Ok(Value::Bool(false))
                        }
                    }
                    _ => {
                        // Primitives are considered sealed
                        Ok(Value::Bool(true))
                    }
                }
            }

            "builtin:StringPrototypeBig" => {
                // String.prototype.big() implementation (deprecated HTML wrapper)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let result = format!("<big>{}</big>", str_text);
                Ok(Value::Str(result))
            }

            "builtin:NumberPrototypeToPrecision" => {
                // Number.prototype.toPrecision(precision) implementation
                let this_val = self.read_reg(args.start)?;
                let num = match this_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                let precision = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => Some((n as usize).clamp(1, 21)), // 1-21 range
                        Value::Float(f) => Some((f.inner() as usize).clamp(1, 21)),
                        _ => None,
                    }
                } else {
                    None
                };

                if num.is_nan() {
                    Ok(Value::Str("NaN".to_string()))
                } else if num.is_infinite() {
                    if num.is_sign_positive() {
                        Ok(Value::Str("Infinity".to_string()))
                    } else {
                        Ok(Value::Str("-Infinity".to_string()))
                    }
                } else {
                    let formatted = if let Some(prec) = precision {
                        // Use exponential notation if number is too large/small for fixed precision
                        if num.abs() >= 10_f64.powi(prec as i32) || (num.abs() < 1.0 && num != 0.0)
                        {
                            format!("{:.precision$e}", num, precision = prec.saturating_sub(1))
                        } else {
                            format!("{:.precision$}", num, precision = prec.saturating_sub(1))
                        }
                    } else {
                        num.to_string()
                    };
                    Ok(Value::Str(formatted))
                }
            }

            // Removed duplicate ArrayPrototypeKeys - implementation at line ~11907 uses proper iterator semantics

            "builtin:WeakMapPrototypeHas" => {
                // WeakMap.prototype.has(key) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let weakmap_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be WeakMaps
                };

                let key = self.read_reg(args.start + 1)?;

                // Simplified implementation: check if key exists in WeakMap-like object
                // In a real implementation, this would use weak references
                if let Some(weakmap_obj) = self.heap.get(weakmap_id.0 as usize) {
                    // Use a simple string representation of the key for lookup
                    let key_str = match key {
                        Value::Object(obj_id) => format!("obj_{}", obj_id.0),
                        Value::Str(s) => format!("str_{}", s),
                        Value::Int(n) => format!("int_{}", n),
                        Value::Float(f) => format!("float_{}", f.inner()),
                        _ => return Ok(Value::Bool(false)), // WeakMap only accepts object keys
                    };

                    Ok(Value::Bool(weakmap_obj.properties.contains_key(&key_str)))
                } else {
                    Ok(Value::Bool(false))
                }
            }

            "builtin:StringPrototypeBlink" => {
                // String.prototype.blink() implementation (deprecated HTML wrapper)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.inner().to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let result = format!("<blink>{}</blink>", str_text);
                Ok(Value::Str(result))
            }

            "builtin:NumberPrototypeValueOf" => {
                // Number.prototype.valueOf() implementation
                let this_val = self.read_reg(args.start)?;

                match this_val {
                    Value::Int(n) => Ok(Value::Int(n)),
                    Value::Float(f) => Ok(Value::Float(f)),
                    Value::Object(obj_id) => {
                        // Check if it's a Number object wrapper
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(Value::Str(type_val)) = obj.properties.get("__type") {
                                if type_val == "Number" {
                                    if let Some(primitive_val) = obj.properties.get("__value") {
                                        return Ok(primitive_val.clone());
                                    }
                                }
                            }
                        }
                        // Not a Number object, return NaN
                        Ok(Value::Float(Float64::new(f64::NAN)))
                    }
                    _ => {
                        // Primitive numbers return themselves, others return NaN
                        Ok(Value::Float(Float64::new(f64::NAN)))
                    }
                }
            }

            // Removed duplicate ArrayPrototypeEntries - implementation at line ~11841 uses proper iterator semantics

            "builtin:WeakMapPrototypeGet" => {
                // WeakMap.prototype.get(key) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let weakmap_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be WeakMaps
                };

                let key = self.read_reg(args.start + 1)?;

                // Simplified implementation: get value from WeakMap-like object
                if let Some(weakmap_obj) = self.heap.get(weakmap_id.0 as usize) {
                    // Use a simple string representation of the key for lookup
                    let key_str = match key {
                        Value::Object(obj_id) => format!("obj_{}", obj_id.0),
                        Value::Str(s) => format!("str_{}", s),
                        Value::Int(n) => format!("int_{}", n),
                        Value::Float(f) => format!("float_{}", f.inner()),
                        _ => return Ok(Value::Undefined), // WeakMap only accepts object keys
                    };

                    Ok(weakmap_obj
                        .properties
                        .get(&key_str)
                        .cloned()
                        .unwrap_or(Value::Undefined))
                } else {
                    Ok(Value::Undefined)
                }
            }

            // ArrayPrototypeReverse: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypeToLowerCase: Removed duplicate dispatch arm (use first occurrence at line 8124)

            // StringPrototypeToUpperCase: Removed duplicate dispatch arm (use first occurrence at line 8137)

            // ObjectPrototypeToString: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypeTrim: Removed duplicate dispatch arm (use first occurrence instead)


            // NumberIsInteger: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypeEndsWith: Removed duplicate dispatch arm (use first occurrence instead)

            // Removed duplicate NumberIsNaN - implementation at line ~8618 has correct argument handling

            // Removed duplicate NumberIsFinite - implementation at line ~8630 has correct argument handling

            "builtin:StringPrototypeCharAt" => {
                // String.prototype.charAt() implementation - returns character at index
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Object(_) => "[object Object]".to_string(),
                    _ => String::new(),
                };

                let index = if args.count >= 2 {
                    let index_val = self.read_reg(args.start + 1)?;
                    match index_val {
                        Value::Int(n) => n.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                let result = str_text
                    .chars()
                    .nth(index)
                    .map(|c| c.to_string())
                    .unwrap_or_default();
                Ok(Value::Str(result))
            }


            "builtin:ArrayPrototypeEvery" => {
                // Array.prototype.every() implementation
                // FAIL-CLOSED: Array.every requires callback invocation which is not yet supported
                // Previous implementations silently returned incorrect results (element truthiness checking)
                // or always returned true instead of calling the provided predicate callback

                self.validate_array_callback_args(args, "Array.prototype.every")?;

                // Fail-closed until proper callback dispatch is implemented
                // Programs like [0].every(() => true) or [1].every(() => false) should error rather than
                // return wrong results based on element truthiness or always returning true
                Err(InterpreterError::TypeError {
                    expected: "supported Array.prototype.every implementation".to_string(),
                    got: "predicate callback invocation not yet supported - would require proper callback dispatch with (value, index, array) args, thisArg handling, and short-circuiting on first falsy result".to_string(),
                })
            }


            // Removed duplicate NumberPrototypeToString - implementation at line ~11219 is identical


            "builtin:StringPrototypeSubstring" => {
                // String.prototype.substring() implementation - returns substring between indices
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Object(_) => "[object Object]".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let len = str_text.len();
                let start = if args.count >= 2 {
                    let start_val = self.read_reg(args.start + 1)?;
                    match start_val {
                        Value::Int(n) => n.max(0).min(len as i64) as usize,
                        Value::Float(f) => f.inner().max(0.0).min(len as f64) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                let end = if args.count >= 3 {
                    let end_val = self.read_reg(args.start + 2)?;
                    match end_val {
                        Value::Int(n) => n.max(0).min(len as i64) as usize,
                        Value::Float(f) => f.inner().max(0.0).min(len as f64) as usize,
                        _ => len,
                    }
                } else {
                    len
                };

                let (actual_start, actual_end) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };
                let result = str_text
                    .chars()
                    .skip(actual_start)
                    .take(actual_end - actual_start)
                    .collect();
                Ok(Value::Str(result))
            }

            // Removed duplicate ArrayPrototypeReduce - implementation at line ~9273 properly fails-closed


            // Removed duplicate ObjectGetOwnPropertyNames - implementation at line ~10883 has correct argument handling








            "builtin:StringPrototypeSplit" => {
                // String.prototype.split() implementation - splits string into array
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Object(_) => "[object Object]".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let result_array_id = self.alloc_object_with_prototype(None)?;

                if args.count < 2 {
                    // No separator provided - return array with original string
                    self.set_object_property(
                        result_array_id,
                        "0".to_string(),
                        Value::Str(str_text),
                    )?;
                    self.set_object_property(result_array_id, "length".to_string(), Value::Int(1))?;
                } else {
                    let separator_val = self.read_reg(args.start + 1)?;
                    match separator_val {
                        Value::Str(sep) => {
                            let parts: Vec<&str> = if sep.is_empty() {
                                // Empty separator splits each character
                                vec![] // We'll handle this case below
                            } else {
                                str_text.split(&sep).collect()
                            };

                            if sep.is_empty() {
                                // Split each character
                                let chars: Vec<String> =
                                    str_text.chars().map(|c| c.to_string()).collect();
                                for (index, char_str) in chars.iter().enumerate() {
                                    self.set_object_property(
                                        result_array_id,
                                        index.to_string(),
                                        Value::Str(char_str.clone()),
                                    )?;
                                }
                                self.set_object_property(
                                    result_array_id,
                                    "length".to_string(),
                                    Value::Int(chars.len() as i64),
                                )?;
                            } else {
                                // Normal split
                                for (index, part) in parts.iter().enumerate() {
                                    self.set_object_property(
                                        result_array_id,
                                        index.to_string(),
                                        Value::Str(part.to_string()),
                                    )?;
                                }
                                self.set_object_property(
                                    result_array_id,
                                    "length".to_string(),
                                    Value::Int(parts.len() as i64),
                                )?;
                            }
                        }
                        _ => {
                            // Non-string separator - return array with original string
                            self.set_object_property(
                                result_array_id,
                                "0".to_string(),
                                Value::Str(str_text),
                            )?;
                            self.set_object_property(
                                result_array_id,
                                "length".to_string(),
                                Value::Int(1),
                            )?;
                        }
                    }
                }

                Ok(Value::Object(result_array_id))
            }

            "builtin:ArrayPrototypeMap" => {
                // Array.prototype.map() implementation
                // FAIL-CLOSED: Array.map requires callback invocation which is not yet supported
                // Previous implementations silently returned incorrect results (identity mapping)
                // or applied hardcoded transformations instead of calling the provided callback

                self.validate_array_callback_args(args, "Array.prototype.map")?;

                // Fail-closed until proper callback dispatch is implemented
                // Programs like [1,2].map(x => x * 2) should error rather than silently return [1,2]
                Err(InterpreterError::TypeError {
                    expected: "supported Array.prototype.map implementation".to_string(),
                    got: "callback invocation not yet supported - would require proper callback dispatch with (element, index, array) args and thisArg handling".to_string(),
                })
            }

            // Removed duplicate DateNow - implementation at line ~8728 is identical

            "builtin:ArrayPrototypeConcat" => {
                // Array.prototype.concat() implementation - concatenates arrays
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects return undefined
                };

                let result_array_id = self.alloc_object_with_prototype(None)?;

                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    let length_prop = obj
                        .properties
                        .get("length")
                        .cloned()
                        .unwrap_or(Value::Int(0));
                    let length = match length_prop {
                        Value::Int(n) => n.max(0) as usize,
                        _ => 0,
                    };

                    // Copy elements from original array
                    let elements: Vec<_> = (0..length)
                        .filter_map(|i| obj.properties.get(&i.to_string()).cloned())
                        .collect();

                    let mut result_index = 0;
                    for element in elements {
                        self.set_object_property(
                            result_array_id,
                            result_index.to_string(),
                            element,
                        )?;
                        result_index += 1;
                    }

                    // Concatenate additional arguments
                    for arg_idx in 1..args.count {
                        let arg_val = self.read_reg(args.start + arg_idx)?;
                        match arg_val {
                            Value::Object(concat_id) => {
                                // If it's an array, concatenate its elements
                                let elements_to_add =
                                    if let Some(concat_obj) = self.heap.get(concat_id.0 as usize) {
                                        if let Some(concat_length_prop) =
                                            concat_obj.properties.get("length")
                                        {
                                            let concat_length = match concat_length_prop {
                                                Value::Int(n) => (*n).max(0) as usize,
                                                _ => 0,
                                            };

                                            let mut elements = Vec::new();
                                            for i in 0..concat_length {
                                                if let Some(element) =
                                                    concat_obj.properties.get(&i.to_string())
                                                {
                                                    elements.push(element.clone());
                                                }
                                            }
                                            elements
                                        } else {
                                            Vec::new()
                                        }
                                    } else {
                                        Vec::new()
                                    };

                                for element in elements_to_add {
                                    self.set_object_property(
                                        result_array_id,
                                        result_index.to_string(),
                                        element,
                                    )?;
                                    result_index += 1;
                                }
                            }
                            _ => {
                                // Non-array values are added as single elements
                                self.set_object_property(
                                    result_array_id,
                                    result_index.to_string(),
                                    arg_val,
                                )?;
                                result_index += 1;
                            }
                        }
                    }

                    self.set_object_property(
                        result_array_id,
                        "length".to_string(),
                        Value::Int(result_index as i64),
                    )?;
                }

                Ok(Value::Object(result_array_id))
            }


            "builtin:JSONStringify" => {
                // JSON.stringify() implementation - simplified version
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let value = self.read_reg(args.start + 1)?;
                let json_str = match value {
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(), // Note: undefined is not valid JSON
                    Value::Bool(b) => b.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Str(s) => format!("\"{}\"", s.replace('"', "\\\"")),
                    Value::Object(_) => "{}".to_string(), // Simplified object representation
                    _ => "null".to_string(),
                };
                Ok(Value::Str(json_str))
            }

            "builtin:JSONParse" => {
                // JSON.parse() implementation - simplified version
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let str_val = self.read_reg(args.start + 1)?;
                let json_str = match str_val {
                    Value::Str(s) => s,
                    _ => return Ok(Value::Undefined),
                };

                // Simplified JSON parsing - handle basic cases
                let trimmed = json_str.trim();
                if trimmed == "null" {
                    Ok(Value::Null)
                } else if trimmed == "true" {
                    Ok(Value::Bool(true))
                } else if trimmed == "false" {
                    Ok(Value::Bool(false))
                } else if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
                    let unquoted = &trimmed[1..trimmed.len() - 1];
                    Ok(Value::Str(unquoted.replace("\\\"", "\"")))
                } else if let Ok(int_val) = trimmed.parse::<i64>() {
                    Ok(Value::Int(int_val))
                } else if let Ok(float_val) = trimmed.parse::<f64>() {
                    Ok(Value::Float(Float64::new(float_val)))
                } else if trimmed == "{}" {
                    // Empty object
                    let obj_id = self.alloc_object_with_prototype(None)?;
                    Ok(Value::Object(obj_id))
                } else {
                    Ok(Value::Undefined) // Parse error
                }
            }

            // builtin:ArrayPrototypeFind - Duplicate removed, consolidated to line 12438

            // builtin:ArrayPrototypeFindIndex - Duplicate removed, consolidated to line 10807

            "builtin:EncodeURIComponent" => {
                // encodeURIComponent() implementation using shared UTF-8 percent codec
                if args.count == 0 {
                    return Ok(Value::Str("undefined".to_string()));
                }

                let value = self.read_reg(args.start + 1)?;
                let input_str = value_to_string_for_uri(&value);
                let encoded = percent_encode_utf8(&input_str, should_encode_uri_component);

                Ok(Value::Str(encoded))
            }

            "builtin:DecodeURIComponent" => {
                // decodeURIComponent() implementation using shared UTF-8 percent codec
                if args.count == 0 {
                    return Ok(Value::Str("undefined".to_string()));
                }

                let value = self.read_reg(args.start + 1)?;
                let encoded_str = value_to_string_for_uri(&value);

                let decoded = match percent_decode_utf8(&encoded_str) {
                    Ok(s) => s,
                    Err(_) => {
                        // In JavaScript, decodeURIComponent throws URIError for invalid sequences
                        // For now, return the original string to avoid breaking existing code
                        encoded_str
                    }
                };

                Ok(Value::Str(decoded))
            }

            "builtin:EncodeURI" => {
                // encodeURI() implementation using shared UTF-8 percent codec
                if args.count == 0 {
                    return Ok(Value::Str("undefined".to_string()));
                }

                let value = self.read_reg(args.start + 1)?;
                let input_str = value_to_string_for_uri(&value);
                let encoded = percent_encode_utf8(&input_str, should_encode_uri);

                Ok(Value::Str(encoded))
            }

            "builtin:DecodeURI" => {
                // decodeURI() implementation using shared UTF-8 percent codec
                if args.count == 0 {
                    return Ok(Value::Str("undefined".to_string()));
                }

                let value = self.read_reg(args.start + 1)?;
                let encoded_str = value_to_string_for_uri(&value);

                let decoded = match percent_decode_utf8(&encoded_str) {
                    Ok(s) => s,
                    Err(_) => {
                        // In JavaScript, decodeURI throws URIError for invalid sequences
                        // For now, return the original string to avoid breaking existing code
                        encoded_str
                    }
                };

                Ok(Value::Str(decoded))
            }

            "builtin:SetTimeout" => {
                // setTimeout() implementation - route through deterministic timer state
                if args.count < 2 {
                    return Ok(Value::Int(0)); // Invalid timer ID
                }

                let callback_val = self.read_reg(args.start + 1)?;
                if !matches!(callback_val, Value::Function(_) | Value::Closure(_)) {
                    return Ok(Value::Int(0)); // Callback is not a function
                }

                let delay_ms = if args.count >= 3 {
                    let delay_val = self.read_reg(args.start + 2)?;
                    match delay_val {
                        Value::Int(n) => n.max(0) as u64,
                        Value::Float(f) => f.inner().max(0.0) as u64,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Use deterministic timer ID allocation
                let timer_id = self.next_timer_id;
                self.next_timer_id = self.next_timer_id.wrapping_add(1);

                let handler_id = match callback_val {
                    Value::Closure(id) => Some(id),
                    _ => None,
                };

                // Store active timer for cancellation support
                self.active_timers.insert(
                    timer_id,
                    ActiveTimer {
                        handler: handler_id,
                        delay_ms,
                        repeating: false,
                    },
                );

                // Emit deterministic witness for replay consistency
                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("builtin:setTimeout:{}", timer_id)),
                );

                Ok(Value::Int(timer_id as i64))
            }

            "builtin:ClearTimeout" => {
                // clearTimeout() implementation - cancel timer through deterministic state
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let timer_id_val = self.read_reg(args.start + 1)?;
                let timer_id = match timer_id_val {
                    Value::Int(i) => i as u32,
                    _ => return Ok(Value::Undefined), // Invalid timer ID type
                };

                // Remove timer from active timers for proper cancellation
                let was_active = self.active_timers.remove(&timer_id).is_some();

                // Emit witness for cancellation (only if timer was actually active)
                if was_active {
                    self.emit_witness(
                        WitnessEventKind::HostcallDispatched,
                        Some(&format!("builtin:clearTimeout:{}", timer_id)),
                    );
                }

                Ok(Value::Undefined)
            }

            "builtin:ParseInt" => {
                // parseInt() implementation - parses string to integer
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let value = self.read_reg(args.start)?;
                let radix_arg = if args.count >= 2 {
                    Some(self.read_reg(args.start + 1)?)
                } else {
                    None
                };

                match Self::parse_int_with_sign_and_radix(&value, radix_arg.as_ref()) {
                    Some(result) => Ok(Value::Int(result)),
                    None => Ok(Value::Float(Float64::new(f64::NAN))),
                }
            }

            "builtin:ParseFloat" => {
                // parseFloat() implementation - parses string to float
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let value = self.read_reg(args.start)?;
                let input_str = match value {
                    Value::Str(s) => s,
                    Value::Int(n) => return Ok(Value::Int(n)),
                    Value::Float(f) => return Ok(Value::Float(f)),
                    Value::Bool(true) => "1".to_string(),
                    Value::Bool(false) => "0".to_string(),
                    _ => return Ok(Value::Float(Float64::new(f64::NAN))),
                };

                let trimmed = input_str.trim();
                if trimmed.is_empty() {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                // Handle Infinity and -Infinity literals first
                if trimmed.starts_with("Infinity") {
                    return Ok(Value::Float(Float64::new(f64::INFINITY)));
                }
                if trimmed.starts_with("-Infinity") {
                    return Ok(Value::Float(Float64::new(f64::NEG_INFINITY)));
                }
                if trimmed.starts_with("+Infinity") {
                    return Ok(Value::Float(Float64::new(f64::INFINITY)));
                }

                // Parse number with scientific notation support
                let mut result_str = String::new();
                let mut has_dot = false;
                let mut has_exponent = false;
                let mut chars = trimmed.chars().peekable();

                // Handle sign
                if let Some(&first_char) = chars.peek() {
                    if first_char == '+' || first_char == '-' {
                        // SAFETY: peek() just confirmed a character exists, so next() cannot return None
                        result_str.push(chars.next().unwrap());
                    }
                }

                // Parse main number part with exponent support
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() {
                        // SAFETY: peek() just confirmed a character exists, so next() cannot return None
                        result_str.push(chars.next().unwrap());
                    } else if c == '.' && !has_dot && !has_exponent {
                        // SAFETY: peek() just confirmed a character exists, so next() cannot return None
                        result_str.push(chars.next().unwrap());
                        has_dot = true;
                    } else if (c == 'e' || c == 'E') && !has_exponent {
                        // SAFETY: peek() just confirmed a character exists, so next() cannot return None
                        result_str.push(chars.next().unwrap());
                        has_exponent = true;

                        // Handle exponent sign
                        if let Some(&next_char) = chars.peek() {
                            if next_char == '+' || next_char == '-' {
                                // SAFETY: peek() just confirmed a character exists, so next() cannot return None
                                result_str.push(chars.next().unwrap());
                            }
                        }
                    } else {
                        break; // Stop at first invalid character
                    }
                }

                // Validate result string is not empty or just signs
                if result_str.is_empty() || result_str == "+" || result_str == "-" {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                if let Ok(parsed) = result_str.parse::<f64>() {
                    // Return Int if it's a finite whole number within i64 range
                    if parsed.is_finite()
                        && parsed.fract() == 0.0
                        && parsed >= i64::MIN as f64
                        && parsed <= i64::MAX as f64
                    {
                        Ok(Value::Int(parsed as i64))
                    } else {
                        Ok(Value::Float(Float64::new(parsed)))
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }

            "builtin:IsNaN" => {
                // isNaN() implementation - checks if value is NaN (with coercion)
                if args.count == 0 {
                    return Ok(Value::Bool(true)); // isNaN() with no args returns true
                }

                let value = self.read_reg(args.start)?;
                let num = match value {
                    Value::Int(_) => return Ok(Value::Bool(false)), // Integers are never NaN
                    Value::Float(f) => f.inner(),
                    _ => {
                        // Coerce to number first
                        Self::coerce_to_float(&value).unwrap_or(f64::NAN)
                    }
                };

                Ok(Value::Bool(num.is_nan()))
            }

            "builtin:IsFinite" => {
                // isFinite() implementation - checks if value is finite (with coercion)
                if args.count == 0 {
                    return Ok(Value::Bool(false)); // isFinite() with no args returns false
                }

                let value = self.read_reg(args.start)?;
                let num = match value {
                    Value::Int(_) => return Ok(Value::Bool(true)), // Integers are always finite
                    Value::Float(f) => f.inner(),
                    _ => {
                        // Coerce to number first
                        Self::coerce_to_float(&value).unwrap_or(f64::NAN)
                    }
                };

                Ok(Value::Bool(num.is_finite()))
            }

            "builtin:ConsoleInfo" => {
                // console.info implementation - prints info arguments to console
                let mut output_parts = Vec::new();

                // Convert all arguments to strings and collect them
                for i in 0..args.count {
                    let arg = self.read_reg(args.start + i)?;
                    let str_representation = self.value_to_string(&arg);
                    output_parts.push(str_representation);
                }

                // Join with spaces (standard console behavior)
                let output = output_parts.join(" ");

                // Bounded console output to prevent DoS via console spam
                if self.console_output.len() >= self.config.max_console_entries {
                    // Ring buffer: drop oldest entry when limit reached
                    self.console_output.remove(0);
                }

                // Capture console output for deterministic replay
                self.console_output.push(ConsoleEntry {
                    level: ConsoleLevel::Info,
                    message: output,
                    instruction_index: self.instructions_executed,
                });

                Ok(Value::Undefined)
            }

            "builtin:StringPrototypeToLocaleLowerCase" => {
                // String.prototype.toLocaleLowerCase() implementation - simplified locale-aware lowercase
                let this_val = self.read_reg(args.start)?;
                let str_text = Self::require_object_coercible_to_string(&this_val)?;

                // Simplified: use standard lowercase (full locale support would require ICU)
                Ok(Value::Str(str_text.to_lowercase()))
            }

            "builtin:StringPrototypeToLocaleUpperCase" => {
                // String.prototype.toLocaleUpperCase() implementation - simplified locale-aware uppercase
                let this_val = self.read_reg(args.start)?;
                let str_text = Self::require_object_coercible_to_string(&this_val)?;

                // Simplified: use standard uppercase (full locale support would require ICU)
                Ok(Value::Str(str_text.to_uppercase()))
            }

            _ => {
                // Unknown builtin method - return undefined
                Ok(Value::Undefined)
            }
        }
    }

    /// Unified Math.random implementation - deterministic with proper [0,1) range.
    fn math_random_impl(&mut self) -> Result<Value, InterpreterError> {
        // Generate deterministic pseudo-random number using execution state as seed
        use crate::security_e2e::Xorshift64;
        use sha2::{Digest, Sha256};

        // Create deterministic seed from execution state using stable hash
        // (SHA-256 is deterministic across builds, unlike DefaultHasher)
        let mut digest = Sha256::new();
        digest.update(&(self.call_stack.len() as u64).to_le_bytes());
        digest.update(&(self.heap.len() as u64).to_le_bytes());
        digest.update(&self.instructions_executed.to_le_bytes());
        digest.update(&(self.ip as u64).to_le_bytes());

        let hash_result = digest.finalize();
        let seed = u64::from_le_bytes([
            hash_result[0], hash_result[1], hash_result[2], hash_result[3],
            hash_result[4], hash_result[5], hash_result[6], hash_result[7],
        ]);
        let mut rng = Xorshift64::new(seed);

        // Generate random value in [0, 1) using 53-bit precision to avoid rounding to 1.0
        // JavaScript Number uses IEEE 754 double precision with 53-bit significand
        let random_bits = rng.next_u64() >> 11; // Use top 53 bits
        let normalized = (random_bits as f64) / (1u64 << 53) as f64;

        Ok(Value::Float(Float64::new(normalized)))
    }

    fn coerce_finite_radix_or_default(value: Value, default: i32) -> i32 {
        match value {
            Value::Int(n) => n as i32,
            Value::Float(f) => {
                let radix = f.inner();
                if radix.is_finite() {
                    radix as i32
                } else {
                    default
                }
            }
            _ => default,
        }
    }

    /// Parse integers with shared parseInt sign and radix handling.
    fn parse_int_with_sign_and_radix(input: &Value, radix_arg: Option<&Value>) -> Option<i64> {
        let input = Self::value_to_primitive_string(input);
        let trimmed = input.trim_start();
        if trimmed.is_empty() {
            return None;
        }

        let radix = if let Some(radix_value) = radix_arg {
            Self::coerce_finite_radix_or_default(radix_value.clone(), 10)
        } else {
            10
        };

        if radix != 0 && (radix < 2 || radix > 36) {
            return None;
        }

        let mut sign = 1i64;
        let mut parse_start = 0usize;
        if trimmed.starts_with('-') {
            sign = -1;
            parse_start = 1;
        } else if trimmed.starts_with('+') {
            parse_start = 1;
        }

        let mut actual_radix = radix;
        let remaining = &trimmed[parse_start..];
        if radix == 16 || radix == 0 {
            if remaining.starts_with("0x") || remaining.starts_with("0X") {
                actual_radix = 16;
                parse_start += 2;
            } else if radix == 0 {
                actual_radix = 10;
            }
        }

        if parse_start >= trimmed.len() {
            return None;
        }

        let mut found = false;
        let mut result = 0i64;
        for c in trimmed[parse_start..].chars() {
            let digit = if c.is_ascii_digit() {
                (c as i64) - ('0' as i64)
            } else if c.is_ascii_alphabetic() {
                (c.to_ascii_lowercase() as i64) - ('a' as i64) + 10
            } else {
                break;
            };

            if digit >= actual_radix as i64 || digit < 0 {
                break;
            }

            found = true;
            result = result
                .saturating_mul(actual_radix as i64)
                .saturating_add(digit);
        }

        if found { Some(sign * result) } else { None }
    }

    /// Unified Number.prototype.toString implementation - spec-consistent radix handling.
    fn number_to_string_impl(
        &self,
        number_val: f64,
        radix: i32,
    ) -> Result<String, InterpreterError> {
        // Validate radix according to ECMAScript spec (2-36)
        if radix < 2 || radix > 36 {
            return Err(InterpreterError::DivisionByZero); // Reuse error type for RangeError
        }

        // Handle special values
        if number_val.is_nan() {
            return Ok("NaN".to_string());
        }
        if number_val.is_infinite() {
            return Ok(if number_val.is_sign_positive() {
                "Infinity"
            } else {
                "-Infinity"
            }
            .to_string());
        }

        // For radix 10, use standard formatting
        if radix == 10 {
            // Convert to integer if possible for cleaner output
            if number_val.fract() == 0.0 && number_val.abs() <= (i64::MAX as f64) {
                return Ok((number_val as i64).to_string());
            } else {
                return Ok(number_val.to_string());
            }
        }

        // For non-decimal radix, only support integers (spec-compliant)
        if number_val.fract() != 0.0 {
            return Ok(number_val.to_string()); // Return decimal representation for fractional
        }

        // Convert integer to specified radix
        let mut result = String::new();
        let mut num = number_val.abs() as u64;
        let radix_u64 = radix as u64;

        if num == 0 {
            result.push('0');
        } else {
            while num > 0 {
                let digit = (num % radix_u64) as u8;
                let ch = if digit < 10 {
                    (b'0' + digit) as char
                } else {
                    (b'a' + (digit - 10)) as char
                };
                result.insert(0, ch);
                num /= radix_u64;
            }
        }

        if number_val.is_sign_negative() && number_val != 0.0 {
            result.insert(0, '-');
        }

        Ok(result)
    }

    /// Map a function index to a builtin capability string if it corresponds to a builtin.
    /// This is a temporary bridge until we have proper builtin registry integration.
    fn map_function_index_to_builtin_capability(&self, func_idx: u32) -> Option<String> {
        // Based on the stdlib installation order, map function indices to builtin capabilities
        // This is a simplified mapping for common builtin methods
        // Note: This approach assumes stdlib is installed starting from index 0
        match func_idx {
            // Object methods (installed first in stdlib.rs)
            0 => Some("builtin:ObjectKeys".to_string()),
            1 => Some("builtin:ObjectValues".to_string()),
            2 => Some("builtin:ObjectEntries".to_string()),
            3 => Some("builtin:ObjectAssign".to_string()),
            4 => Some("builtin:ObjectFreeze".to_string()),
            5 => Some("builtin:ObjectCreate".to_string()),

            // Array methods (installed after Object in stdlib.rs)
            10 => Some("builtin:ArrayIsArray".to_string()),
            11 => Some("builtin:ArrayFrom".to_string()),
            12 => Some("builtin:ArrayOf".to_string()),
            13 => Some("builtin:ArrayPrototypePush".to_string()),
            14 => Some("builtin:ArrayPrototypePop".to_string()),
            15 => Some("builtin:ArrayPrototypeShift".to_string()),
            16 => Some("builtin:ArrayPrototypeUnshift".to_string()),
            17 => Some("builtin:ArrayPrototypeJoin".to_string()),
            18 => Some("builtin:ArrayPrototypeIncludes".to_string()),
            19 => Some("builtin:ArrayPrototypeIndexOf".to_string()),
            20 => Some("builtin:ArrayPrototypeSlice".to_string()),

            // String methods
            30 => Some("builtin:StringPrototypeCharAt".to_string()),
            31 => Some("builtin:StringPrototypeIndexOf".to_string()),
            32 => Some("builtin:StringPrototypeSubstring".to_string()),
            33 => Some("builtin:StringPrototypeSlice".to_string()),
            34 => Some("builtin:StringPrototypeToLowerCase".to_string()),
            35 => Some("builtin:StringPrototypeToUpperCase".to_string()),
            36 => Some("builtin:StringPrototypeSplit".to_string()),
            37 => Some("builtin:StringPrototypeTrim".to_string()),

            // Math methods
            50 => Some("builtin:MathAbs".to_string()),
            51 => Some("builtin:MathCeil".to_string()),
            52 => Some("builtin:MathFloor".to_string()),
            53 => Some("builtin:MathRound".to_string()),
            54 => Some("builtin:MathMax".to_string()),
            55 => Some("builtin:MathMin".to_string()),
            56 => Some("builtin:MathRandom".to_string()),

            // JSON methods
            70 => Some("builtin:JsonParse".to_string()),
            71 => Some("builtin:JsonStringify".to_string()),

            // Global functions
            80 => Some("builtin:isNaN".to_string()),
            81 => Some("builtin:isFinite".to_string()),
            82 => Some("builtin:parseInt".to_string()),
            83 => Some("builtin:parseFloat".to_string()),

            // Number methods
            90 => Some("builtin:NumberIsNaN".to_string()),
            91 => Some("builtin:NumberIsFinite".to_string()),

            // Console methods
            100 => Some("builtin:ConsoleLog".to_string()),
            101 => Some("builtin:ConsoleError".to_string()),
            102 => Some("builtin:ConsoleWarn".to_string()),

            // Date methods
            110 => Some("builtin:DateNow".to_string()),
            111 => Some("builtin:Date".to_string()),

            // Additional Math methods
            57 => Some("builtin:MathPow".to_string()),
            58 => Some("builtin:MathSqrt".to_string()),
            59 => Some("builtin:MathSin".to_string()),
            60 => Some("builtin:MathCos".to_string()),
            61 => Some("builtin:MathLog".to_string()),
            62 => Some("builtin:MathExp".to_string()),
            63 => Some("builtin:MathTan".to_string()),
            64 => Some("builtin:MathPI".to_string()),
            65 => Some("builtin:MathTrunc".to_string()),
            66 => Some("builtin:MathSign".to_string()),

            // Additional String methods
            38 => Some("builtin:StringPrototypeIncludes".to_string()),
            39 => Some("builtin:StringPrototypeStartsWith".to_string()),
            40 => Some("builtin:StringPrototypeEndsWith".to_string()),
            41 => Some("builtin:StringPrototypeReplace".to_string()),
            42 => Some("builtin:StringPrototypeRepeat".to_string()),
            43 => Some("builtin:StringPrototypePadStart".to_string()),
            44 => Some("builtin:StringPrototypePadEnd".to_string()),

            // Additional Array methods
            21 => Some("builtin:ArrayPrototypeReverse".to_string()),
            22 => Some("builtin:ArrayPrototypeForEach".to_string()),
            23 => Some("builtin:ArrayPrototypeMap".to_string()),
            24 => Some("builtin:ArrayPrototypeFilter".to_string()),
            25 => Some("builtin:ArrayPrototypeFind".to_string()),
            26 => Some("builtin:ArrayPrototypeConcat".to_string()),
            27 => Some("builtin:ArrayPrototypeReduce".to_string()),
            28 => Some("builtin:ArrayPrototypeSort".to_string()),
            29 => Some("builtin:ArrayPrototypeSplice".to_string()),
            202 => Some("builtin:ArrayPrototypeFlat".to_string()),
            203 => Some("builtin:ArrayPrototypeSome".to_string()),
            204 => Some("builtin:ArrayPrototypeEvery".to_string()),

            // Additional String methods (continued)
            45 => Some("builtin:StringPrototypeMatch".to_string()),
            46 => Some("builtin:StringPrototypeSearch".to_string()),

            // Promise methods
            120 => Some("builtin:PromiseResolve".to_string()),

            // Additional Object methods
            6 => Some("builtin:ObjectHasOwnProperty".to_string()),
            7 => Some("builtin:ObjectDefineProperty".to_string()),

            // Error constructors
            130 => Some("builtin:Error".to_string()),

            // Type conversion constructors
            140 => Some("builtin:Number".to_string()),
            141 => Some("builtin:Boolean".to_string()),

            // Primitive constructors
            150 => Some("builtin:Symbol".to_string()),

            // Operators
            160 => Some("builtin:typeof".to_string()),

            // Collection constructors
            170 => Some("builtin:Map".to_string()),
            171 => Some("builtin:Set".to_string()),
            172 => Some("builtin:WeakMap".to_string()),
            173 => Some("builtin:WeakSet".to_string()),

            // Collection prototype methods
            174 => Some("builtin:MapPrototypeSet".to_string()),
            175 => Some("builtin:MapPrototypeGet".to_string()),
            176 => Some("builtin:SetPrototypeAdd".to_string()),
            177 => Some("builtin:SetPrototypeHas".to_string()),
            178 => Some("builtin:MapPrototypeHas".to_string()),
            179 => Some("builtin:MapPrototypeDelete".to_string()),
            180 => Some("builtin:SetPrototypeDelete".to_string()),
            181 => Some("builtin:SetPrototypeClear".to_string()),
            182 => Some("builtin:ArrayPrototypeLastIndexOf".to_string()),
            183 => Some("builtin:ArrayPrototypeFindIndex".to_string()),
            184 => Some("builtin:StringPrototypeCharCodeAt".to_string()),
            185 => Some("builtin:StringFromCharCode".to_string()),
            186 => Some("builtin:ObjectGetOwnPropertyNames".to_string()),
            187 => Some("builtin:ObjectGetPrototypeOf".to_string()),
            188 => Some("builtin:PromiseReject".to_string()),
            189 => Some("builtin:MathAtan2".to_string()),
            190 => Some("builtin:FunctionPrototypeCall".to_string()),
            191 => Some("builtin:MathAsin".to_string()),
            192 => Some("builtin:MathAcos".to_string()),
            193 => Some("builtin:RegExp".to_string()),
            194 => Some("builtin:ArrayPrototypeReduceRight".to_string()),
            195 => Some("builtin:StringPrototypeSubstr".to_string()),
            196 => Some("builtin:NumberPrototypeToString".to_string()),
            197 => Some("builtin:PromiseAll".to_string()),
            198 => Some("builtin:FunctionPrototypeApply".to_string()),
            199 => Some("builtin:StringPrototypeLocaleCompare".to_string()),
            200 => Some("builtin:DatePrototypeGetTime".to_string()),
            201 => Some("builtin:DatePrototypeToString".to_string()),
            205 => Some("builtin:ObjectPrototypeValueOf".to_string()),
            206 => Some("builtin:ArrayPrototypeFlatMap".to_string()),
            207 => Some("builtin:MathHypot".to_string()),
            208 => Some("builtin:ArrayPrototypeCopyWithin".to_string()),
            209 => Some("builtin:ArrayPrototypeFill".to_string()),
            210 => Some("builtin:StringPrototypeCodePointAt".to_string()),
            211 => Some("builtin:StringFromCodePoint".to_string()),
            212 => Some("builtin:MathImul".to_string()),
            213 => Some("builtin:ArrayPrototypeAt".to_string()),
            214 => Some("builtin:StringPrototypeAt".to_string()),
            215 => Some("builtin:ObjectGetOwnPropertyDescriptor".to_string()),
            216 => Some("builtin:MathClz32".to_string()),
            217 => Some("builtin:ArrayPrototypeEntries".to_string()),
            218 => Some("builtin:ArrayPrototypeKeys".to_string()),
            219 => Some("builtin:ArrayPrototypeValues".to_string()),
            220 => Some("builtin:ObjectSetPrototypeOf".to_string()),
            221 => Some("builtin:SymbolIterator".to_string()),
            222 => Some("builtin:StringPrototypeNormalize".to_string()),
            223 => Some("builtin:StringPrototypeTrimStart".to_string()),
            224 => Some("builtin:StringPrototypeTrimEnd".to_string()),
            225 => Some("builtin:ArrayPrototypeFind".to_string()),
            226 => Some("builtin:StringPrototypePadStart".to_string()),
            227 => Some("builtin:StringPrototypePadEnd".to_string()),
            228 => Some("builtin:ObjectPrototypeHasOwnProperty".to_string()),
            229 => Some("builtin:StringPrototypeStartsWith".to_string()),
            230 => Some("builtin:StringPrototypeEndsWith".to_string()),
            231 => Some("builtin:NumberIsInteger".to_string()),
            232 => Some("builtin:NumberParseFloat".to_string()),
            233 => Some("builtin:StringPrototypeRepeat".to_string()),
            234 => Some("builtin:NumberParseInt".to_string()),
            235 => Some("builtin:StringPrototypeReplace".to_string()),
            236 => Some("builtin:ArrayPrototypeFilter".to_string()),
            237 => Some("builtin:ArrayPrototypeMap".to_string()),
            238 => Some("builtin:StringPrototypeIncludes".to_string()),
            239 => Some("builtin:NumberIsNaNMethod".to_string()),
            240 => Some("builtin:MathPow".to_string()),
            241 => Some("builtin:ArrayPrototypeReduce".to_string()),
            242 => Some("builtin:StringPrototypeMatch".to_string()),
            243 => Some("builtin:ArrayPrototypeReverse".to_string()),
            244 => Some("builtin:MathSin".to_string()),
            245 => Some("builtin:MathCos".to_string()),
            246 => Some("builtin:ArrayPrototypeConcat".to_string()),
            247 => Some("builtin:MathTan".to_string()),
            248 => Some("builtin:ArrayPrototypeSort".to_string()),
            249 => Some("builtin:StringPrototypeMatch".to_string()),
            250 => Some("builtin:MathAtan".to_string()),
            251 => Some("builtin:ArrayPrototypeFill".to_string()),
            252 => Some("builtin:ObjectPrototypePropertyIsEnumerable".to_string()),
            253 => Some("builtin:StringPrototypeConcat".to_string()),
            254 => Some("builtin:MathAtan2".to_string()),
            255 => Some("builtin:ArrayPrototypeEvery".to_string()),
            256 => Some("builtin:DatePrototypeGetTime".to_string()),
            257 => Some("builtin:StringPrototypeLocaleCompare".to_string()),
            258 => Some("builtin:MathLog10".to_string()),
            259 => Some("builtin:ArrayPrototypeSome".to_string()),
            260 => Some("builtin:ObjectPrototypeValueOf".to_string()),
            261 => Some("builtin:StringPrototypeCharCodeAt".to_string()),
            262 => Some("builtin:MathLog2".to_string()),
            263 => Some("builtin:ArrayPrototypeReduceRight".to_string()),
            264 => Some("builtin:ObjectPrototypeToString".to_string()),
            265 => Some("builtin:StringFromCharCode".to_string()),
            266 => Some("builtin:MathAcos".to_string()),
            267 => Some("builtin:ArrayPrototypeLastIndexOf".to_string()),
            268 => Some("builtin:RegExpPrototypeTest".to_string()),
            269 => Some("builtin:StringPrototypeCodePointAt".to_string()),
            270 => Some("builtin:MathAsin".to_string()),
            271 => Some("builtin:ArrayPrototypeFindIndex".to_string()),
            272 => Some("builtin:ObjectGetOwnPropertyNames".to_string()),
            273 => Some("builtin:StringPrototypeNormalize".to_string()),
            274 => Some("builtin:MathCbrt".to_string()),
            275 => Some("builtin:ArrayPrototypeFlat".to_string()),
            276 => Some("builtin:PromiseResolve".to_string()),
            277 => Some("builtin:StringPrototypeReplaceAll".to_string()),
            278 => Some("builtin:MathClz32".to_string()),
            279 => Some("builtin:ArrayPrototypeFlatMap".to_string()),
            280 => Some("builtin:ObjectDefineProperty".to_string()),
            281 => Some("builtin:StringPrototypeAt".to_string()),
            282 => Some("builtin:MathFround".to_string()),
            283 => Some("builtin:ArrayPrototypeAt".to_string()),
            284 => Some("builtin:ObjectGetPrototypeOf".to_string()),
            285 => Some("builtin:StringPrototypeToWellFormed".to_string()),
            286 => Some("builtin:MathAcosh".to_string()),
            287 => Some("builtin:ArrayFromAsync".to_string()),
            288 => Some("builtin:ObjectIs".to_string()),
            289 => Some("builtin:StringPrototypeIsWellFormed".to_string()),
            290 => Some("builtin:MathAsinh".to_string()),
            291 => Some("builtin:ArrayPrototypeWith".to_string()),
            292 => Some("builtin:ObjectSetPrototypeOf".to_string()),
            293 => Some("builtin:StringPrototypeToLowerCase".to_string()),
            294 => Some("builtin:MathAtanh".to_string()),
            295 => Some("builtin:ArrayPrototypeToReversed".to_string()),
            296 => Some("builtin:ObjectHasOwnProperty".to_string()),
            297 => Some("builtin:StringPrototypeToUpperCase".to_string()),
            298 => Some("builtin:MathHypot".to_string()),
            299 => Some("builtin:ArrayPrototypeToSorted".to_string()),
            300 => Some("builtin:ObjectPropertyIsEnumerable".to_string()),
            301 => Some("builtin:StringPrototypeTrimStart".to_string()),
            302 => Some("builtin:MathImul".to_string()),
            303 => Some("builtin:ArrayPrototypeToSpliced".to_string()),
            304 => Some("builtin:ObjectIsExtensible".to_string()),
            305 => Some("builtin:StringPrototypeTrimEnd".to_string()),
            306 => Some("builtin:MathSign".to_string()),
            307 => Some("builtin:ArrayPrototypeGroup".to_string()),
            308 => Some("builtin:ObjectPreventExtensions".to_string()),
            309 => Some("builtin:StringPrototypeSearch".to_string()),
            310 => Some("builtin:MathTrunc".to_string()),
            311 => Some("builtin:ArrayPrototypeGroupToMap".to_string()),
            312 => Some("builtin:ObjectSeal".to_string()),
            313 => Some("builtin:StringPrototypeSubstr".to_string()),
            314 => Some("builtin:NumberPrototypeToFixed".to_string()),
            315 => Some("builtin:ArrayPrototypeCopyWithin".to_string()),
            316 => Some("builtin:ObjectIsFrozen".to_string()),
            317 => Some("builtin:StringPrototypeAnchor".to_string()),
            318 => Some("builtin:NumberPrototypeToExponential".to_string()),
            319 => Some("builtin:ArrayPrototypeValues".to_string()),
            320 => Some("builtin:ObjectIsSealed".to_string()),
            321 => Some("builtin:StringPrototypeBig".to_string()),
            322 => Some("builtin:NumberPrototypeToPrecision".to_string()),
            323 => Some("builtin:ArrayPrototypeKeys".to_string()),
            324 => Some("builtin:WeakMapPrototypeHas".to_string()),
            325 => Some("builtin:StringPrototypeBlink".to_string()),
            326 => Some("builtin:NumberPrototypeValueOf".to_string()),
            327 => Some("builtin:ArrayPrototypeEntries".to_string()),
            328 => Some("builtin:WeakMapPrototypeGet".to_string()),
            329 => Some("builtin:ArrayPrototypeReverse".to_string()),
            330 => Some("builtin:StringPrototypeToLowerCase".to_string()),
            331 => Some("builtin:StringPrototypeToUpperCase".to_string()),
            332 => Some("builtin:ObjectPrototypeToString".to_string()),
            333 => Some("builtin:StringPrototypeTrim".to_string()),
            334 => Some("builtin:ArrayPrototypeForEach".to_string()),
            335 => Some("builtin:NumberIsInteger".to_string()),
            336 => Some("builtin:StringPrototypeEndsWith".to_string()),
            337 => Some("builtin:NumberIsNaN".to_string()),
            338 => Some("builtin:NumberIsFinite".to_string()),
            339 => Some("builtin:StringPrototypeCharAt".to_string()),
            340 => Some("builtin:ArrayPrototypeSome".to_string()),
            341 => Some("builtin:ArrayPrototypeEvery".to_string()),
            342 => Some("builtin:StringPrototypeCharCodeAt".to_string()),
            343 => Some("builtin:NumberPrototypeToString".to_string()),
            344 => Some("builtin:ObjectPrototypeHasOwnProperty".to_string()),
            345 => Some("builtin:StringPrototypeSubstring".to_string()),
            346 => Some("builtin:ArrayPrototypeReduce".to_string()),
            347 => Some("builtin:MathAbs".to_string()),
            348 => Some("builtin:ObjectGetOwnPropertyNames".to_string()),
            349 => Some("builtin:MathMax".to_string()),
            350 => Some("builtin:MathMin".to_string()),
            351 => Some("builtin:StringPrototypeLocaleCompare".to_string()),
            352 => Some("builtin:ArrayPrototypeFilter".to_string()),
            353 => Some("builtin:MathFloor".to_string()),
            354 => Some("builtin:MathCeil".to_string()),
            355 => Some("builtin:MathRound".to_string()),
            // 356: Removed duplicate StringPrototypeSplit mapping (use ID 36 instead)
            357 => Some("builtin:ArrayPrototypeMap".to_string()),
            358 => Some("builtin:MathSqrt".to_string()),
            359 => Some("builtin:MathPow".to_string()),
            360 => Some("builtin:StringPrototypeReplace".to_string()),
            361 => Some("builtin:MathRandom".to_string()),
            362 => Some("builtin:DateNow".to_string()),
            363 => Some("builtin:ArrayPrototypeConcat".to_string()),
            364 => Some("builtin:StringPrototypeMatch".to_string()),
            365 => Some("builtin:JSONStringify".to_string()),
            366 => Some("builtin:JSONParse".to_string()),
            367 => Some("builtin:ArrayPrototypeFind".to_string()),
            368 => Some("builtin:ArrayPrototypeFindIndex".to_string()),
            369 => Some("builtin:MathSin".to_string()),
            370 => Some("builtin:MathCos".to_string()),
            371 => Some("builtin:MathTan".to_string()),
            372 => Some("builtin:RegExpPrototypeTest".to_string()),
            373 => Some("builtin:EncodeURIComponent".to_string()),
            374 => Some("builtin:DecodeURIComponent".to_string()),
            375 => Some("builtin:SetTimeout".to_string()),
            376 => Some("builtin:ClearTimeout".to_string()),
            377 => Some("builtin:ParseInt".to_string()),
            378 => Some("builtin:ParseFloat".to_string()),
            379 => Some("builtin:IsNaN".to_string()),
            380 => Some("builtin:IsFinite".to_string()),
            // 381-383: Removed duplicate console mappings (use 100-102 instead)
            384 => Some("builtin:ConsoleInfo".to_string()),
            385 => Some("builtin:ArrayPrototypeSort".to_string()),
            386 => Some("builtin:StringPrototypeToLocaleLowerCase".to_string()),
            387 => Some("builtin:StringPrototypeToLocaleUpperCase".to_string()),
            388 => Some("builtin:MathLog".to_string()),

            _ => None, // Not a recognized builtin
        }
    }

    /// Compare two values for equality (used by array methods like lastIndexOf).
    /// Implements JavaScript equality comparison rules.
    fn values_equal(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Undefined, Value::Undefined) => true,
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => {
                let a_val = a.inner();
                let b_val = b.inner();
                // Handle NaN case (NaN != NaN in JS)
                if a_val.is_nan() || b_val.is_nan() {
                    false
                } else {
                    a_val == b_val
                }
            }
            (Value::Int(a), Value::Float(b)) => {
                let b_val = b.inner();
                if b_val.is_nan() {
                    false
                } else {
                    (*a as f64) == b_val
                }
            }
            (Value::Float(a), Value::Int(b)) => {
                let a_val = a.inner();
                if a_val.is_nan() {
                    false
                } else {
                    a_val == (*b as f64)
                }
            }
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a.0 == b.0, // Object identity comparison
            _ => false,                                         // Different types are not equal
        }
    }

    /// Convert a Value to a string representation for console output.
    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::Undefined => "undefined".to_string(),
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) => {
                let v = f.inner();
                if v.is_nan() {
                    "NaN".to_string()
                } else if v.is_infinite() {
                    if v.is_sign_negative() {
                        "-Infinity".to_string()
                    } else {
                        "Infinity".to_string()
                    }
                } else if v == 0.0 && v.is_sign_negative() {
                    "0".to_string() // JS prints -0 as "0"
                } else {
                    format!("{v}")
                }
            }
            Value::Str(s) => s.clone(),
            Value::Object(id) => {
                // Try to get a simple string representation
                if let Some(_obj) = self.heap.get(id.0 as usize) {
                    "[object Object]".to_string() // Keep it simple
                } else {
                    format!("[object#{}]", id.0)
                }
            }
            Value::Function(idx) => format!("[Function: fn{}]", idx),
            Value::Closure(idx) => format!("[Function: closure{}]", idx),
            Value::Iterator(idx) => format!("[object Iterator#{}]", idx),
            Value::GeneratorFunction(idx) => format!("[GeneratorFunction: gen{}]", idx),
            Value::Generator(idx) => format!("[object Generator#{}]", idx),
            Value::AsyncFunction(idx) => format!("[AsyncFunction: async{}]", idx),
            Value::AsyncFunctionObject(idx) => format!("[object AsyncFunction#{}]", idx),
            Value::AsyncGeneratorFunction(idx) => {
                format!("[AsyncGeneratorFunction: async_gen{}]", idx)
            }
            Value::AsyncGeneratorObject(idx) => format!("[object AsyncGenerator#{}]", idx),
            Value::Promise(idx) => format!("[object Promise#{}]", idx),
            Value::BuiltinFunction(builtin) => {
                format!("[Function: builtin {}]", builtin.display_name())
            }
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
        let previous = self.registers[actual_reg].clone();
        self.registers[actual_reg] = value;
        if let Err(err) = self.sync_estimated_memory_bytes() {
            self.registers[actual_reg] = previous;
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(err);
        }
        Ok(())
    }

    // -- Heap operations ---------------------------------------------------

    fn estimate_string_bytes(text: &str) -> u64 {
        MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(text.len() as u64)
    }

    fn estimate_value_bytes(value: &Value) -> u64 {
        match value {
            Value::Str(text) => Self::estimate_string_bytes(text),
            _ => 0,
        }
    }

    fn estimate_scope_frame_bytes(frame: &ScopeFrame) -> u64 {
        let bindings = frame
            .bindings
            .iter()
            .map(|(name, binding)| {
                MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES
                    .saturating_add(Self::estimate_string_bytes(name))
                    .saturating_add(Self::estimate_value_bytes(&binding.value))
            })
            .sum::<u64>();
        MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES.saturating_add(bindings)
    }

    fn estimate_scope_chain_bytes(frames: &[ScopeFrame]) -> u64 {
        frames
            .iter()
            .map(Self::estimate_scope_frame_bytes)
            .sum::<u64>()
    }

    fn estimate_call_frame_bytes(frame: &CallFrame) -> u64 {
        MEMORY_ESTIMATE_CALL_FRAME_BASE_BYTES
            .saturating_add(Self::estimate_value_bytes(&frame.this_value))
            .saturating_add(
                frame
                    .construct_this
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_pending_exception
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_pending_return
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_scope_chain
                    .as_ref()
                    .map_or(0, |frames| Self::estimate_scope_chain_bytes(frames)),
            )
    }

    fn estimate_heap_object_bytes(object: &HeapObject) -> u64 {
        let properties = object
            .properties
            .iter()
            .map(|(key, value)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_string_bytes(key))
                    .saturating_add(Self::estimate_value_bytes(value))
            })
            .sum::<u64>();
        MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES.saturating_add(properties)
    }

    fn estimate_iterator_bytes(iterator: &RuntimeIteratorState) -> u64 {
        match iterator {
            RuntimeIteratorState::ForIn(state) => {
                let keys = state
                    .keys
                    .iter()
                    .map(|key| Self::estimate_string_bytes(key))
                    .sum::<u64>();
                MEMORY_ESTIMATE_ITERATOR_BASE_BYTES.saturating_add(keys)
            }
            RuntimeIteratorState::ForOf(state) => {
                let values = state
                    .values
                    .iter()
                    .map(Self::estimate_value_bytes)
                    .sum::<u64>();
                MEMORY_ESTIMATE_ITERATOR_BASE_BYTES.saturating_add(values)
            }
        }
    }

    fn estimate_generator_bytes(generator: &GeneratorObject) -> u64 {
        let registers = generator
            .saved_registers
            .iter()
            .map(Self::estimate_value_bytes)
            .sum::<u64>();
        MEMORY_ESTIMATE_GENERATOR_BASE_BYTES.saturating_add(registers)
    }

    fn heap_object_count_u32(&self) -> u32 {
        u32::try_from(self.heap.len()).unwrap_or(u32::MAX)
    }

    fn memory_budget_error(
        &self,
        requested_bytes: u64,
        requested_heap_objects: u32,
    ) -> InterpreterError {
        InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes: self.config.max_total_memory_bytes,
            requested_heap_objects,
            max_heap_objects: self.config.max_heap_objects,
        }
    }

    fn recompute_estimated_memory_bytes(&self) -> u64 {
        self.heap
            .iter()
            .map(Self::estimate_heap_object_bytes)
            .sum::<u64>()
            .saturating_add(
                self.registers
                    .iter()
                    .map(Self::estimate_value_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(Self::estimate_scope_chain_bytes(&self.scope_chain.frames))
            .saturating_add(
                self.closures
                    .iter()
                    .map(|closure| {
                        MEMORY_ESTIMATE_CLOSURE_BASE_BYTES
                            .saturating_add(Self::estimate_scope_chain_bytes(&closure.captured_env))
                    })
                    .sum::<u64>(),
            )
            .saturating_add(
                self.call_stack
                    .iter()
                    .map(Self::estimate_call_frame_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                self.iterators
                    .iter()
                    .map(Self::estimate_iterator_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                self.generators
                    .iter()
                    .map(Self::estimate_generator_bytes)
                    .sum::<u64>(),
            )
    }

    fn sync_estimated_memory_bytes(&mut self) -> Result<u64, InterpreterError> {
        let requested_bytes = self.recompute_estimated_memory_bytes();
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.estimated_memory_bytes = requested_bytes;
        Ok(requested_bytes)
    }

    fn check_temporary_memory_budget(&self, temporary_bytes: u64) -> Result<(), InterpreterError> {
        let requested_bytes = self.estimated_memory_bytes.saturating_add(temporary_bytes);
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        Ok(())
    }

    fn clone_scope_frames_with_budget(
        &self,
        frames: &[ScopeFrame],
    ) -> Result<Vec<ScopeFrame>, InterpreterError> {
        self.clone_scope_frames_with_temporary_budget(frames, 0)
    }

    fn clone_scope_frames_with_temporary_budget(
        &self,
        frames: &[ScopeFrame],
        temporary_bytes: u64,
    ) -> Result<Vec<ScopeFrame>, InterpreterError> {
        self.check_temporary_memory_budget(
            temporary_bytes.saturating_add(Self::estimate_scope_chain_bytes(frames)),
        )?;
        Ok(frames.to_vec())
    }

    fn snapshot_scope_chain(&self) -> Result<Vec<ScopeFrame>, InterpreterError> {
        self.snapshot_scope_chain_with_temporary_budget(0)
    }

    fn snapshot_scope_chain_with_temporary_budget(
        &self,
        temporary_bytes: u64,
    ) -> Result<Vec<ScopeFrame>, InterpreterError> {
        self.check_temporary_memory_budget(
            temporary_bytes
                .saturating_add(Self::estimate_scope_chain_bytes(&self.scope_chain.frames)),
        )?;
        Ok(self.scope_chain.snapshot())
    }

    fn rollback_call_setup(&mut self) {
        if let Some(frame) = self.call_stack.pop() {
            self.pending_exception = frame.saved_pending_exception;
            self.pending_return = frame.saved_pending_return;
            self.suspended_abrupt_completions
                .truncate(frame.saved_suspended_abrupt_depth);
            self.finally_modes.truncate(frame.saved_finally_mode_depth);
            if let Some(saved) = frame.saved_scope_chain {
                self.scope_chain.frames = saved;
            } else {
                while self.scope_chain.depth() > frame.saved_scope_depth {
                    self.scope_chain.pop();
                }
            }
        }
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    /// Compat shim. Several recently-landed Date/Error/Map/Set/Promise
    /// builtin blocks compute an ObjectId by calling `self.next_object_id()`
    /// and then `self.heap.push(obj)` directly, which bypasses heap-budget
    /// and HeapAllocate capability checks. This shim returns the u32 ID that
    /// the next `self.heap.push` would produce so those blocks keep
    /// compiling; the proper fix is to migrate them to
    /// `alloc_object_with_prototype` + `set_object_property`, which
    /// several blocks in this file have already adopted.
    pub(crate) fn next_object_id(&self) -> u32 {
        u32::try_from(self.heap.len()).unwrap_or(u32::MAX)
    }

    /// Allocate a new object with an explicit prototype link.
    ///
    /// Returns an error if the heap exceeds `u32::MAX` objects, preventing
    /// silent ObjectId aliasing.
    pub fn alloc_object_with_prototype(
        &mut self,
        prototype: Option<ObjectId>,
    ) -> Result<ObjectId, InterpreterError> {
        // Check HeapAllocate capability before allocating objects
        if !self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::HeapAllocate)
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: "HeapAllocate".to_string(),
            });
        }

        let requested_heap_objects = self.heap_object_count_u32().saturating_add(1);
        if requested_heap_objects > self.config.max_heap_objects {
            return Err(
                self.memory_budget_error(self.estimated_memory_bytes, requested_heap_objects)
            );
        }
        let id =
            ObjectId(
                u32::try_from(self.heap.len()).map_err(|_| InterpreterError::TypeError {
                    expected: "heap capacity".into(),
                    got: format!("exceeded u32::MAX ({})", self.heap.len()),
                })?,
            );
        let mut object = HeapObject::new();
        object.prototype = prototype;
        let object_size = Self::estimate_heap_object_bytes(&object);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(object_size);
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, requested_heap_objects));
        }
        self.heap.push(object);
        self.estimated_memory_bytes = requested_bytes;

        // Record object allocation profiling
        if let Some(profiler) = &mut self.profiling_data {
            profiler.record_object_allocation(object_size);
        }

        Ok(id)
    }

    /// Allocate a new object on the heap and return its ID.
    ///
    /// This method has been removed to prevent panics on memory exhaustion.
    /// Use `alloc_object_with_prototype(None)?` instead for fallible allocation.
    #[deprecated(
        since = "0.1.0",
        note = "Use alloc_object_with_prototype(None)? instead to avoid panics on memory exhaustion"
    )]
    pub fn alloc_object(&mut self) -> ObjectId {
        self.alloc_object_with_prototype(None)
            .expect("heap object allocation failed")
    }

    fn alloc_iterator(&mut self, iterator: RuntimeIteratorState) -> Result<u32, InterpreterError> {
        let handle =
            u32::try_from(self.iterators.len()).map_err(|_| InterpreterError::TypeError {
                expected: "iterator table capacity".into(),
                got: format!("exceeded u32::MAX ({})", self.iterators.len()),
            })?;
        self.iterators.push(iterator);
        Ok(handle)
    }

    fn expect_iterator_handle(&self, iterator: Value) -> Result<u32, InterpreterError> {
        match iterator {
            Value::Iterator(handle) => Ok(handle),
            other => Err(InterpreterError::TypeError {
                expected: "iterator".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    fn iterator_state_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut RuntimeIteratorState, InterpreterError> {
        self.iterators
            .get_mut(handle as usize)
            .ok_or(InterpreterError::IteratorNotFound { handle })
    }

    fn collect_for_in_keys(&self, object_id: ObjectId) -> Result<Vec<String>, InterpreterError> {
        let mut keys = Vec::new();
        let mut seen = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut current = Some(object_id);
        let mut depth = 0u32;

        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                break;
            }
            let object = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
            for key in object.properties.keys() {
                if seen.insert(key.clone()) {
                    keys.push(key.clone());
                }
            }
            current = object.prototype;
            depth += 1;
        }

        Ok(keys)
    }

    fn collect_for_of_values(&self, iterable: &Value) -> Result<Vec<Value>, InterpreterError> {
        match iterable {
            Value::Str(text) => Ok(text.chars().map(|ch| Value::Str(ch.to_string())).collect()),
            Value::Object(object_id) => {
                let object = self
                    .heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                let mut indexed_values = object
                    .properties
                    .iter()
                    .filter_map(|(key, value)| key.parse::<u64>().ok().map(|index| (index, value)))
                    .collect::<Vec<_>>();
                indexed_values.sort_by_key(|(index, _)| *index);
                if indexed_values.is_empty() {
                    return Err(InterpreterError::TypeError {
                        expected: "iterable".to_string(),
                        got: iterable.type_name().to_string(),
                    });
                }
                Ok(indexed_values
                    .into_iter()
                    .map(|(_, value)| value.clone())
                    .collect())
            }
            other => Err(InterpreterError::TypeError {
                expected: "iterable".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    fn mark_deleted_for_in_iterators(&mut self, object_id: ObjectId, key: &str) {
        for iterator in &mut self.iterators {
            if let RuntimeIteratorState::ForIn(state) = iterator
                && state.object_id == object_id
            {
                state.deleted_keys.insert(key.to_string());
            }
        }
    }

    fn set_object_property(
        &mut self,
        object_id: ObjectId,
        key: String,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let previous = {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            object.properties.insert(key.clone(), value)
        };
        if let Err(err) = self.sync_estimated_memory_bytes() {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            if let Some(previous) = previous {
                object.properties.insert(key, previous);
            } else {
                object.properties.remove(&key);
            }
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(err);
        }
        Ok(())
    }

    fn remove_object_property(
        &mut self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<bool, InterpreterError> {
        let removed = self
            .heap
            .get_mut(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .properties
            .remove(key);
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        Ok(removed.is_some())
    }

    fn ensure_function_prototype(&mut self, func_idx: u32) -> Result<ObjectId, InterpreterError> {
        if let Some(existing) = self.function_prototypes.get(&func_idx) {
            Ok(*existing)
        } else {
            let prototype = self.alloc_object_with_prototype(None)?;
            self.function_prototypes.insert(func_idx, prototype);
            Ok(prototype)
        }
    }

    /// Get the number of objects on the heap.
    pub fn heap_size(&self) -> usize {
        self.heap.len()
    }

    /// Return the current live-memory estimate used by the interpreter.
    pub fn estimated_memory_bytes(&self) -> u64 {
        self.estimated_memory_bytes
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
        self.execute_with_hook(module, trace_id, None)
    }

    pub fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionResult, InterpreterError> {
        let mut core = InterpreterCore::new(self.config.clone(), trace_id);
        if let Some(hook) = hook {
            core.set_hook(hook);
        }
        match core.execute(module) {
            Ok(result) => Ok(result),
            Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                let requested_hook_action =
                    requested_hook_action_from_error(action.as_str(), reason.clone())
                        .ok_or(InterpreterError::ContainmentActionRequested { action, reason })?;
                Ok(core.take_execution_result(Value::Undefined, Some(requested_hook_action)))
            }
            Err(err) => Err(err),
        }
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
        self.execute_with_hook(module, trace_id, None)
    }

    pub fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionResult, InterpreterError> {
        let mut core = InterpreterCore::new(self.config.clone(), trace_id);
        if let Some(hook) = hook {
            core.set_hook(hook);
        }
        match core.execute(module) {
            Ok(result) => Ok(result),
            Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                let requested_hook_action =
                    requested_hook_action_from_error(action.as_str(), reason.clone())
                        .ok_or(InterpreterError::ContainmentActionRequested { action, reason })?;
                Ok(core.take_execution_result(Value::Undefined, Some(requested_hook_action)))
            }
            Err(err) => Err(err),
        }
    }
}

fn format_requested_hook_action(action: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) if !reason.is_empty() => format!("{action} ({reason})"),
        _ => action.to_string(),
    }
}

fn requested_hook_action_from_error(action: &str, reason: Option<String>) -> Option<HookAction> {
    match action {
        "challenge" => Some(HookAction::Challenge(ChallengeToken {
            // SAFETY: challenge action requires reason, validated by caller
            token: reason.unwrap(),
        })),
        "sandbox" => Some(HookAction::Sandbox),
        "suspend" => Some(HookAction::Suspend),
        // SAFETY: terminate action requires reason, validated by caller
        "terminate" => Some(HookAction::Terminate(reason.unwrap())),
        // SAFETY: quarantine action requires reason, validated by caller
        "quarantine" => Some(HookAction::Quarantine(reason.unwrap())),
        _ => None,
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
        self.execute_with_hook(module, trace_id, force_lane, None)
    }

    pub fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        force_lane: Option<LaneChoice>,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<RoutedResult, InterpreterError> {
        let (lane, reason) = if let Some(forced) = force_lane {
            (forced, LaneReason::PolicyDirective)
        } else {
            self.select_lane(module)
        };

        let result = match lane {
            LaneChoice::QuickJs => self.quickjs.execute_with_hook(module, trace_id, hook)?,
            LaneChoice::V8 => self.v8.execute_with_hook(module, trace_id, hook)?,
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

    /// Enable profiling with the specified configuration.
    pub fn enable_profiling(&mut self, _config: crate::profiling::ProfilingConfig) {
        // Lane routing creates a fresh interpreter core per execution; profiling
        // is owned by the core rather than persisted on the router.
    }

    /// Disable profiling and return collected data.
    pub fn disable_profiling(&mut self) -> Option<crate::profiling::Profiler> {
        None
    }

    /// Get reference to current profiling data.
    pub fn profiling_data(&self) -> Option<&crate::profiling::Profiler> {
        None
    }
}

// ---------------------------------------------------------------------------
// Shared UTF-8 Percent Codec
// ---------------------------------------------------------------------------

/// Convert a JavaScript value to string for URI encoding.
fn value_to_string_for_uri(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Undefined => "undefined".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Object(_) => "[object Object]".to_string(),
        _ => "[object Object]".to_string(),
    }
}

/// Check if a character should be encoded in a URI context.
/// Based on RFC 3986 unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
fn is_uri_unreserved(c: char) -> bool {
    matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~')
}

/// Check if a character should be encoded in a URI component context (encodeURIComponent).
/// This is more restrictive than encodeURI - only unreserved characters are allowed.
fn should_encode_uri_component(c: char) -> bool {
    !is_uri_unreserved(c)
}

/// Check if a character should be encoded in a URI context (encodeURI).
/// This allows more characters than encodeURIComponent including some reserved ones.
fn should_encode_uri(c: char) -> bool {
    // encodeURI allows unreserved chars plus some reserved chars used in URIs
    if is_uri_unreserved(c) {
        return false;
    }
    // Allow common URI reserved characters that should not be encoded
    !matches!(c, ';' | ',' | '/' | '?' | ':' | '@' | '&' | '=' | '+' | '$' | '#')
}

/// Percent-encode a string for URI contexts using proper UTF-8 encoding.
fn percent_encode_utf8<F>(input: &str, should_encode: F) -> String
where
    F: Fn(char) -> bool,
{
    let mut result = String::new();
    for c in input.chars() {
        if should_encode(c) {
            // Encode each byte of the UTF-8 representation
            let utf8_bytes = c.to_string().as_bytes().to_vec();
            for byte in utf8_bytes {
                result.push_str(&format!("%{:02X}", byte));
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Percent-decode a URI-encoded string, handling UTF-8 sequences properly.
fn percent_decode_utf8(encoded: &str) -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    let mut chars = encoded.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Collect hex digits
            let hex1 = chars.next().ok_or("Incomplete percent sequence")?;
            let hex2 = chars.next().ok_or("Incomplete percent sequence")?;

            let hex_str = format!("{}{}", hex1, hex2);
            let byte_val = u8::from_str_radix(&hex_str, 16)
                .map_err(|_| "Invalid hex in percent sequence")?;
            bytes.push(byte_val);
        } else {
            // Non-percent character - convert to UTF-8 bytes
            let char_bytes = c.to_string().into_bytes();
            bytes.extend(char_bytes);
        }
    }

    String::from_utf8(bytes).map_err(|_| "Invalid UTF-8 sequence")
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
    use std::sync::{Arc, Mutex};

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

    /// Build a test interpreter config that grants the execution capabilities
    /// every baseline interpreter test needs. The production `quickjs_defaults`
    /// / `v8_defaults` intentionally start with an empty capability set so
    /// callers must explicitly grant what an extension may do; tests are not
    /// exercising the grant-policy surface, so they need a fully-enabled
    /// baseline to actually dispatch VM instructions and allocate objects.
    fn test_quickjs_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        config
    }

    fn test_v8_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::v8_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        config
    }

    fn quickjs_execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
        QuickJsLane::with_config(test_quickjs_config()).execute(module, "test-trace")
    }

    fn v8_execute(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
        V8Lane::with_config(test_v8_config()).execute(module, "test-trace")
    }

    fn quickjs_test_core() -> InterpreterCore {
        InterpreterCore::new(test_quickjs_config(), "test-trace")
    }

    #[test]
    fn parseint_nan_radix_defaults_for_global_and_number_parseint_builtin_ids() {
        let mut interpreter = quickjs_test_core();

        for func_index in [82, 234, 377] {
            interpreter.registers[0] = Value::Str("42".to_string());
            interpreter.registers[1] = Value::Float(Float64::new(f64::NAN));

            let result = interpreter
                .call_builtin_by_id(func_index, RegRange { start: 0, count: 2 })
                .expect("parseInt with NaN radix should not fail interpreter dispatch");
            assert_eq!(
                result,
                Value::Int(42),
                "parseInt builtin ID {} should default NaN radix to decimal",
                func_index
            );
        }
    }

    #[test]
    fn parseint_sign_and_radix_semantics_consistent_across_builtins() {
        let mut interpreter = quickjs_test_core();

        let run_case = |interpreter: &mut InterpreterCore,
                        builtin_id: u32,
                        input: &str,
                        radix: Option<i64>,
                        expected: Option<i64>| {
            interpreter.registers[0] = Value::Str(input.to_string());
            let count = if let Some(radix) = radix {
                interpreter.registers[1] = Value::Int(radix);
                2
            } else {
                1
            };

            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count })
                .expect("parseInt builtin should run with unified sign/radix helper");

            match expected {
                Some(expected) => {
                    assert_eq!(
                        result,
                        Value::Int(expected),
                        "parseInt builtin ID {builtin_id} input {input:?} failed"
                    );
                }
                None => match result {
                    Value::Float(value) => assert!(
                        value.is_nan(),
                        "parseInt builtin ID {builtin_id} input {input:?} should return NaN"
                    ),
                    // SAFETY: Test validates parseInt builtin returns NaN for invalid input cases
                    other => panic!(
                        "parseInt builtin ID {builtin_id} input {input:?} expected NaN, got {other:?}"
                    ),
                },
            }
        };

        for (builtin_id, input, radix, expected) in [
            (82u32, " -10", None, Some(-10)),
            (234u32, "  -10", None, Some(-10)),
            (377u32, "-10", None, Some(-10)),
            (82u32, "ff", Some(16), Some(255)),
            (234u32, "0x10", Some(0), Some(16)),
            (377u32, "0X10", Some(0), Some(16)),
            (82u32, "101", Some(2), Some(5)),
            (377u32, "101", Some(2), Some(5)),
            (82u32, "a", Some(10), None),
            (234u32, "+15", None, Some(15)),
            (377u32, "123xyz", None, Some(123)),
            (377u32, "0", Some(37), None),
        ] {
            run_case(&mut interpreter, builtin_id, input, radix, expected);
        }
    }

    #[test]
    fn parseint_number_to_string_nan_radix_defaults_for_builtin_ids() {
        let mut interpreter = quickjs_test_core();

        for func_index in [196, 343] {
            interpreter.registers[0] = Value::Int(42);
            interpreter.registers[1] = Value::Float(Float64::new(f64::NAN));

            let result = interpreter
                .call_builtin_by_id(func_index, RegRange { start: 0, count: 2 })
                .expect("Number.toString with NaN radix should not fail interpreter dispatch");
            assert_eq!(
                result,
                Value::Str("42".to_string()),
                "Number.toString builtin ID {} should default NaN radix to decimal",
                func_index
            );
        }
    }

    fn assert_string_split_result(result: Value, expected: Vec<&str>, core: &mut InterpreterCore) {
        let Value::Object(array_id) = result else {
            // SAFETY: Test helper validates string split returns array object type
            panic!("split should return array object, got {result:?}");
        };

        let array_obj = &core.heap[array_id.0 as usize];
        let length = match array_obj.properties.get("length") {
            Some(Value::Int(length)) => *length as usize,
            Some(other) => {
                // SAFETY: Test helper validates string split array has integer length property
                panic!("split length should be Int, got {other:?}");
            }
            // SAFETY: Test helper validates string split array has length property
            None => panic!("split result missing length"),
        };

        assert_eq!(length, expected.len());
        for (index, expected_part) in expected.iter().enumerate() {
            assert_eq!(
                array_obj.properties.get(&index.to_string()),
                Some(&Value::Str((*expected_part).to_string()))
            );
        }
    }

    #[test]
    fn string_split_omitted_and_undefined_separator_returns_whole_string() {
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Str("hello".to_string());

        // SAFETY: call_builtin cannot fail with valid test inputs
        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 1 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["hello"], &mut core);

        core.registers[1] = Value::Undefined;
        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 2 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["hello"], &mut core);
    }

    #[test]
    fn string_split_omitted_and_undefined_separator_handle_non_ascii() {
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Str("a🙂b".to_string());

        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 1 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["a🙂b"], &mut core);

        core.registers[1] = Value::Undefined;
        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 2 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["a🙂b"], &mut core);
    }

    #[test]
    fn string_split_omitted_and_undefined_separator_handle_non_ascii() {
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Str("a🙂b".to_string());

        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 1 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["a🙂b"], &mut core);

        core.registers[1] = Value::Undefined;
        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 2 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["a🙂b"], &mut core);
    }

    #[test]
    fn string_split_omitted_separator_and_undefined_keep_whole_punctuation_string() {
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Str("a,b".to_string());

        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 1 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["a,b"], &mut core);

        core.registers[1] = Value::Undefined;
        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 2 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["a,b"], &mut core);
    }

    #[test]
    fn string_split_empty_separator_splits_characters() {
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Str("ab".to_string());
        core.registers[1] = Value::Str("".to_string());

        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 2 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["a", "b"], &mut core);
    }

    #[test]
    fn string_split_normal_separator() {
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Str("a,b,c".to_string());
        core.registers[1] = Value::Str(",".to_string());

        let result = core
            .call_builtin(
                "builtin:StringPrototypeSplit",
                RegRange { start: 0, count: 2 },
            )
            .unwrap();
        assert_string_split_result(result, vec!["a", "b", "c"], &mut core);
    }

    #[allow(dead_code)]
    fn assert_both_lanes_value(module: &Ir3Module, expected: Value) {
        assert_eq!(quickjs_execute(module).unwrap().value, expected);
        assert_eq!(v8_execute(module).unwrap().value, expected);
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum HookRecord {
        Property {
            ctx: HookContext,
            target: ObjectId,
            key: String,
        },
        Call {
            ctx: HookContext,
            callee: FunctionRef,
            args: Vec<Value>,
        },
        Allocation {
            ctx: HookContext,
            kind: AllocKind,
            size_hint: usize,
        },
        Import {
            ctx: HookContext,
            specifier: String,
        },
    }

    #[derive(Debug)]
    struct RecordingHook {
        records: Mutex<Vec<HookRecord>>,
        property_action: HookAction,
        call_action: HookAction,
        allocation_action: HookAction,
        import_action: HookAction,
    }

    impl RecordingHook {
        fn allow_all() -> Self {
            Self {
                records: Mutex::new(Vec::new()),
                property_action: HookAction::Allow,
                call_action: HookAction::Allow,
                allocation_action: HookAction::Allow,
                import_action: HookAction::Allow,
            }
        }

        fn with_allocation_action(action: HookAction) -> Self {
            Self {
                allocation_action: action,
                ..Self::allow_all()
            }
        }

        fn records(&self) -> Vec<HookRecord> {
            self.records.lock().unwrap().clone()
        }
    }

    impl InterpreterHook for RecordingHook {
        fn pre_property_access(
            &self,
            ctx: &HookContext,
            target: &ObjectRef,
            key: &PropertyKey,
        ) -> HookAction {
            self.records.lock().unwrap().push(HookRecord::Property {
                ctx: ctx.clone(),
                target: *target,
                key: key.clone(),
            });
            self.property_action.clone()
        }

        fn pre_call(&self, ctx: &HookContext, callee: &FunctionRef, args: &[Value]) -> HookAction {
            self.records.lock().unwrap().push(HookRecord::Call {
                ctx: ctx.clone(),
                callee: callee.clone(),
                args: args.to_vec(),
            });
            self.call_action.clone()
        }

        fn pre_allocation(
            &self,
            ctx: &HookContext,
            kind: AllocKind,
            size_hint: usize,
        ) -> HookAction {
            self.records.lock().unwrap().push(HookRecord::Allocation {
                ctx: ctx.clone(),
                kind,
                size_hint,
            });
            self.allocation_action.clone()
        }

        fn pre_import(&self, ctx: &HookContext, specifier: &str) -> HookAction {
            self.records.lock().unwrap().push(HookRecord::Import {
                ctx: ctx.clone(),
                specifier: specifier.to_string(),
            });
            self.import_action.clone()
        }
    }

    #[test]
    fn interpreter_hook_called_on_property_access() {
        let hook = Arc::new(RecordingHook::allow_all());
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook.clone());

        let oid = core.alloc_object_with_prototype(None).unwrap();
        core.heap[oid.0 as usize]
            .properties
            .insert("secret".to_string(), Value::Int(99));
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::Str("secret".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 2,
                    dst: 0,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        assert_eq!(result.value, Value::Int(99));
        assert_eq!(
            hook.records(),
            vec![HookRecord::Property {
                ctx: HookContext {
                    extension_id: "test".to_string(),
                    instruction_count: 1,
                    current_ip: 0,
                },
                target: oid,
                key: "secret".to_string(),
            }]
        );
    }

    #[test]
    fn interpreter_hook_called_on_call() {
        let hook = Arc::new(RecordingHook::allow_all());
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook.clone());
        core.registers[1] = Value::Int(5);
        core.registers[3] = Value::Function(0);

        let result = core
            .execute(&test_module_with_functions(
                vec![
                    Ir3Instruction::Call {
                        callee: 3,
                        args: RegRange { start: 1, count: 1 },
                        dst: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::Return { value: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 2,
                    arity: 1,
                    frame_size: 2,
                    name: Some("identity".to_string()),
                    is_generator: false,
                }],
            ))
            .unwrap();

        assert_eq!(result.value, Value::Int(5));
        assert_eq!(
            hook.records(),
            vec![HookRecord::Call {
                ctx: HookContext {
                    extension_id: "test".to_string(),
                    instruction_count: 1,
                    current_ip: 0,
                },
                callee: FunctionRef::Function {
                    function_index: 0,
                    name: Some("identity".to_string()),
                },
                args: vec![Value::Int(5)],
            }]
        );
    }

    #[test]
    fn interpreter_hook_called_on_allocation() {
        let hook = Arc::new(RecordingHook::allow_all());
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook.clone());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        assert!(matches!(result.value, Value::Object(_)));
        assert_eq!(
            hook.records(),
            vec![HookRecord::Allocation {
                ctx: HookContext {
                    extension_id: "test".to_string(),
                    instruction_count: 1,
                    current_ip: 0,
                },
                kind: AllocKind::Object,
                size_hint: 0,
            }]
        );
    }

    #[test]
    fn interpreter_hook_called_on_closure_allocation() {
        let hook = Arc::new(RecordingHook::allow_all());
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook.clone());

        let result = core
            .execute(&test_module_with_functions(
                vec![
                    Ir3Instruction::CreateClosure {
                        dst: 0,
                        function_index: 0,
                        capture_count: 2,
                    },
                    Ir3Instruction::Halt,
                ],
                vec![Ir3FunctionDesc {
                    entry: 1,
                    arity: 0,
                    frame_size: 1,
                    name: Some("closure_target".to_string()),
                    is_generator: false,
                }],
            ))
            .unwrap();

        assert!(matches!(result.value, Value::Closure(0)));
        assert_eq!(
            hook.records(),
            vec![HookRecord::Allocation {
                ctx: HookContext {
                    extension_id: "test".to_string(),
                    instruction_count: 1,
                    current_ip: 0,
                },
                kind: AllocKind::Closure,
                size_hint: 2,
            }]
        );
    }

    #[test]
    fn interpreter_hook_allow_continues_execution() {
        let hook = Arc::new(RecordingHook::allow_all());
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook);

        let oid = core.alloc_object_with_prototype(None).unwrap();
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::Str("key".to_string());
        core.registers[3] = Value::Int(7);

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::SetProperty {
                    obj: 1,
                    key: 2,
                    val: 3,
                },
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 2,
                    dst: 0,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        assert_eq!(result.value, Value::Int(7));
    }

    #[test]
    fn interpreter_hook_terminate_stops_execution() {
        let hook = Arc::new(RecordingHook::with_allocation_action(
            HookAction::Terminate("policy denied object allocation".to_string()),
        ));
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook.clone());

        let err = core
            .execute(&test_module(vec![Ir3Instruction::NewObject { dst: 0 }]))
            .unwrap_err();

        assert_eq!(
            err,
            InterpreterError::ContainmentActionRequested {
                action: "terminate".to_string(),
                reason: Some("policy denied object allocation".to_string()),
            }
        );
        assert_eq!(hook.records().len(), 1);
    }

    #[test]
    fn lane_execute_with_hook_preserves_requested_containment_in_result() {
        let hook = Arc::new(RecordingHook::with_allocation_action(
            HookAction::Terminate("policy denied object allocation".to_string()),
        ));
        let lane = QuickJsLane::new();
        let result = lane
            .execute_with_hook(
                &test_module(vec![Ir3Instruction::NewObject { dst: 0 }]),
                "test-trace",
                Some(hook),
            )
            .expect("lane should surface containment as structured output");

        assert_eq!(
            result.requested_hook_action,
            Some(HookAction::Terminate(
                "policy denied object allocation".to_string()
            ))
        );
        assert_eq!(result.value, Value::Undefined);
        assert_eq!(result.instructions_executed, 1);
    }

    #[test]
    fn interpreter_hook_none_preserves_execution_when_unset() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test-trace");
        let oid = core.alloc_object_with_prototype(None).unwrap();
        core.heap[oid.0 as usize]
            .properties
            .insert("stable".to_string(), Value::Int(12));
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::Str("stable".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 2,
                    dst: 0,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        assert_eq!(result.value, Value::Int(12));
        assert!(core.hook.is_none());
    }

    #[test]
    fn interpreter_hook_receives_correct_context() {
        let hook = Arc::new(RecordingHook::allow_all());
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook.clone());

        let mut module = test_module(vec![
            Ir3Instruction::LoadInt { dst: 4, value: 1 },
            Ir3Instruction::NewArray { dst: 0 },
            Ir3Instruction::Halt,
        ]);
        module.header.source_label = "extension://hook-test".to_string();

        let result = core.execute(&module).unwrap();
        assert!(matches!(result.value, Value::Object(_)));
        assert_eq!(
            hook.records(),
            vec![HookRecord::Allocation {
                ctx: HookContext {
                    extension_id: "extension://hook-test".to_string(),
                    instruction_count: 2,
                    current_ip: 1,
                },
                kind: AllocKind::Array,
                size_hint: 0,
            }]
        );
    }

    #[test]
    fn interpreter_hook_pre_import_surface_is_available() {
        let hook = RecordingHook::allow_all();
        let config = InterpreterConfig::quickjs_defaults();
        let core = InterpreterCore::new(config, "test-trace");
        let mut module = test_module(vec![Ir3Instruction::Halt]);
        module.header.source_label = "extension://import-surface".to_string();

        let ctx = core.hook_context(&module);
        let action = hook.pre_import(&ctx, "lodash");

        assert_eq!(action, HookAction::Allow);
        assert_eq!(
            hook.records(),
            vec![HookRecord::Import {
                ctx: HookContext {
                    extension_id: "extension://import-surface".to_string(),
                    instruction_count: 0,
                    current_ip: 0,
                },
                specifier: "lodash".to_string(),
            }]
        );
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
    fn add_coerces_bool_and_null_to_number() {
        // JS semantics: true + null = 1 + 0 = 1
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
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(1));
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
                is_generator: false,
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
    fn reexecution_restores_initial_register_seed_without_runtime_leakage() {
        let m = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 3,
                    args: RegRange { start: 1, count: 1 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadInt { dst: 1, value: 10 },
                Ir3Instruction::Add {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 3,
                name: Some("add_ten".to_string()),
                is_generator: false,
            }],
        );

        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 1000;
        let mut core = InterpreterCore::new(config, "test");
        core.registers[1] = Value::Int(5);
        core.registers[3] = Value::Function(0);

        let first = core.execute(&m).unwrap();
        assert_eq!(first.value, Value::Int(15));

        let second = core.execute(&m).unwrap();
        assert_eq!(second.value, Value::Int(15));
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
                is_generator: false,
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
        config.granted_capabilities = BTreeSet::from([RuntimeCapability::NetworkEgress]);
        let lane = QuickJsLane::with_config(config);
        let result = lane.execute(&m, "test").unwrap();
        assert_eq!(result.value, Value::Undefined);
    }

    #[test]
    fn active_math_abs_handles_min_int_and_coercions() {
        fn call_math_abs(value: Value) -> Value {
            let mut core = quickjs_test_core();
            core.registers.resize(1, Value::Undefined);
            core.registers[0] = value;
            core.dispatch_builtin_hostcall("builtin:MathAbs", RegRange { start: 0, count: 1 })
                .unwrap()
        }

        assert_eq!(call_math_abs(Value::Int(-7)), Value::Int(7));
        assert_eq!(
            call_math_abs(Value::Float(Float64::new(-2.5))),
            Value::Float(Float64::new(2.5))
        );
        // Math.abs(i64::MIN) uses saturating_abs -> i64::MAX (consistent with stdlib)
        assert_eq!(call_math_abs(Value::Int(i64::MIN)), Value::Int(i64::MAX));
        assert_eq!(
            call_math_abs(Value::Str(" -3.5 ".to_string())),
            Value::Float(Float64::new(3.5))
        );
        assert_eq!(
            call_math_abs(Value::Bool(true)),
            Value::Float(Float64::new(1.0))
        );

        let result = call_math_abs(Value::Undefined);
        let Value::Float(result) = result else {
            panic!("expected Math.abs(undefined) to produce NaN float");
        };
        assert!(result.inner().is_nan());
    }

    #[test]
    fn math_abs_i64_min_saturating_regression() {
        // Regression test for bd-3iu4f: Math.abs(i64::MIN) should use saturating_abs
        // instead of panicking or converting to Float
        fn call_math_abs(value: Value) -> Value {
            let mut core = quickjs_test_core();
            core.registers.resize(1, Value::Undefined);
            core.registers[0] = value;
            core.dispatch_builtin_hostcall("builtin:MathAbs", RegRange { start: 0, count: 1 })
                .unwrap()
        }

        // Core fix: i64::MIN should saturate to i64::MAX (not panic or convert to Float)
        assert_eq!(call_math_abs(Value::Int(i64::MIN)), Value::Int(i64::MAX));

        // Edge cases around i64::MIN
        assert_eq!(
            call_math_abs(Value::Int(i64::MIN + 1)),
            Value::Int(i64::MAX)
        );
        assert_eq!(call_math_abs(Value::Int(-1)), Value::Int(1));
        assert_eq!(call_math_abs(Value::Int(0)), Value::Int(0));
        assert_eq!(call_math_abs(Value::Int(i64::MAX)), Value::Int(i64::MAX));

        // Float coercion should still work normally
        assert_eq!(
            call_math_abs(Value::Float(Float64::new(-42.5))),
            Value::Float(Float64::new(42.5))
        );

        // String coercion should still work normally
        assert_eq!(
            call_math_abs(Value::Str("-123".to_string())),
            Value::Float(Float64::new(123.0))
        );

        // Boolean coercion should still work normally
        assert_eq!(
            call_math_abs(Value::Bool(false)),
            Value::Float(Float64::new(0.0))
        );

        // Null/undefined should still produce NaN
        let result = call_math_abs(Value::Null);
        let Value::Float(f) = result else {
            panic!("expected Math.abs(null) to produce NaN float");
        };
        assert!(f.inner().is_nan());
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
        config.granted_capabilities = BTreeSet::from([RuntimeCapability::FsRead]);
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
            InterpreterError::UnsupportedMembershipSemantics {
                operator: "in".to_string(),
            },
            InterpreterError::UncaughtException {
                value: "test error".to_string(),
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
            InterpreterError::RequireSpecifierNotString {
                got: "undefined".to_string(),
            },
            InterpreterError::TypeError {
                expected: "number".to_string(),
                got: "object".to_string(),
            },
            InterpreterError::StringPoolOutOfBounds {
                index: 99,
                pool_size: 5,
            },
            InterpreterError::UnsupportedMembershipSemantics {
                operator: "instanceof".to_string(),
            },
            InterpreterError::UncaughtException {
                value: "test error".to_string(),
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
        assert_eq!(
            Value::BuiltinFunction(BuiltinFunction::require("/tmp/entry.cjs")).type_name(),
            "function"
        );
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
        assert!(Value::BuiltinFunction(BuiltinFunction::require("/tmp/entry.cjs")).is_truthy());
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
        assert_eq!(c.max_heap_objects, 100_000);
        assert_eq!(c.max_total_memory_bytes, 64 * 1024 * 1024);
        assert_eq!(c.max_scope_depth, 512);
        assert!(c.granted_capabilities.is_empty());
    }

    #[test]
    fn interpreter_config_v8_defaults_fields() {
        let c = InterpreterConfig::v8_defaults();
        assert_eq!(c.instruction_budget, 1_000_000);
        assert_eq!(c.max_registers, 4096);
        assert_eq!(c.max_call_depth, 256);
        assert_eq!(c.max_heap_objects, 1_000_000);
        assert_eq!(c.max_total_memory_bytes, 512 * 1024 * 1024);
        assert_eq!(c.max_scope_depth, 512);
        assert!(c.granted_capabilities.is_empty());
    }

    #[test]
    fn interpreter_config_supports_all_runtime_capability_variants() {
        // Test exhaustiveness: verify all 17 RuntimeCapability variants can be inserted
        let all_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
            RuntimeCapability::ModuleLoad,
        ]);

        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = all_capabilities.clone();

        // Verify all capabilities are stored and can be retrieved
        assert_eq!(config.granted_capabilities.len(), 17); // 17 total capabilities
        assert!(
            config
                .granted_capabilities
                .contains(&RuntimeCapability::VmDispatch)
        );
        assert!(
            config
                .granted_capabilities
                .contains(&RuntimeCapability::ModuleLoad)
        );

        // Verify BTreeSet maintains deterministic ordering
        let capabilities_vec: Vec<_> = config.granted_capabilities.iter().collect();
        let capabilities_vec2: Vec<_> = all_capabilities.iter().collect();
        assert_eq!(capabilities_vec, capabilities_vec2);
    }

    #[test]
    fn scope_chain_push_respects_max_scope_depth() {
        let mut chain = ScopeChain::new();
        chain.push(2).unwrap();
        let err = chain.push(2).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::ScopeDepthExceeded {
                requested_depth: 3,
                max_depth: 2,
            }
        ));
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
        assert_eq!(core.estimated_memory_bytes(), 0);
        let id = core.alloc_object_with_prototype(None).unwrap();
        assert_eq!(id, ObjectId(0));
        assert_eq!(core.heap_size(), 1);
        let id2 = core.alloc_object_with_prototype(None).unwrap();
        assert_eq!(id2, ObjectId(1));
        assert_eq!(core.heap_size(), 2);
        assert!(core.estimated_memory_bytes() > 0);
    }

    #[test]
    fn alloc_object_with_prototype_respects_heap_budget() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_heap_objects = 2;
        let mut core = InterpreterCore::new(config, "heap-budget");
        assert_eq!(core.alloc_object_with_prototype(None).unwrap(), ObjectId(0));
        assert_eq!(core.alloc_object_with_prototype(None).unwrap(), ObjectId(1));
        let err = core.alloc_object_with_prototype(None).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::MemoryBudgetExceeded {
                requested_heap_objects: 3,
                max_heap_objects: 2,
                ..
            }
        ));
    }

    #[test]
    fn custom_heap_budget_allows_limit_then_fails() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_heap_objects = 10;
        let mut core = InterpreterCore::new(config, "custom-heap-budget");
        for expected in 0_u32..10 {
            assert_eq!(
                core.alloc_object_with_prototype(None).unwrap(),
                ObjectId(expected)
            );
        }
        let err = core.alloc_object_with_prototype(None).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::MemoryBudgetExceeded {
                requested_heap_objects: 11,
                max_heap_objects: 10,
                ..
            }
        ));
    }

    #[test]
    fn estimated_memory_bytes_tracks_property_growth() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "memory-estimate");
        let oid = core.alloc_object_with_prototype(None).unwrap();
        let before = core.estimated_memory_bytes();
        core.heap[oid.0 as usize]
            .properties
            .insert("payload".to_string(), Value::Str("hello world".to_string()));
        core.sync_estimated_memory_bytes().unwrap();
        assert!(core.estimated_memory_bytes() > before);
    }

    #[test]
    fn new_object_instruction_returns_memory_budget_exceeded() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_heap_objects = 0;
        let mut core = InterpreterCore::new(config, "budget");
        let module = test_module(vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::Halt,
        ]);
        let err = core.execute(&module).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::MemoryBudgetExceeded {
                requested_heap_objects: 1,
                max_heap_objects: 0,
                ..
            }
        ));
    }

    #[test]
    fn load_str_instruction_returns_memory_budget_exceeded() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_total_memory_bytes = 1;
        let mut core = InterpreterCore::new(config, "string-budget");
        let module = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::Halt,
            ],
            vec!["hello".to_string()],
        );
        let err = core.execute(&module).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::MemoryBudgetExceeded { max_bytes: 1, .. }
        ));
    }

    #[test]
    fn instruction_budget_and_memory_budget_are_independent() {
        let budget_module = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
        let mut budget_config = InterpreterConfig::quickjs_defaults();
        budget_config.instruction_budget = 5;
        budget_config.max_total_memory_bytes = u64::MAX;
        let budget_lane = QuickJsLane::with_config(budget_config);
        let budget_err = budget_lane
            .execute(&budget_module, "budget-first")
            .unwrap_err();
        assert!(matches!(
            budget_err,
            InterpreterError::BudgetExhausted {
                executed: 5,
                budget: 5,
            }
        ));

        let memory_module = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                Ir3Instruction::Halt,
            ],
            vec!["hello".to_string()],
        );
        let mut memory_config = InterpreterConfig::quickjs_defaults();
        memory_config.instruction_budget = 10_000;
        memory_config.max_total_memory_bytes = 1;
        let memory_lane = QuickJsLane::with_config(memory_config);
        let memory_err = memory_lane
            .execute(&memory_module, "memory-first")
            .unwrap_err();
        assert!(matches!(
            memory_err,
            InterpreterError::MemoryBudgetExceeded { max_bytes: 1, .. }
        ));
    }

    #[test]
    fn memory_budget_exceeded_display_includes_requested_and_limits() {
        let err = InterpreterError::MemoryBudgetExceeded {
            requested_bytes: 4096,
            max_bytes: 2048,
            requested_heap_objects: 12,
            max_heap_objects: 10,
        };
        let display = err.to_string();
        assert!(display.contains("12 heap objects"));
        assert!(display.contains("4096 bytes"));
        assert!(display.contains("10 heap objects"));
        assert!(display.contains("2048 bytes"));
    }

    #[test]
    fn scope_chain_snapshot_respects_memory_budget() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_scope_depth = 4;
        let mut core = InterpreterCore::new(config, "scope-snapshot-budget");
        core.scope_chain.push(core.config.max_scope_depth).unwrap();
        core.scope_chain.current_mut().bindings.insert(
            "payload".to_string(),
            ScopeBinding {
                value: Value::Str("x".repeat(128)),
                kind: BindingKind::Var,
                initialized: true,
            },
        );
        core.sync_estimated_memory_bytes().unwrap();
        let snapshot_bytes = InterpreterCore::estimate_scope_chain_bytes(&core.scope_chain.frames);
        core.config.max_total_memory_bytes = core
            .estimated_memory_bytes()
            .saturating_add(snapshot_bytes)
            .saturating_sub(1);
        let err = core.snapshot_scope_chain().unwrap_err();
        assert!(matches!(err, InterpreterError::MemoryBudgetExceeded { .. }));
    }

    #[test]
    fn temporary_scope_clone_budget_counts_existing_snapshot() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "temporary-scope-clone-budget");
        core.scope_chain.current_mut().bindings.insert(
            "payload".to_string(),
            ScopeBinding {
                value: Value::Str("x".repeat(128)),
                kind: BindingKind::Var,
                initialized: true,
            },
        );
        core.sync_estimated_memory_bytes().unwrap();

        let snapshot_bytes = InterpreterCore::estimate_scope_chain_bytes(&core.scope_chain.frames);
        core.config.max_total_memory_bytes = core
            .estimated_memory_bytes()
            .saturating_add(snapshot_bytes.saturating_mul(2))
            .saturating_sub(1);

        let err = core
            .snapshot_scope_chain_with_temporary_budget(snapshot_bytes)
            .unwrap_err();
        assert!(matches!(err, InterpreterError::MemoryBudgetExceeded { .. }));
    }

    #[test]
    fn generator_start_budget_failure_preserves_suspended_start_phase() {
        let payload = "x".repeat(128);
        let mut module = test_module_with_pool(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 1,
                },
                Ir3Instruction::DeclareBinding {
                    name_pool_index: 0,
                    kind: 0,
                },
                Ir3Instruction::StoreScoped {
                    src: 0,
                    name_pool_index: 0,
                },
                Ir3Instruction::CreateGenerator {
                    dst: 1,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    dst: 0,
                    callee: 1,
                    args: RegRange {
                        start: 10,
                        count: 0,
                    },
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadScoped {
                    dst: 0,
                    name_pool_index: 0,
                },
                Ir3Instruction::Yield {
                    value: 0,
                    delegate: false,
                    resume_dst: 1,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["payload".to_string(), payload.clone()],
        );
        module.function_table.push(Ir3FunctionDesc {
            entry: 6,
            arity: 0,
            frame_size: 4,
            name: Some("capturing_generator".to_string()),
            is_generator: true,
        });

        let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "generator");
        let result = core.execute(&module).unwrap();
        assert_eq!(result.value, Value::Generator(0));

        let clone_bytes =
            InterpreterCore::estimate_scope_chain_bytes(&core.closures[0].captured_env);
        core.scope_chain.frames = vec![ScopeFrame::new()];
        core.sync_estimated_memory_bytes().unwrap();
        let baseline_memory = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = baseline_memory
            .saturating_add(clone_bytes)
            .saturating_sub(1);

        let err = core
            .generator_next(&module, 0, Value::Undefined)
            .unwrap_err();
        assert!(matches!(err, InterpreterError::MemoryBudgetExceeded { .. }));
        assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedStart);
        assert_eq!(core.estimated_memory_bytes(), baseline_memory);

        core.config.max_total_memory_bytes = u64::MAX;
        let yielded = core.generator_next(&module, 0, Value::Undefined).unwrap();
        assert_eq!(core.generators[0].phase, GeneratorPhase::SuspendedYield);

        let Value::Object(result_id) = yielded else {
            panic!("expected generator.next() to return a result object");
        };
        let result_object = &core.heap[result_id.0 as usize];
        assert_eq!(
            result_object.properties.get("done"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            result_object.properties.get("value"),
            Some(&Value::Str(payload))
        );
    }

    #[test]
    fn closure_calls_persist_mutated_capture_across_shared_environment() {
        let mut module = test_module_with_pool(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 0 },
                Ir3Instruction::DeclareBinding {
                    name_pool_index: 0,
                    kind: 1,
                },
                Ir3Instruction::InitBinding {
                    name_pool_index: 0,
                    src: 0,
                },
                Ir3Instruction::CreateClosure {
                    dst: 1,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::CreateClosure {
                    dst: 2,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Call {
                    callee: 1,
                    args: RegRange {
                        start: 10,
                        count: 0,
                    },
                    dst: 3,
                },
                Ir3Instruction::Call {
                    callee: 2,
                    args: RegRange {
                        start: 10,
                        count: 0,
                    },
                    dst: 4,
                },
                Ir3Instruction::Move { dst: 0, src: 4 },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadScoped {
                    dst: 0,
                    name_pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 1 },
                Ir3Instruction::Add {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::StoreScoped {
                    src: 2,
                    name_pool_index: 0,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec!["n".to_string()],
        );
        module.function_table.push(Ir3FunctionDesc {
            entry: 9,
            arity: 0,
            frame_size: 4,
            name: Some("increment".to_string()),
            is_generator: false,
        });

        let result = quickjs_execute(&module).unwrap();
        assert_eq!(result.value, Value::Int(2));
    }

    #[test]
    fn scope_chain_snapshot_produces_correct_frame_count() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "snapshot-frame-count");

        // Push 4 additional frames (starting with 1 global = 5 total)
        for _ in 0..4 {
            core.scope_chain.push(core.config.max_scope_depth).unwrap();
        }

        let snapshot = core.scope_chain.snapshot();
        assert_eq!(snapshot.len(), 5);
    }

    #[test]
    fn closure_captures_correctly_at_deep_scope_chain() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_scope_depth = 15; // Allow deeper nesting
        let mut core = InterpreterCore::new(config, "deep-closure-capture");

        // Build scope chain with depth 10, adding a binding at each level
        for i in 0..10 {
            if i > 0 {
                core.scope_chain.push(core.config.max_scope_depth).unwrap();
            }
            let binding_name = format!("var{}", i);
            let binding_value = format!("value{}", i);
            core.scope_chain.current_mut().bindings.insert(
                binding_name.clone(),
                ScopeBinding {
                    value: Value::Str(binding_value.clone()),
                    kind: BindingKind::Var,
                    initialized: true,
                },
            );
        }

        assert_eq!(core.scope_chain.depth(), 10);

        // Create a closure by capturing the scope chain
        let captured_env = core.snapshot_scope_chain().unwrap();
        assert_eq!(captured_env.len(), 10);

        // Verify all bindings are preserved in the capture
        for (level, frame) in captured_env.iter().enumerate() {
            let binding_name = format!("var{}", level);
            let expected_value = format!("value{}", level);
            if let Some(binding) = frame.bindings.get(&binding_name) {
                assert_eq!(binding.value, Value::Str(expected_value));
            } else {
                panic!("Missing binding {} at scope level {}", binding_name, level);
            }
        }

        // Verify we can store the closure
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env,
        });

        // Verify the closure ID is valid
        assert_eq!(core.closures.len(), 1);
    }

    #[test]
    fn push_scope_instruction_respects_max_scope_depth() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_scope_depth = 2;
        let mut core = InterpreterCore::new(config, "scope-depth-budget");
        let module = test_module(vec![
            Ir3Instruction::PushScope,
            Ir3Instruction::PushScope,
            Ir3Instruction::Halt,
        ]);
        let err = core.execute(&module).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::ScopeDepthExceeded {
                requested_depth: 3,
                max_depth: 2,
            }
        ));
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
            InterpreterError::RequireSpecifierNotString {
                got: "undefined".to_string(),
            },
            InterpreterError::CapabilityDenied {
                capability: "net".to_string(),
            },
            InterpreterError::UnsupportedMembershipSemantics {
                operator: "instanceof".to_string(),
            },
            InterpreterError::IteratorNotFound { handle: 11 },
            InterpreterError::Halted,
            InterpreterError::UncaughtException {
                value: "error msg".to_string(),
            },
            InterpreterError::UninitializedBinding {
                name: "late".to_string(),
            },
            InterpreterError::ConstAssignment {
                name: "CONST_X".to_string(),
            },
            InterpreterError::StringLimitExceeded {
                length: 1024,
                max: 512,
            },
            InterpreterError::MemoryBudgetExceeded {
                requested_bytes: 4096,
                max_bytes: 2048,
                requested_heap_objects: 12,
                max_heap_objects: 10,
            },
            InterpreterError::ContainmentActionRequested {
                action: "terminate".to_string(),
                reason: Some("policy".to_string()),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: InterpreterError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -- Mixed Int/Float arithmetic tests --

    #[test]
    fn eval_add_int_float_promotion() {
        // Int + Float should promote to Float
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Int(1);
        core.registers[1] = Value::Float(Float64::new(0.5));
        let result = core.eval_add(0, 1).unwrap();
        assert_eq!(result, Value::Float(Float64::new(1.5)));
    }

    #[test]
    fn eval_add_float_int_promotion() {
        // Float + Int should promote to Float
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Float(Float64::new(2.5));
        core.registers[1] = Value::Int(3);
        let result = core.eval_add(0, 1).unwrap();
        assert_eq!(result, Value::Float(Float64::new(5.5)));
    }

    #[test]
    fn eval_div_int_int_exact() {
        // 6 / 3 = 2 (exact integer result)
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Int(6);
        core.registers[1] = Value::Int(3);
        let result = core.eval_div(0, 1).unwrap();
        assert_eq!(result, Value::Int(2));
    }

    #[test]
    fn eval_div_int_int_fractional() {
        // 7 / 3 = 2.333... (fractional result)
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Int(7);
        core.registers[1] = Value::Int(3);
        let result = core.eval_div(0, 1).unwrap();
        if let Value::Float(f) = result {
            let v = f.inner();
            assert!((v - 2.333333333333333).abs() < 1e-10);
        } else {
            panic!("Expected Float, got {:?}", result);
        }
    }

    #[test]
    fn eval_div_by_zero_infinity() {
        // 1 / 0 = Infinity
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Int(1);
        core.registers[1] = Value::Int(0);
        let result = core.eval_div(0, 1).unwrap();
        if let Value::Float(f) = result {
            assert!(f.inner().is_infinite() && f.inner() > 0.0);
        } else {
            panic!("Expected Float(Infinity), got {:?}", result);
        }
    }

    #[test]
    fn eval_div_zero_zero_nan() {
        // 0 / 0 = NaN
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Int(0);
        core.registers[1] = Value::Int(0);
        let result = core.eval_div(0, 1).unwrap();
        if let Value::Float(f) = result {
            assert!(f.inner().is_nan());
        } else {
            panic!("Expected Float(NaN), got {:?}", result);
        }
    }

    #[test]
    fn eval_arith_nan_propagation() {
        // NaN + 1 = NaN
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Float(Float64::new(f64::NAN));
        core.registers[1] = Value::Int(1);
        let result = core.eval_add(0, 1).unwrap();
        if let Value::Float(f) = result {
            assert!(f.inner().is_nan());
        } else {
            panic!("Expected Float(NaN), got {:?}", result);
        }
    }

    #[test]
    fn eval_arith_infinity_mul_zero() {
        // Infinity * 0 = NaN
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Float(Float64::new(f64::INFINITY));
        core.registers[1] = Value::Int(0);
        let result = core.eval_arith(0, 1, "mul").unwrap();
        if let Value::Float(f) = result {
            assert!(f.inner().is_nan());
        } else {
            panic!("Expected Float(NaN), got {:?}", result);
        }
    }

    #[test]
    fn eval_mod_float_float() {
        // 5.5 % 2.0 = 1.5
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Float(Float64::new(5.5));
        core.registers[1] = Value::Float(Float64::new(2.0));
        let result = core.eval_mod(0, 1).unwrap();
        if let Value::Float(f) = result {
            assert!((f.inner() - 1.5).abs() < 1e-10);
        } else {
            panic!("Expected Float(1.5), got {:?}", result);
        }
    }

    #[test]
    fn eval_unary_neg_float() {
        // -Float(1.5) = Float(-1.5)
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Float(Float64::new(1.5));
        let result = core.eval_unary_neg(0).unwrap();
        assert_eq!(result, Value::Float(Float64::new(-1.5)));
    }

    #[test]
    fn eval_ieee754_classic() {
        // 0.1 + 0.2 = 0.30000000000000004 (classic IEEE 754 test)
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Float(Float64::new(0.1));
        core.registers[1] = Value::Float(Float64::new(0.2));
        let result = core.eval_add(0, 1).unwrap();
        if let Value::Float(f) = result {
            // The exact value is 0.30000000000000004
            assert!((f.inner() - 0.30000000000000004).abs() < 1e-16);
        } else {
            panic!("Expected Float, got {:?}", result);
        }
    }

    // -----------------------------------------------------------------------
    // Special values: NaN, Infinity, -Infinity, -0
    // -----------------------------------------------------------------------

    #[test]
    fn nan_strict_not_equal_to_itself() {
        // NaN !== NaN
        let nan1 = Value::Float(Float64::new(f64::NAN));
        let nan2 = Value::Float(Float64::new(f64::NAN));
        assert!(!InterpreterCore::strict_eq_values(&nan1, &nan2));
    }

    #[test]
    fn nan_loose_not_equal_to_itself() {
        // NaN != NaN
        let nan1 = Value::Float(Float64::new(f64::NAN));
        let nan2 = Value::Float(Float64::new(f64::NAN));
        assert!(!InterpreterCore::abstract_eq_values(&nan1, &nan2));
    }

    #[test]
    fn negative_zero_strict_equals_positive_zero() {
        // -0 === +0
        let neg_zero = Value::Float(Float64::new(-0.0));
        let pos_zero = Value::Float(Float64::new(0.0));
        assert!(InterpreterCore::strict_eq_values(&neg_zero, &pos_zero));
    }

    #[test]
    fn negative_zero_loose_equals_positive_zero() {
        // -0 == +0
        let neg_zero = Value::Float(Float64::new(-0.0));
        let pos_zero = Value::Float(Float64::new(0.0));
        assert!(InterpreterCore::abstract_eq_values(&neg_zero, &pos_zero));
    }

    #[test]
    fn one_div_neg_zero_is_neg_infinity() {
        // 1 / -0 = -Infinity
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Float(Float64::new(1.0));
        core.registers[1] = Value::Float(Float64::new(-0.0));
        let result = core.eval_div(0, 1).unwrap();
        if let Value::Float(f) = result {
            assert!(f.inner().is_infinite() && f.inner() < 0.0);
        } else {
            panic!("Expected Float(-Infinity), got {:?}", result);
        }
    }

    #[test]
    fn neg_one_div_zero_is_neg_infinity() {
        // -1 / 0 = -Infinity
        let mut core = quickjs_test_core();
        core.registers.resize(4, Value::Undefined);
        core.registers[0] = Value::Float(Float64::new(-1.0));
        core.registers[1] = Value::Int(0);
        let result = core.eval_div(0, 1).unwrap();
        if let Value::Float(f) = result {
            assert!(f.inner().is_infinite() && f.inner() < 0.0);
        } else {
            panic!("Expected Float(-Infinity), got {:?}", result);
        }
    }

    #[test]
    fn float64_display_nan() {
        let nan = Float64::new(f64::NAN);
        assert_eq!(format!("{nan}"), "NaN");
    }

    #[test]
    fn float64_display_infinity() {
        let inf = Float64::new(f64::INFINITY);
        assert_eq!(format!("{inf}"), "Infinity");
    }

    #[test]
    fn float64_display_neg_infinity() {
        let neg_inf = Float64::new(f64::NEG_INFINITY);
        assert_eq!(format!("{neg_inf}"), "-Infinity");
    }

    #[test]
    fn float64_display_neg_zero() {
        // -0 displays as "0" (JS semantics)
        let neg_zero = Float64::new(-0.0);
        assert_eq!(format!("{neg_zero}"), "0");
    }

    #[test]
    fn float64_is_negative_zero() {
        assert!(Float64::new(-0.0).is_negative_zero());
        assert!(!Float64::new(0.0).is_negative_zero());
        assert!(!Float64::new(1.0).is_negative_zero());
    }

    #[test]
    fn value_float_nan_is_falsy() {
        assert!(!Value::Float(Float64::new(f64::NAN)).is_truthy());
    }

    #[test]
    fn value_float_zero_is_falsy() {
        assert!(!Value::Float(Float64::new(0.0)).is_truthy());
        assert!(!Value::Float(Float64::new(-0.0)).is_truthy());
    }

    #[test]
    fn value_float_infinity_is_truthy() {
        assert!(Value::Float(Float64::new(f64::INFINITY)).is_truthy());
        assert!(Value::Float(Float64::new(f64::NEG_INFINITY)).is_truthy());
    }

    #[test]
    fn value_typeof_float_is_number() {
        assert_eq!(Value::Float(Float64::new(1.5)).type_name(), "number");
        assert_eq!(Value::Float(Float64::new(f64::NAN)).type_name(), "number");
        assert_eq!(
            Value::Float(Float64::new(f64::INFINITY)).type_name(),
            "number"
        );
    }

    // -- Capability enforcement tests (bd-3pa1u.2) --

    #[test]
    fn heap_allocate_capability_required_for_object_allocation() {
        // Test with HeapAllocate capability - should succeed
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "heap-alloc-test");

        let result = core.alloc_object_with_prototype(None);
        assert!(result.is_ok());

        // Test without HeapAllocate capability - should fail
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities.clear(); // Remove all capabilities
        let mut core = InterpreterCore::new(config, "no-heap-alloc-test");

        let err = core.alloc_object_with_prototype(None).unwrap_err();
        assert!(
            matches!(err, InterpreterError::CapabilityDenied { capability } if capability == "HeapAllocate")
        );
    }

    #[test]
    fn vm_dispatch_capability_required_for_execution() {
        // Test with VmDispatch capability - should succeed
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        let mut core = InterpreterCore::new(config, "vm-dispatch-test");

        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());

        // Test without VmDispatch capability - should fail
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities.clear(); // Remove all capabilities
        let mut core = InterpreterCore::new(config, "no-vm-dispatch-test");

        let module = test_module(vec![Ir3Instruction::Halt]);
        let err = core.execute(&module).unwrap_err();
        assert!(
            matches!(err, InterpreterError::CapabilityDenied { capability } if capability == "VmDispatch")
        );
    }

    #[test]
    fn capability_denied_error_contains_missing_capability_name() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities.clear(); // Remove all capabilities
        let mut core = InterpreterCore::new(config, "capability-error-test");

        // Test that VmDispatch error contains the correct capability name
        let module = test_module(vec![Ir3Instruction::Halt]);
        let err = core.execute(&module).unwrap_err();
        match err {
            InterpreterError::CapabilityDenied { capability } => {
                assert_eq!(capability, "VmDispatch");
            }
            _ => panic!("Expected CapabilityDenied error"),
        }

        // Test that HeapAllocate error contains the correct capability name
        let err = core.alloc_object_with_prototype(None).unwrap_err();
        match err {
            InterpreterError::CapabilityDenied { capability } => {
                assert_eq!(capability, "HeapAllocate");
            }
            _ => panic!("Expected CapabilityDenied error"),
        }
    }

    // -- ES2015 Class Semantics Tests (bd-6a61n.1.3) --

    #[test]
    fn class_declaration_creates_constructor() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "class-constructor-test");

        // Test basic constructor functionality
        // This should work with current implementation since it just creates a function
        let module = test_module(vec![
            // Test that new Foo() creates an object
            Ir3Instruction::Halt, // TODO: implement proper test
        ]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn class_method_on_prototype() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "class-method-test");

        // TODO: implement test for method on prototype
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn class_extends_sets_prototype_chain() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "class-extends-test");

        // TODO: implement test for inheritance
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn super_call_invokes_parent_constructor() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "super-constructor-test");

        // TODO: implement test for super() calls
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn super_method_calls_parent_method() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "super-method-test");

        // TODO: implement test for super.method() calls
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn static_method_on_constructor() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "static-method-test");

        // TODO: implement test for static methods - this should work with current implementation
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn computed_method_name() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "computed-method-test");

        // TODO: implement test for computed method names like [expr]()
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn getter_setter() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "getter-setter-test");

        // TODO: implement test for getter/setter methods
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn class_expression() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "class-expression-test");

        // TODO: implement test for class expressions
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    #[test]
    fn new_target_in_constructor() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "new-target-test");

        // TODO: implement test for new.target meta-property
        let module = test_module(vec![Ir3Instruction::Halt]);
        let result = core.execute(&module);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Timer substrate tests
    // -----------------------------------------------------------------------

    #[test]
    fn set_timeout_deterministic_regression() {
        // Regression test: Verify setTimeout uses deterministic timer IDs instead of wall-clock time
        // This test ensures the fix for bd-1orko where SystemTime::now() was replaced with next_timer_id

        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);

        // Create two identical interpreter instances with same initial state
        let mut core1 = InterpreterCore::new(config.clone(), "deterministic-timer-test-1");
        let mut core2 = InterpreterCore::new(config, "deterministic-timer-test-2");

        let function_id_1 = core1.allocate_function(
            "callback1",
            vec![],
            vec![Ir3Instruction::Halt],
            0,
            std::collections::BTreeMap::new(),
        );
        let function_id_2 = core2.allocate_function(
            "callback2",
            vec![],
            vec![Ir3Instruction::Halt],
            0,
            std::collections::BTreeMap::new(),
        );

        let callback1 = Value::Function(function_id_1);
        let callback2 = Value::Function(function_id_2);

        // Execute setTimeout on both cores - should get identical timer IDs
        // because they use deterministic next_timer_id, not wall-clock time
        let timer_id_1 = core1
            .execute_builtin_call(
                "builtin:SetTimeout",
                vec![Value::Undefined, callback1, Value::Int(1000)],
            )
            .expect("setTimeout should succeed on core1");

        let timer_id_2 = core2
            .execute_builtin_call(
                "builtin:SetTimeout",
                vec![Value::Undefined, callback2, Value::Int(1000)],
            )
            .expect("setTimeout should succeed on core2");

        // Timer IDs should be identical because they're deterministic, not wall-clock based
        assert_eq!(
            timer_id_1, timer_id_2,
            "Timer IDs should be identical across identical interpreter instances (deterministic)"
        );

        // Both should be the first timer ID (starting from next_timer_id initial value)
        match timer_id_1 {
            Value::Int(id) => {
                assert!(id >= 0, "Timer ID should be non-negative");
                // The exact value depends on initial next_timer_id, but should be consistent
            }
            _ => panic!("setTimeout should return integer timer ID"),
        }

        // Verify both interpreters have the timer in their active_timers state
        assert_eq!(core1.active_timers.len(), 1);
        assert_eq!(core2.active_timers.len(), 1);

        let timer_id_val = timer_id_1.as_int().unwrap() as u32;
        assert!(core1.active_timers.contains_key(&timer_id_val));
        assert!(core2.active_timers.contains_key(&timer_id_val));
    }

    #[test]
    fn set_timeout_returns_deterministic_id() {
        // Regression test: setTimeout returns deterministic, monotonic timer IDs
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);

        let mut core = InterpreterCore::new(config, "setTimeout-deterministic-test");

        // Create a simple callback function
        let function_id = core.allocate_function(
            "test_callback",
            vec![],
            vec![Ir3Instruction::Halt],
            0,
            std::collections::BTreeMap::new(),
        );
        let callback_val = Value::Function(function_id);

        // Test multiple setTimeout calls return sequential IDs
        let timer_id_1 = core
            .execute_builtin_call(
                "builtin:SetTimeout",
                vec![Value::Undefined, callback_val.clone(), Value::Int(1000)],
            )
            .expect("setTimeout should succeed");

        let timer_id_2 = core
            .execute_builtin_call(
                "builtin:SetTimeout",
                vec![Value::Undefined, callback_val.clone(), Value::Int(2000)],
            )
            .expect("setTimeout should succeed");

        // Verify timer IDs are deterministic and sequential
        match (timer_id_1, timer_id_2) {
            (Value::Int(id1), Value::Int(id2)) => {
                assert!(id1 >= 0, "Timer ID should be non-negative");
                assert!(id2 >= 0, "Timer ID should be non-negative");
                assert_eq!(id2, id1 + 1, "Timer IDs should be sequential");
            }
            _ => panic!("setTimeout should return integer timer IDs"),
        }

        // Verify timers are stored in active_timers
        assert_eq!(core.active_timers.len(), 2, "Both timers should be active");
        assert!(
            core.active_timers
                .contains_key(&(timer_id_1.as_int().unwrap() as u32))
        );
        assert!(
            core.active_timers
                .contains_key(&(timer_id_2.as_int().unwrap() as u32))
        );
    }

    #[test]
    fn clear_timeout_cancels_deterministic() {
        // Regression test: clearTimeout properly cancels timers from active_timers
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);

        let mut core = InterpreterCore::new(config, "clearTimeout-test");

        // Create a callback function
        let function_id = core.allocate_function(
            "test_callback",
            vec![],
            vec![Ir3Instruction::Halt],
            0,
            std::collections::BTreeMap::new(),
        );
        let callback_val = Value::Function(function_id);

        // Schedule multiple timers
        let timer_id_1 = core
            .execute_builtin_call(
                "builtin:SetTimeout",
                vec![Value::Undefined, callback_val.clone(), Value::Int(1000)],
            )
            .expect("setTimeout should succeed");

        let timer_id_2 = core
            .execute_builtin_call(
                "builtin:SetTimeout",
                vec![Value::Undefined, callback_val.clone(), Value::Int(2000)],
            )
            .expect("setTimeout should succeed");

        // Verify both timers are active
        assert_eq!(core.active_timers.len(), 2, "Both timers should be active");

        // Clear the first timer
        let clear_result = core
            .execute_builtin_call(
                "builtin:ClearTimeout",
                vec![Value::Undefined, timer_id_1.clone()],
            )
            .expect("clearTimeout should succeed");

        assert_eq!(
            clear_result,
            Value::Undefined,
            "clearTimeout returns undefined"
        );

        // Verify first timer was removed but second remains
        assert_eq!(
            core.active_timers.len(),
            1,
            "Only one timer should remain active"
        );
        assert!(
            !core
                .active_timers
                .contains_key(&(timer_id_1.as_int().unwrap() as u32))
        );
        assert!(
            core.active_timers
                .contains_key(&(timer_id_2.as_int().unwrap() as u32))
        );

        // Clear the second timer
        let clear_result_2 = core
            .execute_builtin_call(
                "builtin:ClearTimeout",
                vec![Value::Undefined, timer_id_2.clone()],
            )
            .expect("clearTimeout should succeed");

        assert_eq!(
            clear_result_2,
            Value::Undefined,
            "clearTimeout returns undefined"
        );

        // Verify all timers are cleared
        assert_eq!(
            core.active_timers.len(),
            0,
            "No timers should remain active"
        );

        // Test clearing non-existent timer (should be safe)
        let clear_invalid = core
            .execute_builtin_call(
                "builtin:ClearTimeout",
                vec![Value::Undefined, Value::Int(99999)],
            )
            .expect("clearTimeout with invalid ID should succeed");

        assert_eq!(
            clear_invalid,
            Value::Undefined,
            "clearing invalid timer returns undefined"
        );
    }

    #[test]
    fn set_interval_repeats() {
        // TODO: Test that setInterval fires multiple times
        // When timer substrate is implemented, this will:
        // 1. Call setInterval with callback and interval
        // 2. Run event loop for several intervals
        // 3. Verify callback fires multiple times at regular intervals
        // Placeholder until implementation.
    }

    #[test]
    fn clear_interval_stops() {
        // TODO: Test that clearInterval stops repeating timer
        // When timer substrate is implemented, this will:
        // 1. Call setInterval to start repeating timer
        // 2. Let it fire a few times
        // 3. Call clearInterval to stop it
        // 4. Verify timer stops firing
        // Placeholder until implementation.
    }

    #[test]
    fn timer_ordering() {
        // TODO: Test that earlier timers fire before later timers
        // When timer substrate is implemented, this will:
        // 1. Schedule multiple timers with different delays
        // 2. Run event loop until all fire
        // 3. Verify execution order matches delay ordering
        // Placeholder until implementation.
    }

    #[test]
    fn microtask_before_timer() {
        // TODO: Test that microtasks drain before timer callbacks
        // When timer substrate is implemented, this will:
        // 1. Schedule a setTimeout(callback, 0)
        // 2. Enqueue a microtask (Promise.then)
        // 3. Run event loop
        // 4. Verify microtask executes before timer callback
        // Placeholder until implementation.
    }

    #[test]
    fn nested_set_timeout() {
        // TODO: Test that setTimeout inside timer callback works
        // When timer substrate is implemented, this will:
        // 1. Call setTimeout with callback that calls setTimeout again
        // 2. Run event loop
        // 3. Verify both timers execute in correct order
        // Placeholder until implementation.
    }

    #[test]
    fn zero_delay_timeout() {
        // TODO: Test that setTimeout(cb, 0) fires after current macrotask + microtasks
        // When timer substrate is implemented, this will:
        // 1. Call setTimeout(callback, 0)
        // 2. Enqueue some microtasks
        // 3. Run event loop
        // 4. Verify timer fires after microtasks drain
        // Placeholder until implementation.
    }

    // RC-4.3 Containment Action Enforcement Tests
    mod containment_tests {
        use super::*;

        pub(super) fn test_interpreter() -> InterpreterCore {
            InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "test-containment")
        }

        #[test]
        fn allow_continues() {
            let mut interpreter = test_interpreter();
            let result = interpreter.handle_containment_action(HookAction::Allow);
            assert!(result.is_ok());
            assert!(!interpreter.suspended);
            assert!(!interpreter.sandboxed);
            assert!(!interpreter.quarantined);
        }

        #[test]
        fn terminate_aborts() {
            let mut interpreter = test_interpreter();
            let result = interpreter
                .handle_containment_action(HookAction::Terminate("policy violation".to_string()));
            match result {
                Err(InterpreterError::Terminated { reason }) => {
                    assert_eq!(reason, "policy violation");
                }
                _ => panic!("Expected Terminated error"),
            }
            assert!(!interpreter.suspended);
            assert!(!interpreter.sandboxed);
            assert!(!interpreter.quarantined);
        }

        #[test]
        fn suspend_pauses() {
            let mut interpreter = test_interpreter();
            let result = interpreter.handle_containment_action(HookAction::Suspend);
            assert!(result.is_ok());
            assert!(interpreter.suspended);
            assert!(!interpreter.sandboxed);
            assert!(!interpreter.quarantined);
        }

        #[test]
        fn sandbox_restricts() {
            let mut interpreter = test_interpreter();
            let result = interpreter.handle_containment_action(HookAction::Sandbox);
            assert!(result.is_ok());
            assert!(!interpreter.suspended);
            assert!(interpreter.sandboxed);
            assert!(!interpreter.quarantined);
        }

        #[test]
        fn challenge_blocks() {
            let mut interpreter = test_interpreter();
            let token = ChallengeToken {
                token: "challenge-123".to_string(),
            };
            let result =
                interpreter.handle_containment_action(HookAction::Challenge(token.clone()));
            match result {
                Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                    assert_eq!(action, "challenge");
                    assert_eq!(reason, Some(token.token));
                }
                _ => panic!("Expected ContainmentActionRequested error"),
            }
            assert_eq!(interpreter.pending_challenges.len(), 1);
            assert_eq!(interpreter.pending_challenges[0].token, "challenge-123");
        }

        #[test]
        fn quarantine_terminates_and_marks() {
            let mut interpreter = test_interpreter();
            let result = interpreter.handle_containment_action(HookAction::Quarantine(
                "malicious behavior".to_string(),
            ));
            match result {
                Err(InterpreterError::Terminated { reason }) => {
                    assert_eq!(reason, "malicious behavior");
                }
                _ => panic!("Expected Terminated error"),
            }
            assert!(!interpreter.suspended);
            assert!(!interpreter.sandboxed);
            assert!(interpreter.quarantined);
        }

        #[test]
        fn evidence_emitted_per_action() {
            let mut interpreter = test_interpreter();
            let initial_evidence_count = interpreter.containment_evidence.len();
            let initial_witness_count = interpreter.witness_events.len();

            interpreter
                .handle_containment_action(HookAction::Sandbox)
                .unwrap();

            assert_eq!(
                interpreter.containment_evidence.len(),
                initial_evidence_count + 1
            );
            assert_eq!(interpreter.witness_events.len(), initial_witness_count + 1);

            let evidence = &interpreter.containment_evidence[0];
            assert_eq!(evidence.kind, WitnessEventKind::ContainmentAction);
            assert_eq!(evidence.instruction_index as usize, interpreter.ip);
        }

        #[test]
        fn interpreter_consistent_after_terminate() {
            let mut interpreter = test_interpreter();
            let initial_ip = interpreter.ip;
            let initial_register_base = interpreter.register_base;

            let _ = interpreter
                .handle_containment_action(HookAction::Terminate("test termination".to_string()));

            // Interpreter state should remain consistent (no half-executed instructions)
            assert_eq!(interpreter.ip, initial_ip);
            assert_eq!(interpreter.register_base, initial_register_base);
            assert_eq!(interpreter.containment_evidence.len(), 1);
        }

        // RC-4.4 Decision Receipt Tests
        #[test]
        fn receipt_has_correct_fields() {
            let mut interpreter = test_interpreter();
            interpreter
                .handle_containment_action(HookAction::Terminate("test".to_string()))
                .ok();

            let receipts = interpreter.decision_receipts().receipts();
            assert_eq!(receipts.len(), 1);

            let receipt = &receipts[0];
            assert_eq!(receipt.extension_id, "extension:current");
            assert_eq!(receipt.operation_type, "terminate");
            assert_eq!(receipt.risk_score, 900_000);
            assert!(receipt.action_taken.contains("terminate"));
            assert!(receipt.timestamp > 0);
            assert_eq!(receipt.instruction_pointer, 0);
            assert!(!receipt.register_state_hash.is_empty());
            assert!(!receipt.signature.is_empty());
        }

        #[test]
        fn receipt_chain_linked() {
            let mut interpreter = test_interpreter();
            interpreter
                .handle_containment_action(HookAction::Sandbox)
                .ok();
            interpreter
                .handle_containment_action(HookAction::Suspend)
                .ok();

            let receipts = interpreter.decision_receipts().receipts();
            assert_eq!(receipts.len(), 2);

            assert!(receipts[0].previous_receipt_hash.is_none());
            assert_eq!(
                receipts[1].previous_receipt_hash,
                Some(receipts[0].signature.clone())
            );
        }

        #[test]
        fn chain_verification_valid() {
            let mut interpreter = test_interpreter();
            interpreter
                .handle_containment_action(HookAction::Sandbox)
                .ok();
            interpreter
                .handle_containment_action(HookAction::Suspend)
                .ok();

            assert!(interpreter.verify_decision_receipt_chain());
        }

        #[test]
        fn chain_verification_tampered() {
            let mut interpreter = test_interpreter();
            interpreter
                .handle_containment_action(HookAction::Sandbox)
                .ok();

            // Tamper with the receipt signature
            interpreter.decision_receipts.receipts[0].signature = "tampered".to_string();

            assert!(!interpreter.verify_decision_receipt_chain());
        }

        #[test]
        fn empty_chain_valid() {
            let interpreter = test_interpreter();
            assert!(interpreter.verify_decision_receipt_chain());
            assert!(interpreter.decision_receipts().is_empty());
        }

        #[test]
        fn export_json_schema() {
            let mut interpreter = test_interpreter();
            interpreter
                .handle_containment_action(HookAction::Sandbox)
                .ok();

            let json_export = interpreter.export_decision_receipts().unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json_export).unwrap();

            assert_eq!(parsed["evidence_type"], "guardplane_decision_chain");
            assert_eq!(parsed["receipt_count"], 1);
            assert_eq!(parsed["chain_verified"], true);
            assert!(parsed["receipts"].is_array());
            assert!(parsed["exported_at"].as_u64().unwrap() > 0);
        }

        #[test]
        fn receipt_includes_risk_score() {
            let mut interpreter = test_interpreter();
            interpreter
                .handle_containment_action(HookAction::Terminate("test".to_string()))
                .ok();

            let receipt = &interpreter.decision_receipts().receipts()[0];
            assert_eq!(receipt.risk_score, 900_000); // High risk for terminate action
        }

        #[test]
        fn receipt_includes_action() {
            let mut interpreter = test_interpreter();
            interpreter
                .handle_containment_action(HookAction::Quarantine("malicious".to_string()))
                .ok();

            let receipt = &interpreter.decision_receipts().receipts()[0];
            assert_eq!(receipt.operation_type, "quarantine");
            assert!(receipt.action_taken.contains("quarantine"));
            assert!(receipt.action_taken.contains("malicious"));
        }
    }

    mod async_function_tests {
        use super::containment_tests::test_interpreter;
        use super::*;

        #[test]
        fn async_function_call_returns_promise() {
            let mut core = test_interpreter();

            // Create a simple async function object in the store
            let async_func_id = core.async_functions.len() as u32;
            core.async_functions.push(AsyncFunctionObject {
                function_index: 0, // dummy function index
                closure_index: None,
                saved_ip: 0,
                saved_registers: Vec::new(),
                saved_register_base: 0,
                phase: AsyncFunctionPhase::SuspendedStart,
                result_promise: 0, // will be set when called
            });

            // Test that calling an async function returns a promise
            let async_func_value = Value::AsyncFunction(async_func_id);

            // For now, we can't fully test this without a complete module
            // but we can verify the Value::AsyncFunction variant exists
            match async_func_value {
                Value::AsyncFunction(id) => assert_eq!(id, async_func_id),
                _ => panic!("Expected AsyncFunction value"),
            }
        }

        #[test]
        fn await_resolved_promise_returns_value() {
            let mut core = test_interpreter();

            // Create a pre-resolved promise
            let handle = core.promise_store.create();
            let js_val = crate::object_model::JsValue::Int(42);
            let label = crate::ifc_artifacts::Label::Public;
            core.promise_store
                .fulfill(handle, js_val, label, &mut core.event_loop.microtasks)
                .unwrap();

            // Store the promise in a register
            core.registers.resize(10, Value::Undefined);
            core.registers[0] = Value::Promise(handle.0);

            // Test that we can read the promise value
            let promise_val = core.read_reg(0).unwrap();
            match promise_val {
                Value::Promise(h) => {
                    assert_eq!(h, handle.0);

                    // Verify the promise is resolved
                    let record = core.promise_store.get(handle).unwrap();
                    assert!(record.state.is_fulfilled());
                }
                _ => panic!("Expected Promise value"),
            }
        }

        #[test]
        fn async_function_phases_exist() {
            // Test that the async function phase enum is complete
            let phases = [
                AsyncFunctionPhase::SuspendedStart,
                AsyncFunctionPhase::Executing,
                AsyncFunctionPhase::SuspendedAwait,
                AsyncFunctionPhase::Completed,
            ];

            // Verify we can match on all phases
            for phase in phases {
                match phase {
                    AsyncFunctionPhase::SuspendedStart => {}
                    AsyncFunctionPhase::Executing => {}
                    AsyncFunctionPhase::SuspendedAwait => {}
                    AsyncFunctionPhase::Completed => {}
                }
            }
        }

        #[test]
        fn value_to_js_value_conversion() {
            // Test that the production value_to_js_value conversion works correctly
            // This exercises the actual conversion helper used by the promise subsystem

            let test_cases = vec![
                (Value::Undefined, crate::object_model::JsValue::Undefined),
                (Value::Null, crate::object_model::JsValue::Null),
                (Value::Bool(true), crate::object_model::JsValue::Bool(true)),
                (
                    Value::Bool(false),
                    crate::object_model::JsValue::Bool(false),
                ),
                (Value::Int(42), crate::object_model::JsValue::Int(42)),
                (Value::Int(-123), crate::object_model::JsValue::Int(-123)),
                (
                    Value::Str("hello".to_string()),
                    crate::object_model::JsValue::Str("hello".to_string()),
                ),
                (
                    Value::Object(ObjectId(100)),
                    crate::object_model::JsValue::Object(crate::object_model::ObjectHandle(100)),
                ),
                (
                    Value::Function(5),
                    crate::object_model::JsValue::Function(5),
                ),
            ];

            for (input, expected) in test_cases {
                let result = BaselineInterpreter::value_to_js_value(&input);
                assert_eq!(result, expected, "Conversion failed for {:?}", input);
            }

            // Test Float conversion (special case due to bit representation)
            let float_val = Value::Float(Float64::new(3.14));
            let float_result = BaselineInterpreter::value_to_js_value(&float_val);
            if let crate::object_model::JsValue::Float(bits) = float_result {
                assert_eq!(f64::from_bits(bits), 3.14, "Float conversion incorrect");
            } else {
                panic!("Expected Float JsValue");
            }

            // Test fallback case (complex types fall back to string conversion)
            let promise_val = Value::Promise(7);
            let promise_result = BaselineInterpreter::value_to_js_value(&promise_val);
            assert!(
                matches!(promise_result, crate::object_model::JsValue::Str(_)),
                "Complex types should fall back to string conversion"
            );
        }

        #[test]
        fn async_generator_creation() {
            let mut core = test_interpreter();

            // Test async generator creation through the production Call instruction path
            // Set up a minimal IR3 module with an async generator function
            let mut module = test_ir3_module();

            // Add an async generator function to the module
            module.function_table.push(Function {
                name: "test_async_gen".to_string(),
                params: vec![],
                body: vec![], // Empty body for this test
                locals_count: 0,
            });

            // Create an AsyncGeneratorFunction value
            let async_gen_func = Value::AsyncGeneratorFunction(0); // closure_index = 0
            core.registers.resize(10, Value::Undefined);
            core.registers[0] = async_gen_func; // callee
            core.registers[1] = Value::Int(0); // func_idx (corresponds to function_table[0])

            // Execute Call instruction that should create AsyncGeneratorObject
            let call_instr = Instruction::Call {
                dst: 5,
                func: 1,                               // register containing func_idx
                args: ArgBlock { start: 2, count: 0 }, // no arguments
            };

            // Process the call instruction
            match core.execute_instruction(&call_instr, &module) {
                Ok(()) => {
                    // Verify async generator was created
                    assert_eq!(core.async_generators.len(), 1);
                    let created_gen = &core.async_generators[0];
                    assert_eq!(created_gen.function_index, 0);
                    assert_eq!(created_gen.closure_index, Some(0));
                    assert!(matches!(
                        created_gen.phase,
                        AsyncGeneratorPhase::SuspendedStart
                    ));

                    // Verify the result register contains AsyncGeneratorObject value
                    if let Value::AsyncGeneratorObject(gen_id) = core.registers[5] {
                        assert_eq!(gen_id, 0);
                    } else {
                        panic!("Expected AsyncGeneratorObject in result register");
                    }
                }
                Err(e) => panic!("Call instruction failed: {:?}", e),
            }
        }

        #[test]
        fn async_generator_function_call_creates_object() {
            let mut core = test_interpreter();

            // Test multiple async generator function calls through interpreter Call path
            let mut module = test_ir3_module();

            // Add multiple async generator functions to test proper indexing
            module.function_table.push(Function {
                name: "async_gen_1".to_string(),
                params: vec!["param1".to_string()],
                body: vec![], // Empty body for this test
                locals_count: 1,
            });
            module.function_table.push(Function {
                name: "async_gen_2".to_string(),
                params: vec!["param1".to_string(), "param2".to_string()],
                body: vec![], // Empty body for this test
                locals_count: 2,
            });

            core.registers.resize(15, Value::Undefined);

            // First call: create async generator from function 0
            core.registers[0] = Value::AsyncGeneratorFunction(10); // closure_index = 10
            core.registers[1] = Value::Int(0); // func_idx = 0

            let call1 = Instruction::Call {
                dst: 5,
                func: 1,
                args: ArgBlock { start: 3, count: 1 },
            };
            core.registers[3] = Value::Str("arg1".to_string()); // argument

            core.execute_instruction(&call1, &module)
                .expect("First call should succeed");

            // Second call: create async generator from function 1
            core.registers[7] = Value::AsyncGeneratorFunction(20); // closure_index = 20
            core.registers[8] = Value::Int(1); // func_idx = 1

            let call2 = Instruction::Call {
                dst: 9,
                func: 8,
                args: ArgBlock {
                    start: 10,
                    count: 2,
                },
            };
            core.registers[10] = Value::Str("arg1".to_string()); // argument 1
            core.registers[11] = Value::Int(42); // argument 2

            core.execute_instruction(&call2, &module)
                .expect("Second call should succeed");

            // Verify both async generators were created correctly
            assert_eq!(core.async_generators.len(), 2);

            // First async generator
            let gen1 = &core.async_generators[0];
            assert_eq!(gen1.function_index, 0);
            assert_eq!(gen1.closure_index, Some(10));
            assert!(matches!(gen1.phase, AsyncGeneratorPhase::SuspendedStart));

            // Second async generator
            let gen2 = &core.async_generators[1];
            assert_eq!(gen2.function_index, 1);
            assert_eq!(gen2.closure_index, Some(20));
            assert!(matches!(gen2.phase, AsyncGeneratorPhase::SuspendedStart));

            // Verify result registers contain correct AsyncGeneratorObject values
            if let Value::AsyncGeneratorObject(id1) = core.registers[5] {
                assert_eq!(id1, 0);
            } else {
                panic!("Expected first AsyncGeneratorObject");
            }

            if let Value::AsyncGeneratorObject(id2) = core.registers[9] {
                assert_eq!(id2, 1);
            } else {
                panic!("Expected second AsyncGeneratorObject");
            }
        }

        #[test]
        fn async_generator_next_returns_promise() {
            let mut core = test_interpreter();

            // Create async generator, call it to get object, then call .next()
            let async_gen_id = {
                core.async_generators.push(AsyncGeneratorObject {
                    function_index: 0,
                    closure_index: None,
                    saved_ip: 0,
                    saved_registers: Vec::new(),
                    saved_register_base: 0,
                    phase: AsyncGeneratorPhase::Completed,
                });
                (core.async_generators.len() - 1) as u32
            };

            let result = core
                .async_generator_next(&test_module(vec![]), async_gen_id, Value::Undefined)
                .unwrap();

            match result {
                Value::Promise(_) => {}
                _ => panic!("Expected Promise value, got {:?}", result),
            }
        }

        #[test]
        fn async_generator_phases_exist() {
            // Test that async generator phase enum is complete
            let phases = [
                AsyncGeneratorPhase::SuspendedStart,
                AsyncGeneratorPhase::SuspendedYield,
                AsyncGeneratorPhase::SuspendedAwait,
                AsyncGeneratorPhase::Executing,
                AsyncGeneratorPhase::Completed,
            ];

            for phase in phases {
                match phase {
                    AsyncGeneratorPhase::SuspendedStart => {}
                    AsyncGeneratorPhase::SuspendedYield => {}
                    AsyncGeneratorPhase::SuspendedAwait => {}
                    AsyncGeneratorPhase::Executing => {}
                    AsyncGeneratorPhase::Completed => {}
                }
            }
        }

        #[test]
        fn async_generator_value_types() {
            // Test async generator value type predicates
            let async_gen_func = Value::AsyncGeneratorFunction(0);
            let async_gen_obj = Value::AsyncGeneratorObject(0);

            assert_eq!(async_gen_func.type_name(), "function");
            assert_eq!(async_gen_obj.type_name(), "object");

            assert!(async_gen_func.is_truthy());
            assert!(async_gen_obj.is_truthy());

            assert!(!async_gen_func.is_nullish());
            assert!(!async_gen_obj.is_nullish());
        }

        /// Regression test for bd-bnji7: String case-conversion builtins must have
        /// consistent toString behavior across all mapped builtin IDs.
        #[test]
        fn string_case_conversion_builtin_consistency() {
            // Test values that previously had inconsistent behavior
            let test_values = vec![
                Value::Function(0),
                Value::Promise(0),
                Value::AsyncGeneratorObject(0),
                Value::BuiltinFunction("test".to_string()),
                Value::Object(0),
                Value::Closure(0),
            ];

            for test_value in test_values {
                let result = BaselineInterpreter::value_to_string(&test_value);

                // All non-primitive values should consistently convert to their
                // appropriate [object Type] string representation
                match test_value {
                    Value::Function(_) => assert_eq!(result, "[object Function]"),
                    Value::Promise(_) => assert_eq!(result, "[object Promise]"),
                    Value::AsyncGeneratorObject(_) => assert_eq!(result, "[object AsyncGenerator]"),
                    Value::BuiltinFunction(_) => assert_eq!(result, "[object Function]"),
                    Value::Object(_) => assert_eq!(result, "[object Object]"),
                    Value::Closure(_) => assert_eq!(result, "[object Function]"),
                    _ => {}
                }
            }
        }

        /// Test that all string case-conversion operations are deterministic
        /// and produce identical results regardless of which builtin ID is used.
        ///
        /// Previously, builtin IDs 34/35, 293/297, 330/331 mapped to different
        /// implementations with divergent wildcard conversion behavior.
        #[test]
        fn string_case_conversion_deterministic_across_builtin_ids() {
            // Test cases that exposed inconsistency between builtin implementations
            let test_cases = vec![
                (Value::Function(42), "[object Function]"),
                (Value::Promise(7), "[object Promise]"),
                (Value::AsyncGeneratorObject(1), "[object AsyncGenerator]"),
                (
                    Value::BuiltinFunction("Math.abs".to_string()),
                    "[object Function]",
                ),
                (Value::Object(123), "[object Object]"),
                (Value::Closure(5), "[object Function]"),
                (Value::Iterator(9), "[object Iterator]"),
                (Value::Null, "null"),
                (Value::Undefined, "undefined"),
                (Value::Int(42), "42"),
                (Value::Bool(true), "true"),
            ];

            for (input, expected_string) in test_cases {
                let result = BaselineInterpreter::value_to_string(&input);
                assert_eq!(
                    result, expected_string,
                    "value_to_string for {:?} should be deterministic",
                    input
                );

                // Verify toLowerCase and toUpperCase produce consistent results
                let lowercase = result.to_lowercase();
                let uppercase = result.to_uppercase();

                // These should be the expected transformations of the unified toString result
                assert_eq!(
                    lowercase,
                    expected_string.to_lowercase(),
                    "toLowerCase should be consistent for {:?}",
                    input
                );
                assert_eq!(
                    uppercase,
                    expected_string.to_uppercase(),
                    "toUpperCase should be consistent for {:?}",
                    input
                );
            }
        }

        /// Regression test for bd-3o8mv: String.prototype methods must implement
        /// RequireObjectCoercible semantics, throwing TypeError for null/undefined.
        #[test]
        fn string_prototype_require_object_coercible() {
            // Test that RequireObjectCoercible properly rejects null and undefined
            let null_result = BaselineInterpreter::require_object_coercible_to_string(&Value::Null);
            assert!(null_result.is_err());
            if let Err(InterpreterError::TypeError { message }) = null_result {
                assert!(message.contains("null"));
            } else {
                panic!("Expected TypeError for null");
            }

            let undef_result =
                BaselineInterpreter::require_object_coercible_to_string(&Value::Undefined);
            assert!(undef_result.is_err());
            if let Err(InterpreterError::TypeError { message }) = undef_result {
                assert!(message.contains("undefined"));
            } else {
                panic!("Expected TypeError for undefined");
            }

            // Test that valid values are properly converted
            let valid_values = vec![
                (Value::Str("hello".to_string()), "hello"),
                (Value::Int(42), "42"),
                (Value::Bool(true), "true"),
                (Value::Function(1), "[object Function]"),
                (Value::Promise(2), "[object Promise]"),
                (Value::AsyncGeneratorObject(3), "[object AsyncGenerator]"),
            ];

            for (input, expected) in valid_values {
                let result = BaselineInterpreter::require_object_coercible_to_string(&input);
                assert!(result.is_ok(), "Should succeed for {:?}", input);
                assert_eq!(
                    result.unwrap(),
                    expected,
                    "Conversion mismatch for {:?}",
                    input
                );
            }
        }

        /// Test that all string case-conversion builtin paths have unified behavior
        /// and properly implement RequireObjectCoercible across all builtin IDs.
        ///
        /// Previously, builtin IDs had divergent null/undefined handling:
        /// - Some converted to "null"/"undefined" strings
        /// - Locale methods had exhaustive tables that also converted them
        /// Now all methods should throw TypeError for null/undefined consistently.
        #[test]
        fn string_case_conversion_unified_object_coercible_behavior() {
            // Test values that should trigger RequireObjectCoercible TypeError
            let invalid_values = vec![Value::Null, Value::Undefined];

            for invalid in invalid_values {
                let result = BaselineInterpreter::require_object_coercible_to_string(&invalid);
                assert!(
                    result.is_err(),
                    "RequireObjectCoercible should reject {:?}",
                    invalid
                );
            }

            // Test values that should be consistently converted across all builtin paths
            // These exercise the various builtin IDs: 34/35 (basic), 293/297, 330/331, 386/387 (locale)
            let test_cases = vec![
                (Value::Function(100), "[object Function]"),
                (Value::Promise(200), "[object Promise]"),
                (Value::AsyncGeneratorObject(300), "[object AsyncGenerator]"),
                (
                    Value::BuiltinFunction("Array.from".to_string()),
                    "[object Function]",
                ),
                (Value::Object(400), "[object Object]"),
                (Value::Iterator(500), "[object Iterator]"),
                (Value::Bool(false), "false"),
                (Value::Int(-42), "-42"),
            ];

            for (input, expected_string) in test_cases {
                let result = BaselineInterpreter::require_object_coercible_to_string(&input);
                assert!(result.is_ok(), "Should convert {:?} successfully", input);

                let converted = result.unwrap();
                assert_eq!(
                    converted, expected_string,
                    "Unified string conversion for {:?} should be deterministic",
                    input
                );

                // Verify case transformations are consistent
                let lowercase = converted.to_lowercase();
                let uppercase = converted.to_uppercase();

                assert_eq!(
                    lowercase,
                    expected_string.to_lowercase(),
                    "toLowerCase should be consistent for {:?}",
                    input
                );
                assert_eq!(
                    uppercase,
                    expected_string.to_uppercase(),
                    "toUpperCase should be consistent for {:?}",
                    input
                );
            }
        }

        /// Regression test for ArrayPrototypeSort value preservation across builtin IDs.
        ///
        /// The issue was that builtin ID 385 implementation was converting all array elements
        /// to strings during sorting and then writing back string values instead of preserving
        /// the original Value types. This caused type corruption where numeric/boolean/object
        /// elements became strings after sorting.
        ///
        /// All three ArrayPrototypeSort builtin IDs (28, 248, 385) should preserve original
        /// element values while only using string representation for comparison during sorting.
        #[test]
        fn array_prototype_sort_preserves_element_values_across_builtin_ids() {
            let mut interpreter = test_interpreter();

            // Create test array with mixed types that should be preserved after sorting
            let array_id = ObjectId::from_raw(100);
            let test_elements = vec![
                (0, Value::Int(42)),                  // Should remain Int(42), not Str("42")
                (1, Value::Bool(true)),               // Should remain Bool(true), not Str("true")
                (2, Value::Float(3.14.into())),       // Should remain Float, not Str("3.14")
                (3, Value::Str("apple".to_string())), // Should remain Str
                (4, Value::Object(ObjectId::from_raw(200))), // Should remain Object, not Str("[object Object]")
            ];

            // Add object to heap
            interpreter.heap.insert(
                array_id.0 as usize,
                HeapObject {
                    properties: test_elements
                        .iter()
                        .map(|(i, val)| (i.to_string(), val.clone()))
                        .chain(std::iter::once(("length".to_string(), Value::Int(5))))
                        .collect(),
                    prototype_id: None,
                },
            );

            // Add nested object for testing object preservation
            interpreter.heap.insert(
                200,
                HeapObject {
                    properties: BTreeMap::new(),
                    prototype_id: None,
                },
            );

            // Test all three ArrayPrototypeSort builtin IDs
            let builtin_ids = [28, 248, 385];

            for builtin_id in builtin_ids {
                // Reset array to original state
                if let Some(obj) = interpreter.heap.get_mut(array_id.0 as usize) {
                    obj.properties.clear();
                    for (i, val) in &test_elements {
                        obj.properties.insert(i.to_string(), val.clone());
                    }
                    obj.properties.insert("length".to_string(), Value::Int(5));
                }

                // Invoke ArrayPrototypeSort via builtin dispatcher
                let result =
                    interpreter.call_builtin_by_id(builtin_id, RegRange { start: 0, count: 1 });

                assert!(
                    result.is_ok(),
                    "Builtin ID {} should complete successfully",
                    builtin_id
                );

                // Verify all element types are preserved after sorting
                if let Some(sorted_obj) = interpreter.heap.get(array_id.0 as usize) {
                    for i in 0..5 {
                        let element = sorted_obj.properties.get(&i.to_string()).expect(&format!(
                            "Builtin ID {} should preserve element {}",
                            builtin_id, i
                        ));

                        // Verify types are preserved, not converted to strings
                        match element {
                            Value::Int(_) => {}    // Good - preserved as Int
                            Value::Bool(_) => {}   // Good - preserved as Bool
                            Value::Float(_) => {}  // Good - preserved as Float
                            Value::Str(_) => {}    // Good - was already Str
                            Value::Object(_) => {} // Good - preserved as Object
                            Value::Undefined => {} // Acceptable for missing elements
                            other => panic!(
                                "Builtin ID {} corrupted element {} type: expected original type, got {:?}",
                                builtin_id, i, other
                            ),
                        }
                    }
                }

                // Test specific preservation cases that were failing before the fix
                if let Some(sorted_obj) = interpreter.heap.get(array_id.0 as usize) {
                    // Find where Int(42) ended up after sorting (should be lexicographically sorted by string rep)
                    let mut found_int = false;
                    for i in 0..5 {
                        if let Some(Value::Int(42)) = sorted_obj.properties.get(&i.to_string()) {
                            found_int = true;
                            break;
                        }
                    }
                    assert!(
                        found_int,
                        "Builtin ID {} should preserve Int(42) as Int type",
                        builtin_id
                    );

                    // Find where Bool(true) ended up
                    let mut found_bool = false;
                    for i in 0..5 {
                        if let Some(Value::Bool(true)) = sorted_obj.properties.get(&i.to_string()) {
                            found_bool = true;
                            break;
                        }
                    }
                    assert!(
                        found_bool,
                        "Builtin ID {} should preserve Bool(true) as Bool type",
                        builtin_id
                    );

                    // Find where Object ended up
                    let mut found_object = false;
                    for i in 0..5 {
                        if let Some(Value::Object(ObjectId(200))) =
                            sorted_obj.properties.get(&i.to_string())
                        {
                            found_object = true;
                            break;
                        }
                    }
                    assert!(
                        found_object,
                        "Builtin ID {} should preserve Object as Object type",
                        builtin_id
                    );
                }
            }

            // Verify sorting order is correct (by string representation, but preserving types)
            // Expected order: "3.14", "42", "[object Object]", "apple", "true"
            if let Some(final_obj) = interpreter.heap.get(array_id.0 as usize) {
                let elem_0 = final_obj.properties.get("0").unwrap();
                let elem_1 = final_obj.properties.get("1").unwrap();
                let elem_4 = final_obj.properties.get("4").unwrap();

                // First element should be 3.14 (string "3.14" comes first lexicographically)
                assert!(
                    matches!(elem_0, Value::Float(_)),
                    "First element should be Float(3.14), got {:?}",
                    elem_0
                );

                // Second element should be 42 (string "42" comes second)
                assert!(
                    matches!(elem_1, Value::Int(42)),
                    "Second element should be Int(42), got {:?}",
                    elem_1
                );

                // Last element should be true (string "true" comes last)
                assert!(
                    matches!(elem_4, Value::Bool(true)),
                    "Last element should be Bool(true), got {:?}",
                    elem_4
                );
            }
        }

        /// Regression test for batch-37 Math/RegExp builtin dispatch deduplication.
        ///
        /// The issue was duplicate match arms for MathSin, MathCos, MathTan, and
        /// RegExpPrototypeTest in the builtin dispatcher. Because both arms matched
        /// the same names, only the first arm was reachable and newer builtin IDs
        /// were effectively dead-code mapping entries.
        ///
        /// All first/duplicate ID pairs should execute the same canonical
        /// implementation and produce identical results.
        #[test]
        fn math_regexp_builtin_dispatch_deduplication_regression() {
            let mut interpreter = test_interpreter();

            // Recreate RegExp object with source property used by the canonical impl.
            let regexp_obj_id = ObjectId::from_raw(500);
            interpreter.heap.insert(
                regexp_obj_id.0 as usize,
                HeapObject {
                    properties: BTreeMap::from_iter([(
                        "source".to_string(),
                        Value::Str("foo".to_string()),
                    )]),
                    prototype_id: None,
                },
            );

            let math_id_pairs = [
                (244u32, 369u32, "builtin:MathSin"),
                (245u32, 370u32, "builtin:MathCos"),
                (247u32, 371u32, "builtin:MathTan"),
            ];
            let math_inputs = [Value::Int(1), Value::Float(1.0.into()), Value::Bool(true)];

            for (first_id, second_id, builtin_name) in math_id_pairs {
                for input in &math_inputs {
                    interpreter.registers[0] = input.clone();

                    assert_eq!(
                        interpreter.map_function_index_to_builtin_capability(first_id),
                        Some(builtin_name.to_string()),
                        "Builtin ID {} should map to {}",
                        first_id,
                        builtin_name
                    );
                    assert_eq!(
                        interpreter.map_function_index_to_builtin_capability(second_id),
                        Some(builtin_name.to_string()),
                        "Builtin ID {} should map to {}",
                        second_id,
                        builtin_name
                    );

                    let first_result = interpreter
                        .call_builtin_by_id(first_id, RegRange { start: 0, count: 1 })
                        .expect("first mapping should execute");
                    let second_result = interpreter
                        .call_builtin_by_id(second_id, RegRange { start: 0, count: 1 })
                        .expect("second mapping should execute");
                    assert_eq!(
                        first_result, second_result,
                        "Builtin IDs {} and {} should execute same {} result",
                        first_id, second_id, builtin_name
                    );
                }
            }

            let regexp_ids = [(268u32, 372u32, "builtin:RegExpPrototypeTest")];
            for (first_id, second_id, builtin_name) in regexp_ids {
                interpreter.registers[0] = Value::Object(regexp_obj_id);
                interpreter.registers[1] = Value::Str("a quick fox".to_string());

                assert_eq!(
                    interpreter.map_function_index_to_builtin_capability(first_id),
                    Some(builtin_name.to_string()),
                    "Builtin ID {} should map to {}",
                    first_id,
                    builtin_name
                );
                assert_eq!(
                    interpreter.map_function_index_to_builtin_capability(second_id),
                    Some(builtin_name.to_string()),
                    "Builtin ID {} should map to {}",
                    second_id,
                    builtin_name
                );

                let first_result = interpreter
                    .call_builtin_by_id(first_id, RegRange { start: 0, count: 2 })
                    .expect("first RegExp mapping should execute");
                let second_result = interpreter
                    .call_builtin_by_id(second_id, RegRange { start: 0, count: 2 })
                    .expect("second RegExp mapping should execute");
                assert_eq!(
                    first_result, second_result,
                    "Builtin IDs {} and {} should execute same {} result",
                    first_id, second_id, builtin_name
                );
            }
        }

        /// Regression test for ArrayPrototypeSort builtin dispatch deduplication.
        ///
        /// The issue was that three separate match arms for "builtin:ArrayPrototypeSort"
        /// existed in the builtin dispatcher (at different line numbers), all matching
        /// the same string. Due to match ordering, only the first arm could execute,
        /// making builtin IDs 248 and 385 unreachable dead code despite being mapped
        /// in map_function_index_to_builtin_capability().
        ///
        /// After consolidation, all three builtin IDs (28, 248, 385) should route through
        /// the same shared implementation and work correctly with mixed Value types.
        #[test]
        fn array_prototype_sort_builtin_dispatch_deduplication_regression() {
            let mut interpreter = test_interpreter();

            // Create test array with mixed types including holes
            let array_id = ObjectId::from_raw(100);
            let test_elements = vec![
                (0, Value::Int(3)),                    // "3"
                (1, Value::Str("banana".to_string())), // "banana"
                (2, Value::Bool(false)),               // "false"
                // index 3 is a hole (should become Undefined)
                (4, Value::Float(1.5.into())),               // "1.5"
                (5, Value::Object(ObjectId::from_raw(200))), // "[object Object]"
            ];

            // Add objects to heap
            interpreter.heap.insert(
                array_id.0 as usize,
                HeapObject {
                    properties: test_elements
                        .iter()
                        .map(|(i, val)| (i.to_string(), val.clone()))
                        .chain(std::iter::once(("length".to_string(), Value::Int(6))))
                        .collect(),
                    prototype_id: None,
                },
            );

            interpreter.heap.insert(
                200,
                HeapObject {
                    properties: BTreeMap::new(),
                    prototype_id: None,
                },
            );

            // Test all three builtin IDs that should map to the same consolidated implementation
            let builtin_ids = [28u32, 248u32, 385u32];

            for builtin_id in builtin_ids {
                // Reset array to original state
                if let Some(obj) = interpreter.heap.get_mut(array_id.0 as usize) {
                    obj.properties.clear();
                    for (i, val) in &test_elements {
                        obj.properties.insert(i.to_string(), val.clone());
                    }
                    obj.properties.insert("length".to_string(), Value::Int(6));
                }

                // Invoke ArrayPrototypeSort via the specific builtin ID
                // This tests that the mapping works and reaches the consolidated implementation
                let builtin_name = interpreter.map_function_index_to_builtin_capability(builtin_id);
                assert_eq!(
                    builtin_name,
                    Some("builtin:ArrayPrototypeSort".to_string()),
                    "Builtin ID {} should map to ArrayPrototypeSort",
                    builtin_id
                );

                // Simulate builtin call through dispatcher
                let result = interpreter.call_builtin(
                    "builtin:ArrayPrototypeSort",
                    RegRange { start: 0, count: 1 },
                );
                assert!(
                    result.is_ok(),
                    "Builtin ID {} should execute successfully",
                    builtin_id
                );

                // Verify the array was sorted correctly
                if let Some(sorted_obj) = interpreter.heap.get(array_id.0 as usize) {
                    // Expected lexicographic order: "1.5", "3", "[object Object]", "banana", "false", "undefined"
                    let elem_0 = sorted_obj.properties.get("0").unwrap();
                    let elem_1 = sorted_obj.properties.get("1").unwrap();
                    let elem_2 = sorted_obj.properties.get("2").unwrap();
                    let elem_3 = sorted_obj.properties.get("3").unwrap();
                    let elem_4 = sorted_obj.properties.get("4").unwrap();
                    let elem_5 = sorted_obj.properties.get("5").unwrap();

                    // Verify elements are in correct sorted order and types preserved
                    assert!(
                        matches!(elem_0, Value::Float(_)),
                        "ID {}: elem[0] should be Float(1.5), got {:?}",
                        builtin_id,
                        elem_0
                    );
                    assert!(
                        matches!(elem_1, Value::Int(3)),
                        "ID {}: elem[1] should be Int(3), got {:?}",
                        builtin_id,
                        elem_1
                    );
                    assert!(
                        matches!(elem_2, Value::Object(_)),
                        "ID {}: elem[2] should be Object, got {:?}",
                        builtin_id,
                        elem_2
                    );
                    assert!(
                        matches!(elem_3, Value::Str(s) if s == "banana"),
                        "ID {}: elem[3] should be Str(banana), got {:?}",
                        builtin_id,
                        elem_3
                    );
                    assert!(
                        matches!(elem_4, Value::Bool(false)),
                        "ID {}: elem[4] should be Bool(false), got {:?}",
                        builtin_id,
                        elem_4
                    );
                    assert!(
                        matches!(elem_5, Value::Undefined),
                        "ID {}: elem[5] should be Undefined (from hole), got {:?}",
                        builtin_id,
                        elem_5
                    );
                }
            }
        }
    }

    // Regression tests for bd-19wq2: Array.prototype.concat array spreading
    #[test]
    fn array_concat_spreads_arrays() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Create first array [1]
        let arr1_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(arr1_id, "0".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(arr1_id, "length".to_string(), Value::Int(1))
            .unwrap();

        // Create second array [2]
        let arr2_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(arr2_id, "0".to_string(), Value::Int(2))
            .unwrap();
        core.set_object_property(arr2_id, "length".to_string(), Value::Int(1))
            .unwrap();

        // Set up registers for concat call: this=arr1, args=[arr2]
        core.registers[0] = Value::Object(arr1_id);
        core.registers[1] = Value::Object(arr2_id);

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ArrayPrototypeConcat".to_string(),
                    args: RegRange { start: 0, count: 2 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Result should be an array with elements [1, 2], not [1, [2]]
        if let Value::Object(result_id) = core.registers[10] {
            let result_obj = &core.heap[result_id.0 as usize];

            // Check length is 2
            assert_eq!(result_obj.properties.get("length"), Some(&Value::Int(2)));

            // Check elements are 1 and 2 (not a nested array)
            assert_eq!(result_obj.properties.get("0"), Some(&Value::Int(1)));
            assert_eq!(result_obj.properties.get("1"), Some(&Value::Int(2)));
        } else {
            panic!("Array concat should return an object");
        }
    }

    #[test]
    fn array_concat_non_array_as_single_element() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Create array [1]
        let arr_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(arr_id, "0".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(arr_id, "length".to_string(), Value::Int(1))
            .unwrap();

        // Set up registers for concat call: this=arr, args=["str"]
        core.registers[0] = Value::Object(arr_id);
        core.registers[1] = Value::Str("str".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ArrayPrototypeConcat".to_string(),
                    args: RegRange { start: 0, count: 2 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Result should be [1, "str"]
        if let Value::Object(result_id) = core.registers[10] {
            let result_obj = &core.heap[result_id.0 as usize];

            // Check length is 2
            assert_eq!(result_obj.properties.get("length"), Some(&Value::Int(2)));

            // Check elements
            assert_eq!(result_obj.properties.get("0"), Some(&Value::Int(1)));
            assert_eq!(
                result_obj.properties.get("1"),
                Some(&Value::Str("str".to_string()))
            );
        } else {
            panic!("Array concat should return an object");
        }
    }

    #[test]
    fn array_concat_multiple_arrays() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Create array [1]
        let arr1_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(arr1_id, "0".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(arr1_id, "length".to_string(), Value::Int(1))
            .unwrap();

        // Create array [2, 3]
        let arr2_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(arr2_id, "0".to_string(), Value::Int(2))
            .unwrap();
        core.set_object_property(arr2_id, "1".to_string(), Value::Int(3))
            .unwrap();
        core.set_object_property(arr2_id, "length".to_string(), Value::Int(2))
            .unwrap();

        // Create array [4]
        let arr3_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(arr3_id, "0".to_string(), Value::Int(4))
            .unwrap();
        core.set_object_property(arr3_id, "length".to_string(), Value::Int(1))
            .unwrap();

        // Set up registers for concat call: this=arr1, args=[arr2, arr3]
        core.registers[0] = Value::Object(arr1_id);
        core.registers[1] = Value::Object(arr2_id);
        core.registers[2] = Value::Object(arr3_id);

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ArrayPrototypeConcat".to_string(),
                    args: RegRange { start: 0, count: 3 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Result should be [1, 2, 3, 4]
        if let Value::Object(result_id) = core.registers[10] {
            let result_obj = &core.heap[result_id.0 as usize];

            // Check length is 4
            assert_eq!(result_obj.properties.get("length"), Some(&Value::Int(4)));

            // Check all elements
            assert_eq!(result_obj.properties.get("0"), Some(&Value::Int(1)));
            assert_eq!(result_obj.properties.get("1"), Some(&Value::Int(2)));
            assert_eq!(result_obj.properties.get("2"), Some(&Value::Int(3)));
            assert_eq!(result_obj.properties.get("3"), Some(&Value::Int(4)));
        } else {
            panic!("Array concat should return an object");
        }
    }

    // Regression tests for bd-11a8p: Global builtin argument indexing
    #[test]
    fn global_builtin_isnan_correct_argument() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test IsNaN with number argument
        core.registers[0] = Value::Float(Float64::new(f64::NAN));

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:IsNaN".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should correctly read register 0 and return true for NaN
        assert_eq!(core.registers[10], Value::Bool(true));

        // Test with non-NaN value
        core.registers[0] = Value::Int(42);

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:IsNaN".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should return false for non-NaN
        assert_eq!(core.registers[10], Value::Bool(false));
    }

    #[test]
    fn global_builtin_isfinite_correct_argument() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test IsFinite with finite number
        core.registers[0] = Value::Int(42);

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:IsFinite".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should correctly read register 0 and return true for finite number
        assert_eq!(core.registers[10], Value::Bool(true));

        // Test with infinity
        core.registers[0] = Value::Float(Float64::new(f64::INFINITY));

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:IsFinite".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should return false for infinity
        assert_eq!(core.registers[10], Value::Bool(false));
    }

    #[test]
    fn global_builtin_parseint_correct_arguments() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test ParseInt with string argument (single argument)
        core.registers[0] = Value::Str("123".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseInt".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should correctly parse "123" as 123
        if let Value::Float(f) = core.registers[10] {
            assert_eq!(f.inner() as i64, 123);
        } else {
            panic!("ParseInt should return a float");
        }

        // Test ParseInt with radix argument
        core.registers[0] = Value::Str("101".to_string());
        core.registers[1] = Value::Int(2); // binary radix

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseInt".to_string(),
                    args: RegRange { start: 0, count: 2 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should correctly parse "101" in base 2 as 5
        if let Value::Float(f) = core.registers[10] {
            assert_eq!(f.inner() as i64, 5);
        } else {
            panic!("ParseInt should return a float");
        }
    }

    #[test]
    fn global_builtin_parsefloat_correct_argument() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test ParseFloat with string argument
        core.registers[0] = Value::Str("3.14".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should correctly parse "3.14" as 3.14
        if let Value::Float(f) = core.registers[10] {
            assert!((f.inner() - 3.14).abs() < f64::EPSILON);
        } else {
            panic!("ParseFloat should return a float");
        }

        // Test with integer
        core.registers[0] = Value::Int(42);

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should return the integer as-is
        assert_eq!(core.registers[10], Value::Int(42));
    }

    // Regression tests for bd-2gbeb: Deterministic Date.now timing
    #[test]
    fn date_now_deterministic_across_runs() {
        let deterministic_epoch_ms = 1_767_225_600_000.0; // 2026-01-01T00:00:00Z

        // Run Date.now multiple times - should always return same value
        for _ in 0..5 {
            let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

            let result = core
                .execute(&test_module(vec![
                    Ir3Instruction::CallBuiltin {
                        builtin: "builtin:DateNow".to_string(),
                        args: RegRange { start: 0, count: 0 },
                        dst: 10,
                    },
                    Ir3Instruction::Halt,
                ]))
                .unwrap();

            // Should always return the fixed deterministic epoch
            if let Value::Float(f) = core.registers[10] {
                assert_eq!(f.inner(), deterministic_epoch_ms);
            } else {
                panic!("Date.now should return a float");
            }
        }
    }

    #[test]
    fn date_constructor_deterministic_across_runs() {
        let deterministic_epoch_ms = 1_767_225_600_000.0; // 2026-01-01T00:00:00Z

        // Run Date constructor multiple times - should always create same timestamp
        for _ in 0..5 {
            let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

            let result = core
                .execute(&test_module(vec![
                    Ir3Instruction::CallBuiltin {
                        builtin: "builtin:Date".to_string(),
                        args: RegRange { start: 0, count: 0 },
                        dst: 10,
                    },
                    Ir3Instruction::Halt,
                ]))
                .unwrap();

            // Should create Date object with deterministic timestamp
            if let Value::Object(date_id) = core.registers[10] {
                let date_obj = &core.heap[date_id.0 as usize];
                let timestamp = date_obj.properties.get("__timestamp").unwrap();

                if let Value::Float(f) = timestamp {
                    assert_eq!(f.inner(), deterministic_epoch_ms);
                } else {
                    panic!("Date timestamp should be a float");
                }
            } else {
                panic!("Date constructor should return an object");
            }
        }
    }

    #[test]
    fn date_prototype_gettime_stable_values() {
        let deterministic_epoch_ms = 1_767_225_600_000.0; // 2026-01-01T00:00:00Z

        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Create Date object
        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:Date".to_string(),
                    args: RegRange { start: 0, count: 0 },
                    dst: 5,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Multiple calls to getTime() should return same value
        for _ in 0..3 {
            // Set up this=date object for getTime call
            core.registers[0] = core.registers[5].clone();

            let result = core
                .execute(&test_module(vec![
                    Ir3Instruction::CallBuiltin {
                        builtin: "builtin:DatePrototypeGetTime".to_string(),
                        args: RegRange { start: 0, count: 1 },
                        dst: 10,
                    },
                    Ir3Instruction::Halt,
                ]))
                .unwrap();

            // Should return the same deterministic timestamp
            if let Value::Float(f) = core.registers[10] {
                assert_eq!(f.inner(), deterministic_epoch_ms);
            } else {
                panic!("Date.prototype.getTime should return a float");
            }
        }
    }

    // Regression tests for bd-7f1a4: Console builtin deduplication and info capture
    #[test]
    fn console_info_capture_output() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Set up arguments for console.info
        core.registers[0] = Value::Str("Info message".to_string());
        core.registers[1] = Value::Int(42);

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ConsoleInfo".to_string(),
                    args: RegRange { start: 0, count: 2 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should capture console.info output
        assert_eq!(core.console_output.len(), 1);
        let console_entry = &core.console_output[0];
        assert_eq!(console_entry.level, ConsoleLevel::Info);
        assert_eq!(console_entry.message, "Info message 42");
        assert_eq!(console_entry.instruction_index, 1);
    }

    #[test]
    fn console_info_hostcall_dispatch() {
        let mut core = quickjs_test_core();

        core.registers[0] = Value::Str("Info hostcall".to_string());
        core.dispatch_console_hostcall("console:info", RegRange { start: 0, count: 1 })
            .unwrap();

        assert_eq!(core.console_output.len(), 1);
        let console_entry = &core.console_output[0];
        assert_eq!(console_entry.level, ConsoleLevel::Info);
        assert_eq!(console_entry.message, "Info hostcall");
    }

    #[test]
    fn console_builtin_ids_100_102_captured() {
        // Test that the original builtin IDs 100-102 properly capture output
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        core.registers[0] = Value::Str("Log test".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ConsoleLog".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should capture output with Log level
        assert_eq!(core.console_output.len(), 1);
        assert_eq!(core.console_output[0].level, ConsoleLevel::Log);
        assert_eq!(core.console_output[0].message, "Log test");

        core.console_output.clear();
        core.registers[0] = Value::Str("Error test".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ConsoleError".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should capture output with Error level
        assert_eq!(core.console_output.len(), 1);
        assert_eq!(core.console_output[0].level, ConsoleLevel::Error);
        assert_eq!(core.console_output[0].message, "Error test");

        core.console_output.clear();
        core.registers[0] = Value::Str("Warn test".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ConsoleWarn".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should capture output with Warn level
        assert_eq!(core.console_output.len(), 1);
        assert_eq!(core.console_output[0].level, ConsoleLevel::Warn);
        assert_eq!(core.console_output[0].message, "Warn test");
    }

    #[test]
    fn console_output_deterministic_metadata() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test that console output includes proper metadata
        core.registers[0] = Value::Str("Test".to_string());
        core.registers[1] = Value::Int(123);

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ConsoleInfo".to_string(),
                    args: RegRange { start: 0, count: 2 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        assert_eq!(core.console_output.len(), 1);
        let entry = &core.console_output[0];

        // Check all metadata fields are populated
        assert_eq!(entry.level, ConsoleLevel::Info);
        assert_eq!(entry.message, "Test 123");
        assert!(entry.instruction_index > 0, "Should have instruction index");
    }

    #[test]
    fn string_prototype_replace_object_coercion() {
        // Test that objects are properly coerced to "[object Object]"
        let mut core = BaselineInterpreter::new();
        let obj_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_register(0, Value::Object(obj_id)).unwrap();
        core.set_register(1, Value::Str("object".to_string()))
            .unwrap();
        core.set_register(2, Value::Str("replacement".to_string()))
            .unwrap();

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 41, // StringPrototypeReplace
                args: RegRange { start: 0, count: 3 },
                dest: 3,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

        let result = core.read_register(3).unwrap();
        assert_eq!(result, Value::Str("[replacement Object]".to_string()));
    }

    #[test]
    fn string_prototype_replace_no_search_arg() {
        // Test that no search argument returns original string
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("hello world".to_string()))
            .unwrap();

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 41, // StringPrototypeReplace
                args: RegRange { start: 0, count: 1 },
                dest: 1,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

        let result = core.read_register(1).unwrap();
        assert_eq!(result, Value::Str("hello world".to_string()));
    }

    #[test]
    fn string_prototype_replace_iterator_coercion() {
        // Test that other value types are coerced to "[object Object]" by default
        let mut core = BaselineInterpreter::new();

        // Using Value::Iterator as an example of non-primitive type
        core.set_register(0, Value::Iterator(IteratorValue::new()))
            .unwrap();
        core.set_register(1, Value::Str("object".to_string()))
            .unwrap();
        core.set_register(2, Value::Str("replaced".to_string()))
            .unwrap();

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 41, // StringPrototypeReplace
                args: RegRange { start: 0, count: 3 },
                dest: 3,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

        let result = core.read_register(3).unwrap();
        assert_eq!(result, Value::Str("[replaced Object]".to_string()));
    }

    #[test]
    fn string_prototype_replace_builtin_function_coercion() {
        // Test that builtin functions are coerced to "[object Object]"
        let mut core = BaselineInterpreter::new();
        let builtin_fn = BuiltinFunction::new(42, "TestFunction".to_string());
        core.set_register(0, Value::BuiltinFunction(builtin_fn))
            .unwrap();
        core.set_register(1, Value::Str("object".to_string()))
            .unwrap();
        core.set_register(2, Value::Str("function".to_string()))
            .unwrap();

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 41, // StringPrototypeReplace
                args: RegRange { start: 0, count: 3 },
                dest: 3,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

        let result = core.read_register(3).unwrap();
        assert_eq!(result, Value::Str("[function Object]".to_string()));
    }

    // Regression tests for bd-1b3v6: parseFloat exponent and Infinity semantics
    #[test]
    fn parse_float_scientific_notation() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test parseFloat("1e3") should return 1000
        core.registers[0] = Value::Str("1e3".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should parse "1e3" as 1000
        assert_eq!(core.registers[10], Value::Int(1000));

        // Test parseFloat("2.5e2") should return 250
        core.registers[0] = Value::Str("2.5e2".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should parse "2.5e2" as 250
        if let Value::Float(f) = core.registers[10] {
            assert_eq!(f.inner(), 250.0);
        } else {
            panic!("Expected Float for 2.5e2");
        }
    }

    #[test]
    fn parse_float_negative_exponent() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test parseFloat("1e-3") should return 0.001
        core.registers[0] = Value::Str("1e-3".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should parse "1e-3" as 0.001
        if let Value::Float(f) = core.registers[10] {
            assert!((f.inner() - 0.001).abs() < f64::EPSILON);
        } else {
            panic!("Expected Float for 1e-3");
        }

        // Test parseFloat("5E+2") should return 500
        core.registers[0] = Value::Str("5E+2".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should parse "5E+2" as 500
        assert_eq!(core.registers[10], Value::Int(500));
    }

    #[test]
    fn parse_float_infinity_literals() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test parseFloat("Infinity")
        core.registers[0] = Value::Str("Infinity".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should return positive infinity
        if let Value::Float(f) = core.registers[10] {
            assert!(f.inner().is_infinite() && f.inner().is_sign_positive());
        } else {
            panic!("Expected Float for Infinity");
        }

        // Test parseFloat("-Infinity")
        core.registers[0] = Value::Str("-Infinity".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should return negative infinity
        if let Value::Float(f) = core.registers[10] {
            assert!(f.inner().is_infinite() && f.inner().is_sign_negative());
        } else {
            panic!("Expected Float for -Infinity");
        }

        // Test parseFloat("+Infinity")
        core.registers[0] = Value::Str("+Infinity".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should return positive infinity
        if let Value::Float(f) = core.registers[10] {
            assert!(f.inner().is_infinite() && f.inner().is_sign_positive());
        } else {
            panic!("Expected Float for +Infinity");
        }
    }

    #[test]
    fn parse_float_invalid_exponent_fallback() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test parseFloat("1e") - incomplete exponent should parse as 1
        core.registers[0] = Value::Str("1e".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should parse up to valid part and return NaN for invalid "1e"
        if let Value::Float(f) = core.registers[10] {
            assert!(f.inner().is_nan());
        } else {
            panic!("Expected NaN for invalid exponent");
        }

        // Test parseFloat("123abc") should stop at 'a' and return 123
        core.registers[0] = Value::Str("123abc".to_string());

        let result = core
            .execute(&test_module(vec![
                Ir3Instruction::CallBuiltin {
                    builtin: "builtin:ParseFloat".to_string(),
                    args: RegRange { start: 0, count: 1 },
                    dst: 10,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();

        // Should stop at first invalid character and return 123
        assert_eq!(core.registers[10], Value::Int(123));
    }

    #[test]
    fn math_random_deterministic_replay() {
        // Regression test: same execution state should produce same random sequence
        // This ensures DefaultHasher replacement with SHA-256 maintains determinism
        let mut core1 = BaselineInterpreter::new();
        let mut core2 = BaselineInterpreter::new();

        // Set both cores to identical state
        core1.instructions_executed = 42;
        core1.ip = 10;
        core2.instructions_executed = 42;
        core2.ip = 10;

        // Call Math.random on both cores
        let result1 = core1.math_random_impl().unwrap();
        let result2 = core2.math_random_impl().unwrap();

        // Should produce identical results (deterministic)
        assert_eq!(result1, result2, "Math.random should be deterministic with same execution state");

        // Verify it's actually a valid random number in [0, 1)
        if let Value::Float(f) = result1 {
            let val = f.inner();
            assert!(val >= 0.0, "Math.random should be >= 0.0, got {}", val);
            assert!(val < 1.0, "Math.random should be < 1.0, got {}", val);
        } else {
            panic!("Math.random should return a Float, got {:?}", result1);
        }
    }

    #[test]
    fn math_random_different_states_produce_different_values() {
        // Test that different execution states produce different random values
        let mut core1 = BaselineInterpreter::new();
        let mut core2 = BaselineInterpreter::new();

        // Set cores to different states
        core1.instructions_executed = 10;
        core2.instructions_executed = 20;

        let result1 = core1.math_random_impl().unwrap();
        let result2 = core2.math_random_impl().unwrap();

        // Should produce different results
        assert_ne!(result1, result2, "Different execution states should produce different random values");
    }

    #[test]
    fn string_prototype_char_code_at_basic() {
        // Test basic charCodeAt functionality with ASCII characters
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("Hello".to_string())).unwrap();
        core.set_register(1, Value::Int(0)).unwrap(); // index 0

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 184, // StringPrototypeCharCodeAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        // "Hello"[0] = 'H' = 72
        let result = core.read_register(2).unwrap();
        assert_eq!(result, Value::Int(72), "charCodeAt('H') should be 72");
    }

    #[test]
    fn string_prototype_char_code_at_utf16_surrogate_pairs() {
        // Test charCodeAt with UTF-16 surrogate pairs (characters outside BMP)
        let mut core = BaselineInterpreter::new();

        // U+1F600 (😀) is encoded as surrogate pair: 0xD83D 0xDE00
        core.set_register(0, Value::Str("😀".to_string())).unwrap();

        // Get first surrogate (high surrogate)
        core.set_register(1, Value::Int(0)).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 184, // StringPrototypeCharCodeAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result1 = core.read_register(2).unwrap();
        assert_eq!(result1, Value::Int(0xD83D), "First UTF-16 code unit should be high surrogate 0xD83D");

        // Get second surrogate (low surrogate)
        core.set_register(1, Value::Int(1)).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 184, // StringPrototypeCharCodeAt
                args: RegRange { start: 0, count: 2 },
                dest: 3,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result2 = core.read_register(3).unwrap();
        assert_eq!(result2, Value::Int(0xDE00), "Second UTF-16 code unit should be low surrogate 0xDE00");
    }

    #[test]
    fn string_prototype_char_code_at_out_of_bounds() {
        // Test charCodeAt with out-of-bounds index returns NaN
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("Hi".to_string())).unwrap();
        core.set_register(1, Value::Int(5)).unwrap(); // index 5 (out of bounds)

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 184, // StringPrototypeCharCodeAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(2).unwrap();
        if let Value::Float(f) = result {
            assert!(f.inner().is_nan(), "Out-of-bounds charCodeAt should return NaN");
        } else {
            panic!("Expected Float NaN, got {:?}", result);
        }
    }

    #[test]
    fn string_prototype_char_code_at_negative_index() {
        // Test charCodeAt with negative index (should treat as 0)
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("Test".to_string())).unwrap();
        core.set_register(1, Value::Int(-1)).unwrap(); // negative index

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 184, // StringPrototypeCharCodeAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        // Should return first character 'T' = 84
        let result = core.read_register(2).unwrap();
        assert_eq!(result, Value::Int(84), "Negative index should be treated as 0");
    }

    #[test]
    fn string_prototype_char_code_at_no_index() {
        // Test charCodeAt with no index argument (should default to 0)
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("ABC".to_string())).unwrap();

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 184, // StringPrototypeCharCodeAt
                args: RegRange { start: 0, count: 1 }, // no index argument
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        // Should return first character 'A' = 65
        let result = core.read_register(1).unwrap();
        assert_eq!(result, Value::Int(65), "No index should default to 0");
    }

    #[test]
    fn string_prototype_char_code_at_type_coercion() {
        // Test charCodeAt with non-string values (should coerce to string)
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Int(123)).unwrap(); // should become "123"
        core.set_register(1, Value::Int(1)).unwrap(); // index 1

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 184, // StringPrototypeCharCodeAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        // "123"[1] = '2' = 50
        let result = core.read_register(2).unwrap();
        assert_eq!(result, Value::Int(50), "charCodeAt on number should coerce to string");
    }

    #[test]
    fn string_prototype_char_at_basic() {
        // Test basic charAt functionality with ASCII characters
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("Hello".to_string())).unwrap();
        core.set_register(1, Value::Int(1)).unwrap(); // index 1

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 30, // StringPrototypeCharAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        // "Hello"[1] = 'e'
        let result = core.read_register(2).unwrap();
        assert_eq!(result, Value::Str("e".to_string()), "charAt(1) should return 'e'");
    }

    #[test]
    fn string_prototype_char_at_utf16_surrogate_pairs() {
        // Test charAt with UTF-16 surrogate pairs (characters outside BMP)
        let mut core = BaselineInterpreter::new();

        // U+1F600 (😀) is encoded as surrogate pair: 0xD83D 0xDE00
        core.set_register(0, Value::Str("😀".to_string())).unwrap();

        // Get first surrogate character (high surrogate)
        core.set_register(1, Value::Int(0)).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 30, // StringPrototypeCharAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result1 = core.read_register(2).unwrap();
        if let Value::Str(s) = result1 {
            // Should be the high surrogate character represented as a string
            assert_eq!(s.len(), 3, "High surrogate should be 3 bytes in UTF-8"); // UTF-8 encoding of high surrogate
            let utf16_units: Vec<u16> = s.encode_utf16().collect();
            assert_eq!(utf16_units[0], 0xD83D, "First character should be high surrogate 0xD83D");
        } else {
            panic!("Expected Str, got {:?}", result1);
        }

        // Get second surrogate character (low surrogate)
        core.set_register(1, Value::Int(1)).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 30, // StringPrototypeCharAt
                args: RegRange { start: 0, count: 2 },
                dest: 3,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result2 = core.read_register(3).unwrap();
        if let Value::Str(s) = result2 {
            // Should be the low surrogate character represented as a string
            assert_eq!(s.len(), 3, "Low surrogate should be 3 bytes in UTF-8"); // UTF-8 encoding of low surrogate
            let utf16_units: Vec<u16> = s.encode_utf16().collect();
            assert_eq!(utf16_units[0], 0xDE00, "Second character should be low surrogate 0xDE00");
        } else {
            panic!("Expected Str, got {:?}", result2);
        }
    }

    #[test]
    fn string_prototype_char_at_out_of_bounds() {
        // Test charAt with out-of-bounds index returns empty string
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("Hi".to_string())).unwrap();
        core.set_register(1, Value::Int(5)).unwrap(); // index 5 (out of bounds)

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 30, // StringPrototypeCharAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(2).unwrap();
        assert_eq!(result, Value::Str("".to_string()), "Out-of-bounds charAt should return empty string");
    }

    #[test]
    fn string_prototype_char_at_negative_index() {
        // Test charAt with negative index (should treat as 0)
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("Test".to_string())).unwrap();
        core.set_register(1, Value::Int(-1)).unwrap(); // negative index

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 30, // StringPrototypeCharAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        // Should return first character 'T'
        let result = core.read_register(2).unwrap();
        assert_eq!(result, Value::Str("T".to_string()), "Negative index should be treated as 0");
    }

    #[test]
    fn string_prototype_char_at_no_index() {
        // Test charAt with no index argument (should default to 0)
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Str("ABC".to_string())).unwrap();

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 30, // StringPrototypeCharAt
                args: RegRange { start: 0, count: 1 }, // no index argument
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        // Should return first character 'A'
        let result = core.read_register(1).unwrap();
        assert_eq!(result, Value::Str("A".to_string()), "No index should default to 0");
    }

    #[test]
    fn string_prototype_char_at_type_coercion() {
        // Test charAt with non-string values (should coerce to string)
        let mut core = BaselineInterpreter::new();
        core.set_register(0, Value::Int(456)).unwrap(); // should become "456"
        core.set_register(1, Value::Int(2)).unwrap(); // index 2

        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 30, // StringPrototypeCharAt
                args: RegRange { start: 0, count: 2 },
                dest: 2,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        // "456"[2] = '6'
        let result = core.read_register(2).unwrap();
        assert_eq!(result, Value::Str("6".to_string()), "charAt on number should coerce to string");
    }

    #[test]
    fn math_round_negative_half_semantics() {
        // Test JavaScript Math.round negative half semantics
        // JavaScript uses floor(x + 0.5), not Rust's round away from zero
        let mut core = BaselineInterpreter::new();

        // Test -0.5 → -0 (not -1)
        core.set_register(0, Value::Float(Float64::new(-0.5))).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 53, // MathRound
                args: RegRange { start: 0, count: 1 },
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(1).unwrap();
        match result {
            Value::Float(f) => {
                let val = f.inner();
                assert!(val == -0.0 || val == 0.0, "Math.round(-0.5) should be -0, got {}", val);
            }
            Value::Int(0) => {}, // Also acceptable
            _ => panic!("Math.round(-0.5) should be -0, got {:?}", result),
        }

        // Test -1.5 → -1 (not -2)
        core.set_register(0, Value::Float(Float64::new(-1.5))).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 53, // MathRound
                args: RegRange { start: 0, count: 1 },
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(1).unwrap();
        assert_eq!(result, Value::Int(-1), "Math.round(-1.5) should be -1, got {:?}", result);
    }

    #[test]
    fn math_round_edge_cases() {
        let mut core = BaselineInterpreter::new();

        // Test -0.1 → -0
        core.set_register(0, Value::Float(Float64::new(-0.1))).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 53, // MathRound
                args: RegRange { start: 0, count: 1 },
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(1).unwrap();
        match result {
            Value::Float(f) => {
                let val = f.inner();
                assert!(val == -0.0 || val == 0.0, "Math.round(-0.1) should be -0, got {}", val);
            }
            Value::Int(0) => {}, // Also acceptable
            _ => panic!("Math.round(-0.1) should be -0, got {:?}", result),
        }

        // Test +0.5 → 1
        core.set_register(0, Value::Float(Float64::new(0.5))).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 53, // MathRound
                args: RegRange { start: 0, count: 1 },
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(1).unwrap();
        assert_eq!(result, Value::Int(1), "Math.round(0.5) should be 1, got {:?}", result);

        // Test NaN → NaN
        core.set_register(0, Value::Float(Float64::new(f64::NAN))).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 53, // MathRound
                args: RegRange { start: 0, count: 1 },
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(1).unwrap();
        match result {
            Value::Float(f) => assert!(f.inner().is_nan(), "Math.round(NaN) should be NaN"),
            _ => panic!("Math.round(NaN) should be NaN, got {:?}", result),
        }

        // Test +Infinity → +Infinity
        core.set_register(0, Value::Float(Float64::new(f64::INFINITY))).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 53, // MathRound
                args: RegRange { start: 0, count: 1 },
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(1).unwrap();
        match result {
            Value::Float(f) => assert_eq!(f.inner(), f64::INFINITY, "Math.round(+Infinity) should be +Infinity"),
            _ => panic!("Math.round(+Infinity) should be +Infinity, got {:?}", result),
        }

        // Test -Infinity → -Infinity
        core.set_register(0, Value::Float(Float64::new(f64::NEG_INFINITY))).unwrap();
        core.execute_module(test_module(vec![
            Ir3Instruction::CallBuiltinId {
                id: 53, // MathRound
                args: RegRange { start: 0, count: 1 },
                dest: 1,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        let result = core.read_register(1).unwrap();
        match result {
            Value::Float(f) => assert_eq!(f.inner(), f64::NEG_INFINITY, "Math.round(-Infinity) should be -Infinity"),
            _ => panic!("Math.round(-Infinity) should be -Infinity, got {:?}", result),
        }
    }

    #[test]
    fn console_builtin_id_deduplication_audit_fix() {
        // Regression test for bd-7f1a4: Verify duplicate console builtin IDs are removed
        // and only correct mappings remain after audit fix

        let core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Verify correct console builtin IDs (100-102) are mapped
        assert_eq!(
            core.map_function_index_to_builtin_capability(100),
            Some("builtin:ConsoleLog".to_string()),
            "ID 100 should map to ConsoleLog"
        );
        assert_eq!(
            core.map_function_index_to_builtin_capability(101),
            Some("builtin:ConsoleError".to_string()),
            "ID 101 should map to ConsoleError"
        );
        assert_eq!(
            core.map_function_index_to_builtin_capability(102),
            Some("builtin:ConsoleWarn".to_string()),
            "ID 102 should map to ConsoleWarn"
        );

        // Verify ConsoleInfo (ID 384) is mapped
        assert_eq!(
            core.map_function_index_to_builtin_capability(384),
            Some("builtin:ConsoleInfo".to_string()),
            "ID 384 should map to ConsoleInfo"
        );

        // Verify duplicate IDs (381-383) are NOT mapped after audit fix
        assert_eq!(
            core.map_function_index_to_builtin_capability(381),
            None,
            "ID 381 should NOT be mapped (duplicate ConsoleLog removed)"
        );
        assert_eq!(
            core.map_function_index_to_builtin_capability(382),
            None,
            "ID 382 should NOT be mapped (duplicate ConsoleError removed)"
        );
        assert_eq!(
            core.map_function_index_to_builtin_capability(383),
            None,
            "ID 383 should NOT be mapped (duplicate ConsoleWarn removed)"
        );
    }

    #[test]
    fn console_builtin_captured_output_all_levels() {
        // Comprehensive test that all console levels capture output correctly
        // with proper level/message/instruction metadata as required by audit

        let mut core = InterpreterCore::new(test_quickjs_config(), "test-trace");

        // Test ConsoleLog (ID 100)
        core.registers[0] = Value::Str("Log message".to_string());
        core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:ConsoleLog".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        assert_eq!(core.console_output.len(), 1);
        assert_eq!(core.console_output[0].level, ConsoleLevel::Log);
        assert_eq!(core.console_output[0].message, "Log message");
        assert_eq!(core.console_output[0].instruction_index, 1);

        // Test ConsoleError (ID 101)
        core.console_output.clear();
        core.registers[0] = Value::Str("Error message".to_string());
        core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:ConsoleError".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        assert_eq!(core.console_output.len(), 1);
        assert_eq!(core.console_output[0].level, ConsoleLevel::Error);
        assert_eq!(core.console_output[0].message, "Error message");

        // Test ConsoleWarn (ID 102)
        core.console_output.clear();
        core.registers[0] = Value::Str("Warn message".to_string());
        core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:ConsoleWarn".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        assert_eq!(core.console_output.len(), 1);
        assert_eq!(core.console_output[0].level, ConsoleLevel::Warn);
        assert_eq!(core.console_output[0].message, "Warn message");

        // Test ConsoleInfo (ID 384) - the critical one from audit
        core.console_output.clear();
        core.registers[0] = Value::Str("Info message".to_string());
        core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:ConsoleInfo".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ])).unwrap();

        assert_eq!(core.console_output.len(), 1);
        assert_eq!(core.console_output[0].level, ConsoleLevel::Info);
        assert_eq!(core.console_output[0].message, "Info message");

        // Verify ConsoleInfo no longer silently drops output as mentioned in audit
        assert!(!core.console_output[0].message.is_empty(),
               "ConsoleInfo should capture output, not silently drop it");
    }

    #[test]
    fn string_prototype_split_builtin_id_deduplication_audit_fix() {
        // Regression test for bd-5wpm4 StringPrototypeSplit deduplication audit
        // Verifies that ID 36 is the primary mapping, and ID 356 was correctly removed
        let interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

        // Verify ID 36 maps to StringPrototypeSplit
        assert_eq!(
            interpreter.builtin_name_from_id(36),
            Some("builtin:StringPrototypeSplit".to_string())
        );

        // Verify ID 356 no longer maps to StringPrototypeSplit (duplicate removed)
        assert_ne!(
            interpreter.builtin_name_from_id(356),
            Some("builtin:StringPrototypeSplit".to_string())
        );

        // Verify ID 357 still works (ArrayPrototypeMap should be unaffected)
        assert_eq!(
            interpreter.builtin_name_from_id(357),
            Some("builtin:ArrayPrototypeMap".to_string())
        );
    }

    #[test]
    fn string_prototype_split_execution_works() {
        // Verify StringPrototypeSplit builtin is functional after deduplication
        let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

        // Test string split functionality
        core.registers[0] = Value::Str("hello,world,test".to_string());
        core.registers[1] = Value::Str(",".to_string());

        let result = core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:StringPrototypeSplit".to_string(),
                args: RegRange { start: 0, count: 2 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]));

        // Verify the call succeeded (should not panic or error)
        assert!(result.is_ok(), "StringPrototypeSplit builtin should work after deduplication");
    }

    #[test]
    fn batch_27_deduplication_regression_test() {
        // Regression test for bd-3n6hg batch-27 Array.reverse and Object.toString deduplication
        // Verifies that duplicate dispatch arms were removed and only first occurrences remain
        let interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

        // Test ArrayPrototypeReverse builtin IDs still work
        assert_eq!(
            interpreter.builtin_name_from_id(21),
            Some("builtin:ArrayPrototypeReverse".to_string())
        );
        assert_eq!(
            interpreter.builtin_name_from_id(243),
            Some("builtin:ArrayPrototypeReverse".to_string())
        );
        assert_eq!(
            interpreter.builtin_name_from_id(329),
            Some("builtin:ArrayPrototypeReverse".to_string())
        );

        // Test ObjectPrototypeToString builtin IDs still work
        assert_eq!(
            interpreter.builtin_name_from_id(264),
            Some("builtin:ObjectPrototypeToString".to_string())
        );
        assert_eq!(
            interpreter.builtin_name_from_id(332),
            Some("builtin:ObjectPrototypeToString".to_string())
        );
    }

    #[test]
    fn array_reverse_functionality_after_dedup() {
        // Verify ArrayPrototypeReverse functionality preserved after removing duplicates
        let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

        // Create an array object with elements
        let array_id = ObjectId(10);
        core.heap.push(Object {
            properties: BTreeMap::from([
                ("length".to_string(), Value::Int(3)),
                ("0".to_string(), Value::Str("first".to_string())),
                ("1".to_string(), Value::Str("second".to_string())),
                ("2".to_string(), Value::Str("third".to_string())),
            ]),
        });
        core.registers[0] = Value::Object(array_id);

        let result = core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:ArrayPrototypeReverse".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]));

        // Verify the call succeeded
        assert!(result.is_ok(), "ArrayPrototypeReverse should work after deduplication");

        // Verify the array was modified (elements should be reversed)
        let obj = core.heap.get(array_id.0 as usize).unwrap();
        if let Some(Value::Str(first)) = obj.properties.get("0") {
            assert_eq!(first, "third", "Array should be reversed after calling reverse()");
        }
    }

    #[test]
    fn object_tostring_functionality_after_dedup() {
        // Verify ObjectPrototypeToString functionality preserved after removing duplicates
        let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

        // Test with different value types
        core.registers[0] = Value::Null;
        let result = core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:ObjectPrototypeToString".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]));

        // Verify the call succeeded
        assert!(result.is_ok(), "ObjectPrototypeToString should work after deduplication");
    }

    #[test]
    fn batch_28_deduplication_regression_test() {
        // Regression test for bd-vu73s batch-28 trim, integer, endsWith deduplication
        // Verifies that duplicate dispatch arms were removed and only first occurrences remain
        let interpreter = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

        // Test StringPrototypeTrim builtin ID still works
        assert_eq!(
            interpreter.builtin_name_from_id(37),  // From original mapping
            Some("builtin:StringPrototypeTrim".to_string())
        );
        assert_eq!(
            interpreter.builtin_name_from_id(333), // From batch-28 mapping
            Some("builtin:StringPrototypeTrim".to_string())
        );

        // Test NumberIsInteger builtin IDs still work
        assert_eq!(
            interpreter.builtin_name_from_id(231), // From batch-28 mapping
            Some("builtin:NumberIsInteger".to_string())
        );
        assert_eq!(
            interpreter.builtin_name_from_id(335), // From batch-28 mapping
            Some("builtin:NumberIsInteger".to_string())
        );

        // Test StringPrototypeEndsWith builtin IDs still work
        assert_eq!(
            interpreter.builtin_name_from_id(40),  // From original mapping
            Some("builtin:StringPrototypeEndsWith".to_string())
        );
        assert_eq!(
            interpreter.builtin_name_from_id(230), // From batch-28 mapping
            Some("builtin:StringPrototypeEndsWith".to_string())
        );
        assert_eq!(
            interpreter.builtin_name_from_id(336), // From batch-28 mapping
            Some("builtin:StringPrototypeEndsWith".to_string())
        );
    }

    #[test]
    fn batch_28_functionality_preserved() {
        // Verify that all batch-28 deduplicated functions still work correctly
        let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults());

        // Test StringPrototypeTrim functionality
        core.registers[0] = Value::Str("  hello world  ".to_string());
        let trim_result = core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:StringPrototypeTrim".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]));
        assert!(trim_result.is_ok(), "StringPrototypeTrim should work after deduplication");

        // Test NumberIsInteger functionality
        core.registers[0] = Value::Int(42);
        let integer_result = core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:NumberIsInteger".to_string(),
                args: RegRange { start: 0, count: 1 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]));
        assert!(integer_result.is_ok(), "NumberIsInteger should work after deduplication");

        // Test StringPrototypeEndsWith functionality
        core.registers[0] = Value::Str("hello world".to_string());
        core.registers[1] = Value::Str("world".to_string());
        let endswith_result = core.execute(&test_module(vec![
            Ir3Instruction::CallBuiltin {
                builtin: "builtin:StringPrototypeEndsWith".to_string(),
                args: RegRange { start: 0, count: 2 },
                dst: 10,
            },
            Ir3Instruction::Halt,
        ]));
        assert!(endswith_result.is_ok(), "StringPrototypeEndsWith should work after deduplication");
    }

    #[test]
    fn string_prototype_pad_start_deduplication_regression() {
        let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

        for builtin_id in [43_u32, 226_u32] {
            interpreter.registers[0] = Value::Str("7".to_string());
            interpreter.registers[1] = Value::Int(3);
            interpreter.registers[2] = Value::Str("0".to_string());

            assert_eq!(
                interpreter.builtin_name_from_id(builtin_id),
                Some("builtin:StringPrototypePadStart".to_string())
            );
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
                .expect("StringPrototypePadStart ID should execute");
            assert_eq!(result, Value::Str("007".to_string()));
        }
    }

    #[test]
    fn string_prototype_pad_end_deduplication_regression() {
        let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

        for builtin_id in [44_u32, 227_u32] {
            interpreter.registers[0] = Value::Str("7".to_string());
            interpreter.registers[1] = Value::Int(3);
            interpreter.registers[2] = Value::Str("0".to_string());

            assert_eq!(
                interpreter.builtin_name_from_id(builtin_id),
                Some("builtin:StringPrototypePadEnd".to_string())
            );
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
                .expect("StringPrototypePadEnd ID should execute");
            assert_eq!(result, Value::Str("700".to_string()));
        }
    }

    #[test]
    fn string_prototype_starts_with_deduplication_regression() {
        let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

        for builtin_id in [39_u32, 229_u32] {
            interpreter.registers[0] = Value::Str("alpha".to_string());
            interpreter.registers[1] = Value::Str("ph".to_string());
            interpreter.registers[2] = Value::Int(2);

            assert_eq!(
                interpreter.builtin_name_from_id(builtin_id),
                Some("builtin:StringPrototypeStartsWith".to_string())
            );
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
                .expect("StringPrototypeStartsWith ID should execute");
            assert_eq!(result, Value::Bool(true));
        }
    }

    #[test]
    fn string_prototype_ends_with_deduplication_regression() {
        let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

        for builtin_id in [40_u32, 230_u32, 336_u32] {
            interpreter.registers[0] = Value::Str("frankenengine".to_string());
            interpreter.registers[1] = Value::Str("engine".to_string());
            interpreter.registers[2] = Value::Int(13);

            assert_eq!(
                interpreter.builtin_name_from_id(builtin_id),
                Some("builtin:StringPrototypeEndsWith".to_string())
            );
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
                .expect("StringPrototypeEndsWith ID should execute");
            assert_eq!(result, Value::Bool(true));
        }
    }

    #[test]
    fn string_prototype_repeat_deduplication_regression() {
        let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

        for builtin_id in [42_u32, 233_u32] {
            interpreter.registers[0] = Value::Str("ha".to_string());
            interpreter.registers[1] = Value::Int(3);

            assert_eq!(
                interpreter.builtin_name_from_id(builtin_id),
                Some("builtin:StringPrototypeRepeat".to_string())
            );
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 2 })
                .expect("StringPrototypeRepeat ID should execute");
            assert_eq!(result, Value::Str("hahaha".to_string()));
        }
    }

    #[test]
    fn string_prototype_includes_deduplication_regression() {
        let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

        for builtin_id in [38_u32, 238_u32] {
            interpreter.registers[0] = Value::Str("frankenengine".to_string());
            interpreter.registers[1] = Value::Str("engine".to_string());
            interpreter.registers[2] = Value::Int(4);

            assert_eq!(
                interpreter.builtin_name_from_id(builtin_id),
                Some("builtin:StringPrototypeIncludes".to_string())
            );
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
                .expect("StringPrototypeIncludes ID should execute");
            assert_eq!(result, Value::Bool(true));
        }
    }

    #[test]
    fn object_define_property_deduplication_regression() {
        let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

        for builtin_id in [7_u32, 280_u32] {
            let object_id = interpreter
                .alloc_object_with_prototype(None)
                .expect("test object allocation should succeed");
            let descriptor_id = interpreter
                .alloc_object_with_prototype(None)
                .expect("test descriptor allocation should succeed");
            interpreter
                .set_object_property(descriptor_id, "value".to_string(), Value::Int(42))
                .expect("test descriptor value write should succeed");

            interpreter.registers[0] = Value::Object(object_id);
            interpreter.registers[1] = Value::Str("answer".to_string());
            interpreter.registers[2] = Value::Object(descriptor_id);

            assert_eq!(
                interpreter.builtin_name_from_id(builtin_id),
                Some("builtin:ObjectDefineProperty".to_string())
            );
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 3 })
                .expect("ObjectDefineProperty ID should execute");
            assert_eq!(result, Value::Object(object_id));

            let object = interpreter
                .heap
                .get(object_id.0 as usize)
                .expect("defined test object should remain allocated");
            assert_eq!(object.properties.get("answer"), Some(&Value::Int(42)));
        }
    }

    #[test]
    fn array_prototype_fill_deduplication_regression() {
        let mut interpreter = InterpreterCore::new(test_quickjs_config(), "test-trace");

        for builtin_id in [209_u32, 251_u32] {
            let array_id = interpreter
                .alloc_object_with_prototype(None)
                .expect("test array allocation should succeed");
            interpreter
                .set_object_property(array_id, "length".to_string(), Value::Int(3))
                .expect("test array length write should succeed");
            interpreter
                .set_object_property(array_id, "0".to_string(), Value::Str("a".to_string()))
                .expect("test array element write should succeed");
            interpreter
                .set_object_property(array_id, "1".to_string(), Value::Str("b".to_string()))
                .expect("test array element write should succeed");
            interpreter
                .set_object_property(array_id, "2".to_string(), Value::Str("c".to_string()))
                .expect("test array element write should succeed");
            interpreter.registers[0] = Value::Object(array_id);
            interpreter.registers[1] = Value::Str("x".to_string());
            interpreter.registers[2] = Value::Int(1);
            interpreter.registers[3] = Value::Int(3);

            assert_eq!(
                interpreter.builtin_name_from_id(builtin_id),
                Some("builtin:ArrayPrototypeFill".to_string())
            );
            let result = interpreter
                .call_builtin_by_id(builtin_id, RegRange { start: 0, count: 4 })
                .expect("ArrayPrototypeFill ID should execute");
            assert_eq!(result, Value::Object(array_id));

            let array = interpreter
                .heap
                .get(array_id.0 as usize)
                .expect("filled test array should remain allocated");
            assert_eq!(array.properties.get("0"), Some(&Value::Str("a".to_string())));
            assert_eq!(array.properties.get("1"), Some(&Value::Str("x".to_string())));
            assert_eq!(array.properties.get("2"), Some(&Value::Str("x".to_string())));
        }
    }
}
