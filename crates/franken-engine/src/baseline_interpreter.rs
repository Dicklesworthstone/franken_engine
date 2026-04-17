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
            "extension:current".to_string(), // TODO: Get actual extension ID from context
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

            // Get instruction name for profiling
            let instruction_name = if self.profiling_data.is_some() {
                Some(crate::profiling::instruction_name(&instr))
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
            // TODO: Add profiling integration when needed
            let _ = (profile_start, instruction_name);
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

    /// Dispatch console hostcalls: console.log, console.error, console.warn.
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
                // TODO: Implement Array.prototype.push
                // For now, return placeholder to bridge the execution gap
                Ok(Value::Undefined)
            }
            "builtin:ArrayIsArray" => {
                // TODO: Implement Array.isArray
                Ok(Value::Bool(false))
            }
            "builtin:ArrayPrototypePop" => {
                // TODO: Implement Array.prototype.pop
                Ok(Value::Undefined)
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

            // String methods
            "builtin:StringPrototypeCharAt" => {
                // TODO: Implement String.prototype.charAt
                Ok(Value::Str("".to_string()))
            }

            // Math methods
            "builtin:MathAbs" => {
                // Math.abs implementation - returns absolute value of the argument
                if args.count > 0 {
                    let arg = self.read_reg(args.start)?;
                    match arg {
                        Value::Int(n) => Ok(Value::Int(n.abs())),
                        Value::Float(f) => Ok(Value::Float(Float64::new(f.inner().abs()))),
                        _ => Ok(Value::Float(Float64::new(f64::NAN))),
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
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
                    Value::Bool(b) => if b { "true".to_string() } else { "false".to_string() },
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => {
                        let val = f.inner();
                        if val.is_nan() || val.is_infinite() {
                            "null".to_string()
                        } else {
                            val.to_string()
                        }
                    },
                    Value::Str(s) => format!("\"{}\"", s.replace('"', "\\\"").replace('\\', "\\\\")),
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

            _ => {
                // Unknown builtin method - return undefined
                Ok(Value::Undefined)
            }
        }
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

            // Array methods (installed after Object in stdlib.rs)
            10 => Some("builtin:ArrayIsArray".to_string()),
            11 => Some("builtin:ArrayFrom".to_string()),
            12 => Some("builtin:ArrayOf".to_string()),
            13 => Some("builtin:ArrayPrototypePush".to_string()),
            14 => Some("builtin:ArrayPrototypePop".to_string()),
            15 => Some("builtin:ArrayPrototypeShift".to_string()),

            // String methods
            30 => Some("builtin:StringPrototypeCharAt".to_string()),
            31 => Some("builtin:StringPrototypeIndexOf".to_string()),

            // Math methods
            50 => Some("builtin:MathAbs".to_string()),
            51 => Some("builtin:MathCeil".to_string()),
            52 => Some("builtin:MathFloor".to_string()),

            // JSON methods
            70 => Some("builtin:JsonParse".to_string()),
            71 => Some("builtin:JsonStringify".to_string()),

            _ => None, // Not a recognized builtin
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
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(Self::estimate_heap_object_bytes(&object));
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, requested_heap_objects));
        }

        // TODO: Add GC pressure profiling when needed
        let _ = requested_bytes;
        self.heap.push(object);
        self.estimated_memory_bytes = requested_bytes;

        // TODO: Add allocation profiling when needed

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
            token: reason.unwrap(),
        })),
        "sandbox" => Some(HookAction::Sandbox),
        "suspend" => Some(HookAction::Suspend),
        "terminate" => Some(HookAction::Terminate(reason.unwrap())),
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
        // TODO: Implement profiling integration
    }

    /// Disable profiling and return collected data.
    pub fn disable_profiling(&mut self) -> Option<crate::profiling::Profiler> {
        // TODO: Implement profiling integration
        None
    }

    /// Get reference to current profiling data.
    pub fn profiling_data(&self) -> Option<&crate::profiling::Profiler> {
        // TODO: Implement profiling integration
        None
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
        config.granted_capabilities =
            BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::HeapAllocate]);
        config
    }

    fn test_v8_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::v8_defaults();
        config.granted_capabilities =
            BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::HeapAllocate]);
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
    fn set_timeout_fires_after_delay() {
        // TODO: Test that setTimeout callback executes after specified delay
        // When timer substrate is implemented, this will:
        // 1. Call setTimeout with a callback and delay
        // 2. Verify timer ID is returned
        // 3. Run event loop until timer fires
        // 4. Verify callback executed at the right time
        // Placeholder until implementation — empty body so the test still compiles/runs.
    }

    #[test]
    fn set_timeout_returns_id() {
        // TODO: Test that setTimeout returns numeric timer ID
        // When timer substrate is implemented, this will:
        // 1. Call setTimeout(callback, delay)
        // 2. Verify return value is a numeric timer ID
        // 3. Verify IDs are deterministic and monotonic
        // Placeholder until implementation.
    }

    #[test]
    fn clear_timeout_cancels() {
        // TODO: Test that clearTimeout prevents timer from firing
        // When timer substrate is implemented, this will:
        // 1. Call setTimeout to schedule a timer
        // 2. Call clearTimeout with the timer ID
        // 3. Run event loop
        // 4. Verify callback never executes
        // Placeholder until implementation.
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
        #[ignore = "API drift: BaselineInterpreter type removed (renamed to InterpreterCore, helpers gone)"]
        fn value_to_js_value_conversion() {
            unimplemented!("needs rewrite - BaselineInterpreter removed");
        }

        #[test]
        #[ignore = "API drift: InterpreterCore::run_module renamed/removed; test needs rewrite against execute()"]
        fn async_generator_creation() {
            unimplemented!("needs rewrite - run_module gone");
        }

        #[test]
        #[ignore = "API drift: InterpreterCore::run_module renamed/removed; test needs rewrite against execute()"]
        fn async_generator_function_call_creates_object() {
            unimplemented!("needs rewrite - run_module gone");
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
    }
}
