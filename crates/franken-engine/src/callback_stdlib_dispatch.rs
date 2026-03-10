#![forbid(unsafe_code)]

//! Callback-driven stdlib dispatch for collection and array-style methods.
//!
//! JavaScript's collection methods (`Array.prototype.map`, `filter`, `reduce`,
//! `forEach`, `find`, `flatMap`, `sort`, etc.) dominate real-world workloads.
//! Each method accepts a user-supplied callback, and the choice of dispatch
//! strategy — interpreter loop, inlined fast path, specialized builtin, or
//! fallback — materially affects throughput, deoptimization risk, and
//! evidence-stream fidelity.
//!
//! This module models the dispatch decision surface:
//!
//! - **StdlibMethod**: The enumeration of supported collection/object/promise
//!   stdlib methods with callback parameters.
//! - **CallbackKind**: Classification of the user-supplied callback (pure,
//!   mutating, async, generator, builtin).
//! - **DispatchStrategy**: The execution strategy selected for a
//!   (method, callback) pair.
//! - **DispatchDecision**: A concrete decision record with cost estimates,
//!   deopt risk, and content hash for replay determinism.
//! - **DispatchTrace**: An aggregated trace of all dispatch decisions for a
//!   compilation unit.
//!
//! All cost and risk values use fixed-point millionths (1_000_000 = 1.0) for
//! cross-platform determinism.
//!
//! Plan reference: bd-1lsy.4.9.1 [RGC-311A].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Module component name for diagnostics.
pub const COMPONENT: &str = "callback_stdlib_dispatch";

/// Schema version for dispatch decisions and traces.
pub const DISPATCH_SCHEMA_VERSION: &str = "franken-engine.callback-stdlib-dispatch.v1";

/// Bead identifier for provenance tracking.
pub const BEAD_ID: &str = "bd-1lsy.4.9.1";

/// Fixed-point unit: 1.0 represented as millionths.
const MILLIONTHS_UNIT: u64 = 1_000_000;

/// Base cost (millionths) for interpreter callback dispatch.
const INTERPRETER_BASE_COST: u64 = 500_000; // 0.5

/// Base cost (millionths) for inlined callback dispatch.
const INLINED_BASE_COST: u64 = 100_000; // 0.1

/// Base cost (millionths) for specialized builtin dispatch.
const SPECIALIZED_BASE_COST: u64 = 50_000; // 0.05

/// Base cost (millionths) for fallback slow dispatch.
const FALLBACK_BASE_COST: u64 = 800_000; // 0.8

/// Deopt risk (millionths) for pure function callbacks.
const PURE_DEOPT_RISK: u64 = 50_000; // 0.05

/// Deopt risk (millionths) for mutating function callbacks.
const MUTATING_DEOPT_RISK: u64 = 350_000; // 0.35

/// Deopt risk (millionths) for async function callbacks.
const ASYNC_DEOPT_RISK: u64 = 600_000; // 0.6

/// Deopt risk (millionths) for generator function callbacks.
const GENERATOR_DEOPT_RISK: u64 = 700_000; // 0.7

/// Deopt risk (millionths) for builtin function callbacks.
const BUILTIN_DEOPT_RISK: u64 = 20_000; // 0.02

/// Per-element cost multiplier scale factor (millionths per element).
const PER_ELEMENT_COST_INTERPRETER: u64 = 1_000; // 0.001

/// Per-element cost multiplier for inlined dispatch.
const PER_ELEMENT_COST_INLINED: u64 = 200; // 0.0002

/// Per-element cost multiplier for specialized dispatch.
const PER_ELEMENT_COST_SPECIALIZED: u64 = 100; // 0.0001

/// Per-element cost multiplier for fallback dispatch.
const PER_ELEMENT_COST_FALLBACK: u64 = 1_500; // 0.0015

/// Maximum stack depth for recursive stdlib callback chains.
const MAX_CALLBACK_STACK_DEPTH: u32 = 64;

/// Threshold (millionths) above which deopt risk forces fallback.
const DEOPT_RISK_FALLBACK_THRESHOLD: u64 = 800_000; // 0.8

/// Cost penalty multiplier for reduce (accumulator overhead).
const REDUCE_OVERHEAD_MULTIPLIER: u64 = 1_200_000; // 1.2x

/// Cost penalty multiplier for flatMap (flattening overhead).
const FLATMAP_OVERHEAD_MULTIPLIER: u64 = 1_500_000; // 1.5x

/// Cost penalty multiplier for sort (comparison callback overhead).
const SORT_OVERHEAD_MULTIPLIER: u64 = 2_000_000; // 2.0x

// ---------------------------------------------------------------------------
// StdlibMethod — supported collection/object stdlib methods
// ---------------------------------------------------------------------------

/// Enumeration of stdlib methods that accept callback parameters and are
/// eligible for dispatch optimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StdlibMethod {
    /// `Array.prototype.map(callback)`
    ArrayMap,
    /// `Array.prototype.filter(callback)`
    ArrayFilter,
    /// `Array.prototype.reduce(callback, initialValue)`
    ArrayReduce,
    /// `Array.prototype.forEach(callback)`
    ArrayForEach,
    /// `Array.prototype.find(callback)`
    ArrayFind,
    /// `Array.prototype.findIndex(callback)`
    ArrayFindIndex,
    /// `Array.prototype.flatMap(callback)`
    ArrayFlatMap,
    /// `Array.prototype.some(callback)`
    ArraySome,
    /// `Array.prototype.every(callback)`
    ArrayEvery,
    /// `Array.prototype.sort(compareFn)`
    ArraySort,
    /// `Array.from(iterable, mapFn)`
    ArrayFrom,
    /// `Object.keys(obj)` — no callback but participates in dispatch chains.
    ObjectKeys,
    /// `Object.values(obj)`
    ObjectValues,
    /// `Object.entries(obj)`
    ObjectEntries,
    /// `Promise.prototype.then(onFulfilled, onRejected)`
    PromiseThen,
    /// `Set.prototype.forEach(callback)`
    SetForEach,
}

impl StdlibMethod {
    /// All method variants for exhaustive enumeration.
    pub const ALL: &'static [StdlibMethod] = &[
        StdlibMethod::ArrayMap,
        StdlibMethod::ArrayFilter,
        StdlibMethod::ArrayReduce,
        StdlibMethod::ArrayForEach,
        StdlibMethod::ArrayFind,
        StdlibMethod::ArrayFindIndex,
        StdlibMethod::ArrayFlatMap,
        StdlibMethod::ArraySome,
        StdlibMethod::ArrayEvery,
        StdlibMethod::ArraySort,
        StdlibMethod::ArrayFrom,
        StdlibMethod::ObjectKeys,
        StdlibMethod::ObjectValues,
        StdlibMethod::ObjectEntries,
        StdlibMethod::PromiseThen,
        StdlibMethod::SetForEach,
    ];

    /// Whether this method produces a new collection (map, filter, flatMap,
    /// from) as opposed to side-effecting iteration (forEach, find, reduce).
    pub fn produces_collection(&self) -> bool {
        matches!(
            self,
            StdlibMethod::ArrayMap
                | StdlibMethod::ArrayFilter
                | StdlibMethod::ArrayFlatMap
                | StdlibMethod::ArrayFrom
                | StdlibMethod::ObjectKeys
                | StdlibMethod::ObjectValues
                | StdlibMethod::ObjectEntries
        )
    }

    /// Whether this method can short-circuit (find, findIndex, some, every).
    pub fn can_short_circuit(&self) -> bool {
        matches!(
            self,
            StdlibMethod::ArrayFind
                | StdlibMethod::ArrayFindIndex
                | StdlibMethod::ArraySome
                | StdlibMethod::ArrayEvery
        )
    }

    /// Whether this method requires a comparator callback (sort).
    pub fn requires_comparator(&self) -> bool {
        matches!(self, StdlibMethod::ArraySort)
    }

    /// Whether this method involves an accumulator (reduce).
    pub fn has_accumulator(&self) -> bool {
        matches!(self, StdlibMethod::ArrayReduce)
    }

    /// Whether this is an async dispatch target (Promise.then).
    pub fn is_async_dispatch(&self) -> bool {
        matches!(self, StdlibMethod::PromiseThen)
    }

    /// Human-readable method name for diagnostics.
    pub fn method_name(&self) -> &'static str {
        match self {
            StdlibMethod::ArrayMap => "Array.prototype.map",
            StdlibMethod::ArrayFilter => "Array.prototype.filter",
            StdlibMethod::ArrayReduce => "Array.prototype.reduce",
            StdlibMethod::ArrayForEach => "Array.prototype.forEach",
            StdlibMethod::ArrayFind => "Array.prototype.find",
            StdlibMethod::ArrayFindIndex => "Array.prototype.findIndex",
            StdlibMethod::ArrayFlatMap => "Array.prototype.flatMap",
            StdlibMethod::ArraySome => "Array.prototype.some",
            StdlibMethod::ArrayEvery => "Array.prototype.every",
            StdlibMethod::ArraySort => "Array.prototype.sort",
            StdlibMethod::ArrayFrom => "Array.from",
            StdlibMethod::ObjectKeys => "Object.keys",
            StdlibMethod::ObjectValues => "Object.values",
            StdlibMethod::ObjectEntries => "Object.entries",
            StdlibMethod::PromiseThen => "Promise.prototype.then",
            StdlibMethod::SetForEach => "Set.prototype.forEach",
        }
    }

    /// The cost overhead multiplier for this method (millionths, 1.0 = 1_000_000).
    fn overhead_multiplier(&self) -> u64 {
        match self {
            StdlibMethod::ArrayReduce => REDUCE_OVERHEAD_MULTIPLIER,
            StdlibMethod::ArrayFlatMap => FLATMAP_OVERHEAD_MULTIPLIER,
            StdlibMethod::ArraySort => SORT_OVERHEAD_MULTIPLIER,
            _ => MILLIONTHS_UNIT, // 1.0x — no overhead
        }
    }
}

impl fmt::Display for StdlibMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.method_name())
    }
}

// ---------------------------------------------------------------------------
// CallbackKind — classification of user-supplied callbacks
// ---------------------------------------------------------------------------

/// Classification of the callback argument passed to a stdlib method.
///
/// The callback kind determines eligibility for inlining, specialization,
/// and the deoptimization risk associated with the dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CallbackKind {
    /// A pure function with no observable side effects.
    PureFunction,
    /// A function that mutates shared state (e.g., closes over mutable variables).
    MutatingFunction,
    /// An async function (returns a Promise).
    AsyncFunction,
    /// A generator function (yields values).
    GeneratorFunction,
    /// A well-known builtin function (e.g., `Number`, `String`, `Boolean`).
    BuiltinFunction,
}

impl CallbackKind {
    /// All callback kind variants.
    pub const ALL: &'static [CallbackKind] = &[
        CallbackKind::PureFunction,
        CallbackKind::MutatingFunction,
        CallbackKind::AsyncFunction,
        CallbackKind::GeneratorFunction,
        CallbackKind::BuiltinFunction,
    ];

    /// The deoptimization risk (millionths) associated with this callback kind.
    pub fn deopt_risk_millionths(&self) -> u64 {
        match self {
            CallbackKind::PureFunction => PURE_DEOPT_RISK,
            CallbackKind::MutatingFunction => MUTATING_DEOPT_RISK,
            CallbackKind::AsyncFunction => ASYNC_DEOPT_RISK,
            CallbackKind::GeneratorFunction => GENERATOR_DEOPT_RISK,
            CallbackKind::BuiltinFunction => BUILTIN_DEOPT_RISK,
        }
    }

    /// Whether this callback kind is eligible for inlining.
    pub fn is_inlining_eligible(&self) -> bool {
        matches!(
            self,
            CallbackKind::PureFunction | CallbackKind::BuiltinFunction
        )
    }

    /// Whether this callback kind may produce async control flow.
    pub fn is_async(&self) -> bool {
        matches!(self, CallbackKind::AsyncFunction)
    }

    /// Human-readable name for diagnostics.
    pub fn kind_name(&self) -> &'static str {
        match self {
            CallbackKind::PureFunction => "pure",
            CallbackKind::MutatingFunction => "mutating",
            CallbackKind::AsyncFunction => "async",
            CallbackKind::GeneratorFunction => "generator",
            CallbackKind::BuiltinFunction => "builtin",
        }
    }
}

impl fmt::Display for CallbackKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "callback:{}", self.kind_name())
    }
}

// ---------------------------------------------------------------------------
// DispatchStrategy — execution strategy for a (method, callback) pair
// ---------------------------------------------------------------------------

/// The execution strategy chosen for dispatching a stdlib method with a
/// particular callback kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DispatchStrategy {
    /// Execute the callback through the interpreter loop per element.
    /// Safe but slow — used when no optimization is provably safe.
    InterpreterCallback,
    /// Inline the callback body into the iteration loop.
    /// Fast but requires the callback to be pure or builtin.
    InlinedCallback,
    /// Use a specialized builtin path that bypasses the callback entirely.
    /// Only applicable when the callback is a well-known builtin.
    SpecializedBuiltin,
    /// Fallback slow path with full safety checks.
    /// Used when the callback kind has unacceptable deopt risk.
    FallbackSlow,
}

impl DispatchStrategy {
    /// All strategy variants.
    pub const ALL: &'static [DispatchStrategy] = &[
        DispatchStrategy::InterpreterCallback,
        DispatchStrategy::InlinedCallback,
        DispatchStrategy::SpecializedBuiltin,
        DispatchStrategy::FallbackSlow,
    ];

    /// The base cost (millionths) for this strategy.
    pub fn base_cost_millionths(&self) -> u64 {
        match self {
            DispatchStrategy::InterpreterCallback => INTERPRETER_BASE_COST,
            DispatchStrategy::InlinedCallback => INLINED_BASE_COST,
            DispatchStrategy::SpecializedBuiltin => SPECIALIZED_BASE_COST,
            DispatchStrategy::FallbackSlow => FALLBACK_BASE_COST,
        }
    }

    /// The per-element cost increment (millionths) for this strategy.
    pub fn per_element_cost_millionths(&self) -> u64 {
        match self {
            DispatchStrategy::InterpreterCallback => PER_ELEMENT_COST_INTERPRETER,
            DispatchStrategy::InlinedCallback => PER_ELEMENT_COST_INLINED,
            DispatchStrategy::SpecializedBuiltin => PER_ELEMENT_COST_SPECIALIZED,
            DispatchStrategy::FallbackSlow => PER_ELEMENT_COST_FALLBACK,
        }
    }

    /// Whether this strategy involves inlining the callback.
    pub fn is_inlined(&self) -> bool {
        matches!(
            self,
            DispatchStrategy::InlinedCallback | DispatchStrategy::SpecializedBuiltin
        )
    }

    /// Whether this strategy is a fallback/slow path.
    pub fn is_fallback(&self) -> bool {
        matches!(self, DispatchStrategy::FallbackSlow)
    }

    /// Human-readable strategy name.
    pub fn strategy_name(&self) -> &'static str {
        match self {
            DispatchStrategy::InterpreterCallback => "interpreter",
            DispatchStrategy::InlinedCallback => "inlined",
            DispatchStrategy::SpecializedBuiltin => "specialized-builtin",
            DispatchStrategy::FallbackSlow => "fallback-slow",
        }
    }
}

impl fmt::Display for DispatchStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "strategy:{}", self.strategy_name())
    }
}

// ---------------------------------------------------------------------------
// StdlibDispatchError — typed error for dispatch operations
// ---------------------------------------------------------------------------

/// Errors that can occur during stdlib dispatch selection and trace building.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StdlibDispatchError {
    /// The given method is not supported for callback dispatch.
    UnsupportedMethod,
    /// The callback type is unsafe for the requested dispatch strategy.
    CallbackTypeUnsafe,
    /// Callback stack depth exceeded.
    StackOverflow,
    /// An internal consistency error.
    InternalError(String),
}

impl fmt::Display for StdlibDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StdlibDispatchError::UnsupportedMethod => {
                write!(f, "unsupported stdlib method for callback dispatch")
            }
            StdlibDispatchError::CallbackTypeUnsafe => {
                write!(f, "callback type is unsafe for requested dispatch strategy")
            }
            StdlibDispatchError::StackOverflow => {
                write!(
                    f,
                    "callback stack depth exceeded maximum ({MAX_CALLBACK_STACK_DEPTH})"
                )
            }
            StdlibDispatchError::InternalError(msg) => {
                write!(f, "internal dispatch error: {msg}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DispatchDecision — a concrete dispatch decision record
// ---------------------------------------------------------------------------

/// A concrete dispatch decision for a single (method, callback) invocation.
///
/// Records the selected strategy, estimated cost, deoptimization risk, and
/// a content hash for deterministic replay verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchDecision {
    /// The stdlib method being dispatched.
    pub method: StdlibMethod,
    /// The classification of the user-supplied callback.
    pub callback_kind: CallbackKind,
    /// The selected dispatch strategy.
    pub strategy: DispatchStrategy,
    /// Estimated total cost (millionths) for this dispatch.
    pub estimated_cost_millionths: u64,
    /// Estimated deoptimization risk (millionths) for this dispatch.
    pub deopt_risk_millionths: u64,
    /// Content hash of the decision inputs for replay determinism.
    pub content_hash: ContentHash,
}

impl DispatchDecision {
    /// Whether this decision selected an inlined (fast) path.
    pub fn is_fast_path(&self) -> bool {
        self.strategy.is_inlined()
    }

    /// Whether this decision fell back to the slow path.
    pub fn is_slow_path(&self) -> bool {
        self.strategy.is_fallback()
    }

    /// Whether the deopt risk exceeds the fallback threshold.
    pub fn is_high_deopt_risk(&self) -> bool {
        self.deopt_risk_millionths >= DEOPT_RISK_FALLBACK_THRESHOLD
    }
}

impl fmt::Display for DispatchDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dispatch({} + {} -> {}, cost={}, deopt={})",
            self.method,
            self.callback_kind,
            self.strategy,
            self.estimated_cost_millionths,
            self.deopt_risk_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// DispatchTrace — aggregated trace of all dispatch decisions
// ---------------------------------------------------------------------------

/// Aggregated trace of all dispatch decisions for a compilation unit or
/// execution session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchTrace {
    /// Unique identifier for this trace.
    pub trace_id: String,
    /// Ordered sequence of dispatch decisions.
    pub decisions: Vec<DispatchDecision>,
    /// Total estimated cost across all decisions (millionths).
    pub total_cost_millionths: u64,
    /// Count of decisions that selected an inlined strategy.
    pub inlined_count: u64,
    /// Count of decisions that fell back to the slow path.
    pub fallback_count: u64,
}

impl DispatchTrace {
    /// Fraction of decisions that used the inlined path (millionths).
    pub fn inlined_fraction_millionths(&self) -> u64 {
        let total = self.decisions.len() as u64;
        if total == 0 {
            return 0;
        }
        self.inlined_count
            .saturating_mul(MILLIONTHS_UNIT)
            .checked_div(total)
            .unwrap_or(0)
    }

    /// Fraction of decisions that used the fallback path (millionths).
    pub fn fallback_fraction_millionths(&self) -> u64 {
        let total = self.decisions.len() as u64;
        if total == 0 {
            return 0;
        }
        self.fallback_count
            .saturating_mul(MILLIONTHS_UNIT)
            .checked_div(total)
            .unwrap_or(0)
    }

    /// Average cost per decision (millionths), or 0 if empty.
    pub fn average_cost_millionths(&self) -> u64 {
        let count = self.decisions.len() as u64;
        if count == 0 {
            return 0;
        }
        self.total_cost_millionths.checked_div(count).unwrap_or(0)
    }

    /// Maximum deopt risk across all decisions (millionths).
    pub fn max_deopt_risk_millionths(&self) -> u64 {
        self.decisions
            .iter()
            .map(|d| d.deopt_risk_millionths)
            .max()
            .unwrap_or(0)
    }

    /// Content hash of the entire trace for deterministic verification.
    pub fn trace_content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(DISPATCH_SCHEMA_VERSION.as_bytes());
        buf.extend_from_slice(self.trace_id.as_bytes());
        for decision in &self.decisions {
            buf.extend_from_slice(decision.content_hash.as_bytes());
        }
        buf.extend_from_slice(&self.total_cost_millionths.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for DispatchTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trace({}, decisions={}, cost={}, inlined={}, fallback={})",
            self.trace_id,
            self.decisions.len(),
            self.total_cost_millionths,
            self.inlined_count,
            self.fallback_count,
        )
    }
}

// ---------------------------------------------------------------------------
// DispatchProfile — summary statistics for a dispatch trace
// ---------------------------------------------------------------------------

/// Summary statistics aggregated from a dispatch trace for performance
/// analysis and regression detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchProfile {
    /// Number of distinct methods dispatched.
    pub distinct_methods: u64,
    /// Number of distinct callback kinds observed.
    pub distinct_callback_kinds: u64,
    /// Number of distinct strategies selected.
    pub distinct_strategies: u64,
    /// Total decisions in the profile.
    pub total_decisions: u64,
    /// Total estimated cost (millionths).
    pub total_cost_millionths: u64,
    /// Average deopt risk (millionths).
    pub average_deopt_risk_millionths: u64,
    /// Content hash of the profile.
    pub content_hash: ContentHash,
}

impl fmt::Display for DispatchProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "profile(methods={}, kinds={}, strategies={}, decisions={}, cost={})",
            self.distinct_methods,
            self.distinct_callback_kinds,
            self.distinct_strategies,
            self.total_decisions,
            self.total_cost_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// DispatchConstraints — limits for dispatch selection
// ---------------------------------------------------------------------------

/// Constraints governing dispatch strategy selection and trace assembly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchConstraints {
    /// Maximum allowable deopt risk (millionths) before forcing fallback.
    pub max_deopt_risk_millionths: u64,
    /// Maximum callback stack depth.
    pub max_stack_depth: u32,
    /// Whether to allow inlining of mutating callbacks.
    pub allow_mutating_inline: bool,
    /// Whether to allow async dispatch for non-promise methods.
    pub allow_async_non_promise: bool,
    /// Security epoch for this dispatch session.
    pub epoch: SecurityEpoch,
}

impl Default for DispatchConstraints {
    fn default() -> Self {
        Self {
            max_deopt_risk_millionths: DEOPT_RISK_FALLBACK_THRESHOLD,
            max_stack_depth: MAX_CALLBACK_STACK_DEPTH,
            allow_mutating_inline: false,
            allow_async_non_promise: false,
            epoch: SecurityEpoch::from_raw(1),
        }
    }
}

impl fmt::Display for DispatchConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "constraints(max-deopt={}, max-depth={}, mut-inline={}, async-nonp={})",
            self.max_deopt_risk_millionths,
            self.max_stack_depth,
            self.allow_mutating_inline,
            self.allow_async_non_promise,
        )
    }
}

// ---------------------------------------------------------------------------
// Core dispatch logic
// ---------------------------------------------------------------------------

/// Select the optimal dispatch strategy for a (method, callback) pair.
///
/// Decision rules:
/// 1. Builtin callbacks on non-async methods -> `SpecializedBuiltin`.
/// 2. Pure callbacks on non-comparator, non-reduce methods -> `InlinedCallback`.
/// 3. Async callbacks on `PromiseThen` -> `InterpreterCallback`.
/// 4. Generator or async callbacks -> `FallbackSlow` (high deopt risk).
/// 5. Mutating callbacks -> `InterpreterCallback` (safe but slow).
/// 6. Everything else -> `FallbackSlow`.
pub fn select_strategy(method: StdlibMethod, callback: CallbackKind) -> DispatchStrategy {
    match callback {
        // Builtin functions get specialized dispatch unless method is async.
        CallbackKind::BuiltinFunction => {
            if method.is_async_dispatch() {
                DispatchStrategy::InterpreterCallback
            } else {
                DispatchStrategy::SpecializedBuiltin
            }
        }
        // Pure functions can be inlined for most methods.
        CallbackKind::PureFunction => {
            if method.requires_comparator() {
                // Sort comparators run O(n log n) times; interpreter is safer.
                DispatchStrategy::InterpreterCallback
            } else {
                DispatchStrategy::InlinedCallback
            }
        }
        // Async callbacks only make sense for Promise.then.
        CallbackKind::AsyncFunction => {
            if method.is_async_dispatch() {
                DispatchStrategy::InterpreterCallback
            } else {
                DispatchStrategy::FallbackSlow
            }
        }
        // Generator callbacks always need fallback.
        CallbackKind::GeneratorFunction => DispatchStrategy::FallbackSlow,
        // Mutating callbacks use interpreter for safety.
        CallbackKind::MutatingFunction => {
            if method.can_short_circuit() {
                // Short-circuit methods with mutation need extra care.
                DispatchStrategy::FallbackSlow
            } else {
                DispatchStrategy::InterpreterCallback
            }
        }
    }
}

/// Estimate the total dispatch cost (millionths) for a method with a given
/// strategy and element count.
///
/// Cost = (base + per_element * element_count) * method_overhead_multiplier
pub fn estimate_dispatch_cost(
    method: StdlibMethod,
    strategy: &DispatchStrategy,
    element_count: u64,
) -> u64 {
    let base = strategy.base_cost_millionths();
    let per_element = strategy.per_element_cost_millionths();
    let raw_cost = base.saturating_add(per_element.saturating_mul(element_count));
    let overhead = method.overhead_multiplier();
    // Multiply by overhead (which is in millionths) and divide by MILLIONTHS_UNIT.
    raw_cost
        .saturating_mul(overhead)
        .checked_div(MILLIONTHS_UNIT)
        .unwrap_or(raw_cost)
}

/// Build a dispatch decision for a (method, callback) pair.
///
/// Selects the strategy, computes estimated cost (for a nominal 100-element
/// collection), and records the deopt risk and content hash.
pub fn build_decision(method: StdlibMethod, callback: CallbackKind) -> DispatchDecision {
    let strategy = select_strategy(method, callback);
    let estimated_cost = estimate_dispatch_cost(method, &strategy, 100);
    let deopt_risk = callback.deopt_risk_millionths();

    // Compute content hash from decision inputs.
    let content_hash = compute_decision_hash(method, callback, strategy);

    DispatchDecision {
        method,
        callback_kind: callback,
        strategy,
        estimated_cost_millionths: estimated_cost,
        deopt_risk_millionths: deopt_risk,
        content_hash,
    }
}

/// Build an aggregated dispatch trace from a vector of decisions.
///
/// Computes totals and counts for the trace summary.
pub fn build_trace(decisions: Vec<DispatchDecision>) -> DispatchTrace {
    let total_cost = decisions
        .iter()
        .map(|d| d.estimated_cost_millionths)
        .fold(0u64, |acc, c| acc.saturating_add(c));

    let inlined_count = decisions.iter().filter(|d| d.strategy.is_inlined()).count() as u64;

    let fallback_count = decisions
        .iter()
        .filter(|d| d.strategy.is_fallback())
        .count() as u64;

    let trace_id = {
        let mut buf = Vec::new();
        buf.extend_from_slice(DISPATCH_SCHEMA_VERSION.as_bytes());
        buf.extend_from_slice(&(decisions.len() as u64).to_le_bytes());
        buf.extend_from_slice(&total_cost.to_le_bytes());
        let hash = ContentHash::compute(&buf);
        format!("trace-{}", &hash.to_hex()[..16])
    };

    DispatchTrace {
        trace_id,
        decisions,
        total_cost_millionths: total_cost,
        inlined_count,
        fallback_count,
    }
}

/// Check whether a (method, callback) pair is eligible for inlining.
///
/// Inlining requires:
/// 1. The callback must be inlining-eligible (pure or builtin).
/// 2. The method must not be a comparator (sort).
/// 3. The method must not be async dispatch (Promise.then).
pub fn is_inlineable(method: &StdlibMethod, callback: &CallbackKind) -> bool {
    if !callback.is_inlining_eligible() {
        return false;
    }
    if method.requires_comparator() {
        return false;
    }
    if method.is_async_dispatch() {
        return false;
    }
    true
}

/// Validate that a callback stack depth is within limits.
pub fn validate_stack_depth(
    current_depth: u32,
    constraints: &DispatchConstraints,
) -> Result<(), StdlibDispatchError> {
    if current_depth >= constraints.max_stack_depth {
        return Err(StdlibDispatchError::StackOverflow);
    }
    Ok(())
}

/// Compute a constrained dispatch decision that respects dispatch constraints.
///
/// If the natural strategy would exceed deopt risk limits or violate
/// constraints, the decision is downgraded to fallback.
pub fn constrained_decision(
    method: StdlibMethod,
    callback: CallbackKind,
    constraints: &DispatchConstraints,
    stack_depth: u32,
) -> Result<DispatchDecision, StdlibDispatchError> {
    validate_stack_depth(stack_depth, constraints)?;

    // Reject async callbacks on non-promise methods unless explicitly allowed.
    if callback.is_async() && !method.is_async_dispatch() && !constraints.allow_async_non_promise {
        return Err(StdlibDispatchError::CallbackTypeUnsafe);
    }

    let mut decision = build_decision(method, callback);

    // Enforce deopt risk ceiling.
    if decision.deopt_risk_millionths > constraints.max_deopt_risk_millionths {
        decision.strategy = DispatchStrategy::FallbackSlow;
        decision.estimated_cost_millionths =
            estimate_dispatch_cost(method, &DispatchStrategy::FallbackSlow, 100);
        decision.content_hash =
            compute_decision_hash(method, callback, DispatchStrategy::FallbackSlow);
    }

    // Disallow mutating-inline unless constraint permits.
    if callback == CallbackKind::MutatingFunction
        && decision.strategy == DispatchStrategy::InlinedCallback
        && !constraints.allow_mutating_inline
    {
        decision.strategy = DispatchStrategy::InterpreterCallback;
        decision.estimated_cost_millionths =
            estimate_dispatch_cost(method, &DispatchStrategy::InterpreterCallback, 100);
        decision.content_hash =
            compute_decision_hash(method, callback, DispatchStrategy::InterpreterCallback);
    }

    Ok(decision)
}

/// Build a dispatch profile summarizing a trace.
pub fn build_profile(trace: &DispatchTrace) -> DispatchProfile {
    let mut methods = std::collections::BTreeSet::new();
    let mut kinds = std::collections::BTreeSet::new();
    let mut strategies = std::collections::BTreeSet::new();
    let mut total_deopt: u64 = 0;

    for d in &trace.decisions {
        methods.insert(d.method);
        kinds.insert(d.callback_kind);
        strategies.insert(d.strategy);
        total_deopt = total_deopt.saturating_add(d.deopt_risk_millionths);
    }

    let count = trace.decisions.len() as u64;
    let avg_deopt = if count > 0 {
        total_deopt.checked_div(count).unwrap_or(0)
    } else {
        0
    };

    let mut hash_buf = Vec::new();
    hash_buf.extend_from_slice(b"profile::");
    hash_buf.extend_from_slice(&count.to_le_bytes());
    hash_buf.extend_from_slice(&trace.total_cost_millionths.to_le_bytes());
    hash_buf.extend_from_slice(&avg_deopt.to_le_bytes());

    DispatchProfile {
        distinct_methods: methods.len() as u64,
        distinct_callback_kinds: kinds.len() as u64,
        distinct_strategies: strategies.len() as u64,
        total_decisions: count,
        total_cost_millionths: trace.total_cost_millionths,
        average_deopt_risk_millionths: avg_deopt,
        content_hash: ContentHash::compute(&hash_buf),
    }
}

/// Canonical stdlib dispatch manifest: builds a trace containing one decision
/// for every (method, callback_kind) pair using default constraints.
///
/// Used for regression testing and evidence-stream seeding.
pub fn franken_engine_stdlib_dispatch_manifest() -> DispatchTrace {
    let constraints = DispatchConstraints::default();
    let mut decisions = Vec::new();

    for method in StdlibMethod::ALL {
        for kind in CallbackKind::ALL {
            // Skip invalid combinations (async on non-promise) to produce
            // a clean manifest.
            if kind.is_async() && !method.is_async_dispatch() {
                continue;
            }
            if let Ok(decision) = constrained_decision(*method, *kind, &constraints, 0) {
                decisions.push(decision);
            }
        }
    }

    build_trace(decisions)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic content hash for a dispatch decision.
fn compute_decision_hash(
    method: StdlibMethod,
    callback: CallbackKind,
    strategy: DispatchStrategy,
) -> ContentHash {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(DISPATCH_SCHEMA_VERSION.as_bytes());
    buf.extend_from_slice(b"::");
    buf.extend_from_slice(method.method_name().as_bytes());
    buf.extend_from_slice(b"::");
    buf.extend_from_slice(callback.kind_name().as_bytes());
    buf.extend_from_slice(b"::");
    buf.extend_from_slice(strategy.strategy_name().as_bytes());
    ContentHash::compute(&buf)
}

/// Classify a numeric deopt risk value into a human-readable tier.
pub fn deopt_risk_tier(risk_millionths: u64) -> &'static str {
    if risk_millionths < 100_000 {
        "negligible"
    } else if risk_millionths < 300_000 {
        "low"
    } else if risk_millionths < 600_000 {
        "moderate"
    } else if risk_millionths < DEOPT_RISK_FALLBACK_THRESHOLD {
        "high"
    } else {
        "critical"
    }
}

/// Compute the total element-count-adjusted cost for a batch of decisions
/// with varying element counts.
pub fn batch_cost(decisions_with_counts: &[(StdlibMethod, DispatchStrategy, u64)]) -> u64 {
    decisions_with_counts
        .iter()
        .map(|(method, strategy, count)| estimate_dispatch_cost(*method, strategy, *count))
        .fold(0u64, |acc, c| acc.saturating_add(c))
}

/// Return the optimal strategy for a method assuming a pure callback.
pub fn optimal_pure_strategy(method: StdlibMethod) -> DispatchStrategy {
    select_strategy(method, CallbackKind::PureFunction)
}

/// Return the worst-case strategy for a method assuming a generator callback.
pub fn worst_case_strategy(method: StdlibMethod) -> DispatchStrategy {
    select_strategy(method, CallbackKind::GeneratorFunction)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- StdlibMethod tests --

    #[test]
    fn test_all_methods_count() {
        assert_eq!(StdlibMethod::ALL.len(), 16);
    }

    #[test]
    fn test_produces_collection_map() {
        assert!(StdlibMethod::ArrayMap.produces_collection());
    }

    #[test]
    fn test_produces_collection_filter() {
        assert!(StdlibMethod::ArrayFilter.produces_collection());
    }

    #[test]
    fn test_produces_collection_foreach_does_not() {
        assert!(!StdlibMethod::ArrayForEach.produces_collection());
    }

    #[test]
    fn test_produces_collection_reduce_does_not() {
        assert!(!StdlibMethod::ArrayReduce.produces_collection());
    }

    #[test]
    fn test_can_short_circuit_find() {
        assert!(StdlibMethod::ArrayFind.can_short_circuit());
    }

    #[test]
    fn test_can_short_circuit_some() {
        assert!(StdlibMethod::ArraySome.can_short_circuit());
    }

    #[test]
    fn test_can_short_circuit_every() {
        assert!(StdlibMethod::ArrayEvery.can_short_circuit());
    }

    #[test]
    fn test_cannot_short_circuit_map() {
        assert!(!StdlibMethod::ArrayMap.can_short_circuit());
    }

    #[test]
    fn test_requires_comparator_sort() {
        assert!(StdlibMethod::ArraySort.requires_comparator());
    }

    #[test]
    fn test_requires_comparator_filter_does_not() {
        assert!(!StdlibMethod::ArrayFilter.requires_comparator());
    }

    #[test]
    fn test_has_accumulator_reduce() {
        assert!(StdlibMethod::ArrayReduce.has_accumulator());
    }

    #[test]
    fn test_is_async_dispatch_promise_then() {
        assert!(StdlibMethod::PromiseThen.is_async_dispatch());
    }

    #[test]
    fn test_method_name_coverage() {
        for method in StdlibMethod::ALL {
            let name = method.method_name();
            assert!(!name.is_empty(), "method name must not be empty");
        }
    }

    #[test]
    fn test_method_display() {
        let s = format!("{}", StdlibMethod::ArrayMap);
        assert_eq!(s, "Array.prototype.map");
    }

    #[test]
    fn test_overhead_multiplier_reduce() {
        assert_eq!(
            StdlibMethod::ArrayReduce.overhead_multiplier(),
            REDUCE_OVERHEAD_MULTIPLIER
        );
    }

    #[test]
    fn test_overhead_multiplier_sort() {
        assert_eq!(
            StdlibMethod::ArraySort.overhead_multiplier(),
            SORT_OVERHEAD_MULTIPLIER
        );
    }

    #[test]
    fn test_overhead_multiplier_default() {
        assert_eq!(
            StdlibMethod::ArrayMap.overhead_multiplier(),
            MILLIONTHS_UNIT
        );
    }

    // -- CallbackKind tests --

    #[test]
    fn test_all_callback_kinds_count() {
        assert_eq!(CallbackKind::ALL.len(), 5);
    }

    #[test]
    fn test_pure_deopt_risk() {
        assert_eq!(
            CallbackKind::PureFunction.deopt_risk_millionths(),
            PURE_DEOPT_RISK
        );
    }

    #[test]
    fn test_builtin_deopt_risk_lowest() {
        let builtin = CallbackKind::BuiltinFunction.deopt_risk_millionths();
        for kind in CallbackKind::ALL {
            assert!(builtin <= kind.deopt_risk_millionths());
        }
    }

    #[test]
    fn test_pure_is_inlining_eligible() {
        assert!(CallbackKind::PureFunction.is_inlining_eligible());
    }

    #[test]
    fn test_mutating_not_inlining_eligible() {
        assert!(!CallbackKind::MutatingFunction.is_inlining_eligible());
    }

    #[test]
    fn test_async_is_async() {
        assert!(CallbackKind::AsyncFunction.is_async());
    }

    #[test]
    fn test_pure_not_async() {
        assert!(!CallbackKind::PureFunction.is_async());
    }

    #[test]
    fn test_callback_kind_display() {
        assert_eq!(format!("{}", CallbackKind::PureFunction), "callback:pure");
    }

    // -- DispatchStrategy tests --

    #[test]
    fn test_all_strategies_count() {
        assert_eq!(DispatchStrategy::ALL.len(), 4);
    }

    #[test]
    fn test_specialized_cheapest_base_cost() {
        let specialized = DispatchStrategy::SpecializedBuiltin.base_cost_millionths();
        for s in DispatchStrategy::ALL {
            assert!(specialized <= s.base_cost_millionths());
        }
    }

    #[test]
    fn test_fallback_most_expensive_base_cost() {
        let fallback = DispatchStrategy::FallbackSlow.base_cost_millionths();
        for s in DispatchStrategy::ALL {
            assert!(fallback >= s.base_cost_millionths());
        }
    }

    #[test]
    fn test_inlined_is_inlined() {
        assert!(DispatchStrategy::InlinedCallback.is_inlined());
    }

    #[test]
    fn test_specialized_is_inlined() {
        assert!(DispatchStrategy::SpecializedBuiltin.is_inlined());
    }

    #[test]
    fn test_interpreter_not_inlined() {
        assert!(!DispatchStrategy::InterpreterCallback.is_inlined());
    }

    #[test]
    fn test_fallback_is_fallback() {
        assert!(DispatchStrategy::FallbackSlow.is_fallback());
    }

    #[test]
    fn test_strategy_display() {
        assert_eq!(
            format!("{}", DispatchStrategy::InlinedCallback),
            "strategy:inlined"
        );
    }

    // -- select_strategy tests --

    #[test]
    fn test_select_pure_map_is_inlined() {
        assert_eq!(
            select_strategy(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
            DispatchStrategy::InlinedCallback
        );
    }

    #[test]
    fn test_select_pure_sort_is_interpreter() {
        assert_eq!(
            select_strategy(StdlibMethod::ArraySort, CallbackKind::PureFunction),
            DispatchStrategy::InterpreterCallback
        );
    }

    #[test]
    fn test_select_builtin_filter_is_specialized() {
        assert_eq!(
            select_strategy(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction),
            DispatchStrategy::SpecializedBuiltin
        );
    }

    #[test]
    fn test_select_builtin_promise_is_interpreter() {
        assert_eq!(
            select_strategy(StdlibMethod::PromiseThen, CallbackKind::BuiltinFunction),
            DispatchStrategy::InterpreterCallback
        );
    }

    #[test]
    fn test_select_generator_always_fallback() {
        for method in StdlibMethod::ALL {
            assert_eq!(
                select_strategy(*method, CallbackKind::GeneratorFunction),
                DispatchStrategy::FallbackSlow,
                "generator callback on {method} should fallback"
            );
        }
    }

    #[test]
    fn test_select_async_non_promise_is_fallback() {
        assert_eq!(
            select_strategy(StdlibMethod::ArrayMap, CallbackKind::AsyncFunction),
            DispatchStrategy::FallbackSlow
        );
    }

    #[test]
    fn test_select_async_promise_is_interpreter() {
        assert_eq!(
            select_strategy(StdlibMethod::PromiseThen, CallbackKind::AsyncFunction),
            DispatchStrategy::InterpreterCallback
        );
    }

    #[test]
    fn test_select_mutating_foreach_is_interpreter() {
        assert_eq!(
            select_strategy(StdlibMethod::ArrayForEach, CallbackKind::MutatingFunction),
            DispatchStrategy::InterpreterCallback
        );
    }

    #[test]
    fn test_select_mutating_find_is_fallback() {
        assert_eq!(
            select_strategy(StdlibMethod::ArrayFind, CallbackKind::MutatingFunction),
            DispatchStrategy::FallbackSlow
        );
    }

    // -- estimate_dispatch_cost tests --

    #[test]
    fn test_cost_zero_elements() {
        let cost = estimate_dispatch_cost(
            StdlibMethod::ArrayMap,
            &DispatchStrategy::InlinedCallback,
            0,
        );
        assert_eq!(cost, INLINED_BASE_COST);
    }

    #[test]
    fn test_cost_increases_with_elements() {
        let cost_10 = estimate_dispatch_cost(
            StdlibMethod::ArrayMap,
            &DispatchStrategy::InlinedCallback,
            10,
        );
        let cost_100 = estimate_dispatch_cost(
            StdlibMethod::ArrayMap,
            &DispatchStrategy::InlinedCallback,
            100,
        );
        assert!(cost_100 > cost_10);
    }

    #[test]
    fn test_cost_reduce_overhead() {
        let map_cost = estimate_dispatch_cost(
            StdlibMethod::ArrayMap,
            &DispatchStrategy::InterpreterCallback,
            100,
        );
        let reduce_cost = estimate_dispatch_cost(
            StdlibMethod::ArrayReduce,
            &DispatchStrategy::InterpreterCallback,
            100,
        );
        assert!(
            reduce_cost > map_cost,
            "reduce should be more expensive than map"
        );
    }

    #[test]
    fn test_cost_sort_overhead() {
        let filter_cost = estimate_dispatch_cost(
            StdlibMethod::ArrayFilter,
            &DispatchStrategy::InterpreterCallback,
            100,
        );
        let sort_cost = estimate_dispatch_cost(
            StdlibMethod::ArraySort,
            &DispatchStrategy::InterpreterCallback,
            100,
        );
        assert!(
            sort_cost > filter_cost,
            "sort should be more expensive than filter"
        );
    }

    #[test]
    fn test_cost_specialized_cheapest() {
        let specialized = estimate_dispatch_cost(
            StdlibMethod::ArrayMap,
            &DispatchStrategy::SpecializedBuiltin,
            100,
        );
        let interpreter = estimate_dispatch_cost(
            StdlibMethod::ArrayMap,
            &DispatchStrategy::InterpreterCallback,
            100,
        );
        assert!(specialized < interpreter);
    }

    // -- build_decision tests --

    #[test]
    fn test_build_decision_fields() {
        let d = build_decision(StdlibMethod::ArrayFilter, CallbackKind::PureFunction);
        assert_eq!(d.method, StdlibMethod::ArrayFilter);
        assert_eq!(d.callback_kind, CallbackKind::PureFunction);
        assert_eq!(d.strategy, DispatchStrategy::InlinedCallback);
        assert!(d.estimated_cost_millionths > 0);
        assert_eq!(d.deopt_risk_millionths, PURE_DEOPT_RISK);
    }

    #[test]
    fn test_build_decision_hash_deterministic() {
        let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let d2 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        assert_eq!(d1.content_hash, d2.content_hash);
    }

    #[test]
    fn test_build_decision_hash_varies_by_method() {
        let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let d2 = build_decision(StdlibMethod::ArrayFilter, CallbackKind::PureFunction);
        assert_ne!(d1.content_hash, d2.content_hash);
    }

    #[test]
    fn test_build_decision_display() {
        let d = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let s = format!("{d}");
        assert!(s.contains("Array.prototype.map"));
        assert!(s.contains("callback:pure"));
    }

    #[test]
    fn test_decision_is_fast_path() {
        let d = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        assert!(d.is_fast_path());
    }

    #[test]
    fn test_decision_is_slow_path() {
        let d = build_decision(StdlibMethod::ArrayMap, CallbackKind::GeneratorFunction);
        assert!(d.is_slow_path());
    }

    // -- is_inlineable tests --

    #[test]
    fn test_inlineable_pure_map() {
        assert!(is_inlineable(
            &StdlibMethod::ArrayMap,
            &CallbackKind::PureFunction
        ));
    }

    #[test]
    fn test_not_inlineable_mutating() {
        assert!(!is_inlineable(
            &StdlibMethod::ArrayMap,
            &CallbackKind::MutatingFunction
        ));
    }

    #[test]
    fn test_not_inlineable_sort() {
        assert!(!is_inlineable(
            &StdlibMethod::ArraySort,
            &CallbackKind::PureFunction
        ));
    }

    #[test]
    fn test_not_inlineable_promise_then() {
        assert!(!is_inlineable(
            &StdlibMethod::PromiseThen,
            &CallbackKind::PureFunction
        ));
    }

    #[test]
    fn test_inlineable_builtin_filter() {
        assert!(is_inlineable(
            &StdlibMethod::ArrayFilter,
            &CallbackKind::BuiltinFunction
        ));
    }

    // -- build_trace tests --

    #[test]
    fn test_build_trace_empty() {
        let trace = build_trace(Vec::new());
        assert!(trace.decisions.is_empty());
        assert_eq!(trace.total_cost_millionths, 0);
        assert_eq!(trace.inlined_count, 0);
        assert_eq!(trace.fallback_count, 0);
    }

    #[test]
    fn test_build_trace_single_decision() {
        let d = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let cost = d.estimated_cost_millionths;
        let trace = build_trace(vec![d]);
        assert_eq!(trace.decisions.len(), 1);
        assert_eq!(trace.total_cost_millionths, cost);
        assert_eq!(trace.inlined_count, 1);
        assert_eq!(trace.fallback_count, 0);
    }

    #[test]
    fn test_build_trace_mixed_strategies() {
        let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let d2 = build_decision(StdlibMethod::ArrayFind, CallbackKind::GeneratorFunction);
        let trace = build_trace(vec![d1, d2]);
        assert_eq!(trace.decisions.len(), 2);
        assert_eq!(trace.inlined_count, 1);
        assert_eq!(trace.fallback_count, 1);
    }

    #[test]
    fn test_trace_inlined_fraction() {
        let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let d2 = build_decision(StdlibMethod::ArrayFilter, CallbackKind::PureFunction);
        let trace = build_trace(vec![d1, d2]);
        assert_eq!(trace.inlined_fraction_millionths(), MILLIONTHS_UNIT);
    }

    #[test]
    fn test_trace_fallback_fraction_zero() {
        let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let trace = build_trace(vec![d1]);
        assert_eq!(trace.fallback_fraction_millionths(), 0);
    }

    #[test]
    fn test_trace_average_cost() {
        let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let d2 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let cost = d1.estimated_cost_millionths;
        let trace = build_trace(vec![d1, d2]);
        assert_eq!(trace.average_cost_millionths(), cost);
    }

    #[test]
    fn test_trace_max_deopt_risk() {
        let d1 = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let d2 = build_decision(StdlibMethod::ArrayMap, CallbackKind::MutatingFunction);
        let trace = build_trace(vec![d1, d2]);
        assert_eq!(trace.max_deopt_risk_millionths(), MUTATING_DEOPT_RISK);
    }

    #[test]
    fn test_trace_content_hash_deterministic() {
        let decisions1 = vec![
            build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
            build_decision(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction),
        ];
        let decisions2 = vec![
            build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
            build_decision(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction),
        ];
        let t1 = build_trace(decisions1);
        let t2 = build_trace(decisions2);
        assert_eq!(t1.trace_content_hash(), t2.trace_content_hash());
    }

    #[test]
    fn test_trace_display() {
        let d = build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction);
        let trace = build_trace(vec![d]);
        let s = format!("{trace}");
        assert!(s.starts_with("trace("));
        assert!(s.contains("decisions=1"));
    }

    // -- constrained_decision tests --

    #[test]
    fn test_constrained_decision_stack_overflow() {
        let constraints = DispatchConstraints::default();
        let result = constrained_decision(
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            &constraints,
            MAX_CALLBACK_STACK_DEPTH,
        );
        assert_eq!(result, Err(StdlibDispatchError::StackOverflow));
    }

    #[test]
    fn test_constrained_decision_async_non_promise_rejected() {
        let constraints = DispatchConstraints::default();
        let result = constrained_decision(
            StdlibMethod::ArrayMap,
            CallbackKind::AsyncFunction,
            &constraints,
            0,
        );
        assert_eq!(result, Err(StdlibDispatchError::CallbackTypeUnsafe));
    }

    #[test]
    fn test_constrained_decision_async_non_promise_allowed() {
        let constraints = DispatchConstraints {
            allow_async_non_promise: true,
            ..DispatchConstraints::default()
        };
        let result = constrained_decision(
            StdlibMethod::ArrayMap,
            CallbackKind::AsyncFunction,
            &constraints,
            0,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_constrained_decision_normal_path() {
        let constraints = DispatchConstraints::default();
        let result = constrained_decision(
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            &constraints,
            0,
        );
        assert!(result.is_ok());
        let d = result.unwrap();
        assert_eq!(d.strategy, DispatchStrategy::InlinedCallback);
    }

    // -- build_profile tests --

    #[test]
    fn test_build_profile_empty_trace() {
        let trace = build_trace(Vec::new());
        let profile = build_profile(&trace);
        assert_eq!(profile.total_decisions, 0);
        assert_eq!(profile.distinct_methods, 0);
    }

    #[test]
    fn test_build_profile_counts() {
        let decisions = vec![
            build_decision(StdlibMethod::ArrayMap, CallbackKind::PureFunction),
            build_decision(StdlibMethod::ArrayFilter, CallbackKind::BuiltinFunction),
            build_decision(StdlibMethod::ArrayMap, CallbackKind::MutatingFunction),
        ];
        let trace = build_trace(decisions);
        let profile = build_profile(&trace);
        assert_eq!(profile.total_decisions, 3);
        assert_eq!(profile.distinct_methods, 2); // ArrayMap, ArrayFilter
        assert_eq!(profile.distinct_callback_kinds, 3); // Pure, Builtin, Mutating
    }

    #[test]
    fn test_build_profile_display() {
        let trace = build_trace(vec![build_decision(
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
        )]);
        let profile = build_profile(&trace);
        let s = format!("{profile}");
        assert!(s.starts_with("profile("));
    }

    // -- deopt_risk_tier tests --

    #[test]
    fn test_deopt_risk_tier_negligible() {
        assert_eq!(deopt_risk_tier(10_000), "negligible");
    }

    #[test]
    fn test_deopt_risk_tier_low() {
        assert_eq!(deopt_risk_tier(200_000), "low");
    }

    #[test]
    fn test_deopt_risk_tier_moderate() {
        assert_eq!(deopt_risk_tier(500_000), "moderate");
    }

    #[test]
    fn test_deopt_risk_tier_high() {
        assert_eq!(deopt_risk_tier(700_000), "high");
    }

    #[test]
    fn test_deopt_risk_tier_critical() {
        assert_eq!(deopt_risk_tier(900_000), "critical");
    }

    // -- batch_cost tests --

    #[test]
    fn test_batch_cost_empty() {
        assert_eq!(batch_cost(&[]), 0);
    }

    #[test]
    fn test_batch_cost_single() {
        let cost = batch_cost(&[(
            StdlibMethod::ArrayMap,
            DispatchStrategy::InlinedCallback,
            100,
        )]);
        let expected = estimate_dispatch_cost(
            StdlibMethod::ArrayMap,
            &DispatchStrategy::InlinedCallback,
            100,
        );
        assert_eq!(cost, expected);
    }

    #[test]
    fn test_batch_cost_additive() {
        let items = vec![
            (
                StdlibMethod::ArrayMap,
                DispatchStrategy::InlinedCallback,
                50,
            ),
            (
                StdlibMethod::ArraySort,
                DispatchStrategy::InterpreterCallback,
                100,
            ),
        ];
        let total = batch_cost(&items);
        let c1 = estimate_dispatch_cost(
            StdlibMethod::ArrayMap,
            &DispatchStrategy::InlinedCallback,
            50,
        );
        let c2 = estimate_dispatch_cost(
            StdlibMethod::ArraySort,
            &DispatchStrategy::InterpreterCallback,
            100,
        );
        assert_eq!(total, c1.saturating_add(c2));
    }

    // -- optimal/worst case strategy helpers --

    #[test]
    fn test_optimal_pure_map() {
        assert_eq!(
            optimal_pure_strategy(StdlibMethod::ArrayMap),
            DispatchStrategy::InlinedCallback
        );
    }

    #[test]
    fn test_worst_case_map() {
        assert_eq!(
            worst_case_strategy(StdlibMethod::ArrayMap),
            DispatchStrategy::FallbackSlow
        );
    }

    // -- manifest tests --

    #[test]
    fn test_manifest_non_empty() {
        let trace = franken_engine_stdlib_dispatch_manifest();
        assert!(!trace.decisions.is_empty());
    }

    #[test]
    fn test_manifest_deterministic() {
        let t1 = franken_engine_stdlib_dispatch_manifest();
        let t2 = franken_engine_stdlib_dispatch_manifest();
        assert_eq!(t1.decisions.len(), t2.decisions.len());
        assert_eq!(t1.total_cost_millionths, t2.total_cost_millionths);
        assert_eq!(t1.trace_content_hash(), t2.trace_content_hash());
    }

    #[test]
    fn test_manifest_no_async_on_non_promise() {
        let trace = franken_engine_stdlib_dispatch_manifest();
        for d in &trace.decisions {
            if d.callback_kind == CallbackKind::AsyncFunction {
                assert!(
                    d.method.is_async_dispatch(),
                    "async callback should only appear on async dispatch methods"
                );
            }
        }
    }

    #[test]
    fn test_manifest_has_inlined_decisions() {
        let trace = franken_engine_stdlib_dispatch_manifest();
        assert!(
            trace.inlined_count > 0,
            "manifest should contain inlined decisions"
        );
    }

    #[test]
    fn test_manifest_trace_id_format() {
        let trace = franken_engine_stdlib_dispatch_manifest();
        assert!(trace.trace_id.starts_with("trace-"));
    }

    // -- StdlibDispatchError Display tests --

    #[test]
    fn test_error_display_unsupported() {
        let e = StdlibDispatchError::UnsupportedMethod;
        assert!(format!("{e}").contains("unsupported"));
    }

    #[test]
    fn test_error_display_callback_unsafe() {
        let e = StdlibDispatchError::CallbackTypeUnsafe;
        assert!(format!("{e}").contains("unsafe"));
    }

    #[test]
    fn test_error_display_stack_overflow() {
        let e = StdlibDispatchError::StackOverflow;
        let s = format!("{e}");
        assert!(s.contains("stack"));
        assert!(s.contains(&MAX_CALLBACK_STACK_DEPTH.to_string()));
    }

    #[test]
    fn test_error_display_internal() {
        let e = StdlibDispatchError::InternalError("test failure".into());
        assert!(format!("{e}").contains("test failure"));
    }

    // -- validate_stack_depth tests --

    #[test]
    fn test_validate_stack_depth_ok() {
        let constraints = DispatchConstraints::default();
        assert!(validate_stack_depth(0, &constraints).is_ok());
    }

    #[test]
    fn test_validate_stack_depth_at_limit() {
        let constraints = DispatchConstraints::default();
        assert!(validate_stack_depth(constraints.max_stack_depth, &constraints).is_err());
    }

    #[test]
    fn test_validate_stack_depth_just_below() {
        let constraints = DispatchConstraints::default();
        assert!(validate_stack_depth(constraints.max_stack_depth - 1, &constraints).is_ok());
    }

    // -- DispatchConstraints default tests --

    #[test]
    fn test_constraints_default() {
        let c = DispatchConstraints::default();
        assert_eq!(c.max_deopt_risk_millionths, DEOPT_RISK_FALLBACK_THRESHOLD);
        assert_eq!(c.max_stack_depth, MAX_CALLBACK_STACK_DEPTH);
        assert!(!c.allow_mutating_inline);
        assert!(!c.allow_async_non_promise);
    }

    #[test]
    fn test_constraints_display() {
        let c = DispatchConstraints::default();
        let s = format!("{c}");
        assert!(s.starts_with("constraints("));
    }

    // -- Serde round-trip tests --

    #[test]
    fn test_serde_stdlib_method() {
        let method = StdlibMethod::ArrayFlatMap;
        let json = serde_json::to_string(&method).unwrap();
        let back: StdlibMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back, method);
    }

    #[test]
    fn test_serde_dispatch_decision() {
        let d = build_decision(StdlibMethod::ArrayReduce, CallbackKind::MutatingFunction);
        let json = serde_json::to_string(&d).unwrap();
        let back: DispatchDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn test_serde_dispatch_trace() {
        let trace = franken_engine_stdlib_dispatch_manifest();
        let json = serde_json::to_string(&trace).unwrap();
        let back: DispatchTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decisions.len(), trace.decisions.len());
        assert_eq!(back.total_cost_millionths, trace.total_cost_millionths);
    }

    #[test]
    fn test_serde_dispatch_error() {
        let e = StdlibDispatchError::InternalError("test".into());
        let json = serde_json::to_string(&e).unwrap();
        let back: StdlibDispatchError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }

    // -- Object method tests --

    #[test]
    fn test_object_keys_produces_collection() {
        assert!(StdlibMethod::ObjectKeys.produces_collection());
    }

    #[test]
    fn test_object_values_produces_collection() {
        assert!(StdlibMethod::ObjectValues.produces_collection());
    }

    #[test]
    fn test_object_entries_produces_collection() {
        assert!(StdlibMethod::ObjectEntries.produces_collection());
    }

    // -- SetForEach tests --

    #[test]
    fn test_set_foreach_does_not_produce_collection() {
        assert!(!StdlibMethod::SetForEach.produces_collection());
    }

    #[test]
    fn test_set_foreach_pure_is_inlined() {
        assert_eq!(
            select_strategy(StdlibMethod::SetForEach, CallbackKind::PureFunction),
            DispatchStrategy::InlinedCallback
        );
    }
}
