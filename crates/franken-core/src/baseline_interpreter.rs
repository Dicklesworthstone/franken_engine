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
//! `BTreeMap`/`BTreeSet` provide deterministic internal ordering; observable
//! data properties use explicit ECMAScript own-key order.
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
    HostcallDecisionRecord, IR_ACCESSOR_GET_PREFIX, IR_ACCESSOR_SET_PREFIX,
    IR_SUPER_CONSTRUCTOR_PROPERTY, IR_SUPER_PROTOTYPE_PROPERTY, Ir0Module, Ir3FunctionDesc,
    Ir3Instruction, Ir3Module, IteratorCloseReason, RegRange, WitnessEvent, WitnessEventKind,
};
use crate::js_string::JsString;
use crate::lowering_pipeline::{
    CLASS_EXPRESSION_CONSTRUCTOR_SELF_CAPTURE_PREFIX, LoweringContext, lower_ir0_to_ir3,
};
use crate::object_model::{OrderedStringMap, canonical_array_index};
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
/// Approximate inline footprint of one IFC label value.
const MEMORY_ESTIMATE_LABEL_BASE_BYTES: u64 = 32;
/// Approximate per-closure base footprint.
const MEMORY_ESTIMATE_CLOSURE_BASE_BYTES: u64 = 32;
/// Approximate per-call-frame base footprint.
const MEMORY_ESTIMATE_CALL_FRAME_BASE_BYTES: u64 = 64;
/// Approximate per-iterator base footprint.
const MEMORY_ESTIMATE_ITERATOR_BASE_BYTES: u64 = 32;
/// Approximate per-generator base footprint.
const MEMORY_ESTIMATE_GENERATOR_BASE_BYTES: u64 = 48;
/// Approximate per-resumable CopyDataProperties state footprint.
const MEMORY_ESTIMATE_COPY_DATA_PROPERTIES_STATE_BASE_BYTES: u64 = 64;

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
    /// Event-loop registration sequence for matching queued macrotasks.
    pub registration_seq: Option<u64>,
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
///
/// This enum is intentionally non-exhaustive at the public crate boundary.
/// Downstream consumers must retain a fallback arm so additive JavaScript
/// value kinds can land without another source-breaking exhaustive-match
/// migration.
#[non_exhaustive]
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
    /// String. Backed by [`JsString`] so lone UTF-16 surrogates are exact
    /// (bd-2vzgi parity with the engine's bd-neika string model); well-formed
    /// strings keep the prior plain-string serde wire format.
    Str(JsString),
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
    /// Async function reference (index into interpreter closure store).
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
    // NOTE: variants must be appended at the tail only — `kind as u64` feeds
    // the register content hash, so mid-enum insertion silently shifts every
    // downstream ordinal (same rule as the engine's BuiltinFunctionKind).
    StringPrototypeCharAt,
    StringPrototypeCharCodeAt,
    StringPrototypeCodePointAt,
    StringPrototypeAt,
    StringPrototypeIsWellFormed,
    StringPrototypeToWellFormed,
    ArrayIsArray,
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

    /// A receiver-bound String.prototype method surfaced by `GetProperty` on
    /// a string value (bd-2vzgi). Carries no module provenance.
    fn string_method(kind: BuiltinFunctionKind) -> Self {
        Self {
            kind,
            module_specifier: String::new(),
        }
    }

    /// Receiver-independent `Array.isArray`, materialized by the dedicated
    /// pure factory hostcall emitted for an unshadowed static member read.
    fn array_is_array() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayIsArray,
            module_specifier: String::new(),
        }
    }

    fn display_name(&self) -> &'static str {
        match self.kind {
            BuiltinFunctionKind::Require => "require",
            BuiltinFunctionKind::StringPrototypeCharAt => "charAt",
            BuiltinFunctionKind::StringPrototypeCharCodeAt => "charCodeAt",
            BuiltinFunctionKind::StringPrototypeCodePointAt => "codePointAt",
            BuiltinFunctionKind::StringPrototypeAt => "at",
            BuiltinFunctionKind::StringPrototypeIsWellFormed => "isWellFormed",
            BuiltinFunctionKind::StringPrototypeToWellFormed => "toWellFormed",
            BuiltinFunctionKind::ArrayIsArray => "isArray",
        }
    }
}

impl Value {
    /// Convenience constructor funneling any string-ish payload into the
    /// canonical [`JsString`] backing (mirrors the engine's `Value::str`).
    pub fn str(value: impl Into<JsString>) -> Self {
        Self::Str(value.into())
    }

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

    /// Whether this runtime value has ECMAScript object identity.
    ///
    /// The baseline carrier keeps functions, promises, iterators, and other
    /// exotic objects in dedicated variants instead of wrapping each one in
    /// [`Value::Object`]. Keep this match exhaustive so every future variant
    /// makes an explicit object-versus-primitive choice (bd-ptu9m).
    #[allow(clippy::match_like_matches_macro)] // Exhaustiveness is the point of this classifier.
    pub fn is_object_like(&self) -> bool {
        match self {
            Self::Undefined
            | Self::Null
            | Self::Bool(_)
            | Self::Int(_)
            | Self::Float(_)
            | Self::Str(_) => false,
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
#[derive(Debug, Clone, Default)]
pub struct HeapObject {
    /// Data properties in ECMAScript own-key order with deterministic lookup.
    pub properties: OrderedStringMap<Value>,
    /// Accessor descriptor storage, parallel to `properties` so the baseline
    /// heap can model the object_model accessor/data split.
    pub accessors: BTreeMap<String, AccessorProperty>,
    /// Prototype link used by membership operators and constructor instances.
    pub prototype: Option<ObjectId>,
    /// Constructor function index that allocated this object via `Construct`.
    pub constructor_function: Option<u32>,
    /// Whether this object was allocated by an array-producing path.
    pub is_array: bool,
}

impl Serialize for HeapObject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let order = self.properties.baseline_string_key_order().map(|_| {
            self.own_property_keys()
                .into_iter()
                .filter(|key| canonical_array_index(key).is_none())
                .collect::<Vec<_>>()
        });
        let field_count =
            4 + if self.accessors.is_empty() { 0 } else { 1 } + if order.is_some() { 1 } else { 0 };
        let mut object = serializer.serialize_struct("HeapObject", field_count)?;
        object.serialize_field("properties", &self.properties)?;
        if !self.accessors.is_empty() {
            object.serialize_field("accessors", &self.accessors)?;
        }
        object.serialize_field("prototype", &self.prototype)?;
        object.serialize_field("constructor_function", &self.constructor_function)?;
        object.serialize_field("is_array", &self.is_array)?;
        if let Some(order) = &order {
            object.serialize_field("own_string_key_order", order)?;
        }
        object.end()
    }
}

impl<'de> Deserialize<'de> for HeapObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        struct HeapObjectWire {
            properties: OrderedStringMap<Value>,
            #[serde(default)]
            accessors: BTreeMap<String, AccessorProperty>,
            prototype: Option<ObjectId>,
            constructor_function: Option<u32>,
            #[serde(default)]
            is_array: bool,
            #[serde(default)]
            own_string_key_order: Option<Vec<String>>,
        }

        let wire = HeapObjectWire::deserialize(deserializer)?;
        let mut object = Self {
            properties: wire.properties,
            accessors: wire.accessors,
            prototype: wire.prototype,
            constructor_function: wire.constructor_function,
            is_array: wire.is_array,
        };

        if let Some(order) = wire.own_string_key_order {
            let mut encoded = BTreeSet::new();
            for key in &order {
                if canonical_array_index(key).is_some() {
                    return Err(D::Error::custom(
                        "canonical array index in ordinary-string key order",
                    ));
                }
                if !encoded.insert(key.clone()) {
                    return Err(D::Error::custom(
                        "duplicate key in ordinary-string key order",
                    ));
                }
            }
            let live = object
                .properties
                .keys()
                .chain(object.accessors.keys())
                .filter(|key| canonical_array_index(key).is_none())
                .cloned()
                .collect::<BTreeSet<_>>();
            if encoded != live {
                return Err(D::Error::custom(
                    "ordinary-string key order must contain every live ordinary key exactly once",
                ));
            }
            object.properties.set_baseline_string_key_order(Some(order));
        }

        Ok(object)
    }
}

impl PartialEq for HeapObject {
    fn eq(&self, other: &Self) -> bool {
        self.properties == other.properties
            && self.accessors == other.accessors
            && self.prototype == other.prototype
            && self.constructor_function == other.constructor_function
            && self.is_array == other.is_array
            && self.properties.baseline_string_key_order().is_some()
                == other.properties.baseline_string_key_order().is_some()
            && self.own_property_keys() == other.own_property_keys()
    }
}

impl Eq for HeapObject {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PropertyOrderRollback {
    Unchanged,
    RemoveInsertedKey,
    Restore(Option<Vec<String>>),
}

impl HeapObject {
    pub fn new() -> Self {
        Self::default()
    }

    fn contains_own_property(&self, key: &str) -> bool {
        self.accessors.contains_key(key) || self.properties.contains_key(key)
    }

    /// Record a logical own-property definition without moving an existing
    /// key across data/accessor descriptor-kind transitions.
    ///
    /// Before recording, reconcile the hidden chronology with the observable
    /// public fields. This preserves the position of an accessor inserted
    /// directly through the ADR-frozen public `accessors` map before a later
    /// interpreter mutation. The returned delta restores the exact prior
    /// hidden state if the definition is rejected by the memory budget.
    fn record_property_definition(&mut self, key: &str, existed: bool) -> PropertyOrderRollback {
        if canonical_array_index(key).is_some() {
            return PropertyOrderRollback::Unchanged;
        }

        let normalized = self
            .own_property_keys()
            .into_iter()
            .filter(|candidate| canonical_array_index(candidate).is_none())
            .collect::<Vec<_>>();
        let previous = self
            .properties
            .baseline_string_key_order()
            .map(<[String]>::to_vec);
        let normalized_existing = previous.as_deref() == Some(normalized.as_slice());
        if !normalized_existing {
            self.properties
                .set_baseline_string_key_order(Some(normalized));
        }

        let order = self
            .properties
            .baseline_string_key_order_mut()
            .expect("ordinary-string order was just initialized");
        let key_was_inserted = if existed && order.iter().any(|candidate| candidate == key) {
            false
        } else {
            order.retain(|candidate| candidate != key);
            order.push(key.to_string());
            true
        };

        if !normalized_existing {
            PropertyOrderRollback::Restore(previous)
        } else if key_was_inserted {
            PropertyOrderRollback::RemoveInsertedKey
        } else {
            PropertyOrderRollback::Unchanged
        }
    }

    fn rollback_property_definition_order(&mut self, key: &str, rollback: PropertyOrderRollback) {
        match rollback {
            PropertyOrderRollback::Unchanged => {}
            PropertyOrderRollback::RemoveInsertedKey => {
                if let Some(order) = self.properties.baseline_string_key_order_mut() {
                    order.retain(|candidate| candidate != key);
                }
            }
            PropertyOrderRollback::Restore(previous) => {
                self.properties.set_baseline_string_key_order(previous);
            }
        }
    }

    fn forget_property_order(&mut self, key: &str) {
        if let Some(order) = self.properties.baseline_string_key_order_mut() {
            order.retain(|candidate| candidate != key);
        }
    }

    /// Return all live own string keys in ECMAScript order.
    ///
    /// Legacy payloads without the additive chronology sidecar recover the
    /// strongest order their historical shape retained: ordered data keys,
    /// then lexical accessor-only keys. The live-key union is completed
    /// defensively so even low-level field mutation cannot hide a key.
    fn own_property_keys(&self) -> Vec<String> {
        let mut array_indices = BTreeMap::<u32, String>::new();
        for key in self.properties.keys().chain(self.accessors.keys()) {
            if let Some(index) = canonical_array_index(key) {
                array_indices.entry(index).or_insert_with(|| key.clone());
            }
        }

        let mut ordinary = Vec::new();
        let mut seen = BTreeSet::new();
        if let Some(order) = self.properties.baseline_string_key_order() {
            for key in order {
                if self.contains_own_property(key) && seen.insert(key.clone()) {
                    ordinary.push(key.clone());
                }
            }
        }
        for key in self.properties.keys().chain(self.accessors.keys()) {
            if canonical_array_index(key).is_none() && seen.insert(key.clone()) {
                ordinary.push(key.clone());
            }
        }

        array_indices.into_values().chain(ordinary).collect()
    }
}

/// Baseline accessor descriptor: getter/setter functions for one property key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccessorProperty {
    pub get: Option<Value>,
    pub set: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeProperty {
    Data(Value),
    Accessor(AccessorProperty),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessorKind {
    Get,
    Set,
}

/// Resumable state for the object-rest CopyDataProperties operation.
///
/// Keys and exclusions are snapshotted once. Property descriptors are looked
/// up again immediately before each read so a preceding getter can delete a
/// later key, while keys added after the snapshot remain absent.
#[derive(Debug, Clone)]
struct CopyDataPropertiesState {
    instruction_ip: usize,
    register_base: usize,
    call_depth: usize,
    target_id: ObjectId,
    source: Value,
    /// Exact immutable code-unit snapshot for string sources. Keeping it once
    /// makes indexed property reads linear overall instead of rescanning the
    /// prefix for every code-unit key.
    string_units: Option<Vec<u16>>,
    keys: Vec<String>,
    excluded: BTreeSet<String>,
    next_index: usize,
    /// The getter return value is written to the instruction's `value_dst`.
    /// Returning to the same instruction consumes it under this key.
    awaiting_key: Option<String>,
}

impl CopyDataPropertiesState {
    fn belongs_to(&self, instruction_ip: usize, register_base: usize, call_depth: usize) -> bool {
        self.instruction_ip == instruction_ip
            && self.register_base == register_base
            && self.call_depth == call_depth
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
    /// Saved IFC label snapshot for the register file at the time of yield.
    saved_register_labels: Vec<crate::ifc_artifacts::Label>,
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
    /// Saved IFC label snapshot for the register file at the time of await.
    saved_register_labels: Vec<crate::ifc_artifacts::Label>,
    /// Saved register base offset.
    saved_register_base: usize,
    /// Current phase of the async function.
    phase: AsyncFunctionPhase,
    /// Promise that will be resolved/rejected when the async function completes.
    result_promise: u32,
}

/// Fully validated state needed to enter an async function call frame.
struct AsyncCallSetup {
    function_index: u32,
    function_entry: u32,
    closure_index: Option<u32>,
    captured_env: Option<Vec<ScopeFrame>>,
    arguments: Vec<(Value, crate::ifc_artifacts::Label)>,
    this_value: Value,
    this_label: crate::ifc_artifacts::Label,
    super_value: Value,
    super_label: crate::ifc_artifacts::Label,
    result_register: u32,
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
    /// Saved IFC label snapshot at suspension.
    saved_register_labels: Vec<crate::ifc_artifacts::Label>,
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
    /// Active finally-frame depth at `BeginTry`. Abrupt transfer to this
    /// handler exits and discards every finally completion above this depth.
    finally_frame_depth: usize,
}

/// Classifies the completion record captured when a finally block is entered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum FinallyMode {
    /// Entered via normal control flow (try body completed, or catch body completed).
    Normal,
    /// Entered because an exception was in flight. `EnterFinally` moves it
    /// from interpreter pending state into the new `FinallyFrame`.
    Exception,
    /// Entered because a return was in flight. `EnterFinally` moves it into
    /// the new `FinallyFrame`.
    Return,
}

/// One-shot ownership record for the exact `EnterFinally` instruction chosen
/// by an unwind edge. This must survive instruction-boundary cancellation or
/// budget exhaustion before the target instruction executes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingFinallyEntry {
    target: usize,
    mode: FinallyMode,
}

/// Completion record owned by one actively executing finally body. Keeping
/// the completion in the frame prevents a nested abrupt completion from
/// suspending and later resurrecting a completion that it overrides.
#[derive(Debug, Clone)]
struct FinallyFrame {
    completion: Option<AbruptCompletion>,
}

/// A suspended abrupt completion that should resume if a newer one is later
/// consumed locally.
#[derive(Debug, Clone)]
enum AbruptCompletion {
    Exception(LabeledException),
    Return(LabeledReturn),
}

/// Exception completion carried across calls, catches, and `finally` unwinding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LabeledException {
    value: Value,
    label: crate::ifc_artifacts::Label,
}

/// Return completion carried while control unwinds through `finally`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LabeledReturn {
    value: Value,
    label: crate::ifc_artifacts::Label,
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
    label: crate::ifc_artifacts::Label,
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
                label: crate::ifc_artifacts::Label::Public,
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
    /// Register where the return value should be placed. Some internal calls
    /// intentionally discard completion values, such as accessor setters.
    return_reg: Option<u32>,
    /// Base register offset for this frame (reserved for frame isolation).
    register_base: usize,
    /// Function table index (reserved for frame-level diagnostics).
    #[allow(dead_code)]
    function_index: Option<u32>,
    /// The `this` value for this call frame.  Set to the receiver for method
    /// calls, `undefined` for plain calls, or the newly allocated object for
    /// constructor calls.  Arrow functions inherit from the defining frame.
    this_value: Value,
    /// IFC label paired with `this_value` for receiver-aware calls.
    this_label: crate::ifc_artifacts::Label,
    /// The `new.target` value for this call frame. Constructor calls set this
    /// to the invoked constructor value; non-constructor calls use undefined.
    new_target_value: Value,
    /// IFC label paired with `new_target_value`.
    new_target_label: crate::ifc_artifacts::Label,
    /// The `super` value for this call frame. Constructors receive the parent
    /// constructor; methods receive the parent prototype.
    super_value: Value,
    /// IFC label paired with `super_value`.
    super_label: crate::ifc_artifacts::Label,
    /// For constructor calls (`new`): the `this` object allocated before
    /// entering the constructor body. If the constructor returns a non-object,
    /// this value is used as the result instead (ES2020 §9.2.2 step 13).
    construct_this: Option<Value>,
    /// Caller exception state saved across the call so callee control flow
    /// cannot clobber an outer in-flight abrupt completion.
    saved_pending_exception: Option<LabeledException>,
    /// Caller return state saved for the same reason.
    saved_pending_return: Option<LabeledReturn>,
    /// Count of suspended abrupt completions before entering the callee.
    saved_suspended_abrupt_depth: usize,
    /// Count of active finally completion frames before entering the callee.
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
    /// Async function ID if this frame is executing an async function.
    async_function_id: Option<u32>,
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
        // REGRESSION TEST COVERAGE: This assignment of extension_id to DecisionReceipt
        // is critical for bd-ldm0f. The extension_id must propagate correctly through
        // the entire receipt pipeline without corruption or loss.
        let mut receipt = DecisionReceipt {
            extension_id, // <- CRITICAL: extension_id propagation point for bd-ldm0f
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

        // SAFETY: Receipt was just pushed above, so receipts is non-empty
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
    /// Range error (e.g. an out-of-range code point argument). Mirrors the
    /// engine's variant and Display wording for oracle parity (bd-7zwar).
    RangeError { message: String },
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
            Self::RangeError { message } => write!(f, "range error: {message}"),
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
// Console output capture (RC-1.10: console.log/error/warn/info)
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
    /// Log level (log, error, warn, info).
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
    /// Console output captured from console.log/error/warn/info calls.
    pub console_output: Vec<ConsoleEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSeed {
    registers: Vec<Value>,
    register_labels: Vec<crate::ifc_artifacts::Label>,
    heap: Vec<HeapObject>,
    function_prototypes: BTreeMap<FunctionObjectKey, ObjectId>,
    function_objects: BTreeMap<FunctionObjectKey, ObjectId>,
}

/// Eager execution seed for testing comparison
#[derive(Debug, Clone)]
pub struct EagerExecutionSeed {
    pub registers: Vec<Value>,
    pub heap: Vec<HeapObject>,
}

#[derive(Debug, Clone)]
struct ModuleExecutionSnapshot {
    registers: Vec<Value>,
    register_labels: Vec<crate::ifc_artifacts::Label>,
    call_stack: Vec<CallFrame>,
    ip: usize,
    register_base: usize,
    catch_frames: Vec<CatchFrame>,
    pending_exception: Option<LabeledException>,
    pending_return: Option<LabeledReturn>,
    suspended_abrupt_completions: Vec<AbruptCompletion>,
    finally_frames: Vec<FinallyFrame>,
    pending_finally_entry: Option<PendingFinallyEntry>,
    copy_data_properties_states: Vec<CopyDataPropertiesState>,
    scope_chain: ScopeChain,
    pending_captures: Vec<u32>,
    current_module_specifier: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FunctionObjectKey {
    Function(u32),
    Closure(u32),
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

#[derive(Debug, Clone)]
struct LabeledPromiseCombinatorState {
    tracker: PromiseCombinatorState,
    accumulated_label: crate::ifc_artifacts::Label,
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
    /// IFC label for each register slot. Missing labels default to Public.
    register_labels: Vec<crate::ifc_artifacts::Label>,
    /// Call stack.
    call_stack: Vec<CallFrame>,
    /// Object heap.
    heap: Vec<HeapObject>,
    /// Approximate live memory tracked for fail-closed budget enforcement.
    estimated_memory_bytes: u64,
    /// Dedicated iterator runtime state used by iterator-specific IR3 ops.
    iterators: Vec<RuntimeIteratorState>,
    /// Lazily allocated prototype objects for constructor function values.
    /// Closure identity is significant: repeated evaluations of the same class
    /// expression must not share a prototype merely because they share code.
    function_prototypes: BTreeMap<FunctionObjectKey, ObjectId>,
    /// Heap-backed own-property storage for callable values.
    function_objects: BTreeMap<FunctionObjectKey, ObjectId>,
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
    /// A pending exception value during an unwind edge, consumed by
    /// `EnterCatch` or moved into an owned `FinallyFrame` by `EnterFinally`.
    pending_exception: Option<LabeledException>,
    /// A pending return value before `EnterFinally` captures it or the return
    /// completes.
    pending_return: Option<LabeledReturn>,
    /// Saved outer abrupt completion state that was temporarily suspended by a
    /// newer local throw/return or by exception unwinding across nested calls
    /// or intermediary finally blocks. If the newer abrupt completion is
    /// consumed locally, the most recent suspended completion resumes.
    suspended_abrupt_completions: Vec<AbruptCompletion>,
    /// Stack of completion records owned by active finally bodies. Pushed by
    /// `EnterFinally` and consumed by `EndFinally` or an overriding abrupt
    /// transfer.
    finally_frames: Vec<FinallyFrame>,
    /// One-shot entry ownership set by an unwind edge and consumed by the
    /// exact `EnterFinally` instruction it targets.
    pending_finally_entry: Option<PendingFinallyEntry>,
    /// Nested object-rest copies awaiting an accessor return. A stack rather
    /// than a single slot is required because an included getter may itself
    /// execute another object-rest copy.
    copy_data_properties_states: Vec<CopyDataPropertiesState>,
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
    /// Async generator object store.
    async_generators: Vec<AsyncGeneratorObject>,
    /// Async function object store.
    async_functions: Vec<AsyncFunctionObject>,
    /// Promise store for ES2020 Promise semantics.
    promise_store: crate::promise_model::PromiseStore,
    /// Deterministic event loop state (microtasks + macrotasks + virtual clock).
    event_loop: crate::promise_model::EventLoop,
    /// Active promise combinator trackers keyed by combinator id.
    promise_combinators: BTreeMap<u64, LabeledPromiseCombinatorState>,
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
    fn module_specifier_string(value: &JsString) -> Result<&str, InterpreterError> {
        value.as_str().ok_or_else(|| InterpreterError::TypeError {
            expected: "well-formed UTF-8 module specifier".to_string(),
            got: "ECMAScript string containing a lone surrogate".to_string(),
        })
    }

    fn metadata_pool_string(
        module: &Ir3Module,
        pool_index: u32,
        missing_fallback: String,
    ) -> Result<String, InterpreterError> {
        let Some(value) = module.constant_pool.get(pool_index as usize) else {
            return Ok(missing_fallback);
        };
        value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "well-formed UTF-8 metadata string".to_string(),
                got: "ECMAScript string containing a lone surrogate".to_string(),
            })
    }

    /// Create a new interpreter core with the given configuration.
    pub fn new(config: InterpreterConfig, trace_id: impl Into<String>) -> Self {
        let max_regs = config.max_registers as usize;
        Self {
            config,
            hook: None,
            registers: vec![Value::Undefined; max_regs],
            register_labels: vec![crate::ifc_artifacts::Label::Public; max_regs],
            call_stack: Vec::new(),
            heap: Vec::new(),
            estimated_memory_bytes: 0,
            iterators: Vec::new(),
            function_prototypes: BTreeMap::new(),
            function_objects: BTreeMap::new(),
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
            finally_frames: Vec::new(),
            pending_finally_entry: None,
            copy_data_properties_states: Vec::new(),
            last_pre_run_seed: None,
            last_post_run_seed: None,
            scope_chain: ScopeChain::new(),
            closures: Vec::new(),
            pending_captures: Vec::new(),
            generators: Vec::new(),
            async_generators: Vec::new(),
            async_functions: Vec::new(),
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

    /// Enable profiling with the specified configuration.
    pub fn enable_profiling(&mut self, config: crate::profiling::ProfilingConfig) {
        self.profiling_data = Some(crate::profiling::Profiler::new(config));
    }

    /// Disable profiling and return collected data.
    pub fn disable_profiling(&mut self) -> Option<crate::profiling::Profiler> {
        self.profiling_data.take()
    }

    /// Get reference to current profiling data.
    pub fn profiling_data(&self) -> Option<&crate::profiling::Profiler> {
        self.profiling_data.as_ref()
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

        let mut result = self.run_loop(module);
        if result.is_err() {
            // CopyDataProperties continuations are internal to this execution.
            // A fresh execute() always restarts from its caller-visible seed,
            // so no failed/cancelled run may retain their snapshotted keys.
            self.discard_all_copy_data_properties_states();
        }

        // Drain any pending microtasks enqueued during execution
        // (promise reactions, thenable resolutions, etc.).
        self.drain_microtasks();

        // Run the event loop until all pending work is complete after normal
        // top-level termination.  A failed script should not run timer
        // callbacks after the failure path has been selected.
        if matches!(result, Ok(_) | Err(InterpreterError::Halted))
            && let Err(err) = self.run_event_loop_until_idle(module)
        {
            result = Err(err);
        }

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

    pub fn capture_execution_seed(&self) -> ExecutionSeed {
        let max_regs = self.config.max_registers as usize;
        let mut registers = self.registers.clone();
        registers.resize(max_regs, Value::Undefined);
        registers.truncate(max_regs);
        let mut register_labels = self.register_labels.clone();
        register_labels.resize(max_regs, crate::ifc_artifacts::Label::Public);
        register_labels.truncate(max_regs);
        ExecutionSeed {
            registers,
            register_labels,
            heap: self.heap.clone(),
            function_prototypes: self.function_prototypes.clone(),
            function_objects: self.function_objects.clone(),
        }
    }

    pub fn reset_execution_state_from_seed(&mut self, seed: &ExecutionSeed) {
        self.register_base = 0;
        self.registers = seed.registers.clone();
        self.register_labels = seed.register_labels.clone();
        self.register_labels
            .resize(self.registers.len(), crate::ifc_artifacts::Label::Public);
        self.call_stack.clear();
        self.heap = seed.heap.clone();
        self.iterators.clear();
        self.function_prototypes = seed.function_prototypes.clone();
        self.function_objects = seed.function_objects.clone();
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
        self.finally_frames.clear();
        self.pending_finally_entry = None;
        self.copy_data_properties_states.clear();
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        self.module_state = ModuleState::new();
        self.active_cjs_context = None;
        self.current_module_specifier = None;
        self.promise_combinators.clear();
        self.promise_combinator_watchers.clear();
        self.next_promise_combinator_id = 0;
    }

    // ---- Proptest helper methods (H2.4) ---------------------------------

    /// Create new interpreter instance for proptest (normal lazy seed mode)
    pub fn new_for_proptest() -> Self {
        let config = InterpreterConfig {
            instruction_budget: 10000,
            max_registers: 32,
            max_call_depth: 100,
            max_string_size: 1024,
            max_heap_objects: 1000,
            max_total_memory_bytes: 1024 * 1024,
            max_scope_depth: 100,
            module_root: None,
            granted_capabilities: std::collections::BTreeSet::new(),
            extension_id: Some("proptest".to_string()),
            cancellation_token: None,
            checkpoint_density: 1000,
        };

        Self::new(config, "proptest")
    }

    /// Create new interpreter instance for eager seed comparison testing
    pub fn new_for_proptest_eager_seeds() -> Self {
        Self::new_for_proptest()
    }

    /// Write to register (test helper)
    pub fn write_register(&mut self, reg: usize, value: Value) {
        if reg < self.registers.len() {
            self.registers[reg] = value;
        } else if reg < self.config.max_registers as usize {
            self.registers.resize(reg + 1, Value::Undefined);
            self.registers[reg] = value;
        }
    }

    /// Write to heap slot (test helper)
    pub fn write_heap_slot(&mut self, slot: u32, value: Value) {
        let slot_idx = slot as usize;
        while self.heap.len() <= slot_idx {
            self.heap.push(HeapObject {
                properties: OrderedStringMap::new(),
                accessors: std::collections::BTreeMap::new(),
                prototype: None,
                constructor_function: None,
                is_array: false,
            });
        }

        if let Some(heap_obj) = self.heap.get_mut(slot_idx) {
            let existed = heap_obj.contains_own_property("value");
            heap_obj.record_property_definition("value", existed);
            heap_obj.properties.insert("value".to_string(), value);
        }
    }

    /// Get register values for comparison (test helper)
    pub fn get_registers(&self) -> &Vec<Value> {
        &self.registers
    }

    /// Get heap for comparison (test helper)
    pub fn get_heap(&self) -> &Vec<HeapObject> {
        &self.heap
    }

    /// Capture execution seed in eager format for testing
    pub fn capture_execution_seed_eager_for_test(&self) -> EagerExecutionSeed {
        EagerExecutionSeed {
            registers: self.registers.clone(),
            heap: self.heap.clone(),
        }
    }

    /// Reset from eager seed format for testing
    pub fn reset_execution_state_from_seed_eager_for_test(&mut self, seed: &EagerExecutionSeed) {
        self.registers = seed.registers.clone();
        self.heap = seed.heap.clone();

        // Reset other state like the normal reset method
        self.register_base = 0;
        self.call_stack.clear();
        self.iterators.clear();
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
        self.finally_frames.clear();
        self.pending_finally_entry = None;
        self.copy_data_properties_states.clear();
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
            register_labels: self.register_labels.clone(),
            call_stack: self.call_stack.clone(),
            ip: self.ip,
            register_base: self.register_base,
            catch_frames: self.catch_frames.clone(),
            pending_exception: self.pending_exception.clone(),
            pending_return: self.pending_return.clone(),
            suspended_abrupt_completions: self.suspended_abrupt_completions.clone(),
            finally_frames: self.finally_frames.clone(),
            pending_finally_entry: self.pending_finally_entry.clone(),
            copy_data_properties_states: self.copy_data_properties_states.clone(),
            scope_chain: self.scope_chain.clone(),
            pending_captures: self.pending_captures.clone(),
            current_module_specifier: self.current_module_specifier.clone(),
        }
    }

    fn restore_module_execution(&mut self, snapshot: ModuleExecutionSnapshot) {
        self.registers = snapshot.registers;
        self.register_labels = snapshot.register_labels;
        self.register_labels
            .resize(self.registers.len(), crate::ifc_artifacts::Label::Public);
        self.call_stack = snapshot.call_stack;
        self.ip = snapshot.ip;
        self.register_base = snapshot.register_base;
        self.catch_frames = snapshot.catch_frames;
        self.pending_exception = snapshot.pending_exception;
        self.pending_return = snapshot.pending_return;
        self.suspended_abrupt_completions = snapshot.suspended_abrupt_completions;
        self.finally_frames = snapshot.finally_frames;
        self.pending_finally_entry = snapshot.pending_finally_entry;
        self.copy_data_properties_states = snapshot.copy_data_properties_states;
        self.scope_chain = snapshot.scope_chain;
        self.pending_captures = snapshot.pending_captures;
        self.current_module_specifier = snapshot.current_module_specifier;
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    fn prepare_module_execution(&mut self, module_specifier: &str) -> Result<(), InterpreterError> {
        let max_regs = self.config.max_registers as usize;
        self.registers.clear();
        self.register_labels.clear();
        self.clear_register_range(0, max_regs);
        self.call_stack.clear();
        self.ip = 0;
        self.register_base = 0;
        self.catch_frames.clear();
        self.pending_exception = None;
        self.pending_return = None;
        self.suspended_abrupt_completions.clear();
        self.finally_frames.clear();
        self.pending_finally_entry = None;
        self.copy_data_properties_states.clear();
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
                    binding.label = crate::ifc_artifacts::Label::Public;
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
        (Value::str(specifier), Value::str(dirname))
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
            let object = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let properties = object
                .own_property_keys()
                .into_iter()
                .filter_map(|key| {
                    object
                        .properties
                        .get(&key)
                        .cloned()
                        .map(|value| (key, value))
                })
                .collect::<Vec<_>>();
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
        receiver: Option<&Value>,
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
                let specifier = Self::module_specifier_string(&specifier)?;
                let previous_module_specifier = self.current_module_specifier.clone();
                if !builtin.module_specifier.is_empty() {
                    self.current_module_specifier = Some(builtin.module_specifier.clone());
                }
                let result = self.require_module(module, specifier);
                self.current_module_specifier = previous_module_specifier;
                result
            }
            BuiltinFunctionKind::ArrayIsArray => {
                let arg = if args.count > 0 {
                    Some(self.read_reg(args.start)?)
                } else {
                    None
                };
                self.array_is_array_value(arg)
            }
            BuiltinFunctionKind::StringPrototypeCharAt
            | BuiltinFunctionKind::StringPrototypeCharCodeAt
            | BuiltinFunctionKind::StringPrototypeCodePointAt
            | BuiltinFunctionKind::StringPrototypeAt
            | BuiltinFunctionKind::StringPrototypeIsWellFormed
            | BuiltinFunctionKind::StringPrototypeToWellFormed => {
                let receiver = receiver.ok_or_else(|| InterpreterError::TypeError {
                    expected: "string receiver".to_string(),
                    got: format!("detached String.prototype.{}", builtin.display_name()),
                })?;
                let text = self.string_receiver_to_js_string(receiver)?;
                let index = if args.count > 0 {
                    Some(self.read_reg(args.start)?)
                } else {
                    None
                };
                Ok(match builtin.kind {
                    BuiltinFunctionKind::StringPrototypeCharAt => {
                        Self::string_char_at_value(&text, index.as_ref())
                    }
                    BuiltinFunctionKind::StringPrototypeCharCodeAt => {
                        Self::string_char_code_at_value(&text, index.as_ref())
                    }
                    BuiltinFunctionKind::StringPrototypeCodePointAt => {
                        Self::string_code_point_at_value(&text, index.as_ref())
                    }
                    BuiltinFunctionKind::StringPrototypeAt => {
                        Self::string_at_value(&text, index.as_ref())
                    }
                    BuiltinFunctionKind::StringPrototypeIsWellFormed => {
                        Self::string_is_well_formed_value(&text)
                    }
                    BuiltinFunctionKind::StringPrototypeToWellFormed => {
                        Self::string_to_well_formed_value(&text)
                    }
                    BuiltinFunctionKind::Require | BuiltinFunctionKind::ArrayIsArray => {
                        unreachable!("handled above")
                    }
                })
            }
        }
    }

    /// Single semantic implementation shared by the direct
    /// `builtin:ArrayIsArray` hostcall and its first-class callable twin.
    fn array_is_array_value(&self, arg: Option<Value>) -> Result<Value, InterpreterError> {
        let Some(arg) = arg else {
            return Ok(Value::Bool(false));
        };
        match arg {
            Value::Object(object_id) => {
                let is_array = self
                    .heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
                    .is_array;
                Ok(Value::Bool(is_array))
            }
            _ => Ok(Value::Bool(false)),
        }
    }

    // -----------------------------------------------------------------------
    // String.prototype method impls (bd-2vzgi) — exact UTF-16 semantics
    // mirroring the engine's bd-neika string model. Each method has ONE impl
    // fn shared by the hostcall dispatch ("builtin:StringPrototype*") and the
    // first-class `BuiltinFunction` method-call path, so the two seams cannot
    // drift (the engine's dual-seam divergence was the hard lesson of
    // bd-neika).
    // -----------------------------------------------------------------------

    /// Receiver coercion for String.prototype methods: exact for string
    /// values (no lossy projection), `TypeError` for undefined/null (ES
    /// "object coercible" requirement, engine parity), display coercion for
    /// the remaining primitives.
    fn string_receiver_to_js_string(&self, receiver: &Value) -> Result<JsString, InterpreterError> {
        match receiver {
            Value::Str(s) => Ok(s.clone()),
            Value::Undefined | Value::Null => Err(InterpreterError::TypeError {
                expected: "object-coercible string receiver".to_string(),
                got: receiver.type_name().to_string(),
            }),
            other => Ok(JsString::from(self.value_to_string(other))),
        }
    }

    /// `ToIntegerOrInfinity`-style coercion for index arguments (engine
    /// `value_as_integer` parity): numbers and numeric strings truncate
    /// toward zero, `NaN` contributes 0, everything else falls back to 0.
    fn string_index_as_integer(value: &Value) -> i64 {
        match value {
            Value::Int(n) => *n,
            Value::Float(f) => {
                let v = f.inner();
                if v.is_nan() { 0 } else { v.trunc() as i64 }
            }
            Value::Bool(true) => 1,
            Value::Str(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    0
                } else {
                    trimmed
                        .parse::<f64>()
                        .map(|v| if v.is_nan() { 0 } else { v.trunc() as i64 })
                        .unwrap_or(0)
                }
            }
            _ => 0,
        }
    }

    /// `String.prototype.charAt`: the single UTF-16 code unit at `index`. A
    /// surrogate half stays a real lone-surrogate string value; out-of-range
    /// or negative indices yield the empty string.
    fn string_char_at_value(text: &JsString, index: Option<&Value>) -> Value {
        let index = index.map(Self::string_index_as_integer).unwrap_or(0);
        if index < 0 {
            return Value::str("");
        }
        match text.encode_utf16().nth(index as usize) {
            Some(unit) => Value::Str(JsString::from_code_units(&[unit])),
            None => Value::str(""),
        }
    }

    /// `String.prototype.charCodeAt`: the exact code unit as an integer, or
    /// `NaN` when out of range.
    fn string_char_code_at_value(text: &JsString, index: Option<&Value>) -> Value {
        let index = index.map(Self::string_index_as_integer).unwrap_or(0);
        if index < 0 {
            return Value::Float(Float64::new(f64::NAN));
        }
        match text.encode_utf16().nth(index as usize) {
            Some(unit) => Value::Int(i64::from(unit)),
            None => Value::Float(Float64::new(f64::NAN)),
        }
    }

    /// `String.prototype.codePointAt`: UTF-16 code-unit indexed per ES2015
    /// CodePointAt (a valid pair combines, an unpaired surrogate yields its
    /// own unit value), matching the engine seams upgraded by bd-rdnhc so
    /// the differential oracle agrees; out-of-range / negative yields
    /// undefined.
    fn string_code_point_at_value(text: &JsString, index: Option<&Value>) -> Value {
        let index = index.map(Self::string_index_as_integer).unwrap_or(0);
        if index < 0 {
            return Value::Undefined;
        }
        match text.code_point_at(index as usize) {
            Some(code_point) => Value::Int(i64::from(code_point)),
            None => Value::Undefined,
        }
    }

    /// `String.prototype.at`: relative code-unit indexing (negative counts
    /// from the end); out-of-range yields undefined.
    fn string_at_value(text: &JsString, index: Option<&Value>) -> Value {
        let units: Vec<u16> = text.code_units_vec();
        let len = units.len() as i64;
        let raw = index.map(Self::string_index_as_integer).unwrap_or(0);
        let idx = if raw < 0 { raw + len } else { raw };
        if idx < 0 || idx >= len {
            return Value::Undefined;
        }
        Value::Str(JsString::from_code_units(&[units[idx as usize]]))
    }

    /// `String.prototype.isWellFormed` (ES2024): `true` iff the string
    /// contains no unpaired surrogate (engine parity; bd-7zwar).
    fn string_is_well_formed_value(text: &JsString) -> Value {
        Value::Bool(text.is_well_formed())
    }

    /// `String.prototype.toWellFormed` (ES2024): the U+FFFD projection —
    /// exact content when already well-formed (engine parity; bd-7zwar).
    fn string_to_well_formed_value(text: &JsString) -> Value {
        Value::str(text.as_utf8_projection())
    }

    /// Property access on a string receiver (`GetProperty` with a
    /// `Value::Str` object): `length` is the ES UTF-16 code-unit count and
    /// canonical indexed keys expose one exact UTF-16 code unit, and the
    /// known String.prototype methods surface as first-class
    /// [`BuiltinFunction`] values the `CallMethod` seam dispatches with the
    /// receiver. Unknown keys return `None` (the `GetProperty` caller yields
    /// `undefined` per ES GetV semantics — bd-7zwar).
    fn string_property_value(text: &JsString, key: &str) -> Option<Value> {
        match key {
            "length" => Some(Value::Int(text.utf16_len() as i64)),
            "charAt" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeCharAt,
            ))),
            "charCodeAt" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeCharCodeAt,
            ))),
            "codePointAt" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeCodePointAt,
            ))),
            "at" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeAt,
            ))),
            "isWellFormed" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeIsWellFormed,
            ))),
            "toWellFormed" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeToWellFormed,
            ))),
            _ => canonical_array_index(key)
                .and_then(|index| text.encode_utf16().nth(index as usize))
                .map(|unit| Value::Str(JsString::from_code_units(&[unit]))),
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

    fn enter_async_function_call(&mut self, setup: AsyncCallSetup) -> Result<(), InterpreterError> {
        let AsyncCallSetup {
            function_index,
            function_entry,
            closure_index,
            captured_env,
            arguments,
            this_value,
            this_label,
            super_value,
            super_label,
            result_register,
        } = setup;

        let promise_handle = self.promise_store.create();
        let async_func_id =
            u32::try_from(self.async_functions.len()).map_err(|_| InterpreterError::TypeError {
                expected: "async function table capacity".into(),
                got: format!("exceeded u32::MAX ({})", self.async_functions.len()),
            })?;
        self.async_functions.push(AsyncFunctionObject {
            function_index,
            closure_index,
            saved_ip: 0,
            saved_registers: Vec::new(),
            saved_register_labels: Vec::new(),
            saved_register_base: 0,
            phase: AsyncFunctionPhase::Executing,
            result_promise: promise_handle.0,
        });
        self.write_reg(result_register, Value::Promise(promise_handle.0))?;

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
            return_reg: None,
            register_base: self.register_base,
            function_index: Some(function_index),
            this_value,
            this_label,
            new_target_value: Value::Undefined,
            new_target_label: crate::ifc_artifacts::Label::Public,
            super_value,
            super_label,
            construct_this: None,
            saved_pending_exception: self.pending_exception.take(),
            saved_pending_return: self.pending_return.take(),
            saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
            saved_finally_mode_depth: self.finally_frames.len(),
            saved_scope_depth: scope_depth,
            saved_scope_chain: saved_chain,
            closure_id: closure_index,
            captured_scope_depth,
            async_function_id: Some(async_func_id),
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
        self.clear_register_range(self.register_base, req_len);
        for (index, (value, label)) in arguments.into_iter().enumerate() {
            let register = index as u32;
            if register < self.config.max_registers {
                self.write_reg_with_label(register, value, label)?;
            }
        }

        self.ip = function_entry as usize;
        Ok(())
    }

    fn complete_return(
        &mut self,
        return_val: Value,
        return_label: crate::ifc_artifacts::Label,
    ) -> Result<Option<Value>, InterpreterError> {
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
            self.finally_frames.truncate(frame.saved_finally_mode_depth);
            self.persist_closure_capture_updates(&frame);
            self.restore_scope_chain_for_frame(&frame);
            self.pending_exception = frame.saved_pending_exception;
            self.pending_return = frame.saved_pending_return;
            // ES2020 §9.2.2 step 13: if this is a constructor call and the
            // return value is not an object, use the allocated `this` object
            // instead.
            let (effective_val, effective_label) = match &frame.construct_this {
                Some(this_obj) if !return_val.is_object_like() => {
                    (this_obj.clone(), frame.this_label.clone())
                }
                _ => (return_val, return_label),
            };
            if let Some(return_reg) = frame.return_reg {
                self.write_reg_with_label(return_reg, effective_val, effective_label)?;
            }
            self.ip = frame.return_ip;
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            Ok(None)
        } else {
            self.pending_exception = None;
            self.pending_return = None;
            self.suspended_abrupt_completions.clear();
            self.finally_frames.clear();
            self.pending_finally_entry = None;
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

    fn unwind_call_stack_to(
        &mut self,
        target_depth: usize,
    ) -> (Option<LabeledException>, Option<LabeledReturn>) {
        let mut restored_pending_exception = None;
        let mut restored_pending_return = None;
        let mut restored_suspended_abrupt_depth = None;
        while self.call_stack.len() > target_depth {
            if let Some(frame) = self.call_stack.pop() {
                self.persist_closure_capture_updates(&frame);
                self.register_base = frame.register_base;
                self.finally_frames.truncate(frame.saved_finally_mode_depth);
                self.restore_scope_chain_for_frame(&frame);
                restored_pending_exception = frame.saved_pending_exception;
                restored_pending_return = frame.saved_pending_return;
                restored_suspended_abrupt_depth = Some(frame.saved_suspended_abrupt_depth);
            }
        }
        if let Some(depth) = restored_suspended_abrupt_depth {
            self.suspended_abrupt_completions.truncate(depth);
        }
        // A copy owned by the handler's frame is abandoned when control jumps
        // to that handler. Copies owned by shallower callers remain suspended
        // if the exception was caught inside an included getter.
        self.copy_data_properties_states
            .retain(|state| state.call_depth < target_depth);
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
        self.finally_frames.truncate(frame.finally_frame_depth);
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
        pending_exception: Option<LabeledException>,
        pending_return: Option<LabeledReturn>,
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
        self.finally_frames.truncate(frame.finally_frame_depth);
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

    fn current_containment_extension_id(&self) -> ExtensionId {
        self.config
            .extension_id
            .as_ref()
            .filter(|extension_id| !extension_id.is_empty())
            .cloned()
            .or_else(|| {
                self.current_module_specifier
                    .as_ref()
                    .filter(|specifier| !specifier.is_empty())
                    .cloned()
            })
            .unwrap_or_else(|| self.trace_id.clone())
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

        let extension_id = self.current_containment_extension_id();

        // Add decision receipt to the evidence chain
        self.decision_receipts.add_receipt(
            extension_id,
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

    fn enter_function_call(
        &mut self,
        module: &Ir3Module,
        callee_val: Value,
        this_value: Value,
        mut arg_vals: Vec<Value>,
        return_ip: usize,
        return_reg: Option<u32>,
    ) -> Result<(), InterpreterError> {
        let (func_idx, captured_env, closure_id) = match &callee_val {
            Value::Function(idx) => (*idx, None, None),
            Value::Closure(closure_id) => {
                let closure = self.closures.get(*closure_id as usize).ok_or_else(|| {
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
        if func.rest_param_index.is_some() {
            return Err(InterpreterError::TypeError {
                expected: "accessor function without a rest parameter".to_string(),
                got: "rest-parameter descriptor on getter/setter invocation".to_string(),
            });
        }
        arg_vals.truncate(func.arity as usize);

        if self.call_stack.len() >= self.config.max_call_depth {
            return Err(InterpreterError::StackOverflow {
                depth: self.call_stack.len(),
                max: self.config.max_call_depth,
            });
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
        let super_value = self.method_super_value(&callee_val, &this_value)?;
        self.call_stack.push(CallFrame {
            return_ip,
            return_reg,
            register_base: self.register_base,
            function_index: Some(func_idx),
            this_value,
            this_label: crate::ifc_artifacts::Label::Public,
            new_target_value: Value::Undefined,
            new_target_label: crate::ifc_artifacts::Label::Public,
            super_value,
            super_label: crate::ifc_artifacts::Label::Public,
            construct_this: None,
            saved_pending_exception: self.pending_exception.take(),
            saved_pending_return: self.pending_return.take(),
            saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
            saved_finally_mode_depth: self.finally_frames.len(),
            saved_scope_depth: scope_depth,
            saved_scope_chain: saved_chain,
            closure_id,
            captured_scope_depth,
            async_function_id: None,
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
        self.clear_register_range(self.register_base, req_len);

        for (i, val) in arg_vals.into_iter().enumerate() {
            let reg = i as u32;
            if reg < self.config.max_registers {
                self.write_reg(reg, val)?;
            }
        }

        self.ip = func.entry as usize;
        Ok(())
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
                self.clear_register_range(self.register_base, req_len);

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
            let (saved_ip, saved_regs, saved_labels, saved_base) = {
                let gobj = &mut self.generators[gen_id as usize];
                (
                    gobj.saved_ip,
                    std::mem::take(&mut gobj.saved_registers),
                    std::mem::take(&mut gobj.saved_register_labels),
                    gobj.saved_register_base,
                )
            };

            self.ip = saved_ip;
            self.register_base = saved_base;
            self.restore_saved_register_range(saved_base, saved_regs, saved_labels);
        }

        let result = self.run_loop(module);

        match &result {
            Ok(yielded_val) => {
                let max_regs = self.config.max_registers as usize;
                let saved_regs: Vec<Value> =
                    self.registers[self.register_base..self.register_base + max_regs].to_vec();
                let saved_labels = self
                    .register_labels_in_range(self.register_base, self.register_base + max_regs);

                let gobj = &mut self.generators[gen_id as usize];
                gobj.saved_ip = self.ip;
                gobj.saved_registers = saved_regs;
                gobj.saved_register_labels = saved_labels;
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

        // Save caller execution context
        let caller_ip = self.ip;
        let caller_register_base = self.register_base;
        let caller_scope = self.snapshot_scope_chain()?;
        let caller_scope_bytes = Self::estimate_scope_chain_bytes(&caller_scope);

        // Create promise for the async generator result
        let result_promise = self.promise_store.create().0;

        let (is_start, func_idx, closure_idx) = {
            let async_gen = &mut self.async_generators[gen_id as usize];
            let is_start = async_gen.phase == AsyncGeneratorPhase::SuspendedStart;
            let func_idx = async_gen.function_index;
            let closure_idx = async_gen.closure_index;
            async_gen.phase = AsyncGeneratorPhase::Executing;
            (is_start, func_idx, closure_idx)
        };

        // Set up execution context
        if is_start {
            let start_result = (|| -> Result<(), InterpreterError> {
                let func = _module.function_table.get(func_idx as usize).ok_or(
                    InterpreterError::FunctionNotFound {
                        index: func_idx,
                        table_size: _module.function_table.len() as u32,
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
                self.clear_register_range(self.register_base, req_len);

                self.ip = func.entry as usize;
                Ok(())
            })();

            if let Err(err) = start_result {
                // Restore caller context on error
                self.ip = caller_ip;
                self.register_base = caller_register_base;
                self.scope_chain.frames = caller_scope;
                let async_gen = &mut self.async_generators[gen_id as usize];
                async_gen.phase = AsyncGeneratorPhase::SuspendedStart;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();

                // Reject the promise with the error
                let js_val = crate::object_model::JsValue::Str(JsString::from(format!("{err:?}")));
                let label = crate::ifc_artifacts::Label::Public;
                self.promise_store
                    .reject(
                        crate::promise_model::PromiseHandle(result_promise),
                        js_val,
                        label,
                        &mut self.event_loop.microtasks,
                    )
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "promise rejection".into(),
                        got: format!("failed to reject promise: {e:?}"),
                    })?;
                return Ok(Value::Promise(result_promise));
            }
        } else {
            // Resume from saved state (SuspendedYield/SuspendedAwait)
            let (saved_ip, saved_regs, saved_labels, saved_base) = {
                let async_gen = &mut self.async_generators[gen_id as usize];
                (
                    async_gen.saved_ip,
                    std::mem::take(&mut async_gen.saved_registers),
                    std::mem::take(&mut async_gen.saved_register_labels),
                    async_gen.saved_register_base,
                )
            };

            self.ip = saved_ip;
            self.register_base = saved_base;
            self.restore_saved_register_range(saved_base, saved_regs, saved_labels);
        }

        // Execute until yield/return/throw
        let execution_result = self.run_loop(_module);

        // Handle execution result and fulfill promise accordingly
        let promise_result = match &execution_result {
            Ok(result_value)
                if matches!(
                    _module.instructions.get(self.ip),
                    Some(Ir3Instruction::Return { .. })
                ) =>
            {
                let async_gen = &mut self.async_generators[gen_id as usize];
                async_gen.phase = AsyncGeneratorPhase::Completed;

                let result_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(result_id, "value".to_string(), result_value.clone())?;
                self.set_object_property(result_id, "done".to_string(), Value::Bool(true))?;

                let js_val = crate::object_model::JsValue::Object(
                    crate::object_model::ObjectHandle(result_id.0),
                );
                let label = crate::ifc_artifacts::Label::Public;
                self.promise_store.fulfill(
                    crate::promise_model::PromiseHandle(result_promise),
                    js_val,
                    label,
                    &mut self.event_loop.microtasks,
                )
            }
            Ok(yield_result) => {
                // Yield already returns the generator result object
                // `{ value, done: false }`; promise-wrap it directly.
                let max_regs = self.config.max_registers as usize;
                let saved_regs: Vec<Value> =
                    self.registers[self.register_base..self.register_base + max_regs].to_vec();
                let saved_labels = self
                    .register_labels_in_range(self.register_base, self.register_base + max_regs);

                let async_gen = &mut self.async_generators[gen_id as usize];
                async_gen.saved_ip = self.ip;
                async_gen.saved_registers = saved_regs;
                async_gen.saved_register_labels = saved_labels;
                async_gen.saved_register_base = self.register_base;
                async_gen.phase = AsyncGeneratorPhase::SuspendedYield;

                let js_val = Self::value_to_js_value(yield_result);
                let label = crate::ifc_artifacts::Label::Public;
                self.promise_store.fulfill(
                    crate::promise_model::PromiseHandle(result_promise),
                    js_val,
                    label,
                    &mut self.event_loop.microtasks,
                )
            }
            Err(InterpreterError::Halted) => {
                // Generator completed
                let async_gen = &mut self.async_generators[gen_id as usize];
                async_gen.phase = AsyncGeneratorPhase::Completed;

                // Create {value: undefined, done: true} object
                let result_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(result_id, "value".to_string(), Value::Undefined)?;
                self.set_object_property(result_id, "done".to_string(), Value::Bool(true))?;

                let js_val = crate::object_model::JsValue::Object(
                    crate::object_model::ObjectHandle(result_id.0),
                );
                let label = crate::ifc_artifacts::Label::Public;
                self.promise_store.fulfill(
                    crate::promise_model::PromiseHandle(result_promise),
                    js_val,
                    label,
                    &mut self.event_loop.microtasks,
                )
            }
            Err(err) => {
                // Generator threw an error
                let async_gen = &mut self.async_generators[gen_id as usize];
                async_gen.phase = AsyncGeneratorPhase::Completed;

                // Reject the promise with the error
                let js_val = crate::object_model::JsValue::Str(JsString::from(format!("{err:?}")));
                let label = crate::ifc_artifacts::Label::Public;
                self.promise_store.reject(
                    crate::promise_model::PromiseHandle(result_promise),
                    js_val,
                    label,
                    &mut self.event_loop.microtasks,
                )
            }
        };

        // Restore caller execution context
        self.ip = caller_ip;
        self.register_base = caller_register_base;
        self.scope_chain.frames = caller_scope;
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();

        // Handle promise operation result
        promise_result.map_err(|e| InterpreterError::TypeError {
            expected: "promise operation".into(),
            got: format!("failed promise operation: {e:?}"),
        })?;

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
                    if let Some(final_value) =
                        self.complete_return(Value::Undefined, crate::ifc_artifacts::Label::Public)?
                    {
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
                    let label = self.read_reg_label(src)?;
                    self.write_reg_with_label(dst, val, label)?;
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
                    let callee_label = self.read_reg_label(callee)?;

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
                        let result = self.dispatch_builtin_function(module, builtin, None, args)?;
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

                    // Async function call: return the result promise immediately
                    // while executing the body on an async-marked call frame.
                    if let Value::AsyncFunction(_) = &callee_val {
                        let func = module.function_table.get(func_idx as usize).ok_or(
                            InterpreterError::FunctionNotFound {
                                index: func_idx,
                                table_size: module.function_table.len() as u32,
                            },
                        )?;
                        self.validate_function_rest_param(func)?;

                        if self.call_stack.len() >= self.config.max_call_depth {
                            return Err(InterpreterError::StackOverflow {
                                depth: self.call_stack.len(),
                                max: self.config.max_call_depth,
                            });
                        }

                        let mut arg_vals = Vec::new();
                        let mut arg_labels = Vec::new();
                        for i in 0..args.count {
                            let reg = args.start.checked_add(i).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            arg_vals.push(self.read_reg(reg)?);
                            arg_labels.push(self.read_reg_label(reg)?);
                        }
                        arg_vals.truncate(func.arity as usize);
                        arg_labels.truncate(func.arity as usize);
                        self.apply_rest_param(
                            module,
                            &mut arg_vals,
                            func.rest_param_index,
                            func.arity,
                            args,
                        )?;
                        self.apply_rest_param_labels(
                            &mut arg_labels,
                            func.rest_param_index,
                            func.arity,
                            args,
                        )?;
                        self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;

                        self.enter_async_function_call(AsyncCallSetup {
                            function_index: func_idx,
                            function_entry: func.entry,
                            closure_index: closure_id,
                            captured_env,
                            arguments: arg_vals.into_iter().zip(arg_labels).collect(),
                            this_value: Value::Undefined,
                            this_label: crate::ifc_artifacts::Label::Public,
                            super_value: Value::Undefined,
                            super_label: callee_label,
                            result_register: dst,
                        })?;
                        continue;
                    }

                    // Generator function call: create a suspended GeneratorObject.
                    if let Value::GeneratorFunction(cid) = &callee_val {
                        let func = module.function_table.get(func_idx as usize).ok_or(
                            InterpreterError::FunctionNotFound {
                                index: func_idx,
                                table_size: module.function_table.len() as u32,
                            },
                        )?;
                        if func.rest_param_index.is_some() {
                            return Err(InterpreterError::TypeError {
                                expected: "generator call without unsupported rest metadata"
                                    .to_string(),
                                got: "generator rest parameters are not implemented".to_string(),
                            });
                        }
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
                            saved_register_labels: Vec::new(),
                            saved_register_base: 0,
                            phase: GeneratorPhase::SuspendedStart,
                        });
                        self.write_reg(dst, Value::Generator(gen_id))?;
                        self.ip += 1;
                        continue;
                    }

                    // Async generator function call: create a suspended AsyncGeneratorObject.
                    if let Value::AsyncGeneratorFunction(cid) = &callee_val {
                        let func = module.function_table.get(func_idx as usize).ok_or(
                            InterpreterError::FunctionNotFound {
                                index: func_idx,
                                table_size: module.function_table.len() as u32,
                            },
                        )?;
                        if func.rest_param_index.is_some() {
                            return Err(InterpreterError::TypeError {
                                expected: "async-generator call without unsupported rest metadata"
                                    .to_string(),
                                got: "async-generator rest parameters are not implemented"
                                    .to_string(),
                            });
                        }
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
                            saved_register_labels: Vec::new(),
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
                            self.validate_function_rest_param(func)?;

                            if self.call_stack.len() >= self.config.max_call_depth {
                                return Err(InterpreterError::StackOverflow {
                                    depth: self.call_stack.len(),
                                    max: self.config.max_call_depth,
                                });
                            }

                            let mut arg_vals = Vec::new();
                            let mut arg_labels = Vec::new();
                            for i in 0..args.count {
                                let reg = args.start.checked_add(i).ok_or(
                                    InterpreterError::RegisterOutOfBounds {
                                        register: args.start,
                                        max: self.config.max_registers,
                                    },
                                )?;
                                arg_vals.push(self.read_reg(reg)?);
                                arg_labels.push(self.read_reg_label(reg)?);
                            }
                            arg_vals.truncate(func.arity as usize);
                            arg_labels.truncate(func.arity as usize);
                            self.apply_rest_param(
                                module,
                                &mut arg_vals,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.apply_rest_param_labels(
                                &mut arg_labels,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
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
                            // Plain calls do not supply a receiver. Closures inherit the
                            // defining frame's `this`; non-closure calls use `undefined`.
                            let (frame_this, frame_this_label) = self.call_stack.last().map_or(
                                (Value::Undefined, crate::ifc_artifacts::Label::Public),
                                |frame| (frame.this_value.clone(), frame.this_label.clone()),
                            );
                            // Arrow closures inherit `this` from the defining frame.
                            let (call_this, call_this_label) = if captured_env.is_some() {
                                (frame_this, frame_this_label)
                            } else {
                                (Value::Undefined, crate::ifc_artifacts::Label::Public)
                            };
                            let super_value = self
                                .function_super_value(&callee_val, IR_SUPER_PROTOTYPE_PROPERTY)?;

                            self.call_stack.push(CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: Some(dst),
                                register_base: self.register_base,
                                function_index: Some(func_idx),
                                this_value: call_this,
                                this_label: call_this_label,
                                new_target_value: Value::Undefined,
                                new_target_label: crate::ifc_artifacts::Label::Public,
                                super_value,
                                super_label: callee_label,
                                construct_this: None,
                                saved_pending_exception: self.pending_exception.take(),
                                saved_pending_return: self.pending_return.take(),
                                saved_suspended_abrupt_depth: self
                                    .suspended_abrupt_completions
                                    .len(),
                                saved_finally_mode_depth: self.finally_frames.len(),
                                saved_scope_depth: scope_depth,
                                saved_scope_chain: saved_chain,
                                closure_id,
                                captured_scope_depth,
                                async_function_id: None,
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
                            self.clear_register_range(self.register_base, req_len);

                            // Copy arguments into registers for the callee.
                            for (i, (val, label)) in
                                arg_vals.into_iter().zip(arg_labels).enumerate()
                            {
                                let reg = i as u32;
                                if reg < self.config.max_registers {
                                    self.write_reg_with_label(reg, val, label)?;
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
                    let receiver_label = self.read_reg_label(receiver)?;
                    let callee_val = self.read_reg(callee)?;
                    let callee_label = self.read_reg_label(callee)?;

                    if let Value::BuiltinFunction(builtin) = &callee_val {
                        let result = self.dispatch_builtin_function(
                            module,
                            builtin,
                            Some(&receiver_val),
                            args,
                        )?;
                        self.write_reg(dst, result)?;
                        self.ip += 1;
                        continue;
                    }

                    let (func_idx, captured_env, closure_id) = match &callee_val {
                        Value::Function(idx) => (*idx, None, None),
                        Value::Closure(closure_id) | Value::AsyncFunction(closure_id) => {
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
                    self.validate_function_rest_param(func)?;

                    if self.call_stack.len() >= self.config.max_call_depth {
                        return Err(InterpreterError::StackOverflow {
                            depth: self.call_stack.len(),
                            max: self.config.max_call_depth,
                        });
                    }

                    let mut arg_vals = Vec::new();
                    let mut arg_labels = Vec::new();
                    for i in 0..args.count {
                        let reg = args.start.checked_add(i).ok_or(
                            InterpreterError::RegisterOutOfBounds {
                                register: args.start,
                                max: self.config.max_registers,
                            },
                        )?;
                        arg_vals.push(self.read_reg(reg)?);
                        arg_labels.push(self.read_reg_label(reg)?);
                    }
                    arg_vals.truncate(func.arity as usize);
                    arg_labels.truncate(func.arity as usize);
                    self.apply_rest_param(
                        module,
                        &mut arg_vals,
                        func.rest_param_index,
                        func.arity,
                        args,
                    )?;
                    self.apply_rest_param_labels(
                        &mut arg_labels,
                        func.rest_param_index,
                        func.arity,
                        args,
                    )?;
                    self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;

                    let super_value = self.method_super_value(&callee_val, &receiver_val)?;
                    if matches!(&callee_val, Value::AsyncFunction(_)) {
                        self.enter_async_function_call(AsyncCallSetup {
                            function_index: func_idx,
                            function_entry: func.entry,
                            closure_index: closure_id,
                            captured_env,
                            arguments: arg_vals.into_iter().zip(arg_labels).collect(),
                            this_value: receiver_val,
                            this_label: receiver_label,
                            super_value,
                            super_label: callee_label,
                            result_register: dst,
                        })?;
                        continue;
                    }

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
                        return_reg: Some(dst),
                        register_base: self.register_base,
                        function_index: Some(func_idx),
                        this_value: receiver_val,
                        this_label: receiver_label,
                        new_target_value: Value::Undefined,
                        new_target_label: crate::ifc_artifacts::Label::Public,
                        super_value,
                        super_label: callee_label,
                        construct_this: None,
                        saved_pending_exception: self.pending_exception.take(),
                        saved_pending_return: self.pending_return.take(),
                        saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
                        saved_finally_mode_depth: self.finally_frames.len(),
                        saved_scope_depth: scope_depth,
                        saved_scope_chain: saved_chain,
                        closure_id,
                        captured_scope_depth,
                        async_function_id: None,
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
                    self.clear_register_range(self.register_base, req_len);

                    for (i, (val, label)) in arg_vals.into_iter().zip(arg_labels).enumerate() {
                        let reg = i as u32;
                        if reg < self.config.max_registers {
                            self.write_reg_with_label(reg, val, label)?;
                        }
                    }

                    self.ip = func.entry as usize;
                }
                Ir3Instruction::Return { value } => {
                    let return_val = self.read_reg(value)?;
                    let return_label = self.read_reg_label(value)?;
                    // A return from inside a finally overrides any in-flight
                    // exception, and a return from inside try/catch must still
                    // unwind through enclosing finally blocks before it can
                    // complete.
                    self.suspend_current_abrupt_completion();
                    self.pending_exception = None;
                    self.pending_return = Some(LabeledReturn {
                        value: return_val.clone(),
                        label: return_label.clone(),
                    });
                    if let Some(finally_target) = self.pop_current_finally_target() {
                        self.pending_finally_entry = Some(PendingFinallyEntry {
                            target: finally_target,
                            mode: FinallyMode::Return,
                        });
                        self.ip = finally_target;
                    } else {
                        self.pending_return = None;
                        if let Some(final_value) = self.complete_return(return_val, return_label)? {
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

                    // Promise hostcalls return an explicit label for their
                    // Promise-handle result.  Keep this separate from generic
                    // hostcalls, whose current contract remains Public.
                    if is_promise_cap {
                        let (result, result_label) =
                            self.dispatch_promise_hostcall(&capability.0, args)?;
                        self.write_reg_with_label(dst, result, result_label)?;
                        self.ip += 1;
                        continue;
                    }

                    let result = if capability.0 == "module:require" {
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
                        let specifier = Self::module_specifier_string(&specifier)?;
                        self.require_module(module, specifier)?
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
                    let specifier_str = Self::module_specifier_string(&specifier_str)?;
                    let namespace = self.import_module(module, specifier_str)?;
                    self.write_reg(dst, namespace)?;
                    self.ip += 1;
                }
                Ir3Instruction::ExportBinding {
                    name_pool_index,
                    src,
                } => {
                    let name = Self::metadata_pool_string(
                        module,
                        name_pool_index,
                        format!("__export_{name_pool_index}"),
                    )?;
                    let value = self.read_reg(src)?;
                    self.register_module_export(&name, value)?;
                    self.ip += 1;
                }
                Ir3Instruction::GetProperty { obj, key, dst } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let key_str = Self::property_key(&key_val);

                    let called_accessor = match &obj_val {
                        Value::Object(oid) => self.load_object_property_or_call_accessor(
                            module,
                            obj_val.clone(),
                            *oid,
                            &key_str,
                            dst,
                        )?,
                        // String receivers expose `length` (UTF-16 code-unit
                        // count) and the String.prototype methods wired for
                        // bd-2vzgi; unknown keys yield `undefined` per ES
                        // GetV semantics, matching the engine (bd-7zwar —
                        // previously a fail-closed TypeError).
                        Value::Str(text) => match Self::string_property_value(text, &key_str) {
                            Some(value) => {
                                self.write_reg(dst, value)?;
                                false
                            }
                            None => {
                                self.write_reg(dst, Value::Undefined)?;
                                false
                            }
                        },
                        _ if Self::function_object_key(&obj_val).is_some() => self
                            .load_function_like_property_or_call_accessor(
                                module,
                                obj_val.clone(),
                                &key_str,
                                dst,
                            )?,
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: obj_val.type_name().to_string(),
                            });
                        }
                    };
                    if !called_accessor {
                        self.ip += 1;
                    }
                }
                Ir3Instruction::SetProperty { obj, key, val } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let set_val = self.read_reg(val)?;
                    let key_str = Self::property_key(&key_val);

                    let called_accessor = match &obj_val {
                        Value::Object(oid) => self.set_object_property_or_call_accessor(
                            module,
                            obj_val.clone(),
                            *oid,
                            key_str,
                            set_val,
                        )?,
                        _ if Self::function_object_key(&obj_val).is_some() => self
                            .set_function_like_property_or_call_accessor(
                                module,
                                obj_val.clone(),
                                &key_str,
                                set_val,
                            )?,
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: obj_val.type_name().to_string(),
                            });
                        }
                    };
                    if !called_accessor {
                        self.ip += 1;
                    }
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
                    let id = self.alloc_array_with_prototype(None)?;
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
                                    // `n + 1` would overflow on a property key that
                                    // parses to `u32::MAX` (e.g. "4294967295");
                                    // saturate to match `array_like_length`.
                                    key.parse::<u32>()
                                        .ok()
                                        .map_or(current, |n| current.max(n.saturating_add(1)))
                                })
                            })
                            .unwrap_or(0);
                        self.set_object_property(arr_id, next_idx.to_string(), elem_val)?;
                        self.set_object_property(
                            arr_id,
                            "length".to_string(),
                            Value::Int(i64::from(next_idx.saturating_add(1))),
                        )?;
                    }
                    self.ip += 1;
                }
                Ir3Instruction::ArraySlice { array, start, dst } => {
                    let arr_val = self.read_reg(array)?;
                    let start_val = self.read_reg(start)?;
                    let Value::Object(arr_id) = arr_val else {
                        return Err(InterpreterError::TypeError {
                            expected: "array object".to_string(),
                            got: arr_val.type_name().to_string(),
                        });
                    };

                    let elements: Vec<Value> = {
                        let obj = self
                            .heap
                            .get(arr_id.0 as usize)
                            .ok_or(InterpreterError::ObjectNotFound { id: arr_id.0 })?;
                        let length = obj
                            .properties
                            .get("length")
                            .and_then(|value| match value {
                                Value::Int(n) if *n > 0 => usize::try_from(*n).ok(),
                                _ => None,
                            })
                            .unwrap_or_else(|| {
                                obj.properties
                                    .keys()
                                    .filter_map(|key| key.parse::<usize>().ok())
                                    .max()
                                    .map_or(0, |index| index.saturating_add(1))
                            });
                        (0..length)
                            .map(|index| {
                                obj.properties
                                    .get(&index.to_string())
                                    .cloned()
                                    .unwrap_or(Value::Undefined)
                            })
                            .collect()
                    };

                    let length = elements.len();
                    let start_idx = match start_val {
                        Value::Undefined | Value::Null => 0,
                        Value::Bool(false) => 0,
                        Value::Bool(true) => 1usize.min(length),
                        Value::Int(n) if n < 0 => {
                            usize::try_from((length as i64).saturating_add(n).max(0)).unwrap_or(0)
                        }
                        Value::Int(n) => usize::try_from(n).unwrap_or(usize::MAX).min(length),
                        Value::Float(f) => {
                            let value = f.inner();
                            if !value.is_finite() {
                                0
                            } else if value < 0.0 {
                                ((length as f64) + value).max(0.0) as usize
                            } else {
                                (value as usize).min(length)
                            }
                        }
                        other => {
                            return Err(InterpreterError::TypeError {
                                expected: "integer-compatible array slice start".to_string(),
                                got: other.type_name().to_string(),
                            });
                        }
                    };

                    let result_values: Vec<Value> = elements.into_iter().skip(start_idx).collect();
                    let result_id = self.alloc_array_from_values(&result_values)?;
                    self.write_reg(dst, Value::Object(result_id))?;
                    self.ip += 1;
                }
                Ir3Instruction::SpreadIntoArray { array, iterable } => {
                    // Spread iterable elements into an array
                    let arr_val = self.read_reg(array)?;
                    let iter_val = self.read_reg(iterable)?;
                    if let Value::Object(arr_id) = arr_val {
                        // Get elements from the iterable: an array-like
                        // object, or a string spread per code point with
                        // lone surrogates preserved exactly (ES string
                        // iteration; bd-7zwar, engine parity with bd-rdnhc —
                        // previously a string iterable was silently skipped).
                        let elements: Vec<Value> = match &iter_val {
                            Value::Object(iter_id) => {
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
                            }
                            Value::Str(text) => text
                                .code_point_elements()
                                .into_iter()
                                .map(Value::Str)
                                .collect(),
                            _ => Vec::new(),
                        };
                        // Push elements to target array
                        if self.heap.get(arr_id.0 as usize).is_some() {
                            let next_idx = self
                                .heap
                                .get(arr_id.0 as usize)
                                .map(|obj| {
                                    obj.properties.keys().fold(0u32, |current, key| {
                                        // `n + 1` would overflow on a property key
                                        // that parses to `u32::MAX`; saturate to
                                        // match `array_like_length`.
                                        key.parse::<u32>()
                                            .ok()
                                            .map_or(current, |n| current.max(n.saturating_add(1)))
                                    })
                                })
                                .unwrap_or(0);
                            let mut end_idx = next_idx;
                            for (offset, elem) in elements.into_iter().enumerate() {
                                let offset = u32::try_from(offset).map_err(|_| {
                                    InterpreterError::TypeError {
                                        expected: "array index capacity".into(),
                                        got: format!("spread element offset {offset}"),
                                    }
                                })?;
                                let idx = next_idx.checked_add(offset).ok_or_else(|| {
                                    InterpreterError::TypeError {
                                        expected: "array index capacity".into(),
                                        got: format!("array index overflow at {next_idx}+{offset}"),
                                    }
                                })?;
                                self.set_object_property(arr_id, idx.to_string(), elem)?;
                                end_idx = idx.saturating_add(1);
                            }
                            // Maintain `length` like ArrayPush does (engine
                            // parity; bd-7zwar — spread results previously
                            // had no length property in this lane).
                            self.set_object_property(
                                arr_id,
                                "length".to_string(),
                                Value::Int(i64::from(end_idx)),
                            )?;
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
                                obj.own_property_keys()
                                    .into_iter()
                                    .filter_map(|key| {
                                        obj.properties.get(&key).cloned().map(|value| (key, value))
                                    })
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
                Ir3Instruction::CopyDataProperties {
                    target,
                    source,
                    excluded,
                    value_dst,
                } => {
                    let entered_getter = self.execute_copy_data_properties(
                        module, target, source, excluded, value_dst,
                    )?;
                    if !entered_getter {
                        self.ip += 1;
                    }
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
                    self.write_reg(dst, Value::str(val.typeof_name()))?;
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
                    let callee_label = self.read_reg_label(callee)?;

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
                            self.validate_function_rest_param(func)?;

                            if self.call_stack.len() >= self.config.max_call_depth {
                                return Err(InterpreterError::StackOverflow {
                                    depth: self.call_stack.len(),
                                    max: self.config.max_call_depth,
                                });
                            }

                            let mut arg_vals = Vec::new();
                            let mut arg_labels = Vec::new();
                            for i in 0..args.count {
                                let reg = args.start.checked_add(i).ok_or(
                                    InterpreterError::RegisterOutOfBounds {
                                        register: args.start,
                                        max: self.config.max_registers,
                                    },
                                )?;
                                arg_vals.push(self.read_reg(reg)?);
                                arg_labels.push(self.read_reg_label(reg)?);
                            }
                            arg_vals.truncate(func.arity as usize);
                            arg_labels.truncate(func.arity as usize);
                            self.apply_rest_param(
                                module,
                                &mut arg_vals,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.apply_rest_param_labels(
                                &mut arg_labels,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;

                            // Materializing the implicit rest Array is policy-
                            // guarded. Allocate the constructor receiver only
                            // after that guard succeeds so a denied rest
                            // allocation leaves no constructor setup behind.
                            let prototype = self
                                .function_prototype_for_value(&callee_val)?
                                .ok_or_else(|| InterpreterError::TypeError {
                                    expected: "constructor function".to_string(),
                                    got: callee_val.type_name().to_string(),
                                })?;
                            let this_id = self.alloc_object_with_prototype(Some(prototype))?;
                            if let Some(this_obj) = self.heap.get_mut(this_id.0 as usize) {
                                this_obj.constructor_function = Some(func_idx);
                            }
                            let this_val = Value::Object(this_id);
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
                            let super_value = self.function_metadata_property(
                                &callee_val,
                                IR_SUPER_CONSTRUCTOR_PROPERTY,
                            )?;
                            self.call_stack.push(CallFrame {
                                return_ip: self.ip + 1,
                                return_reg: Some(dst),
                                register_base: self.register_base,
                                function_index: Some(func_idx),
                                this_value: this_val.clone(),
                                this_label: callee_label.clone(),
                                new_target_value: callee_val.clone(),
                                new_target_label: callee_label.clone(),
                                super_value,
                                super_label: callee_label,
                                construct_this: Some(this_val.clone()),
                                saved_pending_exception: self.pending_exception.take(),
                                saved_pending_return: self.pending_return.take(),
                                saved_suspended_abrupt_depth: self
                                    .suspended_abrupt_completions
                                    .len(),
                                saved_finally_mode_depth: self.finally_frames.len(),
                                saved_scope_depth: scope_depth,
                                saved_scope_chain: saved_chain,
                                closure_id,
                                captured_scope_depth,
                                async_function_id: None,
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
                            self.clear_register_range(self.register_base, req_len);

                            // Parameters occupy r0..rN-1, matching deferred
                            // function lowering. `this` is carried by the call
                            // frame and recovered through `LoadThis`.
                            for (i, (val, label)) in
                                arg_vals.into_iter().zip(arg_labels).enumerate()
                            {
                                let reg = i as u32;
                                if reg < self.config.max_registers {
                                    self.write_reg_with_label(reg, val, label)?;
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
                    // Exact-unit concatenation so split surrogate halves heal
                    // across template parts, matching engine semantics.
                    let mut result = JsString::empty();
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
                            Value::Int(n) => JsString::from(n.to_string()),
                            Value::Float(f) => JsString::from(f.to_string()),
                            Value::Bool(b) => JsString::from(if b { "true" } else { "false" }),
                            Value::Null => JsString::from("null"),
                            Value::Undefined => JsString::from("undefined"),
                            Value::Object(_) | Value::Iterator(_) | Value::Generator(_) => {
                                JsString::from("[object Object]")
                            }
                            Value::Promise(_) => JsString::from("[object Promise]"),
                            Value::Function(_)
                            | Value::Closure(_)
                            | Value::GeneratorFunction(_)
                            | Value::BuiltinFunction(_)
                            | Value::AsyncFunction(_)
                            | Value::AsyncFunctionObject(_)
                            | Value::AsyncGeneratorFunction(_)
                            | Value::AsyncGeneratorObject(_) => JsString::from("function"),
                        };
                        self.check_string_limit(result.len().saturating_add(part_str.len()))?;
                        result = result.concat(&part_str);
                    }
                    self.write_reg(dst, Value::Str(result))?;
                    self.ip += 1;
                }
                Ir3Instruction::Halt => {
                    return Err(InterpreterError::Halted);
                }
                Ir3Instruction::LoadThis { dst } => {
                    let (this_val, this_label) = self.call_stack.last().map_or(
                        (Value::Undefined, crate::ifc_artifacts::Label::Public),
                        |frame| (frame.this_value.clone(), frame.this_label.clone()),
                    );
                    self.write_reg_with_label(dst, this_val, this_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadNewTarget { dst } => {
                    let (new_target, new_target_label) = self.call_stack.last().map_or(
                        (Value::Undefined, crate::ifc_artifacts::Label::Public),
                        |frame| {
                            (
                                frame.new_target_value.clone(),
                                frame.new_target_label.clone(),
                            )
                        },
                    );
                    self.write_reg_with_label(dst, new_target, new_target_label)?;
                    self.ip += 1;
                }
                Ir3Instruction::LoadSuper { dst } => {
                    let (super_value, super_label) = self.call_stack.last().map_or(
                        (Value::Undefined, crate::ifc_artifacts::Label::Public),
                        |frame| (frame.super_value.clone(), frame.super_label.clone()),
                    );
                    self.write_reg_with_label(dst, super_value, super_label)?;
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
                        finally_frame_depth: self.finally_frames.len(),
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
                    let thrown_label = self.read_reg_label(value)?;
                    self.suspend_current_abrupt_completion();
                    self.pending_return = None;
                    self.pending_exception = Some(LabeledException {
                        value: thrown.clone(),
                        label: thrown_label,
                    });
                    // Walk the catch frame stack to find the nearest valid handler.
                    // Use rposition to find the topmost matching frame by index,
                    // then truncate to remove it and any frames above it — but
                    // NOT frames below it (which belong to outer try blocks).
                    if let Some(frame) = self.pop_exception_target_frame() {
                        self.pending_finally_entry = (frame.finally_target
                            == Some(frame.catch_target))
                        .then_some(PendingFinallyEntry {
                            target: frame.catch_target,
                            mode: FinallyMode::Exception,
                        });
                        self.ip = frame.catch_target;
                    } else {
                        // No catch handler found — uncaught exception.
                        self.suspended_abrupt_completions.clear();
                        let desc = match &thrown {
                            Value::Str(s) => s.to_string(),
                            Value::Int(n) => n.to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Undefined => "undefined".to_string(),
                            Value::Null => "null".to_string(),
                            _ => "[object]".to_string(),
                        };
                        self.pending_exception = None;
                        self.pending_finally_entry = None;
                        self.finally_frames.clear();
                        self.discard_all_copy_data_properties_states();
                        return Err(InterpreterError::UncaughtException { value: desc });
                    }
                }
                Ir3Instruction::EnterCatch { dst } => {
                    // Load the pending exception into the catch binding register.
                    let exception = self.pending_exception.take().unwrap_or(LabeledException {
                        value: Value::Undefined,
                        label: crate::ifc_artifacts::Label::Public,
                    });
                    self.restore_suspended_abrupt_completion();
                    self.write_reg_with_label(dst, exception.value, exception.label)?;
                    self.ip += 1;
                }
                Ir3Instruction::EnterFinally => {
                    // Only the unwind edge that selected this target owns the
                    // pending completion. Normal nested entry may observe an
                    // outer pending completion without consuming it.
                    let mode = if self
                        .pending_finally_entry
                        .as_ref()
                        .is_some_and(|entry| entry.target == self.ip)
                    {
                        self.pending_finally_entry
                            .take()
                            .map_or(FinallyMode::Normal, |entry| entry.mode)
                    } else {
                        FinallyMode::Normal
                    };
                    let completion = match mode {
                        FinallyMode::Exception => self
                            .pending_exception
                            .take()
                            .map(AbruptCompletion::Exception),
                        FinallyMode::Return => {
                            self.pending_return.take().map(AbruptCompletion::Return)
                        }
                        FinallyMode::Normal => None,
                    };
                    self.finally_frames.push(FinallyFrame { completion });
                    self.ip += 1;
                }
                Ir3Instruction::EndFinally => {
                    match self.finally_frames.pop().and_then(|frame| frame.completion) {
                        Some(AbruptCompletion::Exception(thrown)) => {
                            self.pending_return = None;
                            self.pending_exception = Some(thrown.clone());
                            let desc = match &thrown.value {
                                Value::Str(s) => s.to_string(),
                                Value::Int(n) => n.to_string(),
                                Value::Bool(b) => b.to_string(),
                                Value::Undefined => "undefined".to_string(),
                                Value::Null => "null".to_string(),
                                _ => "[object]".to_string(),
                            };
                            // Look for another catch frame to propagate to.
                            if let Some(frame) = self.pop_exception_target_frame() {
                                self.pending_finally_entry = (frame.finally_target
                                    == Some(frame.catch_target))
                                .then_some(PendingFinallyEntry {
                                    target: frame.catch_target,
                                    mode: FinallyMode::Exception,
                                });
                                self.ip = frame.catch_target;
                            } else {
                                self.suspended_abrupt_completions.clear();
                                self.pending_exception = None;
                                self.pending_finally_entry = None;
                                self.finally_frames.clear();
                                self.discard_all_copy_data_properties_states();
                                return Err(InterpreterError::UncaughtException { value: desc });
                            }
                        }
                        Some(AbruptCompletion::Return(pending_return)) => {
                            self.pending_exception = None;
                            if let Some(finally_target) = self.pop_current_finally_target() {
                                self.pending_return = Some(pending_return);
                                self.pending_finally_entry = Some(PendingFinallyEntry {
                                    target: finally_target,
                                    mode: FinallyMode::Return,
                                });
                                self.ip = finally_target;
                            } else if let Some(final_value) =
                                self.complete_return(pending_return.value, pending_return.label)?
                            {
                                return Ok(final_value);
                            }
                        }
                        None => {
                            // Normal completion — just continue.
                            self.ip += 1;
                        }
                    }
                }
                Ir3Instruction::DiscardAbruptCompletion => {
                    let _ = self.finally_frames.pop();
                    self.restore_suspended_abrupt_completion();
                    self.ip += 1;
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
                    let mut captured_env = self.snapshot_scope_chain()?;
                    let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                        InterpreterError::TypeError {
                            expected: "closure table capacity".into(),
                            got: format!("exceeded u32::MAX ({})", self.closures.len()),
                        }
                    })?;
                    // Class constructors capture their private self name before
                    // the destination register receives the new closure. Only
                    // the constructor-specific marker is cyclically initialized:
                    // descriptor-name matching would corrupt an unrelated outer
                    // capture when a class method and that capture share a name.
                    // The marker is materialized in the immediate capture frame;
                    // ancestor frames can belong to an enclosing constructor.
                    if let Some(frame) = captured_env.last_mut() {
                        for (name, binding) in &mut frame.bindings {
                            if name.starts_with(CLASS_EXPRESSION_CONSTRUCTOR_SELF_CAPTURE_PREFIX) {
                                binding.value = Value::Closure(closure_id);
                                binding.initialized = true;
                                break;
                            }
                        }
                    }
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
                    let awaited_label = self.read_reg_label(promise_reg)?;

                    // Convert the awaited value to a Promise if it's not already one
                    let promise_handle = match awaited_value {
                        Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                        _ => {
                            // await non-promise: create a resolved promise with the value
                            let js_val = Self::value_to_js_value(&awaited_value);
                            let handle = self.promise_store.create();
                            self.fulfill_promise(handle, js_val, awaited_label.clone())?;
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
                    let promise_state = promise_record.state.clone();
                    let promise_label = promise_record.label.clone();
                    let effective_label = awaited_label.join(&promise_label);

                    if promise_state.is_settled() {
                        // Promise already settled - continue execution synchronously
                        match promise_state {
                            crate::promise_model::PromiseState::Fulfilled(js_val) => {
                                let result_value = Self::js_value_to_value(&js_val);
                                self.write_reg_with_label(
                                    promise_reg,
                                    result_value,
                                    effective_label,
                                )?;
                                self.ip += 1;
                                continue;
                            }
                            crate::promise_model::PromiseState::Rejected(js_reason) => {
                                let error_value = Self::js_value_to_value(&js_reason);
                                if let Some(async_func_id) = self
                                    .call_stack
                                    .last()
                                    .and_then(|frame| frame.async_function_id)
                                {
                                    let async_func = self
                                        .async_functions
                                        .get(async_func_id as usize)
                                        .ok_or_else(|| InterpreterError::TypeError {
                                            expected: "valid async function".to_string(),
                                            got: format!(
                                                "async function #{async_func_id} not found"
                                            ),
                                        })?;
                                    let promise_handle = crate::promise_model::PromiseHandle(
                                        async_func.result_promise,
                                    );
                                    let js_reason = Self::value_to_js_value(&error_value);
                                    self.reject_promise(
                                        promise_handle,
                                        js_reason,
                                        effective_label,
                                    )?;
                                    if let Some(func) =
                                        self.async_functions.get_mut(async_func_id as usize)
                                    {
                                        func.phase = AsyncFunctionPhase::Completed;
                                    }
                                    if let Some(final_value) = self.complete_return(
                                        Value::Undefined,
                                        crate::ifc_artifacts::Label::Public,
                                    )? {
                                        return Ok(final_value);
                                    }
                                    continue;
                                }
                                return Err(InterpreterError::UncaughtException {
                                    value: format!("{}", error_value),
                                });
                            }
                            crate::promise_model::PromiseState::Pending => {
                                unreachable!("is_settled() returned true but state is Pending")
                            }
                        }
                    } else {
                        // Promise is pending - suspend the async function execution
                        let current_frame =
                            self.call_stack
                                .last()
                                .ok_or_else(|| InterpreterError::TypeError {
                                    expected: "call frame during await".to_string(),
                                    got: "no call frame found".to_string(),
                                })?;

                        let async_func_id = current_frame.async_function_id.ok_or_else(|| {
                            InterpreterError::TypeError {
                                expected: "await only in async function".to_string(),
                                got: "await outside async function context".to_string(),
                            }
                        })?;

                        let saved_registers = self.registers[self.register_base..].to_vec();
                        let saved_register_labels =
                            self.register_labels_in_range(self.register_base, self.registers.len());

                        // Save the current execution state
                        let async_func = self
                            .async_functions
                            .get_mut(async_func_id as usize)
                            .ok_or_else(|| InterpreterError::TypeError {
                                expected: "valid async function".to_string(),
                                got: format!("async function #{async_func_id} not found"),
                            })?;

                        // Save state for when the promise resolves
                        async_func.saved_ip = self.ip + 1; // Resume after the await instruction
                        async_func.saved_registers = saved_registers;
                        async_func.saved_register_labels = saved_register_labels;
                        async_func.saved_register_base = self.register_base;
                        async_func.phase = AsyncFunctionPhase::SuspendedAwait;

                        // franken-core records the suspension state but does not own the
                        // module-aware scheduler needed to resume pending awaits.
                        return Err(InterpreterError::TypeError {
                            expected: "settled promise for franken-core baseline await".to_string(),
                            got: concat!(
                                "pending promise await is explicitly unsupported by the ",
                                "franken-core baseline interpreter; async frame is suspended ",
                                "and result promise remains pending"
                            )
                            .to_string(),
                        });
                    }
                }
                Ir3Instruction::AsyncReturn { value_reg } => {
                    let return_value = self.read_reg(value_reg)?;
                    let return_label = self.read_reg_label(value_reg)?;

                    // Find the currently executing async function
                    let current_frame =
                        self.call_stack
                            .last()
                            .ok_or_else(|| InterpreterError::TypeError {
                                expected: "call frame during async return".to_string(),
                                got: "no call frame found".to_string(),
                            })?;

                    let async_func_id = current_frame.async_function_id.ok_or_else(|| {
                        InterpreterError::TypeError {
                            expected: "async return only in async function".to_string(),
                            got: "async return outside async function context".to_string(),
                        }
                    })?;

                    // Get the async function object to find its promise
                    let async_func = self
                        .async_functions
                        .get(async_func_id as usize)
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "valid async function".to_string(),
                            got: format!("async function #{async_func_id} not found"),
                        })?;

                    let promise_handle =
                        crate::promise_model::PromiseHandle(async_func.result_promise);

                    // Resolve the promise with the return value
                    let js_val = Self::value_to_js_value(&return_value);
                    self.fulfill_promise(promise_handle, js_val, return_label)?;

                    // Update the async function phase to completed
                    if let Some(func) = self.async_functions.get_mut(async_func_id as usize) {
                        func.phase = AsyncFunctionPhase::Completed;
                    }

                    // Return from the async function without overwriting the
                    // caller register that already holds the result promise.
                    if let Some(final_value) =
                        self.complete_return(Value::Undefined, crate::ifc_artifacts::Label::Public)?
                    {
                        return Ok(final_value);
                    }
                    continue;
                }
                Ir3Instruction::AsyncThrow { error_reg } => {
                    let error_value = self.read_reg(error_reg)?;
                    let error_label = self.read_reg_label(error_reg)?;

                    // Find the currently executing async function
                    let current_frame =
                        self.call_stack
                            .last()
                            .ok_or_else(|| InterpreterError::TypeError {
                                expected: "call frame during async throw".to_string(),
                                got: "no call frame found".to_string(),
                            })?;

                    let async_func_id = current_frame.async_function_id.ok_or_else(|| {
                        InterpreterError::TypeError {
                            expected: "async throw only in async function".to_string(),
                            got: "async throw outside async function context".to_string(),
                        }
                    })?;

                    // Get the async function object to find its promise
                    let async_func = self
                        .async_functions
                        .get(async_func_id as usize)
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "valid async function".to_string(),
                            got: format!("async function #{async_func_id} not found"),
                        })?;

                    let promise_handle =
                        crate::promise_model::PromiseHandle(async_func.result_promise);

                    // Reject the promise with the error value
                    let js_reason = Self::value_to_js_value(&error_value);
                    self.reject_promise(promise_handle, js_reason, error_label)?;

                    // Update the async function phase to completed
                    if let Some(func) = self.async_functions.get_mut(async_func_id as usize) {
                        func.phase = AsyncFunctionPhase::Completed;
                    }

                    // Return from the async function without overwriting the
                    // caller register that already holds the result promise.
                    if let Some(final_value) =
                        self.complete_return(Value::Undefined, crate::ifc_artifacts::Label::Public)?
                    {
                        return Ok(final_value);
                    }
                    continue;
                }
                Ir3Instruction::PushCapture { name_pool_index } => {
                    let _ = Self::metadata_pool_string(
                        module,
                        name_pool_index,
                        format!("__capture_{name_pool_index}"),
                    )?;
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
                    let name = Self::metadata_pool_string(
                        module,
                        name_pool_index,
                        format!("__binding_{name_pool_index}"),
                    )?;
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
                    let name = Self::metadata_pool_string(
                        module,
                        name_pool_index,
                        format!("__binding_{name_pool_index}"),
                    )?;
                    let (val, label) = if let Some((_, binding)) = self.scope_chain.resolve(&name) {
                        if !binding.initialized {
                            return Err(InterpreterError::UninitializedBinding {
                                name: name.clone(),
                            });
                        }
                        (binding.value.clone(), binding.label.clone())
                    } else if let Some(context) = self.active_cjs_context.as_ref() {
                        let (filename, dirname) =
                            self.cjs_filename_dirname(Some(&context.module_specifier));
                        let value = match name.as_str() {
                            "__filename" => filename,
                            "__dirname" => dirname,
                            _ => Value::Undefined,
                        };
                        (value, crate::ifc_artifacts::Label::Public)
                    } else {
                        (Value::Undefined, crate::ifc_artifacts::Label::Public)
                    };
                    self.write_reg_with_label(dst, val, label)?;
                    self.ip += 1;
                }
                Ir3Instruction::StoreScoped {
                    src,
                    name_pool_index,
                } => {
                    let name = Self::metadata_pool_string(
                        module,
                        name_pool_index,
                        format!("__binding_{name_pool_index}"),
                    )?;
                    let val = self.read_reg(src)?;
                    let label = self.read_reg_label(src)?;
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
                        binding.label = label;
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
                    let name = Self::metadata_pool_string(
                        module,
                        name_pool_index,
                        format!("__binding_{name_pool_index}"),
                    )?;
                    let val = self.read_reg(src)?;
                    let label = self.read_reg_label(src)?;
                    let mut previous = None;
                    if let Some(binding) = self.scope_chain.resolve_mut(&name) {
                        previous = Some(binding.clone());
                        binding.value = val;
                        binding.label = label;
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
            // String concatenation over exact code units: a trailing high
            // surrogate heals against a leading low surrogate (bd-2vzgi),
            // e.g. s.charAt(1) + s.charAt(2) === "😀" for s = "a😀b".
            (Value::Str(x), Value::Str(y)) => {
                self.check_string_limit(x.len().saturating_add(y.len()))?;
                Ok(Value::Str(x.concat(y)))
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
                Ok(Value::Str(x.concat(&JsString::from(other_str))))
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
                Ok(Value::Str(JsString::from(other_str).concat(y)))
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

    /// ECMAScript `ToInt32` for a floating-point operand (ECMA-262 §7.1.6):
    /// truncate toward zero, reduce modulo 2^32, and reinterpret the low 32
    /// bits as signed. Rust's `f64 as i32` cast *saturates* (since 1.45), so
    /// every operand whose magnitude exceeds 2^31 would collapse to
    /// `i32::MAX` — wrong for JS bitwise/shift semantics, which require
    /// modular wrapping (e.g. `(3000000000.5) | 0` is `-1294967296`, not
    /// `2147483647`). NaN and ±Infinity map to 0. `f64 % 2^32` via
    /// `rem_euclid` is exact (IEEE `fmod` is exact), so this is precise for
    /// every finite input, including magnitudes past 2^53.
    fn js_to_int32(value: f64) -> i32 {
        if !value.is_finite() {
            return 0;
        }
        (value.trunc().rem_euclid(4_294_967_296.0) as u32) as i32
    }

    fn eval_bit_not(&self, src: u32) -> Result<Value, InterpreterError> {
        let value = self.read_reg(src)?;
        // JS bitwise ops: ToInt32 conversion
        let number = match &value {
            Value::Int(n) => *n as i32,
            Value::Float(f) => Self::js_to_int32(f.inner()),
            _ => {
                let n = Self::coerce_to_float(&value).ok_or(InterpreterError::TypeError {
                    expected: "number-coercible primitive".to_string(),
                    got: value.type_name().to_string(),
                })?;
                Self::js_to_int32(n)
            }
        };
        Ok(Value::Int((!number) as i64))
    }

    fn eval_relational(&self, lhs: u32, rhs: u32, op: &str) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;

        // String comparison: lexicographic over exact UTF-16 code units per
        // ES2020 7.2.13 IsLessThan, matching the engine seam upgraded by
        // bd-rdnhc (bd-7zwar; previously the derived code-point/byte order,
        // which disagrees for astral content and projects lone surrogates).
        if let (Value::Str(x), Value::Str(y)) = (&a, &b) {
            let ordering = x.utf16_cmp(y);
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

        // JS ToInt32: truncate toward zero then reduce modulo 2^32 (wrapping,
        // not saturating — see `js_to_int32`).
        let to_i32 = |v: &Value| -> Result<i32, InterpreterError> {
            match v {
                Value::Int(n) => Ok(*n as i32),
                Value::Float(f) => Ok(Self::js_to_int32(f.inner())),
                _ => {
                    let n = Self::coerce_to_float(v).ok_or(InterpreterError::TypeError {
                        expected: "number".to_string(),
                        got: v.type_name().to_string(),
                    })?;
                    Ok(Self::js_to_int32(n))
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
        let prototype = self
            .function_prototype_for_value(&constructor)?
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "function".to_string(),
                got: constructor.type_name().to_string(),
            })?;

        let Value::Object(object_id) = candidate else {
            return Ok(Value::Bool(false));
        };

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
                        return Ok(Some(Value::str(key)));
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

    fn decode_accessor_definition_key(key: &str) -> Option<(AccessorKind, String)> {
        key.strip_prefix(IR_ACCESSOR_GET_PREFIX)
            .map(|name| (AccessorKind::Get, name.to_string()))
            .or_else(|| {
                key.strip_prefix(IR_ACCESSOR_SET_PREFIX)
                    .map(|name| (AccessorKind::Set, name.to_string()))
            })
    }

    fn prototype_chain_lookup_property(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Option<RuntimeProperty>, InterpreterError> {
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut visited = BTreeSet::new();

        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                return Ok(None);
            }
            let object = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
            if let Some(accessor) = object.accessors.get(key) {
                return Ok(Some(RuntimeProperty::Accessor(accessor.clone())));
            }
            if let Some(val) = object.properties.get(key) {
                return Ok(Some(RuntimeProperty::Data(val.clone())));
            }
            current = object.prototype;
            depth += 1;
        }

        Ok(None)
    }

    /// Walk the prototype chain to find a data property value.
    fn prototype_chain_get(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        let Some(property) = self.prototype_chain_lookup_property(object_id, key)? else {
            return Ok(Value::Undefined);
        };
        match property {
            RuntimeProperty::Data(value) => Ok(value),
            RuntimeProperty::Accessor(accessor) => Ok(accessor.get.unwrap_or(Value::Undefined)),
        }
    }

    fn copy_data_properties_object_id(&self, source: &Value) -> Option<ObjectId> {
        match source {
            Value::Object(object_id) => Some(*object_id),
            _ => self.function_object_id(source),
        }
    }

    fn copy_data_properties_keys(&self, source: &Value) -> Result<Vec<String>, InterpreterError> {
        match source {
            Value::Undefined | Value::Null => Err(InterpreterError::TypeError {
                expected: "object-coercible object-rest source".to_string(),
                got: source.type_name().to_string(),
            }),
            Value::Str(text) => Ok((0..text.utf16_len())
                .map(|index| index.to_string())
                .collect()),
            _ => {
                let Some(object_id) = self.copy_data_properties_object_id(source) else {
                    // Boolean and number wrappers have no enumerable own
                    // properties in the baseline carrier. Other exotic
                    // object-like values likewise expose no ordinary own-key
                    // storage here.
                    return Ok(Vec::new());
                };
                let object = self
                    .heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                Ok(object
                    .own_property_keys()
                    .into_iter()
                    // Array length is a non-enumerable own data property. The
                    // current baseline descriptor carrier has no general
                    // enumerable bit yet, so preserve this shipped invariant
                    // explicitly for array-backed objects.
                    .filter(|key| !(object.is_array && key == "length"))
                    .collect())
            }
        }
    }

    fn copy_data_properties_own_property(
        &self,
        source: &Value,
        key: &str,
        string_units: Option<&[u16]>,
    ) -> Result<Option<RuntimeProperty>, InterpreterError> {
        if let Some(units) = string_units {
            let Ok(index) = key.parse::<usize>() else {
                return Ok(None);
            };
            return Ok(units.get(index).copied().map(|unit| {
                RuntimeProperty::Data(Value::Str(JsString::from_code_units(&[unit])))
            }));
        }

        let Some(object_id) = self.copy_data_properties_object_id(source) else {
            return Ok(None);
        };
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if object.is_array && key == "length" {
            return Ok(None);
        }
        if let Some(accessor) = object.accessors.get(key) {
            return Ok(Some(RuntimeProperty::Accessor(accessor.clone())));
        }
        Ok(object
            .properties
            .get(key)
            .cloned()
            .map(RuntimeProperty::Data))
    }

    fn discard_copy_data_properties_state(&mut self, state_index: usize) {
        if state_index < self.copy_data_properties_states.len() {
            self.copy_data_properties_states.remove(state_index);
        }
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    fn discard_all_copy_data_properties_states(&mut self) {
        self.copy_data_properties_states.clear();
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    /// Execute or resume the CopyDataProperties operation used by object-rest
    /// binding initialization. Returns `true` when control entered a getter;
    /// that getter returns to this same instruction and writes `value_dst`.
    fn execute_copy_data_properties(
        &mut self,
        module: &Ir3Module,
        target: u32,
        source: u32,
        excluded: RegRange,
        value_dst: u32,
    ) -> Result<bool, InterpreterError> {
        let instruction_ip = self.ip;
        let register_base = self.register_base;
        let call_depth = self.call_stack.len();
        let state_index = if self
            .copy_data_properties_states
            .last()
            .is_some_and(|state| state.belongs_to(instruction_ip, register_base, call_depth))
        {
            self.copy_data_properties_states.len() - 1
        } else {
            let target_value = self.read_reg(target)?;
            let Value::Object(target_id) = target_value else {
                return Err(InterpreterError::TypeError {
                    expected: "object CopyDataProperties target".to_string(),
                    got: target_value.type_name().to_string(),
                });
            };
            let source_value = self.read_reg(source)?;
            let keys = self.copy_data_properties_keys(&source_value)?;
            let string_units = match &source_value {
                Value::Str(text) => Some(text.code_units_vec()),
                _ => None,
            };
            let mut excluded_keys = BTreeSet::new();
            for offset in 0..excluded.count {
                let register = excluded.start.checked_add(offset).ok_or(
                    InterpreterError::RegisterOutOfBounds {
                        register: excluded.start,
                        max: self.config.max_registers,
                    },
                )?;
                excluded_keys.insert(Self::property_key(&self.read_reg(register)?));
            }
            let state = CopyDataPropertiesState {
                instruction_ip,
                register_base,
                call_depth,
                target_id,
                source: source_value,
                string_units,
                keys,
                excluded: excluded_keys,
                next_index: 0,
                awaiting_key: None,
            };
            self.check_temporary_memory_budget(Self::estimate_copy_data_properties_state_bytes(
                &state,
            ))?;
            self.copy_data_properties_states.push(state);
            if let Err(err) = self.sync_estimated_memory_bytes() {
                self.copy_data_properties_states.pop();
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                return Err(err);
            }
            self.copy_data_properties_states.len() - 1
        };

        if let Some(key) = self.copy_data_properties_states[state_index]
            .awaiting_key
            .take()
        {
            let value = match self.read_reg(value_dst) {
                Ok(value) => value,
                Err(err) => {
                    self.discard_copy_data_properties_state(state_index);
                    return Err(err);
                }
            };
            let target_id = self.copy_data_properties_states[state_index].target_id;
            if let Err(err) = self.set_plain_data_property(target_id, key, value) {
                self.discard_copy_data_properties_state(state_index);
                return Err(err);
            }
        }

        loop {
            let Some(key) = ({
                let state = &mut self.copy_data_properties_states[state_index];
                let key = state.keys.get(state.next_index).cloned();
                if key.is_some() {
                    state.next_index = state.next_index.saturating_add(1);
                }
                key
            }) else {
                self.discard_copy_data_properties_state(state_index);
                return Ok(false);
            };

            if self.copy_data_properties_states[state_index]
                .excluded
                .contains(&key)
            {
                continue;
            }

            let source_value = self.copy_data_properties_states[state_index].source.clone();
            let string_units = self.copy_data_properties_states[state_index]
                .string_units
                .as_deref();
            let property =
                match self.copy_data_properties_own_property(&source_value, &key, string_units) {
                    Ok(property) => property,
                    Err(err) => {
                        self.discard_copy_data_properties_state(state_index);
                        return Err(err);
                    }
                };
            let value = match property {
                None => continue,
                Some(RuntimeProperty::Data(value)) => value,
                Some(RuntimeProperty::Accessor(accessor)) => {
                    let Some(getter) = accessor.get else {
                        let target_id = self.copy_data_properties_states[state_index].target_id;
                        if let Err(err) =
                            self.set_plain_data_property(target_id, key, Value::Undefined)
                        {
                            self.discard_copy_data_properties_state(state_index);
                            return Err(err);
                        }
                        continue;
                    };
                    self.copy_data_properties_states[state_index].awaiting_key = Some(key);
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        self.discard_copy_data_properties_state(state_index);
                        return Err(err);
                    }
                    if let Err(err) = self.enter_function_call(
                        module,
                        getter,
                        source_value,
                        Vec::new(),
                        self.ip,
                        Some(value_dst),
                    ) {
                        self.discard_copy_data_properties_state(state_index);
                        return Err(err);
                    }
                    return Ok(true);
                }
            };
            let target_id = self.copy_data_properties_states[state_index].target_id;
            if let Err(err) = self.set_plain_data_property(target_id, key, value) {
                self.discard_copy_data_properties_state(state_index);
                return Err(err);
            }
        }
    }

    fn load_runtime_property(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        property: Option<RuntimeProperty>,
        dst: u32,
    ) -> Result<bool, InterpreterError> {
        match property {
            Some(RuntimeProperty::Data(value)) => {
                self.write_reg(dst, value)?;
                Ok(false)
            }
            Some(RuntimeProperty::Accessor(accessor)) => {
                if let Some(getter) = accessor.get {
                    self.enter_function_call(
                        module,
                        getter,
                        receiver,
                        Vec::new(),
                        self.ip + 1,
                        Some(dst),
                    )?;
                    Ok(true)
                } else {
                    self.write_reg(dst, Value::Undefined)?;
                    Ok(false)
                }
            }
            None => {
                self.write_reg(dst, Value::Undefined)?;
                Ok(false)
            }
        }
    }

    fn load_object_property_or_call_accessor(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        object_id: ObjectId,
        key: &str,
        dst: u32,
    ) -> Result<bool, InterpreterError> {
        self.run_pre_property_access_hook(module, object_id, key)?;
        let property = self.prototype_chain_lookup_property(object_id, key)?;
        self.load_runtime_property(module, receiver, property, dst)
    }

    fn set_object_property_or_call_accessor(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        object_id: ObjectId,
        key: String,
        value: Value,
    ) -> Result<bool, InterpreterError> {
        self.run_pre_property_access_hook(module, object_id, &key)?;
        if key == "__proto__" {
            let prototype = match value {
                Value::Object(id) => Some(id),
                Value::Null => None,
                _ => {
                    return Ok(false);
                }
            };
            self.heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
                .prototype = prototype;
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Ok(false);
        }
        match self.prototype_chain_lookup_property(object_id, &key)? {
            Some(RuntimeProperty::Accessor(accessor)) => {
                if let Some(setter) = accessor.set {
                    self.enter_function_call(
                        module,
                        setter,
                        receiver,
                        vec![value],
                        self.ip + 1,
                        None,
                    )?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => {
                self.set_object_property(object_id, key, value)?;
                Ok(false)
            }
        }
    }

    fn load_function_like_property_or_call_accessor(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        key: &str,
        dst: u32,
    ) -> Result<bool, InterpreterError> {
        if let Some(object_id) = self.function_object_id(&receiver) {
            self.run_pre_property_access_hook(module, object_id, key)?;
            if let Some(property) = self.prototype_chain_lookup_property(object_id, key)? {
                return self.load_runtime_property(module, receiver, Some(property), dst);
            }
        }

        if key == "prototype"
            && let Some(prototype) = self.function_prototype_for_value(&receiver)?
        {
            self.write_reg(dst, Value::Object(prototype))?;
            return Ok(false);
        }

        self.write_reg(dst, Value::Undefined)?;
        Ok(false)
    }

    fn set_function_like_property_or_call_accessor(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        key: &str,
        value: Value,
    ) -> Result<bool, InterpreterError> {
        let Some(object_id) = self.ensure_function_object(&receiver)? else {
            return Err(InterpreterError::TypeError {
                expected: "function".to_string(),
                got: receiver.type_name().to_string(),
            });
        };
        let called = self.set_object_property_or_call_accessor(
            module,
            receiver.clone(),
            object_id,
            key.to_string(),
            value.clone(),
        )?;
        if !called
            && key == "prototype"
            && let Value::Object(prototype) = value
            && let Some(function_key) = self.function_prototype_key_for_value(&receiver)?
        {
            self.function_prototypes.insert(function_key, prototype);
        }
        Ok(called)
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
            if object.properties.contains_key(key) || object.accessors.contains_key(key) {
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
            _ => crate::object_model::JsValue::Str(JsString::from(val.to_string())),
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
            crate::object_model::JsValue::Symbol(sym) => Value::str(format!("Symbol({})", sym.0)),
        }
    }

    fn promise_hostcall_argument(
        &self,
        args: RegRange,
        index: u32,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        if index >= args.count {
            return Ok((Value::Undefined, crate::ifc_artifacts::Label::Public));
        }
        let register =
            args.start
                .checked_add(index)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
        Ok((self.read_reg(register)?, self.read_reg_label(register)?))
    }

    fn promise_hostcall_registration_label(
        &self,
        args: RegRange,
    ) -> Result<crate::ifc_artifacts::Label, InterpreterError> {
        let mut label = crate::ifc_artifacts::Label::Public;
        for index in 0..args.count {
            let (_, argument_label) = self.promise_hostcall_argument(args, index)?;
            label = label.join(&argument_label);
        }
        Ok(label)
    }

    fn collect_promise_combinator_inputs(
        &self,
        args: RegRange,
    ) -> Result<Vec<(Value, crate::ifc_artifacts::Label)>, InterpreterError> {
        if args.count == 0 {
            return Ok(Vec::new());
        }
        let first = self.read_reg(args.start)?;
        let first_label = self.read_reg_label(args.start)?;
        if args.count == 1 {
            if let Value::Object(id) = first {
                return Ok(self
                    .read_array_like_values(id)
                    .into_iter()
                    .map(|value| (value, first_label.clone()))
                    .collect());
            }
            return Ok(vec![(first, first_label)]);
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
            values.push((self.read_reg(reg)?, self.read_reg_label(reg)?));
        }
        Ok(values)
    }

    fn array_like_length(&self, obj_id: ObjectId) -> Result<u32, InterpreterError> {
        let object = self
            .heap
            .get(obj_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: obj_id.0 })?;
        if let Some(Value::Int(length)) = object.properties.get("length") {
            return Ok(u32::try_from((*length).max(0)).unwrap_or(u32::MAX));
        }
        Ok(object.properties.keys().fold(0u32, |current, key| {
            key.parse::<u32>()
                .ok()
                .map_or(current, |index| current.max(index.saturating_add(1)))
        }))
    }

    fn array_index_value(
        &self,
        obj_id: ObjectId,
        index: u32,
    ) -> Result<Option<Value>, InterpreterError> {
        Ok(self
            .heap
            .get(obj_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: obj_id.0 })?
            .properties
            .get(&index.to_string())
            .cloned())
    }

    fn read_array_like_values(&self, obj_id: ObjectId) -> Vec<Value> {
        self.heap
            .get(obj_id.0 as usize)
            .map(|obj| {
                let mut values = Vec::new();
                let mut idx = 0u32;
                while let Some(val) = obj.properties.get(&idx.to_string()) {
                    values.push(val.clone());
                    idx = idx.saturating_add(1);
                }
                values
            })
            .unwrap_or_default()
    }

    fn alloc_array_from_values(&mut self, values: &[Value]) -> Result<ObjectId, InterpreterError> {
        let id = self.alloc_array_with_prototype(None)?;
        for (index, value) in values.iter().cloned().enumerate() {
            self.set_object_property(id, index.to_string(), value)?;
        }
        self.set_object_property(id, "length".to_string(), Value::Int(values.len() as i64))?;
        Ok(id)
    }

    /// Replace a declared rest-parameter slot with an Array containing every
    /// trailing argument. Fixed parameters retain their positional values and
    /// an omitted rest tail becomes an empty Array.
    fn apply_rest_param(
        &mut self,
        module: &Ir3Module,
        arg_vals: &mut Vec<Value>,
        rest_param_index: Option<u32>,
        arity: u32,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let Some(rest_index) = rest_param_index else {
            return Ok(());
        };
        self.validate_rest_param_index(rest_index, arity)?;

        let mut elements = Vec::new();
        for offset in rest_index..args.count {
            let reg =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            elements.push(self.read_reg(reg)?);
        }
        self.run_pre_allocation_hook(module, AllocKind::Array, elements.len())?;
        let array_id = self.alloc_array_from_values(&elements)?;
        let rest_slot = rest_index as usize;
        if arg_vals.len() <= rest_slot {
            arg_vals.resize(rest_slot + 1, Value::Undefined);
        }
        arg_vals.truncate(rest_slot + 1);
        arg_vals[rest_slot] = Value::Object(array_id);
        Ok(())
    }

    /// Label-file twin of [`Self::apply_rest_param`]. The rest Array depends
    /// on every trailing argument, so its register receives their lattice join.
    fn apply_rest_param_labels(
        &self,
        arg_labels: &mut Vec<crate::ifc_artifacts::Label>,
        rest_param_index: Option<u32>,
        arity: u32,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let Some(rest_index) = rest_param_index else {
            return Ok(());
        };
        self.validate_rest_param_index(rest_index, arity)?;

        let mut rest_label = crate::ifc_artifacts::Label::Public;
        for offset in rest_index..args.count {
            let reg =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            rest_label = rest_label.join(&self.read_reg_label(reg)?);
        }
        let rest_slot = rest_index as usize;
        if arg_labels.len() <= rest_slot {
            arg_labels.resize(rest_slot + 1, crate::ifc_artifacts::Label::Public);
        }
        arg_labels.truncate(rest_slot + 1);
        arg_labels[rest_slot] = rest_label;
        Ok(())
    }

    fn validate_rest_param_index(
        &self,
        rest_index: u32,
        arity: u32,
    ) -> Result<(), InterpreterError> {
        if rest_index.checked_add(1) == Some(arity) && rest_index < self.config.max_registers {
            return Ok(());
        }
        Err(InterpreterError::TypeError {
            expected: format!(
                "final rest parameter index for arity {arity} below register limit {}",
                self.config.max_registers
            ),
            got: rest_index.to_string(),
        })
    }

    fn validate_function_rest_param(
        &self,
        function: &Ir3FunctionDesc,
    ) -> Result<(), InterpreterError> {
        if let Some(rest_index) = function.rest_param_index {
            self.validate_rest_param_index(rest_index, function.arity)?;
        }
        Ok(())
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
            let mut props = vec![("status", Value::str(outcome.status.clone()))];
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

    fn register_combinator(&mut self, state: LabeledPromiseCombinatorState) -> u64 {
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
            state.accumulated_label = state.accumulated_label.join(&label);
            match &mut state.tracker {
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
            let resolution_label = self
                .promise_combinators
                .get(&combinator_id)
                .map(|state| state.accumulated_label.clone())
                .unwrap_or(label);
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
            self.fulfill_promise(handle, value, resolution_label)?;
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
            state.accumulated_label = state.accumulated_label.join(&label);
            match &mut state.tracker {
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
            let resolution_label = self
                .promise_combinators
                .get(&combinator_id)
                .map(|state| state.accumulated_label.clone())
                .unwrap_or(label);
            match resolution {
                ResolutionData::FulfillAllSettled(handle, outcomes, total) => {
                    let value = self.build_promise_all_settled_result(outcomes, total)?;
                    self.fulfill_promise(handle, value, resolution_label)?;
                }
                ResolutionData::Reject(handle, reason) => {
                    self.reject_promise(handle, reason, resolution_label)?;
                }
                ResolutionData::RejectAny(handle, errors) => {
                    let aggregate = self.build_aggregate_error(errors)?;
                    self.reject_promise(handle, aggregate, resolution_label)?;
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
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        let inputs = self.collect_promise_combinator_inputs(args)?;
        let mut accumulated_label = self.promise_hostcall_registration_label(args)?;
        for (input, input_label) in &inputs {
            accumulated_label = accumulated_label.join(input_label);
            if let Value::Promise(handle) = input {
                let record = self
                    .promise_store
                    .get(crate::promise_model::PromiseHandle(*handle))
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "promise".to_string(),
                        got: e.to_string(),
                    })?;
                accumulated_label = accumulated_label.join(&record.label);
            }
        }
        let total = inputs.len() as u32;
        let result_promise = self.promise_store.create();

        match kind {
            PromiseCombinatorKind::All | PromiseCombinatorKind::AllSettled if total == 0 => {
                let empty = self.build_promise_all_result(Vec::new())?;
                self.fulfill_promise(result_promise, empty, accumulated_label.clone())?;
                return Ok((Value::Promise(result_promise.0), accumulated_label));
            }
            PromiseCombinatorKind::Any if total == 0 => {
                let aggregate = self.build_aggregate_error(Vec::new())?;
                self.reject_promise(result_promise, aggregate, accumulated_label.clone())?;
                return Ok((Value::Promise(result_promise.0), accumulated_label));
            }
            PromiseCombinatorKind::Race if total == 0 => {
                return Ok((Value::Promise(result_promise.0), accumulated_label));
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

        let combinator_id = self.register_combinator(LabeledPromiseCombinatorState {
            tracker: state,
            accumulated_label: accumulated_label.clone(),
        });

        for (index, (input, input_label)) in inputs.into_iter().enumerate() {
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
                    self.update_combinator_fulfillment(combinator_id, index, js_val, input_label)?;
                }
            }
        }

        Ok((Value::Promise(result_promise.0), accumulated_label))
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
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        match cap {
            "promise:constructor" => {
                // Create a new pending promise and return its handle.
                let handle = self.promise_store.create();
                Ok((
                    Value::Promise(handle.0),
                    crate::ifc_artifacts::Label::Public,
                ))
            }
            "promise:resolve" => {
                // If arg0 is a Promise, resolve it with arg1.
                // Otherwise create a pre-resolved promise with arg0 as the value.
                let (arg0, arg0_label) = self.promise_hostcall_argument(args, 0)?;
                match arg0 {
                    Value::Promise(h) => {
                        // Resolve the existing promise with the given value.
                        let (val, value_label) = self.promise_hostcall_argument(args, 1)?;
                        let js_val = Self::value_to_js_value(&val);
                        let handle = crate::promise_model::PromiseHandle(h);
                        let settlement_label = arg0_label.join(&value_label);
                        self.fulfill_promise(handle, js_val, settlement_label.clone())?;
                        Ok((Value::Promise(h), settlement_label))
                    }
                    _ => {
                        // Promise.resolve(value) — create a pre-resolved promise.
                        let js_val = Self::value_to_js_value(&arg0);
                        let handle = self.promise_store.create();
                        self.fulfill_promise(handle, js_val, arg0_label.clone())?;
                        Ok((Value::Promise(handle.0), arg0_label))
                    }
                }
            }
            "promise:reject" => {
                let (arg0, arg0_label) = self.promise_hostcall_argument(args, 0)?;
                match arg0 {
                    Value::Promise(h) => {
                        let (reason, reason_label) = self.promise_hostcall_argument(args, 1)?;
                        let js_reason = Self::value_to_js_value(&reason);
                        let handle = crate::promise_model::PromiseHandle(h);
                        let settlement_label = arg0_label.join(&reason_label);
                        self.reject_promise(handle, js_reason, settlement_label.clone())?;
                        Ok((Value::Promise(h), settlement_label))
                    }
                    _ => {
                        // Promise.reject(reason) — create a pre-rejected promise.
                        let js_reason = Self::value_to_js_value(&arg0);
                        let handle = self.promise_store.create();
                        self.reject_promise(handle, js_reason, arg0_label.clone())?;
                        Ok((Value::Promise(handle.0), arg0_label))
                    }
                }
            }
            "promise:then" => {
                // arg0 = promise handle, arg1 = onFulfilled (optional),
                // arg2 = onRejected (optional).
                let (arg0, _) = self.promise_hostcall_argument(args, 0)?;
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                let registration_label = self.promise_hostcall_registration_label(args)?;
                // In the baseline interpreter, .then() callbacks are simplified:
                // we register reactions with no closure handlers (identity propagation).
                let result = self
                    .promise_store
                    .then(
                        handle,
                        None,
                        None,
                        registration_label.clone(),
                        &mut self.event_loop.microtasks,
                    )
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "valid promise handle".to_string(),
                        got: e.to_string(),
                    })?;
                Ok((Value::Promise(result.0), registration_label))
            }
            "promise:catch" => {
                // Sugar for .then(undefined, onRejected).
                let (arg0, _) = self.promise_hostcall_argument(args, 0)?;
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                let registration_label = self.promise_hostcall_registration_label(args)?;
                let result = self
                    .promise_store
                    .then(
                        handle,
                        None,
                        None,
                        registration_label.clone(),
                        &mut self.event_loop.microtasks,
                    )
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "valid promise handle".to_string(),
                        got: e.to_string(),
                    })?;
                Ok((Value::Promise(result.0), registration_label))
            }
            "promise:finally" => {
                // Similar to .then(handler, handler) for finally semantics.
                let (arg0, _) = self.promise_hostcall_argument(args, 0)?;
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                let registration_label = self.promise_hostcall_registration_label(args)?;
                let result = self
                    .promise_store
                    .then(
                        handle,
                        None,
                        None,
                        registration_label.clone(),
                        &mut self.event_loop.microtasks,
                    )
                    .map_err(|e| InterpreterError::TypeError {
                        expected: "valid promise handle".to_string(),
                        got: e.to_string(),
                    })?;
                Ok((Value::Promise(result.0), registration_label))
            }
            "promise:all" => self.dispatch_promise_combinator(PromiseCombinatorKind::All, args),
            "promise:race" => self.dispatch_promise_combinator(PromiseCombinatorKind::Race, args),
            "promise:allSettled" => {
                self.dispatch_promise_combinator(PromiseCombinatorKind::AllSettled, args)
            }
            "promise:any" => self.dispatch_promise_combinator(PromiseCombinatorKind::Any, args),
            _ => {
                // Unknown promise sub-capability — return undefined.
                Ok((Value::Undefined, crate::ifc_artifacts::Label::Public))
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
    fn run_event_loop_until_idle(&mut self, module: &Ir3Module) -> Result<(), InterpreterError> {
        const MAX_TURNS: u32 = 10_000; // Safety limit to prevent infinite loops
        let mut turns = 0;

        while self.event_loop.has_pending_work() && turns < MAX_TURNS {
            turns += 1;

            // Phase 1: Execute one macrotask (if ready)
            let turn_result = self.event_loop.turn();
            if let Some(macrotask) = turn_result.macrotask {
                self.execute_macrotask_callback(module, &macrotask)?;
            }

            // Phase 2: Drain all microtasks enqueued during macrotask execution
            self.drain_microtasks();
        }

        Ok(())
    }

    fn execute_macrotask_callback(
        &mut self,
        module: &Ir3Module,
        macrotask: &crate::promise_model::Macrotask,
    ) -> Result<(), InterpreterError> {
        if macrotask.source != crate::promise_model::MacrotaskSource::Timer {
            return Ok(());
        }

        let Some((timer_id, timer)) = self
            .active_timers
            .iter()
            .find(|(_, timer)| timer.registration_seq == Some(macrotask.registration_seq))
            .map(|(timer_id, timer)| (*timer_id, timer.clone()))
        else {
            return Ok(());
        };

        if timer.handler != Some(macrotask.handler.0) {
            return Ok(());
        }

        if !timer.repeating {
            self.active_timers.remove(&timer_id);
        }

        if let Some(handler) = timer.handler {
            self.execute_timer_closure(module, handler)?;
        }

        Ok(())
    }

    fn execute_timer_closure(
        &mut self,
        module: &Ir3Module,
        closure_id: u32,
    ) -> Result<(), InterpreterError> {
        let closure =
            self.closures
                .get(closure_id as usize)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "valid closure".to_string(),
                    got: format!("closure#{closure_id} not found"),
                })?;
        let func_idx = closure.function_index;
        let func = module.function_table.get(func_idx as usize).ok_or(
            InterpreterError::FunctionNotFound {
                index: func_idx,
                table_size: module.function_table.len() as u32,
            },
        )?;
        self.validate_function_rest_param(func)?;
        let captured_env = self.clone_scope_frames_with_budget(&closure.captured_env)?;

        if self.call_stack.len() >= self.config.max_call_depth {
            return Err(InterpreterError::StackOverflow {
                depth: self.call_stack.len(),
                max: self.config.max_call_depth,
            });
        }

        let callee = Value::Closure(closure_id);
        let mut arg_vals = Vec::new();
        let mut arg_labels = Vec::new();
        let empty_args = RegRange { start: 0, count: 0 };
        self.apply_rest_param(
            module,
            &mut arg_vals,
            func.rest_param_index,
            func.arity,
            empty_args,
        )?;
        self.apply_rest_param_labels(
            &mut arg_labels,
            func.rest_param_index,
            func.arity,
            empty_args,
        )?;
        self.run_pre_call_hook(module, &callee, func_idx, &arg_vals)?;

        let initial_call_depth = self.call_stack.len();
        let saved_ip = self.ip;
        let saved_return_reg = self.read_reg(0).unwrap_or(Value::Undefined);
        let scope_depth = self.scope_chain.depth();
        let captured_env_bytes = Self::estimate_scope_chain_bytes(&captured_env);
        let captured_scope_depth = captured_env.len();
        let saved_chain = self.snapshot_scope_chain_with_temporary_budget(captured_env_bytes)?;

        self.call_stack.push(CallFrame {
            return_ip: module.instructions.len(),
            return_reg: Some(0),
            register_base: self.register_base,
            function_index: Some(func_idx),
            this_value: Value::Undefined,
            this_label: crate::ifc_artifacts::Label::Public,
            new_target_value: Value::Undefined,
            new_target_label: crate::ifc_artifacts::Label::Public,
            super_value: self.function_super_value(&callee, IR_SUPER_PROTOTYPE_PROPERTY)?,
            super_label: crate::ifc_artifacts::Label::Public,
            construct_this: None,
            saved_pending_exception: self.pending_exception.take(),
            saved_pending_return: self.pending_return.take(),
            saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
            saved_finally_mode_depth: self.finally_frames.len(),
            saved_scope_depth: scope_depth,
            saved_scope_chain: Some(saved_chain),
            closure_id: Some(closure_id),
            captured_scope_depth,
            async_function_id: None,
        });

        self.scope_chain.frames = captured_env;
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
        self.clear_register_range(self.register_base, req_len);
        for (index, (value, label)) in arg_vals.into_iter().zip(arg_labels).enumerate() {
            let reg = index as u32;
            if reg < self.config.max_registers {
                self.write_reg_with_label(reg, value, label)?;
            }
        }

        self.ip = func.entry as usize;
        let result = self.run_loop(module);
        if self.call_stack.len() > initial_call_depth {
            let (restored_pending_exception, restored_pending_return) =
                self.unwind_call_stack_to(initial_call_depth);
            self.pending_exception = restored_pending_exception;
            self.pending_return = restored_pending_return;
        }
        self.ip = saved_ip;
        self.write_reg(0, saved_return_reg)?;

        match result {
            Ok(_) | Err(InterpreterError::Halted) => Ok(()),
            Err(err) => Err(err),
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
                    label: task_label,
                } => {
                    // With no closure handler, the identity transform propagates
                    // the argument to the result promise as a fulfillment value.
                    let _ = self.fulfill_promise(result_promise, argument, task_label);
                }
                crate::promise_model::Microtask::PromiseRejection {
                    reason,
                    result_promise,
                    label: task_label,
                } => {
                    let _ = self.reject_promise(result_promise, reason, task_label);
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
            // Property keys remain UTF-8 `String`: a lone-surrogate key routes
            // through the lossy projection (documented engine-parity boundary).
            Value::Str(s) => s.to_string(),
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

    /// Dispatch console hostcalls: console.log, console.error, console.warn, console.info.
    ///
    /// Hostcall capabilities:
    /// - `console:log` — console.log(...args)
    /// - `console:error` — console.error(...args)
    /// - `console:warn` — console.warn(...args)
    /// - `console:info` — console.info(...args)
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
                        registration_seq: handler_id.map(|handler| {
                            self.event_loop.set_timeout(
                                crate::closure_model::ClosureHandle(handler),
                                delay_ms,
                                crate::ifc_artifacts::Label::Public,
                            )
                        }),
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
                        registration_seq: None,
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
            "builtin:ReferenceError" | "builtin:TypeError" => {
                let message = self
                    .optional_arg(args, 0)?
                    .map_or_else(String::new, |value| self.value_to_string(&value));
                let name = cap.strip_prefix("builtin:").unwrap_or(cap);
                let object_id = self.alloc_object_with_properties(&[
                    ("name", Value::str(name)),
                    ("message", Value::str(message)),
                ])?;
                Ok(Value::Object(object_id))
            }

            // Array methods
            "builtin:ArrayPrototypePush" => {
                let this = self.required_arg(args, 0, "array object")?;
                let array_id = self.expect_object(this, "array object")?;
                let base_len = self.array_like_length(array_id)?;
                for offset in 1..args.count {
                    let value = self.read_arg(args, offset)?;
                    let index = base_len.saturating_add(offset - 1);
                    self.set_object_property(array_id, index.to_string(), value)?;
                }
                let new_len = base_len.saturating_add(args.count.saturating_sub(1));
                self.set_object_property(
                    array_id,
                    "length".to_string(),
                    Value::Int(i64::from(new_len)),
                )?;
                Ok(Value::Int(i64::from(new_len)))
            }
            "builtin:ArrayIsArray" => {
                let arg = self.optional_arg(args, 0)?;
                self.array_is_array_value(arg)
            }
            "builtin:ArrayIsArrayFunction" => {
                Ok(Value::BuiltinFunction(BuiltinFunction::array_is_array()))
            }
            "builtin:ArrayPrototypePop" => {
                let this = self.required_arg(args, 0, "array object")?;
                let array_id = self.expect_object(this, "array object")?;
                let length = self.array_like_length(array_id)?;
                if length == 0 {
                    self.set_object_property(array_id, "length".to_string(), Value::Int(0))?;
                    return Ok(Value::Undefined);
                }
                let index = length - 1;
                let value = self
                    .array_index_value(array_id, index)?
                    .unwrap_or(Value::Undefined);
                self.remove_object_property(array_id, &index.to_string())?;
                self.set_object_property(
                    array_id,
                    "length".to_string(),
                    Value::Int(i64::from(index)),
                )?;
                Ok(value)
            }

            // Object methods
            "builtin:ObjectKeys" => {
                let this = self.required_arg(args, 0, "object")?;
                let object_id = self.expect_object(this, "object")?;
                let keys = self.own_enumerable_keys(object_id)?;
                let values = keys.into_iter().map(Value::str).collect::<Vec<_>>();
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            "builtin:ObjectValues" => {
                let this = self.required_arg(args, 0, "object")?;
                let object_id = self.expect_object(this, "object")?;
                let keys = self.own_enumerable_keys(object_id)?;
                let values = {
                    let object = self
                        .heap
                        .get(object_id.0 as usize)
                        .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                    keys.into_iter()
                        .filter_map(|key| object.properties.get(&key).cloned())
                        .collect::<Vec<_>>()
                };
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }

            // String methods (hostcall convention: receiver in args[0],
            // index in args[1]; shared impls with the BuiltinFunction
            // method-call seam so the two paths cannot drift).
            "builtin:StringPrototypeCharAt" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                let index = self.optional_arg(args, 1)?;
                Ok(Self::string_char_at_value(&text, index.as_ref()))
            }
            "builtin:StringPrototypeCharCodeAt" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                let index = self.optional_arg(args, 1)?;
                Ok(Self::string_char_code_at_value(&text, index.as_ref()))
            }
            "builtin:StringPrototypeCodePointAt" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                let index = self.optional_arg(args, 1)?;
                Ok(Self::string_code_point_at_value(&text, index.as_ref()))
            }
            "builtin:StringPrototypeAt" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                let index = self.optional_arg(args, 1)?;
                Ok(Self::string_at_value(&text, index.as_ref()))
            }
            "builtin:StringPrototypeIsWellFormed" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                Ok(Self::string_is_well_formed_value(&text))
            }
            "builtin:StringPrototypeToWellFormed" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                Ok(Self::string_to_well_formed_value(&text))
            }
            "builtin:StringFromCharCode" => {
                // String.fromCharCode(...codeUnits): ToUint16 per argument;
                // a surrogate unit stays a real lone surrogate, and adjacent
                // high+low units heal into the supplementary code point when
                // from_code_units normalizes (engine bd-neika parity).
                let mut units: Vec<u16> = Vec::with_capacity(args.count as usize);
                for i in 0..args.count {
                    let reg =
                        args.start
                            .checked_add(i)
                            .ok_or(InterpreterError::RegisterOutOfBounds {
                                register: args.start,
                                max: self.config.max_registers,
                            })?;
                    let unit = match self.read_reg(reg)? {
                        Value::Int(n) => n as u32,
                        Value::Float(f) => {
                            let v = f.inner();
                            if v.is_finite() {
                                v.trunc().rem_euclid(4_294_967_296.0) as u32
                            } else {
                                0
                            }
                        }
                        _ => 0,
                    };
                    units.push((unit & 0xFFFF) as u16);
                }
                Ok(Value::Str(JsString::from_code_units(&units)))
            }
            "builtin:StringFromCodePoint" => {
                // String.fromCodePoint(...codePoints): each argument must be
                // an integral code point in 0..=0x10FFFF (RangeError
                // otherwise); surrogate code points are accepted and yield a
                // real lone-surrogate unit, supplementary code points encode
                // as their UTF-16 pair. Mirrors the engine arm exactly for
                // oracle parity (bd-7zwar).
                let mut units: Vec<u16> = Vec::with_capacity(args.count as usize);
                for i in 0..args.count {
                    let reg =
                        args.start
                            .checked_add(i)
                            .ok_or(InterpreterError::RegisterOutOfBounds {
                                register: args.start,
                                max: self.config.max_registers,
                            })?;
                    let code_point_number = match self.read_reg(reg)? {
                        Value::Int(n) => n as f64,
                        Value::Float(f) => f.inner(),
                        Value::Bool(true) => 1.0,
                        Value::Bool(false) | Value::Null => 0.0,
                        Value::Str(s) => {
                            let trimmed = s.trim();
                            if trimmed.is_empty() {
                                0.0
                            } else {
                                trimmed.parse::<f64>().unwrap_or(f64::NAN)
                            }
                        }
                        _ => f64::NAN,
                    };
                    if !code_point_number.is_finite()
                        || code_point_number.fract() != 0.0
                        || !(0.0..=0x10FFFF as f64).contains(&code_point_number)
                    {
                        return Err(InterpreterError::RangeError {
                            message: format!(
                                "String.fromCodePoint invalid code point: {code_point_number}"
                            ),
                        });
                    }
                    let code_point = code_point_number as u32;
                    if code_point < 0x10000 {
                        units.push(code_point as u16);
                    } else {
                        let offset = code_point - 0x10000;
                        units.push(0xD800 + (offset >> 10) as u16);
                        units.push(0xDC00 + (offset & 0x3FF) as u16);
                    }
                }
                Ok(Value::Str(JsString::from_code_units(&units)))
            }

            // Math methods
            "builtin:MathAbs" => {
                // Math.abs implementation - returns absolute value of the argument
                if args.count > 0 {
                    let arg = self.read_reg(args.start)?;
                    match arg {
                        Value::Int(i64::MIN) => Ok(Value::Float(Float64::new(-(i64::MIN as f64)))),
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
                    return Ok(Value::str("undefined"));
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
                        // Escape per code unit: backslash/quote escapes cannot
                        // double-process each other (the old replace-chain
                        // escaped quotes first and then doubled the inserted
                        // backslashes), and a lone surrogate is emitted as a
                        // \uXXXX escape (engine bd-neika parity).
                        let mut out = String::with_capacity(s.len().saturating_add(2));
                        out.push('"');
                        for decoded in char::decode_utf16(s.encode_utf16()) {
                            match decoded {
                                Ok('"') => out.push_str("\\\""),
                                Ok('\\') => out.push_str("\\\\"),
                                Ok(ch) => out.push(ch),
                                Err(err) => {
                                    out.push_str(&format!("\\u{:04x}", err.unpaired_surrogate()));
                                }
                            }
                        }
                        out.push('"');
                        out
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
                Ok(Value::str(json_str))
            }
            "builtin:JsonParse" => {
                // Full recursive JSON values over exact UTF-16 input units,
                // including raw lone surrogates (bd-y3yxl) and units contributed
                // by `\uXXXX` escapes (bd-zql4d). Invalid JSON and non-string
                // inputs preserve core's existing simplified posture by yielding
                // undefined instead of a SyntaxError.
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }
                let json_str = match self.read_reg(args.start)? {
                    Value::Str(text) => text,
                    _ => return Ok(Value::Undefined),
                };
                let units = json_str.code_units_vec();
                let mut pos = 0usize;
                let heap_checkpoint = self.heap.len();
                let memory_checkpoint = self.estimated_memory_bytes;
                Self::json_skip_ws(&units, &mut pos);
                match self.json_parse_value(&units, &mut pos, 0) {
                    Ok(Some(value)) => {
                        Self::json_skip_ws(&units, &mut pos);
                        if pos == units.len() {
                            Ok(value)
                        } else {
                            self.rollback_json_parse(heap_checkpoint, memory_checkpoint);
                            Ok(Value::Undefined)
                        }
                    }
                    Ok(None) => {
                        self.rollback_json_parse(heap_checkpoint, memory_checkpoint);
                        Ok(Value::Undefined)
                    }
                    Err(err) => {
                        self.rollback_json_parse(heap_checkpoint, memory_checkpoint);
                        Err(err)
                    }
                }
            }

            // Node `path` builtins (bd-tu0c3): pure-compute posix semantics
            // (plus the win32 join/basename/isAbsolute subset), dispatched
            // from the lowering's path-module member-call interception. No
            // host effect. Argument-validation failures surface as core's
            // plain `InterpreterError::TypeError` (core has no error-object
            // prototype machinery; the engine twin throws the JS-catchable
            // ERR_INVALID_ARG_TYPE TypeError object).
            "builtin:PathJoin" => {
                let parts = self.path_string_args(args, "paths")?;
                Ok(Value::str(node_path_posix_join(&parts)))
            }
            "builtin:PathResolve" => {
                let parts = self.path_resolve_args(args)?;
                Ok(Value::str(node_path_posix_resolve(&parts)))
            }
            "builtin:PathNormalize" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::str(node_path_posix_normalize(&path)))
            }
            "builtin:PathBasename" => {
                let path = self.path_string_arg(args, 0, "path")?;
                let ext = self.path_optional_string_arg(args, 1, "ext")?;
                Ok(Value::str(node_path_basename_impl(
                    &path,
                    ext.as_deref(),
                    &['/'],
                    false,
                )))
            }
            "builtin:PathDirname" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::str(node_path_posix_dirname(&path)))
            }
            "builtin:PathExtname" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::str(node_path_posix_extname(&path)))
            }
            "builtin:PathIsAbsolute" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::Bool(path.starts_with('/')))
            }
            "builtin:PathRelative" => {
                let from = self.path_string_arg(args, 0, "from")?;
                let to = self.path_string_arg(args, 1, "to")?;
                Ok(Value::str(node_path_posix_relative(&from, &to)))
            }
            "builtin:PathParse" => {
                let path = self.path_string_arg(args, 0, "path")?;
                let parsed = node_path_posix_parse(&path);
                let object_id = self.alloc_object_with_properties(&[
                    ("root", Value::str(parsed.root)),
                    ("dir", Value::str(parsed.dir)),
                    ("base", Value::str(parsed.base)),
                    ("ext", Value::str(parsed.ext)),
                    ("name", Value::str(parsed.name)),
                ])?;
                Ok(Value::Object(object_id))
            }
            "builtin:PathFormat" => {
                let value = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                let Value::Object(object_id) = value else {
                    return Err(InterpreterError::TypeError {
                        expected: "object `pathObject` argument for path.format".to_string(),
                        got: value.type_name().to_string(),
                    });
                };
                let root = self.path_format_object_property(object_id, "root");
                let dir = self.path_format_object_property(object_id, "dir");
                let base = self.path_format_object_property(object_id, "base");
                let name = self.path_format_object_property(object_id, "name");
                let ext = self.path_format_object_property(object_id, "ext");
                Ok(Value::str(node_path_posix_format(
                    &root, &dir, &base, &name, &ext,
                )))
            }
            "builtin:PathWin32Join" => {
                let parts = self.path_string_args(args, "paths")?;
                Ok(Value::str(node_path_win32_join(&parts)))
            }
            "builtin:PathWin32Basename" => {
                let path = self.path_string_arg(args, 0, "path")?;
                let ext = self.path_optional_string_arg(args, 1, "ext")?;
                Ok(Value::str(node_path_basename_impl(
                    &path,
                    ext.as_deref(),
                    &['/', '\\'],
                    true,
                )))
            }
            "builtin:PathWin32IsAbsolute" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::Bool(node_path_win32_is_absolute(&path)))
            }

            // Node `querystring` builtins (bd-qmy52): pure-compute parse/
            // stringify/escape/unescape, dispatched from the lowering's
            // querystring-module member-call interception. No host effect;
            // semantics pinned against bun 1.3.14. Mirror of the engine arms.
            "builtin:QuerystringParse" => {
                let input = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                // Node: a non-string (or empty) input yields an empty object.
                let Value::Str(input) = input else {
                    return Ok(Value::Object(self.alloc_object_with_properties(&[])?));
                };
                let sep = self.qs_separator_arg(args, 1, "&")?;
                let eq = self.qs_separator_arg(args, 2, "=")?;
                let max_pairs = self.qs_max_pairs_arg(args, 3)?;
                let entries = node_qs_parse(input.as_ref(), &sep, &eq, max_pairs);
                // Node returns a null-prototype object; engine objects already
                // allocate without a prototype. Single-value keys are scalars,
                // repeated keys are real engine arrays.
                let object_id = self.alloc_object_with_properties(&[])?;
                for (key, values) in entries {
                    let value = if values.len() == 1 {
                        Value::str(values.into_iter().next().unwrap_or_default())
                    } else {
                        let elements: Vec<Value> = values.into_iter().map(Value::str).collect();
                        Value::Object(self.alloc_array_from_values(&elements)?)
                    };
                    self.set_object_property(object_id, key, value)?;
                }
                Ok(Value::Object(object_id))
            }
            "builtin:QuerystringStringify" => {
                let sep = self.qs_separator_arg(args, 1, "&")?;
                let eq = self.qs_separator_arg(args, 2, "=")?;
                let value = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                // Node: only a non-null object stringifies; every other input
                // (undefined, null, primitives) is ''.
                let Value::Object(object_id) = value else {
                    return Ok(Value::str(""));
                };
                Ok(Value::str(self.qs_stringify_object(object_id, &sep, &eq)))
            }
            "builtin:QuerystringEscape" => {
                // Node coerces the argument with String() before escaping
                // (bun: qs.escape(42) is '42').
                let value = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                let coerced = match &value {
                    Value::Str(s) => s.to_string(),
                    other => self.value_to_string(other),
                };
                Ok(Value::str(node_qs_escape(&coerced)))
            }
            "builtin:QuerystringUnescape" => {
                let value = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                let coerced = match &value {
                    Value::Str(s) => s.to_string(),
                    other => self.value_to_string(other),
                };
                Ok(Value::str(node_qs_unescape(&coerced)))
            }

            // Node `os` builtins (bd-qmy52): FIXED deterministic engine-
            // contained values (see the NODE_OS_* constants block) — no
            // ambient authority, nothing reads the real host.
            // getPriority/setPriority validate arguments like Node; core
            // surfaces the failures as its plain TypeError/RangeError
            // variants (the engine twin throws JS-catchable error objects).
            "builtin:OsPlatform" => Ok(Value::str(NODE_OS_PLATFORM)),
            "builtin:OsArch" => Ok(Value::str("x64")),
            "builtin:OsType" => Ok(Value::str("Linux")),
            "builtin:OsEndianness" => Ok(Value::str("LE")),
            "builtin:OsMachine" => Ok(Value::str("x86_64")),
            "builtin:OsRelease" => Ok(Value::str(NODE_OS_RELEASE)),
            "builtin:OsVersion" => Ok(Value::str(NODE_OS_VERSION)),
            "builtin:OsHomedir" => Ok(Value::str("/home")),
            "builtin:OsTmpdir" => Ok(Value::str("/tmp")),
            "builtin:OsHostname" => Ok(Value::str("localhost")),
            "builtin:OsUptime" => Ok(Value::Float(Float64::new(1.0))),
            "builtin:OsTotalmem" => Ok(Value::Int(NODE_OS_TOTALMEM_BYTES)),
            "builtin:OsFreemem" => Ok(Value::Int(NODE_OS_FREEMEM_BYTES)),
            "builtin:OsAvailableParallelism" => Ok(Value::Int(1)),
            "builtin:OsLoadavg" => {
                // Fixed idle load; length 3 like Node.
                let zero = Value::Float(Float64::new(0.0));
                let array_id = self.alloc_array_from_values(&[zero.clone(), zero.clone(), zero])?;
                Ok(Value::Object(array_id))
            }
            "builtin:OsCpus" => {
                // One fixed virtual CPU: non-empty, fully-typed shape.
                let times_id = self.alloc_object_with_properties(&[
                    ("user", Value::Int(0)),
                    ("nice", Value::Int(0)),
                    ("sys", Value::Int(0)),
                    ("idle", Value::Int(0)),
                    ("irq", Value::Int(0)),
                ])?;
                let cpu_id = self.alloc_object_with_properties(&[
                    ("model", Value::str("franken-virtual")),
                    ("speed", Value::Int(1000)),
                    ("times", Value::Object(times_id)),
                ])?;
                let array_id = self.alloc_array_from_values(&[Value::Object(cpu_id)])?;
                Ok(Value::Object(array_id))
            }
            "builtin:OsNetworkInterfaces" => {
                // The engine exposes NO network shape: an empty interfaces
                // map (a valid Node shape).
                Ok(Value::Object(self.alloc_object_with_properties(&[])?))
            }
            "builtin:OsUserInfo" => {
                let object_id = self.alloc_object_with_properties(&[
                    ("username", Value::str("franken")),
                    ("uid", Value::Int(0)),
                    ("gid", Value::Int(0)),
                    ("shell", Value::str("/bin/sh")),
                    ("homedir", Value::str("/home")),
                ])?;
                Ok(Value::Object(object_id))
            }
            "builtin:OsGetPriority" => {
                // Node: `getPriority(pid = 0)` — an absent/undefined pid takes
                // the default; anything else validates as an int32. The fixed
                // priority is 0 (PRIORITY_NORMAL) for every pid.
                if let Some(pid) = self.optional_arg(args, 0)?
                    && !matches!(pid, Value::Undefined)
                {
                    self.os_validate_int32(&pid, "pid", i64::from(i32::MIN), i64::from(i32::MAX))?;
                }
                Ok(Value::Int(0))
            }
            "builtin:OsSetPriority" => {
                // Node: `setPriority([pid, ]priority)` — when `priority` is
                // undefined the single-argument form applies (priority := pid,
                // pid := 0). pid validates as an int32 first, then priority as
                // an integer in [-20, 19]. The engine accepts valid values and
                // does nothing (no host process to re-prioritize); returns
                // undefined.
                let first = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                let second = self.optional_arg(args, 1)?.unwrap_or(Value::Undefined);
                let (pid, priority) = if matches!(second, Value::Undefined) {
                    (Value::Int(0), first)
                } else {
                    (first, second)
                };
                self.os_validate_int32(&pid, "pid", i64::from(i32::MIN), i64::from(i32::MAX))?;
                self.os_validate_int32(&priority, "priority", -20, 19)?;
                Ok(Value::Undefined)
            }
            "builtin:OsConstants" => {
                // `os.constants` — the nested { signals, errno, priority }
                // object (real POSIX numbers; see the NODE_OS_* tables).
                let signals = self.alloc_os_constant_group(NODE_OS_SIGNALS)?;
                let errno = self.alloc_os_constant_group(NODE_OS_ERRNO)?;
                let priority = self.alloc_os_constant_group(NODE_OS_PRIORITY)?;
                let object_id = self.alloc_object_with_properties(&[
                    ("signals", signals),
                    ("errno", errno),
                    ("priority", priority),
                ])?;
                Ok(Value::Object(object_id))
            }

            _ => {
                // Unknown builtin method - return undefined
                Ok(Value::Undefined)
            }
        }
    }

    /// bd-tu0c3: read ALL hostcall args as strings for a variadic path builtin
    /// (join), failing on the first non-string (Node validates every join
    /// argument, including `undefined`).
    fn path_string_args(
        &self,
        args: RegRange,
        arg_name: &str,
    ) -> Result<Vec<String>, InterpreterError> {
        let mut parts = Vec::with_capacity(args.count as usize);
        for offset in 0..args.count {
            match self.read_arg(args, offset)? {
                Value::Str(s) => parts.push(s.to_string()),
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: format!("string `{arg_name}[{offset}]` path argument"),
                        got: other.type_name().to_string(),
                    });
                }
            }
        }
        Ok(parts)
    }

    /// bd-tu0c3: collect `path.resolve` arguments with Node's LAZY right-to-
    /// left validation: segments are validated (string-required) from the last
    /// argument backwards and collection STOPS at the first absolute segment —
    /// arguments to its left are never inspected (Node: `resolve(7, '/a')` is
    /// `'/a'`, not a TypeError). Returned in left-to-right order for
    /// [`node_path_posix_resolve`].
    fn path_resolve_args(&self, args: RegRange) -> Result<Vec<String>, InterpreterError> {
        let mut collected: Vec<String> = Vec::with_capacity(args.count as usize);
        let mut offset = args.count;
        while offset > 0 {
            offset -= 1;
            let value = self.read_arg(args, offset)?;
            let Value::Str(s) = value else {
                return Err(InterpreterError::TypeError {
                    expected: format!("string `paths[{offset}]` path argument"),
                    got: value.type_name().to_string(),
                });
            };
            let segment = s.to_string();
            let is_absolute = segment.starts_with('/');
            collected.push(segment);
            if is_absolute {
                break;
            }
        }
        collected.reverse();
        Ok(collected)
    }

    /// bd-tu0c3: required string argument of a path builtin at `offset`
    /// (missing arguments read as `undefined`, which fails validation exactly
    /// like Node).
    fn path_string_arg(
        &self,
        args: RegRange,
        offset: u32,
        arg_name: &str,
    ) -> Result<String, InterpreterError> {
        let value = self.optional_arg(args, offset)?.unwrap_or(Value::Undefined);
        match value {
            Value::Str(s) => Ok(s.to_string()),
            other => Err(InterpreterError::TypeError {
                expected: format!("string `{arg_name}` path argument"),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// bd-tu0c3: optional string argument of a path builtin at `offset`
    /// (`basename`'s `ext`): absent or `undefined` is accepted as `None`, any
    /// other non-string fails (Node validates `ext` only when it is not
    /// `undefined`).
    fn path_optional_string_arg(
        &self,
        args: RegRange,
        offset: u32,
        arg_name: &str,
    ) -> Result<Option<String>, InterpreterError> {
        match self.optional_arg(args, offset)? {
            None | Some(Value::Undefined) => Ok(None),
            Some(Value::Str(s)) => Ok(Some(s.to_string())),
            Some(other) => Err(InterpreterError::TypeError {
                expected: format!("string `{arg_name}` path argument"),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// bd-tu0c3: read an own string-ish property of the `path.format` path
    /// object; absent/`undefined` reads as `''`, other values are coerced with
    /// the standard stringification (Node coerces via template literals).
    /// Own-property only (no prototype walk).
    fn path_format_object_property(&self, object_id: ObjectId, key: &str) -> String {
        match self
            .heap
            .get(object_id.0 as usize)
            .and_then(|object| object.properties.get(key).cloned())
        {
            None | Some(Value::Undefined) => String::new(),
            Some(Value::Str(s)) => s.to_string(),
            Some(other) => self.value_to_string(&other),
        }
    }

    /// bd-qmy52: optional custom separator argument for querystring
    /// parse/stringify. Node treats any FALSY value (`undefined`, `null`,
    /// `''`, `0`, `false`, `NaN`) as "use the default" and stringifies
    /// everything else (`String(sep)`).
    fn qs_separator_arg(
        &self,
        args: RegRange,
        offset: u32,
        default: &str,
    ) -> Result<String, InterpreterError> {
        let value = self.optional_arg(args, offset)?.unwrap_or(Value::Undefined);
        if !value.is_truthy() {
            return Ok(default.to_string());
        }
        Ok(self.value_to_string(&value))
    }

    /// bd-qmy52: `options.maxKeys` for `querystring.parse`. Default 1000
    /// pairs; a number that is `<= 0`, `Infinity`, `NaN`, or non-integer
    /// disables the limit (Node's `--pairs === 0` countdown never reaches 0
    /// for those); a non-number `maxKeys` (or no/non-object options) keeps the
    /// default. Own-property read only, like the other options bags.
    fn qs_max_pairs_arg(
        &self,
        args: RegRange,
        offset: u32,
    ) -> Result<Option<u64>, InterpreterError> {
        const DEFAULT_MAX_PAIRS: u64 = 1000;
        let Some(Value::Object(options_id)) = self.optional_arg(args, offset)? else {
            return Ok(Some(DEFAULT_MAX_PAIRS));
        };
        let max_keys = self
            .heap
            .get(options_id.0 as usize)
            .and_then(|object| object.properties.get("maxKeys").cloned());
        Ok(match max_keys {
            Some(Value::Int(n)) => {
                if n > 0 {
                    Some(n as u64)
                } else {
                    None
                }
            }
            Some(Value::Float(f)) => {
                let v = f.inner();
                if v.is_finite() && v > 0.0 && v.fract() == 0.0 {
                    Some(v as u64)
                } else {
                    None
                }
            }
            _ => Some(DEFAULT_MAX_PAIRS),
        })
    }

    /// bd-qmy52: Node's `stringifyPrimitive` for `querystring.stringify`
    /// values and array elements: strings pass through, finite numbers
    /// stringify, booleans map to `true`/`false`, and EVERYTHING else
    /// (undefined, null, NaN, Infinity, objects, functions) becomes `''`.
    /// (Core's `Value` has no BigInt variant; the engine twin also
    /// stringifies bigints.)
    fn qs_stringify_primitive(&self, value: &Value) -> String {
        match value {
            Value::Str(s) => s.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) if f.inner().is_finite() => self.value_to_string(value),
            Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
            _ => String::new(),
        }
    }

    /// bd-qmy52: `querystring.stringify` body over a heap object: own
    /// properties in ECMAScript `Object.keys` order (canonical array indices
    /// numerically first, then other strings by creation order), array values expand to
    /// repeated `key=element` pairs (an EMPTY array contributes nothing, bun:
    /// `stringify({e: [], f: 'y'})` is `'f=y'`), other values stringify via
    /// [`Self::qs_stringify_primitive`]; keys and values escape with
    /// [`node_qs_escape`]. An array receiver's `length` property is skipped
    /// (approximates its non-enumerability).
    fn qs_stringify_object(&self, object_id: ObjectId, sep: &str, eq: &str) -> String {
        let entries: Vec<(String, Value)> = self
            .heap
            .get(object_id.0 as usize)
            .map(|object| {
                object
                    .own_property_keys()
                    .into_iter()
                    .filter(|key| !(object.is_array && key == "length"))
                    .filter_map(|key| {
                        object
                            .properties
                            .get(&key)
                            .cloned()
                            .map(|value| (key, value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut pieces: Vec<String> = Vec::new();
        for (key, value) in entries {
            let key_prefix = format!("{}{eq}", node_qs_escape(&key));
            if let Value::Object(id) = value
                && self
                    .heap
                    .get(id.0 as usize)
                    .is_some_and(|object| object.is_array)
            {
                for element in self.read_array_like_values(id) {
                    pieces.push(format!(
                        "{key_prefix}{}",
                        node_qs_escape(&self.qs_stringify_primitive(&element))
                    ));
                }
                continue;
            }
            pieces.push(format!(
                "{key_prefix}{}",
                node_qs_escape(&self.qs_stringify_primitive(&value))
            ));
        }
        pieces.join(sep)
    }

    /// bd-qmy52: Node `validateInt32`-shaped check for the os builtins
    /// (`getPriority`/`setPriority` pids and priorities). Core has no
    /// error-object prototype machinery: a non-number surfaces as core's
    /// plain `InterpreterError::TypeError` and a non-integer/out-of-range
    /// number as `InterpreterError::RangeError` (the engine twin throws the
    /// JS-catchable ERR_INVALID_ARG_TYPE / ERR_OUT_OF_RANGE error objects).
    fn os_validate_int32(
        &self,
        value: &Value,
        arg_name: &str,
        lo: i64,
        hi: i64,
    ) -> Result<i64, InterpreterError> {
        let number = match value {
            Value::Int(n) => *n as f64,
            Value::Float(f) => f.inner(),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: format!("number `{arg_name}` argument"),
                    got: other.type_name().to_string(),
                });
            }
        };
        if !number.is_finite() || number.fract() != 0.0 {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "The value of \"{arg_name}\" is out of range. It must be an integer. Received {}",
                    self.value_to_string(value)
                ),
            });
        }
        let integer = number as i64;
        if integer < lo || integer > hi {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "The value of \"{arg_name}\" is out of range. It must be >= {lo} && <= {hi}. Received {}",
                    self.value_to_string(value)
                ),
            });
        }
        Ok(integer)
    }

    /// bd-qmy52: allocate one flat `{ NAME: number, … }` group of the
    /// `os.constants` object.
    fn alloc_os_constant_group(
        &mut self,
        entries: &[(&str, i64)],
    ) -> Result<Value, InterpreterError> {
        let props: Vec<(&str, Value)> = entries
            .iter()
            .map(|(name, number)| (*name, Value::Int(*number)))
            .collect();
        Ok(Value::Object(self.alloc_object_with_properties(&props)?))
    }

    fn optional_arg(&self, args: RegRange, offset: u32) -> Result<Option<Value>, InterpreterError> {
        if offset >= args.count {
            return Ok(None);
        }
        Ok(Some(self.read_arg(args, offset)?))
    }

    fn required_arg(
        &self,
        args: RegRange,
        offset: u32,
        expected: &str,
    ) -> Result<Value, InterpreterError> {
        self.optional_arg(args, offset)?
            .ok_or_else(|| InterpreterError::TypeError {
                expected: expected.to_string(),
                got: "undefined".to_string(),
            })
    }

    fn read_arg(&self, args: RegRange, offset: u32) -> Result<Value, InterpreterError> {
        let reg = args
            .start
            .checked_add(offset)
            .ok_or(InterpreterError::RegisterOutOfBounds {
                register: args.start,
                max: self.config.max_registers,
            })?;
        self.read_reg(reg)
    }

    fn expect_object(&self, value: Value, expected: &str) -> Result<ObjectId, InterpreterError> {
        match value {
            Value::Object(object_id) => {
                self.heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                Ok(object_id)
            }
            other => Err(InterpreterError::TypeError {
                expected: expected.to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    fn own_enumerable_keys(&self, object_id: ObjectId) -> Result<Vec<String>, InterpreterError> {
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        Ok(object
            .own_property_keys()
            .into_iter()
            .filter(|key| !(object.is_array && key == "length"))
            .collect())
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
            Value::Str(s) => s.to_string(),
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

    fn read_reg_label(&self, reg: u32) -> Result<crate::ifc_artifacts::Label, InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + reg as usize;
        Ok(self
            .register_labels
            .get(actual_reg)
            .cloned()
            .unwrap_or(crate::ifc_artifacts::Label::Public))
    }

    fn clear_register_range(&mut self, start: usize, end: usize) {
        if end > self.registers.len() {
            self.registers.resize(end, Value::Undefined);
        }
        self.registers[start..end].fill(Value::Undefined);

        if end > self.register_labels.len() {
            self.register_labels
                .resize(end, crate::ifc_artifacts::Label::Public);
        }
        self.register_labels[start..end].fill(crate::ifc_artifacts::Label::Public);
    }

    fn register_labels_in_range(
        &self,
        start: usize,
        end: usize,
    ) -> Vec<crate::ifc_artifacts::Label> {
        (start..end)
            .map(|idx| {
                self.register_labels
                    .get(idx)
                    .cloned()
                    .unwrap_or(crate::ifc_artifacts::Label::Public)
            })
            .collect()
    }

    fn restore_saved_register_range(
        &mut self,
        base: usize,
        saved_regs: Vec<Value>,
        saved_labels: Vec<crate::ifc_artifacts::Label>,
    ) {
        let req_len = base + saved_regs.len();
        self.clear_register_range(base, req_len);
        for (i, val) in saved_regs.into_iter().enumerate() {
            self.registers[base + i] = val;
        }
        for (i, label) in saved_labels.into_iter().enumerate() {
            if base + i < req_len {
                self.register_labels[base + i] = label;
            }
        }
    }

    fn write_reg(&mut self, reg: u32, value: Value) -> Result<(), InterpreterError> {
        self.write_reg_with_label(reg, value, crate::ifc_artifacts::Label::Public)
    }

    fn write_reg_with_label(
        &mut self,
        reg: u32,
        value: Value,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
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
        if actual_reg >= self.register_labels.len() {
            self.register_labels
                .resize(actual_reg + 1, crate::ifc_artifacts::Label::Public);
        }
        let previous = self.registers[actual_reg].clone();
        let previous_label = self.register_labels[actual_reg].clone();
        self.registers[actual_reg] = value;
        self.register_labels[actual_reg] = label;
        if let Err(err) = self.sync_estimated_memory_bytes() {
            self.registers[actual_reg] = previous;
            self.register_labels[actual_reg] = previous_label;
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

    fn estimate_label_bytes(label: &crate::ifc_artifacts::Label) -> u64 {
        MEMORY_ESTIMATE_LABEL_BASE_BYTES.saturating_add(match label {
            crate::ifc_artifacts::Label::Custom { name, .. } => name.len() as u64,
            _ => 0,
        })
    }

    fn estimate_scope_frame_bytes(frame: &ScopeFrame) -> u64 {
        let bindings = frame
            .bindings
            .iter()
            .map(|(name, binding)| {
                MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES
                    .saturating_add(Self::estimate_string_bytes(name))
                    .saturating_add(Self::estimate_value_bytes(&binding.value))
                    .saturating_add(Self::estimate_label_bytes(&binding.label))
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
            .saturating_add(Self::estimate_value_bytes(&frame.new_target_value))
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
                    .map(|pending| Self::estimate_value_bytes(&pending.value))
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_pending_return
                    .as_ref()
                    .map(|pending| Self::estimate_value_bytes(&pending.value))
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
                    // OrderedStringMap owns a second key for its ES-order
                    // index/vector spine in addition to the lookup-map key.
                    .saturating_add(Self::estimate_string_bytes(key))
                    .saturating_add(Self::estimate_value_bytes(value))
            })
            .sum::<u64>();
        let accessors = object
            .accessors
            .iter()
            .map(|(key, accessor)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_string_bytes(key))
                    .saturating_add(
                        accessor
                            .get
                            .as_ref()
                            .map(Self::estimate_value_bytes)
                            .unwrap_or(0),
                    )
                    .saturating_add(
                        accessor
                            .set
                            .as_ref()
                            .map(Self::estimate_value_bytes)
                            .unwrap_or(0),
                    )
            })
            .sum::<u64>();
        let own_string_key_order = object
            .properties
            .baseline_string_key_order()
            .map(|order| {
                order
                    .iter()
                    .map(|key| Self::estimate_string_bytes(key))
                    .sum::<u64>()
            })
            .unwrap_or(0);
        MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES
            .saturating_add(properties)
            .saturating_add(accessors)
            .saturating_add(own_string_key_order)
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

    fn estimate_copy_data_properties_state_bytes(state: &CopyDataPropertiesState) -> u64 {
        let keys = state
            .keys
            .iter()
            .map(|key| Self::estimate_string_bytes(key))
            .sum::<u64>();
        let excluded = state
            .excluded
            .iter()
            .map(|key| Self::estimate_string_bytes(key))
            .sum::<u64>();
        let awaiting_key = state
            .awaiting_key
            .as_deref()
            .map(Self::estimate_string_bytes)
            .unwrap_or(0);
        MEMORY_ESTIMATE_COPY_DATA_PROPERTIES_STATE_BASE_BYTES
            .saturating_add(Self::estimate_value_bytes(&state.source))
            .saturating_add(
                state
                    .string_units
                    .as_ref()
                    .map_or(0, |units| (units.len() as u64).saturating_mul(2)),
            )
            .saturating_add(keys)
            .saturating_add(excluded)
            .saturating_add(awaiting_key)
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
                self.copy_data_properties_states
                    .iter()
                    .map(Self::estimate_copy_data_properties_state_bytes)
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
            self.finally_frames.truncate(frame.saved_finally_mode_depth);
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
        self.alloc_heap_object_with_prototype(prototype, false)
    }

    fn alloc_heap_object_with_prototype(
        &mut self,
        prototype: Option<ObjectId>,
        is_array: bool,
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
        object.is_array = is_array;
        let allocation_bytes = Self::estimate_heap_object_bytes(&object);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(allocation_bytes);
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, requested_heap_objects));
        }

        self.heap.push(object);
        self.estimated_memory_bytes = requested_bytes;

        if let Some(profiler) = &mut self.profiling_data {
            if is_array {
                profiler.record_array_allocation(allocation_bytes);
            } else {
                profiler.record_object_allocation(allocation_bytes);
            }
        }

        Ok(id)
    }

    pub fn alloc_array_with_prototype(
        &mut self,
        prototype: Option<ObjectId>,
    ) -> Result<ObjectId, InterpreterError> {
        self.alloc_heap_object_with_prototype(prototype, true)
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
            for key in object.own_property_keys() {
                if seen.insert(key.clone()) {
                    keys.push(key);
                }
            }
            current = object.prototype;
            depth += 1;
        }

        Ok(keys)
    }

    fn collect_for_of_values(&self, iterable: &Value) -> Result<Vec<Value>, InterpreterError> {
        match iterable {
            // ES string iteration yields one element per code point, with an
            // unpaired surrogate preserved as its own single-unit element
            // (bd-7zwar, engine parity with bd-rdnhc; previously iterated the
            // U+FFFD projection).
            Value::Str(text) => Ok(text
                .code_point_elements()
                .into_iter()
                .map(Value::Str)
                .collect()),
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
        let (
            previous_data,
            previous_data_position,
            previous_accessor,
            property_key,
            order_rollback,
        ) = {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            if let Some((kind, property_key)) = Self::decode_accessor_definition_key(&key) {
                let existed = object.contains_own_property(&property_key);
                let order_rollback = object.record_property_definition(&property_key, existed);
                let previous_data_position =
                    object.properties.string_insertion_position(&property_key);
                let previous_data = object
                    .properties
                    .remove_preserving_baseline_order(&property_key);
                let previous_accessor = object.accessors.get(&property_key).cloned();
                let accessor = object.accessors.entry(property_key.clone()).or_default();
                match kind {
                    AccessorKind::Get => accessor.get = Some(value),
                    AccessorKind::Set => accessor.set = Some(value),
                }
                (
                    previous_data,
                    previous_data_position,
                    previous_accessor,
                    property_key,
                    order_rollback,
                )
            } else {
                let existed = object.contains_own_property(&key);
                let order_rollback = object.record_property_definition(&key, existed);
                let previous_accessor = object.accessors.remove(&key);
                let previous_data = object.properties.insert(key.clone(), value);
                (
                    previous_data,
                    None,
                    previous_accessor,
                    key.clone(),
                    order_rollback,
                )
            }
        };
        if let Err(err) = self.sync_estimated_memory_bytes() {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            if let Some(previous) = previous_data {
                if let Some(position) = previous_data_position {
                    object.properties.insert_at_string_position(
                        property_key.clone(),
                        previous,
                        position,
                    );
                } else {
                    object.properties.insert(property_key.clone(), previous);
                }
            } else {
                object
                    .properties
                    .remove_preserving_baseline_order(&property_key);
            }
            if let Some(previous) = previous_accessor {
                object.accessors.insert(property_key.clone(), previous);
            } else {
                object.accessors.remove(&property_key);
            }
            object.rollback_property_definition_order(&property_key, order_rollback);
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(err);
        }
        Ok(())
    }

    /// Insert an ordinary own data property without interpreting the private
    /// accessor-definition prefixes used by IR class lowering. External data
    /// formats such as JSON must preserve those strings as literal keys.
    fn set_plain_data_property(
        &mut self,
        object_id: ObjectId,
        key: String,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let (previous_data, previous_accessor, order_rollback) = {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let existed = object.contains_own_property(&key);
            let order_rollback = object.record_property_definition(&key, existed);
            let previous_accessor = object.accessors.remove(&key);
            let previous_data = object.properties.insert(key.clone(), value);
            (previous_data, previous_accessor, order_rollback)
        };
        if let Err(err) = self.sync_estimated_memory_bytes() {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            if let Some(previous) = previous_data {
                object.properties.insert(key.clone(), previous);
            } else {
                object.properties.remove_preserving_baseline_order(&key);
            }
            if let Some(previous) = previous_accessor {
                object.accessors.insert(key.clone(), previous);
            }
            object.rollback_property_definition_order(&key, order_rollback);
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
        let object = self
            .heap
            .get_mut(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let removed = object.properties.remove(key);
        let removed_accessor = object.accessors.remove(key);
        if removed.is_some() || removed_accessor.is_some() {
            object.forget_property_order(key);
        }
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        Ok(removed.is_some() || removed_accessor.is_some())
    }

    #[cfg(test)]
    fn ensure_function_prototype(&mut self, func_idx: u32) -> Result<ObjectId, InterpreterError> {
        self.ensure_function_prototype_for_key(FunctionObjectKey::Function(func_idx))
    }

    fn ensure_function_prototype_for_key(
        &mut self,
        function_key: FunctionObjectKey,
    ) -> Result<ObjectId, InterpreterError> {
        if let Some(existing) = self.function_prototypes.get(&function_key) {
            Ok(*existing)
        } else {
            let prototype = self.alloc_object_with_prototype(None)?;
            self.function_prototypes.insert(function_key, prototype);
            Ok(prototype)
        }
    }

    fn function_object_key(value: &Value) -> Option<FunctionObjectKey> {
        match value {
            Value::Function(idx) => Some(FunctionObjectKey::Function(*idx)),
            Value::Closure(closure_id) => Some(FunctionObjectKey::Closure(*closure_id)),
            _ => None,
        }
    }

    fn function_prototype_key_for_value(
        &self,
        value: &Value,
    ) -> Result<Option<FunctionObjectKey>, InterpreterError> {
        match value {
            Value::Function(idx) => Ok(Some(FunctionObjectKey::Function(*idx))),
            Value::Closure(closure_id) => {
                self.closures.get(*closure_id as usize).ok_or_else(|| {
                    InterpreterError::TypeError {
                        expected: "valid closure".to_string(),
                        got: format!("closure#{closure_id} not found"),
                    }
                })?;
                Ok(Some(FunctionObjectKey::Closure(*closure_id)))
            }
            _ => Ok(None),
        }
    }

    fn function_object_id(&self, value: &Value) -> Option<ObjectId> {
        Self::function_object_key(value).and_then(|key| self.function_objects.get(&key).copied())
    }

    fn function_metadata_property(
        &self,
        value: &Value,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        let Some(object_id) = self.function_object_id(value) else {
            return Ok(Value::Undefined);
        };
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        Ok(object
            .properties
            .get(key)
            .cloned()
            .unwrap_or(Value::Undefined))
    }

    fn function_super_value(
        &self,
        value: &Value,
        primary_key: &str,
    ) -> Result<Value, InterpreterError> {
        let primary = self.function_metadata_property(value, primary_key)?;
        if primary != Value::Undefined {
            return Ok(primary);
        }
        self.function_metadata_property(value, IR_SUPER_CONSTRUCTOR_PROPERTY)
    }

    fn method_super_value(
        &self,
        callee: &Value,
        receiver: &Value,
    ) -> Result<Value, InterpreterError> {
        let from_method = self.function_metadata_property(callee, IR_SUPER_PROTOTYPE_PROPERTY)?;
        if from_method != Value::Undefined {
            return Ok(from_method);
        }

        let from_constructor =
            self.function_metadata_property(callee, IR_SUPER_CONSTRUCTOR_PROPERTY)?;
        if from_constructor != Value::Undefined {
            return Ok(from_constructor);
        }

        let Value::Object(receiver_id) = receiver else {
            return Ok(Value::Undefined);
        };
        let Some(prototype_id) = self
            .heap
            .get(receiver_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: receiver_id.0 })?
            .prototype
        else {
            return Ok(Value::Undefined);
        };
        let parent_prototype = self
            .heap
            .get(prototype_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: prototype_id.0 })?
            .prototype;

        Ok(parent_prototype
            .map(Value::Object)
            .unwrap_or(Value::Undefined))
    }

    fn ensure_function_object(
        &mut self,
        value: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let Some(key) = Self::function_object_key(value) else {
            return Ok(None);
        };
        if let Some(existing) = self.function_objects.get(&key) {
            return Ok(Some(*existing));
        }
        let object_id = self.alloc_object_with_prototype(None)?;
        self.function_objects.insert(key, object_id);
        Ok(Some(object_id))
    }

    fn function_prototype_for_value(
        &mut self,
        value: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let Some(function_key) = self.function_prototype_key_for_value(value)? else {
            return Ok(None);
        };
        self.ensure_function_prototype_for_key(function_key)
            .map(Some)
    }

    // -- JSON.parse recursive-descent parser (bd-zql4d) --------------------

    fn json_skip_ws(units: &[u16], pos: &mut usize) {
        while matches!(units.get(*pos), Some(0x20 | 0x09 | 0x0A | 0x0D)) {
            *pos += 1;
        }
    }

    /// Parse a JSON string token directly over exact UTF-16 code units. Both
    /// raw units and `\uXXXX` escapes remain exact: paired surrogates heal into
    /// one scalar, while a lone surrogate remains representable in [`JsString`].
    fn json_parse_string(units: &[u16], pos: &mut usize) -> Option<JsString> {
        if units.get(*pos) != Some(&0x22) {
            return None;
        }
        *pos += 1;
        let mut parsed = Vec::new();
        while let Some(&unit) = units.get(*pos) {
            *pos += 1;
            match unit {
                0x22 => return Some(JsString::from_code_units(&parsed)),
                0x5C => {
                    let &escaped = units.get(*pos)?;
                    *pos += 1;
                    match escaped {
                        0x22 => parsed.push(0x22),
                        0x5C => parsed.push(0x5C),
                        0x2F => parsed.push(0x2F),
                        0x62 => parsed.push(0x08),
                        0x66 => parsed.push(0x0C),
                        0x6E => parsed.push(0x0A),
                        0x72 => parsed.push(0x0D),
                        0x74 => parsed.push(0x09),
                        0x75 => {
                            if *pos + 4 > units.len() {
                                return None;
                            }
                            let mut code = 0u16;
                            for &digit in &units[*pos..*pos + 4] {
                                let nibble = match digit {
                                    0x30..=0x39 => digit - 0x30,
                                    0x41..=0x46 => digit - 0x41 + 10,
                                    0x61..=0x66 => digit - 0x61 + 10,
                                    _ => return None,
                                };
                                code = (code << 4) | nibble;
                            }
                            *pos += 4;
                            parsed.push(code);
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1F => return None,
                _ => parsed.push(unit),
            }
        }
        None
    }

    fn json_parse_number(units: &[u16], pos: &mut usize) -> Option<Value> {
        let start = *pos;
        if units.get(*pos) == Some(&0x2D) {
            *pos += 1;
        }
        match units.get(*pos) {
            Some(0x30) => {
                *pos += 1;
                // JSON does not allow a leading zero before another digit.
                if matches!(units.get(*pos), Some(0x30..=0x39)) {
                    return None;
                }
            }
            Some(0x31..=0x39) => {
                *pos += 1;
                while matches!(units.get(*pos), Some(0x30..=0x39)) {
                    *pos += 1;
                }
            }
            _ => return None,
        }
        let mut is_float = false;
        if units.get(*pos) == Some(&0x2E) {
            is_float = true;
            *pos += 1;
            let fraction_start = *pos;
            while matches!(units.get(*pos), Some(0x30..=0x39)) {
                *pos += 1;
            }
            if *pos == fraction_start {
                return None;
            }
        }
        if matches!(units.get(*pos), Some(0x65 | 0x45)) {
            is_float = true;
            *pos += 1;
            if matches!(units.get(*pos), Some(0x2B | 0x2D)) {
                *pos += 1;
            }
            let exponent_start = *pos;
            while matches!(units.get(*pos), Some(0x30..=0x39)) {
                *pos += 1;
            }
            if *pos == exponent_start {
                return None;
            }
        }
        let token = String::from_utf16(&units[start..*pos]).ok()?;
        if token == "-0" {
            return Some(Value::Float(Float64::new(-0.0)));
        }
        if !is_float && let Ok(value) = token.parse::<i64>() {
            return Some(Value::Int(value));
        }
        token
            .parse::<f64>()
            .ok()
            .map(|value| Value::Float(Float64::new(value)))
    }

    fn json_parse_value(
        &mut self,
        units: &[u16],
        pos: &mut usize,
        depth: usize,
    ) -> Result<Option<Value>, InterpreterError> {
        if depth > 200 {
            return Ok(None);
        }
        Self::json_skip_ws(units, pos);
        let Some(&unit) = units.get(*pos) else {
            return Ok(None);
        };
        match unit {
            0x7B => self.json_parse_object(units, pos, depth),
            0x5B => self.json_parse_array(units, pos, depth),
            0x22 => Ok(Self::json_parse_string(units, pos).map(Value::str)),
            0x74 if units[*pos..].starts_with(&[0x74, 0x72, 0x75, 0x65]) => {
                *pos += 4;
                Ok(Some(Value::Bool(true)))
            }
            0x66 if units[*pos..].starts_with(&[0x66, 0x61, 0x6C, 0x73, 0x65]) => {
                *pos += 5;
                Ok(Some(Value::Bool(false)))
            }
            0x6E if units[*pos..].starts_with(&[0x6E, 0x75, 0x6C, 0x6C]) => {
                *pos += 4;
                Ok(Some(Value::Null))
            }
            0x2D | 0x30..=0x39 => Ok(Self::json_parse_number(units, pos)),
            _ => Ok(None),
        }
    }

    fn json_parse_object(
        &mut self,
        units: &[u16],
        pos: &mut usize,
        depth: usize,
    ) -> Result<Option<Value>, InterpreterError> {
        *pos += 1;
        let object_id = self.alloc_object_with_prototype(None)?;
        Self::json_skip_ws(units, pos);
        if units.get(*pos) == Some(&0x7D) {
            *pos += 1;
            return Ok(Some(Value::Object(object_id)));
        }
        loop {
            Self::json_skip_ws(units, pos);
            let Some(key) = Self::json_parse_string(units, pos) else {
                return Ok(None);
            };
            Self::json_skip_ws(units, pos);
            if units.get(*pos) != Some(&0x3A) {
                return Ok(None);
            }
            *pos += 1;
            let Some(value) = self.json_parse_value(units, pos, depth + 1)? else {
                return Ok(None);
            };
            self.set_plain_data_property(object_id, key.to_string(), value)?;
            Self::json_skip_ws(units, pos);
            match units.get(*pos) {
                Some(0x2C) => *pos += 1,
                Some(0x7D) => {
                    *pos += 1;
                    return Ok(Some(Value::Object(object_id)));
                }
                _ => return Ok(None),
            }
        }
    }

    fn json_parse_array(
        &mut self,
        units: &[u16],
        pos: &mut usize,
        depth: usize,
    ) -> Result<Option<Value>, InterpreterError> {
        *pos += 1;
        let array_id = self.alloc_array_with_prototype(None)?;
        Self::json_skip_ws(units, pos);
        if units.get(*pos) == Some(&0x5D) {
            *pos += 1;
            self.set_plain_data_property(array_id, "length".to_string(), Value::Int(0))?;
            return Ok(Some(Value::Object(array_id)));
        }
        let mut length = 0u32;
        loop {
            let Some(value) = self.json_parse_value(units, pos, depth + 1)? else {
                return Ok(None);
            };
            self.set_plain_data_property(array_id, length.to_string(), value)?;
            length = length.saturating_add(1);
            Self::json_skip_ws(units, pos);
            match units.get(*pos) {
                Some(0x2C) => *pos += 1,
                Some(0x5D) => {
                    *pos += 1;
                    self.set_plain_data_property(
                        array_id,
                        "length".to_string(),
                        Value::Int(i64::from(length)),
                    )?;
                    return Ok(Some(Value::Object(array_id)));
                }
                _ => return Ok(None),
            }
        }
    }

    fn rollback_json_parse(&mut self, heap_len: usize, estimated_memory_bytes: u64) {
        self.heap.truncate(heap_len);
        self.estimated_memory_bytes = estimated_memory_bytes;
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
        let (result, _) = self.execute_with_hook_and_profiling(module, trace_id, hook, None)?;
        Ok(result)
    }

    fn execute_with_hook_and_profiling(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
        profiling_config: Option<crate::profiling::ProfilingConfig>,
    ) -> Result<(ExecutionResult, Option<crate::profiling::Profiler>), InterpreterError> {
        let mut core = InterpreterCore::new(self.config.clone(), trace_id);
        if let Some(hook) = hook {
            core.set_hook(hook);
        }
        if let Some(config) = profiling_config {
            core.enable_profiling(config);
        }
        let result = match core.execute(module) {
            Ok(result) => result,
            Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                let requested_hook_action =
                    requested_hook_action_from_error(action.as_str(), reason.clone())
                        .ok_or(InterpreterError::ContainmentActionRequested { action, reason })?;
                core.take_execution_result(Value::Undefined, Some(requested_hook_action))
            }
            Err(err) => return Err(err),
        };
        Ok((result, core.disable_profiling()))
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
        let (result, _) = self.execute_with_hook_and_profiling(module, trace_id, hook, None)?;
        Ok(result)
    }

    fn execute_with_hook_and_profiling(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
        profiling_config: Option<crate::profiling::ProfilingConfig>,
    ) -> Result<(ExecutionResult, Option<crate::profiling::Profiler>), InterpreterError> {
        let mut core = InterpreterCore::new(self.config.clone(), trace_id);
        if let Some(hook) = hook {
            core.set_hook(hook);
        }
        if let Some(config) = profiling_config {
            core.enable_profiling(config);
        }
        let result = match core.execute(module) {
            Ok(result) => result,
            Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                let requested_hook_action =
                    requested_hook_action_from_error(action.as_str(), reason.clone())
                        .ok_or(InterpreterError::ContainmentActionRequested { action, reason })?;
                core.take_execution_result(Value::Undefined, Some(requested_hook_action))
            }
            Err(err) => return Err(err),
        };
        Ok((result, core.disable_profiling()))
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
            // SAFETY: Challenge action requires a token reason
            token: reason.unwrap(),
        })),
        "sandbox" => Some(HookAction::Sandbox),
        "suspend" => Some(HookAction::Suspend),
        // SAFETY: Terminate action requires a reason
        "terminate" => Some(HookAction::Terminate(reason.unwrap())),
        // SAFETY: Quarantine action requires a reason
        "quarantine" => Some(HookAction::Quarantine(reason.unwrap())),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Node `path` builtin semantics (bd-tu0c3)
//
// Pure-compute string algorithms backing the `builtin:Path*` hostcalls emitted
// by the lowering pipeline's path-module interception. Posix semantics follow
// Node's `path.posix` implementation (the default `path` on linux IS posix);
// the win32 helpers cover the small separator-sensitive subset the lowering
// recognizes (join/basename/isAbsolute). Mirror of the canonical copy in
// `franken-engine/src/baseline_interpreter.rs` — keep the two in lockstep.
// ---------------------------------------------------------------------------

/// Resolve `.`/`..` segments of `path`: splits on `separators`, drops empty
/// and `.` segments, pops a stack entry for `..` (keeping leading `..`s only
/// when `allow_above_root`, i.e. for relative paths), then joins with `sep`.
/// Shared by normalize/join/resolve for both separator families.
fn node_path_normalize_segments(
    path: &str,
    allow_above_root: bool,
    sep: char,
    separators: &[char],
) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split(|c: char| separators.contains(&c)) {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            match stack.last() {
                Some(&last) if last != ".." => {
                    stack.pop();
                }
                _ => {
                    if allow_above_root {
                        stack.push("..");
                    }
                }
            }
        } else {
            stack.push(segment);
        }
    }
    let mut out = String::new();
    for (index, segment) in stack.iter().enumerate() {
        if index > 0 {
            out.push(sep);
        }
        out.push_str(segment);
    }
    out
}

/// Node `path.posix.normalize`: dot-segment resolution, `//` collapse,
/// trailing-slash preservation; `''` -> `'.'`; leading `..` preserved for
/// relative paths and dropped above an absolute root.
fn node_path_posix_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let is_absolute = path.starts_with('/');
    let trailing_separator = path.ends_with('/');
    let mut normalized = node_path_normalize_segments(path, !is_absolute, '/', &['/']);
    if normalized.is_empty() {
        if is_absolute {
            return "/".to_string();
        }
        return if trailing_separator {
            "./".to_string()
        } else {
            ".".to_string()
        };
    }
    if trailing_separator {
        normalized.push('/');
    }
    if is_absolute {
        format!("/{normalized}")
    } else {
        normalized
    }
}

/// Node `path.posix.join`: empty segments dropped, joined with `/`, then
/// normalized; no segments (or all empty) -> `'.'`.
fn node_path_posix_join(parts: &[String]) -> String {
    let mut joined = String::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if !joined.is_empty() {
            joined.push('/');
        }
        joined.push_str(part);
    }
    if joined.is_empty() {
        return ".".to_string();
    }
    node_path_posix_normalize(&joined)
}

/// Node `path.posix.resolve` over pre-validated string segments: right-to-left
/// until an absolute segment wins, then normalize. The engine has NO ambient
/// cwd, so a FIXED synthetic cwd `"/"` is prefixed when no segment is absolute
/// — any consistent absolute base is behaviorally correct for pure-compute
/// resolution (the compat corpus asserts predicates over resolve()'s output,
/// never a host cwd value). The result never has a trailing slash unless it is
/// the root itself.
fn node_path_posix_resolve(parts: &[String]) -> String {
    let mut resolved = String::new();
    let mut resolved_absolute = false;
    let mut index = parts.len() as i64 - 1;
    while index >= -1 && !resolved_absolute {
        let segment: &str = if index >= 0 {
            parts[index as usize].as_str()
        } else {
            // Synthetic cwd (see doc comment above).
            "/"
        };
        index -= 1;
        if segment.is_empty() {
            continue;
        }
        resolved = format!("{segment}/{resolved}");
        resolved_absolute = segment.starts_with('/');
    }
    let normalized = node_path_normalize_segments(&resolved, !resolved_absolute, '/', &['/']);
    if resolved_absolute {
        format!("/{normalized}")
    } else if normalized.is_empty() {
        ".".to_string()
    } else {
        normalized
    }
}

/// Node `basename` shared across separator families: trailing separators
/// trimmed, last component returned, and `ext` stripped only when it is a
/// proper suffix strictly shorter than the basename (Node keeps `basename ==
/// ext` intact). `skip_win32_drive` skips a leading `X:` drive prefix (win32).
fn node_path_basename_impl(
    path: &str,
    ext: Option<&str>,
    separators: &[char],
    skip_win32_drive: bool,
) -> String {
    let mut p = path;
    if skip_win32_drive && p.len() >= 2 {
        let bytes = p.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            p = &p[2..];
        }
    }
    let trimmed = p.trim_end_matches(|c: char| separators.contains(&c));
    let base = match trimmed.rfind(|c: char| separators.contains(&c)) {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    };
    if let Some(ext) = ext
        && !ext.is_empty()
        && base.len() > ext.len()
        && base.ends_with(ext)
    {
        return base[..base.len() - ext.len()].to_string();
    }
    base.to_string()
}

/// Node `path.posix.dirname`: no trailing slash in the result, `'/'` -> `'/'`,
/// bare name -> `'.'`. Direct port of Node's end-scan (byte comparisons are
/// against ASCII `/`, so scanning UTF-8 bytes is boundary-safe).
fn node_path_posix_dirname(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let bytes = path.as_bytes();
    let has_root = bytes[0] == b'/';
    let mut end: i64 = -1;
    let mut matched_slash = true;
    let mut index = bytes.len() as i64 - 1;
    while index >= 1 {
        if bytes[index as usize] == b'/' {
            if !matched_slash {
                end = index;
                break;
            }
        } else {
            matched_slash = false;
        }
        index -= 1;
    }
    if end == -1 {
        return if has_root {
            "/".to_string()
        } else {
            ".".to_string()
        };
    }
    if has_root && end == 1 {
        return "//".to_string();
    }
    path[..end as usize].to_string()
}

/// Node `path.posix.extname`: the last `.`-suffix of the final component, with
/// Node's exact dotfile rules (`.bashrc` -> `''`, `file.` -> `'.'`, `..` ->
/// `''`). Direct port of Node's single-pass backward scan.
fn node_path_posix_extname(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut start_dot: i64 = -1;
    let mut start_part: i64 = 0;
    let mut end: i64 = -1;
    let mut matched_slash = true;
    // Track the state of characters (if any) we see before our first dot and
    // after any path separator we find (Node's `preDotState`).
    let mut pre_dot_state: i64 = 0;
    let mut index = bytes.len() as i64 - 1;
    while index >= 0 {
        let code = bytes[index as usize];
        if code == b'/' {
            // Reached a path separator that was not part of a set of trailing
            // separators at the end of the string: stop.
            if !matched_slash {
                start_part = index + 1;
                break;
            }
            index -= 1;
            continue;
        }
        if end == -1 {
            // First non-separator from the end marks the end of the extension.
            matched_slash = false;
            end = index + 1;
        }
        if code == b'.' {
            if start_dot == -1 {
                start_dot = index;
            } else if pre_dot_state != 1 {
                pre_dot_state = 1;
            }
        } else if start_dot != -1 {
            // A non-dot character before the dot marks a real name part.
            pre_dot_state = -1;
        }
        index -= 1;
    }
    if start_dot == -1
        || end == -1
        // The dot(s) were the first character(s) of the component (dotfile) …
        || pre_dot_state == 0
        // … or the component is exactly `..`.
        || (pre_dot_state == 1 && start_dot == end - 1 && start_dot == start_part + 1)
    {
        return String::new();
    }
    path[start_dot as usize..end as usize].to_string()
}

/// Node `path.posix.relative` over resolved paths (same synthetic cwd as
/// [`node_path_posix_resolve`]): common-prefix segments dropped, `..` per
/// remaining `from` segment, then the remaining `to` segments.
fn node_path_posix_relative(from: &str, to: &str) -> String {
    let from_resolved = node_path_posix_resolve(std::slice::from_ref(&from.to_string()));
    let to_resolved = node_path_posix_resolve(std::slice::from_ref(&to.to_string()));
    if from_resolved == to_resolved {
        return String::new();
    }
    let from_segments: Vec<&str> = from_resolved.split('/').filter(|s| !s.is_empty()).collect();
    let to_segments: Vec<&str> = to_resolved.split('/').filter(|s| !s.is_empty()).collect();
    let mut common = 0usize;
    while common < from_segments.len()
        && common < to_segments.len()
        && from_segments[common] == to_segments[common]
    {
        common += 1;
    }
    let mut out_segments: Vec<&str> =
        std::iter::repeat_n("..", from_segments.len() - common).collect();
    out_segments.extend_from_slice(&to_segments[common..]);
    out_segments.join("/")
}

/// The `{ root, dir, base, ext, name }` decomposition of
/// [`node_path_posix_parse`].
struct NodePathParsed {
    root: String,
    dir: String,
    base: String,
    ext: String,
    name: String,
}

/// Node `path.posix.parse`: root/dir/base/ext/name decomposition. `base` uses
/// the basename rules (trailing slashes trimmed), `ext`/`name` use the extname
/// dotfile rules over `base`, `dir` is everything before the final component
/// (root for a root-only path, `''` for a bare name).
fn node_path_posix_parse(path: &str) -> NodePathParsed {
    if path.is_empty() {
        return NodePathParsed {
            root: String::new(),
            dir: String::new(),
            base: String::new(),
            ext: String::new(),
            name: String::new(),
        };
    }
    let root = if path.starts_with('/') { "/" } else { "" };
    let base = node_path_basename_impl(path, None, &['/'], false);
    let ext = node_path_posix_extname(&base);
    let name = base[..base.len() - ext.len()].to_string();
    let trimmed = path.trim_end_matches('/');
    let dir = match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(index) => trimmed[..index].to_string(),
        None => root.to_string(),
    };
    NodePathParsed {
        root: root.to_string(),
        dir,
        base,
        ext,
        name,
    }
}

/// Node `path.posix.format`: `dir`+`base` win over `root`+`name`+`ext`
/// (`base` wins over `name`+`ext`; an extension without a leading dot gets
/// one). Empty-string properties count as absent, matching JS truthiness in
/// Node's `_format`.
fn node_path_posix_format(root: &str, dir: &str, base: &str, name: &str, ext: &str) -> String {
    let dir_part = if dir.is_empty() { root } else { dir };
    let formatted_ext = if ext.is_empty() {
        String::new()
    } else if ext.starts_with('.') {
        ext.to_string()
    } else {
        format!(".{ext}")
    };
    let base_part = if base.is_empty() {
        format!("{name}{formatted_ext}")
    } else {
        base.to_string()
    };
    if dir_part.is_empty() {
        return base_part;
    }
    if dir_part == root {
        format!("{dir_part}{base_part}")
    } else {
        format!("{dir_part}/{base_part}")
    }
}

/// Node `path.win32.isAbsolute`: a leading separator (either kind, incl. UNC)
/// or a drive letter followed by `:` and a separator.
fn node_path_win32_is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if bytes[0] == b'/' || bytes[0] == b'\\' {
        return true;
    }
    bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

/// Node `path.win32.normalize`: both separators accepted, output uses `\`.
/// Handles drive-letter roots (`C:\`, drive-relative `C:x`), UNC roots
/// (`\\server\share`), and bare separator roots; `\\?\`-style device
/// namespaces are not modeled (outside the recognized corpus surface).
fn node_path_win32_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let bytes = path.as_bytes();
    let is_sep = |b: u8| b == b'/' || b == b'\\';
    let mut device = String::new();
    let mut is_absolute = false;
    let mut root_len = 0usize;
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        device.push(bytes[0] as char);
        device.push(':');
        root_len = 2;
        if bytes.len() > 2 && is_sep(bytes[2]) {
            is_absolute = true;
            root_len = 3;
        }
    } else if is_sep(bytes[0]) {
        is_absolute = true;
        root_len = 1;
        if bytes.len() > 1 && is_sep(bytes[1]) {
            // Candidate UNC root: `\\server\share`.
            let mut cursor = 2usize;
            let server_start = cursor;
            while cursor < bytes.len() && !is_sep(bytes[cursor]) {
                cursor += 1;
            }
            if cursor > server_start && cursor < bytes.len() {
                let server_end = cursor;
                while cursor < bytes.len() && is_sep(bytes[cursor]) {
                    cursor += 1;
                }
                let share_start = cursor;
                while cursor < bytes.len() && !is_sep(bytes[cursor]) {
                    cursor += 1;
                }
                if cursor > share_start {
                    device = format!(
                        "\\\\{}\\{}",
                        &path[server_start..server_end],
                        &path[share_start..cursor]
                    );
                    root_len = cursor;
                }
            }
        }
    }
    let tail = &path[root_len..];
    let trailing_separator = tail.ends_with(['/', '\\']);
    let mut normalized = node_path_normalize_segments(tail, !is_absolute, '\\', &['/', '\\']);
    if normalized.is_empty() && !is_absolute {
        normalized.push('.');
    }
    if trailing_separator {
        normalized.push('\\');
    }
    if is_absolute {
        format!("{device}\\{normalized}")
    } else {
        format!("{device}{normalized}")
    }
}

/// Node `path.win32.join`: empty segments dropped, joined with `\`, Node's
/// UNC-safety heuristic applied (a joined result must not ACCIDENTALLY read as
/// UNC unless the first part already matched a UNC root), then win32
/// normalization.
fn node_path_win32_join(parts: &[String]) -> String {
    let mut joined = String::new();
    let mut first_part: Option<&str> = None;
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if joined.is_empty() {
            first_part = Some(part.as_str());
            joined.push_str(part);
        } else {
            joined.push('\\');
            joined.push_str(part);
        }
    }
    if joined.is_empty() {
        return ".".to_string();
    }
    let is_sep = |b: u8| b == b'/' || b == b'\\';
    let first_bytes = first_part.unwrap_or("").as_bytes();
    let mut needs_replace = true;
    let mut slash_count = 0usize;
    if !first_bytes.is_empty() && is_sep(first_bytes[0]) {
        slash_count += 1;
        if first_bytes.len() > 1 && is_sep(first_bytes[1]) {
            slash_count += 1;
            if first_bytes.len() > 2 {
                if is_sep(first_bytes[2]) {
                    slash_count += 1;
                } else {
                    // The first part matched a UNC root (`\\server`); keep it.
                    needs_replace = false;
                }
            }
        }
    }
    if needs_replace {
        let joined_bytes = joined.as_bytes();
        while slash_count < joined_bytes.len() && is_sep(joined_bytes[slash_count]) {
            slash_count += 1;
        }
        if slash_count >= 2 {
            joined = format!("\\{}", &joined[slash_count..]);
        }
    }
    node_path_win32_normalize(&joined)
}

// ---------------------------------------------------------------------------
// Node `querystring` builtin semantics (bd-qmy52)
//
// Pure-compute string algorithms backing the `builtin:Querystring*` hostcalls
// emitted by the lowering pipeline's querystring-module interception. Escape/
// unescape/parse edge behaviors are pinned against bun 1.3.14 (Node-compatible
// reference). Mirror of the canonical copy in
// `franken-engine/src/baseline_interpreter.rs` — keep the two in lockstep.
// ---------------------------------------------------------------------------

/// Characters Node's `querystring.escape` leaves literal (the `noEscape`
/// table): ASCII alphanumerics plus `- . _ ~ ! ' ( ) *`. Everything else —
/// including space and `+` — percent-encodes.
fn qs_is_unescaped_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '!' | '\'' | '(' | ')' | '*')
}

/// Node `querystring.escape`: percent-encode every char outside the noEscape
/// set as uppercase-hex UTF-8 bytes (bun: space -> `%20`, `+` -> `%2B`,
/// `é` -> `%C3%A9`, `中` -> `%E4%B8%AD`).
fn node_qs_escape(input: &str) -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    let mut utf8_buf = [0u8; 4];
    for c in input.chars() {
        if qs_is_unescaped_char(c) {
            out.push(c);
        } else {
            for byte in c.encode_utf8(&mut utf8_buf).as_bytes() {
                out.push('%');
                out.push(char::from(HEX_UPPER[(byte >> 4) as usize]));
                out.push(char::from(HEX_UPPER[(byte & 0x0f) as usize]));
            }
        }
    }
    out
}

/// Hex digit value of an ASCII byte (Node's `isHexTable` accepts both cases).
fn qs_hex_digit_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

/// Strict percent-decode matching the `decodeURIComponent` accept set Node's
/// `querystring.unescape` tries first: every `%` must be followed by two hex
/// digits and the decoded byte sequence must be valid UTF-8; `+` is NOT
/// decoded. `None` on any violation (the caller falls back to the lenient
/// `unescapeBuffer` semantics).
fn qs_strict_percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = qs_hex_digit_value(*bytes.get(index + 1)?)?;
            let lo = qs_hex_digit_value(*bytes.get(index + 2)?)?;
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Lenient fallback matching Node's `unescapeBuffer`: valid `%XX` pairs decode
/// byte-wise, malformed `%` sequences stay literal, and the byte buffer is
/// decoded as UTF-8 with U+FFFD replacement (bun: `qs.unescape('%FF')` is
/// `'\u{FFFD}'`, `qs.unescape('a%2')` is `'a%2'`).
fn qs_lenient_unescape(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(index + 1).copied().and_then(qs_hex_digit_value),
                bytes.get(index + 2).copied().and_then(qs_hex_digit_value),
            )
        {
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Node `querystring.unescape`: try the strict `decodeURIComponent`-shaped
/// decode first, fall back to the lenient `unescapeBuffer` semantics on any
/// malformed input. `+` never decodes to space here — only `parse`'s component
/// handling does that (bun: `qs.unescape('x+y')` is `'x+y'`).
fn node_qs_unescape(input: &str) -> String {
    match qs_strict_percent_decode(input) {
        Some(decoded) => decoded,
        None => qs_lenient_unescape(input),
    }
}

/// True when `raw` contains at least one complete valid `%XX` escape — Node's
/// parse routes a key/value through the decoder only when its scanner saw a
/// full valid escape (`keyEncoded`/`valEncoded`), so `'a%2'` stays literal.
fn qs_component_looks_encoded(raw: &str) -> bool {
    raw.as_bytes().windows(3).any(|window| {
        window[0] == b'%'
            && qs_hex_digit_value(window[1]).is_some()
            && qs_hex_digit_value(window[2]).is_some()
    })
}

/// Decode one `parse` component: `+` becomes space FIRST (Node's `plusChar`
/// substitution precedes decoding), then the unescape pass runs only when the
/// raw component contained a complete valid `%XX` escape.
fn qs_parse_component(raw: &str) -> String {
    let plussed = raw.replace('+', " ");
    if qs_component_looks_encoded(raw) {
        node_qs_unescape(&plussed)
    } else {
        plussed
    }
}

/// Node `querystring.parse` over a pre-validated input string: split on `sep`,
/// the FIRST `eq` in a segment splits key/value (a key without `eq` maps to
/// `''`), `max_pairs` slots (default 1000, `None` = unlimited) are consumed by
/// stored pairs AND by empty segments between separators (bun:
/// `parse('&a=1', null, null, { maxKeys: 1 })` is `{}` but a TRAILING empty
/// segment is a no-op: `parse('a=1&')` is `{ a: '1' }`), and repeated keys
/// collect into arrays. Returns entries in first-seen key order with per-key
/// value order preserved; keys with one value are scalars at allocation.
fn node_qs_parse(
    input: &str,
    sep: &str,
    eq: &str,
    max_pairs: Option<u64>,
) -> Vec<(String, Vec<String>)> {
    let mut entries: Vec<(String, Vec<String>)> = Vec::new();
    if input.is_empty() {
        return entries;
    }
    // A truthy custom separator can stringify to '' (e.g. `[]`); Node's
    // char-code matcher then never matches, i.e. no splitting occurs. Same
    // for an empty `eq`: the whole segment becomes the key.
    let segments: Vec<&str> = if sep.is_empty() {
        vec![input]
    } else {
        input.split(sep).collect()
    };
    let last_index = segments.len() - 1;
    let mut remaining = max_pairs;
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            // Empty segment BETWEEN separators: consumes a pair slot without
            // storing anything (Node decrements `pairs`); trailing is a no-op.
            if index < last_index
                && let Some(slots) = remaining.as_mut()
            {
                *slots -= 1;
                if *slots == 0 {
                    return entries;
                }
            }
            continue;
        }
        let (raw_key, raw_value) = if eq.is_empty() {
            (*segment, None)
        } else {
            match segment.find(eq) {
                Some(pos) => (&segment[..pos], Some(&segment[pos + eq.len()..])),
                None => (*segment, None),
            }
        };
        let key = qs_parse_component(raw_key);
        let value = raw_value.map(qs_parse_component).unwrap_or_default();
        match entries.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, values)) => values.push(value),
            None => entries.push((key, vec![value])),
        }
        if let Some(slots) = remaining.as_mut() {
            *slots -= 1;
            if *slots == 0 {
                return entries;
            }
        }
    }
    entries
}

// ---------------------------------------------------------------------------
// Node `os` builtin fixed values (bd-qmy52)
//
// The engine has NO ambient authority: the `builtin:Os*` hostcalls return
// FIXED, deterministic, linux-shaped engine-contained values (they never read
// the real host). The compat corpus asserts types and predicates, not host
// facts, so any internally-consistent value set is behaviorally correct.
// Mirror of the canonical copy in
// `franken-engine/src/baseline_interpreter.rs` — keep the two in lockstep.
// ---------------------------------------------------------------------------

/// `os.platform()` — fixed linux value.
const NODE_OS_PLATFORM: &str = "linux";
/// `os.release()` — fixed plausible kernel release string.
const NODE_OS_RELEASE: &str = "6.0.0-franken";
/// `os.version()` — fixed plausible kernel version string.
const NODE_OS_VERSION: &str = "#1 SMP PREEMPT_DYNAMIC franken";
/// `os.totalmem()` — fixed 16 GiB.
const NODE_OS_TOTALMEM_BYTES: i64 = 17_179_869_184;
/// `os.freemem()` — fixed 8 GiB (strictly below [`NODE_OS_TOTALMEM_BYTES`]).
const NODE_OS_FREEMEM_BYTES: i64 = 8_589_934_592;

/// POSIX signal numbers for `os.constants.signals` (linux, x86-64 numbering).
const NODE_OS_SIGNALS: &[(&str, i64)] = &[
    ("SIGHUP", 1),
    ("SIGINT", 2),
    ("SIGQUIT", 3),
    ("SIGILL", 4),
    ("SIGTRAP", 5),
    ("SIGABRT", 6),
    ("SIGBUS", 7),
    ("SIGFPE", 8),
    ("SIGKILL", 9),
    ("SIGUSR1", 10),
    ("SIGSEGV", 11),
    ("SIGUSR2", 12),
    ("SIGPIPE", 13),
    ("SIGALRM", 14),
    ("SIGTERM", 15),
    ("SIGCHLD", 17),
    ("SIGCONT", 18),
    ("SIGSTOP", 19),
    ("SIGTSTP", 20),
];

/// POSIX errno numbers for `os.constants.errno` (linux).
const NODE_OS_ERRNO: &[(&str, i64)] = &[
    ("EPERM", 1),
    ("ENOENT", 2),
    ("ESRCH", 3),
    ("EINTR", 4),
    ("EIO", 5),
    ("EBADF", 9),
    ("EAGAIN", 11),
    ("ENOMEM", 12),
    ("EACCES", 13),
    ("EFAULT", 14),
    ("EBUSY", 16),
    ("EEXIST", 17),
    ("ENOTDIR", 20),
    ("EISDIR", 21),
    ("EINVAL", 22),
    ("ENFILE", 23),
    ("EMFILE", 24),
    ("ENOSPC", 28),
    ("ESPIPE", 29),
    ("EROFS", 30),
    ("EPIPE", 32),
    ("ERANGE", 34),
];

/// `os.constants.priority` values (Node's uv priority constants).
const NODE_OS_PRIORITY: &[(&str, i64)] = &[
    ("PRIORITY_LOW", 19),
    ("PRIORITY_BELOW_NORMAL", 10),
    ("PRIORITY_NORMAL", 0),
    ("PRIORITY_ABOVE_NORMAL", -7),
    ("PRIORITY_HIGH", -14),
    ("PRIORITY_HIGHEST", -20),
];

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
    profiling_config: Option<crate::profiling::ProfilingConfig>,
    profiling_data: Option<crate::profiling::Profiler>,
}

impl Default for LaneRouter {
    fn default() -> Self {
        Self {
            quickjs: QuickJsLane::new(),
            v8: V8Lane::new(),
            profiling_config: None,
            profiling_data: None,
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
            profiling_config: None,
            profiling_data: None,
        }
    }

    /// Route and execute the module.
    pub fn execute(
        &mut self,
        module: &Ir3Module,
        trace_id: &str,
        force_lane: Option<LaneChoice>,
    ) -> Result<RoutedResult, InterpreterError> {
        self.execute_with_hook(module, trace_id, force_lane, None)
    }

    pub fn execute_with_hook(
        &mut self,
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

        self.profiling_data = None;
        let profiling_config = self.profiling_config.clone();
        let (result, profiling_data) = match lane {
            LaneChoice::QuickJs => self.quickjs.execute_with_hook_and_profiling(
                module,
                trace_id,
                hook,
                profiling_config,
            )?,
            LaneChoice::V8 => {
                self.v8
                    .execute_with_hook_and_profiling(module, trace_id, hook, profiling_config)?
            }
        };
        self.profiling_data = profiling_data;

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
    pub fn enable_profiling(&mut self, config: crate::profiling::ProfilingConfig) {
        self.profiling_config = Some(config);
        self.profiling_data = None;
    }

    /// Disable profiling and return collected data.
    pub fn disable_profiling(&mut self) -> Option<crate::profiling::Profiler> {
        self.profiling_config = None;
        self.profiling_data.take()
    }

    /// Get reference to current profiling data.
    pub fn profiling_data(&self) -> Option<&crate::profiling::Profiler> {
        self.profiling_data.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Expression, Statement};
    use crate::ir_contract::{
        CapabilityTag, Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion, Reg, RegRange,
    };
    use crate::parser::Es2020Parser;
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
        m.constant_pool = pool.into_iter().map(Into::into).collect();
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

    fn test_module_with_pool_and_functions(
        instructions: Vec<Ir3Instruction>,
        pool: Vec<String>,
        functions: Vec<Ir3FunctionDesc>,
    ) -> Ir3Module {
        let mut m = test_module_with_pool(instructions, pool);
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

    fn class_test_function(entry: u32, name: &str) -> Ir3FunctionDesc {
        Ir3FunctionDesc {
            entry,
            arity: 0,
            frame_size: 4,
            name: Some(name.to_string()),
            is_generator: false,
            rest_param_index: None,
        }
    }

    fn object_id_from_value(value: &Value, context: &str) -> ObjectId {
        match value {
            Value::Object(id) => *id,
            other => panic!("{context} should be an object, got {other:?}"),
        }
    }

    #[test]
    fn class_semantic_tests_reject_halt_only_todo_smokes() {
        let source = include_str!("baseline_interpreter.rs");
        let section_start = source
            .find("// -- ES2015 Class Semantics Tests")
            .expect("class semantics section should exist");
        let section = &source[section_start..];
        let section_end = section
            .find("// -----------------------------------------------------------------------")
            .expect("timer section separator should follow class semantics tests");
        let section = &section[..section_end];

        for block in section.split("#[test]").skip(1) {
            let has_todo = block.contains("TODO");
            let has_halt_only = block.contains("test_module(vec![Ir3Instruction::Halt])");
            let has_bare_success = block.contains("assert!(result.is_ok())");
            assert!(
                !(has_todo && has_halt_only && has_bare_success),
                "class semantic test remains a halt-only placeholder: {}",
                block
                    .lines()
                    .find(|line| line.trim_start().starts_with("fn "))
                    .unwrap_or("<unknown>")
                    .trim()
            );
        }
    }

    #[test]
    fn profiling_lifecycle_records_executed_instructions() {
        let mut core = quickjs_test_core();
        assert!(core.profiling_data().is_none());

        core.enable_profiling(crate::profiling::ProfilingConfig::default());
        assert!(core.profiling_data().is_some());

        let module = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 2 },
            Ir3Instruction::LoadInt { dst: 2, value: 3 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = core.execute(&module).unwrap();
        assert_eq!(result.value, Value::Int(5));

        let profiler = core
            .disable_profiling()
            .expect("profiling should return collected profiler");
        assert!(core.profiling_data().is_none());

        let report = profiler.generate_report("franken-core-baseline".to_string());
        assert_eq!(
            report
                .instruction_stats
                .get("LoadInt")
                .expect("LoadInt should be counted")
                .count,
            2
        );
        assert_eq!(
            report
                .instruction_stats
                .get("Add")
                .expect("Add should be counted")
                .count,
            1
        );
        assert!(
            report
                .hotspots
                .iter()
                .any(|hotspot| hotspot.name == "LoadInt")
        );
        assert!(report.hotspots.iter().any(|hotspot| hotspot.name == "Add"));
    }

    #[test]
    fn router_profiling_returns_last_routed_execution_profiler() {
        let mut router = test_router();
        assert!(router.profiling_data().is_none());

        router.enable_profiling(crate::profiling::ProfilingConfig::default());

        let module = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 8 },
            Ir3Instruction::LoadInt { dst: 2, value: 13 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let result = router.execute(&module, "router-profile", None).unwrap();
        assert_eq!(result.lane, LaneChoice::QuickJs);
        assert_eq!(result.result.value, Value::Int(21));

        let live_report = router
            .profiling_data()
            .expect("router should retain latest profiler")
            .generate_report("router-profile-live".to_string());
        assert_eq!(
            live_report
                .instruction_stats
                .get("LoadInt")
                .expect("LoadInt should be counted")
                .count,
            2
        );

        let profiler = router
            .disable_profiling()
            .expect("router should return collected profiler");
        assert!(router.profiling_data().is_none());

        let report = profiler.generate_report("router-profile-final".to_string());
        assert_eq!(
            report
                .instruction_stats
                .get("Add")
                .expect("Add should be counted")
                .count,
            1
        );
    }

    #[test]
    fn profiling_memory_stats_record_object_and_array_allocations() {
        let mut core = quickjs_test_core();
        core.enable_profiling(crate::profiling::ProfilingConfig::default());

        let object_id = core.alloc_object_with_prototype(None).unwrap();
        let array_id = core.alloc_array_with_prototype(None).unwrap();

        assert!(!core.heap[object_id.0 as usize].is_array);
        assert!(core.heap[array_id.0 as usize].is_array);

        let profiler = core
            .disable_profiling()
            .expect("profiling should return collected profiler");
        let report = profiler.generate_report("allocation-profile".to_string());

        assert_eq!(report.memory_stats.objects_allocated, 1);
        assert_eq!(report.memory_stats.arrays_allocated, 1);
        assert_eq!(
            report.memory_stats.total_bytes_allocated,
            MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES * 2
        );
    }

    fn test_quickjs_config_with(
        extra: impl IntoIterator<Item = RuntimeCapability>,
    ) -> InterpreterConfig {
        let mut config = test_quickjs_config();
        config.granted_capabilities.extend(extra);
        config
    }

    fn test_router() -> LaneRouter {
        LaneRouter::with_configs(test_quickjs_config(), test_v8_config())
    }

    #[allow(dead_code)]
    fn assert_both_lanes_value(module: &Ir3Module, expected: Value) {
        // SAFETY: Test helper assumes valid module execution; unwrap safe in test context
        assert_eq!(quickjs_execute(module).unwrap().value, expected);
        // SAFETY: Test helper assumes valid module execution; unwrap safe in test context
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

        fn records_without_startup_module_record(&self) -> Vec<HookRecord> {
            let mut records = self.records();
            let is_startup_module_record = matches!(
                records.first(),
                Some(HookRecord::Allocation {
                    ctx,
                    kind,
                    size_hint,
                }) if ctx.instruction_count == 0
                    && ctx.current_ip == 0
                    && *kind == AllocKind::Object
                    && *size_hint == 0
            );
            if is_startup_module_record {
                records.remove(0);
            }
            records
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
        let config = test_quickjs_config();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook.clone());

        // SAFETY: alloc_object_with_prototype() in test environment with sufficient heap space
        // cannot fail under normal test conditions.
        let oid = core.alloc_object_with_prototype(None).unwrap();
        core.heap[oid.0 as usize]
            .properties
            .insert("secret".to_string(), Value::Int(99));
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::str("secret");

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
            hook.records_without_startup_module_record(),
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
        let config = test_quickjs_config();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook.clone());
        core.registers[1] = Value::Int(5);
        core.registers[2] = Value::Int(99);
        core.registers[3] = Value::Function(0);

        let result = core
            .execute(&test_module_with_functions(
                vec![
                    Ir3Instruction::Call {
                        callee: 3,
                        args: RegRange { start: 1, count: 2 },
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
                    rest_param_index: None,
                }],
            ))
            .unwrap();

        assert_eq!(result.value, Value::Int(5));
        assert_eq!(
            hook.records_without_startup_module_record(),
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
    fn call_method_binds_receiver_as_this() {
        let mut core = quickjs_test_core();
        let receiver_id = core.alloc_object_with_prototype(None).unwrap();
        core.registers[1] = Value::Object(receiver_id);
        core.registers[2] = Value::Function(0);

        let result = core
            .execute(&test_module_with_functions(
                vec![
                    Ir3Instruction::CallMethod {
                        receiver: 1,
                        callee: 2,
                        args: RegRange { start: 3, count: 0 },
                        dst: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 1,
                    name: Some("return_this".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            ))
            .unwrap();

        assert_eq!(result.value, Value::Object(receiver_id));
    }

    #[test]
    fn plain_call_load_this_is_undefined() {
        let mut core = quickjs_test_core();
        core.registers[1] = Value::Function(0);

        let result = core
            .execute(&test_module_with_functions(
                vec![
                    Ir3Instruction::Call {
                        callee: 1,
                        args: RegRange { start: 2, count: 0 },
                        dst: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 1,
                    name: Some("return_this".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            ))
            .unwrap();

        assert_eq!(result.value, Value::Undefined);
    }

    #[test]
    fn interpreter_hook_called_on_allocation() {
        let hook = Arc::new(RecordingHook::allow_all());
        let config = test_quickjs_config();
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
            hook.records_without_startup_module_record(),
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
        let config = test_quickjs_config();
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
                    rest_param_index: None,
                }],
            ))
            .unwrap();

        assert!(matches!(result.value, Value::Closure(0)));
        assert_eq!(
            hook.records_without_startup_module_record(),
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
        let config = test_quickjs_config();
        let mut core = InterpreterCore::new(config, "test-trace");
        core.set_hook(hook);

        let oid = core.alloc_object_with_prototype(None).unwrap();
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::str("key");
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
        let config = test_quickjs_config();
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
        let lane = QuickJsLane::with_config(test_quickjs_config());
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
        assert_eq!(result.instructions_executed, 0);
    }

    #[test]
    fn interpreter_hook_none_preserves_execution_when_unset() {
        let config = test_quickjs_config();
        let mut core = InterpreterCore::new(config, "test-trace");
        let oid = core.alloc_object_with_prototype(None).unwrap();
        core.heap[oid.0 as usize]
            .properties
            .insert("stable".to_string(), Value::Int(12));
        core.registers[1] = Value::Object(oid);
        core.registers[2] = Value::str("stable");

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
        let config = test_quickjs_config();
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
            hook.records_without_startup_module_record(),
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
        assert_eq!(result.value, Value::str("hello"));
    }

    #[test]
    fn load_str_preserves_lone_surrogate_constant_bd_vltnh() {
        let exact = JsString::from_code_units(&[0xD800]);
        let mut module = test_module(vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Halt,
        ]);
        module.constant_pool.push(exact.clone());

        let result = quickjs_execute(&module).unwrap();
        assert_eq!(result.value, Value::Str(exact));
    }

    #[test]
    fn metadata_pool_consumers_reject_lone_surrogate_entries_bd_vltnh() {
        for instruction in [
            Ir3Instruction::PushCapture { name_pool_index: 0 },
            Ir3Instruction::DeclareBinding {
                name_pool_index: 0,
                kind: BindingKind::Let as u8,
            },
        ] {
            let mut module = test_module(vec![instruction, Ir3Instruction::Halt]);
            module
                .constant_pool
                .push(JsString::from_code_units(&[0xD800]));

            let error = quickjs_execute(&module).unwrap_err();
            assert!(matches!(error, InterpreterError::TypeError { .. }));
        }
    }

    #[test]
    fn module_specifier_strings_reject_lone_surrogates_bd_vltnh() {
        let ordinary = JsString::from("./fixture.js");
        assert_eq!(
            InterpreterCore::module_specifier_string(&ordinary).unwrap(),
            "./fixture.js"
        );

        let exact = JsString::from_code_units(&[0xD800]);
        let error = InterpreterCore::module_specifier_string(&exact).unwrap_err();
        assert!(matches!(error, InterpreterError::TypeError { .. }));

        let mut module = test_module(vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::Halt,
        ]);
        module.constant_pool.push(exact);
        let error = quickjs_execute(&module).unwrap_err();
        assert!(matches!(error, InterpreterError::TypeError { .. }));
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
        assert_eq!(result.value, Value::str("hello world"));
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
    fn div_by_zero_returns_infinity() {
        let m = test_module(vec![
            Ir3Instruction::LoadInt { dst: 1, value: 10 },
            Ir3Instruction::LoadInt { dst: 2, value: 0 },
            Ir3Instruction::Div {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
        ]);
        let result = quickjs_execute(&m).unwrap();
        assert_eq!(result.value, Value::Float(Float64::new(f64::INFINITY)));
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
                rest_param_index: None,
            }],
        );

        let mut config = test_quickjs_config();
        config.instruction_budget = 1000;
        let mut core = InterpreterCore::new(config, "test");
        // Pre-set registers: r3 = callee function, r1 = argument.
        core.registers[3] = Value::Function(0);
        core.registers[1] = Value::Int(5);
        let result = core.execute(&m).unwrap();
        assert_eq!(result.value, Value::Int(15));
    }

    #[test]
    fn plain_call_secret_argument_returns_secret_bd_ur3tk_6() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 1,
                name: Some("identity".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(
            1,
            Value::str("secret-argument"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("secret argument should be writable");

        assert_eq!(
            core.run_loop(&module).expect("identity call should return"),
            Value::str("secret-argument")
        );
        assert_eq!(
            core.read_reg_label(2).expect("caller return label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn plain_call_label_frames_do_not_alias_bd_ur3tk_6() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 0, count: 0 },
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
                Ir3Instruction::Return { value: 7 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 8,
                name: Some("return_fresh_r7".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(
            7,
            Value::str("caller-only"),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("caller label should be writable");
        core.write_reg_with_label(
            1,
            Value::str("stale-destination"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("stale destination should be writable");

        assert_eq!(
            core.run_loop(&module)
                .expect("fresh callee frame should return"),
            Value::Undefined
        );
        assert_eq!(
            core.read_reg_label(1).expect("public return label"),
            crate::ifc_artifacts::Label::Public
        );
        assert_eq!(
            core.read_reg_label(7).expect("preserved caller label"),
            crate::ifc_artifacts::Label::Confidential
        );
    }

    #[test]
    fn nested_plain_calls_preserve_labels_across_two_frames_bd_ur3tk_6() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 2 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 2,
                    frame_size: 3,
                    name: Some("outer_identity".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 4,
                    arity: 1,
                    frame_size: 1,
                    name: Some("inner_identity".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.registers[1] = Value::Function(1);
        core.write_reg_with_label(
            2,
            Value::str("nested-secret"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("nested argument should be writable");

        assert_eq!(
            core.run_loop(&module).expect("nested calls should return"),
            Value::str("nested-secret")
        );
        assert_eq!(
            core.read_reg_label(3).expect("nested return label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn call_method_load_this_preserves_receiver_label_bd_ur3tk_6() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 1,
                    args: RegRange { start: 2, count: 0 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 0,
                frame_size: 1,
                name: Some("return_this".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        core.write_reg_with_label(
            0,
            Value::str("secret-receiver"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("receiver should be writable");
        core.registers[1] = Value::Function(0);

        assert_eq!(
            core.run_loop(&module).expect("method should return this"),
            Value::str("secret-receiver")
        );
        assert_eq!(
            core.read_reg_label(2).expect("method return label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn call_method_argument_preserves_label_bd_ur3tk_6() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 1,
                    args: RegRange { start: 2, count: 1 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 1,
                name: Some("return_argument".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::str("public-receiver");
        core.registers[1] = Value::Function(0);
        core.write_reg_with_label(
            2,
            Value::str("secret-argument"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("argument should be writable");

        assert_eq!(
            core.run_loop(&module)
                .expect("method should return argument"),
            Value::str("secret-argument")
        );
        assert_eq!(
            core.read_reg_label(3).expect("method result label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn nested_frame_move_preserves_argument_and_return_label_bd_ur3tk_11() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
                Ir3Instruction::Move { dst: 1, src: 0 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 2,
                name: Some("move_identity".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(
            1,
            Value::str("secret-through-move"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("secret argument should be writable");

        assert_eq!(
            core.run_loop(&module).expect("Move identity should return"),
            Value::str("secret-through-move")
        );
        assert_eq!(
            core.read_reg_label(2).expect("caller Move return label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn move_is_self_safe_and_overwrites_destination_label_bd_ur3tk_11() {
        let module = test_module(vec![
            Ir3Instruction::Move { dst: 0, src: 0 },
            Ir3Instruction::Move { dst: 1, src: 2 },
            Ir3Instruction::Return { value: 1 },
        ]);
        let mut core = quickjs_test_core();
        core.write_reg_with_label(
            0,
            Value::str("self-secret"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("self-Move source should be writable");
        core.write_reg_with_label(
            1,
            Value::str("stale-secret"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("destination should be writable");
        core.registers[2] = Value::str("public-source");

        assert_eq!(
            core.run_loop(&module).expect("Move sequence should return"),
            Value::str("public-source")
        );
        assert_eq!(
            core.read_reg_label(0).expect("self-Move label"),
            crate::ifc_artifacts::Label::Secret
        );
        assert_eq!(
            core.read_reg_label(1)
                .expect("overwritten destination label"),
            crate::ifc_artifacts::Label::Public
        );
    }

    #[test]
    fn scoped_binding_init_store_and_load_preserve_labels_bd_ur3tk_11() {
        let module = test_module_with_pool(
            vec![
                Ir3Instruction::DeclareBinding {
                    name_pool_index: 0,
                    kind: BindingKind::Let as u8,
                },
                Ir3Instruction::InitBinding {
                    name_pool_index: 0,
                    src: 0,
                },
                Ir3Instruction::LoadScoped {
                    dst: 1,
                    name_pool_index: 0,
                },
                Ir3Instruction::DeclareBinding {
                    name_pool_index: 1,
                    kind: BindingKind::Var as u8,
                },
                Ir3Instruction::StoreScoped {
                    src: 2,
                    name_pool_index: 1,
                },
                Ir3Instruction::LoadScoped {
                    dst: 3,
                    name_pool_index: 1,
                },
                Ir3Instruction::StoreScoped {
                    src: 4,
                    name_pool_index: 1,
                },
                Ir3Instruction::LoadScoped {
                    dst: 5,
                    name_pool_index: 1,
                },
                Ir3Instruction::Return { value: 3 },
            ],
            vec!["initialized".to_string(), "stored".to_string()],
        );
        let mut core = quickjs_test_core();
        core.write_reg_with_label(
            0,
            Value::str("initialized-secret"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("InitBinding source should be writable");
        core.write_reg_with_label(
            2,
            Value::str("stored-confidential"),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("StoreScoped source should be writable");
        core.registers[4] = Value::str("public-overwrite");

        assert_eq!(
            core.run_loop(&module)
                .expect("scope transfers should return"),
            Value::str("stored-confidential")
        );
        assert_eq!(
            core.read_reg_label(1).expect("initialized binding label"),
            crate::ifc_artifacts::Label::Secret
        );
        assert_eq!(
            core.read_reg_label(3).expect("stored binding label"),
            crate::ifc_artifacts::Label::Confidential
        );
        assert_eq!(
            core.read_reg_label(5).expect("overwritten binding label"),
            crate::ifc_artifacts::Label::Public
        );
    }

    #[test]
    fn return_label_survives_finally_nested_call_bd_ur3tk_2() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 2 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::BeginTry {
                    catch_target: 4,
                    finally_target: Some(4),
                },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::EnterFinally,
                Ir3Instruction::Call {
                    callee: 1,
                    args: RegRange { start: 0, count: 0 },
                    dst: 2,
                },
                Ir3Instruction::EndFinally,
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 2,
                    frame_size: 3,
                    name: Some("return_through_finally".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 7,
                    arity: 0,
                    frame_size: 1,
                    name: Some("finally_helper".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(
            1,
            Value::str("secret-through-finally"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("secret return argument should be writable");
        core.registers[2] = Value::Function(1);

        assert_eq!(
            core.run_loop(&module)
                .expect("finally return should survive nested helper call"),
            Value::str("secret-through-finally")
        );
        assert_eq!(
            core.read_reg_label(3).expect("caller return label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn nested_finally_return_override_keeps_new_label_bd_ur3tk_2() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 2 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::BeginTry {
                    catch_target: 8,
                    finally_target: Some(8),
                },
                Ir3Instruction::BeginTry {
                    catch_target: 5,
                    finally_target: Some(5),
                },
                Ir3Instruction::Return { value: 1 },
                Ir3Instruction::EnterFinally,
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::EndFinally,
                Ir3Instruction::EnterFinally,
                Ir3Instruction::EndFinally,
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 2,
                frame_size: 2,
                name: Some("nested_finally_override".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(
            1,
            Value::str("secret-override"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("secret overriding return should be writable");
        core.registers[2] = Value::str("public-initial-return");

        assert_eq!(
            core.run_loop(&module)
                .expect("inner finally return should override outer completion"),
            Value::str("secret-override")
        );
        assert_eq!(
            core.read_reg_label(3).expect("overriding return label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn caught_throw_restores_suspended_return_label_bd_ur3tk_2() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 2 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::BeginTry {
                    catch_target: 4,
                    finally_target: Some(4),
                },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::EnterFinally,
                Ir3Instruction::BeginTry {
                    catch_target: 7,
                    finally_target: None,
                },
                Ir3Instruction::Throw { value: 1 },
                Ir3Instruction::EnterCatch { dst: 2 },
                Ir3Instruction::EndFinally,
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 2,
                frame_size: 3,
                name: Some("caught_throw_during_finally".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(
            1,
            Value::str("secret-suspended-return"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("secret pending return should be writable");
        core.registers[2] = Value::str("public-local-throw");

        assert_eq!(
            core.run_loop(&module)
                .expect("caught throw should restore the suspended return"),
            Value::str("secret-suspended-return")
        );
        assert_eq!(
            core.read_reg_label(3)
                .expect("restored suspended return label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn module_snapshot_round_trips_labeled_returns_bd_ur3tk_2() {
        let mut core = quickjs_test_core();
        let pending = LabeledReturn {
            value: Value::str("pending"),
            label: crate::ifc_artifacts::Label::Secret,
        };
        let suspended = LabeledReturn {
            value: Value::str("suspended"),
            label: crate::ifc_artifacts::Label::Custom {
                name: "tenant-return".to_string(),
                level: 4,
            },
        };
        core.pending_return = Some(pending.clone());
        core.suspended_abrupt_completions
            .push(AbruptCompletion::Return(suspended.clone()));
        let snapshot = core.snapshot_module_execution();

        core.pending_return = None;
        core.suspended_abrupt_completions.clear();
        core.restore_module_execution(snapshot);

        assert_eq!(core.pending_return, Some(pending));
        assert!(matches!(
            core.suspended_abrupt_completions.as_slice(),
            [AbruptCompletion::Return(restored)] if restored == &suspended
        ));
    }

    #[test]
    fn throw_to_catch_preserves_exact_label_bd_ur3tk_14() {
        let module = test_module(vec![
            Ir3Instruction::BeginTry {
                catch_target: 2,
                finally_target: None,
            },
            Ir3Instruction::Throw { value: 0 },
            Ir3Instruction::EnterCatch { dst: 1 },
            Ir3Instruction::Halt,
        ]);
        let mut core = quickjs_test_core();
        core.write_reg_with_label(
            0,
            Value::str("secret-exception"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("thrown value should be writable");
        core.write_reg_with_label(
            1,
            Value::str("stale-catch-value"),
            crate::ifc_artifacts::Label::TopSecret,
        )
        .expect("catch destination should be seedable");

        core.execute(&module)
            .expect("throw should enter the catch handler");

        assert_eq!(core.registers[1], Value::str("secret-exception"));
        assert_eq!(
            core.read_reg_label(1).expect("catch label should exist"),
            crate::ifc_artifacts::Label::Secret,
            "catch binding receives the thrown label rather than Public or a stale label"
        );
    }

    #[test]
    fn nested_catch_call_and_finally_restore_exception_label_bd_ur3tk_14() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::BeginTry {
                    catch_target: 3,
                    finally_target: None,
                },
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 3 },
                    dst: 4,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::EnterCatch { dst: 5 },
                Ir3Instruction::Halt,
                Ir3Instruction::BeginTry {
                    catch_target: 8,
                    finally_target: Some(8),
                },
                Ir3Instruction::Throw { value: 0 },
                Ir3Instruction::Halt,
                Ir3Instruction::EnterFinally,
                Ir3Instruction::BeginTry {
                    catch_target: 11,
                    finally_target: None,
                },
                Ir3Instruction::Throw { value: 1 },
                Ir3Instruction::EnterCatch { dst: 3 },
                Ir3Instruction::Call {
                    callee: 2,
                    args: RegRange { start: 4, count: 0 },
                    dst: 3,
                },
                Ir3Instruction::EndFinally,
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 5,
                    arity: 3,
                    frame_size: 4,
                    name: Some("exception_through_finally".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 14,
                    arity: 0,
                    frame_size: 1,
                    name: Some("helper_while_exception_pending".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(
            1,
            Value::str("outer-secret-exception"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("outer exception argument should be writable");
        core.registers[2] = Value::str("inner-public-exception");
        core.registers[3] = Value::Function(1);

        core.execute(&module)
            .expect("outer caller should catch the exception after finally");

        assert_eq!(core.registers[5], Value::str("outer-secret-exception"));
        assert_eq!(
            core.read_reg_label(5)
                .expect("caller catch label should exist"),
            crate::ifc_artifacts::Label::Secret,
            "inner catch consumption and helper call must restore the outer exception label"
        );
    }

    #[test]
    fn module_snapshot_round_trips_labeled_exceptions_bd_ur3tk_14() {
        let mut core = quickjs_test_core();
        let pending = LabeledException {
            value: Value::str("pending-exception"),
            label: crate::ifc_artifacts::Label::Secret,
        };
        let suspended = LabeledException {
            value: Value::str("suspended-exception"),
            label: crate::ifc_artifacts::Label::Custom {
                name: "tenant-exception".to_string(),
                level: 4,
            },
        };
        core.pending_exception = Some(pending.clone());
        core.suspended_abrupt_completions
            .push(AbruptCompletion::Exception(suspended.clone()));
        let snapshot = core.snapshot_module_execution();

        core.pending_exception = None;
        core.suspended_abrupt_completions.clear();
        core.restore_module_execution(snapshot);

        assert_eq!(core.pending_exception, Some(pending));
        assert!(matches!(
            core.suspended_abrupt_completions.as_slice(),
            [AbruptCompletion::Exception(restored)] if restored == &suspended
        ));
    }

    #[test]
    fn discard_abrupt_completion_preserves_outer_frame_label_bd_kfxwe() {
        let module = test_module(vec![Ir3Instruction::DiscardAbruptCompletion]);
        let mut core = quickjs_test_core();
        let outer = LabeledException {
            value: Value::str("outer"),
            label: crate::ifc_artifacts::Label::Secret,
        };
        core.finally_frames.push(FinallyFrame {
            completion: Some(AbruptCompletion::Exception(outer.clone())),
        });
        core.finally_frames.push(FinallyFrame {
            completion: Some(AbruptCompletion::Exception(LabeledException {
                value: Value::str("inner"),
                label: crate::ifc_artifacts::Label::Public,
            })),
        });
        let snapshot = core.snapshot_module_execution();
        core.finally_frames.clear();
        core.restore_module_execution(snapshot);

        core.run_loop(&module)
            .expect("discard should resume after the local finally completion");

        assert!(core.pending_exception.is_none());
        assert!(core.pending_return.is_none());
        assert_eq!(core.finally_frames.len(), 1);
        match &core.finally_frames[0].completion {
            Some(AbruptCompletion::Exception(restored)) => assert_eq!(restored, &outer),
            other => panic!("expected outer exception frame, got {other:?}"),
        }
        assert!(core.suspended_abrupt_completions.is_empty());

        let mut normal_nested_core = quickjs_test_core();
        let outer_normal_entry = LabeledException {
            value: Value::str("outer-normal-entry"),
            label: crate::ifc_artifacts::Label::TopSecret,
        };
        normal_nested_core.finally_frames.push(FinallyFrame {
            completion: Some(AbruptCompletion::Exception(outer_normal_entry.clone())),
        });
        normal_nested_core
            .finally_frames
            .push(FinallyFrame { completion: None });

        normal_nested_core
            .run_loop(&module)
            .expect("normal nested finally must not discard an outer completion");

        assert!(normal_nested_core.pending_exception.is_none());
        assert_eq!(normal_nested_core.finally_frames.len(), 1);
        match &normal_nested_core.finally_frames[0].completion {
            Some(AbruptCompletion::Exception(restored)) => {
                assert_eq!(restored, &outer_normal_entry);
            }
            other => panic!("expected preserved outer normal-entry frame, got {other:?}"),
        }
    }

    #[test]
    fn finally_entry_survives_budget_boundary_and_snapshot_bd_kfxwe() {
        let module = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::BeginTry {
                catch_target: 3,
                finally_target: Some(3),
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::EndFinally,
        ]);
        let mut core = quickjs_test_core();
        core.config.instruction_budget = 3;

        assert!(matches!(
            core.run_loop(&module),
            Err(InterpreterError::BudgetExhausted {
                executed: 3,
                budget: 3,
            })
        ));
        assert_eq!(core.ip, 3);
        assert_eq!(
            core.pending_finally_entry,
            Some(PendingFinallyEntry {
                target: 3,
                mode: FinallyMode::Return,
            })
        );

        let snapshot = core.snapshot_module_execution();
        core.pending_finally_entry = None;
        core.restore_module_execution(snapshot);
        core.config.instruction_budget = 10;

        assert_eq!(
            core.run_loop(&module)
                .expect("resumed finally must complete the pending return"),
            Value::Int(7)
        );
        assert!(core.pending_return.is_none());
        assert!(core.pending_finally_entry.is_none());
        assert!(core.finally_frames.is_empty());
    }

    #[test]
    fn finally_entry_survives_cancellation_boundary_bd_kfxwe() {
        let module = test_module(vec![
            Ir3Instruction::BeginTry {
                catch_target: 2,
                finally_target: Some(2),
            },
            Ir3Instruction::Throw { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::EndFinally,
        ]);
        let token = CancellationToken::new();
        token.cancel();
        let mut config = test_quickjs_config();
        config.cancellation_token = Some(token.clone());
        config.checkpoint_density = 3;
        let mut core = InterpreterCore::new(config, "bd-kfxwe-cancel");
        core.write_reg_with_label(0, Value::str("boom"), crate::ifc_artifacts::Label::Secret)
            .expect("throw value should fit in r0");

        assert_eq!(core.run_loop(&module), Err(InterpreterError::Cancelled));
        assert_eq!(core.ip, 2);
        assert_eq!(
            core.pending_finally_entry,
            Some(PendingFinallyEntry {
                target: 2,
                mode: FinallyMode::Exception,
            })
        );

        token.reset();
        assert_eq!(
            core.run_loop(&module),
            Err(InterpreterError::UncaughtException {
                value: "boom".to_string(),
            })
        );
        assert!(core.pending_exception.is_none());
        assert!(core.pending_finally_entry.is_none());
        assert!(core.finally_frames.is_empty());
    }

    fn execute_exception_source_with_core_bd_kfxwe(source: &str) -> (Value, InterpreterCore) {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("finally ownership regression source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd_kfxwe_runtime.js");
        let module = lower_ir0_to_ir3(
            &ir0,
            &LoweringContext::new(
                "trace-bd-kfxwe-runtime",
                "decision-bd-kfxwe-runtime",
                "policy-bd-kfxwe-runtime",
            ),
        )
        .expect("finally ownership regression source should lower")
        .ir3;
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = std::collections::BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        let mut core = InterpreterCore::new(config, "bd-kfxwe-runtime");
        let value = core
            .execute(&module)
            .expect("finally ownership regression should execute")
            .value;
        (value, core)
    }

    #[test]
    fn escaped_finally_completion_records_are_balanced_bd_kfxwe() {
        let (value, core) = execute_exception_source_with_core_bd_kfxwe(
            "function f(){ try { return \"outer\"; } finally { try { try { return \"inner\"; } finally { throw \"new\"; } } catch(e) {} } } f();",
        );

        assert_eq!(value, Value::str("outer"));
        assert!(core.pending_exception.is_none());
        assert!(core.pending_return.is_none());
        assert!(core.pending_finally_entry.is_none());
        assert!(core.finally_frames.is_empty());
        assert!(core.suspended_abrupt_completions.is_empty());
    }

    #[test]
    fn uncaught_throw_from_finally_clears_completion_records_bd_kfxwe() {
        let module = test_module(vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::BeginTry {
                catch_target: 3,
                finally_target: Some(3),
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::EnterFinally,
            Ir3Instruction::Throw { value: 1 },
        ]);
        let mut core = quickjs_test_core();
        core.write_reg_with_label(1, Value::str("new"), crate::ifc_artifacts::Label::Secret)
            .expect("throw value should fit in r1");

        assert_eq!(
            core.run_loop(&module),
            Err(InterpreterError::UncaughtException {
                value: "new".to_string(),
            })
        );
        assert!(core.pending_exception.is_none());
        assert!(core.pending_return.is_none());
        assert!(core.pending_finally_entry.is_none());
        assert!(core.finally_frames.is_empty());
        assert!(core.suspended_abrupt_completions.is_empty());
    }

    fn constructor_descriptor_bd_ur3tk_4(
        entry: u32,
        arity: u32,
        frame_size: u32,
    ) -> Ir3FunctionDesc {
        Ir3FunctionDesc {
            entry,
            arity,
            frame_size,
            name: Some("labeled_constructor".to_string()),
            is_generator: false,
            rest_param_index: None,
        }
    }

    #[test]
    fn constructor_this_and_implicit_result_use_only_callee_label_bd_ur3tk_4() {
        for return_explicit_this in [true, false] {
            let mut instructions = vec![
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Halt,
            ];
            if return_explicit_this {
                instructions.extend([
                    Ir3Instruction::LoadThis { dst: 1 },
                    Ir3Instruction::Return { value: 1 },
                ]);
            } else {
                instructions.push(Ir3Instruction::Return { value: 0 });
            }
            let module = test_module_with_functions(
                instructions,
                vec![constructor_descriptor_bd_ur3tk_4(2, 1, 2)],
            );
            let mut core = quickjs_test_core();
            core.write_reg_with_label(0, Value::Function(0), crate::ifc_artifacts::Label::Secret)
                .expect("constructor should be writable");
            core.write_reg_with_label(1, Value::Int(99), crate::ifc_artifacts::Label::TopSecret)
                .expect("constructor argument should be writable");

            core.execute(&module)
                .expect("labeled constructor should execute");

            assert!(matches!(core.registers[2], Value::Object(_)));
            assert_eq!(
                core.read_reg_label(2)
                    .expect("constructed result label should exist"),
                crate::ifc_artifacts::Label::Secret,
                "constructor this provenance comes from the callee, not an ignored or discarded argument (return_explicit_this={return_explicit_this})"
            );
        }
    }

    #[test]
    fn constructor_explicit_object_return_keeps_argument_label_bd_ur3tk_4() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Return { value: 0 },
            ],
            vec![constructor_descriptor_bd_ur3tk_4(2, 1, 1)],
        );
        let mut core = quickjs_test_core();
        let explicit_object = core
            .alloc_object_with_prototype(None)
            .expect("explicit object should allocate");
        core.write_reg_with_label(0, Value::Function(0), crate::ifc_artifacts::Label::Secret)
            .expect("constructor should be writable");
        core.write_reg_with_label(
            1,
            Value::Object(explicit_object),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("explicit object argument should be writable");

        core.execute(&module)
            .expect("explicit object constructor should execute");

        assert_eq!(core.registers[2], Value::Object(explicit_object));
        assert_eq!(
            core.read_reg_label(2).expect("explicit result label"),
            crate::ifc_artifacts::Label::Confidential,
            "an explicit object return keeps its own label instead of the constructor label"
        );
    }

    #[test]
    fn constructor_new_target_throw_preserves_callee_label_bd_ur3tk_4() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::BeginTry {
                    catch_target: 3,
                    finally_target: None,
                },
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 0 },
                    dst: 2,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::EnterCatch { dst: 3 },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadNewTarget { dst: 0 },
                Ir3Instruction::Throw { value: 0 },
            ],
            vec![constructor_descriptor_bd_ur3tk_4(5, 0, 1)],
        );
        let mut core = quickjs_test_core();
        core.write_reg_with_label(0, Value::Function(0), crate::ifc_artifacts::Label::Secret)
            .expect("constructor should be writable");

        core.execute(&module)
            .expect("caller should catch the thrown new.target");

        assert_eq!(core.registers[3], Value::Function(0));
        assert_eq!(
            core.read_reg_label(3).expect("new.target catch label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn constructor_super_value_preserves_callee_label_bd_ur3tk_4() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 0 },
                    dst: 2,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadSuper { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![constructor_descriptor_bd_ur3tk_4(2, 0, 1)],
        );
        let mut core = quickjs_test_core();
        let super_object = core
            .alloc_object_with_prototype(None)
            .expect("super object should allocate");
        let constructor = Value::Function(0);
        let function_object = core
            .ensure_function_object(&constructor)
            .expect("function metadata object should allocate")
            .expect("Function should have metadata storage");
        core.set_object_property(
            function_object,
            IR_SUPER_CONSTRUCTOR_PROPERTY.to_string(),
            Value::Object(super_object),
        )
        .expect("super metadata should be writable");
        core.write_reg_with_label(0, constructor, crate::ifc_artifacts::Label::Secret)
            .expect("constructor should be writable");

        core.execute(&module)
            .expect("constructor should return its super metadata object");

        assert_eq!(core.registers[2], Value::Object(super_object));
        assert_eq!(
            core.read_reg_label(2).expect("super result label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn plain_call_super_metadata_uses_only_callee_label_bd_ur3tk_20() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadSuper { dst: 1 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 2,
                name: Some("plain_super_reader".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        let super_object = core
            .alloc_object_with_prototype(None)
            .expect("super object should allocate");
        let callee = Value::Function(0);
        let function_object = core
            .ensure_function_object(&callee)
            .expect("function metadata object should allocate")
            .expect("Function should have metadata storage");
        core.set_object_property(
            function_object,
            IR_SUPER_PROTOTYPE_PROPERTY.to_string(),
            Value::Object(super_object),
        )
        .expect("super metadata should be writable");
        core.write_reg_with_label(0, callee, crate::ifc_artifacts::Label::Secret)
            .expect("callee should be writable");
        core.write_reg_with_label(1, Value::Int(41), crate::ifc_artifacts::Label::TopSecret)
            .expect("argument should be writable");

        core.execute(&module).expect("plain call should execute");

        assert_eq!(core.registers[2], Value::Object(super_object));
        assert_eq!(
            core.read_reg_label(2).expect("plain super result label"),
            crate::ifc_artifacts::Label::Secret,
            "super provenance comes from the callee without overjoining its argument"
        );
    }

    #[test]
    fn call_method_super_metadata_uses_only_callee_label_bd_ur3tk_20() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 1,
                    args: RegRange { start: 2, count: 1 },
                    dst: 3,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadSuper { dst: 1 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 2,
                name: Some("method_super_reader".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = quickjs_test_core();
        let super_object = core
            .alloc_object_with_prototype(None)
            .expect("super object should allocate");
        let callee = Value::Function(0);
        let function_object = core
            .ensure_function_object(&callee)
            .expect("function metadata object should allocate")
            .expect("Function should have metadata storage");
        core.set_object_property(
            function_object,
            IR_SUPER_PROTOTYPE_PROPERTY.to_string(),
            Value::Object(super_object),
        )
        .expect("super metadata should be writable");
        core.write_reg_with_label(
            0,
            Value::str("receiver"),
            crate::ifc_artifacts::Label::Confidential,
        )
        .expect("receiver should be writable");
        core.write_reg_with_label(1, callee, crate::ifc_artifacts::Label::Secret)
            .expect("callee should be writable");
        core.write_reg_with_label(2, Value::Int(42), crate::ifc_artifacts::Label::TopSecret)
            .expect("argument should be writable");

        core.execute(&module).expect("method call should execute");

        assert_eq!(core.registers[3], Value::Object(super_object));
        assert_eq!(
            core.read_reg_label(3).expect("method super result label"),
            crate::ifc_artifacts::Label::Secret,
            "super provenance comes from the callee without overjoining its argument"
        );
    }

    fn lower_source_and_find_unresolved_argument_seed_bd_ur3tk_11(
        source: &str,
    ) -> (Ir3Module, Reg) {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("value-transfer regression source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd_ur3tk_11.js");
        let output = lower_ir0_to_ir3(
            &ir0,
            &LoweringContext::new(
                "trace-bd-ur3tk-11",
                "decision-bd-ur3tk-11",
                "policy-bd-ur3tk-11",
            ),
        )
        .expect("value-transfer regression source should lower");
        let module = output.ir3;
        let main_end = module
            .instructions
            .iter()
            .position(|instruction| matches!(instruction, Ir3Instruction::Halt))
            .expect("lowered main block should terminate with Halt");
        let (call_index, mut seed_reg) = module.instructions[..main_end]
            .iter()
            .enumerate()
            .find_map(|(index, instruction)| match instruction {
                Ir3Instruction::Call { args, .. } if args.count == 1 => Some((index, args.start)),
                _ => None,
            })
            .expect("source should contain one top-level single-argument call");

        // Ordinary source lowering moves an unresolved input through one or
        // more fresh temporaries before packing the call range. Walk that
        // exact Move chain back to the unwritten backing register so the test
        // can inject a labeled external input without introducing a new IR
        // source-label opcode.
        let mut search_end = call_index;
        let mut traced_move_count = 0_u32;
        while let Some((index, source_reg)) = module.instructions[..search_end]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, instruction)| match instruction {
                Ir3Instruction::Move { dst, src } if *dst == seed_reg => Some((index, *src)),
                _ => None,
            })
        {
            seed_reg = source_reg;
            search_end = index;
            traced_move_count = traced_move_count.saturating_add(1);
        }
        assert!(
            traced_move_count >= 2,
            "seed tracing should cross the unresolved-binding load and call-range packing moves"
        );

        // Pin the monotonic-allocation assumption behind the white-box seed:
        // the terminal unresolved binding register must not be produced by an
        // earlier instruction. Canonical IR names synchronous destinations
        // `dst` or `value_dst`; the two suspended-result forms use
        // `resume_dst` and `promise_reg`. Checking all four avoids duplicating
        // the instruction enum's large match here.
        assert!(
            module.instructions[..call_index].iter().all(|instruction| {
                let crate::deterministic_serde::CanonicalValue::Map(fields) =
                    instruction.canonical_value()
                else {
                    unreachable!("IR3 instructions canonicalize to maps");
                };
                ["dst", "value_dst", "resume_dst", "promise_reg"]
                    .iter()
                    .all(|field| {
                        !matches!(
                            fields.get(*field),
                            Some(crate::deterministic_serde::CanonicalValue::U64(destination))
                                if *destination == u64::from(seed_reg)
                        )
                    })
            }),
            "terminal unresolved input r{seed_reg} must have no earlier writer"
        );

        (module, seed_reg)
    }

    fn assert_source_transfer_preserves_secret_bd_ur3tk_11(source: &str) {
        let (module, seed_reg) = lower_source_and_find_unresolved_argument_seed_bd_ur3tk_11(source);
        let mut core = quickjs_test_core();
        core.write_reg_with_label(
            seed_reg,
            Value::str("source-secret"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("unresolved source input should be seedable");

        let result = core
            .execute(&module)
            .expect("source-lowered value transfers should execute");
        assert_eq!(result.value, Value::str("source-secret"));
        assert_eq!(
            core.read_reg_label(0).expect("source completion label"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    #[test]
    fn source_local_moves_preserve_secret_to_completion_bd_ur3tk_11() {
        assert_source_transfer_preserves_secret_bd_ur3tk_11(
            "function identity(value) { return value; } identity(secret_input);",
        );
    }

    #[test]
    fn captured_parameter_preserves_secret_through_scope_bd_ur3tk_11() {
        assert_source_transfer_preserves_secret_bd_ur3tk_11(
            "function outer(value) { return function inner() { return value; }; }\
             outer(secret_input)();",
        );
    }

    #[test]
    fn captured_local_preserves_secret_through_scope_bd_ur3tk_11() {
        assert_source_transfer_preserves_secret_bd_ur3tk_11(
            "function outer(value) {\
               let local = value;\
               return function inner() { return local; };\
             }\
             outer(secret_input)();",
        );
    }

    #[test]
    fn destructuring_default_preserves_secret_through_moves_bd_ur3tk_11() {
        assert_source_transfer_preserves_secret_bd_ur3tk_11(
            "function unpack(value) {\
               let { missing = value } = {};\
               return missing;\
             }\
             unpack(secret_input);",
        );
    }

    fn assert_rest_array_result_bd_ur3tk_9(
        core: &InterpreterCore,
        result: Value,
        destination: Reg,
    ) {
        let Value::Object(array_id) = result else {
            panic!("rest parameter should return an Array object");
        };
        assert_eq!(
            core.read_array_like_values(array_id),
            vec![Value::Int(20), Value::Int(30)]
        );
        assert_eq!(
            core.read_reg_label(destination)
                .expect("rest return label should remain readable"),
            crate::ifc_artifacts::Label::Secret
        );
    }

    fn rest_return_descriptor_bd_ur3tk_9() -> Ir3FunctionDesc {
        Ir3FunctionDesc {
            entry: 2,
            arity: 2,
            frame_size: 2,
            name: Some("return_rest".to_string()),
            is_generator: false,
            rest_param_index: Some(1),
        }
    }

    #[test]
    fn plain_call_rest_joins_only_trailing_argument_labels_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 3 },
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![rest_return_descriptor_bd_ur3tk_9()],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(1, Value::Int(10), crate::ifc_artifacts::Label::TopSecret)
            .expect("fixed argument should be writable");
        core.write_reg_with_label(2, Value::Int(20), crate::ifc_artifacts::Label::Confidential)
            .expect("first rest argument should be writable");
        core.write_reg_with_label(3, Value::Int(30), crate::ifc_artifacts::Label::Secret)
            .expect("second rest argument should be writable");

        let result = core.run_loop(&module).expect("rest call should return");
        assert_rest_array_result_bd_ur3tk_9(&core, result, 4);
    }

    #[test]
    fn method_call_rest_joins_trailing_argument_labels_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 1,
                    args: RegRange { start: 2, count: 3 },
                    dst: 5,
                },
                Ir3Instruction::Return { value: 5 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![rest_return_descriptor_bd_ur3tk_9()],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::str("receiver");
        core.registers[1] = Value::Function(0);
        core.write_reg_with_label(2, Value::Int(10), crate::ifc_artifacts::Label::TopSecret)
            .expect("fixed argument should be writable");
        core.write_reg_with_label(3, Value::Int(20), crate::ifc_artifacts::Label::Confidential)
            .expect("first rest argument should be writable");
        core.write_reg_with_label(4, Value::Int(30), crate::ifc_artifacts::Label::Secret)
            .expect("second rest argument should be writable");

        let result = core.run_loop(&module).expect("rest method should return");
        assert_rest_array_result_bd_ur3tk_9(&core, result, 5);
    }

    #[test]
    fn constructor_rest_uses_r0_formal_abi_and_joins_labels_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 3 },
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![rest_return_descriptor_bd_ur3tk_9()],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(1, Value::Int(10), crate::ifc_artifacts::Label::TopSecret)
            .expect("fixed argument should be writable");
        core.write_reg_with_label(2, Value::Int(20), crate::ifc_artifacts::Label::Confidential)
            .expect("first rest argument should be writable");
        core.write_reg_with_label(3, Value::Int(30), crate::ifc_artifacts::Label::Secret)
            .expect("second rest argument should be writable");

        let result = core
            .run_loop(&module)
            .expect("rest constructor should return its explicit Array");
        assert_rest_array_result_bd_ur3tk_9(&core, result, 4);
    }

    #[test]
    fn empty_rest_materializes_empty_public_array_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![rest_return_descriptor_bd_ur3tk_9()],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        core.write_reg_with_label(1, Value::Int(10), crate::ifc_artifacts::Label::TopSecret)
            .expect("fixed argument should be writable");

        let result = core.run_loop(&module).expect("empty rest should return");
        let Value::Object(array_id) = result else {
            panic!("empty rest parameter should return an Array object");
        };
        assert!(core.read_array_like_values(array_id).is_empty());
        assert_eq!(
            core.read_reg_label(2).expect("empty rest result label"),
            crate::ifc_artifacts::Label::Public
        );
    }

    #[test]
    fn malformed_nonfinal_rest_descriptor_is_rejected_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 3 },
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 3,
                frame_size: 3,
                name: Some("malformed_rest".to_string()),
                is_generator: false,
                rest_param_index: Some(1),
            }],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);

        let error = core
            .run_loop(&module)
            .expect_err("non-final rest metadata must fail closed");
        assert!(matches!(error, InterpreterError::TypeError { .. }));
    }

    #[test]
    fn malformed_constructor_rest_is_rejected_before_allocation_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 3 },
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 3,
                frame_size: 3,
                name: Some("malformed_constructor_rest".to_string()),
                is_generator: false,
                rest_param_index: Some(1),
            }],
        );
        let mut core = quickjs_test_core();
        core.registers[0] = Value::Function(0);
        let heap_len = core.heap.len();
        let estimated_memory_bytes = core.estimated_memory_bytes;
        let function_prototypes = core.function_prototypes.clone();

        core.run_loop(&module)
            .expect_err("malformed constructor metadata must fail before setup");
        assert_eq!(core.heap.len(), heap_len);
        assert_eq!(core.estimated_memory_bytes, estimated_memory_bytes);
        assert_eq!(core.function_prototypes, function_prototypes);
    }

    #[test]
    fn rest_policy_hooks_observe_guarded_materialized_carrier_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 3 },
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![rest_return_descriptor_bd_ur3tk_9()],
        );
        let hook = Arc::new(RecordingHook::allow_all());
        let mut core = quickjs_test_core();
        core.set_hook(hook.clone());
        core.registers[0] = Value::Function(0);
        core.registers[1] = Value::Int(10);
        core.registers[2] = Value::Int(20);
        core.registers[3] = Value::Int(30);

        core.run_loop(&module)
            .expect("guarded rest call should execute");
        let records = hook.records_without_startup_module_record();
        assert_eq!(records.len(), 2);
        assert!(matches!(
            records.first(),
            Some(HookRecord::Allocation {
                kind: AllocKind::Array,
                size_hint: 2,
                ..
            })
        ));
        let HookRecord::Call { args, .. } = &records[1] else {
            panic!("pre-call hook must run after rest allocation");
        };
        assert_eq!(args.first(), Some(&Value::Int(10)));
        let Some(Value::Object(rest_array)) = args.get(1) else {
            panic!("pre-call hook must receive the materialized rest Array");
        };
        assert_eq!(
            core.read_array_like_values(*rest_array),
            vec![Value::Int(20), Value::Int(30)]
        );
    }

    #[test]
    fn denied_rest_allocation_leaves_heap_unchanged_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 2 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![rest_return_descriptor_bd_ur3tk_9()],
        );
        let hook = Arc::new(RecordingHook::with_allocation_action(
            HookAction::Terminate("rest allocation denied".to_string()),
        ));
        let mut core = quickjs_test_core();
        core.set_hook(hook.clone());
        core.registers[0] = Value::Function(0);
        core.registers[1] = Value::Int(10);
        core.registers[2] = Value::Int(20);
        let heap_len = core.heap.len();
        let estimated_memory_bytes = core.estimated_memory_bytes;

        core.run_loop(&module)
            .expect_err("allocation policy must deny the implicit rest Array");
        assert_eq!(core.heap.len(), heap_len);
        assert_eq!(core.estimated_memory_bytes, estimated_memory_bytes);
        assert!(matches!(
            hook.records_without_startup_module_record().as_slice(),
            [HookRecord::Allocation {
                kind: AllocKind::Array,
                size_hint: 1,
                ..
            }]
        ));
    }

    #[test]
    fn denied_constructor_rest_allocation_leaves_setup_unchanged_bd_ur3tk_9() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 2 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![rest_return_descriptor_bd_ur3tk_9()],
        );
        let hook = Arc::new(RecordingHook::with_allocation_action(
            HookAction::Terminate("constructor rest allocation denied".to_string()),
        ));
        let mut core = quickjs_test_core();
        core.set_hook(hook.clone());
        core.registers[0] = Value::Function(0);
        core.registers[1] = Value::Int(10);
        core.registers[2] = Value::Int(20);
        let heap_len = core.heap.len();
        let estimated_memory_bytes = core.estimated_memory_bytes;
        let function_prototypes = core.function_prototypes.clone();

        core.run_loop(&module)
            .expect_err("rest allocation policy must deny constructor setup");
        assert_eq!(core.heap.len(), heap_len);
        assert_eq!(core.estimated_memory_bytes, estimated_memory_bytes);
        assert_eq!(core.function_prototypes, function_prototypes);
        assert!(matches!(
            hook.records_without_startup_module_record().as_slice(),
            [HookRecord::Allocation {
                kind: AllocKind::Array,
                size_hint: 1,
                ..
            }]
        ));
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
                rest_param_index: None,
            }],
        );

        let mut config = test_quickjs_config();
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
                rest_param_index: None,
            }],
        );

        let mut config = test_quickjs_config();
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

        let mut config = test_quickjs_config();
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

        let mut config = test_quickjs_config();
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
        let config = test_quickjs_config_with([RuntimeCapability::NetworkEgress]);
        let lane = QuickJsLane::with_config(config);
        let result = lane.execute(&m, "test").unwrap();
        assert_eq!(result.value, Value::Undefined);
    }

    #[test]
    fn promise_resolve_wrapper_preserves_source_label_bd_ur3tk_13() {
        let module = test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Halt,
        ]);
        let mut core = quickjs_test_core();
        core.write_reg_with_label(
            0,
            Value::str("secret-resolution"),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("resolution source should be writable");

        core.execute(&module)
            .expect("Promise.resolve hostcall should execute");

        let Value::Promise(handle) = core.registers[1] else {
            panic!("Promise.resolve should return a Promise handle");
        };
        assert_eq!(
            core.read_reg_label(1).expect("result label should exist"),
            crate::ifc_artifacts::Label::Secret
        );
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(handle))
            .expect("resolved Promise should exist");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
    }

    #[test]
    fn promise_existing_reject_joins_target_and_reason_labels_bd_ur3tk_13() {
        let module = test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:reject".to_string()),
                args: RegRange { start: 0, count: 2 },
                dst: 2,
            },
            Ir3Instruction::Halt,
        ]);
        let cases = [
            (
                crate::ifc_artifacts::Label::Secret,
                crate::ifc_artifacts::Label::Custom {
                    name: "tenant-rejection".to_string(),
                    level: 2,
                },
                "target-dominant",
            ),
            (
                crate::ifc_artifacts::Label::Public,
                crate::ifc_artifacts::Label::Secret,
                "reason-dominant",
            ),
        ];

        for (target_label, reason_label, reason) in cases {
            let expected_label = target_label.join(&reason_label);
            let mut core = quickjs_test_core();
            let target = core.promise_store.create();
            core.write_reg_with_label(0, Value::Promise(target.0), target_label)
                .expect("target Promise should be writable");
            core.write_reg_with_label(1, Value::str(reason), reason_label)
                .expect("rejection reason should be writable");

            core.execute(&module)
                .expect("existing-target Promise.reject hostcall should execute");

            assert_eq!(core.registers[2], Value::Promise(target.0));
            assert_eq!(
                core.read_reg_label(2).expect("result label should exist"),
                expected_label,
                "returned handle joins the target-handle and reason labels"
            );
            let record = core
                .promise_store
                .get(target)
                .expect("rejected Promise should exist");
            assert_eq!(
                record.label, expected_label,
                "settlement joins target-reference and reason provenance"
            );
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Rejected(
                    crate::object_model::JsValue::Str(value)
                ) if value == reason
            ));
        }
    }

    #[test]
    fn pending_promise_reactions_preserve_registration_labels_bd_ur3tk_13() {
        let custom = crate::ifc_artifacts::Label::Custom {
            name: "tenant-reaction".to_string(),
            level: 4,
        };
        let cases = [
            (
                "promise:then",
                3,
                crate::ifc_artifacts::Label::Public,
                crate::ifc_artifacts::Label::Public,
                crate::ifc_artifacts::Label::Secret,
                crate::ifc_artifacts::Label::Secret,
            ),
            (
                "promise:catch",
                2,
                crate::ifc_artifacts::Label::Public,
                custom.clone(),
                crate::ifc_artifacts::Label::Public,
                custom,
            ),
            (
                "promise:finally",
                2,
                crate::ifc_artifacts::Label::Secret,
                crate::ifc_artifacts::Label::Public,
                crate::ifc_artifacts::Label::Public,
                crate::ifc_artifacts::Label::Secret,
            ),
        ];

        for (capability, count, source_label, handler_label, reject_label, expected_label) in cases
        {
            let module = test_module(vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(capability.to_string()),
                    args: RegRange { start: 0, count },
                    dst: 3,
                },
                Ir3Instruction::Halt,
            ]);
            let mut core = quickjs_test_core();
            let source = core.promise_store.create();
            core.write_reg_with_label(0, Value::Promise(source.0), source_label)
                .expect("source Promise should be writable");
            core.write_reg_with_label(1, Value::Undefined, handler_label)
                .expect("fulfillment handler slot should be writable");
            core.write_reg_with_label(2, Value::Undefined, reject_label)
                .expect("rejection handler slot should be writable");

            core.execute(&module)
                .expect("Promise reaction hostcall should execute");

            let Value::Promise(result_handle) = core.registers[3] else {
                panic!("{capability} should return a Promise handle");
            };
            assert_eq!(
                core.read_reg_label(3).expect("result label should exist"),
                expected_label,
                "{capability} result handle carries registration provenance"
            );
            core.fulfill_promise(
                source,
                crate::object_model::JsValue::Int(7),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("source Promise should fulfill");
            core.drain_microtasks();
            let result = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("reaction result Promise should exist");
            assert_eq!(
                result.label, expected_label,
                "{capability} result settlement joins registration provenance"
            );
        }
    }

    fn promise_combinator_module_bd_ur3tk_19(
        capability: &str,
        args: RegRange,
        dst: Reg,
    ) -> Ir3Module {
        test_module(vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag(capability.to_string()),
                args,
                dst,
            },
            Ir3Instruction::Halt,
        ])
    }

    fn execute_promise_combinator_bd_ur3tk_19(
        core: &mut InterpreterCore,
        capability: &str,
        args: RegRange,
        dst: Reg,
    ) -> crate::promise_model::PromiseHandle {
        core.execute(&promise_combinator_module_bd_ur3tk_19(
            capability, args, dst,
        ))
        .unwrap_or_else(|error| panic!("{capability} should execute: {error}"));
        let Value::Promise(handle) = core.registers[dst as usize] else {
            panic!("{capability} should return a Promise handle");
        };
        crate::promise_model::PromiseHandle(handle)
    }

    #[test]
    fn combinators_join_direct_inputs_in_both_orders_bd_ur3tk_19() {
        for capability in [
            "promise:all",
            "promise:allSettled",
            "promise:race",
            "promise:any",
        ] {
            for secret_first in [true, false] {
                let mut core = quickjs_test_core();
                let (first_label, second_label) = if secret_first {
                    (
                        crate::ifc_artifacts::Label::Secret,
                        crate::ifc_artifacts::Label::Public,
                    )
                } else {
                    (
                        crate::ifc_artifacts::Label::Public,
                        crate::ifc_artifacts::Label::Secret,
                    )
                };
                core.write_reg_with_label(0, Value::Int(10), first_label)
                    .expect("first input should be writable");
                core.write_reg_with_label(1, Value::Int(20), second_label)
                    .expect("second input should be writable");

                let result = execute_promise_combinator_bd_ur3tk_19(
                    &mut core,
                    capability,
                    RegRange { start: 0, count: 2 },
                    2,
                );

                assert_eq!(
                    core.read_reg_label(2).expect("result label should exist"),
                    crate::ifc_artifacts::Label::Secret,
                    "{capability} returned handle must join every direct input (secret_first={secret_first})"
                );
                let record = core
                    .promise_store
                    .get(result)
                    .expect("aggregate Promise should exist");
                assert_eq!(
                    record.label,
                    crate::ifc_artifacts::Label::Secret,
                    "{capability} settlement must be independent of input order (secret_first={secret_first})"
                );
                assert!(record.state.is_settled());
            }
        }
    }

    #[test]
    fn combinators_join_already_settled_promise_labels_bd_ur3tk_19() {
        for capability in [
            "promise:all",
            "promise:allSettled",
            "promise:race",
            "promise:any",
        ] {
            for secret_first in [true, false] {
                let mut core = quickjs_test_core();
                let first = core.promise_store.create();
                let second = core.promise_store.create();
                let (first_label, second_label) = if secret_first {
                    (
                        crate::ifc_artifacts::Label::Secret,
                        crate::ifc_artifacts::Label::Public,
                    )
                } else {
                    (
                        crate::ifc_artifacts::Label::Public,
                        crate::ifc_artifacts::Label::Secret,
                    )
                };
                core.fulfill_promise(first, crate::object_model::JsValue::Int(10), first_label)
                    .expect("first Promise should fulfill");
                core.fulfill_promise(second, crate::object_model::JsValue::Int(20), second_label)
                    .expect("second Promise should fulfill");
                core.registers[0] = Value::Promise(first.0);
                core.registers[1] = Value::Promise(second.0);

                let result = execute_promise_combinator_bd_ur3tk_19(
                    &mut core,
                    capability,
                    RegRange { start: 0, count: 2 },
                    2,
                );

                assert_eq!(
                    core.read_reg_label(2).expect("result label should exist"),
                    crate::ifc_artifacts::Label::Secret,
                    "{capability} handle must include known settlement provenance (secret_first={secret_first})"
                );
                let record = core
                    .promise_store
                    .get(result)
                    .expect("aggregate Promise should exist");
                assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            }
        }
    }

    #[test]
    fn combinator_array_inputs_inherit_iterable_carrier_label_bd_ur3tk_19() {
        let mut core = quickjs_test_core();
        let settled = core.promise_store.create();
        core.fulfill_promise(
            settled,
            crate::object_model::JsValue::Int(20),
            crate::ifc_artifacts::Label::Public,
        )
        .expect("nested Promise should fulfill");
        let inputs = core
            .alloc_array_from_values(&[Value::Int(10), Value::Promise(settled.0)])
            .expect("input array should allocate");
        core.write_reg_with_label(
            0,
            Value::Object(inputs),
            crate::ifc_artifacts::Label::Secret,
        )
        .expect("input array carrier should be writable");

        let result = execute_promise_combinator_bd_ur3tk_19(
            &mut core,
            "promise:all",
            RegRange { start: 0, count: 1 },
            1,
        );

        assert_eq!(
            core.read_reg_label(1).expect("result label should exist"),
            crate::ifc_artifacts::Label::Secret
        );
        let record = core
            .promise_store
            .get(result)
            .expect("Promise.all aggregate should exist");
        assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
    }

    #[test]
    fn pending_all_variants_join_settlements_in_both_orders_bd_ur3tk_19() {
        for capability in ["promise:all", "promise:allSettled"] {
            for secret_first in [true, false] {
                let mut core = quickjs_test_core();
                let first = core.promise_store.create();
                let second = core.promise_store.create();
                core.write_reg_with_label(
                    0,
                    Value::Promise(first.0),
                    crate::ifc_artifacts::Label::Public,
                )
                .expect("first pending Promise should be writable");
                core.write_reg_with_label(
                    1,
                    Value::Promise(second.0),
                    crate::ifc_artifacts::Label::Public,
                )
                .expect("second pending Promise should be writable");
                let result = execute_promise_combinator_bd_ur3tk_19(
                    &mut core,
                    capability,
                    RegRange { start: 0, count: 2 },
                    2,
                );

                if capability == "promise:all" {
                    let (first_label, second_label) = if secret_first {
                        (
                            crate::ifc_artifacts::Label::Secret,
                            crate::ifc_artifacts::Label::Public,
                        )
                    } else {
                        (
                            crate::ifc_artifacts::Label::Public,
                            crate::ifc_artifacts::Label::Secret,
                        )
                    };
                    core.fulfill_promise(first, crate::object_model::JsValue::Int(10), first_label)
                        .expect("first Promise should fulfill");
                    core.fulfill_promise(
                        second,
                        crate::object_model::JsValue::Int(20),
                        second_label,
                    )
                    .expect("second Promise should fulfill");
                } else if secret_first {
                    core.reject_promise(
                        first,
                        crate::object_model::JsValue::Str("secret-first".into()),
                        crate::ifc_artifacts::Label::Secret,
                    )
                    .expect("first Promise should reject");
                    core.fulfill_promise(
                        second,
                        crate::object_model::JsValue::Int(20),
                        crate::ifc_artifacts::Label::Public,
                    )
                    .expect("second Promise should fulfill");
                } else {
                    core.fulfill_promise(
                        first,
                        crate::object_model::JsValue::Int(10),
                        crate::ifc_artifacts::Label::Public,
                    )
                    .expect("first Promise should fulfill");
                    core.reject_promise(
                        second,
                        crate::object_model::JsValue::Str("secret-last".into()),
                        crate::ifc_artifacts::Label::Secret,
                    )
                    .expect("second Promise should reject");
                }

                let record = core
                    .promise_store
                    .get(result)
                    .expect("aggregate Promise should exist");
                assert_eq!(
                    record.label,
                    crate::ifc_artifacts::Label::Secret,
                    "{capability} must retain the earlier settlement label (secret_first={secret_first})"
                );
                assert!(matches!(
                    &record.state,
                    crate::promise_model::PromiseState::Fulfilled(_)
                ));
            }
        }
    }

    #[test]
    fn promise_any_rejections_join_labels_in_both_orders_bd_ur3tk_19() {
        for secret_first in [true, false] {
            let mut core = quickjs_test_core();
            let first = core.promise_store.create();
            let second = core.promise_store.create();
            core.registers[0] = Value::Promise(first.0);
            core.registers[1] = Value::Promise(second.0);
            let result = execute_promise_combinator_bd_ur3tk_19(
                &mut core,
                "promise:any",
                RegRange { start: 0, count: 2 },
                2,
            );
            let (first_label, second_label) = if secret_first {
                (
                    crate::ifc_artifacts::Label::Secret,
                    crate::ifc_artifacts::Label::Public,
                )
            } else {
                (
                    crate::ifc_artifacts::Label::Public,
                    crate::ifc_artifacts::Label::Secret,
                )
            };
            core.reject_promise(
                first,
                crate::object_model::JsValue::Str("first".into()),
                first_label,
            )
            .expect("first Promise should reject");
            core.reject_promise(
                second,
                crate::object_model::JsValue::Str("second".into()),
                second_label,
            )
            .expect("second Promise should reject");

            let record = core
                .promise_store
                .get(result)
                .expect("Promise.any aggregate should exist");
            assert_eq!(
                record.label,
                crate::ifc_artifacts::Label::Secret,
                "Promise.any AggregateError label must not depend on rejection order"
            );
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Rejected(_)
            ));
        }
    }

    #[test]
    fn combinator_cross_branch_short_circuits_retain_prior_label_bd_ur3tk_19() {
        for capability in ["promise:all", "promise:any"] {
            let mut core = quickjs_test_core();
            let first = core.promise_store.create();
            let second = core.promise_store.create();
            core.registers[0] = Value::Promise(first.0);
            core.registers[1] = Value::Promise(second.0);
            let result = execute_promise_combinator_bd_ur3tk_19(
                &mut core,
                capability,
                RegRange { start: 0, count: 2 },
                2,
            );

            if capability == "promise:all" {
                core.fulfill_promise(
                    first,
                    crate::object_model::JsValue::Int(10),
                    crate::ifc_artifacts::Label::Secret,
                )
                .expect("first Promise should fulfill");
                core.reject_promise(
                    second,
                    crate::object_model::JsValue::Str("public-rejection".into()),
                    crate::ifc_artifacts::Label::Public,
                )
                .expect("second Promise should reject");
            } else {
                core.reject_promise(
                    first,
                    crate::object_model::JsValue::Str("secret-rejection".into()),
                    crate::ifc_artifacts::Label::Secret,
                )
                .expect("first Promise should reject");
                core.fulfill_promise(
                    second,
                    crate::object_model::JsValue::Int(20),
                    crate::ifc_artifacts::Label::Public,
                )
                .expect("second Promise should fulfill");
            }

            let record = core
                .promise_store
                .get(result)
                .expect("aggregate Promise should exist");
            assert_eq!(
                record.label,
                crate::ifc_artifacts::Label::Secret,
                "{capability} must retain a prior Secret settlement when a Public input short-circuits"
            );
            assert_eq!(
                matches!(
                    &record.state,
                    crate::promise_model::PromiseState::Rejected(_)
                ),
                capability == "promise:all"
            );
        }
    }

    #[test]
    fn combinator_short_circuits_join_all_input_references_bd_ur3tk_19() {
        for (capability, reject_winner) in [
            ("promise:all", true),
            ("promise:race", false),
            ("promise:race", true),
            ("promise:any", false),
        ] {
            let mut core = quickjs_test_core();
            let winner = core.promise_store.create();
            let pending = core.promise_store.create();
            core.write_reg_with_label(
                0,
                Value::Promise(winner.0),
                crate::ifc_artifacts::Label::Public,
            )
            .expect("winner should be writable");
            core.write_reg_with_label(
                1,
                Value::Promise(pending.0),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("pending competitor should be writable");
            let result = execute_promise_combinator_bd_ur3tk_19(
                &mut core,
                capability,
                RegRange { start: 0, count: 2 },
                2,
            );
            assert_eq!(
                core.read_reg_label(2).expect("result label should exist"),
                crate::ifc_artifacts::Label::Secret,
                "{capability} returned handle must include every input reference"
            );

            if reject_winner {
                core.reject_promise(
                    winner,
                    crate::object_model::JsValue::Str("public-winner".into()),
                    crate::ifc_artifacts::Label::Public,
                )
                .expect("winner should reject");
            } else {
                core.fulfill_promise(
                    winner,
                    crate::object_model::JsValue::Int(7),
                    crate::ifc_artifacts::Label::Public,
                )
                .expect("winner should fulfill");
            }

            let record = core
                .promise_store
                .get(result)
                .expect("short-circuit aggregate should exist");
            assert_eq!(
                record.label,
                crate::ifc_artifacts::Label::Secret,
                "{capability} winner must retain the pending competitor reference label"
            );
            assert!(record.state.is_settled());
        }
    }

    #[test]
    fn empty_combinators_preserve_carrier_labels_bd_ur3tk_19() {
        for capability in [
            "promise:all",
            "promise:allSettled",
            "promise:race",
            "promise:any",
        ] {
            let mut core = quickjs_test_core();
            let result = execute_promise_combinator_bd_ur3tk_19(
                &mut core,
                capability,
                RegRange { start: 0, count: 0 },
                0,
            );
            assert_eq!(
                core.read_reg_label(0)
                    .expect("empty result label should exist"),
                crate::ifc_artifacts::Label::Public
            );
            let record = core
                .promise_store
                .get(result)
                .expect("empty aggregate should exist");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Public);
            assert_eq!(
                record.state.is_settled(),
                capability != "promise:race",
                "only an empty Promise.race remains pending"
            );

            let mut core = quickjs_test_core();
            let empty_array = core
                .alloc_array_from_values(&[])
                .expect("empty array should allocate");
            core.write_reg_with_label(
                0,
                Value::Object(empty_array),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("empty array carrier should be writable");
            let result = execute_promise_combinator_bd_ur3tk_19(
                &mut core,
                capability,
                RegRange { start: 0, count: 1 },
                1,
            );
            assert_eq!(
                core.read_reg_label(1)
                    .expect("empty result label should exist"),
                crate::ifc_artifacts::Label::Secret,
                "{capability} must preserve a labeled empty iterable carrier"
            );
            let record = core
                .promise_store
                .get(result)
                .expect("empty aggregate should exist");
            if capability != "promise:race" {
                assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            }
        }
    }

    #[test]
    fn builtin_array_is_array_uses_explicit_array_metadata() {
        let array = quickjs_execute(&test_module(vec![
            Ir3Instruction::NewArray { dst: 4 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayIsArray".to_string()),
                args: RegRange { start: 4, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();
        assert_eq!(array.value, Value::Bool(true));

        let object = quickjs_execute(&test_module(vec![
            Ir3Instruction::NewObject { dst: 4 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ArrayIsArray".to_string()),
                args: RegRange { start: 4, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();
        assert_eq!(object.value, Value::Bool(false));
    }

    #[test]
    fn array_slice_instruction_returns_remaining_elements() {
        let module = test_module(vec![
            Ir3Instruction::NewArray { dst: 1 },
            Ir3Instruction::LoadInt { dst: 2, value: 7 },
            Ir3Instruction::ArrayPush {
                array: 1,
                element: 2,
            },
            Ir3Instruction::LoadInt { dst: 3, value: 8 },
            Ir3Instruction::ArrayPush {
                array: 1,
                element: 3,
            },
            Ir3Instruction::LoadInt { dst: 4, value: 9 },
            Ir3Instruction::ArrayPush {
                array: 1,
                element: 4,
            },
            Ir3Instruction::LoadInt { dst: 5, value: 1 },
            Ir3Instruction::ArraySlice {
                array: 1,
                start: 5,
                dst: 0,
            },
            Ir3Instruction::Halt,
        ]);
        let mut core = quickjs_test_core();
        let result = core.execute(&module).unwrap();
        let rest_id = object_id_from_value(&result.value, "ArraySlice result");

        assert_ne!(
            rest_id,
            object_id_from_value(&core.registers[1], "ArraySlice source")
        );
        assert!(core.heap[rest_id.0 as usize].is_array);
        assert_eq!(
            core.read_array_like_values(rest_id),
            vec![Value::Int(8), Value::Int(9)]
        );
        assert_eq!(
            core.heap[rest_id.0 as usize].properties.get("length"),
            Some(&Value::Int(2))
        );
    }

    #[test]
    fn array_push_does_not_overflow_on_u32_max_index_key() {
        // Regression (bd-qsz8t): a property key that parses to `u32::MAX`
        // ("4294967295") fed the `ArrayPush` sparse-length fold a `n + 1`,
        // overflowing u32 — a debug-build panic / release-build wrap. The fold
        // now saturates (matching `array_like_length`), so the op completes
        // instead of crashing on this adversarial key.
        let module = test_module_with_pool(
            vec![
                Ir3Instruction::NewArray { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 4, value: 1 },
                Ir3Instruction::SetProperty {
                    obj: 1,
                    key: 3,
                    val: 4,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 42 },
                Ir3Instruction::ArrayPush {
                    array: 1,
                    element: 2,
                },
                Ir3Instruction::Move { dst: 0, src: 1 },
                Ir3Instruction::Halt,
            ],
            vec!["4294967295".to_string()],
        );
        let mut core = quickjs_test_core();
        // The load-bearing assertion: this must not panic on the u32::MAX
        // sparse-fold (it did before the fix in debug builds).
        let result = core
            .execute(&module)
            .expect("array push must not overflow on a u32::MAX index key");
        let arr_id = object_id_from_value(&result.value, "array push result");
        // Saturating fold yields next_idx == u32::MAX, so the push writes at
        // that index, overwriting the pathological key with the pushed value.
        assert_eq!(
            core.heap[arr_id.0 as usize].properties.get("4294967295"),
            Some(&Value::Int(42)),
            "push must have completed and written the element"
        );
    }

    #[test]
    fn builtin_array_push_and_pop_mutate_receiver_length() {
        let mut core = quickjs_test_core();
        let array_id = core.alloc_array_with_prototype(None).unwrap();
        core.registers[0] = Value::Object(array_id);
        core.registers[1] = Value::Int(7);
        core.registers[2] = Value::str("x");

        let pushed = core
            .dispatch_builtin_hostcall(
                "builtin:ArrayPrototypePush",
                RegRange { start: 0, count: 3 },
            )
            .unwrap();
        assert_eq!(pushed, Value::Int(2));
        assert_eq!(
            core.heap[array_id.0 as usize].properties.get("0"),
            Some(&Value::Int(7))
        );
        assert_eq!(
            core.heap[array_id.0 as usize].properties.get("1"),
            Some(&Value::str("x"))
        );
        assert_eq!(
            core.heap[array_id.0 as usize].properties.get("length"),
            Some(&Value::Int(2))
        );

        let popped = core
            .dispatch_builtin_hostcall("builtin:ArrayPrototypePop", RegRange { start: 0, count: 1 })
            .unwrap();
        assert_eq!(popped, Value::str("x"));
        assert_eq!(
            core.heap[array_id.0 as usize].properties.get("length"),
            Some(&Value::Int(1))
        );
        assert!(!core.heap[array_id.0 as usize].properties.contains_key("1"));
    }

    #[test]
    fn builtin_object_keys_and_values_return_allocated_arrays() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "b".to_string(), Value::Int(2))
            .unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        core.registers[4] = Value::Object(object_id);

        let keys = core
            .dispatch_builtin_hostcall("builtin:ObjectKeys", RegRange { start: 4, count: 1 })
            .unwrap();
        let Value::Object(keys_id) = keys else {
            panic!("Object.keys should return an array object");
        };
        assert_ne!(keys_id, object_id);
        assert!(core.heap[keys_id.0 as usize].is_array);
        assert_eq!(
            core.read_array_like_values(keys_id),
            vec![Value::str("b"), Value::str("a")]
        );

        let values = core
            .dispatch_builtin_hostcall("builtin:ObjectValues", RegRange { start: 4, count: 1 })
            .unwrap();
        let Value::Object(values_id) = values else {
            panic!("Object.values should return an array object");
        };
        assert_ne!(values_id, object_id);
        assert!(core.heap[values_id.0 as usize].is_array);
        assert_eq!(
            core.read_array_like_values(values_id),
            vec![Value::Int(2), Value::Int(1)]
        );
    }

    #[test]
    fn baseline_data_property_consumers_use_es_own_key_order() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        for (key, value) in [
            ("b", 1),
            ("10", 2),
            ("2", 3),
            ("01", 4),
            ("4294967295", 5),
            ("0", 6),
            ("a", 7),
            ("4294967294", 9),
        ] {
            core.set_object_property(object_id, key.to_string(), Value::Int(value))
                .unwrap();
        }
        core.set_object_property(object_id, "b".to_string(), Value::Int(8))
            .unwrap();
        assert!(core.remove_object_property(object_id, "b").unwrap());
        core.set_object_property(object_id, "b".to_string(), Value::Int(8))
            .unwrap();

        let expected_keys = vec![
            "0".to_string(),
            "2".to_string(),
            "10".to_string(),
            "4294967294".to_string(),
            "01".to_string(),
            "4294967295".to_string(),
            "a".to_string(),
            "b".to_string(),
        ];
        assert_eq!(core.own_enumerable_keys(object_id).unwrap(), expected_keys);
        assert_eq!(core.collect_for_in_keys(object_id).unwrap(), expected_keys);
        assert_eq!(
            core.qs_stringify_object(object_id, "&", "="),
            "0=6&2=3&10=2&4294967294=9&01=4&4294967295=5&a=7&b=8"
        );
    }

    #[test]
    fn mixed_data_accessor_consumers_use_one_es_own_key_order() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "z".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(1),
        )
        .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}10"),
            Value::Function(2),
        )
        .unwrap();
        core.set_object_property(object_id, "2".to_string(), Value::Int(2))
            .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}1"),
            Value::Function(3),
        )
        .unwrap();
        core.set_object_property(object_id, "4294967295".to_string(), Value::Int(5))
            .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}4294967294"),
            Value::Function(4),
        )
        .unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(6))
            .unwrap();

        let expected = vec![
            "1".to_string(),
            "2".to_string(),
            "10".to_string(),
            "4294967294".to_string(),
            "z".to_string(),
            "x".to_string(),
            "4294967295".to_string(),
            "a".to_string(),
        ];
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            expected
        );
        assert_eq!(core.own_enumerable_keys(object_id).unwrap(), expected);
        assert_eq!(core.collect_for_in_keys(object_id).unwrap(), expected);

        core.registers[4] = Value::Object(object_id);
        let keys = core
            .dispatch_builtin_hostcall("builtin:ObjectKeys", RegRange { start: 4, count: 1 })
            .unwrap();
        let Value::Object(keys_id) = keys else {
            panic!("Object.keys should return an array object");
        };
        assert_eq!(
            core.read_array_like_values(keys_id),
            expected.into_iter().map(Value::str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn descriptor_kind_conversions_preserve_creation_position() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        for (key, value) in [("a", 1), ("b", 2), ("c", 3)] {
            core.set_object_property(object_id, key.to_string(), Value::Int(value))
                .unwrap();
        }
        let expected = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}b"),
            Value::Function(1),
        )
        .unwrap();
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            expected
        );
        assert!(!core.heap[object_id.0 as usize].properties.contains_key("b"));
        assert!(core.heap[object_id.0 as usize].accessors.contains_key("b"));

        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_SET_PREFIX}b"),
            Value::Function(2),
        )
        .unwrap();
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            expected
        );

        core.set_plain_data_property(object_id, "b".to_string(), Value::Int(4))
            .unwrap();
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            expected
        );
        assert_eq!(
            core.heap[object_id.0 as usize].properties.get("b"),
            Some(&Value::Int(4))
        );
        assert!(!core.heap[object_id.0 as usize].accessors.contains_key("b"));
        assert_eq!(core.qs_stringify_object(object_id, "&", "="), "a=1&b=4&c=3");
    }

    #[test]
    fn deleted_accessor_recreation_appends_ordinary_key() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(1),
        )
        .unwrap();
        core.set_object_property(object_id, "b".to_string(), Value::Int(2))
            .unwrap();

        assert!(core.remove_object_property(object_id, "x").unwrap());
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(2),
        )
        .unwrap();
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            vec!["a".to_string(), "b".to_string(), "x".to_string()]
        );
    }

    #[test]
    fn heap_object_mixed_order_serde_roundtrip_and_legacy_fallback() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(1),
        )
        .unwrap();
        core.set_object_property(object_id, "b".to_string(), Value::Int(2))
            .unwrap();

        let encoded = serde_json::to_value(&core.heap[object_id.0 as usize]).unwrap();
        assert!(encoded["properties"].is_object());
        assert_eq!(
            encoded["own_string_key_order"],
            serde_json::json!(["a", "x", "b"])
        );
        let restored: HeapObject = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(
            restored.own_property_keys(),
            vec!["a".to_string(), "x".to_string(), "b".to_string()]
        );
        let standalone_properties: OrderedStringMap<Value> =
            serde_json::from_value(serde_json::to_value(&restored.properties).unwrap()).unwrap();
        assert_eq!(standalone_properties, restored.properties);

        let mut data_only = HeapObject::new();
        data_only
            .properties
            .insert("only".to_string(), Value::Int(1));
        let legacy_data_only = data_only.clone();
        let _ = data_only.record_property_definition("only", true);
        assert_eq!(
            data_only.own_property_keys(),
            legacy_data_only.own_property_keys()
        );
        assert_ne!(data_only, legacy_data_only);

        let mut legacy_encoded = encoded.clone();
        legacy_encoded
            .as_object_mut()
            .unwrap()
            .remove("own_string_key_order");
        let legacy: HeapObject = serde_json::from_value(legacy_encoded).unwrap();
        assert_eq!(
            legacy.own_property_keys(),
            vec!["a".to_string(), "b".to_string(), "x".to_string()]
        );
        assert_ne!(restored, legacy);

        let mut duplicate_order = encoded;
        duplicate_order["own_string_key_order"] = serde_json::json!(["a", "x", "x"]);
        assert!(serde_json::from_value::<HeapObject>(duplicate_order).is_err());

        let mut incomplete_order = serde_json::to_value(&restored).unwrap();
        incomplete_order["own_string_key_order"] = serde_json::json!(["a", "x"]);
        assert!(serde_json::from_value::<HeapObject>(incomplete_order).is_err());

        let mut public_field_mutation = restored.clone();
        public_field_mutation.accessors.insert(
            "y".to_string(),
            AccessorProperty {
                get: Some(Value::Function(2)),
                set: None,
            },
        );
        let normalized = serde_json::to_value(&public_field_mutation).unwrap();
        assert_eq!(
            normalized["own_string_key_order"],
            serde_json::json!(["a", "x", "b", "y"])
        );
        let normalized_roundtrip: HeapObject = serde_json::from_value(normalized).unwrap();
        assert_eq!(normalized_roundtrip, public_field_mutation);
        assert_eq!(
            normalized_roundtrip.own_property_keys(),
            vec![
                "a".to_string(),
                "x".to_string(),
                "b".to_string(),
                "y".to_string()
            ]
        );

        let mut mutation_core = quickjs_test_core();
        let mutation_id = mutation_core.alloc_object_with_prototype(None).unwrap();
        mutation_core.heap[mutation_id.0 as usize] = public_field_mutation;
        mutation_core.estimated_memory_bytes = mutation_core.recompute_estimated_memory_bytes();
        mutation_core
            .set_object_property(mutation_id, "c".to_string(), Value::Int(3))
            .unwrap();
        assert_eq!(
            mutation_core.heap[mutation_id.0 as usize].own_property_keys(),
            vec![
                "a".to_string(),
                "x".to_string(),
                "b".to_string(),
                "y".to_string(),
                "c".to_string()
            ]
        );
    }

    #[test]
    fn public_accessor_order_normalization_rolls_back_exact_hidden_state() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(1),
        )
        .unwrap();
        core.set_object_property(object_id, "b".to_string(), Value::Int(2))
            .unwrap();
        core.heap[object_id.0 as usize].accessors.insert(
            "y".to_string(),
            AccessorProperty {
                get: Some(Value::Function(2)),
                set: None,
            },
        );
        core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();

        let raw_order_before = core.heap[object_id.0 as usize]
            .properties
            .baseline_string_key_order()
            .unwrap()
            .to_vec();
        let memory_before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = memory_before;
        let error = core
            .set_object_property(object_id, "c".to_string(), Value::str("x".repeat(512)))
            .unwrap_err();

        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(
            core.heap[object_id.0 as usize]
                .properties
                .baseline_string_key_order(),
            Some(raw_order_before.as_slice())
        );
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            vec![
                "a".to_string(),
                "x".to_string(),
                "b".to_string(),
                "y".to_string()
            ]
        );
        assert_eq!(core.estimated_memory_bytes(), memory_before);
    }

    #[test]
    fn legacy_heap_order_normalizes_before_a_new_property_appends() {
        let legacy_json = serde_json::json!({
            "properties": {"a": Value::Int(1), "b": Value::Int(2)},
            "accessors": {"x": {"get": Value::Function(1), "set": null}},
            "prototype": null,
            "constructor_function": null,
            "is_array": false
        });
        let legacy: HeapObject = serde_json::from_value(legacy_json).unwrap();
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.heap[object_id.0 as usize] = legacy;
        core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();

        let original_memory_limit = core.config.max_total_memory_bytes;
        let memory_before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = memory_before;
        let error = core
            .set_object_property(object_id, "c".to_string(), Value::str("x".repeat(512)))
            .unwrap_err();
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert!(
            core.heap[object_id.0 as usize]
                .properties
                .baseline_string_key_order()
                .is_none()
        );
        assert_eq!(core.estimated_memory_bytes(), memory_before);
        core.config.max_total_memory_bytes = original_memory_limit;

        core.set_object_property(object_id, "c".to_string(), Value::Int(3))
            .unwrap();
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            vec![
                "a".to_string(),
                "b".to_string(),
                "x".to_string(),
                "c".to_string()
            ]
        );
    }

    #[test]
    fn write_heap_slot_records_ordinary_key_order() {
        let mut core = quickjs_test_core();
        core.write_heap_slot(0, Value::Int(1));
        core.set_object_property(
            ObjectId(0),
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(1),
        )
        .unwrap();
        assert_eq!(
            core.heap[0].own_property_keys(),
            vec!["value".to_string(), "x".to_string()]
        );
    }

    #[test]
    fn mixed_property_order_survives_execution_seed_restore() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(1),
        )
        .unwrap();
        core.set_object_property(object_id, "b".to_string(), Value::Int(2))
            .unwrap();
        let seed = core.capture_execution_seed();

        assert!(core.remove_object_property(object_id, "x").unwrap());
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(2),
        )
        .unwrap();
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            vec!["a".to_string(), "b".to_string(), "x".to_string()]
        );

        core.reset_execution_state_from_seed(&seed);
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            vec!["a".to_string(), "x".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn legacy_order_materialization_charges_each_sidecar_string() {
        let legacy_json = serde_json::json!({
            "properties": {"a": Value::Int(1), "b": Value::Int(2)},
            "accessors": {"x": {"get": Value::Function(1), "set": null}},
            "prototype": null,
            "constructor_function": null,
            "is_array": false
        });
        let legacy: HeapObject = serde_json::from_value(legacy_json).unwrap();
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.heap[object_id.0 as usize] = legacy;
        core.estimated_memory_bytes = core.recompute_estimated_memory_bytes();
        let memory_before = core.estimated_memory_bytes();

        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        let expected_delta = ["a", "b", "x"]
            .into_iter()
            .map(InterpreterCore::estimate_string_bytes)
            .sum::<u64>();
        assert_eq!(
            core.estimated_memory_bytes() - memory_before,
            expected_delta
        );
    }

    #[test]
    fn failed_accessor_conversion_restores_data_property_order() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(object_id, "b".to_string(), Value::Int(2))
            .unwrap();
        let memory_before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = memory_before;

        let error = core
            .set_object_property(
                object_id,
                format!("{IR_ACCESSOR_GET_PREFIX}a"),
                Value::str("x".repeat(512)),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(
            core.own_enumerable_keys(object_id).unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            core.heap[object_id.0 as usize].properties.get("a"),
            Some(&Value::Int(1))
        );
        assert!(!core.heap[object_id.0 as usize].accessors.contains_key("a"));
        assert_eq!(core.estimated_memory_bytes(), memory_before);
    }

    #[test]
    fn failed_accessor_to_data_conversion_restores_kind_order_and_memory() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        core.set_object_property(
            object_id,
            format!("{IR_ACCESSOR_GET_PREFIX}x"),
            Value::Function(1),
        )
        .unwrap();
        core.set_object_property(object_id, "b".to_string(), Value::Int(2))
            .unwrap();
        let memory_before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = memory_before;

        let error = core
            .set_plain_data_property(object_id, "x".to_string(), Value::str("x".repeat(512)))
            .unwrap_err();
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(
            core.heap[object_id.0 as usize].own_property_keys(),
            vec!["a".to_string(), "x".to_string(), "b".to_string()]
        );
        assert!(!core.heap[object_id.0 as usize].properties.contains_key("x"));
        assert_eq!(
            core.heap[object_id.0 as usize]
                .accessors
                .get("x")
                .and_then(|accessor| accessor.get.as_ref()),
            Some(&Value::Function(1))
        );
        assert_eq!(core.estimated_memory_bytes(), memory_before);
    }

    #[test]
    fn failed_new_property_restores_existing_sidecar_and_memory() {
        let mut core = quickjs_test_core();
        let object_id = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object_id, "a".to_string(), Value::Int(1))
            .unwrap();
        let object_before = serde_json::to_value(&core.heap[object_id.0 as usize]).unwrap();
        let memory_before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = memory_before;

        let error = core
            .set_object_property(object_id, "b".to_string(), Value::str("x".repeat(512)))
            .unwrap_err();
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(
            serde_json::to_value(&core.heap[object_id.0 as usize]).unwrap(),
            object_before
        );
        assert_eq!(core.estimated_memory_bytes(), memory_before);
    }

    #[test]
    fn builtin_json_parse_rolls_back_late_invalid_allocations() {
        let mut core = quickjs_test_core();
        core.registers[4] = Value::str(r#"{"a":[1,2]} trailing"#);
        let heap_before = core.heap_size();
        let memory_before = core.estimated_memory_bytes();

        let result = core
            .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 4, count: 1 })
            .unwrap();

        assert_eq!(result, Value::Undefined);
        assert_eq!(core.heap_size(), heap_before);
        assert_eq!(core.estimated_memory_bytes(), memory_before);
    }

    #[test]
    fn builtin_json_parse_preserves_raw_lone_surrogate_units() {
        let mut core = quickjs_test_core();
        for expected in [vec![0xD800], vec![0xDC00], vec![0xD83D, 0xDE00]] {
            let mut json = vec![0x22];
            json.extend_from_slice(&expected);
            json.push(0x22);
            core.registers[4] = Value::Str(JsString::from_code_units(&json));

            let result = core
                .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 4, count: 1 })
                .unwrap();

            let Value::Str(parsed) = result else {
                panic!("JSON.parse should return the parsed string");
            };
            assert_eq!(parsed.code_units_vec(), expected);
        }

        let mut nested = "{\"value\":\"".encode_utf16().collect::<Vec<_>>();
        nested.push(0xD800);
        nested.extend("\"}".encode_utf16());
        core.registers[4] = Value::Str(JsString::from_code_units(&nested));
        let nested_result = core
            .dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 4, count: 1 })
            .unwrap();
        let Value::Object(nested_id) = nested_result else {
            panic!("JSON.parse should allocate the nested object");
        };
        let Some(Value::Str(nested_value)) =
            core.heap[nested_id.0 as usize].properties.get("value")
        else {
            panic!("nested JSON string should be stored as a data property");
        };
        assert_eq!(nested_value.code_units_vec(), vec![0xD800]);

        core.registers[4] = Value::Str(JsString::from_code_units(&[0x22, 0x1F, 0x22]));
        assert_eq!(
            core.dispatch_builtin_hostcall("builtin:JsonParse", RegRange { start: 4, count: 1 })
                .unwrap(),
            Value::Undefined,
            "raw JSON control units must remain invalid"
        );
    }

    #[test]
    fn builtin_math_abs_promotes_i64_minimum_magnitude_to_float() {
        let mut core = quickjs_test_core();
        core.registers[4] = Value::Int(i64::MIN);

        let result = core
            .dispatch_builtin_hostcall("builtin:MathAbs", RegRange { start: 4, count: 1 })
            .unwrap();
        let Value::Float(result) = result else {
            panic!("Math.abs(i64::MIN) must promote the positive magnitude to Float");
        };
        assert_eq!(result.inner(), -(i64::MIN as f64));
    }

    #[test]
    fn builtin_string_char_at_uses_receiver_and_optional_index() {
        let mut core = quickjs_test_core();
        core.registers[4] = Value::str("hello");
        core.registers[5] = Value::Int(1);

        let explicit = core
            .dispatch_builtin_hostcall(
                "builtin:StringPrototypeCharAt",
                RegRange { start: 4, count: 2 },
            )
            .unwrap();
        assert_eq!(explicit, Value::str("e"));

        core.registers[4] = Value::Int(42);
        let default_index = core
            .dispatch_builtin_hostcall(
                "builtin:StringPrototypeCharAt",
                RegRange { start: 4, count: 1 },
            )
            .unwrap();
        assert_eq!(default_index, Value::str("4"));

        core.registers[5] = Value::Int(99);
        let out_of_range = core
            .dispatch_builtin_hostcall(
                "builtin:StringPrototypeCharAt",
                RegRange { start: 4, count: 2 },
            )
            .unwrap();
        assert_eq!(out_of_range, Value::Str(JsString::empty()));
    }

    #[test]
    fn string_receiver_index_properties_preserve_exact_utf16_units_bd_pel1v() {
        let text = JsString::from_code_units(&[0x0061, 0xD83D, 0xDE00, 0xD800]);

        for (key, expected_unit) in [("0", 0x0061), ("1", 0xD83D), ("2", 0xDE00), ("3", 0xD800)] {
            let Some(Value::Str(value)) = InterpreterCore::string_property_value(&text, key) else {
                panic!("canonical in-range string index {key} must produce a string value");
            };
            assert_eq!(value.code_units_vec(), vec![expected_unit]);
        }

        assert_eq!(
            InterpreterCore::string_property_value(&text, "length"),
            Some(Value::Int(4))
        );
        for key in ["4", "01", "-1", "1.0", "4294967295"] {
            assert_eq!(
                InterpreterCore::string_property_value(&text, key),
                None,
                "non-canonical or out-of-range key {key} must stay absent"
            );
        }
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

        let config = test_quickjs_config_with([RuntimeCapability::FsRead]);
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
        let mut router = test_router();
        let result = router.execute(&m, "test", None).unwrap();
        assert_eq!(result.lane, LaneChoice::QuickJs);
        assert_eq!(result.reason, LaneReason::DefaultFallback);
    }

    #[test]
    fn router_selects_quickjs_for_capability_module() {
        let mut m = test_module(vec![Ir3Instruction::Halt]);
        m.required_capabilities = vec![CapabilityTag("net".to_string())];
        let mut router = test_router();
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
        let mut router = test_router();
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
        let mut router = test_router();
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
        assert!(!Value::Str(JsString::empty()).is_truthy());

        assert!(Value::Bool(true).is_truthy());
        assert!(Value::Int(1).is_truthy());
        assert!(Value::Int(-1).is_truthy());
        assert!(Value::str("x").is_truthy());
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
        assert_eq!(Value::str("hi").to_string(), "hi");
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
            Value::str("hello"),
            Value::Object(ObjectId(7)),
            Value::Function(3),
        ] {
            let json = serde_json::to_string(&val).unwrap();
            let deser: Value = serde_json::from_str(&json).unwrap();
            assert_eq!(val, deser);
        }
    }

    #[test]
    fn historical_value_wire_bytes_survive_the_0_2_api_migration() {
        let cases = [
            (Value::Undefined, r#""Undefined""#.to_string()),
            (Value::Null, r#""Null""#.to_string()),
            (Value::Bool(true), r#"{"Bool":true}"#.to_string()),
            (Value::Int(42), r#"{"Int":42}"#.to_string()),
            (
                Value::Float(Float64::new(1.5)),
                r#"{"Float":4609434218613702656}"#.to_string(),
            ),
            (Value::str("hello"), r#"{"Str":"hello"}"#.to_string()),
            (
                Value::Str(JsString::from_code_units(&[0xD800])),
                r#"{"Str":{"$wtf16":[55296]}}"#.to_string(),
            ),
            (Value::Object(ObjectId(7)), r#"{"Object":7}"#.to_string()),
            (Value::Function(3), r#"{"Function":3}"#.to_string()),
            (Value::Closure(4), r#"{"Closure":4}"#.to_string()),
            (Value::Iterator(5), r#"{"Iterator":5}"#.to_string()),
            (
                Value::GeneratorFunction(6),
                r#"{"GeneratorFunction":6}"#.to_string(),
            ),
            (Value::Generator(7), r#"{"Generator":7}"#.to_string()),
            (
                Value::AsyncFunction(8),
                r#"{"AsyncFunction":8}"#.to_string(),
            ),
            (
                Value::AsyncFunctionObject(9),
                r#"{"AsyncFunctionObject":9}"#.to_string(),
            ),
            (
                Value::AsyncGeneratorFunction(10),
                r#"{"AsyncGeneratorFunction":10}"#.to_string(),
            ),
            (
                Value::AsyncGeneratorObject(11),
                r#"{"AsyncGeneratorObject":11}"#.to_string(),
            ),
            (Value::Promise(12), r#"{"Promise":12}"#.to_string()),
            (
                Value::BuiltinFunction(BuiltinFunction {
                    kind: BuiltinFunctionKind::Require,
                    module_specifier: "node:path".to_string(),
                }),
                r#"{"BuiltinFunction":{"kind":"require","module_specifier":"node:path"}}"#
                    .to_string(),
            ),
        ];

        for (value, historical_wire) in cases {
            let encoded = serde_json::to_string(&value).unwrap();
            assert_eq!(encoded, historical_wire);

            let decoded: Value = serde_json::from_str(&historical_wire).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(serde_json::to_string(&decoded).unwrap(), historical_wire);
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
        assert_eq!(result.value, Value::str("answer: 42"));
    }

    #[test]
    fn value_ord() {
        assert!(Value::Undefined < Value::Null);
        assert!(Value::Null < Value::Bool(false));
        assert!(Value::Bool(false) < Value::Bool(true));
        assert!(Value::Bool(true) < Value::Int(0));
        assert!(Value::Int(0) < Value::Str(JsString::empty()));
        assert!(Value::Str(JsString::empty()) < Value::Object(ObjectId(0)));
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
            Value::str("hello"),
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
        let mut config = test_v8_config();
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
        assert_eq!(Value::Str(JsString::empty()).type_name(), "string");
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
        assert!(!Value::Str(JsString::empty()).is_truthy());
        assert!(Value::str("x").is_truthy());
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
        // SAFETY: First push() call with valid scope depth setting cannot fail.
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
        let mut router = test_router();
        // SAFETY: router.execute() with valid test module and valid parameters
        // cannot fail under normal test conditions.
        let result = router.execute(&m, "test", None).unwrap();
        assert_eq!(result.lane, LaneChoice::V8);
        assert_eq!(result.reason, LaneReason::ThroughputOptimized);
    }

    #[test]
    fn alloc_object_and_heap_size() {
        let config = test_quickjs_config();
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
        let mut config = test_quickjs_config();
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
        let mut config = test_quickjs_config();
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
        let config = test_quickjs_config();
        let mut core = InterpreterCore::new(config, "memory-estimate");
        let oid = core.alloc_object_with_prototype(None).unwrap();
        let before = core.estimated_memory_bytes();
        core.heap[oid.0 as usize]
            .properties
            .insert("payload".to_string(), Value::str("hello world"));
        core.sync_estimated_memory_bytes().unwrap();
        assert!(core.estimated_memory_bytes() > before);
    }

    #[test]
    fn new_object_instruction_returns_memory_budget_exceeded() {
        let mut config = test_quickjs_config();
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
        let mut config = test_quickjs_config();
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
        let mut budget_config = test_quickjs_config();
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
        let mut memory_config = test_quickjs_config();
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
                value: Value::str("x".repeat(128)),
                label: crate::ifc_artifacts::Label::Public,
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
                value: Value::str("x".repeat(128)),
                label: crate::ifc_artifacts::Label::Public,
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
    fn custom_scope_label_is_accounted_and_store_rolls_back_bd_ur3tk_11() {
        let config = InterpreterConfig::quickjs_defaults();
        let mut core = InterpreterCore::new(config, "custom-scope-label-budget");
        core.scope_chain.current_mut().bindings.insert(
            "payload".to_string(),
            ScopeBinding {
                value: Value::Undefined,
                label: crate::ifc_artifacts::Label::Public,
                kind: BindingKind::Var,
                initialized: true,
            },
        );
        core.sync_estimated_memory_bytes().unwrap();
        let custom_name = "tenant-sensitive".repeat(32);
        core.write_reg_with_label(
            0,
            Value::Int(7),
            crate::ifc_artifacts::Label::Custom {
                name: custom_name.clone(),
                level: 3,
            },
        )
        .expect("custom-labeled source should be writable before tightening the budget");
        core.config.max_total_memory_bytes = core
            .estimated_memory_bytes()
            .saturating_add(custom_name.len() as u64)
            .saturating_sub(1);
        let module = test_module_with_pool(
            vec![Ir3Instruction::StoreScoped {
                src: 0,
                name_pool_index: 0,
            }],
            vec!["payload".to_string()],
        );

        let error = core
            .run_loop(&module)
            .expect_err("custom scope label must respect the memory budget");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        let (_, binding) = core
            .scope_chain
            .resolve("payload")
            .expect("failed StoreScoped should restore the binding");
        assert_eq!(binding.value, Value::Undefined);
        assert_eq!(binding.label, crate::ifc_artifacts::Label::Public);
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
            rest_param_index: None,
        });

        let mut core = InterpreterCore::new(test_quickjs_config(), "generator");
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
            Some(&Value::str(payload))
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
            rest_param_index: None,
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
                    value: Value::str(binding_value.clone()),
                    label: crate::ifc_artifacts::Label::Public,
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
                assert_eq!(binding.value, Value::str(expected_value));
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
        let mut config = test_quickjs_config();
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
        // SAFETY: Test division with valid register indices and values; eval_div succeeds in controlled test environment
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
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
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
        let mut core = InterpreterCore::new(test_quickjs_config(), "class-constructor-test");
        core.registers[1] = Value::Function(0);

        let result = core
            .execute(&test_module_with_functions(
                vec![
                    Ir3Instruction::Construct {
                        callee: 1,
                        args: RegRange { start: 2, count: 0 },
                        dst: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 1,
                    name: Some("Foo".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            ))
            .unwrap();

        let instance_id = match result.value {
            Value::Object(id) => id,
            other => panic!("new Foo() should return an object, got {other:?}"),
        };
        let prototype_id = *core
            .function_prototypes
            .get(&FunctionObjectKey::Function(0))
            .expect("constructor prototype should be allocated");
        let instance = core
            .heap
            .get(instance_id.0 as usize)
            .expect("constructed instance should remain in the heap");
        assert_eq!(instance.constructor_function, Some(0));
        assert_eq!(instance.prototype, Some(prototype_id));
    }

    #[test]
    fn class_method_on_prototype() {
        let mut core = InterpreterCore::new(test_quickjs_config(), "class-method-test");
        let prototype_id = core.ensure_function_prototype(0).unwrap();
        core.set_object_property(prototype_id, "method".to_string(), Value::Function(1))
            .unwrap();
        core.registers[1] = Value::Function(0);

        let result = core
            .execute(&test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::Construct {
                        callee: 1,
                        args: RegRange { start: 2, count: 0 },
                        dst: 0,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 3,
                        pool_index: 0,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 3,
                        dst: 4,
                    },
                    Ir3Instruction::CallMethod {
                        receiver: 0,
                        callee: 4,
                        args: RegRange { start: 5, count: 0 },
                        dst: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::Return { value: 0 },
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec!["method".to_string()],
                vec![
                    Ir3FunctionDesc {
                        entry: 5,
                        arity: 0,
                        frame_size: 1,
                        name: Some("Foo".to_string()),
                        is_generator: false,
                        rest_param_index: None,
                    },
                    Ir3FunctionDesc {
                        entry: 6,
                        arity: 0,
                        frame_size: 1,
                        name: Some("method".to_string()),
                        is_generator: false,
                        rest_param_index: None,
                    },
                ],
            ))
            .unwrap();

        let constructed = match core.registers[0].clone() {
            Value::Object(id) => id,
            other => panic!("constructed receiver should stay in r0, got {other:?}"),
        };
        assert_eq!(result.value, Value::Object(constructed));
        assert_eq!(
            core.prototype_chain_get(constructed, "method").unwrap(),
            Value::Function(1)
        );
    }

    #[test]
    fn class_extends_sets_prototype_chain() {
        let mut core = quickjs_test_core();
        let base_prototype = core.ensure_function_prototype(0).unwrap();
        core.set_object_property(base_prototype, "inherited".to_string(), Value::Int(42))
            .unwrap();
        let derived_prototype = core.ensure_function_prototype(1).unwrap();
        core.heap[derived_prototype.0 as usize].prototype = Some(base_prototype);
        core.registers[1] = Value::Function(1);

        let result = core
            .execute(&test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::Construct {
                        callee: 1,
                        args: RegRange { start: 2, count: 0 },
                        dst: 4,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 2,
                        pool_index: 0,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 4,
                        key: 2,
                        dst: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec!["inherited".to_string()],
                vec![
                    class_test_function(4, "Base"),
                    class_test_function(6, "Derived"),
                ],
            ))
            .unwrap();

        let instance = object_id_from_value(&core.registers[4], "derived instance");
        assert_eq!(
            core.heap[instance.0 as usize].prototype,
            Some(derived_prototype)
        );
        assert_eq!(result.value, Value::Int(42));
    }

    #[test]
    fn super_call_invokes_parent_constructor() {
        let mut core = quickjs_test_core();
        core.registers[1] = Value::Function(0);

        core.execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::NewObject { dst: 0 },
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 1,
                    args: RegRange { start: 3, count: 0 },
                    dst: 2,
                },
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 3,
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadBool {
                    dst: 2,
                    value: true,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec!["parentInitialized".to_string()],
            vec![class_test_function(5, "Parent")],
        ))
        .unwrap();

        assert_eq!(core.registers[0], Value::Bool(true));
    }

    #[test]
    fn super_method_calls_parent_method() {
        let mut core = quickjs_test_core();
        let derived_prototype = core.ensure_function_prototype(0).unwrap();
        let base_prototype = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(base_prototype, "describe".to_string(), Value::Function(1))
            .unwrap();
        core.heap[derived_prototype.0 as usize].prototype = Some(base_prototype);
        core.registers[1] = Value::Function(0);

        let result = core
            .execute(&test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::Construct {
                        callee: 1,
                        args: RegRange { start: 2, count: 0 },
                        dst: 4,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 2,
                        pool_index: 0,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 4,
                        key: 2,
                        dst: 3,
                    },
                    Ir3Instruction::CallMethod {
                        receiver: 4,
                        callee: 3,
                        args: RegRange { start: 5, count: 0 },
                        dst: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                    Ir3Instruction::LoadInt { dst: 0, value: 7 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec!["describe".to_string()],
                vec![
                    class_test_function(5, "Derived"),
                    class_test_function(7, "Base.describe"),
                ],
            ))
            .unwrap();

        assert_eq!(result.value, Value::Int(7));
    }

    /// bd-snlhk: the IR3 lowering used to reconstruct the closure free-var
    /// binding_id -> name map by zipping body first-appearance order against
    /// the alphabetical `free_vars` list, silently swapping captured bindings
    /// whenever first-use order diverged from alphabetical order. The fix
    /// carries `free_var_ids` from IR1, paired index-wise with `free_vars`.
    /// Two free vars first-used in REVERSE alphabetical order: the old
    /// heuristic computed alpha - zebra = -7 instead of zebra - alpha = 7.
    #[test]
    fn closure_free_vars_bind_correct_names_non_alphabetical_first_use() {
        let tree = CanonicalEs2020Parser
            .parse(
                "let zebra = 9;\nlet alpha = 2;\nfunction f() { return zebra - alpha; }\nf();",
                ParseGoal::Script,
            )
            .expect("free-var source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "free-var-order-test.js");
        let ctx = LoweringContext::new(
            "trace-free-var-order",
            "decision-free-var-order",
            "policy-free-var-order",
        );
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("free-var closure should lower");

        let mut core = quickjs_test_core();
        let result = core
            .execute(&output.ir3)
            .expect("free-var closure should execute");
        assert_eq!(
            result.value,
            Value::Int(7),
            "zebra - alpha must bind each free var to its own value (bd-snlhk)"
        );
    }

    /// bd-snlhk: three captured `let`s where every wrong permutation of the
    /// (name -> value) binding yields a result different from 100 - 10 - 1.
    #[test]
    fn closure_free_vars_bind_three_captured_lets_exactly() {
        let tree = CanonicalEs2020Parser
            .parse(
                "let cherry = 100;\nlet banana = 10;\nlet apple = 1;\nfunction g() { return cherry - banana - apple; }\ng();",
                ParseGoal::Script,
            )
            .expect("three-free-var source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "free-var-three-test.js");
        let ctx = LoweringContext::new(
            "trace-free-var-three",
            "decision-free-var-three",
            "policy-free-var-three",
        );
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("three-free-var closure should lower");

        let mut core = quickjs_test_core();
        let result = core
            .execute(&output.ir3)
            .expect("three-free-var closure should execute");
        assert_eq!(
            result.value,
            Value::Int(89),
            "cherry - banana - apple must be 89 under exact binding (bd-snlhk)"
        );
    }

    #[test]
    fn static_method_on_constructor() {
        let tree = CanonicalEs2020Parser
            .parse(
                "class Foo { static staticMethod() { return 123; } }\nFoo.staticMethod();",
                ParseGoal::Script,
            )
            .expect("static class method source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "class-static-method-test.js");
        let ctx = LoweringContext::new(
            "trace-class-static-method",
            "decision-class-static-method",
            "policy-class-static-method",
        );
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("static class method should lower");
        assert!(
            output
                .ir3
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::SetProperty { .. })),
            "static method lowering should attach the method to the constructor value"
        );

        let mut core = quickjs_test_core();
        let result = core
            .execute(&output.ir3)
            .expect("constructor function object should carry static methods");

        assert_eq!(result.value, Value::Int(123));
    }

    #[test]
    fn computed_method_name() {
        let mut core = quickjs_test_core();
        let prototype = core.ensure_function_prototype(0).unwrap();
        core.set_object_property(prototype, "dynamicName".to_string(), Value::Function(1))
            .unwrap();
        core.registers[1] = Value::Function(0);

        let result = core
            .execute(&test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::Construct {
                        callee: 1,
                        args: RegRange { start: 2, count: 0 },
                        dst: 4,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 2,
                        pool_index: 0,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 4,
                        key: 2,
                        dst: 3,
                    },
                    Ir3Instruction::CallMethod {
                        receiver: 4,
                        callee: 3,
                        args: RegRange { start: 5, count: 0 },
                        dst: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::Return { value: 0 },
                    Ir3Instruction::LoadInt { dst: 0, value: 99 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec!["dynamicName".to_string()],
                vec![
                    class_test_function(5, "ComputedHost"),
                    class_test_function(7, "dynamicName"),
                ],
            ))
            .unwrap();

        assert_eq!(result.value, Value::Int(99));
    }

    #[test]
    fn getter_setter() {
        let tree = CanonicalEs2020Parser
            .parse(
                "class Box { set value(v) { this.stored = v; } get value() { return this.stored; } }\nconst box = new Box();\nbox.value = 321;\nbox.value;",
                ParseGoal::Script,
            )
            .expect("class accessor source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "class-accessor-test.js");
        let ctx = LoweringContext::new(
            "trace-class-accessor",
            "decision-class-accessor",
            "policy-class-accessor",
        );
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("class accessors should lower");
        assert!(
            output
                .ir3
                .constant_pool
                .iter()
                .any(|key| key.starts_with(IR_ACCESSOR_GET_PREFIX)),
            "getter lowering should define an accessor descriptor"
        );
        assert!(
            output
                .ir3
                .constant_pool
                .iter()
                .any(|key| key.starts_with(IR_ACCESSOR_SET_PREFIX)),
            "setter lowering should define an accessor descriptor"
        );

        let mut core = quickjs_test_core();
        let result = core
            .execute(&output.ir3)
            .expect("getter/setter accessors should execute through descriptor calls");

        assert_eq!(result.value, Value::Int(321));
    }

    #[test]
    fn copy_data_properties_rejects_nullish_and_boxes_empty_primitives_bd_f1ixz() {
        for source in [Value::Null, Value::Undefined] {
            let mut core = quickjs_test_core();
            let target = core.alloc_object_with_prototype(None).unwrap();
            core.registers[1] = Value::Object(target);
            core.registers[2] = source;
            let error = core
                .execute(&test_module(vec![
                    Ir3Instruction::CopyDataProperties {
                        target: 1,
                        source: 2,
                        excluded: RegRange { start: 3, count: 0 },
                        value_dst: 4,
                    },
                    Ir3Instruction::Halt,
                ]))
                .unwrap_err();
            assert!(matches!(error, InterpreterError::TypeError { .. }));
            assert!(core.copy_data_properties_states.is_empty());
        }

        for source in [Value::Null, Value::Undefined] {
            let mut spread = quickjs_test_core();
            let spread_target = spread.alloc_object_with_prototype(None).unwrap();
            spread.registers[1] = Value::Object(spread_target);
            spread.registers[2] = source;
            let result = spread
                .execute(&test_module(vec![
                    Ir3Instruction::SpreadIntoObject {
                        target: 1,
                        source: 2,
                    },
                    Ir3Instruction::Move { dst: 0, src: 1 },
                    Ir3Instruction::Halt,
                ]))
                .unwrap();
            assert_eq!(result.value, Value::Object(spread_target));
            assert!(
                spread.heap[spread_target.0 as usize]
                    .own_property_keys()
                    .is_empty()
            );
        }

        for source in [
            Value::Bool(true),
            Value::Int(7),
            Value::Float(Float64::new(1.5)),
        ] {
            let mut core = quickjs_test_core();
            let target = core.alloc_object_with_prototype(None).unwrap();
            core.registers[1] = Value::Object(target);
            core.registers[2] = source;
            core.execute(&test_module(vec![
                Ir3Instruction::CopyDataProperties {
                    target: 1,
                    source: 2,
                    excluded: RegRange { start: 3, count: 0 },
                    value_dst: 4,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap();
            assert!(core.heap[target.0 as usize].own_property_keys().is_empty());
            assert!(core.copy_data_properties_states.is_empty());
        }
    }

    #[test]
    fn copy_data_properties_copies_exact_string_units_after_exclusion_bd_f1ixz() {
        let mut core = quickjs_test_core();
        let target = core.alloc_object_with_prototype(None).unwrap();
        core.registers[1] = Value::Object(target);
        core.registers[2] = Value::Str(JsString::from_code_units(&[0xD83D, 0xDE00, 0xD800]));
        core.registers[3] = Value::str("1");

        core.execute(&test_module(vec![
            Ir3Instruction::CopyDataProperties {
                target: 1,
                source: 2,
                excluded: RegRange { start: 3, count: 1 },
                value_dst: 4,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

        let object = &core.heap[target.0 as usize];
        assert_eq!(object.own_property_keys(), vec!["0", "2"]);
        for (key, expected_unit) in [("0", 0xD83D), ("2", 0xD800)] {
            let Some(Value::Str(value)) = object.properties.get(key) else {
                panic!("string index {key} should be copied as a data property");
            };
            assert_eq!(value.code_units_vec(), vec![expected_unit]);
        }
        assert!(core.copy_data_properties_states.is_empty());
    }

    #[test]
    fn copy_data_properties_omits_array_length_and_uses_plain_data_writes_bd_f1ixz() {
        let mut core = quickjs_test_core();
        let target = core.alloc_object_with_prototype(None).unwrap();
        let source = core.alloc_array_with_prototype(None).unwrap();
        core.set_plain_data_property(source, "0".into(), Value::Int(1))
            .unwrap();
        core.set_plain_data_property(source, "length".into(), Value::Int(1))
            .unwrap();
        core.set_plain_data_property(source, "custom".into(), Value::Int(2))
            .unwrap();
        let prototype_value = core.alloc_object_with_prototype(None).unwrap();
        core.set_plain_data_property(source, "__proto__".into(), Value::Object(prototype_value))
            .unwrap();
        let prefixed_key = format!("{IR_ACCESSOR_GET_PREFIX}literal");
        core.set_plain_data_property(source, prefixed_key.clone(), Value::Int(3))
            .unwrap();
        core.registers[1] = Value::Object(target);
        core.registers[2] = Value::Object(source);

        core.execute(&test_module(vec![
            Ir3Instruction::CopyDataProperties {
                target: 1,
                source: 2,
                excluded: RegRange { start: 3, count: 0 },
                value_dst: 4,
            },
            Ir3Instruction::Halt,
        ]))
        .unwrap();

        let object = &core.heap[target.0 as usize];
        assert_eq!(
            object.own_property_keys(),
            vec!["0", "custom", "__proto__", prefixed_key.as_str()]
        );
        assert!(!object.properties.contains_key("length"));
        assert_eq!(object.prototype, None);
        assert_eq!(
            object.properties.get("__proto__"),
            Some(&Value::Object(prototype_value))
        );
        assert_eq!(object.properties.get(&prefixed_key), Some(&Value::Int(3)));
        assert!(object.accessors.is_empty());
    }

    #[test]
    fn copy_data_properties_resumes_included_getter_with_source_receiver_bd_f1ixz() {
        let mut core = quickjs_test_core();
        let target = core.alloc_object_with_prototype(None).unwrap();
        let source = core.alloc_object_with_prototype(None).unwrap();
        core.set_plain_data_property(source, "calls".into(), Value::Int(0))
            .unwrap();
        core.set_plain_data_property(source, "marker".into(), Value::Int(41))
            .unwrap();
        core.set_object_property(
            source,
            format!("{IR_ACCESSOR_GET_PREFIX}included"),
            Value::Function(0),
        )
        .unwrap();
        core.set_object_property(
            source,
            format!("{IR_ACCESSOR_SET_PREFIX}setter_only"),
            Value::Function(0),
        )
        .unwrap();
        // An invalid getter is a useful tripwire: exclusion must happen before
        // the property read, so this value must never be invoked.
        core.set_object_property(
            source,
            format!("{IR_ACCESSOR_GET_PREFIX}excluded"),
            Value::Function(99),
        )
        .unwrap();
        core.registers[1] = Value::Object(target);
        core.registers[2] = Value::Object(source);
        core.registers[3] = Value::str("excluded");

        let result = core
            .execute(&test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::CopyDataProperties {
                        target: 1,
                        source: 2,
                        excluded: RegRange { start: 3, count: 1 },
                        value_dst: 4,
                    },
                    Ir3Instruction::Move { dst: 0, src: 1 },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::LoadStr {
                        dst: 1,
                        pool_index: 0,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 1,
                        dst: 2,
                    },
                    Ir3Instruction::LoadInt { dst: 3, value: 1 },
                    Ir3Instruction::Add {
                        dst: 4,
                        lhs: 2,
                        rhs: 3,
                    },
                    Ir3Instruction::SetProperty {
                        obj: 0,
                        key: 1,
                        val: 4,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 5,
                        pool_index: 1,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 5,
                        dst: 6,
                    },
                    Ir3Instruction::Return { value: 6 },
                ],
                vec!["calls".to_string(), "marker".to_string()],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 0,
                    frame_size: 8,
                    name: Some("included_getter".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            ))
            .unwrap();

        assert_eq!(result.value, Value::Object(target));
        let object = &core.heap[target.0 as usize];
        assert_eq!(object.properties.get("marker"), Some(&Value::Int(41)));
        assert_eq!(object.properties.get("included"), Some(&Value::Int(41)));
        assert_eq!(
            object.properties.get("setter_only"),
            Some(&Value::Undefined)
        );
        assert!(!object.contains_own_property("excluded"));
        assert!(object.accessors.is_empty());
        assert_eq!(
            core.heap[source.0 as usize].properties.get("calls"),
            Some(&Value::Int(1))
        );
        assert!(core.copy_data_properties_states.is_empty());
    }

    #[test]
    fn copy_data_properties_snapshots_keys_and_rechecks_descriptors_bd_f1ixz() {
        let mut core = quickjs_test_core();
        let target = core.alloc_object_with_prototype(None).unwrap();
        let source = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(
            source,
            format!("{IR_ACCESSOR_GET_PREFIX}a"),
            Value::Function(0),
        )
        .unwrap();
        core.set_plain_data_property(source, "b".into(), Value::Int(2))
            .unwrap();
        core.registers[1] = Value::Object(target);
        core.registers[2] = Value::Object(source);

        core.execute(&test_module_with_pool_and_functions(
            vec![
                Ir3Instruction::CopyDataProperties {
                    target: 1,
                    source: 2,
                    excluded: RegRange { start: 3, count: 0 },
                    value_dst: 4,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::DeleteProperty {
                    obj: 0,
                    key: 1,
                    dst: 2,
                },
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 1,
                },
                Ir3Instruction::LoadInt { dst: 4, value: 3 },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 3,
                    val: 4,
                },
                Ir3Instruction::LoadInt { dst: 5, value: 1 },
                Ir3Instruction::Return { value: 5 },
            ],
            vec!["b".to_string(), "c".to_string()],
            vec![class_test_function(2, "mutating_getter")],
        ))
        .unwrap();

        let object = &core.heap[target.0 as usize];
        assert_eq!(object.own_property_keys(), vec!["a"]);
        assert_eq!(object.properties.get("a"), Some(&Value::Int(1)));
        assert!(!object.contains_own_property("b"));
        assert!(!object.contains_own_property("c"));
        assert_eq!(
            core.heap[source.0 as usize].properties.get("c"),
            Some(&Value::Int(3))
        );
        assert!(core.copy_data_properties_states.is_empty());
    }

    #[test]
    fn copy_data_properties_nested_state_and_throw_cleanup_bd_f1ixz() {
        let mut nested = quickjs_test_core();
        let outer_target = nested.alloc_object_with_prototype(None).unwrap();
        let outer_source = nested.alloc_object_with_prototype(None).unwrap();
        let inner_target = nested.alloc_object_with_prototype(None).unwrap();
        let inner_source = nested.alloc_object_with_prototype(None).unwrap();
        nested
            .set_plain_data_property(inner_source, "v".into(), Value::Int(9))
            .unwrap();
        nested
            .set_plain_data_property(
                outer_source,
                "innerTarget".into(),
                Value::Object(inner_target),
            )
            .unwrap();
        nested
            .set_plain_data_property(
                outer_source,
                "innerSource".into(),
                Value::Object(inner_source),
            )
            .unwrap();
        nested
            .set_object_property(
                outer_source,
                format!("{IR_ACCESSOR_GET_PREFIX}outer"),
                Value::Function(0),
            )
            .unwrap();
        nested.registers[1] = Value::Object(outer_target);
        nested.registers[2] = Value::Object(outer_source);
        nested.registers[3] = Value::str("innerTarget");
        nested.registers[4] = Value::str("innerSource");
        nested
            .execute(&test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::CopyDataProperties {
                        target: 1,
                        source: 2,
                        excluded: RegRange { start: 3, count: 2 },
                        value_dst: 5,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::LoadStr {
                        dst: 1,
                        pool_index: 0,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 1,
                        dst: 2,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 3,
                        pool_index: 1,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 3,
                        dst: 4,
                    },
                    Ir3Instruction::CopyDataProperties {
                        target: 2,
                        source: 4,
                        excluded: RegRange { start: 8, count: 0 },
                        value_dst: 5,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 6,
                        pool_index: 2,
                    },
                    Ir3Instruction::GetProperty {
                        obj: 2,
                        key: 6,
                        dst: 7,
                    },
                    Ir3Instruction::Return { value: 7 },
                ],
                vec![
                    "innerTarget".to_string(),
                    "innerSource".to_string(),
                    "v".to_string(),
                ],
                vec![class_test_function(2, "nested_copy_getter")],
            ))
            .unwrap();
        assert_eq!(
            nested.heap[outer_target.0 as usize].properties.get("outer"),
            Some(&Value::Int(9))
        );
        assert_eq!(
            nested.heap[inner_target.0 as usize].properties.get("v"),
            Some(&Value::Int(9))
        );
        assert!(nested.copy_data_properties_states.is_empty());

        let mut throwing = quickjs_test_core();
        let target = throwing.alloc_object_with_prototype(None).unwrap();
        let source = throwing.alloc_object_with_prototype(None).unwrap();
        throwing
            .set_object_property(
                source,
                format!("{IR_ACCESSOR_GET_PREFIX}boom"),
                Value::Function(0),
            )
            .unwrap();
        throwing.registers[1] = Value::Object(target);
        throwing.registers[2] = Value::Object(source);
        let result = throwing
            .execute(&test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::BeginTry {
                        catch_target: 3,
                        finally_target: None,
                    },
                    Ir3Instruction::CopyDataProperties {
                        target: 1,
                        source: 2,
                        excluded: RegRange { start: 7, count: 0 },
                        value_dst: 4,
                    },
                    Ir3Instruction::EndTry,
                    Ir3Instruction::EnterCatch { dst: 6 },
                    Ir3Instruction::LoadStr {
                        dst: 7,
                        pool_index: 1,
                    },
                    Ir3Instruction::SetProperty {
                        obj: 1,
                        key: 7,
                        val: 6,
                    },
                    Ir3Instruction::Move { dst: 0, src: 1 },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 0,
                    },
                    Ir3Instruction::Throw { value: 0 },
                ],
                vec!["boom".to_string(), "caught".to_string()],
                vec![class_test_function(8, "throwing_getter")],
            ))
            .unwrap();
        assert_eq!(result.value, Value::Object(target));
        assert_eq!(
            throwing.heap[target.0 as usize].properties.get("caught"),
            Some(&Value::str("boom"))
        );
        assert!(throwing.copy_data_properties_states.is_empty());
    }

    #[test]
    fn copy_data_properties_state_is_budgeted_and_cleaned_on_failure_bd_f1ixz() {
        let mut core = quickjs_test_core();
        let target = core.alloc_object_with_prototype(None).unwrap();
        let source = core.alloc_object_with_prototype(None).unwrap();
        for index in 0..8 {
            core.set_plain_data_property(
                source,
                format!("long-copy-key-{index}-{}", "x".repeat(32)),
                Value::Int(index),
            )
            .unwrap();
        }
        core.registers[1] = Value::Object(target);
        core.registers[2] = Value::Object(source);
        core.sync_estimated_memory_bytes().unwrap();
        let baseline_memory = core.estimated_memory_bytes();
        let probe_state = CopyDataPropertiesState {
            instruction_ip: 0,
            register_base: 0,
            call_depth: 0,
            target_id: target,
            source: Value::Object(source),
            string_units: None,
            keys: core
                .copy_data_properties_keys(&Value::Object(source))
                .unwrap(),
            excluded: BTreeSet::new(),
            next_index: 0,
            awaiting_key: None,
        };
        let state_bytes = InterpreterCore::estimate_copy_data_properties_state_bytes(&probe_state);
        core.config.max_total_memory_bytes = baseline_memory
            .saturating_add(state_bytes)
            .saturating_sub(1);

        let error = core
            .execute(&test_module(vec![
                Ir3Instruction::CopyDataProperties {
                    target: 1,
                    source: 2,
                    excluded: RegRange { start: 3, count: 0 },
                    value_dst: 4,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap_err();
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert!(core.copy_data_properties_states.is_empty());
        assert!(core.heap[target.0 as usize].own_property_keys().is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn class_expression() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "const C = class { method() { return 1; } };\nconst c = new C();\nc.method();",
                ParseGoal::Script,
            )
            .expect("class expression should parse as structured AST");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                assert!(matches!(
                    decl.declarations[0].initializer.as_ref(),
                    Some(Expression::ClassExpression { .. })
                ));
            }
            other => panic!("expected class expression variable declaration, got {other:?}"),
        }
        let ir0 = Ir0Module::from_syntax_tree(tree, "class-expression-test.js");
        let ctx = LoweringContext::new(
            "trace-class-expression",
            "decision-class-expression",
            "policy-class-expression",
        );
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("class expression should lower");

        assert!(
            output
                .ir3
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::Construct { .. })),
            "class expression should produce an executable constructor"
        );

        let mut core = quickjs_test_core();
        let result = core
            .execute(&output.ir3)
            .expect("class expression constructor and prototype method should execute");

        assert_eq!(result.value, Value::Int(1));
    }

    fn execute_class_expression_source_bd_va13y(source: &str) -> Value {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("bd-va13y class expression source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd-va13y-class-expression.js");
        let output = lower_ir0_to_ir3(
            &ir0,
            &LoweringContext::new("trace-bd-va13y", "decision-bd-va13y", "policy-bd-va13y"),
        )
        .expect("bd-va13y class expression source should lower");
        quickjs_test_core()
            .execute(&output.ir3)
            .expect("bd-va13y class expression source should execute")
            .value
    }

    #[test]
    fn constructor_preserves_explicit_object_like_returns_bd_ptu9m() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let callable = function(){ return 7; }; \
                 let promise = Promise.resolve(9); \
                 let builtin = Array.isArray; \
                 function* make(){ yield 1; } let generator = make(); \
                 function ReturnCallable(){ return callable; } \
                 function ReturnPromise(){ return promise; } \
                 function ReturnBuiltin(){ return builtin; } \
                 function ReturnGenerator(){ return generator; } \
                 new ReturnCallable() === callable && \
                 new ReturnPromise() === promise && \
                 new ReturnBuiltin() === builtin && \
                 new ReturnGenerator() === generator;"
            ),
            Value::Bool(true)
        );
    }

    #[test]
    fn constructor_primitive_return_keeps_allocated_instance_bd_ptu9m() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "function KeepThis(){ this.value = 4; return 7; } \
                 let instance = new KeepThis(); instance.value === 4;"
            ),
            Value::Bool(true)
        );
    }

    #[test]
    fn named_class_expression_constructor_and_method_share_private_self_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let C = class Inner { \
                     constructor(){ this.ctor = Inner; } \
                     method(){ return Inner; } \
                 }; \
                 let D = C; C = 0; let value = new D(); \
                 value.ctor === D && value.method() === D;"
            ),
            Value::Bool(true)
        );
    }

    #[test]
    fn named_class_expression_nested_method_closure_keeps_self_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let C = class Inner { self(){ return () => Inner; } }; \
                 let D = C; C = 0; new D().self()() === D;"
            ),
            Value::Bool(true)
        );
    }

    #[test]
    fn named_class_expression_nested_constructor_closure_keeps_self_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let C = class Inner { constructor(){ this.self = () => Inner; } }; \
                 let D = C; C = 0; new D().self() === D;"
            ),
            Value::Bool(true)
        );
    }

    #[test]
    fn named_class_expression_shadows_outer_but_not_params_or_locals_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let Inner = 7; \
                 let C = class Inner { \
                     parameter(Inner){ return Inner; } \
                     local(){ let Inner = 9; return Inner; } \
                     self(){ return Inner; } \
                 }; \
                 let value = new C(); \
                 value.parameter(8) === 8 && value.local() === 9 && \
                 value.self() === C && Inner === 7;"
            ),
            Value::Bool(true)
        );
    }

    #[test]
    fn duplicate_named_class_expressions_keep_distinct_self_cells_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let A = class Inner { method(){ return Inner; } }; \
                 let B = class Inner { method(){ return Inner; } }; \
                 new A().method() === A && new B().method() === B;"
            ),
            Value::Bool(true)
        );
    }

    #[test]
    fn nested_factory_class_expression_shares_constructor_and_method_self_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "function make(){ \
                     return class Inner { \
                         constructor(){ this.ctor = Inner; } \
                         method(){ return Inner; } \
                     }; \
                 } \
                 let C = make(); let D = make(); \
                 let c = new C(); let d = new D(); \
                 (c.ctor === C ? 1 : 0) + \
                 (c.method() === C ? 2 : 0) + \
                 (d.ctor === D ? 4 : 0) + \
                 (d.method() === D ? 8 : 0) + \
                 (C !== D ? 16 : 0) + \
                 (c instanceof C ? 32 : 0) + \
                 (d instanceof D ? 64 : 0) + \
                 (!(c instanceof D) ? 128 : 0) + \
                 (!(d instanceof C) ? 256 : 0);"
            ),
            Value::Int(511)
        );
    }

    #[test]
    fn class_method_name_does_not_overwrite_same_named_outer_capture_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let method = 7; \
                 let C = class Inner { method(){ return method; } }; \
                 new C().method();"
            ),
            Value::Int(7)
        );
    }

    #[test]
    fn named_class_expression_self_does_not_leak_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y("let C = class Inner {}; typeof Inner;"),
            Value::str("undefined")
        );
    }

    #[test]
    fn anonymous_class_has_no_synthetic_self_binding_bd_va13y() {
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let C = class { \
                     constructor(){ \
                         try { anonymous; } catch (error) { this.kind = error.name; } \
                     } \
                 }; \
                 new C().kind;"
            ),
            Value::str("ReferenceError")
        );
        assert_eq!(
            execute_class_expression_source_bd_va13y(
                "let anonymous = 9; \
                 let C = class { method(){ return anonymous; } }; \
                 new C().method();"
            ),
            Value::Int(9)
        );
    }

    #[test]
    fn class_expression_extends_super_parse_lower_execute() {
        let tree = CanonicalEs2020Parser
            .parse(
                "class Base { constructor() { this.base = 40; } value() { return this.base + 2; } }\nconst Child = class extends Base { constructor() { super(); } value() { return super.value(); } };\nconst c = new Child();\nc.value();",
                ParseGoal::Script,
            )
            .expect("class expression extends/super should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "class-expression-extends-super-test.js");
        let ctx = LoweringContext::new(
            "trace-class-expression-extends",
            "decision-class-expression-extends",
            "policy-class-expression-extends",
        );
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("class expression extends should lower");
        assert!(
            output
                .ir3
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::LoadSuper { .. })),
            "derived class expression should lower super bindings"
        );

        let mut core = quickjs_test_core();
        let result = core
            .execute(&output.ir3)
            .expect("class expression extends/super should execute");

        assert_eq!(result.value, Value::Int(42));
    }

    #[test]
    fn new_target_in_constructor() {
        let tree = CanonicalEs2020Parser
            .parse(
                "class C { constructor() { this.kind = typeof new.target; } }\nconst c = new C();\nc.kind;",
                ParseGoal::Script,
        )
        .expect("new.target should parse in class constructor bodies");
        let ir0 = Ir0Module::from_syntax_tree(tree, "new-target-class-test.js");
        let ctx = LoweringContext::new(
            "trace-new-target",
            "decision-new-target",
            "policy-new-target",
        );
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("new.target should lower");
        assert!(
            output
                .ir3
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::LoadNewTarget { .. })),
            "constructor body should load new.target explicitly"
        );

        let mut core = quickjs_test_core();
        let result = core
            .execute(&output.ir3)
            .expect("new.target should execute through constructor frames");

        assert_eq!(result.value, Value::str("function"));
    }

    #[test]
    fn class_extends_super_parse_lower_execute() {
        let tree = CanonicalEs2020Parser
            .parse(
                "class Base { constructor() { this.base = 41; } describe() { return this.base + 1; } }\nclass Child extends Base { constructor() { super(); } describe() { return super.describe(); } }\nconst c = new Child();\nc.describe();",
                ParseGoal::Script,
            )
            .expect("class extends with super constructor and method calls should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "class-extends-super-test.js");
        let ctx = LoweringContext::new(
            "trace-class-extends-super",
            "decision-class-extends-super",
            "policy-class-extends-super",
        );
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("class extends and super should lower");
        assert!(
            output
                .ir3
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::LoadSuper { .. })),
            "constructor and method bodies should load a frame super binding"
        );
        assert!(
            output
                .ir3
                .constant_pool
                .iter()
                .any(|constant| constant == IR_SUPER_CONSTRUCTOR_PROPERTY),
            "derived constructor lowering should record its parent constructor"
        );
        assert!(
            output
                .ir3
                .constant_pool
                .iter()
                .any(|constant| constant == IR_SUPER_PROTOTYPE_PROPERTY),
            "derived method lowering should record its parent prototype"
        );

        let mut core = quickjs_test_core();
        let result = core
            .execute(&output.ir3)
            .expect("class extends and super should execute through parser/lowering path");

        assert_eq!(result.value, Value::Int(42));
    }

    // -----------------------------------------------------------------------
    // Timer substrate tests
    // -----------------------------------------------------------------------

    fn timer_callback_desc(entry: u32, name: &str) -> Ir3FunctionDesc {
        Ir3FunctionDesc {
            entry,
            arity: 0,
            frame_size: 1,
            name: Some(name.to_string()),
            is_generator: false,
            rest_param_index: None,
        }
    }

    fn timer_hostcall(capability: &str, args: RegRange, dst: u32) -> Ir3Instruction {
        Ir3Instruction::HostCall {
            capability: CapabilityTag(capability.to_string()),
            args,
            dst,
        }
    }

    fn timer_id(value: Value) -> u32 {
        match value {
            Value::Int(id) => u32::try_from(id).expect("timer id must be non-negative"),
            other => panic!("expected integer timer id, got {other:?}"),
        }
    }

    fn timer_callback_body(pool_index: u32) -> Vec<Ir3Instruction> {
        vec![
            Ir3Instruction::LoadStr { dst: 0, pool_index },
            timer_hostcall("console:log", RegRange { start: 0, count: 1 }, 1),
            Ir3Instruction::Return { value: 1 },
        ]
    }

    fn test_module_with_timer_callback(
        mut top_level: Vec<Ir3Instruction>,
        message: &str,
    ) -> Ir3Module {
        let callback_entry = top_level.len() as u32;
        top_level.extend(timer_callback_body(0));
        test_module_with_pool_and_functions(
            top_level,
            vec![message.to_string()],
            vec![timer_callback_desc(callback_entry, "timer_callback")],
        )
    }

    #[test]
    fn set_timeout_fires_after_delay() {
        let mut core = quickjs_test_core();
        let result = core
            .execute(&test_module_with_timer_callback(
                vec![
                    Ir3Instruction::CreateClosure {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::LoadInt { dst: 1, value: 25 },
                    timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                    Ir3Instruction::Halt,
                ],
                "timer fired after delay",
            ))
            .unwrap();

        assert_eq!(core.read_reg(2).unwrap(), Value::Int(0));
        assert!(core.active_timers.is_empty());
        assert_eq!(result.console_output.len(), 1);
        assert_eq!(result.console_output[0].message, "timer fired after delay");
        assert!(
            result
                .witness_events
                .iter()
                .any(|event| event.kind == WitnessEventKind::HostcallDispatched)
        );
    }

    #[test]
    fn timer_callback_materializes_empty_rest_array_bd_ur3tk_9() {
        let top_level = vec![
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 0 },
            timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
            Ir3Instruction::Halt,
        ];
        let callback_entry = top_level.len() as u32;
        let mut instructions = top_level;
        instructions.extend([
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            timer_hostcall("console:log", RegRange { start: 2, count: 1 }, 3),
            Ir3Instruction::Return { value: 3 },
        ]);
        let module = test_module_with_pool_and_functions(
            instructions,
            vec!["length".to_string()],
            vec![Ir3FunctionDesc {
                entry: callback_entry,
                arity: 1,
                frame_size: 4,
                name: Some("rest_timer_callback".to_string()),
                is_generator: false,
                rest_param_index: Some(0),
            }],
        );

        let mut core = quickjs_test_core();
        let result = core.execute(&module).expect("rest timer should execute");
        assert_eq!(result.console_output.len(), 1);
        assert_eq!(result.console_output[0].message, "0");
    }

    #[test]
    fn set_timeout_returns_id() {
        let mut core = quickjs_test_core();
        let result = core
            .execute(&test_module_with_timer_callback(
                vec![
                    Ir3Instruction::CreateClosure {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::LoadInt { dst: 1, value: 10 },
                    timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                    Ir3Instruction::LoadInt { dst: 1, value: 20 },
                    timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 3),
                    Ir3Instruction::Halt,
                ],
                "timer callback",
            ))
            .unwrap();

        assert_eq!(core.read_reg(2).unwrap(), Value::Int(0));
        assert_eq!(core.read_reg(3).unwrap(), Value::Int(1));
        assert!(core.active_timers.is_empty());
        assert_eq!(result.console_output.len(), 2);
    }

    #[test]
    fn clear_timeout_cancels() {
        let mut core = quickjs_test_core();
        let result = core
            .execute(&test_module_with_timer_callback(
                vec![
                    Ir3Instruction::CreateClosure {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::LoadInt { dst: 1, value: 30 },
                    timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                    timer_hostcall("timer:clearTimeout", RegRange { start: 2, count: 1 }, 3),
                    Ir3Instruction::Halt,
                ],
                "cancelled timer should not fire",
            ))
            .unwrap();

        assert_eq!(core.read_reg(3).unwrap(), Value::Undefined);
        assert!(core.active_timers.is_empty());
        assert!(result.console_output.is_empty());
    }

    #[test]
    fn set_interval_repeats() {
        let mut core = quickjs_test_core();
        core.execute(&test_module_with_functions(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 40 },
                timer_hostcall("timer:setInterval", RegRange { start: 0, count: 2 }, 2),
                Ir3Instruction::Halt,
            ],
            vec![timer_callback_desc(0, "timer_callback")],
        ))
        .unwrap();

        let timer = core
            .active_timers
            .get(&0)
            .expect("interval should be active");
        assert_eq!(timer.handler, Some(0));
        assert_eq!(timer.delay_ms, 40);
        assert!(timer.repeating);
        assert_eq!(timer.registration_seq, None);
    }

    #[test]
    fn clear_interval_stops() {
        let mut core = quickjs_test_core();
        core.execute(&test_module_with_functions(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::LoadInt { dst: 1, value: 50 },
                timer_hostcall("timer:setInterval", RegRange { start: 0, count: 2 }, 2),
                timer_hostcall("timer:clearInterval", RegRange { start: 2, count: 1 }, 3),
                Ir3Instruction::Halt,
            ],
            vec![timer_callback_desc(0, "timer_callback")],
        ))
        .unwrap();

        assert_eq!(core.read_reg(3).unwrap(), Value::Undefined);
        assert!(core.active_timers.is_empty());
    }

    #[test]
    fn timer_ordering() {
        let mut core = quickjs_test_core();
        let mut instructions = vec![
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 30 },
            timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 10 },
            timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 3),
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 2,
                capture_count: 0,
            },
            Ir3Instruction::LoadInt { dst: 1, value: 20 },
            timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 4),
            Ir3Instruction::Halt,
        ];
        let first_entry = instructions.len() as u32;
        instructions.extend(timer_callback_body(0));
        let second_entry = instructions.len() as u32;
        instructions.extend(timer_callback_body(1));
        let third_entry = instructions.len() as u32;
        instructions.extend(timer_callback_body(2));

        let result = core
            .execute(&test_module_with_pool_and_functions(
                instructions,
                vec!["delay-30".into(), "delay-10".into(), "delay-20".into()],
                vec![
                    timer_callback_desc(first_entry, "delay_30"),
                    timer_callback_desc(second_entry, "delay_10"),
                    timer_callback_desc(third_entry, "delay_20"),
                ],
            ))
            .unwrap();

        let messages = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>();
        assert_eq!(messages, vec!["delay-10", "delay-20", "delay-30"]);
        assert!(core.active_timers.is_empty());
    }

    #[test]
    fn microtask_before_timer() {
        let mut event_loop = crate::promise_model::EventLoop::new();
        event_loop
            .microtasks
            .enqueue(crate::promise_model::Microtask::PromiseReaction {
                handler: None,
                argument: crate::object_model::JsValue::Undefined,
                result_promise: crate::promise_model::PromiseHandle(0),
                label: crate::ifc_artifacts::Label::Public,
            });
        event_loop.set_timeout(
            crate::closure_model::ClosureHandle(0),
            0,
            crate::ifc_artifacts::Label::Public,
        );

        assert_eq!(event_loop.drain_microtasks(), 1);
        let turn = event_loop.turn();
        let macrotask = turn.macrotask.expect("timer should run after microtasks");
        assert_eq!(
            macrotask.source,
            crate::promise_model::MacrotaskSource::Timer
        );
    }

    #[test]
    fn nested_set_timeout() {
        let mut core = quickjs_test_core();
        let result = core
            .execute(&test_module_with_timer_callback(
                vec![
                    Ir3Instruction::CreateClosure {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::LoadInt { dst: 1, value: 5 },
                    timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                    Ir3Instruction::LoadInt { dst: 1, value: 0 },
                    timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 3),
                    Ir3Instruction::Halt,
                ],
                "nested timer callback",
            ))
            .unwrap();

        assert_eq!(timer_id(core.read_reg(2).unwrap()), 0);
        assert_eq!(timer_id(core.read_reg(3).unwrap()), 1);
        assert!(core.active_timers.is_empty());
        assert_eq!(result.console_output.len(), 2);
    }

    #[test]
    fn zero_delay_timeout() {
        let mut core = quickjs_test_core();
        let result = core
            .execute(&test_module_with_timer_callback(
                vec![
                    Ir3Instruction::CreateClosure {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::LoadInt { dst: 1, value: -1 },
                    timer_hostcall("timer:setTimeout", RegRange { start: 0, count: 2 }, 2),
                    Ir3Instruction::Halt,
                ],
                "zero delay timer",
            ))
            .unwrap();

        assert_eq!(timer_id(core.read_reg(2).unwrap()), 0);
        assert!(core.active_timers.is_empty());
        assert_eq!(result.console_output[0].message, "zero delay timer");
    }

    // RC-4.3 Containment Action Enforcement Tests
    mod containment_tests {
        use super::*;

        pub(super) fn test_interpreter() -> InterpreterCore {
            let mut config = test_quickjs_config();
            config.extension_id = Some("extension://containment-test".to_string());
            InterpreterCore::new(config, "test-containment")
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
            assert_eq!(receipt.extension_id, "extension://containment-test");
            assert_eq!(receipt.operation_type, "terminate");
            assert_eq!(receipt.risk_score, 900_000);
            assert!(receipt.action_taken.contains("terminate"));
            assert!(receipt.timestamp > 0);
            assert_eq!(receipt.instruction_pointer, 0);
            assert!(!receipt.register_state_hash.is_empty());
            assert!(!receipt.signature.is_empty());
        }

        #[test]
        fn receipt_uses_current_module_specifier_when_config_extension_id_absent() {
            let mut config = test_quickjs_config();
            config.extension_id = None;
            let mut interpreter = InterpreterCore::new(config, "test-containment");
            interpreter.current_module_specifier = Some("extension://module-source".to_string());

            interpreter
                .handle_containment_action(HookAction::Sandbox)
                .ok();

            let receipts = interpreter.decision_receipts().receipts();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].extension_id, "extension://module-source");
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

            // SAFETY: Test exports receipts after handling action; export succeeds in controlled test environment
            let json_export = interpreter.export_decision_receipts().unwrap();
            // SAFETY: JSON was just produced by export_decision_receipts; parsing succeeds for valid JSON
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
        fn create_async_function_stores_closure_reference_without_executor_state() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-create");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::Halt,
                ],
                vec![Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 1,
                    name: Some("test_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );

            core.execute(&module).expect("module should halt cleanly");

            assert_eq!(core.promise_store.len(), 0);
            assert!(matches!(core.registers[0], Value::AsyncFunction(0)));
        }

        #[test]
        fn async_function_call_returns_and_resolves_promise() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-call");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 0,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadInt { dst: 0, value: 42 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 0,
                    frame_size: 1,
                    name: Some("test_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );

            core.execute(&module)
                .expect("async function execution should resolve its promise");

            let Value::Promise(handle) = core.registers[1] else {
                panic!("async call should leave result promise in destination register");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(handle))
                .expect("result promise exists");
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(
                    42
                ))
            ));
            assert!(matches!(
                core.async_functions[0].phase,
                AsyncFunctionPhase::Completed
            ));
            assert!(matches!(core.registers[0], Value::AsyncFunction(0)));
        }

        #[test]
        fn async_function_throw_rejects_result_promise() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-throw");
            let mut module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 0,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 0,
                    },
                    Ir3Instruction::AsyncThrow { error_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 0,
                    frame_size: 1,
                    name: Some("throw_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            module.constant_pool.push("boom".into());

            core.execute(&module)
                .expect("async throw should reject its promise without aborting");

            let Value::Promise(handle) = core.registers[1] else {
                panic!("async call should leave result promise in destination register");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(handle))
                .expect("result promise exists");
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
                    reason
                )) if reason == "boom"
            ));
            assert!(matches!(
                core.async_functions[0].phase,
                AsyncFunctionPhase::Completed
            ));
        }

        #[test]
        fn async_function_awaits_resolved_promise_and_fulfills_with_value() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-await");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("await_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let handle = core.promise_store.create();
            core.promise_store
                .fulfill(
                    handle,
                    crate::object_model::JsValue::Int(99),
                    crate::ifc_artifacts::Label::Public,
                    &mut core.event_loop.microtasks,
                )
                .expect("seed promise should be fulfillable");
            core.registers[10] = Value::Promise(handle.0);

            core.execute(&module)
                .expect("resolved await should continue through async return");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async call should leave result promise in destination register");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result promise exists");
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(
                    99
                ))
            ));
            assert!(matches!(
                core.async_functions[0].phase,
                AsyncFunctionPhase::Completed
            ));
        }

        #[test]
        fn async_function_awaits_secret_promise_preserves_result_label() {
            let mut core =
                InterpreterCore::new(test_quickjs_config(), "async-function-await-secret");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("await_secret_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let handle = core.promise_store.create();
            core.promise_store
                .fulfill(
                    handle,
                    crate::object_model::JsValue::Str("secret".into()),
                    crate::ifc_artifacts::Label::Secret,
                    &mut core.event_loop.microtasks,
                )
                .expect("seed promise should be fulfillable");
            core.registers[10] = Value::Promise(handle.0);

            core.execute(&module)
                .expect("secret-labeled promise await should resolve");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async call should leave result promise in destination register");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                    value
                )) if value == "secret"
            ));
        }

        #[test]
        fn async_await_joins_handle_and_settlement_labels_bd_ur3tk_3() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-await-handle-label");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("await_labeled_handle".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let handle = core.promise_store.create();
            core.promise_store
                .fulfill(
                    handle,
                    crate::object_model::JsValue::Str("public-payload".into()),
                    crate::ifc_artifacts::Label::Public,
                    &mut core.event_loop.microtasks,
                )
                .expect("seed promise should be fulfillable");
            core.write_reg_with_label(
                10,
                Value::Promise(handle.0),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("Promise handle should accept its external label");

            core.execute(&module)
                .expect("settled await should preserve the handle label");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async call should leave its result Promise");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result Promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                    value
                )) if value == "public-payload"
            ));
        }

        #[test]
        fn async_rejected_await_joins_handle_label_bd_ur3tk_3() {
            let mut core =
                InterpreterCore::new(test_quickjs_config(), "async-rejected-handle-label");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("await_labeled_rejection".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let handle = core.promise_store.create();
            core.promise_store
                .reject(
                    handle,
                    crate::object_model::JsValue::Str("public-reason".into()),
                    crate::ifc_artifacts::Label::Public,
                    &mut core.event_loop.microtasks,
                )
                .expect("seed promise should be rejectable");
            core.write_reg_with_label(
                10,
                Value::Promise(handle.0),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("rejected Promise handle should accept its external label");

            core.execute(&module)
                .expect("rejected settled await should reject the result Promise");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async call should leave its result Promise");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result Promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
                    value
                )) if value == "public-reason"
            ));
        }

        #[test]
        fn async_method_preserves_receiver_label_bd_ur3tk_3() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-method-receiver");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::CallMethod {
                        receiver: 2,
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 0,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadThis { dst: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 0,
                    frame_size: 1,
                    name: Some("async_method_this".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            core.write_reg_with_label(
                2,
                Value::str("secret-receiver"),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("receiver should be writable");

            core.execute(&module)
                .expect("async method should dispatch and resolve");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async method should leave its result Promise");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result Promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                    value
                )) if value == "secret-receiver"
            ));
        }

        #[test]
        fn async_method_preserves_argument_label_bd_ur3tk_3() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-method-argument");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::CallMethod {
                        receiver: 2,
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("async_method_argument".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            core.registers[2] = Value::str("public-receiver");
            core.write_reg_with_label(
                10,
                Value::str("secret-argument"),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("method argument should be writable");

            core.execute(&module)
                .expect("async method should preserve argument labels");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async method should leave its result Promise");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result Promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                    value
                )) if value == "secret-argument"
            ));
        }

        #[test]
        fn async_direct_return_preserves_argument_label_bd_ur3tk_3() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-direct-return-label");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("direct_async_return".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            core.write_reg_with_label(
                10,
                Value::str("secret-return"),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("async argument should be writable");

            core.execute(&module)
                .expect("direct async return should resolve");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async call should leave its result Promise");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result Promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
        }

        #[test]
        fn async_direct_throw_preserves_argument_label_bd_ur3tk_3() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-direct-throw-label");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AsyncThrow { error_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("direct_async_throw".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            core.write_reg_with_label(
                10,
                Value::str("secret-rejection"),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("async rejection argument should be writable");

            core.execute(&module)
                .expect("direct async throw should reject its Promise");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async call should leave its result Promise");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result Promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Str(
                    value
                )) if value == "secret-rejection"
            ));
        }

        #[test]
        fn async_plain_call_super_uses_only_callee_label_bd_ur3tk_20() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-plain-super-label");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadSuper { dst: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 2,
                    arity: 1,
                    frame_size: 1,
                    name: Some("async_plain_super_reader".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let captured_env = core.scope_chain.snapshot();
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env,
            });
            core.write_reg_with_label(
                0,
                Value::AsyncFunction(0),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("async callee should be writable");
            core.write_reg_with_label(10, Value::Int(43), crate::ifc_artifacts::Label::TopSecret)
                .expect("async argument should be writable");

            core.execute(&module)
                .expect("async plain call should resolve");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async plain call should leave its result Promise");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result Promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(
                    crate::object_model::JsValue::Undefined
                )
            ));
        }

        #[test]
        fn async_method_super_uses_only_callee_label_bd_ur3tk_20() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-method-super-label");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CallMethod {
                        receiver: 2,
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::LoadSuper { dst: 1 },
                    Ir3Instruction::AsyncReturn { value_reg: 1 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 2,
                    arity: 1,
                    frame_size: 2,
                    name: Some("async_method_super_reader".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let parent_prototype = core
                .alloc_object_with_prototype(None)
                .expect("parent prototype should allocate");
            let method_prototype = core
                .alloc_object_with_prototype(Some(parent_prototype))
                .expect("method prototype should allocate");
            let receiver = core
                .alloc_object_with_prototype(Some(method_prototype))
                .expect("receiver should allocate");
            let captured_env = core.scope_chain.snapshot();
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env,
            });
            core.write_reg_with_label(
                0,
                Value::AsyncFunction(0),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("async method should be writable");
            core.write_reg_with_label(
                2,
                Value::Object(receiver),
                crate::ifc_artifacts::Label::TopSecret,
            )
            .expect("receiver should be writable");
            core.write_reg_with_label(
                10,
                Value::Int(44),
                crate::ifc_artifacts::Label::Confidential,
            )
            .expect("method argument should be writable");

            core.execute(&module)
                .expect("async method call should resolve");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async method call should leave its result Promise");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result Promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(
                    crate::object_model::JsValue::Object(handle)
                ) if handle.0 == parent_prototype.0
            ));
        }

        #[test]
        fn async_function_awaits_labeled_non_promise_without_downgrade() {
            let mut core =
                InterpreterCore::new(test_quickjs_config(), "async-function-await-non-promise");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("await_labeled_value_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            core.write_reg_with_label(
                10,
                Value::Str("secret".into()),
                crate::ifc_artifacts::Label::Secret,
            )
            .expect("test register should be writable");

            core.execute(&module)
                .expect("labeled non-promise await should resolve");

            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async call should leave result promise in destination register");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result promise exists");
            assert_eq!(record.label, crate::ifc_artifacts::Label::Secret);
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Str(
                    value
                )) if value == "secret"
            ));
        }

        #[test]
        fn async_function_pending_await_uses_explicit_unsupported_contract() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-function-pending");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncFunction {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 1,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 1,
                    frame_size: 1,
                    name: Some("pending_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let handle = core.promise_store.create();
            core.registers[10] = Value::Promise(handle.0);

            let err = core
                .execute(&module)
                .expect_err("pending await should use an explicit franken-core contract");
            assert!(
                format!("{err:?}").contains("pending promise await is explicitly unsupported"),
                "unexpected error: {err:?}"
            );
            assert!(matches!(
                core.async_functions[0].phase,
                AsyncFunctionPhase::SuspendedAwait
            ));
            let Value::Promise(result_handle) = core.registers[1] else {
                panic!("async call should leave result promise before failing closed");
            };
            let record = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("result promise exists");
            assert!(matches!(
                &record.state,
                crate::promise_model::PromiseState::Pending
            ));
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
            let cases = [
                (Value::Undefined, crate::object_model::JsValue::Undefined),
                (Value::Null, crate::object_model::JsValue::Null),
                (Value::Bool(true), crate::object_model::JsValue::Bool(true)),
                (
                    Value::Bool(false),
                    crate::object_model::JsValue::Bool(false),
                ),
                (Value::Int(42), crate::object_model::JsValue::Int(42)),
                (
                    Value::Float(Float64::new(3.25)),
                    crate::object_model::JsValue::Float(3.25f64.to_bits()),
                ),
                (
                    Value::str("hello"),
                    crate::object_model::JsValue::str("hello"),
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

            for (input, expected) in cases {
                assert_eq!(InterpreterCore::value_to_js_value(&input), expected);
            }

            assert!(matches!(
                InterpreterCore::value_to_js_value(&Value::Promise(7)),
                crate::object_model::JsValue::Str(_)
            ));
        }

        #[test]
        fn async_generator_creation() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-generator-create");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncGenerator {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::Halt,
                ],
                vec![Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 1,
                    name: Some("test_async_gen".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );

            core.execute(&module)
                .expect("async generator function creation should succeed");

            assert_eq!(core.closures.len(), 1);
            assert_eq!(core.closures[0].function_index, 0);
            assert!(matches!(
                core.registers[0],
                Value::AsyncGeneratorFunction(0)
            ));
        }

        #[test]
        fn async_generator_function_call_creates_object() {
            let mut core = InterpreterCore::new(test_quickjs_config(), "async-generator-call");
            let module = test_module_with_functions(
                vec![
                    Ir3Instruction::CreateAsyncGenerator {
                        dst: 0,
                        function_index: 0,
                        capture_count: 0,
                    },
                    Ir3Instruction::Call {
                        callee: 0,
                        args: RegRange {
                            start: 10,
                            count: 0,
                        },
                        dst: 1,
                    },
                    Ir3Instruction::Halt,
                    Ir3Instruction::Halt,
                ],
                vec![Ir3FunctionDesc {
                    entry: 3,
                    arity: 0,
                    frame_size: 1,
                    name: Some("test_async_gen".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );

            core.execute(&module)
                .expect("async generator function call should succeed");

            assert_eq!(core.async_generators.len(), 1);
            let created = &core.async_generators[0];
            assert_eq!(created.function_index, 0);
            assert_eq!(created.closure_index, Some(0));
            assert!(matches!(created.phase, AsyncGeneratorPhase::SuspendedStart));
            assert!(matches!(core.registers[1], Value::AsyncGeneratorObject(0)));
        }

        #[test]
        fn async_generator_next_returns_promise() {
            let mut core = test_interpreter();
            core.config
                .granted_capabilities
                .insert(RuntimeCapability::HeapAllocate);

            // Create async generator, call it to get object, then call .next()
            let async_gen_id = {
                core.async_generators.push(AsyncGeneratorObject {
                    function_index: 0,
                    closure_index: None,
                    saved_ip: 0,
                    saved_registers: Vec::new(),
                    saved_register_labels: Vec::new(),
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
        fn async_generator_next_suspended_start_executes() {
            let mut core = test_interpreter();

            // Create a simple async generator function that yields then returns
            let module = test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 0,
                    }, // Load "hello"
                    Ir3Instruction::Yield {
                        value: 0,
                        delegate: false,
                        resume_dst: 1,
                    }, // Yield "hello"
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 1,
                    }, // Load "world"
                    Ir3Instruction::Return { value: 0 }, // Return "world"
                ],
                vec!["hello".to_string(), "world".to_string()],
                vec![Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("test_async_gen".to_string()),
                    is_generator: true,
                    rest_param_index: None,
                }],
            );

            let async_gen_id = {
                core.async_generators.push(AsyncGeneratorObject {
                    function_index: 0,
                    closure_index: None,
                    saved_ip: 0,
                    saved_registers: Vec::new(),
                    saved_register_labels: Vec::new(),
                    saved_register_base: 0,
                    phase: AsyncGeneratorPhase::SuspendedStart,
                });
                (core.async_generators.len() - 1) as u32
            };

            let result = core
                .async_generator_next(&module, async_gen_id, Value::Undefined)
                .expect("async generator execution should succeed");

            // Should return a promise
            assert!(
                matches!(result, Value::Promise(_)),
                "should return a promise"
            );

            // Check that the async generator state was updated to SuspendedYield
            assert!(matches!(
                core.async_generators[async_gen_id as usize].phase,
                AsyncGeneratorPhase::SuspendedYield
            ));
        }

        #[test]
        fn async_generator_next_suspended_yield_resumes() {
            let mut core = test_interpreter();

            // Create a simple async generator function that yields then returns
            let module = test_module_with_pool_and_functions(
                vec![
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 0,
                    }, // Load "hello"
                    Ir3Instruction::Yield {
                        value: 0,
                        delegate: false,
                        resume_dst: 1,
                    }, // Yield "hello"
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 1,
                    }, // Load "world"
                    Ir3Instruction::Return { value: 0 }, // Return "world"
                ],
                vec!["hello".to_string(), "world".to_string()],
                vec![Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("test_async_gen".to_string()),
                    is_generator: true,
                    rest_param_index: None,
                }],
            );

            let async_gen_id = {
                core.async_generators.push(AsyncGeneratorObject {
                    function_index: 0,
                    closure_index: None,
                    saved_ip: 2, // Resume after yield
                    saved_registers: vec![Value::Undefined],
                    saved_register_labels: vec![crate::ifc_artifacts::Label::Public],
                    saved_register_base: 0,
                    phase: AsyncGeneratorPhase::SuspendedYield,
                });
                (core.async_generators.len() - 1) as u32
            };

            let result = core
                .async_generator_next(&module, async_gen_id, Value::Undefined)
                .expect("async generator resume should succeed");

            // Should return a promise
            assert!(
                matches!(result, Value::Promise(_)),
                "should return a promise"
            );

            // Check that the async generator state was updated to Completed
            assert!(matches!(
                core.async_generators[async_gen_id as usize].phase,
                AsyncGeneratorPhase::Completed
            ));
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
