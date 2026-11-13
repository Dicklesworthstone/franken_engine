//! Baseline interpreter skeleton for the current execution-profile contract.
//!
//! Consumes `Ir3Module` and produces execution results carrying the witness
//! events and hostcall decisions that `ExecutionOrchestrator::execute` seals
//! into the `Ir4Module` witness (bd-drb55).  The baseline interpreter is the
//! canonical execution path — all optimized paths must prove equivalence
//! against it (per 9F.1).
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

use std::cell::{Ref, RefCell, RefMut};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
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
    AccessorKind, HostcallDecisionRecord, IR_ACCESSOR_GET_PREFIX, IR_ACCESSOR_SET_PREFIX,
    IR_SUPER_CONSTRUCTOR_PROPERTY, IR_SUPER_PROTOTYPE_PROPERTY, Ir0Module, Ir3FunctionDesc,
    Ir3Instruction, Ir3Module, IteratorCloseReason, RegRange, WitnessEvent, WitnessEventKind,
};
use crate::js_string::JsString;
use crate::lowering_pipeline::{
    CLASS_EXPRESSION_CONSTRUCTOR_SELF_CAPTURE_PREFIX, FUNCTION_EXPRESSION_SELF_CAPTURE_PREFIX,
    LoweringContext, lower_ir0_to_ir3,
};
use crate::object_model::{
    BaselineStringAccessor, BaselineSymbolProperty, ExactOrderedStringMap, OrderedStringMap,
    PropertyKey as TypedPropertyKey, SymbolId, WellKnownSymbol, canonical_array_index,
};
pub use crate::object_model::{BuiltinFunction, BuiltinFunctionKind};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use crate::runtime_config::ExecutionConfig;

mod array_methods;
mod async_generator;
mod function_methods;
mod property_descriptors;
mod string_methods;
use async_generator::{
    AsyncGeneratorAwaitKind, AsyncGeneratorContinuation, AsyncGeneratorObject,
    AsyncGeneratorResumeKind,
};
use property_descriptors::{PropertyAttributes, PropertyAttributesWire};

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
const MEMORY_ESTIMATE_CALL_FRAME_BASE_BYTES: u64 =
    64 + std::mem::size_of::<crate::ifc_artifacts::Label>() as u64;
/// Approximate per-iterator base footprint.
const MEMORY_ESTIMATE_ITERATOR_BASE_BYTES: u64 = 32;
/// Approximate per-generator base footprint.
const MEMORY_ESTIMATE_GENERATOR_BASE_BYTES: u64 = 48;
/// Approximate per-resumable CopyDataProperties state footprint.
const MEMORY_ESTIMATE_COPY_DATA_PROPERTIES_STATE_BASE_BYTES: u64 = 64;
/// Fixed persisted mapping for ES2020 well-known Symbol identities.
const WELL_KNOWN_SYMBOL_SCHEMA: &str = "es2020-symbol-ids-1-13-v1";
/// First dynamically allocated Symbol identity after the fixed well-known set.
const FIRST_DYNAMIC_SYMBOL_ID: u32 = 14;

/// Maximum length of a capability tag recorded in witness and decision-log
/// payloads. Execution continues to use the complete tag; only the bounded
/// evidence representation is shortened.
const CAPABILITY_TAG_RECORD_BYTE_CAP: usize = 256;
/// Reserved prefix for a bounded capability-tag representation that commits
/// to the complete original tag with SHA-256. Inputs already using this
/// prefix are re-encoded so an ordinary short tag cannot impersonate the
/// representation of a different, overlong tag.
const CAPABILITY_TAG_DIGEST_PREFIX: &str = "<TRUNCATED:sha256:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostcallCapabilityClass {
    Runtime(RuntimeCapability),
    InternalAllowed,
    Unknown,
}

/// Internal HostCall tags implemented by this interpreter. This is a closed
/// surface: adding a dispatcher arm requires adding its exact tag here too.
/// Prefix membership is intentionally insufficient because IR3 is an input
/// boundary and may contain attacker-chosen capability strings (bd-pr33n).
const KNOWN_INTERNAL_HOSTCALLS: &[&str] = &[
    "ifc.check_flow",
    "promise:constructor",
    "promise:resolve",
    "promise:reject",
    "promise:then",
    "promise:catch",
    "promise:finally",
    "promise:all",
    "promise:race",
    "promise:allSettled",
    "promise:any",
    "number:isNaN",
    "number:isFinite",
    "number:Number.isNaN",
    "number:Number.isFinite",
    "number:Number.isInteger",
    "number:Number.isSafeInteger",
    "console:log",
    "console:error",
    "console:warn",
    "console:info",
    "timer:setTimeout",
    "timer:setInterval",
    "timer:clearTimeout",
    "timer:clearInterval",
    "builtin:ReferenceError",
    "builtin:TypeError",
    "builtin:ConstructSuperSpread",
    "builtin:ObjectLiteralSetPrototype",
    "builtin:ArrayPrototypePush",
    "builtin:ArrayPrototypePop",
    "builtin:ArrayIsArray",
    "builtin:ArrayIsArrayFunction",
    "builtin:SymbolFunction",
    "builtin:SymbolFor",
    "builtin:SymbolKeyFor",
    "builtin:SymbolIterator",
    "builtin:SymbolToPrimitive",
    "builtin:SymbolHasInstance",
    "builtin:SymbolToStringTag",
    "builtin:SymbolSpecies",
    "builtin:SymbolIsConcatSpreadable",
    "builtin:SymbolUnscopables",
    "builtin:SymbolAsyncIterator",
    "builtin:SymbolMatch",
    "builtin:SymbolMatchAll",
    "builtin:SymbolReplace",
    "builtin:SymbolSearch",
    "builtin:SymbolSplit",
    "builtin:ObjectKeys",
    "builtin:ObjectValues",
    "builtin:ObjectEntries",
    "builtin:ObjectGetOwnPropertyNames",
    "builtin:ObjectGetOwnPropertySymbols",
    "builtin:ReflectOwnKeys",
    "builtin:ObjectAssign",
    "builtin:ObjectDefineProperty",
    "builtin:ObjectGetOwnPropertyDescriptor",
    "builtin:ReflectDefineProperty",
    "builtin:ObjectDefinePropertyFunction",
    "builtin:ObjectGetOwnPropertyDescriptorFunction",
    "builtin:ReflectDefinePropertyFunction",
    "builtin:StringPrototypeCharAt",
    "builtin:StringPrototypeCharCodeAt",
    "builtin:StringPrototypeCodePointAt",
    "builtin:StringPrototypeAt",
    "builtin:StringPrototypeIsWellFormed",
    "builtin:StringPrototypeToWellFormed",
    "builtin:StringFromCharCode",
    "builtin:StringFromCodePoint",
    "builtin:MathAbs",
    "builtin:JsonStringify",
    "builtin:JsonParse",
    "builtin:PathJoin",
    "builtin:PathResolve",
    "builtin:PathNormalize",
    "builtin:PathBasename",
    "builtin:PathDirname",
    "builtin:PathExtname",
    "builtin:PathIsAbsolute",
    "builtin:PathRelative",
    "builtin:PathParse",
    "builtin:PathFormat",
    "builtin:PathWin32Join",
    "builtin:PathWin32Basename",
    "builtin:PathWin32IsAbsolute",
    "builtin:QuerystringParse",
    "builtin:QuerystringStringify",
    "builtin:QuerystringEscape",
    "builtin:QuerystringUnescape",
    "builtin:OsPlatform",
    "builtin:OsArch",
    "builtin:OsType",
    "builtin:OsEndianness",
    "builtin:OsMachine",
    "builtin:OsRelease",
    "builtin:OsVersion",
    "builtin:OsHomedir",
    "builtin:OsTmpdir",
    "builtin:OsHostname",
    "builtin:OsUptime",
    "builtin:OsTotalmem",
    "builtin:OsFreemem",
    "builtin:OsAvailableParallelism",
    "builtin:OsLoadavg",
    "builtin:OsCpus",
    "builtin:OsNetworkInterfaces",
    "builtin:OsUserInfo",
    "builtin:OsGetPriority",
    "builtin:OsSetPriority",
    "builtin:OsConstants",
];

/// Canonical operator-facing label for the deterministic execution profile.
pub const DETERMINISTIC_PROFILE_LABEL: &str = "baseline_deterministic_profile";
/// Canonical operator-facing label for the throughput execution profile.
pub const THROUGHPUT_PROFILE_LABEL: &str = "baseline_throughput_profile";
/// Legacy lineage label still accepted on input for the deterministic profile.
pub const LEGACY_QUICKJS_PROFILE_LABEL: &str = "quickjs_inspired_native";
/// Legacy lineage label still accepted on input for the throughput profile.
pub const LEGACY_V8_PROFILE_LABEL: &str = "v8_inspired_native";

/// Borrow `tag` if it fits within [`CAPABILITY_TAG_RECORD_BYTE_CAP`] and does
/// not occupy the reserved digest namespace. Otherwise return a `Cow::Owned`
/// beginning with a SHA-256 commitment to the complete tag, followed by as
/// much UTF-8-safe display prefix as fits within the byte cap.
///
/// Prefixing the digest representation, and re-encoding inputs that already
/// start with [`CAPABILITY_TAG_DIGEST_PREFIX`], keeps the encoded and verbatim
/// domains disjoint. This prevents both overlong-prefix collisions and a
/// crafted short tag from impersonating an encoded long tag while preserving
/// ordinary short tags byte-for-byte (bd-hxukn, bd-lvoff).
fn recordable_capability_tag(tag: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if tag.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP && !tag.starts_with(CAPABILITY_TAG_DIGEST_PREFIX)
    {
        return Cow::Borrowed(tag);
    }

    let digest = ContentHash::compute(tag.as_bytes()).to_hex();
    let marker = format!("{CAPABILITY_TAG_DIGEST_PREFIX}{digest}>:");
    let prefix_len = CAPABILITY_TAG_RECORD_BYTE_CAP.saturating_sub(marker.len());
    // Walk back to the nearest UTF-8 char boundary so the prefix stays
    // a valid `&str` slice.
    let mut cut = prefix_len.min(tag.len());
    while cut > 0 && !tag.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(marker.len() + cut);
    out.push_str(&marker);
    out.push_str(&tag[..cut]);
    debug_assert!(out.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);
    Cow::Owned(out)
}

/// Canonical evidence and gate identity for the module-loading aliases still
/// accepted at IR and package boundaries.
fn capability_gate_key(tag: &str) -> &str {
    match tag {
        "module:require" | "module:import" | "module.import" | "module_load" => "module_load",
        _ => tag,
    }
}

fn check_module_load_capability_gate(
    interpreter: &mut InterpreterCore,
    instruction_index: u32,
) -> Result<(), InterpreterError> {
    const CAPABILITY_TAG: &str = "module_load";
    if !interpreter
        .config
        .granted_capabilities
        .contains(&RuntimeCapability::ModuleLoad)
    {
        interpreter.emit_witness(
            WitnessEventKind::CapabilityChecked,
            Some("denied:module_load"),
        );
        interpreter.hostcall_decisions.push(HostcallDecisionRecord {
            seq: interpreter.hostcall_decisions.len() as u64,
            capability: crate::ir_contract::CapabilityTag(CAPABILITY_TAG.to_string()),
            allowed: false,
            instruction_index,
        });
        return Err(InterpreterError::CapabilityDenied {
            capability: CAPABILITY_TAG.to_string(),
        });
    }

    interpreter.emit_witness(
        WitnessEventKind::HostcallDispatched,
        Some("cap:module_load"),
    );
    interpreter.emit_witness(
        WitnessEventKind::CapabilityChecked,
        Some("granted:module_load"),
    );
    interpreter.hostcall_decisions.push(HostcallDecisionRecord {
        seq: interpreter.hostcall_decisions.len() as u64,
        capability: crate::ir_contract::CapabilityTag(CAPABILITY_TAG.to_string()),
        allowed: true,
        instruction_index,
    });
    Ok(())
}

fn classify_hostcall_capability(tag: &str) -> HostcallCapabilityClass {
    if KNOWN_INTERNAL_HOSTCALLS.contains(&tag) {
        HostcallCapabilityClass::InternalAllowed
    } else if let Some(capability) = RuntimeCapability::from_tag_str(tag) {
        HostcallCapabilityClass::Runtime(capability)
    } else {
        HostcallCapabilityClass::Unknown
    }
}

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

/// Executable timer state is kept outside the public timer/queue schemas.
/// Registration sequences distinguish repeated schedules of the same callable.
struct TimerInvocation {
    callee: Value,
    arguments: Vec<(Value, crate::ifc_artifacts::Label)>,
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
            // ECMAScript uses exponent notation outside [1e-6, 1e21),
            // including Number results that overflow the integer fast path.
            f.write_str(ryu_js::Buffer::new().format(self.0))
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

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MIN_SAFE_INTEGER: i64 = -MAX_SAFE_INTEGER;

/// Keep integers only where the Number representation is exact, and never
/// erase a negative zero while converting a floating-point result.
#[inline]
fn js_number_to_value(value: f64) -> Value {
    if value.is_finite()
        && !(value == 0.0 && value.is_sign_negative())
        && value.fract() == 0.0
        && (MIN_SAFE_INTEGER as f64..=MAX_SAFE_INTEGER as f64).contains(&value)
    {
        Value::Int(value as i64)
    } else {
        Value::Float(Float64::new(value))
    }
}

#[inline]
fn js_int_to_value(value: i64) -> Value {
    if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        Value::Int(value)
    } else {
        Value::Float(Float64::new(value as f64))
    }
}

/// Both operands must be safe integers before using their exact integer
/// result. This also covers values supplied through the public IR/state API:
/// two out-of-range i64 values may round to the same Number before subtraction.
#[inline]
fn js_safe_integer_result(lhs: i64, rhs: i64, result: Option<i64>) -> Option<Value> {
    if (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&lhs)
        && (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&rhs)
    {
        result
            .filter(|value| (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value))
            .map(Value::Int)
    } else {
        None
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
    /// Exact safe-integer representation of a JavaScript Number. Numeric
    /// ingress and arithmetic promote values outside ±(2^53 - 1) to Float.
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
    /// ECMAScript Symbol primitive identity. Additive variants stay at the
    /// tail so all pre-existing non-self-describing serde discriminants remain
    /// stable.
    Symbol(SymbolId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeSymbolKind {
    Private,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeSymbolRecord {
    symbol_id: SymbolId,
    kind: RuntimeSymbolKind,
    description: Option<JsString>,
    registry_key: Option<JsString>,
}

struct RuntimeSymbolRecordRef<'a>(&'a RuntimeSymbolRecord);

impl Serialize for RuntimeSymbolRecordRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let record = self.0;
        let mut wire = serializer.serialize_struct(
            "RuntimeSymbolRecord",
            if matches!(record.kind, RuntimeSymbolKind::Global) {
                4
            } else {
                3
            },
        )?;
        wire.serialize_field("symbol_id", &record.symbol_id.0)?;
        wire.serialize_field(
            "kind",
            match record.kind {
                RuntimeSymbolKind::Private => "private",
                RuntimeSymbolKind::Global => "global",
            },
        )?;
        wire.serialize_field("description", &record.description)?;
        if matches!(record.kind, RuntimeSymbolKind::Global) {
            wire.serialize_field("registry_key", &record.registry_key)?;
        }
        wire.end()
    }
}

/// Distinguishes a missing field from a present JSON `null` field.
#[derive(Debug)]
struct PresentNullable<T>(Option<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PresentNullable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(deserializer).map(Self)
    }
}

fn deserialize_present_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<PresentNullable<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    PresentNullable::<T>::deserialize(deserializer).map(Some)
}

/// Distinguishes an absent optional field from a present value while still
/// rejecting JSON `null` for non-nullable records.
#[derive(Debug)]
struct PresentValue<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PresentValue<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self)
    }
}

fn deserialize_present_value<'de, D, T>(
    deserializer: D,
) -> Result<Option<PresentValue<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    PresentValue::<T>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeSymbolState {
    next_symbol_id: u32,
    symbols: BTreeMap<SymbolId, RuntimeSymbolRecord>,
}

impl Default for RuntimeSymbolState {
    fn default() -> Self {
        Self {
            next_symbol_id: FIRST_DYNAMIC_SYMBOL_ID,
            symbols: BTreeMap::new(),
        }
    }
}

impl Serialize for RuntimeSymbolState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let records = self
            .symbols
            .values()
            .map(RuntimeSymbolRecordRef)
            .collect::<Vec<_>>();
        let mut state = serializer.serialize_struct("RuntimeSymbolState", 3)?;
        state.serialize_field("well_known_schema", WELL_KNOWN_SYMBOL_SCHEMA)?;
        state.serialize_field("next_symbol_id", &self.next_symbol_id)?;
        state.serialize_field("symbols", &records)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RuntimeSymbolState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SymbolStateWire {
            well_known_schema: String,
            next_symbol_id: u32,
            symbols: Vec<SymbolRecordWire>,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SymbolRecordWire {
            symbol_id: u32,
            kind: String,
            #[serde(default, deserialize_with = "deserialize_present_nullable")]
            description: Option<PresentNullable<JsString>>,
            #[serde(default, deserialize_with = "deserialize_present_nullable")]
            registry_key: Option<PresentNullable<JsString>>,
        }

        let wire = SymbolStateWire::deserialize(deserializer)?;
        if wire.well_known_schema != WELL_KNOWN_SYMBOL_SCHEMA {
            return Err(D::Error::custom("unknown well-known Symbol schema"));
        }
        let mut symbols = BTreeMap::new();
        let mut previous_id = None;
        for record in wire.symbols {
            let id = SymbolId(record.symbol_id);
            if let Some(previous) = previous_id
                && id <= previous
            {
                return Err(D::Error::custom(
                    "dynamic Symbol records must be strictly increasing",
                ));
            }
            previous_id = Some(id);
            let description = record
                .description
                .ok_or_else(|| D::Error::custom("Symbol description field is required"))?
                .0;
            let (kind, registry_key) = match record.kind.as_str() {
                "private" => {
                    if record.registry_key.is_some() {
                        return Err(D::Error::custom(
                            "private Symbol record forbids registry_key",
                        ));
                    }
                    (RuntimeSymbolKind::Private, None)
                }
                "global" => {
                    let registry_key = record
                        .registry_key
                        .ok_or_else(|| {
                            D::Error::custom("global Symbol record requires registry_key")
                        })?
                        .0
                        .ok_or_else(|| {
                            D::Error::custom("global Symbol registry_key cannot be null")
                        })?;
                    if description.as_ref() != Some(&registry_key) {
                        return Err(D::Error::custom(
                            "global Symbol description must equal registry_key",
                        ));
                    }
                    (RuntimeSymbolKind::Global, Some(registry_key))
                }
                _ => return Err(D::Error::custom("unknown dynamic Symbol kind")),
            };
            if symbols
                .insert(
                    id,
                    RuntimeSymbolRecord {
                        symbol_id: id,
                        kind,
                        description,
                        registry_key,
                    },
                )
                .is_some()
            {
                return Err(D::Error::custom("duplicate dynamic Symbol id"));
            }
        }
        let state = Self {
            next_symbol_id: wire.next_symbol_id,
            symbols,
        };
        state.validate().map_err(D::Error::custom)?;
        Ok(state)
    }
}

impl RuntimeSymbolState {
    fn is_default(&self) -> bool {
        self.next_symbol_id == FIRST_DYNAMIC_SYMBOL_ID && self.symbols.is_empty()
    }

    fn validate(&self) -> Result<(), String> {
        if self.next_symbol_id < FIRST_DYNAMIC_SYMBOL_ID {
            return Err("next_symbol_id overlaps reserved well-known Symbols".to_string());
        }
        let mut registry_keys = BTreeSet::new();
        for (id, record) in &self.symbols {
            if id.0 < FIRST_DYNAMIC_SYMBOL_ID || id.0 == u32::MAX {
                return Err(format!("invalid dynamic Symbol id {}", id.0));
            }
            if record.symbol_id != *id {
                return Err("dynamic Symbol record id mismatch".to_string());
            }
            if id.0 >= self.next_symbol_id {
                return Err(format!(
                    "dynamic Symbol id {} is not below next_symbol_id {}",
                    id.0, self.next_symbol_id
                ));
            }
            match record.kind {
                RuntimeSymbolKind::Private => {
                    if record.registry_key.is_some() {
                        return Err("private Symbol has a registry key".to_string());
                    }
                }
                RuntimeSymbolKind::Global => {
                    let key = record
                        .registry_key
                        .as_ref()
                        .ok_or_else(|| "global Symbol lacks a registry key".to_string())?;
                    if record.description.as_ref() != Some(key) {
                        return Err("global Symbol description/registry mismatch".to_string());
                    }
                    if !registry_keys.insert(key.clone()) {
                        return Err("duplicate global Symbol registry key".to_string());
                    }
                }
            }
        }
        Ok(())
    }

    fn contains(&self, id: SymbolId) -> bool {
        (1..FIRST_DYNAMIC_SYMBOL_ID).contains(&id.0) || self.symbols.contains_key(&id)
    }

    fn allocate_private(
        &mut self,
        description: Option<JsString>,
    ) -> Result<SymbolId, InterpreterError> {
        self.allocate(RuntimeSymbolKind::Private, description, None)
    }

    fn intern_global(&mut self, key: JsString) -> Result<SymbolId, InterpreterError> {
        if let Some(record) = self.symbols.values().find(|record| {
            matches!(record.kind, RuntimeSymbolKind::Global)
                && record.registry_key.as_ref() == Some(&key)
        }) {
            return Ok(record.symbol_id);
        }
        self.allocate(RuntimeSymbolKind::Global, Some(key.clone()), Some(key))
    }

    fn allocate(
        &mut self,
        kind: RuntimeSymbolKind,
        description: Option<JsString>,
        registry_key: Option<JsString>,
    ) -> Result<SymbolId, InterpreterError> {
        if self.next_symbol_id == u32::MAX {
            return Err(InterpreterError::TypeError {
                expected: "available Symbol identity".to_string(),
                got: "Symbol identity space exhausted".to_string(),
            });
        }
        let symbol_id = SymbolId(self.next_symbol_id);
        self.next_symbol_id += 1;
        self.symbols.insert(
            symbol_id,
            RuntimeSymbolRecord {
                symbol_id,
                kind,
                description,
                registry_key,
            },
        );
        Ok(symbol_id)
    }

    fn key_for(&self, id: SymbolId) -> Option<&JsString> {
        self.symbols.get(&id).and_then(|record| {
            matches!(record.kind, RuntimeSymbolKind::Global)
                .then_some(record.registry_key.as_ref())
                .flatten()
        })
    }

    fn description(&self, id: SymbolId) -> Option<&JsString> {
        self.symbols
            .get(&id)
            .and_then(|record| record.description.as_ref())
    }
}

fn well_known_symbol_description(id: SymbolId) -> Option<&'static str> {
    match id.0 {
        1 => Some("Symbol.iterator"),
        2 => Some("Symbol.toPrimitive"),
        3 => Some("Symbol.hasInstance"),
        4 => Some("Symbol.toStringTag"),
        5 => Some("Symbol.species"),
        6 => Some("Symbol.isConcatSpreadable"),
        7 => Some("Symbol.unscopables"),
        8 => Some("Symbol.asyncIterator"),
        9 => Some("Symbol.match"),
        10 => Some("Symbol.matchAll"),
        11 => Some("Symbol.replace"),
        12 => Some("Symbol.search"),
        13 => Some("Symbol.split"),
        _ => None,
    }
}

impl BuiltinFunction {
    fn require(module_specifier: impl Into<String>) -> Self {
        Self {
            kind: BuiltinFunctionKind::Require,
            module_specifier: module_specifier.into(),
            bound_object: None,
        }
    }

    /// A receiver-bound String.prototype method surfaced by `GetProperty` on
    /// a string value (bd-2vzgi). Carries no module provenance.
    fn string_method(kind: BuiltinFunctionKind) -> Self {
        Self {
            kind,
            module_specifier: String::new(),
            bound_object: None,
        }
    }

    /// Receiver-independent `Array.isArray`, materialized by the dedicated
    /// pure factory hostcall emitted for an unshadowed static member read.
    fn array_is_array() -> Self {
        Self {
            kind: BuiltinFunctionKind::ArrayIsArray,
            module_specifier: String::new(),
            bound_object: None,
        }
    }

    fn symbol(kind: BuiltinFunctionKind) -> Self {
        Self {
            kind,
            module_specifier: String::new(),
            bound_object: None,
        }
    }

    fn generator_next() -> Self {
        Self {
            kind: BuiltinFunctionKind::GeneratorPrototypeNext,
            module_specifier: String::new(),
            bound_object: None,
        }
    }

    /// Bind a resolving callable to its legacy Promise handle or to the
    /// shared resolving-pair identity selected by its builtin kind.
    fn promise_capability(kind: BuiltinFunctionKind, bound_identity: u32) -> Self {
        Self {
            kind,
            module_specifier: String::new(),
            bound_object: Some(bound_identity),
        }
    }

    fn promise_method(kind: BuiltinFunctionKind) -> Self {
        Self {
            kind,
            module_specifier: String::new(),
            bound_object: None,
        }
    }
}

#[cfg(test)]
mod promise_value_roundtrip_tests {
    use super::*;

    #[test]
    fn microtask_payload_clones_are_admitted_before_dequeue_and_released_on_error() {
        let mut core = InterpreterCore::new(
            InterpreterConfig::quickjs_defaults(),
            "microtask-payload-budget",
        );
        let promise = core.create_promise_accounted().unwrap();
        let task = crate::promise_model::Microtask::ResolveThenableValue {
            promise,
            then: crate::object_model::JsValue::BuiltinFunction(BuiltinFunction::require(
                "owner/".repeat(1024),
            )),
            thenable: crate::object_model::JsValue::Object(crate::object_model::ObjectHandle(0)),
            label: crate::ifc_artifacts::Label::Custom {
                name: "private-job".repeat(1024),
                level: 4,
            },
        };
        let clone_bytes = (std::mem::size_of::<crate::promise_model::Microtask>() as u64)
            + crate::promise_model::estimate_microtask_payload_memory_bytes(&task);
        core.event_loop.microtasks.enqueue(task);
        core.sync_estimated_memory_bytes().unwrap();
        let before = core.estimated_memory_bytes;
        let witness_len = core.event_loop.microtasks.witness_log().len();
        let original_ceiling = core.config.max_total_memory_bytes;
        core.config.max_total_memory_bytes = before + clone_bytes - 1;

        assert!(matches!(
            core.drain_microtasks(None),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.event_loop.microtasks.pending_count(), 1);
        assert_eq!(core.event_loop.microtasks.witness_log().len(), witness_len);
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert_eq!(core.estimated_memory_bytes, before);

        core.config.max_total_memory_bytes = original_ceiling;
        assert!(matches!(
            core.drain_microtasks(None),
            Err(InterpreterError::TypeError { .. })
        ));
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn a_partial_microtask_checkpoint_is_a_fatal_limit_error() {
        let mut core =
            InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "microtask-limit");
        let promises: Vec<_> = (0..3)
            .map(|_| core.create_promise_accounted().unwrap())
            .collect();
        for promise in &promises {
            core.event_loop
                .microtasks
                .enqueue(crate::promise_model::Microtask::PromiseReaction {
                    handler: None,
                    argument: crate::object_model::JsValue::Int(1),
                    result_promise: *promise,
                    label: crate::ifc_artifacts::Label::Public,
                });
        }
        core.sync_estimated_memory_bytes().unwrap();
        let error = core.drain_microtasks_with_limit(None, 2).unwrap_err();
        assert_eq!(
            error,
            InterpreterError::MicrotaskLimitExceeded {
                drained: 2,
                max_drain: 2
            }
        );
        assert!(!InterpreterCore::is_js_catchable_error(&error));
        assert_eq!(core.event_loop.microtasks.pending_count(), 1);
        assert!(matches!(
            core.promise_store.get(promises[2]).unwrap().state,
            crate::promise_model::PromiseState::Pending
        ));
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
        core.drain_microtasks_with_limit(None, 1).unwrap();
        assert!(core.event_loop.microtasks.is_empty());
    }

    #[test]
    fn thenable_jobs_retain_the_exact_callable_and_resolution_label() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "captured-then");
        let callable = Value::BuiltinFunction(BuiltinFunction::require("/owner.cjs"));
        let object = core
            .alloc_object_with_properties(&[("then", callable.clone())])
            .unwrap();
        let promise = core.create_promise_accounted().unwrap();
        core.resolve_promise_with_value(
            promise,
            Value::Object(object),
            crate::ifc_artifacts::Label::Secret,
        )
        .unwrap();
        core.set_object_runtime_property(
            object,
            RuntimePropertyKey::String(JsString::from("then")),
            Value::Undefined,
        )
        .unwrap();
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
        let task = core.event_loop.microtasks.dequeue().unwrap();
        let crate::promise_model::Microtask::ResolveThenableValue {
            promise: captured_promise,
            then,
            thenable,
            label,
        } = task
        else {
            panic!("expected a captured thenable job");
        };
        assert_eq!(captured_promise, promise);
        assert_eq!(InterpreterCore::js_value_to_value(&then), callable);
        assert_eq!(
            InterpreterCore::js_value_to_value(&thenable),
            Value::Object(object)
        );
        assert_eq!(label, crate::ifc_artifacts::Label::Secret);
    }

    #[test]
    fn captured_thenable_job_admission_rolls_back_the_queue_and_promise_state() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        let mut core = InterpreterCore::new(config, "captured-then-budget");
        let object = core
            .alloc_object_with_properties(&[("then", Value::Function(0))])
            .unwrap();
        let promise = core.create_promise_accounted().unwrap();
        core.sync_estimated_memory_bytes().unwrap();
        let before = core.estimated_memory_bytes;
        let enqueued = core.event_loop.microtasks.total_enqueued();
        core.config.max_total_memory_bytes = before;
        assert!(matches!(
            core.resolve_promise_with_value(
                promise,
                Value::Object(object),
                crate::ifc_artifacts::Label::Public,
            ),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.event_loop.microtasks.total_enqueued(), enqueued);
        assert!(core.event_loop.microtasks.is_empty());
        assert!(matches!(
            core.promise_store.get(promise).unwrap().state,
            crate::promise_model::PromiseState::Pending
        ));
        assert_eq!(core.estimated_memory_bytes, before);
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn every_callable_and_suspended_value_roundtrips_through_promises() {
        let values = [
            Value::Function(5),
            Value::Closure(5),
            Value::Iterator(5),
            Value::GeneratorFunction(5),
            Value::Generator(5),
            Value::AsyncFunction(5),
            Value::AsyncFunctionObject(5),
            Value::AsyncGeneratorFunction(5),
            Value::AsyncGeneratorObject(5),
            Value::Promise(5),
            Value::BuiltinFunction(BuiltinFunction::require("/modules/owner.cjs")),
            Value::BuiltinFunction(BuiltinFunction::promise_capability(
                BuiltinFunctionKind::PromiseResolveFunction,
                5,
            )),
        ];
        for value in values {
            let payload = InterpreterCore::value_to_js_value(&value);
            assert_eq!(InterpreterCore::js_value_to_value(&payload), value);
            let encoded = serde_json::to_string(&payload).expect("serialize Promise value");
            let decoded: crate::object_model::JsValue =
                serde_json::from_str(&encoded).expect("deserialize Promise value");
            assert_eq!(payload, decoded);
            assert!(payload.is_object());
            assert_eq!(payload.type_name(), value.type_name());
            assert_eq!(
                payload.is_callable(),
                InterpreterCore::is_sync_callable(&value)
            );
        }
    }

    #[test]
    fn promise_builtin_provenance_retains_its_owned_memory_charge() {
        let builtin = BuiltinFunction::require("/modules/owner.cjs");
        let expected = MEMORY_ESTIMATE_STRING_BASE_BYTES + builtin.module_specifier.len() as u64;
        assert_eq!(
            crate::promise_model::estimate_js_value_memory_bytes(
                &crate::object_model::JsValue::BuiltinFunction(builtin)
            ),
            expected
        );
        assert_eq!(
            crate::promise_model::estimate_js_value_memory_bytes(
                &crate::object_model::JsValue::BuiltinFunction(BuiltinFunction::array_is_array())
            ),
            0
        );
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
            Self::Symbol(_) => true,
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
            | Self::Str(_)
            | Self::Symbol(_) => false,
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
            Self::Symbol(_) => "symbol",
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
            Self::Symbol(_) => "symbol",
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
            Self::Symbol(id) => write!(f, "Symbol({})", id.0),
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
    /// Per-own-string-property IFC labels (bd-ojvo1, core-twin parity with the
    /// engine slice). A missing entry denotes `Label::Public`, so this map stays
    /// sparse and serialization/construction are unchanged for the common case.
    /// Without it, a `Secret` value written to a property of a lower-labeled
    /// object would launder back out as the object's label on later reads.
    property_labels: OrderedStringMap<crate::ifc_artifacts::Label>,
    /// Non-default descriptor bits, keyed by exact UTF-16 or Symbol identity.
    property_attributes: BTreeMap<RuntimePropertyKey, PropertyAttributes>,
    /// Descriptor/presence observations survive deletion and later writes.
    /// This protects enumeration and missing-property reads as well as values.
    property_structure_label: Option<crate::ifc_artifacts::Label>,
    /// Accessor descriptor storage, parallel to `properties` so the baseline
    /// heap can model the object_model accessor/data split.
    pub accessors: BTreeMap<String, AccessorProperty>,
    /// Prototype link used by membership operators and constructor instances.
    pub prototype: Option<ObjectId>,
    /// Constructor function index that allocated this object via `Construct`.
    pub constructor_function: Option<u32>,
    /// Engine-private parent constructor slot, inaccessible to guest code.
    derived_constructor_parent: Option<Value>,
    /// IFC provenance paired with the private parent constructor slot.
    derived_constructor_parent_label: Option<crate::ifc_artifacts::Label>,
    /// Whether the owning function is a derived class constructor.
    is_derived_constructor: bool,
    /// Whether the owning function uses the implicit forwarding constructor.
    is_default_derived_constructor: bool,
    /// Whether this object was allocated by an array-producing path.
    pub is_array: bool,
}

struct HeapSymbolPropertyRef<'a> {
    symbol_id: SymbolId,
    property: &'a BaselineSymbolProperty<Value>,
}

impl Serialize for HeapSymbolPropertyRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        match self.property {
            BaselineSymbolProperty::Data(value) => {
                let mut record = serializer.serialize_struct("SymbolProperty", 3)?;
                record.serialize_field("symbol_id", &self.symbol_id.0)?;
                record.serialize_field("kind", "data")?;
                record.serialize_field("value", value)?;
                record.end()
            }
            BaselineSymbolProperty::Accessor { get, set } => {
                let mut record = serializer.serialize_struct("SymbolProperty", 4)?;
                record.serialize_field("symbol_id", &self.symbol_id.0)?;
                record.serialize_field("kind", "accessor")?;
                record.serialize_field("get", get)?;
                record.serialize_field("set", set)?;
                record.end()
            }
        }
    }
}

impl Serialize for HeapObject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let has_exact_only_accessors = self.has_exact_only_accessors();
        let exact_accessor_entries =
            has_exact_only_accessors.then(|| self.exact_accessor_entries());
        let has_accessors = !self.accessors.is_empty() || has_exact_only_accessors;
        let needs_exact_order = self.properties.baseline_string_key_order().is_some()
            || self.properties.exact_len() != self.properties.len()
            || has_exact_only_accessors;
        let order = needs_exact_order.then(|| {
            self.own_exact_property_keys()
                .into_iter()
                .filter(|key| key.as_str().and_then(canonical_array_index).is_none())
                .collect::<Vec<_>>()
        });
        let symbol_properties = self
            .properties
            .baseline_symbol_properties()
            .map(|(symbol_id, property)| HeapSymbolPropertyRef {
                symbol_id,
                property,
            })
            .collect::<Vec<_>>();
        let has_constructor_metadata = self.is_derived_constructor
            || self.is_default_derived_constructor
            || self.derived_constructor_parent.is_some()
            || self.derived_constructor_parent_label.is_some();
        let field_count = 4
            + if has_accessors { 1 } else { 0 }
            + if order.is_some() { 1 } else { 0 }
            + if symbol_properties.is_empty() { 0 } else { 1 }
            + if self.property_labels.is_empty() {
                0
            } else {
                1
            }
            + if has_constructor_metadata { 4 } else { 0 };
        let field_count = field_count
            + usize::from(!self.property_attributes.is_empty())
            + usize::from(self.property_structure_label.is_some());
        let mut object = serializer.serialize_struct("HeapObject", field_count)?;
        object.serialize_field("properties", &self.properties)?;
        if has_accessors {
            if let Some(exact_accessor_entries) = &exact_accessor_entries {
                object.serialize_field("accessors", exact_accessor_entries)?;
            } else {
                object.serialize_field("accessors", &self.accessors)?;
            }
        }
        object.serialize_field("prototype", &self.prototype)?;
        object.serialize_field("constructor_function", &self.constructor_function)?;
        object.serialize_field("is_array", &self.is_array)?;
        if has_constructor_metadata {
            object.serialize_field(
                "derived_constructor_parent",
                &self.derived_constructor_parent,
            )?;
            object.serialize_field(
                "derived_constructor_parent_label",
                &self.derived_constructor_parent_label,
            )?;
            object.serialize_field("is_derived_constructor", &self.is_derived_constructor)?;
            object.serialize_field(
                "is_default_derived_constructor",
                &self.is_default_derived_constructor,
            )?;
        }
        if let Some(order) = &order {
            object.serialize_field("own_string_key_order", order)?;
        }
        if !self.property_labels.is_empty() {
            object.serialize_field("property_labels", &self.property_labels)?;
        }
        if !symbol_properties.is_empty() {
            object.serialize_field("symbol_properties", &symbol_properties)?;
        }
        if !self.property_attributes.is_empty() {
            let attributes = self
                .property_attributes
                .iter()
                .map(|(key, attributes)| PropertyAttributesWire::from_entry(key, *attributes))
                .collect::<Vec<_>>();
            object.serialize_field("property_attributes", &attributes)?;
        }
        if let Some(label) = &self.property_structure_label {
            object.serialize_field("property_structure_label", label)?;
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
            accessors: ExactOrderedStringMap<AccessorProperty>,
            prototype: Option<ObjectId>,
            constructor_function: Option<u32>,
            #[serde(default)]
            is_array: bool,
            #[serde(default)]
            derived_constructor_parent: Option<Value>,
            #[serde(default)]
            derived_constructor_parent_label: Option<crate::ifc_artifacts::Label>,
            #[serde(default)]
            is_derived_constructor: bool,
            #[serde(default)]
            is_default_derived_constructor: bool,
            #[serde(default)]
            own_string_key_order: Option<Vec<JsString>>,
            #[serde(default)]
            property_labels: OrderedStringMap<crate::ifc_artifacts::Label>,
            #[serde(default)]
            symbol_properties: Vec<HeapSymbolPropertyWire>,
            #[serde(default)]
            property_attributes: Vec<PropertyAttributesWire>,
            #[serde(default)]
            property_structure_label: Option<crate::ifc_artifacts::Label>,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HeapSymbolPropertyWire {
            symbol_id: u32,
            kind: String,
            value: Option<Value>,
            #[serde(default, deserialize_with = "deserialize_present_nullable")]
            get: Option<PresentNullable<Value>>,
            #[serde(default, deserialize_with = "deserialize_present_nullable")]
            set: Option<PresentNullable<Value>>,
        }

        let wire = HeapObjectWire::deserialize(deserializer)?;
        let has_parent = wire.derived_constructor_parent.is_some();
        let has_parent_label = wire.derived_constructor_parent_label.is_some();
        if has_parent != has_parent_label {
            return Err(D::Error::custom(
                "derived constructor parent and label must be present together",
            ));
        }
        if wire.is_derived_constructor != has_parent {
            return Err(D::Error::custom(
                "derived constructor metadata must include parent, label, and derived flag",
            ));
        }
        if wire.is_default_derived_constructor && !wire.is_derived_constructor {
            return Err(D::Error::custom(
                "default derived constructor flag requires derived constructor metadata",
            ));
        }
        let mut object = Self {
            properties: wire.properties,
            property_labels: wire.property_labels,
            property_attributes: BTreeMap::new(),
            property_structure_label: wire.property_structure_label,
            accessors: BTreeMap::new(),
            prototype: wire.prototype,
            constructor_function: wire.constructor_function,
            derived_constructor_parent: wire.derived_constructor_parent,
            derived_constructor_parent_label: wire.derived_constructor_parent_label,
            is_derived_constructor: wire.is_derived_constructor,
            is_default_derived_constructor: wire.is_default_derived_constructor,
            is_array: wire.is_array,
        };

        for (key, accessor) in wire.accessors {
            if object.properties.contains_exact_key(&key) {
                return Err(D::Error::custom(
                    "property key cannot be both data and accessor",
                ));
            }
            object.insert_exact_accessor(key, accessor);
        }

        if let Some(order) = wire.own_string_key_order {
            let mut encoded = BTreeSet::new();
            for key in &order {
                if key.as_str().and_then(canonical_array_index).is_some() {
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
                .own_exact_property_keys()
                .into_iter()
                .filter(|key| key.as_str().and_then(canonical_array_index).is_none())
                .collect::<BTreeSet<_>>();
            if encoded != live {
                return Err(D::Error::custom(
                    "ordinary-string key order must contain every live ordinary key exactly once",
                ));
            }
            object.properties.set_baseline_string_key_order(Some(order));
        } else if object.properties.exact_len() != object.properties.len()
            || object.has_exact_only_accessors()
        {
            return Err(D::Error::custom(
                "exact string properties require own_string_key_order",
            ));
        }

        let mut seen_symbols = BTreeSet::new();
        for record in wire.symbol_properties {
            let symbol_id = SymbolId(record.symbol_id);
            if symbol_id.0 == 0 {
                return Err(D::Error::custom("Symbol property id 0 is invalid"));
            }
            if !seen_symbols.insert(symbol_id) {
                return Err(D::Error::custom("duplicate Symbol property id"));
            }
            let property = match record.kind.as_str() {
                "data" => {
                    if record.get.is_some() || record.set.is_some() {
                        return Err(D::Error::custom("data Symbol property forbids get/set"));
                    }
                    BaselineSymbolProperty::Data(
                        record.value.ok_or_else(|| {
                            D::Error::custom("data Symbol property requires value")
                        })?,
                    )
                }
                "accessor" => {
                    if record.value.is_some() {
                        return Err(D::Error::custom("accessor Symbol property forbids value"));
                    }
                    let get = record
                        .get
                        .ok_or_else(|| D::Error::custom("accessor Symbol property requires get"))?
                        .0;
                    let set = record
                        .set
                        .ok_or_else(|| D::Error::custom("accessor Symbol property requires set"))?
                        .0;
                    BaselineSymbolProperty::Accessor { get, set }
                }
                _ => return Err(D::Error::custom("unknown Symbol property kind")),
            };
            object
                .properties
                .insert_baseline_symbol_property(symbol_id, property);
        }

        for record in wire.property_attributes {
            let (key, attributes) = record.into_entry().map_err(D::Error::custom)?;
            if !object.contains_own_runtime_property(&key) {
                return Err(D::Error::custom(
                    "attributes require an existing own property",
                ));
            }
            if object.property_attributes.insert(key, attributes).is_some() {
                return Err(D::Error::custom("duplicate property attributes"));
            }
        }
        Ok(object)
    }
}

impl PartialEq for HeapObject {
    fn eq(&self, other: &Self) -> bool {
        self.properties == other.properties
            && self.property_attributes == other.property_attributes
            && self.property_structure_label == other.property_structure_label
            && self.accessors == other.accessors
            && self.prototype == other.prototype
            && self.constructor_function == other.constructor_function
            && self.derived_constructor_parent == other.derived_constructor_parent
            && self.derived_constructor_parent_label == other.derived_constructor_parent_label
            && self.is_derived_constructor == other.is_derived_constructor
            && self.is_default_derived_constructor == other.is_default_derived_constructor
            && self.is_array == other.is_array
            && self.properties.baseline_string_key_order().is_some()
                == other.properties.baseline_string_key_order().is_some()
            && self.own_exact_property_keys() == other.own_exact_property_keys()
            && self.properties.baseline_symbol_key_order()
                == other.properties.baseline_symbol_key_order()
            && self
                .properties
                .baseline_symbol_properties()
                .eq(other.properties.baseline_symbol_properties())
    }
}

impl Eq for HeapObject {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PropertyOrderRollback {
    Unchanged,
    RemoveInsertedKey,
    Restore(Option<Vec<JsString>>),
}

impl HeapObject {
    pub fn new() -> Self {
        Self::default()
    }

    fn exact_accessor(&self, key: &JsString) -> Option<AccessorProperty> {
        match key.as_str() {
            Some(key) => self.accessors.get(key).cloned(),
            None => self
                .properties
                .baseline_exact_string_accessor(key)
                .map(|accessor| AccessorProperty {
                    get: accessor.get.clone(),
                    set: accessor.set.clone(),
                }),
        }
    }

    fn insert_exact_accessor(
        &mut self,
        key: JsString,
        accessor: AccessorProperty,
    ) -> Option<AccessorProperty> {
        match key.as_str() {
            Some(key) => self.accessors.insert(key.to_string(), accessor),
            None => self
                .properties
                .insert_baseline_exact_string_accessor(
                    key,
                    BaselineStringAccessor {
                        get: accessor.get,
                        set: accessor.set,
                    },
                )
                .map(|accessor| AccessorProperty {
                    get: accessor.get,
                    set: accessor.set,
                }),
        }
    }

    fn remove_exact_accessor(&mut self, key: &JsString) -> Option<AccessorProperty> {
        match key.as_str() {
            Some(key) => self.accessors.remove(key),
            None => self
                .properties
                .remove_baseline_exact_string_accessor(key)
                .map(|accessor| AccessorProperty {
                    get: accessor.get,
                    set: accessor.set,
                }),
        }
    }

    fn exact_accessor_entries(&self) -> Vec<(JsString, AccessorProperty)> {
        self.own_exact_property_keys()
            .into_iter()
            .filter_map(|key| self.exact_accessor(&key).map(|accessor| (key, accessor)))
            .collect()
    }

    fn has_exact_only_accessors(&self) -> bool {
        self.properties
            .baseline_exact_string_accessors()
            .next()
            .is_some()
    }

    fn contains_own_property(&self, key: &str) -> bool {
        self.accessors.contains_key(key) || self.properties.contains_key(key)
    }

    fn contains_own_runtime_property(&self, key: &RuntimePropertyKey) -> bool {
        match key {
            RuntimePropertyKey::String(key) => {
                self.properties.contains_exact_key(key)
                    || match key.as_str() {
                        Some(key) => self.accessors.contains_key(key),
                        None => self
                            .properties
                            .baseline_exact_string_accessor(key)
                            .is_some(),
                    }
            }
            RuntimePropertyKey::Symbol(symbol) => {
                self.properties.baseline_symbol_property(*symbol).is_some()
            }
        }
    }

    /// Record a logical own-property definition without moving an existing
    /// key across data/accessor descriptor-kind transitions.
    ///
    /// Before recording, reconcile the hidden chronology with the observable
    /// public fields. This preserves the position of an accessor inserted
    /// directly through the ADR-frozen public `accessors` map before a later
    /// interpreter mutation. The returned delta restores the exact prior
    /// hidden state if the definition is rejected by the memory budget.
    fn record_property_definition(
        &mut self,
        key: &JsString,
        existed: bool,
    ) -> PropertyOrderRollback {
        if key.as_str().and_then(canonical_array_index).is_some() {
            return PropertyOrderRollback::Unchanged;
        }

        let normalized = self
            .own_exact_property_keys()
            .into_iter()
            .filter(|candidate| candidate.as_str().and_then(canonical_array_index).is_none())
            .collect::<Vec<_>>();
        let previous = self
            .properties
            .baseline_string_key_order()
            .map(<[JsString]>::to_vec);
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
            order.push(key.clone());
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

    fn rollback_property_definition_order(
        &mut self,
        key: &JsString,
        rollback: PropertyOrderRollback,
    ) {
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

    fn forget_property_order(&mut self, key: &JsString) {
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
    #[cfg(test)]
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
                let Some(key) = key.as_str() else {
                    continue;
                };
                if self.contains_own_property(key) && seen.insert(key.to_string()) {
                    ordinary.push(key.to_string());
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

    /// Return all live exact string keys in ECMAScript string-key order.
    fn own_exact_property_keys(&self) -> Vec<JsString> {
        let mut array_indices = BTreeMap::<u32, JsString>::new();
        for key in self.properties.exact_keys() {
            if let Some(index) = key.as_str().and_then(canonical_array_index) {
                array_indices.entry(index).or_insert(key);
            }
        }
        for key in self.accessors.keys() {
            if let Some(index) = canonical_array_index(key) {
                array_indices
                    .entry(index)
                    .or_insert_with(|| JsString::from(key));
            }
        }

        let mut ordinary = Vec::new();
        let mut seen = BTreeSet::new();
        if let Some(order) = self.properties.baseline_string_key_order() {
            for key in order {
                let runtime_key = RuntimePropertyKey::String(key.clone());
                if self.contains_own_runtime_property(&runtime_key) && seen.insert(key.clone()) {
                    ordinary.push(key.clone());
                }
            }
        }
        for key in self.properties.exact_keys() {
            if key.as_str().and_then(canonical_array_index).is_none() && seen.insert(key.clone()) {
                ordinary.push(key);
            }
        }
        for key in self.accessors.keys().map(JsString::from).chain(
            self.properties
                .baseline_exact_string_accessors()
                .map(|(key, _)| key.clone()),
        ) {
            if key.as_str().and_then(canonical_array_index).is_none() && seen.insert(key.clone()) {
                ordinary.push(key);
            }
        }

        array_indices.into_values().chain(ordinary).collect()
    }

    /// Return all live own keys in ECMAScript order: integer strings,
    /// ordinary strings, then Symbols in their property-creation order.
    #[cfg(test)]
    fn own_typed_property_keys(&self) -> Vec<TypedPropertyKey> {
        self.own_property_keys()
            .into_iter()
            .map(TypedPropertyKey::String)
            .chain(
                self.properties
                    .baseline_symbol_key_order()
                    .iter()
                    .copied()
                    .map(TypedPropertyKey::Symbol),
            )
            .collect()
    }

    fn own_runtime_property_keys(&self) -> Vec<RuntimePropertyKey> {
        self.own_exact_property_keys()
            .into_iter()
            .map(RuntimePropertyKey::String)
            .chain(
                self.properties
                    .baseline_symbol_key_order()
                    .iter()
                    .copied()
                    .map(RuntimePropertyKey::Symbol),
            )
            .collect()
    }
}

fn heap_object_contains_symbols(object: &HeapObject) -> bool {
    !object.properties.baseline_symbol_key_order().is_empty()
        || object
            .properties
            .all_data_values()
            .any(|value| matches!(value, Value::Symbol(_)))
        || object.accessors.values().any(|accessor| {
            accessor
                .get
                .as_ref()
                .is_some_and(|value| matches!(value, Value::Symbol(_)))
                || accessor
                    .set
                    .as_ref()
                    .is_some_and(|value| matches!(value, Value::Symbol(_)))
        })
        || object
            .properties
            .baseline_exact_string_accessors()
            .any(|(_, accessor)| {
                accessor
                    .get
                    .as_ref()
                    .is_some_and(|value| matches!(value, Value::Symbol(_)))
                    || accessor
                        .set
                        .as_ref()
                        .is_some_and(|value| matches!(value, Value::Symbol(_)))
            })
        || object
            .properties
            .baseline_symbol_properties()
            .any(|(_, property)| match property {
                BaselineSymbolProperty::Data(value) => matches!(value, Value::Symbol(_)),
                BaselineSymbolProperty::Accessor { get, set } => {
                    get.as_ref()
                        .is_some_and(|value| matches!(value, Value::Symbol(_)))
                        || set
                            .as_ref()
                            .is_some_and(|value| matches!(value, Value::Symbol(_)))
                }
            })
}

fn validate_symbol_value(state: &RuntimeSymbolState, value: &Value) -> Result<(), String> {
    if let Value::Symbol(id) = value
        && !state.contains(*id)
    {
        return Err(format!("unresolved Symbol id {}", id.0));
    }
    Ok(())
}

fn validate_heap_symbol_references(
    state: &RuntimeSymbolState,
    object: &HeapObject,
) -> Result<(), String> {
    for value in object.properties.all_data_values() {
        validate_symbol_value(state, value)?;
    }
    for accessor in object.accessors.values() {
        if let Some(getter) = &accessor.get {
            validate_symbol_value(state, getter)?;
        }
        if let Some(setter) = &accessor.set {
            validate_symbol_value(state, setter)?;
        }
    }
    for (_, accessor) in object.properties.baseline_exact_string_accessors() {
        if let Some(getter) = &accessor.get {
            validate_symbol_value(state, getter)?;
        }
        if let Some(setter) = &accessor.set {
            validate_symbol_value(state, setter)?;
        }
    }
    for (id, property) in object.properties.baseline_symbol_properties() {
        if !state.contains(id) {
            return Err(format!("unresolved Symbol property id {}", id.0));
        }
        match property {
            BaselineSymbolProperty::Data(value) => validate_symbol_value(state, value)?,
            BaselineSymbolProperty::Accessor { get, set } => {
                if let Some(getter) = get {
                    validate_symbol_value(state, getter)?;
                }
                if let Some(setter) = set {
                    validate_symbol_value(state, setter)?;
                }
            }
        }
    }
    Ok(())
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

/// Private executable property key. Descriptor-model and hook-facing string
/// keys remain `String`; the runtime string arm keeps exact UTF-16 identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RuntimePropertyKey {
    String(JsString),
    Symbol(SymbolId),
}

/// Resumable state for the object-rest CopyDataProperties operation.
///
/// Keys and exclusions are snapshotted once. Property descriptors are looked
/// up again immediately before each read so a preceding getter can delete a
/// later key, while keys added after the snapshot remain absent.
#[derive(Debug, Clone)]
enum CopyDataPropertiesWriteMode {
    /// Object rest/spread define fresh own data properties and never invoke a
    /// setter on the newly created target.
    CreateData,
    /// Object.assign performs ordinary Set on its target. The source offset
    /// lets the HostCall resume the correct argument after a getter/setter.
    Set {
        target_receiver: Value,
        source_arg_offset: u32,
    },
}

#[derive(Debug, Clone)]
enum CopyDataPropertiesAwaiting {
    Getter(RuntimePropertyKey),
}

#[derive(Debug, Clone)]
struct CopyDataPropertiesState {
    instruction_ip: usize,
    register_base: usize,
    call_depth: usize,
    target_id: ObjectId,
    source: Value,
    source_label: crate::ifc_artifacts::Label,
    /// Exact immutable code-unit snapshot for string sources. Keeping it once
    /// makes indexed property reads linear overall instead of rescanning the
    /// prefix for every code-unit key.
    string_units: Option<Vec<u16>>,
    keys: Vec<RuntimePropertyKey>,
    excluded: BTreeSet<RuntimePropertyKey>,
    next_index: usize,
    write_mode: CopyDataPropertiesWriteMode,
    /// Getter results return through the operation's scratch register;
    /// setters return only for control-flow continuation.
    awaiting: Option<CopyDataPropertiesAwaiting>,
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
    keys: Vec<JsString>,
    next_index: usize,
    deleted_keys: BTreeSet<JsString>,
    done: bool,
    closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeForOfState {
    values: Vec<Value>,
    /// Read array length and properties at each step, preserving holes,
    /// inherited getters, and mutations made while processing prior values.
    array_object: Option<ObjectId>,
    /// Ordinary property backing for an iterator returned by Symbol.iterator.
    iterator_object: Option<ObjectId>,
    /// The original receiver can differ from its function-property backing.
    iterator_receiver: Option<Value>,
    /// Captured once by GetIterator, then called for each subsequent step.
    next_method: Option<Value>,
    label: crate::ifc_artifacts::Label,
    next_index: usize,
    done: bool,
    closed: bool,
    return_called: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InlineCallCompletion {
    Value(Value),
    Throw(LabeledException),
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
    exports: BTreeMap<JsString, Value>,
    cjs_module_object: Option<ObjectId>,
    /// Immutable executable owner of functions that outlive module evaluation.
    /// Retained once per module, shared by every closure created from it.
    compiled_module: Option<Rc<Ir3Module>>,
    retained_program_bytes: u64,
}

#[derive(Debug, Clone, Default)]
struct ModuleState {
    modules: BTreeMap<String, ModuleRuntimeRecord>,
    retained_program_bytes: u64,
}

impl ModuleState {
    fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
            retained_program_bytes: 0,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Complete isolated activation captured after parameter initialization or
    /// a yield. This keeps lexical cells, control stacks, and registers owned
    /// by the generator instead of borrowing the caller's active context.
    execution: Option<ModuleExecutionSnapshot>,
    /// Destination register that receives the argument to the next `.next(v)`
    /// after a source `yield`. `None` while suspended at body start.
    resume_dst: Option<u32>,
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
    /// Complete isolated state at body entry or an await boundary.
    execution: Option<ModuleExecutionSnapshot>,
    /// The immutable owner is shared with the module registry when available.
    owner_module: Option<Rc<Ir3Module>>,
    /// Raw IR can retain a private owner when no module record exists.
    retained_program_bytes: u64,
    /// The private register arena stays owned while executing or parked.
    register_storage_bytes: u64,
    /// Provenance accumulated across awaited completions.
    label: crate::ifc_artifacts::Label,
    phase: AsyncFunctionPhase,
    result_promise: u32,
}

/// A settlement delivered to a parked async activation by one microtask.
struct AsyncResumeValue {
    result_register: u32,
    settlement: Result<crate::object_model::JsValue, crate::object_model::JsValue>,
    label: crate::ifc_artifacts::Label,
}

/// Context information for resuming an async function after a pending await.
#[derive(Debug, Clone)]
struct AsyncResumptionContext {
    /// The async function whose activation was suspended.
    async_function_id: u32,
    /// Register overwritten by the fulfillment value or rejection completion.
    result_register: u32,
}

/// Fully validated state needed to enter an async function call frame.
struct AsyncCallSetup {
    function_index: u32,
    function_entry: u32,
    captured_env: Option<Vec<ScopeFrame>>,
    arguments: Vec<(Value, crate::ifc_artifacts::Label)>,
    this_value: Value,
    this_label: crate::ifc_artifacts::Label,
    super_value: Value,
    super_label: crate::ifc_artifacts::Label,
    result_register: u32,
}

/// Fully validated state needed to initialize a synchronous generator through
/// its parameter prologue and suspend it at `GeneratorBodyStart`.
struct GeneratorCallSetup {
    function_index: u32,
    function_entry: u32,
    captured_env: Vec<ScopeFrame>,
    arguments: Vec<(Value, crate::ifc_artifacts::Label)>,
    this_value: Value,
    this_label: crate::ifc_artifacts::Label,
    super_value: Value,
    super_label: crate::ifc_artifacts::Label,
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
    /// Resolve the target's kind while its owning program is active. An
    /// exception can unwind across programs before this frame is consumed.
    catch_is_finally: bool,
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

/// Mutable state shared by every scope/closure view of one lexical binding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeBindingState {
    value: Value,
    label: crate::ifc_artifacts::Label,
    /// `true` once initialized (let/const start uninitialized in TDZ).
    initialized: bool,
}

/// A single binding in a scope environment.
///
/// Scope snapshots clone the handle, not the state. Fresh declarations create
/// fresh cells, while closures and their callers retain live views of the same
/// value, label, and initialization state.
#[derive(Debug, Clone)]
struct ScopeBinding {
    kind: BindingKind,
    state: Rc<RefCell<ScopeBindingState>>,
}

impl ScopeBinding {
    fn new(kind: BindingKind) -> Self {
        Self::with_state(
            kind,
            Value::Undefined,
            crate::ifc_artifacts::Label::Public,
            kind.is_hoisted(),
        )
    }

    fn with_state(
        kind: BindingKind,
        value: Value,
        label: crate::ifc_artifacts::Label,
        initialized: bool,
    ) -> Self {
        Self {
            kind,
            state: Rc::new(RefCell::new(ScopeBindingState {
                value,
                label,
                initialized,
            })),
        }
    }

    fn state(&self) -> Result<Ref<'_, ScopeBindingState>, InterpreterError> {
        self.state
            .try_borrow()
            .map_err(|_| InterpreterError::TypeError {
                expected: "available scope binding state".to_string(),
                got: "state is already mutably borrowed".to_string(),
            })
    }

    fn state_mut(&self) -> Result<RefMut<'_, ScopeBindingState>, InterpreterError> {
        self.state
            .try_borrow_mut()
            .map_err(|_| InterpreterError::TypeError {
                expected: "available mutable scope binding state".to_string(),
                got: "state is already borrowed".to_string(),
            })
    }

    fn snapshot_state(&self) -> Result<ScopeBindingState, InterpreterError> {
        Ok(self.state()?.clone())
    }

    fn restore_state(&self, previous: ScopeBindingState) -> Result<(), InterpreterError> {
        *self.state_mut()? = previous;
        Ok(())
    }

    #[cfg(test)]
    fn value(&self) -> Result<Value, InterpreterError> {
        Ok(self.state()?.value.clone())
    }
}

/// A single scope frame in the environment chain.
#[derive(Debug, Clone)]
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
        self.bindings.insert(name, ScopeBinding::new(kind))
    }

    fn get(&self, name: &str) -> Option<&ScopeBinding> {
        self.bindings.get(name)
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
    /// Function-table indices are local to the module that created the closure.
    module_specifier: Option<String>,
    /// Captured scope chain snapshot at closure creation time.
    captured_env: Vec<ScopeFrame>,
}

/// Private, per-closure state installed by `DefineMethod`.
///
/// This cannot be represented by guest-visible properties or keyed by a
/// function-table index: evaluating one method body more than once produces
/// distinct closures with distinct inferred names and `[[HomeObject]]` values.
#[derive(Debug, Clone)]
struct ClosureMethodMetadata {
    home_object: ObjectId,
    name: JsString,
    definition_label: crate::ifc_artifacts::Label,
}

/// A call stack frame.
#[derive(Debug, Clone)]
struct AccessorCallReturnSite {
    return_ip: usize,
    return_reg: Option<u32>,
    context_label: crate::ifc_artifacts::Label,
}

/// Constructor arguments stay in their existing storage until the callee's
/// fixed slots and rest array have been prepared. A spread list therefore
/// never needs to fit in the caller's register frame or an unbounded Vec.
enum ConstructorArguments {
    Registers(RegRange),
    Array {
        object: ObjectId,
        count: u32,
        label: crate::ifc_artifacts::Label,
    },
}

impl ConstructorArguments {
    fn count(&self) -> u32 {
        match self {
            Self::Registers(args) => args.count,
            Self::Array { count, .. } => *count,
        }
    }
}

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
    /// Whether this is a derived constructor activation. Derived activations
    /// begin with an uninitialized `this` binding and use distinct return rules.
    derived_constructor: bool,
    /// Whether the current constructor's `this` binding has been initialized.
    this_initialized: bool,
    /// A parent entered by `super()` initializes the immediately enclosing
    /// derived activation with its effective object result when it returns.
    initialize_derived_this_on_return: bool,
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
    /// Restore code and relative-import identity together with lexical state.
    saved_module_specifier: Option<String>,
    /// Async function ID if this frame is executing an async function.
    async_function_id: Option<u32>,
    /// Provenance of the operation that selected this activation: an accessor
    /// receiver or a constructor argument-list shape. Kept on the frame so
    /// defaults, nested calls, side effects, and returns cannot erase it.
    accessor_context_label: crate::ifc_artifacts::Label,
}

// ---------------------------------------------------------------------------
// Interpreter hooks
// ---------------------------------------------------------------------------

pub type ExtensionId = String;
pub type ObjectRef = ObjectId;
/// Legacy well-formed string property key accepted by
/// [`InterpreterHook::pre_property_access`].
pub type PropertyKey = String;

/// Exact property-key identity presented to interpreter hooks.
///
/// This type is deliberately distinct from the legacy [`PropertyKey`] alias:
/// a `Symbol` never crosses the compatibility callback as a display string,
/// and a non-well-formed ECMAScript string retains its exact UTF-16 units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookPropertyKey {
    String(JsString),
    Symbol(SymbolId),
}

impl HookPropertyKey {
    /// Borrow the frozen legacy callback key when that view is lossless.
    pub fn as_legacy_str(&self) -> Result<&str, HookPropertyKeyCompatibilityError> {
        match self {
            Self::String(key) => key
                .as_str()
                .ok_or(HookPropertyKeyCompatibilityError::NonWellFormedString),
            Self::Symbol(_) => Err(HookPropertyKeyCompatibilityError::Symbol),
        }
    }

    /// Convert to the frozen legacy callback key when that conversion is
    /// lossless.
    pub fn to_legacy_property_key(&self) -> Result<PropertyKey, HookPropertyKeyCompatibilityError> {
        self.as_legacy_str().map(ToOwned::to_owned)
    }
}

/// Why the default typed-key adapter cannot call a legacy string-only hook.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookPropertyKeyCompatibilityError {
    NonWellFormedString,
    Symbol,
}

impl fmt::Display for HookPropertyKeyCompatibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonWellFormedString => {
                write!(
                    f,
                    "non-well-formed ECMAScript string property key is not representable by the legacy string hook"
                )
            }
            Self::Symbol => {
                write!(
                    f,
                    "Symbol property key is not representable by the legacy string hook"
                )
            }
        }
    }
}

impl std::error::Error for HookPropertyKeyCompatibilityError {}

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
                Value::Symbol(id) => 18 + u64::from(id.0),
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
    /// Frozen compatibility callback for well-formed string property keys.
    ///
    /// New implementations that need exact strings or Symbols should override
    /// [`InterpreterHook::pre_property_access_typed`]. The default typed
    /// adapter calls this method only when conversion is lossless.
    fn pre_property_access(
        &self,
        ctx: &HookContext,
        target: &ObjectRef,
        key: &PropertyKey,
    ) -> HookAction;

    /// Typed property callback used by executable object property operations.
    ///
    /// The default implementation preserves existing hook implementations:
    /// well-formed strings reach [`InterpreterHook::pre_property_access`],
    /// while Symbols and non-well-formed strings fail closed without invoking
    /// that legacy callback.
    fn pre_property_access_typed(
        &self,
        ctx: &HookContext,
        target: &ObjectRef,
        key: &HookPropertyKey,
    ) -> Result<HookAction, HookPropertyKeyCompatibilityError> {
        let legacy_key = key.to_legacy_property_key()?;
        Ok(self.pre_property_access(ctx, target, &legacy_key))
    }

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
    /// Pending asynchronous work exceeded the deterministic turn limit.
    EventLoopTurnLimitExceeded { turns: u32, max_turns: u32 },
    /// A microtask checkpoint could not drain within its deterministic budget.
    MicrotaskLimitExceeded { drained: u32, max_drain: u32 },
}

impl fmt::Display for InterpreterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted { executed, budget } => {
                write!(f, "instruction budget exhausted: {executed}/{budget}")
            }
            Self::EventLoopTurnLimitExceeded { turns, max_turns } => {
                write!(
                    f,
                    "event loop turn limit exceeded: {turns}/{max_turns} with pending work"
                )
            }
            Self::MicrotaskLimitExceeded { drained, max_drain } => {
                write!(
                    f,
                    "microtask limit exceeded: {drained}/{max_drain} with pending work"
                )
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
                let name = user_visible_binding_name(name);
                write!(f, "Cannot access '{name}' before initialization")
            }
            Self::ConstAssignment { name } => {
                let name = user_visible_binding_name(name);
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

fn user_visible_binding_name(name: &str) -> &str {
    if name.starts_with('\0') {
        name.rsplit_once('\0')
            .map(|(_, source_name)| source_name)
            .filter(|source_name| !source_name.is_empty())
            .unwrap_or(name)
    } else {
        name
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
    /// IFC provenance paired with [`Self::value`] at the execution boundary.
    pub completion_label: crate::ifc_artifacts::Label,
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
    symbol_state: RuntimeSymbolState,
    array_null_prototypes: BTreeSet<ObjectId>,
    function_null_prototypes: BTreeSet<ObjectId>,
}

impl Serialize for ExecutionSeed {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let include_symbol_state = !self.symbol_state.is_default() || self.contains_symbol_values();
        let include_array_null_prototypes = !self.array_null_prototypes.is_empty();
        let include_function_null_prototypes = !self.function_null_prototypes.is_empty();
        let mut seed = serializer.serialize_struct(
            "ExecutionSeed",
            5 + usize::from(include_symbol_state)
                + usize::from(include_array_null_prototypes)
                + usize::from(include_function_null_prototypes),
        )?;
        seed.serialize_field("registers", &self.registers)?;
        seed.serialize_field("register_labels", &self.register_labels)?;
        seed.serialize_field("heap", &self.heap)?;
        seed.serialize_field(
            "function_prototypes",
            &self
                .function_prototypes
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
        )?;
        seed.serialize_field(
            "function_objects",
            &self
                .function_objects
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
        )?;
        if include_symbol_state {
            seed.serialize_field("symbol_state", &self.symbol_state)?;
        }
        if include_array_null_prototypes {
            seed.serialize_field("array_null_prototypes", &self.array_null_prototypes)?;
        }
        if include_function_null_prototypes {
            seed.serialize_field("function_null_prototypes", &self.function_null_prototypes)?;
        }
        seed.end()
    }
}

impl<'de> Deserialize<'de> for ExecutionSeed {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ExecutionSeedWire {
            registers: Vec<Value>,
            register_labels: Vec<crate::ifc_artifacts::Label>,
            heap: Vec<HeapObject>,
            function_prototypes: Vec<(FunctionObjectKey, ObjectId)>,
            function_objects: Vec<(FunctionObjectKey, ObjectId)>,
            #[serde(default, deserialize_with = "deserialize_present_value")]
            symbol_state: Option<PresentValue<RuntimeSymbolState>>,
            #[serde(default)]
            array_null_prototypes: BTreeSet<ObjectId>,
            #[serde(default)]
            function_null_prototypes: BTreeSet<ObjectId>,
        }

        let wire = ExecutionSeedWire::deserialize(deserializer)?;
        let symbol_state_was_present = wire.symbol_state.is_some();
        let function_prototypes = wire
            .function_prototypes
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let function_objects = wire
            .function_objects
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let seed = Self {
            registers: wire.registers,
            register_labels: wire.register_labels,
            heap: wire.heap,
            function_prototypes,
            function_objects,
            symbol_state: wire.symbol_state.map(|state| state.0).unwrap_or_default(),
            array_null_prototypes: wire.array_null_prototypes,
            function_null_prototypes: wire.function_null_prototypes,
        };
        if !symbol_state_was_present && seed.contains_symbol_values() {
            return Err(D::Error::custom(
                "execution seed with Symbol values or keys requires symbol_state",
            ));
        }
        seed.validate_symbol_references()
            .map_err(D::Error::custom)?;
        seed.validate_array_prototype_references()
            .map_err(D::Error::custom)?;
        Ok(seed)
    }
}

impl ExecutionSeed {
    fn validate_array_prototype_references(&self) -> Result<(), String> {
        for object_id in &self.array_null_prototypes {
            if !self
                .heap
                .get(object_id.0 as usize)
                .is_some_and(|object| object.is_array && object.prototype.is_none())
            {
                return Err(
                    "execution seed null array prototype must reference an array with no prototype"
                        .into(),
                );
            }
        }
        for object_id in &self.function_null_prototypes {
            if !self.function_objects.values().any(|id| id == object_id)
                || !self
                    .heap
                    .get(object_id.0 as usize)
                    .is_some_and(|object| object.prototype.is_none())
            {
                return Err("execution seed null function prototype must reference a function with no prototype".into());
            }
        }
        Ok(())
    }

    fn contains_symbol_values(&self) -> bool {
        self.registers
            .iter()
            .any(|value| matches!(value, Value::Symbol(_)))
            || self.heap.iter().any(heap_object_contains_symbols)
    }

    fn validate_symbol_references(&self) -> Result<(), String> {
        self.symbol_state.validate()?;
        for value in &self.registers {
            validate_symbol_value(&self.symbol_state, value)?;
        }
        for object in &self.heap {
            validate_heap_symbol_references(&self.symbol_state, object)?;
        }
        Ok(())
    }
}

/// Eager execution seed for testing comparison
#[derive(Debug, Clone)]
pub struct EagerExecutionSeed {
    pub registers: Vec<Value>,
    pub heap: Vec<HeapObject>,
    function_prototypes: BTreeMap<FunctionObjectKey, ObjectId>,
    function_objects: BTreeMap<FunctionObjectKey, ObjectId>,
    symbol_state: RuntimeSymbolState,
    array_null_prototypes: BTreeSet<ObjectId>,
    function_null_prototypes: BTreeSet<ObjectId>,
}

impl EagerExecutionSeed {
    fn validate_symbol_references(&self) -> Result<(), String> {
        self.symbol_state.validate()?;
        for value in &self.registers {
            validate_symbol_value(&self.symbol_state, value)?;
        }
        for object in &self.heap {
            validate_heap_symbol_references(&self.symbol_state, object)?;
        }
        for object_id in &self.array_null_prototypes {
            if !self
                .heap
                .get(object_id.0 as usize)
                .is_some_and(|object| object.is_array && object.prototype.is_none())
            {
                return Err(
                    "eager seed null array prototype must reference an array with no prototype"
                        .into(),
                );
            }
        }
        for object_id in &self.function_null_prototypes {
            if !self.function_objects.values().any(|id| id == object_id)
                || !self
                    .heap
                    .get(object_id.0 as usize)
                    .is_some_and(|object| object.prototype.is_none())
            {
                return Err(
                    "eager seed null function prototype must reference an object with no prototype"
                        .into(),
                );
            }
        }
        Ok(())
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunLoopMode {
    Normal,
    Generator,
    Async,
    AsyncGenerator,
}

#[derive(Debug)]
enum RunLoopExit {
    Value(LabeledReturn),
    AsyncAwait,
    AsyncGeneratorAwait {
        completion: LabeledReturn,
        kind: AsyncGeneratorAwaitKind,
    },
    AsyncThrow {
        exception: LabeledException,
    },
    GeneratorBodyStart,
    GeneratorYield {
        result: Value,
        label: crate::ifc_artifacts::Label,
        resume_dst: u32,
    },
    GeneratorReturn {
        value: Value,
        label: crate::ifc_artifacts::Label,
    },
    GeneratorThrow {
        exception: LabeledException,
        description: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum FunctionObjectKey {
    Function(u32),
    Closure(u32),
    Builtin(BuiltinFunctionKind),
}

#[derive(Debug, Clone)]
struct CallSetupRegisterSlotSnapshot {
    index: usize,
    value: Option<Value>,
    label: Option<crate::ifc_artifacts::Label>,
}

#[derive(Debug, Clone)]
struct CallSetupSnapshot {
    heap_len: usize,
    function_prototypes: Option<BTreeMap<FunctionObjectKey, ObjectId>>,
    call_stack_depth: usize,
    register_base: usize,
    ip: usize,
    registers_len: usize,
    register_labels_len: usize,
    callee_register_start: usize,
    callee_registers: Vec<Value>,
    callee_register_labels: Vec<crate::ifc_artifacts::Label>,
    result_register: Option<CallSetupRegisterSlotSnapshot>,
    async_functions_len: usize,
    profiling_memory_stats: Option<crate::profiling::MemoryStats>,
    estimated_memory_bytes: u64,
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

/// Executable reactions belong to a registration, not to the closure store:
/// callbacks may also be ordinary function-table entries or native callables.
/// The queue's handler handle selects the fulfillment (0) or rejection (1)
/// side of the registration keyed by its derived promise.
#[derive(Debug, Clone)]
enum PromiseReactionAction {
    Call(Value),
    Finally(Value),
    Forward(crate::promise_model::PromiseHandle),
    Combinator {
        combinator_id: u64,
        index: u32,
    },
    Restore {
        value: Value,
        rejected: bool,
        label: crate::ifc_artifacts::Label,
    },
}

#[derive(Debug, Clone)]
struct PromiseReactionRegistration {
    on_fulfilled: Option<PromiseReactionAction>,
    on_rejected: Option<PromiseReactionAction>,
}

/// Resolve and reject share this cell, even while adoption leaves the Promise
/// pending. A subsequent thenable job gets a fresh pair for the same Promise.
#[derive(Debug, Clone)]
struct PromiseResolvingFunctions {
    promise: crate::promise_model::PromiseHandle,
    already_resolved: bool,
    label: crate::ifc_artifacts::Label,
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
    /// Arrays whose implicit intrinsic prototype was explicitly removed.
    array_null_prototypes: BTreeSet<ObjectId>,
    /// Function backing objects whose implicit Function prototype was removed.
    function_null_prototypes: BTreeSet<ObjectId>,
    /// Active joins prevent recursive array stringification from recursing forever.
    array_join_stack: Vec<ObjectId>,
    /// Native-method buffers held while getters, setters or callbacks execute.
    array_method_temporary_bytes: u64,
    /// Interpreter-owned Symbol identities, descriptions, and global registry.
    symbol_state: RuntimeSymbolState,
    /// Approximate live memory tracked for fail-closed budget enforcement.
    estimated_memory_bytes: u64,
    /// Execution snapshots moved out while a generator activation is running.
    /// Nested generator calls accumulate here so allocation checks continue to
    /// account for every synchronously suspended caller.
    temporarily_suspended_execution_bytes: u64,
    /// Call depth represented by the same temporarily moved-out executions.
    /// Active depth checks add this to the installed activation's stack.
    temporarily_suspended_call_depth: usize,
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
    /// Non-forgeable concise-method identity and `[[HomeObject]]`, keyed by
    /// closure ID so independently evaluated method definitions never alias.
    closure_method_metadata: BTreeMap<u32, ClosureMethodMetadata>,
    /// Pending capture names for the next `CreateClosure` instruction.
    pending_captures: Vec<u32>,
    /// Generator object store.
    generators: Vec<GeneratorObject>,
    /// Async generator object store.
    async_generators: Vec<AsyncGeneratorObject>,
    /// Async function object store.
    async_functions: Vec<AsyncFunctionObject>,
    /// Pending await continuations, keyed by the Promise returned from the
    /// internal await reaction registration.
    async_resumption_contexts: BTreeMap<u32, AsyncResumptionContext>,
    /// Await continuations retaining the generator and front request identity.
    async_generator_continuations: BTreeMap<u32, AsyncGeneratorContinuation>,
    /// Promise store for ES2020 Promise semantics.
    promise_store: crate::promise_model::PromiseStore,
    /// Pending executable reactions, removed when their selected job runs.
    promise_reactions: BTreeMap<crate::promise_model::PromiseHandle, PromiseReactionRegistration>,
    /// Resolving functions may escape their executor and remain callable.
    promise_resolving_functions: BTreeMap<u32, PromiseResolvingFunctions>,
    /// Deterministic event loop state (microtasks + macrotasks + virtual clock).
    event_loop: crate::promise_model::EventLoop,
    /// Active promise combinator trackers keyed by combinator id.
    promise_combinators: BTreeMap<u64, LabeledPromiseCombinatorState>,
    /// Watchers keyed by promise handle for combinator updates.
    promise_combinator_watchers:
        BTreeMap<crate::promise_model::PromiseHandle, Vec<PromiseCombinatorWatcher>>,
    /// Monotonic combinator id generator.
    next_promise_combinator_id: u64,
    /// Macrotask payload ownership moved to a stack-local action during an
    /// event-loop turn remains physically live until the handler returns.
    /// Keep the released queue bytes charged during the transfer so nested
    /// Promise mutations observe one coherent runtime component (bd-ur3tk.21).
    promise_in_flight_task_bytes: u64,
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
    /// Callable values and captured arguments for scheduled one-shot timers.
    timer_invocations: BTreeMap<u64, TimerInvocation>,
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
    fn filesystem_module_specifier(value: &JsString) -> Result<&str, InterpreterError> {
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
            array_null_prototypes: BTreeSet::new(),
            function_null_prototypes: BTreeSet::new(),
            array_join_stack: Vec::new(),
            array_method_temporary_bytes: 0,
            symbol_state: RuntimeSymbolState::default(),
            estimated_memory_bytes: 0,
            temporarily_suspended_execution_bytes: 0,
            temporarily_suspended_call_depth: 0,
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
            closure_method_metadata: BTreeMap::new(),
            pending_captures: Vec::new(),
            generators: Vec::new(),
            async_generators: Vec::new(),
            async_functions: Vec::new(),
            async_resumption_contexts: BTreeMap::new(),
            async_generator_continuations: BTreeMap::new(),
            promise_store: crate::promise_model::PromiseStore::new(),
            promise_reactions: BTreeMap::new(),
            promise_resolving_functions: BTreeMap::new(),
            event_loop: crate::promise_model::EventLoop::new(),
            promise_combinators: BTreeMap::new(),
            promise_combinator_watchers: BTreeMap::new(),
            next_promise_combinator_id: 0,
            promise_in_flight_task_bytes: 0,
            module_state: ModuleState::new(),
            active_cjs_context: None,
            current_module_specifier: None,
            console_output: Vec::new(),
            profiling_data: None,
            next_timer_id: 0,
            active_timers: BTreeMap::new(),
            timer_invocations: BTreeMap::new(),
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
        completion: LabeledReturn,
        requested_hook_action: Option<HookAction>,
    ) -> ExecutionResult {
        let LabeledReturn { value, label } = completion;
        ExecutionResult {
            value,
            completion_label: label,
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
        crate::ir_contract::verify_ir3_specialization(module).map_err(|error| {
            InterpreterError::TypeError {
                expected: "supported, structurally valid core IR3 module".to_string(),
                got: error.to_string(),
            }
        })?;

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
        self.reset_execution_state_from_seed(&seed)?;
        self.sync_estimated_memory_bytes()?;
        let entry_specifier = module.header.source_label.clone();
        self.current_module_specifier = Some(entry_specifier.clone());
        self.ensure_module_record(module, &entry_specifier)?;

        self.push_event("execution_started", "ok", None);

        let mut result = self.run_loop_labeled(module);
        if result.is_err() {
            // CopyDataProperties continuations are internal to this execution.
            // A fresh execute() always restarts from its caller-visible seed,
            // so no failed/cancelled run may retain their snapshotted keys.
            self.discard_all_copy_data_properties_states();
        }

        // Drain any pending microtasks enqueued during execution
        // (promise reactions, thenable resolutions, etc.).
        if let Err(error) = self.drain_microtasks(Some(module)) {
            result = Err(error);
        }

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
                let completion_label = self
                    .read_reg_label(0)
                    .unwrap_or(crate::ifc_artifacts::Label::Public);
                self.emit_witness(WitnessEventKind::ExecutionCompleted, None);
                Ok(self.take_execution_result(
                    LabeledReturn {
                        value: final_value,
                        label: completion_label,
                    },
                    None,
                ))
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
            symbol_state: self.symbol_state.clone(),
            array_null_prototypes: self.array_null_prototypes.clone(),
            function_null_prototypes: self.function_null_prototypes.clone(),
        }
    }

    pub fn reset_execution_state_from_seed(
        &mut self,
        seed: &ExecutionSeed,
    ) -> Result<(), InterpreterError> {
        seed.validate_symbol_references()
            .and_then(|()| seed.validate_array_prototype_references())
            .map_err(|got| InterpreterError::TypeError {
                expected: "execution seed with resolved Symbol identities".to_string(),
                got,
            })?;
        self.register_base = 0;
        self.registers = seed.registers.clone();
        self.register_labels = seed.register_labels.clone();
        self.register_labels
            .resize(self.registers.len(), crate::ifc_artifacts::Label::Public);
        self.call_stack.clear();
        self.heap = seed.heap.clone();
        self.array_null_prototypes = seed.array_null_prototypes.clone();
        self.function_null_prototypes = seed.function_null_prototypes.clone();
        self.array_join_stack.clear();
        self.array_method_temporary_bytes = 0;
        self.symbol_state = seed.symbol_state.clone();
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
        self.temporarily_suspended_execution_bytes = 0;
        self.temporarily_suspended_call_depth = 0;
        self.module_state = ModuleState::new();
        self.active_cjs_context = None;
        self.current_module_specifier = None;
        self.promise_combinators.clear();
        self.promise_reactions.clear();
        self.promise_resolving_functions.clear();
        self.promise_combinator_watchers.clear();
        self.next_promise_combinator_id = 0;
        self.promise_in_flight_task_bytes = 0;
        self.active_timers.clear();
        self.timer_invocations.clear();
        self.next_timer_id = 0;
        self.async_resumption_contexts.clear();
        self.async_functions.clear();
        self.reset_async_generator_requests();
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        Ok(())
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
                property_labels: OrderedStringMap::new(),
                property_attributes: BTreeMap::new(),
                property_structure_label: None,
                accessors: std::collections::BTreeMap::new(),
                prototype: None,
                constructor_function: None,
                derived_constructor_parent: None,
                derived_constructor_parent_label: None,
                is_derived_constructor: false,
                is_default_derived_constructor: false,
                is_array: false,
            });
        }

        if let Some(heap_obj) = self.heap.get_mut(slot_idx) {
            let existed = heap_obj.contains_own_property("value");
            heap_obj.record_property_definition(&JsString::from("value"), existed);
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
            function_prototypes: self.function_prototypes.clone(),
            function_objects: self.function_objects.clone(),
            symbol_state: self.symbol_state.clone(),
            array_null_prototypes: self.array_null_prototypes.clone(),
            function_null_prototypes: self.function_null_prototypes.clone(),
        }
    }

    /// Reset from eager seed format for testing
    pub fn reset_execution_state_from_seed_eager_for_test(
        &mut self,
        seed: &EagerExecutionSeed,
    ) -> Result<(), InterpreterError> {
        seed.validate_symbol_references()
            .map_err(|got| InterpreterError::TypeError {
                expected: "eager execution seed with resolved Symbol identities".to_string(),
                got,
            })?;
        self.registers = seed.registers.clone();
        self.heap = seed.heap.clone();
        self.function_prototypes = seed.function_prototypes.clone();
        self.function_objects = seed.function_objects.clone();
        self.array_null_prototypes = seed.array_null_prototypes.clone();
        self.function_null_prototypes = seed.function_null_prototypes.clone();
        self.array_join_stack.clear();
        self.array_method_temporary_bytes = 0;
        self.symbol_state = seed.symbol_state.clone();

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
        self.temporarily_suspended_execution_bytes = 0;
        self.temporarily_suspended_call_depth = 0;
        self.module_state = ModuleState::new();
        self.active_cjs_context = None;
        self.current_module_specifier = None;
        self.promise_combinators.clear();
        self.promise_reactions.clear();
        self.promise_resolving_functions.clear();
        self.promise_combinator_watchers.clear();
        self.next_promise_combinator_id = 0;
        self.promise_in_flight_task_bytes = 0;
        self.active_timers.clear();
        self.timer_invocations.clear();
        self.next_timer_id = 0;
        self.async_resumption_contexts.clear();
        self.async_functions.clear();
        self.reset_async_generator_requests();
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        Ok(())
    }

    #[cfg(test)]
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

    /// Move the currently installed execution context out of the interpreter.
    /// Heap objects, closures, generator tables, budgets, and witness streams
    /// remain shared; only frame-local execution state is transferred.
    fn take_module_execution(&mut self) -> ModuleExecutionSnapshot {
        ModuleExecutionSnapshot {
            registers: std::mem::take(&mut self.registers),
            register_labels: std::mem::take(&mut self.register_labels),
            call_stack: std::mem::take(&mut self.call_stack),
            ip: std::mem::take(&mut self.ip),
            register_base: std::mem::take(&mut self.register_base),
            catch_frames: std::mem::take(&mut self.catch_frames),
            pending_exception: self.pending_exception.take(),
            pending_return: self.pending_return.take(),
            suspended_abrupt_completions: std::mem::take(&mut self.suspended_abrupt_completions),
            finally_frames: std::mem::take(&mut self.finally_frames),
            pending_finally_entry: self.pending_finally_entry.take(),
            copy_data_properties_states: std::mem::take(&mut self.copy_data_properties_states),
            scope_chain: std::mem::replace(&mut self.scope_chain, ScopeChain::new()),
            pending_captures: std::mem::take(&mut self.pending_captures),
            current_module_specifier: self.current_module_specifier.take(),
        }
    }

    fn install_module_execution(&mut self, snapshot: ModuleExecutionSnapshot) {
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
    }

    fn restore_module_execution(&mut self, snapshot: ModuleExecutionSnapshot) {
        self.install_module_execution(snapshot);
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
        preserve_resolved_bindings: bool,
    ) -> Result<(), InterpreterError> {
        let (filename_value, dirname_value) = self
            .cjs_filename_dirname(module_specifier.or(self.current_module_specifier.as_deref()));
        let require_value = Value::BuiltinFunction(BuiltinFunction::require(
            module_specifier.unwrap_or_default(),
        ));

        let mut replaced = Vec::with_capacity(5);
        for (name, value) in [
            ("require", require_value),
            ("exports", Value::Object(exports_object)),
            ("module", Value::Object(module_object)),
            ("__filename", filename_value),
            ("__dirname", dirname_value),
        ] {
            if preserve_resolved_bindings && self.scope_chain.resolve(name).is_some() {
                continue;
            }
            let name = name.to_string();
            {
                let frame = self.scope_chain.current_mut();
                let replaced_binding = frame.declare(name.clone(), BindingKind::Var);
                let replaced_state = replaced_binding
                    .as_ref()
                    .map(ScopeBinding::snapshot_state)
                    .transpose()?;
                if let Some(binding) = frame.get(&name) {
                    let mut state = binding.state_mut()?;
                    state.value = value;
                    state.label = crate::ifc_artifacts::Label::Public;
                    state.initialized = true;
                }
                replaced.push((name, replaced_binding, replaced_state));
            }
        }
        if let Err(err) = self.sync_estimated_memory_bytes() {
            let current = self.scope_chain.current_mut();
            for (name, old, old_state) in replaced {
                if let Some(old_binding) = old {
                    if let Some(old_state) = old_state {
                        old_binding.restore_state(old_state)?;
                    }
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
            true,
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
                compiled_module: None,
                retained_program_bytes: 0,
            },
        );
        Ok(namespace_object)
    }

    /// Resolve a closure's executable owner. Never interpret a module-local
    /// function index using an importing module's unrelated function table.
    fn callable_module(&self, callee: &Value) -> Result<Option<Rc<Ir3Module>>, InterpreterError> {
        let closure_id = match callee {
            Value::Closure(id)
            | Value::GeneratorFunction(id)
            | Value::AsyncFunction(id)
            | Value::AsyncGeneratorFunction(id) => *id,
            _ => return Ok(None),
        };
        let closure =
            self.closures
                .get(closure_id as usize)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "valid closure".to_string(),
                    got: format!("closure#{closure_id} not found"),
                })?;
        let Some(owner) = closure.module_specifier.as_deref() else {
            // Public hand-built IR can supply module-local function values.
            return Ok(None);
        };
        self.module_state
            .modules
            .get(owner)
            .and_then(|record| record.compiled_module.clone())
            .map(Some)
            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                specifier: owner.to_string(),
                reason: "closure executable owner is not retained".to_string(),
            })
    }

    fn retained_module_program_bytes(module: &Ir3Module) -> u64 {
        let instructions = module.instructions.iter().fold(
            (module.instructions.len() as u64)
                .saturating_mul(std::mem::size_of::<Ir3Instruction>() as u64),
            |bytes, instruction| {
                bytes.saturating_add(match instruction {
                    Ir3Instruction::HostCall { capability, .. } => {
                        Self::estimate_string_bytes(&capability.0)
                    }
                    _ => 0,
                })
            },
        );
        let constants = module.constant_pool.iter().fold(
            (module.constant_pool.len() as u64)
                .saturating_mul(std::mem::size_of::<JsString>() as u64),
            |bytes, value| bytes.saturating_add(Self::estimate_js_string_bytes(value)),
        );
        let functions = module.function_table.iter().fold(
            (module.function_table.len() as u64)
                .saturating_mul(std::mem::size_of::<crate::ir_contract::Ir3FunctionDesc>() as u64),
            |bytes, function| {
                bytes.saturating_add(
                    function
                        .name
                        .as_deref()
                        .map(Self::estimate_string_bytes)
                        .unwrap_or(0),
                )
            },
        );
        let capabilities = module.required_capabilities.iter().fold(
            (module.required_capabilities.len() as u64)
                .saturating_mul(std::mem::size_of::<crate::ir_contract::CapabilityTag>() as u64),
            |bytes, capability| bytes.saturating_add(Self::estimate_string_bytes(&capability.0)),
        );
        let specialization = module.specialization.as_ref().map_or(0, |linkage| {
            linkage.proof_input_ids.iter().fold(
                Self::estimate_string_bytes(&linkage.optimization_class).saturating_add(
                    (linkage.proof_input_ids.len() as u64)
                        .saturating_mul(std::mem::size_of::<String>() as u64),
                ),
                |bytes, proof| bytes.saturating_add(Self::estimate_string_bytes(proof)),
            )
        });
        (std::mem::size_of::<Ir3Module>() as u64)
            .saturating_add(std::mem::size_of::<[usize; 2]>() as u64)
            .saturating_add(Self::estimate_string_bytes(&module.header.source_label))
            .saturating_add(instructions)
            .saturating_add(constants)
            .saturating_add(functions)
            .saturating_add(capabilities)
            .saturating_add(specialization)
    }

    /// Retain code only when an executable closure needs it. This avoids
    /// cloning a module for every function and leaves pure borrowed-IR runs
    /// free of a redundant program copy. Admission precedes allocation.
    fn retain_current_module_program(
        &mut self,
        module: &Ir3Module,
    ) -> Result<(), InterpreterError> {
        let Some(specifier) = self.current_module_specifier.as_deref() else {
            return Ok(());
        };
        let Some(record) = self.module_state.modules.get(specifier) else {
            return Ok(());
        };
        if record.compiled_module.is_some() {
            return Ok(());
        }
        let bytes = Self::retained_module_program_bytes(module);
        self.check_temporary_memory_budget(bytes)?;
        let program = Rc::new(module.clone());
        let record = self
            .module_state
            .modules
            .get_mut(specifier)
            .expect("validated module");
        record.compiled_module = Some(program);
        record.retained_program_bytes = bytes;
        self.module_state.retained_program_bytes = self
            .module_state
            .retained_program_bytes
            .saturating_add(bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(bytes);
        Ok(())
    }

    /// A refused closure allocation must not leave newly retained code behind.
    fn release_unused_current_module_program(&mut self) {
        let Some(specifier) = self.current_module_specifier.as_deref() else {
            return;
        };
        if self
            .closures
            .iter()
            .any(|closure| closure.module_specifier.as_deref() == Some(specifier))
        {
            return;
        }
        if let Some(record) = self.module_state.modules.get_mut(specifier) {
            record.compiled_module = None;
            self.module_state.retained_program_bytes = self
                .module_state
                .retained_program_bytes
                .saturating_sub(std::mem::take(&mut record.retained_program_bytes));
        }
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
            false,
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
                .own_exact_property_keys()
                .into_iter()
                .filter_map(|key| {
                    object
                        .properties
                        .get_exact(&key)
                        .cloned()
                        .map(|value| (key, value))
                })
                .collect::<Vec<_>>();
            for (key, value) in properties {
                if key.as_str() == Some("default") {
                    continue;
                }
                self.register_module_export_exact(key, value)?;
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

        // Publish a cycle-visible record only when preparation has succeeded.
        // Read, parse, and lowering failures must not leave an `Evaluating`
        // record that a subsequent load mistakes for an active cyclic import.
        // Evaluation still publishes before executing any module code, so
        // CommonJS cycles can observe the same partially initialized exports.
        let namespace_object = self.ensure_module_record(module, resolved)?;
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
        specifier: &JsString,
    ) -> Result<Value, InterpreterError> {
        let specifier = Self::filesystem_module_specifier(specifier)?;
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
        specifier: &JsString,
    ) -> Result<Value, InterpreterError> {
        let specifier = Self::filesystem_module_specifier(specifier)?;
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
        receiver_label: crate::ifc_artifacts::Label,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        let result = match builtin.kind {
            BuiltinFunctionKind::ObjectDefineProperty
            | BuiltinFunctionKind::ObjectGetOwnPropertyDescriptor
            | BuiltinFunctionKind::ReflectDefineProperty => {
                return self.dispatch_descriptor_builtin(
                    module,
                    builtin.kind,
                    args,
                    receiver_label,
                );
            }
            BuiltinFunctionKind::FunctionPrototypeCall
            | BuiltinFunctionKind::FunctionPrototypeApply => {
                return self.dispatch_function_method(
                    module,
                    builtin.kind,
                    receiver,
                    args,
                    receiver_label,
                );
            }
            BuiltinFunctionKind::StringPrototypeIndexOf
            | BuiltinFunctionKind::StringPrototypeLastIndexOf
            | BuiltinFunctionKind::StringPrototypeIncludes
            | BuiltinFunctionKind::StringPrototypeStartsWith
            | BuiltinFunctionKind::StringPrototypeEndsWith
            | BuiltinFunctionKind::StringPrototypeSlice
            | BuiltinFunctionKind::StringPrototypeSubstring => {
                return self.dispatch_string_method(
                    module,
                    builtin.kind,
                    receiver,
                    args,
                    receiver_label,
                );
            }
            BuiltinFunctionKind::ArrayPrototypePush
            | BuiltinFunctionKind::ArrayPrototypePop
            | BuiltinFunctionKind::ArrayPrototypeJoin
            | BuiltinFunctionKind::ArrayPrototypeMap
            | BuiltinFunctionKind::ArrayPrototypeFilter
            | BuiltinFunctionKind::ArrayPrototypeForEach
            | BuiltinFunctionKind::ArrayPrototypeSome
            | BuiltinFunctionKind::ArrayPrototypeEvery
            | BuiltinFunctionKind::ArrayPrototypeFind
            | BuiltinFunctionKind::ArrayPrototypeFindIndex
            | BuiltinFunctionKind::ArrayPrototypeReduce
            | BuiltinFunctionKind::ArrayPrototypeReduceRight => {
                return self.dispatch_array_method(
                    module,
                    builtin.kind,
                    receiver,
                    args,
                    receiver_label,
                );
            }
            BuiltinFunctionKind::Require => {
                check_module_load_capability_gate(self, self.ip as u32)?;
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
            BuiltinFunctionKind::ArrayIsArray => {
                let arg = if args.count > 0 {
                    Some(self.read_reg(args.start)?)
                } else {
                    None
                };
                self.array_is_array_value(arg)
            }
            BuiltinFunctionKind::Symbol => {
                let description = if args.count > 0 {
                    self.symbol_description_argument(Some(self.read_reg(args.start)?))?
                } else {
                    None
                };
                self.allocate_private_symbol(description).map(Value::Symbol)
            }
            BuiltinFunctionKind::SymbolFor => {
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let key = self.symbol_registry_key_argument(value)?;
                self.intern_global_symbol(key).map(Value::Symbol)
            }
            BuiltinFunctionKind::SymbolKeyFor => {
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let Value::Symbol(symbol) = value else {
                    return Err(InterpreterError::TypeError {
                        expected: "Symbol".to_string(),
                        got: value.type_name().to_string(),
                    });
                };
                Ok(self
                    .symbol_state
                    .key_for(symbol)
                    .cloned()
                    .map(Value::Str)
                    .unwrap_or(Value::Undefined))
            }
            BuiltinFunctionKind::SymbolPrototypeToString => {
                let Some(Value::Symbol(symbol)) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "Symbol receiver".to_string(),
                        got: receiver.map_or("undefined", Value::type_name).to_string(),
                    });
                };
                Ok(Value::Str(self.symbol_to_string(*symbol)))
            }
            BuiltinFunctionKind::GeneratorPrototypeNext => {
                let Some(Value::Generator(generator_id)) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "Generator receiver".to_string(),
                        got: receiver.map_or("undefined", Value::type_name).to_string(),
                    });
                };
                let argument = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let argument_label = if args.count > 0 {
                    self.read_reg_label(args.start)?
                } else {
                    crate::ifc_artifacts::Label::Public
                };
                return self.generator_next(module, *generator_id, argument, argument_label);
            }
            BuiltinFunctionKind::AsyncGeneratorPrototypeNext
            | BuiltinFunctionKind::AsyncGeneratorPrototypeReturn
            | BuiltinFunctionKind::AsyncGeneratorPrototypeThrow => {
                let Some(Value::AsyncGeneratorObject(generator_id)) = receiver else {
                    let promise = self.create_promise_accounted()?;
                    let error = InterpreterError::TypeError {
                        expected: "AsyncGenerator receiver".into(),
                        got: receiver.map_or("undefined", Value::type_name).into(),
                    };
                    let reason = self.promise_error_value(&error)?;
                    self.reject_promise(
                        promise,
                        Self::value_to_js_value(&reason),
                        receiver_label.clone(),
                    )?;
                    return Ok((Value::Promise(promise.0), receiver_label));
                };
                let (argument, argument_label) = self.promise_hostcall_argument(args, 0)?;
                let label = receiver_label.join(&argument_label);
                let value = if builtin.kind == BuiltinFunctionKind::AsyncGeneratorPrototypeNext {
                    self.async_generator_next(module, *generator_id, argument, label.clone())?
                } else {
                    let kind = if builtin.kind == BuiltinFunctionKind::AsyncGeneratorPrototypeReturn
                    {
                        AsyncGeneratorResumeKind::Return
                    } else {
                        AsyncGeneratorResumeKind::Throw
                    };
                    self.enqueue_async_generator_request(
                        *generator_id,
                        kind,
                        argument,
                        label.clone(),
                    )?
                };
                return Ok((value, label));
            }
            BuiltinFunctionKind::AsyncIteratorPrototypeAsyncIterator => {
                return Ok((
                    receiver.cloned().unwrap_or(Value::Undefined),
                    receiver_label,
                ));
            }
            BuiltinFunctionKind::PromiseCapabilityResolve
            | BuiltinFunctionKind::PromiseCapabilityReject => {
                let handle_id =
                    builtin
                        .bound_object
                        .ok_or_else(|| InterpreterError::TypeError {
                            expected: "bound promise capability".to_string(),
                            got: "unbound promise capability function".to_string(),
                        })?;
                let is_resolve = builtin.kind == BuiltinFunctionKind::PromiseCapabilityResolve;
                let value = self.apply_promise_capability(
                    crate::promise_model::PromiseHandle(handle_id),
                    args,
                    is_resolve,
                )?;
                return Ok((value, crate::ifc_artifacts::Label::Public));
            }
            BuiltinFunctionKind::PromisePrototypeThen
            | BuiltinFunctionKind::PromisePrototypeCatch
            | BuiltinFunctionKind::PromisePrototypeFinally => {
                let Some(Value::Promise(handle)) = receiver else {
                    return Err(InterpreterError::TypeError {
                        expected: "Promise receiver".to_string(),
                        got: receiver.map_or("undefined", Value::type_name).to_string(),
                    });
                };
                let handle = crate::promise_model::PromiseHandle(*handle);
                let source_label = self
                    .promise_store
                    .get(handle)
                    .map_err(|error| InterpreterError::TypeError {
                        expected: "valid Promise receiver".to_string(),
                        got: error.to_string(),
                    })?
                    .label
                    .clone();
                let label = receiver_label
                    .join(&source_label)
                    .join(&self.promise_hostcall_registration_label(args)?);
                let (first, _) = self.promise_hostcall_argument(args, 0)?;
                let (second, _) = self.promise_hostcall_argument(args, 1)?;
                let capability = match builtin.kind {
                    BuiltinFunctionKind::PromisePrototypeThen => "promise:then",
                    BuiltinFunctionKind::PromisePrototypeCatch => "promise:catch",
                    _ => "promise:finally",
                };
                return self.register_promise_method(handle, capability, first, second, label);
            }
            BuiltinFunctionKind::PromiseResolveFunction
            | BuiltinFunctionKind::PromiseRejectFunction => {
                let pair_id = builtin
                    .bound_object
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "bound Promise resolving function".to_string(),
                        got: "unbound Promise resolving function".to_string(),
                    })?;
                let (argument, label) = self.promise_hostcall_argument(args, 0)?;
                self.apply_promise_resolving_function(
                    pair_id,
                    argument,
                    label,
                    builtin.kind == BuiltinFunctionKind::PromiseResolveFunction,
                )?;
                return Ok((Value::Undefined, crate::ifc_artifacts::Label::Public));
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
                match builtin.kind {
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
                        Ok(Self::string_is_well_formed_value(&text))
                    }
                    BuiltinFunctionKind::StringPrototypeToWellFormed => {
                        Ok(Self::string_to_well_formed_value(&text))
                    }
                    BuiltinFunctionKind::Require
                    | BuiltinFunctionKind::ArrayIsArray
                    | BuiltinFunctionKind::Symbol
                    | BuiltinFunctionKind::SymbolFor
                    | BuiltinFunctionKind::SymbolKeyFor
                    | BuiltinFunctionKind::SymbolPrototypeToString
                    | BuiltinFunctionKind::GeneratorPrototypeNext
                    | BuiltinFunctionKind::PromiseCapabilityResolve
                    | BuiltinFunctionKind::PromiseCapabilityReject
                    | BuiltinFunctionKind::PromisePrototypeThen
                    | BuiltinFunctionKind::PromisePrototypeCatch
                    | BuiltinFunctionKind::PromisePrototypeFinally
                    | BuiltinFunctionKind::PromiseResolveFunction
                    | BuiltinFunctionKind::PromiseRejectFunction
                    | BuiltinFunctionKind::AsyncGeneratorPrototypeNext
                    | BuiltinFunctionKind::AsyncGeneratorPrototypeReturn
                    | BuiltinFunctionKind::AsyncGeneratorPrototypeThrow
                    | BuiltinFunctionKind::AsyncIteratorPrototypeAsyncIterator
                    | BuiltinFunctionKind::ArrayPrototypePush
                    | BuiltinFunctionKind::ArrayPrototypePop
                    | BuiltinFunctionKind::ArrayPrototypeJoin
                    | BuiltinFunctionKind::ArrayPrototypeMap
                    | BuiltinFunctionKind::ArrayPrototypeFilter
                    | BuiltinFunctionKind::ArrayPrototypeForEach
                    | BuiltinFunctionKind::ArrayPrototypeSome
                    | BuiltinFunctionKind::ArrayPrototypeEvery
                    | BuiltinFunctionKind::ArrayPrototypeFind
                    | BuiltinFunctionKind::ArrayPrototypeFindIndex
                    | BuiltinFunctionKind::ArrayPrototypeReduce
                    | BuiltinFunctionKind::ArrayPrototypeReduceRight
                    | BuiltinFunctionKind::StringPrototypeIndexOf
                    | BuiltinFunctionKind::StringPrototypeLastIndexOf
                    | BuiltinFunctionKind::StringPrototypeIncludes
                    | BuiltinFunctionKind::StringPrototypeStartsWith
                    | BuiltinFunctionKind::StringPrototypeEndsWith
                    | BuiltinFunctionKind::StringPrototypeSlice
                    | BuiltinFunctionKind::StringPrototypeSubstring
                    | BuiltinFunctionKind::FunctionPrototypeCall
                    | BuiltinFunctionKind::FunctionPrototypeApply
                    | BuiltinFunctionKind::ObjectDefineProperty
                    | BuiltinFunctionKind::ObjectGetOwnPropertyDescriptor
                    | BuiltinFunctionKind::ReflectDefineProperty => {
                        unreachable!("handled above")
                    }
                }
            }
        };
        result.map(|value| (value, crate::ifc_artifacts::Label::Public))
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

    fn symbol_description_argument(
        &self,
        value: Option<Value>,
    ) -> Result<Option<JsString>, InterpreterError> {
        match value {
            None | Some(Value::Undefined) => Ok(None),
            Some(Value::Str(text)) => Ok(Some(text)),
            Some(Value::Symbol(_)) => Err(InterpreterError::TypeError {
                expected: "Symbol description coercible to string".to_string(),
                got: "symbol".to_string(),
            }),
            Some(value) => Ok(Some(JsString::from(self.value_to_string(&value)))),
        }
    }

    fn symbol_registry_key_argument(&self, value: Value) -> Result<JsString, InterpreterError> {
        match value {
            Value::Str(text) => Ok(text),
            Value::Symbol(_) => Err(InterpreterError::TypeError {
                expected: "Symbol.for key coercible to string".to_string(),
                got: "symbol".to_string(),
            }),
            value => Ok(JsString::from(self.value_to_string(&value))),
        }
    }

    fn allocate_private_symbol(
        &mut self,
        description: Option<JsString>,
    ) -> Result<SymbolId, InterpreterError> {
        let previous = self.symbol_state.clone();
        let previous_memory = self.estimated_memory_bytes;
        let symbol = self.symbol_state.allocate_private(description)?;
        if let Err(err) = self.sync_estimated_memory_bytes() {
            self.symbol_state = previous;
            self.estimated_memory_bytes = previous_memory;
            return Err(err);
        }
        Ok(symbol)
    }

    fn intern_global_symbol(&mut self, key: JsString) -> Result<SymbolId, InterpreterError> {
        let previous = self.symbol_state.clone();
        let previous_memory = self.estimated_memory_bytes;
        let symbol = self.symbol_state.intern_global(key)?;
        if let Err(err) = self.sync_estimated_memory_bytes() {
            self.symbol_state = previous;
            self.estimated_memory_bytes = previous_memory;
            return Err(err);
        }
        Ok(symbol)
    }

    fn symbol_to_string(&self, symbol: SymbolId) -> JsString {
        let prefix = JsString::from("Symbol(");
        let suffix = JsString::from(")");
        match self.symbol_description(symbol) {
            Some(description) => prefix.concat(&description).concat(&suffix),
            None => prefix.concat(&suffix),
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
    fn string_index_as_integer(value: &Value) -> Result<i64, InterpreterError> {
        Ok(match value {
            Value::Symbol(_) => {
                return Err(InterpreterError::TypeError {
                    expected: "string index coercible to number".to_string(),
                    got: "symbol".to_string(),
                });
            }
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
        })
    }

    /// `String.prototype.charAt`: the single UTF-16 code unit at `index`. A
    /// surrogate half stays a real lone-surrogate string value; out-of-range
    /// or negative indices yield the empty string.
    fn string_char_at_value(
        text: &JsString,
        index: Option<&Value>,
    ) -> Result<Value, InterpreterError> {
        let index = index
            .map(Self::string_index_as_integer)
            .transpose()?
            .unwrap_or(0);
        if index < 0 {
            return Ok(Value::str(""));
        }
        Ok(match text.encode_utf16().nth(index as usize) {
            Some(unit) => Value::Str(JsString::from_code_units(&[unit])),
            None => Value::str(""),
        })
    }

    /// `String.prototype.charCodeAt`: the exact code unit as an integer, or
    /// `NaN` when out of range.
    fn string_char_code_at_value(
        text: &JsString,
        index: Option<&Value>,
    ) -> Result<Value, InterpreterError> {
        let index = index
            .map(Self::string_index_as_integer)
            .transpose()?
            .unwrap_or(0);
        if index < 0 {
            return Ok(Value::Float(Float64::new(f64::NAN)));
        }
        Ok(match text.encode_utf16().nth(index as usize) {
            Some(unit) => Value::Int(i64::from(unit)),
            None => Value::Float(Float64::new(f64::NAN)),
        })
    }

    /// `String.prototype.codePointAt`: UTF-16 code-unit indexed per ES2015
    /// CodePointAt (a valid pair combines, an unpaired surrogate yields its
    /// own unit value), matching the engine seams upgraded by bd-rdnhc so
    /// the differential oracle agrees; out-of-range / negative yields
    /// undefined.
    fn string_code_point_at_value(
        text: &JsString,
        index: Option<&Value>,
    ) -> Result<Value, InterpreterError> {
        let index = index
            .map(Self::string_index_as_integer)
            .transpose()?
            .unwrap_or(0);
        if index < 0 {
            return Ok(Value::Undefined);
        }
        Ok(match text.code_point_at(index as usize) {
            Some(code_point) => Value::Int(i64::from(code_point)),
            None => Value::Undefined,
        })
    }

    /// `String.prototype.at`: relative code-unit indexing (negative counts
    /// from the end); out-of-range yields undefined.
    fn string_at_value(text: &JsString, index: Option<&Value>) -> Result<Value, InterpreterError> {
        let units: Vec<u16> = text.code_units_vec();
        let len = units.len() as i64;
        let raw = index
            .map(Self::string_index_as_integer)
            .transpose()?
            .unwrap_or(0);
        let idx = if raw < 0 { raw + len } else { raw };
        if idx < 0 || idx >= len {
            return Ok(Value::Undefined);
        }
        Ok(Value::Str(JsString::from_code_units(
            &[units[idx as usize]],
        )))
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
            "indexOf" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeIndexOf,
            ))),
            "lastIndexOf" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeLastIndexOf,
            ))),
            "includes" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeIncludes,
            ))),
            "startsWith" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeStartsWith,
            ))),
            "endsWith" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeEndsWith,
            ))),
            "slice" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeSlice,
            ))),
            "substring" => Some(Value::BuiltinFunction(BuiltinFunction::string_method(
                BuiltinFunctionKind::StringPrototypeSubstring,
            ))),
            _ => canonical_array_index(key)
                .and_then(|index| text.encode_utf16().nth(index as usize))
                .map(|unit| Value::Str(JsString::from_code_units(&[unit]))),
        }
    }

    fn symbol_property_value(&self, symbol: SymbolId, key: &RuntimePropertyKey) -> Option<Value> {
        let RuntimePropertyKey::String(key) = key else {
            return None;
        };
        match key.as_str()? {
            "description" => Some(
                self.symbol_description(symbol)
                    .map(Value::Str)
                    .unwrap_or(Value::Undefined),
            ),
            "toString" => Some(Value::BuiltinFunction(BuiltinFunction::symbol(
                BuiltinFunctionKind::SymbolPrototypeToString,
            ))),
            _ => None,
        }
    }

    fn symbol_constructor_property_value(key: &str) -> Option<Value> {
        let builtin = |kind| Value::BuiltinFunction(BuiltinFunction::symbol(kind));
        Some(match key {
            "for" => builtin(BuiltinFunctionKind::SymbolFor),
            "keyFor" => builtin(BuiltinFunctionKind::SymbolKeyFor),
            "iterator" => Value::Symbol(WellKnownSymbol::Iterator.id()),
            "toPrimitive" => Value::Symbol(WellKnownSymbol::ToPrimitive.id()),
            "hasInstance" => Value::Symbol(WellKnownSymbol::HasInstance.id()),
            "toStringTag" => Value::Symbol(WellKnownSymbol::ToStringTag.id()),
            "species" => Value::Symbol(WellKnownSymbol::Species.id()),
            "isConcatSpreadable" => Value::Symbol(WellKnownSymbol::IsConcatSpreadable.id()),
            "unscopables" => Value::Symbol(WellKnownSymbol::Unscopables.id()),
            "asyncIterator" => Value::Symbol(WellKnownSymbol::AsyncIterator.id()),
            "match" => Value::Symbol(WellKnownSymbol::Match.id()),
            "matchAll" => Value::Symbol(WellKnownSymbol::MatchAll.id()),
            "replace" => Value::Symbol(WellKnownSymbol::Replace.id()),
            "search" => Value::Symbol(WellKnownSymbol::Search.id()),
            "split" => Value::Symbol(WellKnownSymbol::Split.id()),
            _ => return None,
        })
    }

    fn validate_runtime_property_key(
        &self,
        key: &TypedPropertyKey,
    ) -> Result<(), InterpreterError> {
        if let TypedPropertyKey::Symbol(symbol) = key
            && !self.symbol_state.contains(*symbol)
        {
            return Err(InterpreterError::TypeError {
                expected: "resolved Symbol property key".to_string(),
                got: format!("unresolved Symbol id {}", symbol.0),
            });
        }
        Ok(())
    }

    fn validate_executable_property_key(
        &self,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        if let RuntimePropertyKey::Symbol(symbol) = key
            && !self.symbol_state.contains(*symbol)
        {
            return Err(InterpreterError::TypeError {
                expected: "resolved Symbol property key".to_string(),
                got: format!("unresolved Symbol id {}", symbol.0),
            });
        }
        Ok(())
    }

    fn evaluate_module_ir3(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        let snapshot = self.take_module_execution();
        let previous_suspended_bytes = self.temporarily_suspended_execution_bytes;
        let previous_suspended_depth = self.temporarily_suspended_call_depth;
        self.temporarily_suspended_execution_bytes = previous_suspended_bytes
            .saturating_add(Self::estimate_module_execution_bytes(&snapshot));
        self.temporarily_suspended_call_depth =
            previous_suspended_depth.saturating_add(snapshot.call_stack.len());
        let previous_cjs_context = self.active_cjs_context.take();
        if let Err(err) = self.prepare_module_execution(specifier) {
            self.active_cjs_context = previous_cjs_context;
            self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
            self.temporarily_suspended_call_depth = previous_suspended_depth;
            self.restore_module_execution(snapshot);
            return Err(err);
        }
        let result = self.run_loop(module);
        let microtask_result = self.drain_microtasks(Some(module));
        self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
        self.temporarily_suspended_call_depth = previous_suspended_depth;
        self.restore_module_execution(snapshot);
        self.active_cjs_context = previous_cjs_context;
        match result {
            Ok(_) | Err(InterpreterError::Halted) => microtask_result,
            Err(err) => Err(err),
        }
    }

    fn evaluate_cjs_ir3(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
    ) -> Result<(), InterpreterError> {
        let snapshot = self.take_module_execution();
        let previous_suspended_bytes = self.temporarily_suspended_execution_bytes;
        let previous_suspended_depth = self.temporarily_suspended_call_depth;
        self.temporarily_suspended_execution_bytes = previous_suspended_bytes
            .saturating_add(Self::estimate_module_execution_bytes(&snapshot));
        self.temporarily_suspended_call_depth =
            previous_suspended_depth.saturating_add(snapshot.call_stack.len());
        let previous_cjs_context = self.active_cjs_context.take();
        // A cached module can require a child long after its top-level
        // evaluation has finished. The executing callable's owner remains
        // the parent even when there is no active CommonJS evaluation.
        let parent_module_object = snapshot
            .current_module_specifier
            .as_deref()
            .and_then(|owner| self.module_state.modules.get(owner))
            .and_then(|record| record.cjs_module_object)
            .or_else(|| {
                previous_cjs_context
                    .as_ref()
                    .map(|context| context.module_object)
            });
        if let Err(err) = self.prepare_module_execution(specifier) {
            self.active_cjs_context = previous_cjs_context;
            self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
            self.temporarily_suspended_call_depth = previous_suspended_depth;
            self.restore_module_execution(snapshot);
            return Err(err);
        }
        let cjs_context = match self.init_cjs_environment(module, specifier, parent_module_object) {
            Ok(context) => context,
            Err(err) => {
                self.active_cjs_context = previous_cjs_context;
                self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
                self.temporarily_suspended_call_depth = previous_suspended_depth;
                self.restore_module_execution(snapshot);
                return Err(err);
            }
        };
        if let Some(record) = self.module_state.modules.get_mut(specifier) {
            record.cjs_module_object = Some(cjs_context.module_object);
        }
        self.active_cjs_context = Some(cjs_context.clone());
        let result = self.run_loop(module);
        let microtask_result = self.drain_microtasks(Some(module));
        let eval_outcome = match result {
            Ok(_) | Err(InterpreterError::Halted) => microtask_result,
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
        self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
        self.temporarily_suspended_call_depth = previous_suspended_depth;
        self.restore_module_execution(snapshot);
        self.active_cjs_context = previous_cjs_context;
        eval_outcome.and(finalize_outcome).and(loaded_outcome)
    }

    fn register_module_export(&mut self, name: &str, value: Value) -> Result<(), InterpreterError> {
        self.register_module_export_exact(JsString::from(name), value)
    }

    fn register_module_export_exact(
        &mut self,
        name: JsString,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let diagnostic_name = name.to_string();
        let Some(specifier) = self.current_module_specifier.clone() else {
            return Err(InterpreterError::ExportOutsideModule {
                name: diagnostic_name,
            });
        };
        let namespace_object = {
            let record = self
                .module_state
                .modules
                .get_mut(&specifier)
                .ok_or_else(|| InterpreterError::ExportOutsideModule {
                    name: diagnostic_name.clone(),
                })?;
            record.exports.insert(name.clone(), value.clone());
            record.namespace_object
        };
        self.set_object_runtime_property(
            namespace_object,
            RuntimePropertyKey::String(name),
            value,
        )?;
        Ok(())
    }

    fn prepare_async_function_activation(
        &mut self,
        module: &Ir3Module,
        setup: AsyncCallSetup,
    ) -> Result<u32, InterpreterError> {
        self.ensure_call_depth_available()?;
        let _ = self.read_reg(setup.result_register)?;
        let register_storage_bytes = u64::from(self.config.max_registers).saturating_mul(
            (std::mem::size_of::<Value>() + std::mem::size_of::<crate::ifc_artifacts::Label>())
                as u64,
        );
        self.check_temporary_memory_budget(
            register_storage_bytes
                .saturating_add(std::mem::size_of::<CallFrame>() as u64)
                .saturating_add(std::mem::size_of::<ScopeFrame>() as u64)
                .saturating_add(std::mem::size_of::<AsyncFunctionObject>() as u64),
        )?;
        let async_id =
            u32::try_from(self.async_functions.len()).map_err(|_| InterpreterError::TypeError {
                expected: "async function table capacity".into(),
                got: "exhausted async function identities".into(),
            })?;
        let mut scope_chain = ScopeChain {
            frames: match setup.captured_env {
                Some(frames) => frames,
                None => self.snapshot_scope_chain()?,
            },
        };
        let saved_scope_depth = scope_chain.depth();
        scope_chain.push(self.config.max_scope_depth)?;
        let mut registers = vec![Value::Undefined; self.config.max_registers as usize];
        let mut register_labels =
            vec![crate::ifc_artifacts::Label::Public; self.config.max_registers as usize];
        for (index, (value, label)) in setup.arguments.into_iter().enumerate() {
            if index < registers.len() {
                registers[index] = value;
                register_labels[index] = label;
            }
        }
        let context_label = setup.this_label.join(&setup.super_label);
        let execution = ModuleExecutionSnapshot {
            registers,
            register_labels,
            call_stack: vec![CallFrame {
                return_ip: module.instructions.len(),
                return_reg: None,
                saved_module_specifier: Some(module.header.source_label.clone()),
                register_base: 0,
                function_index: Some(setup.function_index),
                this_value: setup.this_value,
                this_label: setup.this_label,
                new_target_value: Value::Undefined,
                new_target_label: crate::ifc_artifacts::Label::Public,
                super_value: setup.super_value,
                super_label: setup.super_label,
                construct_this: None,
                derived_constructor: false,
                this_initialized: true,
                initialize_derived_this_on_return: false,
                saved_pending_exception: None,
                saved_pending_return: None,
                saved_suspended_abrupt_depth: 0,
                saved_finally_mode_depth: 0,
                saved_scope_depth,
                saved_scope_chain: None,
                async_function_id: Some(async_id),
                accessor_context_label: context_label,
            }],
            ip: setup.function_entry as usize,
            register_base: 0,
            catch_frames: Vec::new(),
            pending_exception: None,
            pending_return: None,
            suspended_abrupt_completions: Vec::new(),
            finally_frames: Vec::new(),
            pending_finally_entry: None,
            copy_data_properties_states: Vec::new(),
            scope_chain,
            pending_captures: Vec::new(),
            current_module_specifier: Some(module.header.source_label.clone()),
        };
        let retained_owner = self
            .module_state
            .modules
            .get(&module.header.source_label)
            .and_then(|record| record.compiled_module.clone());
        let retained_program_bytes = if retained_owner.is_some() {
            0
        } else {
            Self::retained_module_program_bytes(module)
        };
        let retained_bytes = (std::mem::size_of::<AsyncFunctionObject>() as u64)
            .saturating_add(Self::estimate_module_execution_bytes(&execution))
            .saturating_add(retained_program_bytes)
            .saturating_add(register_storage_bytes);
        self.check_temporary_memory_budget(retained_bytes)?;
        // The unpublished activation and owner coexist with Promise creation.
        // Charge that local ownership before either allocation is published.
        let previous_temporary_bytes = self.temporarily_suspended_execution_bytes;
        self.temporarily_suspended_execution_bytes =
            previous_temporary_bytes.saturating_add(retained_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(retained_bytes);
        let owner_module = retained_owner.unwrap_or_else(|| Rc::new(module.clone()));
        let promise = match self.create_promise_accounted() {
            Ok(promise) => promise,
            Err(error) => {
                self.temporarily_suspended_execution_bytes = previous_temporary_bytes;
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(retained_bytes);
                return Err(error);
            }
        };
        self.async_functions.push(AsyncFunctionObject {
            execution: Some(execution),
            owner_module: Some(owner_module),
            retained_program_bytes,
            register_storage_bytes,
            label: crate::ifc_artifacts::Label::Public,
            phase: AsyncFunctionPhase::SuspendedStart,
            result_promise: promise.0,
        });
        self.temporarily_suspended_execution_bytes = previous_temporary_bytes;
        if let Err(error) = self.sync_estimated_memory_bytes() {
            self.async_functions.pop();
            self.promise_store.rollback_last_created(promise);
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        Ok(async_id)
    }

    fn run_async_function_call(&mut self, async_id: u32, dst: u32) -> Result<(), InterpreterError> {
        if let Err(error) = self.run_async_function_activation(async_id, None) {
            self.discard_async_function_activation(async_id);
            return Err(error);
        }
        let result = Value::Promise(self.async_functions[async_id as usize].result_promise);
        if let Err(error) = self.write_reg(dst, result) {
            self.discard_async_function_activation(async_id);
            return Err(error);
        }
        self.ip += 1;
        Ok(())
    }

    fn discard_async_function_activation(&mut self, async_id: u32) {
        if let Some(function) = self.async_functions.get_mut(async_id as usize) {
            function.execution = None;
            function.owner_module = None;
            function.retained_program_bytes = 0;
            function.register_storage_bytes = 0;
            function.label = crate::ifc_artifacts::Label::Public;
            function.phase = AsyncFunctionPhase::Completed;
        }
        self.async_resumption_contexts
            .retain(|_, context| context.async_function_id != async_id);
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    fn suspend_async_function_for_await(
        &mut self,
        promise_handle: crate::promise_model::PromiseHandle,
        result_register: u32,
        await_label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let async_function_id = self
            .call_stack
            .last()
            .and_then(|frame| frame.async_function_id)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "await in an isolated async activation".into(),
                got: "await outside async function context".into(),
            })?;
        let function = self
            .async_functions
            .get(async_function_id as usize)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid async function".into(),
                got: format!("async function #{async_function_id} not found"),
            })?;
        if function.phase != AsyncFunctionPhase::Executing {
            return Err(InterpreterError::TypeError {
                expected: "executing async function".into(),
                got: format!("async function phase: {:?}", function.phase),
            });
        }
        // The complete activation moves at the dispatch boundary. No second
        // register/scope snapshot is allocated at await.
        let context_bytes = Self::async_resumption_context_entry_bytes();
        self.check_temporary_memory_budget(context_bytes)?;
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_add(context_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(context_bytes);
        let registration = (|| {
            let rollback_bytes = self
                .promise_store
                .estimated_memory_bytes()
                .saturating_add(self.event_loop.microtasks.estimated_memory_bytes());
            self.check_temporary_memory_budget(rollback_bytes)?;
            // The rollback copies remain resident while registration grows
            // the store and queue; include that peak in the delta check.
            self.promise_in_flight_task_bytes = self
                .promise_in_flight_task_bytes
                .saturating_add(rollback_bytes);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_add(rollback_bytes);
            let previous_runtime = self.promise_runtime_memory_bytes();
            let store = self.promise_store.clone();
            let queue = self.event_loop.microtasks.clone();
            let result = match self.promise_store.then_for_await(
                promise_handle,
                await_label,
                &mut self.event_loop.microtasks,
            ) {
                Ok(continuation) => self
                    .apply_promise_runtime_memory_delta(previous_runtime)
                    .map(|()| continuation),
                Err(error) => Err(InterpreterError::TypeError {
                    expected: "valid awaited Promise".into(),
                    got: error.to_string(),
                }),
            };
            if result.is_err() {
                self.promise_store = store;
                self.event_loop.microtasks = queue;
            }
            self.promise_in_flight_task_bytes = self
                .promise_in_flight_task_bytes
                .saturating_sub(rollback_bytes);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(rollback_bytes);
            result
        })();
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_sub(context_bytes);
        match registration {
            Ok(continuation) => {
                self.async_resumption_contexts.insert(
                    continuation.0,
                    AsyncResumptionContext {
                        async_function_id,
                        result_register,
                    },
                );
                self.async_functions[async_function_id as usize].phase =
                    AsyncFunctionPhase::SuspendedAwait;
                self.ip += 1;
                Ok(())
            }
            Err(error) => {
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(context_bytes);
                Err(error)
            }
        }
    }

    fn async_resumption_context_entry_bytes() -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<AsyncResumptionContext>() as u64)
    }

    fn take_async_resumption_context(&mut self, promise: u32) -> Option<AsyncResumptionContext> {
        let context = self.async_resumption_contexts.remove(&promise)?;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::async_resumption_context_entry_bytes());
        Some(context)
    }

    fn run_async_body(&mut self, module: &Ir3Module) -> Result<RunLoopExit, InterpreterError> {
        loop {
            let outcome = self.run_loop_with_mode(module, RunLoopMode::Async);
            match outcome {
                Err(error)
                    if Self::is_js_catchable_error(&error) && self.has_exception_target_frame() =>
                {
                    match self.route_run_loop_javascript_error(module, error, RunLoopMode::Async)? {
                        None => continue,
                        Some(error) => return Err(error),
                    }
                }
                other => return other,
            }
        }
    }

    fn resume_async_function_after_await(
        &mut self,
        context: AsyncResumptionContext,
        settled: Result<crate::object_model::JsValue, crate::object_model::JsValue>,
        label: crate::ifc_artifacts::Label,
        _module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let async_id = context.async_function_id;
        let outcome = self.run_async_function_activation(
            async_id,
            Some(AsyncResumeValue {
                result_register: context.result_register,
                settlement: settled,
                label,
            }),
        );
        if outcome.is_err() {
            // The queue has consumed this resumption owner. A refused restore
            // cannot leave an activation that no future job can reach.
            self.discard_async_function_activation(async_id);
        }
        outcome
    }

    fn run_async_function_activation(
        &mut self,
        async_id: u32,
        resumed: Option<AsyncResumeValue>,
    ) -> Result<(), InterpreterError> {
        let (owner, execution, previous_phase) = {
            let function = self
                .async_functions
                .get_mut(async_id as usize)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "valid async activation".into(),
                    got: format!("async function #{async_id} not found"),
                })?;
            let expected_phase = if resumed.is_some() {
                AsyncFunctionPhase::SuspendedAwait
            } else {
                AsyncFunctionPhase::SuspendedStart
            };
            if function.phase != expected_phase {
                return Err(InterpreterError::TypeError {
                    expected: format!("async activation in {expected_phase:?}"),
                    got: format!("async activation in {:?}", function.phase),
                });
            }
            let owner =
                function
                    .owner_module
                    .clone()
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "retained async owner module".into(),
                        got: "missing async owner module".into(),
                    })?;
            let execution =
                function
                    .execution
                    .take()
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "saved async activation".into(),
                        got: "missing async activation".into(),
                    })?;
            let previous_phase = function.phase;
            function.phase = AsyncFunctionPhase::Executing;
            (owner, execution, previous_phase)
        };
        let caller = self.take_module_execution();
        let previous_bytes = self.temporarily_suspended_execution_bytes;
        let previous_depth = self.temporarily_suspended_call_depth;
        let saved_cjs_context = self.active_cjs_context.clone();
        self.temporarily_suspended_execution_bytes =
            previous_bytes.saturating_add(Self::estimate_module_execution_bytes(&caller));
        self.temporarily_suspended_call_depth =
            previous_depth.saturating_add(caller.call_stack.len());
        self.install_module_execution(execution);
        // CJS functions captured their module/exports/require binding cells.
        // A foreign caller's CJS context must not inject globals into this owner.
        self.active_cjs_context = None;
        if let Err(error) = self.sync_estimated_memory_bytes() {
            let execution = self.take_module_execution();
            self.active_cjs_context = saved_cjs_context;
            self.temporarily_suspended_execution_bytes = previous_bytes;
            self.temporarily_suspended_call_depth = previous_depth;
            self.async_functions[async_id as usize].execution = Some(execution);
            self.async_functions[async_id as usize].phase = previous_phase;
            self.restore_module_execution(caller);
            return Err(error);
        }
        let outcome = (|| {
            if let Some(AsyncResumeValue {
                result_register,
                settlement,
                label,
            }) = resumed
            {
                let previous_label = self.async_functions[async_id as usize].label.clone();
                let joined = previous_label.join(&label);
                self.check_temporary_memory_budget(Self::estimate_label_bytes(&joined))?;
                self.async_functions[async_id as usize].label = joined;
                if let Err(error) = self.sync_estimated_memory_bytes() {
                    self.async_functions[async_id as usize].label = previous_label;
                    return Err(error);
                }
                match settlement {
                    Ok(value) => self.write_reg_with_label(
                        result_register,
                        Self::js_value_to_value(&value),
                        label,
                    )?,
                    Err(reason) => {
                        let exception = LabeledException {
                            value: Self::js_value_to_value(&reason),
                            label,
                        };
                        self.suspend_current_abrupt_completion();
                        self.pending_return = None;
                        self.pending_exception = Some(exception.clone());
                        if let Some(frame) = self.pop_exception_target_frame() {
                            self.pending_finally_entry =
                                frame.catch_is_finally.then_some(PendingFinallyEntry {
                                    target: frame.catch_target,
                                    mode: FinallyMode::Exception,
                                });
                            self.ip = frame.catch_target;
                        } else {
                            return Ok(RunLoopExit::AsyncThrow { exception });
                        }
                    }
                }
            }
            self.run_async_body(&owner)
        })();
        let mut execution = self.take_module_execution();
        let escaped_exception = execution.pending_exception.take();
        self.temporarily_suspended_execution_bytes = previous_bytes;
        self.temporarily_suspended_call_depth = previous_depth;
        self.active_cjs_context = saved_cjs_context;
        self.restore_module_execution(caller);
        if matches!(outcome, Ok(RunLoopExit::AsyncAwait)) {
            execution.pending_exception = escaped_exception;
            self.async_functions[async_id as usize].execution = Some(execution);
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Ok(());
        }
        drop(execution);
        drop(owner);
        let function = &mut self.async_functions[async_id as usize];
        function.phase = AsyncFunctionPhase::Completed;
        function.owner_module = None;
        function.retained_program_bytes = 0;
        function.register_storage_bytes = 0;
        let promise = crate::promise_model::PromiseHandle(function.result_promise);
        let context_label =
            std::mem::replace(&mut function.label, crate::ifc_artifacts::Label::Public);
        self.async_resumption_contexts
            .retain(|_, context| context.async_function_id != async_id);
        // Completion payloads can outlive the released activation while
        // Promise resolution invokes thenable getters or schedules adoption.
        let completion_bytes = match &outcome {
            Ok(RunLoopExit::Value(completion)) => Self::estimate_labeled_return_bytes(completion),
            Ok(RunLoopExit::AsyncThrow { exception }) => {
                Self::estimate_labeled_exception_bytes(exception)
            }
            _ => 0,
        }
        .saturating_add(Self::estimate_label_bytes(&context_label))
        .saturating_add(
            escaped_exception
                .as_ref()
                .map(Self::estimate_labeled_exception_bytes)
                .unwrap_or(0),
        );
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_add(completion_bytes);
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        let result = (|| {
            self.check_temporary_memory_budget(0)?;
            match outcome {
                Ok(RunLoopExit::Value(completion)) => self.resolve_promise_with_value(
                    promise,
                    completion.value,
                    context_label.join(&completion.label),
                ),
                Ok(RunLoopExit::AsyncThrow { exception }) => self.reject_promise(
                    promise,
                    Self::value_to_js_value(&exception.value),
                    context_label.join(&exception.label),
                ),
                Err(InterpreterError::Halted) => {
                    self.resolve_promise_with_value(promise, Value::Undefined, context_label)
                }
                Err(error) if Self::is_js_catchable_error(&error) => {
                    let (value, label) = match escaped_exception {
                        Some(exception)
                            if matches!(error, InterpreterError::UncaughtException { .. }) =>
                        {
                            (exception.value, context_label.join(&exception.label))
                        }
                        _ => (self.promise_error_value(&error)?, context_label),
                    };
                    self.reject_promise(promise, Self::value_to_js_value(&value), label)
                }
                Err(error) => Err(error),
                Ok(_) => Err(InterpreterError::TypeError {
                    expected: "async return, throw, or await boundary".into(),
                    got: "generator completion in an async function".into(),
                }),
            }
        })();
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_sub(completion_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(completion_bytes);
        result
    }

    fn complete_return(
        &mut self,
        return_val: Value,
        return_label: crate::ifc_artifacts::Label,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
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
            self.restore_scope_chain_for_frame(&frame);
            self.pending_exception = frame.saved_pending_exception;
            self.pending_return = frame.saved_pending_return;
            let (effective_val, effective_label) = if frame.derived_constructor {
                if return_val.is_object_like() {
                    (return_val, return_label)
                } else if !matches!(&return_val, Value::Undefined) {
                    return Err(InterpreterError::TypeError {
                        expected: "object or undefined from derived constructor".to_string(),
                        got: return_val.type_name().to_string(),
                    });
                } else if frame.this_initialized {
                    (frame.this_value.clone(), frame.this_label.clone())
                } else {
                    return Err(InterpreterError::UninitializedBinding {
                        name: "this".to_string(),
                    });
                }
            } else {
                // Base constructors preserve the ordinary return-object-or-this
                // rule. Non-constructor frames have no `construct_this`.
                match &frame.construct_this {
                    Some(this_obj) if !return_val.is_object_like() => {
                        (this_obj.clone(), frame.this_label.clone())
                    }
                    _ => (return_val, return_label),
                }
            };
            if frame.initialize_derived_this_on_return {
                let Some(derived_frame) = self.call_stack.last_mut() else {
                    return Err(InterpreterError::TypeError {
                        expected: "enclosing derived constructor".to_string(),
                        got: "missing caller frame after super()".to_string(),
                    });
                };
                if !derived_frame.derived_constructor || derived_frame.this_initialized {
                    return Err(InterpreterError::TypeError {
                        expected: "uninitialized enclosing derived-constructor this binding"
                            .to_string(),
                        got: "super() attempted to initialize this twice".to_string(),
                    });
                }
                derived_frame.this_value = effective_val.clone();
                derived_frame.this_label = effective_label.clone();
                derived_frame.this_initialized = true;
            }
            if frame.async_function_id.is_some() && self.call_stack.is_empty() {
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                return Ok(Some(LabeledReturn {
                    value: effective_val,
                    label: effective_label,
                }));
            }
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
            Ok(Some(LabeledReturn {
                value: return_val,
                label: return_label,
            }))
        }
    }

    fn restore_scope_chain_for_frame(&mut self, frame: &CallFrame) {
        self.current_module_specifier = frame.saved_module_specifier.clone();
        // Closure and caller snapshots share lexical binding cells, so a
        // return restores only frame structure; no value merge is needed.
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
        self.pop_exception_target_frame_at_or_above(0)
    }

    fn pop_exception_target_frame_at_or_above(
        &mut self,
        minimum_call_depth: usize,
    ) -> Option<CatchFrame> {
        let current_depth = self.call_stack.len();
        let idx = self
            .catch_frames
            .iter()
            .rposition(|f| f.call_depth >= minimum_call_depth && f.call_depth <= current_depth)?;
        let frame = self.catch_frames[idx].clone();
        self.catch_frames.truncate(idx);
        self.finally_frames.truncate(frame.finally_frame_depth);
        let (restored_pending_exception, restored_pending_return) =
            self.unwind_call_stack_to(frame.call_depth);
        self.suspend_abrupt_completion(restored_pending_exception, restored_pending_return);
        Some(frame)
    }

    fn has_exception_target_frame(&self) -> bool {
        let current_depth = self.call_stack.len();
        self.catch_frames
            .iter()
            .any(|frame| frame.call_depth <= current_depth)
    }

    /// Route a JavaScript runtime failure back through the caller's active
    /// catch/finally frames. Explicit callback throws arrive with their exact
    /// value re-armed in `pending_exception`; native errors are materialized as
    /// small ordinary error objects for catch bindings.
    fn route_javascript_error(
        &mut self,
        _module: &Ir3Module,
        error: InterpreterError,
    ) -> Result<Option<InterpreterError>, InterpreterError> {
        let thrown = if matches!(error, InterpreterError::UncaughtException { .. }) {
            let Some(thrown) = self.pending_exception.take() else {
                return Ok(Some(error));
            };
            thrown
        } else if Self::is_js_catchable_error(&error) {
            let name = match &error {
                InterpreterError::RangeError { .. } => "RangeError",
                InterpreterError::UninitializedBinding { .. } => "ReferenceError",
                _ => "TypeError",
            };
            let object_id = self.alloc_object_with_prototype(None)?;
            self.set_object_property(object_id, "name".to_string(), Value::str(name))?;
            self.set_object_property(
                object_id,
                "message".to_string(),
                Value::str(error.to_string()),
            )?;
            LabeledException {
                value: Value::Object(object_id),
                label: crate::ifc_artifacts::Label::Public,
            }
        } else {
            return Ok(Some(error));
        };

        // A close failure replaces any Return/Break/Continue completion that
        // brought execution to IteratorClose.
        self.pending_return = None;
        self.pending_finally_entry = None;
        self.pending_exception = Some(thrown);
        if let Some(frame) = self.pop_exception_target_frame() {
            self.pending_finally_entry = frame.catch_is_finally.then_some(PendingFinallyEntry {
                target: frame.catch_target,
                mode: FinallyMode::Exception,
            });
            self.ip = frame.catch_target;
            Ok(None)
        } else {
            self.pending_exception = None;
            self.pending_finally_entry = None;
            self.finally_frames.clear();
            self.discard_all_copy_data_properties_states();
            Ok(Some(error))
        }
    }

    /// Route an error raised while the bytecode loop is active. If a nested
    /// generator call propagates an exact thrown value beyond every handler in
    /// the current generator, keep that value armed in the isolated activation
    /// so its caller can continue the same exception completion after restore.
    fn route_run_loop_javascript_error(
        &mut self,
        module: &Ir3Module,
        error: InterpreterError,
        mode: RunLoopMode,
    ) -> Result<Option<InterpreterError>, InterpreterError> {
        let escaped_exception = (matches!(
            mode,
            RunLoopMode::Generator | RunLoopMode::Async | RunLoopMode::AsyncGenerator
        ) && matches!(error, InterpreterError::UncaughtException { .. }))
        .then(|| self.pending_exception.clone())
        .flatten();
        let routed = self.route_javascript_error(module, error)?;
        if routed.is_some()
            && let Some(exception) = escaped_exception
        {
            self.pending_exception = Some(exception);
        }
        Ok(routed)
    }

    fn store_scoped_binding(
        &mut self,
        module: &Ir3Module,
        src: u32,
        name_pool_index: u32,
    ) -> Result<(), InterpreterError> {
        let name = Self::metadata_pool_string(
            module,
            name_pool_index,
            format!("__binding_{name_pool_index}"),
        )?;
        let val = self.read_reg(src)?;
        let label = self.read_reg_label(src)?;
        let mut previous = None;
        if let Some((_, binding)) = self.scope_chain.resolve(&name) {
            let previous_state = binding.snapshot_state()?;
            if !previous_state.initialized {
                return Err(InterpreterError::UninitializedBinding { name });
            }
            if binding.kind == BindingKind::Const {
                return Err(InterpreterError::ConstAssignment { name });
            }
            previous = Some((binding.clone(), previous_state));
            let mut state = binding.state_mut()?;
            state.value = val;
            state.label = label;
        }
        // Silently ignore stores to undeclared variables
        // (strict mode would throw, but baseline is lenient).
        if let Err(err) = self.sync_estimated_memory_bytes() {
            if let Some((binding, old_state)) = previous {
                binding.restore_state(old_state)?;
            }
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(err);
        }
        Ok(())
    }

    fn load_scoped_binding(
        &self,
        module: &Ir3Module,
        name_pool_index: u32,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        let name = Self::metadata_pool_string(
            module,
            name_pool_index,
            format!("__binding_{name_pool_index}"),
        )?;
        if let Some((_, binding)) = self.scope_chain.resolve(&name) {
            let state = binding.state()?;
            if !state.initialized {
                return Err(InterpreterError::UninitializedBinding { name });
            }
            return Ok((state.value.clone(), state.label.clone()));
        }
        if let Some(context) = self.active_cjs_context.as_ref() {
            let (filename, dirname) = self.cjs_filename_dirname(Some(&context.module_specifier));
            let value = match name.as_str() {
                "__filename" => filename,
                "__dirname" => dirname,
                _ => Value::Undefined,
            };
            return Ok((value, crate::ifc_artifacts::Label::Public));
        }
        Ok((Value::Undefined, crate::ifc_artifacts::Label::Public))
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
            // Before a foreign call, `module` supplies the callee's function
            // table while `ip` still identifies an instruction in the caller.
            extension_id: self
                .current_module_specifier
                .clone()
                .unwrap_or_else(|| module.header.source_label.clone()),
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

    fn property_hook_compatibility_error(
        error: HookPropertyKeyCompatibilityError,
    ) -> InterpreterError {
        InterpreterError::TypeError {
            expected: "property key supported by the installed interpreter hook".to_string(),
            got: error.to_string(),
        }
    }

    /// Preserve fail-closed behavior in legacy-only internal property paths
    /// that do not have a module-backed object target to present to a hook.
    fn preflight_legacy_property_key_for_hook(
        &self,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        if self.hook.is_none() {
            return Ok(());
        }
        let hook_key = match key {
            RuntimePropertyKey::String(key) => HookPropertyKey::String(key.clone()),
            RuntimePropertyKey::Symbol(symbol) => HookPropertyKey::Symbol(*symbol),
        };
        hook_key
            .as_legacy_str()
            .map(|_| ())
            .map_err(Self::property_hook_compatibility_error)
    }

    fn run_pre_runtime_property_access_hook(
        &self,
        module: &Ir3Module,
        target: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(key)?;
        let Some(hook) = self.hook.as_ref() else {
            return Ok(());
        };
        let ctx = self.hook_context(module);
        let hook_key = match key {
            RuntimePropertyKey::String(key) => HookPropertyKey::String(key.clone()),
            RuntimePropertyKey::Symbol(symbol) => HookPropertyKey::Symbol(*symbol),
        };
        let action = hook
            .pre_property_access_typed(&ctx, &target, &hook_key)
            .map_err(Self::property_hook_compatibility_error)?;
        self.enforce_hook_action(action)
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

    fn effective_call_depth(&self) -> usize {
        self.temporarily_suspended_call_depth
            .saturating_add(self.call_stack.len())
    }

    fn ensure_call_depth_available(&self) -> Result<(), InterpreterError> {
        let depth = self.effective_call_depth();
        if depth >= self.config.max_call_depth {
            return Err(InterpreterError::StackOverflow {
                depth,
                max: self.config.max_call_depth,
            });
        }
        Ok(())
    }

    fn enter_function_call(
        &mut self,
        module: &Ir3Module,
        callee_val: Value,
        this_value: Value,
        mut arg_vals: Vec<Value>,
        return_site: AccessorCallReturnSite,
    ) -> Result<(), InterpreterError> {
        let AccessorCallReturnSite {
            return_ip,
            return_reg,
            context_label,
        } = return_site;
        let owner_program = self.callable_module(&callee_val)?;
        let module = owner_program.as_deref().unwrap_or(module);
        let (func_idx, captured_env) = match &callee_val {
            Value::Function(idx) => (*idx, None),
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

        self.ensure_call_depth_available()?;

        self.run_pre_call_hook(module, &callee_val, func_idx, &arg_vals)?;

        let setup_snapshot = self.snapshot_call_setup(None, false);
        let setup_result = (|| -> Result<(), InterpreterError> {
            let scope_depth = self.scope_chain.depth();
            let captured_env_bytes = captured_env
                .as_ref()
                .map(|env| Self::estimate_scope_chain_bytes(env))
                .unwrap_or(0);
            let saved_chain = if captured_env.is_some() {
                Some(self.snapshot_scope_chain_with_temporary_budget(captured_env_bytes)?)
            } else {
                None
            };
            let (super_value, super_label) =
                if let Some(binding) = self.concise_method_super_binding(&callee_val)? {
                    binding
                } else {
                    (
                        self.method_super_value(&callee_val, &this_value)?,
                        crate::ifc_artifacts::Label::Public,
                    )
                };
            self.call_stack.push(CallFrame {
                return_ip,
                return_reg,
                register_base: self.register_base,
                function_index: Some(func_idx),
                saved_module_specifier: self.current_module_specifier.clone(),
                this_value,
                this_label: context_label.clone(),
                new_target_value: Value::Undefined,
                new_target_label: crate::ifc_artifacts::Label::Public,
                super_value,
                super_label,
                construct_this: None,
                derived_constructor: false,
                this_initialized: true,
                initialize_derived_this_on_return: false,
                saved_pending_exception: self.pending_exception.take(),
                saved_pending_return: self.pending_return.take(),
                saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
                saved_finally_mode_depth: self.finally_frames.len(),
                saved_scope_depth: scope_depth,
                saved_scope_chain: saved_chain,
                async_function_id: None,
                accessor_context_label: context_label.clone(),
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
                    self.write_reg_with_label(reg, val, context_label.clone())?;
                }
            }

            self.current_module_specifier = Some(module.header.source_label.clone());
            self.ip = func.entry as usize;
            self.sync_estimated_memory_bytes()?;
            Ok(())
        })();
        if let Err(error) = setup_result {
            self.restore_call_setup(setup_snapshot);
            return Err(error);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn enter_constructor_call(
        &mut self,
        module: &Ir3Module,
        callee_value: Value,
        callee_label: crate::ifc_artifacts::Label,
        args: ConstructorArguments,
        return_ip: usize,
        return_reg: Option<u32>,
        new_target_value: Value,
        new_target_label: crate::ifc_artifacts::Label,
        initialize_derived_this_on_return: bool,
    ) -> Result<(), InterpreterError> {
        // An omitted derived constructor is semantically
        // `constructor(...args) { super(...args); }`. Resolve any chain of such
        // synthetic constructors before frame entry so every original argument
        // and the original `new.target` survive without a fixed-arity shim.
        let mut active_callee = callee_value;
        let mut active_callee_label = callee_label;
        let mut visited = BTreeSet::new();
        loop {
            let (_, is_default_derived, parent, parent_label) =
                self.derived_constructor_metadata(&active_callee)?;
            if !is_default_derived {
                break;
            }
            let key = Self::function_object_key(&active_callee).ok_or_else(|| {
                InterpreterError::TypeError {
                    expected: "default derived constructor function".to_string(),
                    got: active_callee.type_name().to_string(),
                }
            })?;
            if !visited.insert(key) {
                return Err(InterpreterError::TypeError {
                    expected: "acyclic derived constructor chain".to_string(),
                    got: "cyclic default-derived superclass metadata".to_string(),
                });
            }
            active_callee = parent;
            active_callee_label = active_callee_label.join(&parent_label);
        }

        let (derived_constructor, _, super_value, super_label) =
            self.derived_constructor_metadata(&active_callee)?;
        let owner_program = self.callable_module(&active_callee)?;
        let module = owner_program.as_deref().unwrap_or(module);
        let (function_index, captured_env) = match &active_callee {
            Value::Function(index) => (*index, None),
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
                )
            }
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "constructor function".to_string(),
                    got: active_callee.type_name().to_string(),
                });
            }
        };
        let function = module.function_table.get(function_index as usize).ok_or(
            InterpreterError::FunctionNotFound {
                index: function_index,
                table_size: module.function_table.len() as u32,
            },
        )?;
        self.validate_function_rest_param(function)?;
        self.ensure_call_depth_available()?;
        if let ConstructorArguments::Registers(registers) = &args
            && registers.count > 0
        {
            let last = registers.start.checked_add(registers.count - 1).ok_or(
                InterpreterError::RegisterOutOfBounds {
                    register: registers.start,
                    max: self.config.max_registers,
                },
            )?;
            if last >= self.config.max_registers {
                return Err(InterpreterError::RegisterOutOfBounds {
                    register: last,
                    max: self.config.max_registers,
                });
            }
        }
        if function.arity > self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: function.arity - 1,
                max: self.config.max_registers,
            });
        }

        // Only fixed callee slots are buffered. The potentially much longer
        // rest tail is copied directly from its source into the rest array.
        // Retain the buffer's charge across allocation and frame setup, whose
        // memory resynchronizations must not lose this native ownership.
        let fixed_count = function
            .rest_param_index
            .unwrap_or(function.arity)
            .min(args.count());
        let mut temporary_bytes = u64::from(function.arity).saturating_mul(
            (std::mem::size_of::<Value>() + std::mem::size_of::<crate::ifc_artifacts::Label>())
                as u64,
        );
        if let ConstructorArguments::Array { label, .. } = &args {
            // The list's shape label remains owned even for a zero-arity
            // superclass that does not retain any individual arguments.
            temporary_bytes = temporary_bytes.saturating_add(Self::estimate_label_bytes(label));
        }
        for offset in 0..fixed_count {
            self.charge_array_method_step()?;
            let (value, label) = self.constructor_argument(&args, offset)?;
            temporary_bytes = temporary_bytes
                .saturating_add(Self::estimate_value_bytes(&value))
                .saturating_add(Self::estimate_label_bytes(&label));
        }
        self.check_temporary_memory_budget(temporary_bytes)?;
        let previous_temporary_bytes = self.array_method_temporary_bytes;
        self.array_method_temporary_bytes =
            previous_temporary_bytes.saturating_add(temporary_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(temporary_bytes);

        let setup_snapshot = self.snapshot_call_setup(None, true);
        let setup_result = (|| -> Result<(), InterpreterError> {
            let (argument_values, argument_labels) =
                self.constructor_parameter_values(module, &args, function)?;

            let (this_value, construct_this, this_initialized) = if derived_constructor {
                (Value::Undefined, None, false)
            } else {
                let prototype = self
                    .function_prototype_for_value(&new_target_value)?
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "constructible new.target".to_string(),
                        got: new_target_value.type_name().to_string(),
                    })?;
                let this_id = self.alloc_object_with_prototype(Some(prototype))?;
                if let Some(object) = self.heap.get_mut(this_id.0 as usize) {
                    object.constructor_function = Some(function_index);
                }
                let this_value = Value::Object(this_id);
                (this_value.clone(), Some(this_value), true)
            };
            self.run_pre_call_hook(module, &active_callee, function_index, &argument_values)?;

            let scope_depth = self.scope_chain.depth();
            let captured_env_bytes = captured_env
                .as_ref()
                .map(|environment| Self::estimate_scope_chain_bytes(environment))
                .unwrap_or(0);
            let saved_scope_chain = if captured_env.is_some() {
                Some(self.snapshot_scope_chain_with_temporary_budget(captured_env_bytes)?)
            } else {
                None
            };
            self.call_stack.push(CallFrame {
                return_ip,
                return_reg,
                register_base: self.register_base,
                function_index: Some(function_index),
                saved_module_specifier: self.current_module_specifier.clone(),
                this_value,
                this_label: active_callee_label.join(&new_target_label),
                new_target_value,
                new_target_label: new_target_label.clone(),
                super_value,
                super_label,
                construct_this,
                derived_constructor,
                this_initialized,
                initialize_derived_this_on_return,
                saved_pending_exception: self.pending_exception.take(),
                saved_pending_return: self.pending_return.take(),
                saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
                saved_finally_mode_depth: self.finally_frames.len(),
                saved_scope_depth: scope_depth,
                saved_scope_chain,
                async_function_id: None,
                accessor_context_label: match &args {
                    ConstructorArguments::Registers(_) => crate::ifc_artifacts::Label::Public,
                    ConstructorArguments::Array { label, .. } => label.clone(),
                },
            });

            if let Some(environment) = captured_env {
                self.scope_chain.frames = environment;
            }
            if let Err(error) = self.scope_chain.push(self.config.max_scope_depth) {
                self.rollback_call_setup();
                return Err(error);
            }
            if let Err(error) = self.sync_estimated_memory_bytes() {
                self.rollback_call_setup();
                return Err(error);
            }

            self.register_base += self.config.max_registers as usize;
            let required_len = self.register_base + self.config.max_registers as usize;
            self.clear_register_range(self.register_base, required_len);
            for (index, (value, label)) in
                argument_values.into_iter().zip(argument_labels).enumerate()
            {
                let register = index as u32;
                if register < self.config.max_registers {
                    self.write_reg_with_label(register, value, label)?;
                }
            }
            self.current_module_specifier = Some(module.header.source_label.clone());
            self.ip = function.entry as usize;
            self.sync_estimated_memory_bytes()?;
            Ok(())
        })();
        if setup_result.is_err() {
            self.restore_call_setup(setup_snapshot);
        }
        self.array_method_temporary_bytes = previous_temporary_bytes;
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        setup_result
    }

    fn constructor_argument(
        &self,
        args: &ConstructorArguments,
        offset: u32,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        match args {
            ConstructorArguments::Registers(args) => self.promise_hostcall_argument(*args, offset),
            ConstructorArguments::Array { object, label, .. } => {
                // The lowering has already evaluated every getter and
                // iterator step into own data properties on a private array.
                let key = RuntimePropertyKey::String(JsString::from(offset.to_string()));
                let value = self.array_index_value(*object, offset)?.ok_or_else(|| {
                    InterpreterError::TypeError {
                        expected: "dense internal constructor argument array".into(),
                        got: format!("missing argument {offset}"),
                    }
                })?;
                let label = label.join(&self.own_stored_runtime_property_label(*object, &key));
                Ok((value, label))
            }
        }
    }

    fn constructor_parameter_values(
        &mut self,
        module: &Ir3Module,
        args: &ConstructorArguments,
        function: &Ir3FunctionDesc,
    ) -> Result<(Vec<Value>, Vec<crate::ifc_artifacts::Label>), InterpreterError> {
        let fixed_count = function
            .rest_param_index
            .unwrap_or(function.arity)
            .min(args.count());
        let mut values = Vec::with_capacity(function.arity as usize);
        let mut labels = Vec::with_capacity(function.arity as usize);
        for offset in 0..fixed_count {
            let (value, label) = self.constructor_argument(args, offset)?;
            values.push(value);
            labels.push(label);
        }
        if let Some(rest_index) = function.rest_param_index {
            let count = args.count().saturating_sub(rest_index);
            self.run_pre_allocation_hook(module, AllocKind::Array, count as usize)?;
            let rest_array = self.alloc_array_with_prototype(None)?;
            let mut rest_label = match args {
                ConstructorArguments::Registers(_) => crate::ifc_artifacts::Label::Public,
                ConstructorArguments::Array { label, .. } => label.clone(),
            };
            let mut retained_rest_label_bytes = Self::estimate_label_bytes(&rest_label);
            self.check_temporary_memory_budget(retained_rest_label_bytes)?;
            self.array_method_temporary_bytes = self
                .array_method_temporary_bytes
                .saturating_add(retained_rest_label_bytes);
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_add(retained_rest_label_bytes);
            for index in 0..count {
                self.charge_array_method_step()?;
                let (value, label) = self.constructor_argument(args, rest_index + index)?;
                let key = RuntimePropertyKey::String(JsString::from(index.to_string()));
                let bytes = Self::estimate_value_bytes(&value)
                    .saturating_add(Self::estimate_label_bytes(&label))
                    .saturating_add(Self::estimate_label_bytes(&rest_label));
                self.with_array_method_temporary(bytes, |core| {
                    core.set_own_runtime_property_label(rest_array, &key, &label)?;
                    core.set_object_property(rest_array, index.to_string(), value)?;
                    let next_label_bytes =
                        Self::estimate_label_bytes(std::cmp::max(&rest_label, &label));
                    core.check_temporary_memory_budget(
                        next_label_bytes.saturating_sub(retained_rest_label_bytes),
                    )?;
                    core.array_method_temporary_bytes = core
                        .array_method_temporary_bytes
                        .saturating_sub(retained_rest_label_bytes)
                        .saturating_add(next_label_bytes);
                    core.estimated_memory_bytes = core
                        .estimated_memory_bytes
                        .saturating_sub(retained_rest_label_bytes)
                        .saturating_add(next_label_bytes);
                    rest_label = rest_label.join(&label);
                    retained_rest_label_bytes = next_label_bytes;
                    Ok(())
                })?;
            }
            self.set_object_property(rest_array, "length".into(), Value::Int(i64::from(count)))?;
            self.set_own_runtime_property_label(
                rest_array,
                &RuntimePropertyKey::String(JsString::from("length")),
                &rest_label,
            )?;
            values.resize(rest_index as usize + 1, Value::Undefined);
            labels.resize(rest_index as usize + 1, crate::ifc_artifacts::Label::Public);
            values[rest_index as usize] = Value::Object(rest_array);
            labels[rest_index as usize] = rest_label;
        }
        Ok((values, labels))
    }

    fn enter_super_constructor_call(
        &mut self,
        module: &Ir3Module,
        args: ConstructorArguments,
        dst: u32,
    ) -> Result<(), InterpreterError> {
        let frame = self
            .call_stack
            .last()
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "active derived constructor".into(),
                got: "super() outside a constructor".into(),
            })?;
        if !frame.derived_constructor || frame.this_initialized {
            return Err(InterpreterError::TypeError {
                expected: "uninitialized derived-constructor this binding".into(),
                got: if frame.derived_constructor {
                    "super() called more than once".into()
                } else {
                    "super() in a base constructor".into()
                },
            });
        }
        self.enter_constructor_call(
            module,
            frame.super_value.clone(),
            frame.super_label.clone(),
            args,
            self.ip + 1,
            Some(dst),
            frame.new_target_value.clone(),
            frame.new_target_label.clone(),
            true,
        )
    }

    fn enter_super_spread_call(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        dst: u32,
    ) -> Result<(), InterpreterError> {
        if args.count == 0 {
            return Err(InterpreterError::TypeError {
                expected: "internal superclass argument array and iterator provenance".into(),
                got: format!("{} operands", args.count),
            });
        }
        let value = self.read_reg(args.start)?;
        let object = self.expect_object(value, "internal superclass argument array")?;
        if !self.heap[object.0 as usize].is_array {
            return Err(InterpreterError::TypeError {
                expected: "internal superclass argument array".into(),
                got: "non-array object".into(),
            });
        }
        let count = self.array_like_length(object)?;
        let mut label =
            self.read_reg_label(args.start)?
                .join(&self.own_stored_runtime_property_label(
                    object,
                    &RuntimePropertyKey::String(JsString::from("length")),
                ));
        for offset in 1..args.count {
            self.charge_array_method_step()?;
            let (iterator, iterator_label) = self.promise_hostcall_argument(args, offset)?;
            let handle = self.expect_iterator_handle(iterator)?;
            label = label
                .join(&iterator_label)
                .join(&self.for_of_iterator_label(handle)?);
        }
        self.enter_super_constructor_call(
            module,
            ConstructorArguments::Array {
                object,
                count,
                label,
            },
            dst,
        )
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

    fn generator_result_object(
        &mut self,
        value: Value,
        done: bool,
    ) -> Result<Value, InterpreterError> {
        let result_id = self.alloc_object_with_prototype(None)?;
        self.set_object_property(result_id, "value".to_string(), value)?;
        self.set_object_property(result_id, "done".to_string(), Value::Bool(done))?;
        Ok(Value::Object(result_id))
    }

    /// Isolated generator activation with no caller-side carrier rollback,
    /// used by the interpreter tests that exercise activation directly (no
    /// caller allocated a rest carrier). Production call branches use
    /// [`Self::prepare_generator_activation_inner`] with the caller snapshot.
    #[cfg(test)]
    fn prepare_generator_activation(
        &mut self,
        module: &Ir3Module,
        setup: GeneratorCallSetup,
    ) -> Result<GeneratorObject, InterpreterError> {
        self.prepare_generator_activation_inner(module, setup, None)
    }

    /// `rollback` carries the caller's pre-carrier [`CallSetupSnapshot`] when
    /// the caller allocated an implicit rest-Array carrier. Pre-prologue setup
    /// refusals (call-depth / scope-depth / memory) occur before any parameter
    /// prologue runs, so the carrier is still the heap tail and a blind
    /// `restore_call_setup` truncate is correct (bd-tstbe). Once the prologue
    /// runs (`run_loop_with_mode`) it may store objects into persistent roots,
    /// so those refusals must NOT truncate the heap and are propagated without
    /// the carrier rollback.
    fn prepare_generator_activation_inner(
        &mut self,
        module: &Ir3Module,
        setup: GeneratorCallSetup,
        rollback: Option<CallSetupSnapshot>,
    ) -> Result<GeneratorObject, InterpreterError> {
        if let Err(error) = self.ensure_call_depth_available() {
            if let Some(snapshot) = rollback {
                self.restore_call_setup(snapshot);
            }
            return Err(error);
        }

        let mut scope_chain = ScopeChain {
            frames: setup.captured_env,
        };
        let saved_scope_depth = scope_chain.depth();
        if let Err(error) = scope_chain.push(self.config.max_scope_depth) {
            if let Some(snapshot) = rollback {
                self.restore_call_setup(snapshot);
            }
            return Err(error);
        }

        let max_registers = self.config.max_registers as usize;
        let mut registers = vec![Value::Undefined; max_registers];
        let mut register_labels = vec![crate::ifc_artifacts::Label::Public; max_registers];
        for (index, (value, label)) in setup.arguments.into_iter().enumerate() {
            if index >= max_registers {
                break;
            }
            registers[index] = value;
            register_labels[index] = label;
        }

        let caller_execution = self.take_module_execution();
        let caller_bytes = Self::estimate_module_execution_bytes(&caller_execution);
        let previous_suspended_bytes = self.temporarily_suspended_execution_bytes;
        let previous_suspended_call_depth = self.temporarily_suspended_call_depth;
        self.temporarily_suspended_execution_bytes =
            previous_suspended_bytes.saturating_add(caller_bytes);
        self.temporarily_suspended_call_depth =
            previous_suspended_call_depth.saturating_add(caller_execution.call_stack.len());
        let module_specifier = Some(module.header.source_label.clone());
        let context_label = setup.this_label.join(&setup.super_label);
        self.install_module_execution(ModuleExecutionSnapshot {
            registers,
            register_labels,
            call_stack: vec![CallFrame {
                return_ip: module.instructions.len(),
                return_reg: None,
                saved_module_specifier: Some(module.header.source_label.clone()),
                register_base: 0,
                function_index: Some(setup.function_index),
                this_value: setup.this_value,
                this_label: setup.this_label,
                new_target_value: Value::Undefined,
                new_target_label: crate::ifc_artifacts::Label::Public,
                super_value: setup.super_value,
                super_label: setup.super_label,
                construct_this: None,
                derived_constructor: false,
                this_initialized: true,
                initialize_derived_this_on_return: false,
                saved_pending_exception: None,
                saved_pending_return: None,
                saved_suspended_abrupt_depth: 0,
                saved_finally_mode_depth: 0,
                saved_scope_depth,
                saved_scope_chain: None,
                async_function_id: None,
                accessor_context_label: context_label,
            }],
            ip: setup.function_entry as usize,
            register_base: 0,
            catch_frames: Vec::new(),
            pending_exception: None,
            pending_return: None,
            suspended_abrupt_completions: Vec::new(),
            finally_frames: Vec::new(),
            pending_finally_entry: None,
            copy_data_properties_states: Vec::new(),
            scope_chain,
            pending_captures: Vec::new(),
            current_module_specifier: module_specifier,
        });

        // Historical core IR through 0.9 has no parameter/body boundary. Keep
        // those explicitly supported artifacts readable by suspending at the
        // function entry; they retain their historical first-next parameter
        // timing. Newly lowered 0.10+ IR must reach the explicit marker.
        let has_explicit_body_boundary = module.header.schema_version
            >= crate::ir_contract::IrSchemaVersion {
                major: 0,
                minor: 10,
                patch: 0,
            };
        // Memory refusal here is still pre-prologue (the prologue only runs
        // via `run_loop_with_mode` below), so undo the installed activation,
        // restore the caller, and roll back the rest-Array carrier (bd-tstbe).
        if let Err(error) = self.sync_estimated_memory_bytes() {
            let _ = self.take_module_execution();
            self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
            self.temporarily_suspended_call_depth = previous_suspended_call_depth;
            self.restore_module_execution(caller_execution);
            if let Some(snapshot) = rollback {
                self.restore_call_setup(snapshot);
            }
            return Err(error);
        }

        // Prologue commit point: from here a refusal is post-prologue and must
        // preserve any language-visible side effects — no carrier rollback.
        let outcome = if has_explicit_body_boundary {
            self.run_loop_with_mode(module, RunLoopMode::Generator)
        } else {
            Ok(RunLoopExit::GeneratorBodyStart)
        };
        let activation = self.take_module_execution();
        let escaped_exception = activation.pending_exception.clone();
        self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
        self.temporarily_suspended_call_depth = previous_suspended_call_depth;
        self.restore_module_execution(caller_execution);

        match outcome {
            Ok(RunLoopExit::GeneratorBodyStart) => Ok(GeneratorObject {
                execution: Some(activation),
                resume_dst: None,
                phase: GeneratorPhase::SuspendedStart,
            }),
            Ok(RunLoopExit::GeneratorThrow {
                exception,
                description,
            }) => {
                self.pending_exception = Some(exception);
                Err(InterpreterError::UncaughtException { value: description })
            }
            Err(error) => {
                if matches!(error, InterpreterError::UncaughtException { .. })
                    && let Some(exception) = escaped_exception
                {
                    self.pending_exception = Some(exception);
                }
                Err(error)
            }
            Ok(
                RunLoopExit::GeneratorReturn { .. }
                | RunLoopExit::GeneratorYield { .. }
                | RunLoopExit::AsyncAwait
                | RunLoopExit::AsyncGeneratorAwait { .. }
                | RunLoopExit::AsyncThrow { .. }
                | RunLoopExit::Value(_),
            ) => Err(InterpreterError::TypeError {
                expected: "generator parameter prologue followed by generator_body_start"
                    .to_string(),
                got: "generator body executed before its suspension boundary".to_string(),
            }),
        }
    }

    fn publish_generator(
        &mut self,
        dst: u32,
        generator: GeneratorObject,
    ) -> Result<u32, InterpreterError> {
        let generator_id =
            u32::try_from(self.generators.len()).map_err(|_| InterpreterError::TypeError {
                expected: "generator table capacity".into(),
                got: format!("exceeded u32::MAX ({})", self.generators.len()),
            })?;
        self.generators.push(generator);
        if let Err(error) = self.sync_estimated_memory_bytes() {
            self.generators.pop();
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        if let Err(error) = self.write_reg(dst, Value::Generator(generator_id)) {
            self.generators.pop();
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        Ok(generator_id)
    }

    fn publish_async_generator(
        &mut self,
        dst: u32,
        generator: AsyncGeneratorObject,
    ) -> Result<u32, InterpreterError> {
        let generator_id = u32::try_from(self.async_generators.len()).map_err(|_| {
            InterpreterError::TypeError {
                expected: "async generator table capacity".into(),
                got: format!("exceeded u32::MAX ({})", self.async_generators.len()),
            }
        })?;
        self.async_generators.push(generator);
        if let Err(error) = self.sync_estimated_memory_bytes() {
            self.async_generators.pop();
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        if let Err(error) = self.write_reg(dst, Value::AsyncGeneratorObject(generator_id)) {
            self.async_generators.pop();
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        Ok(generator_id)
    }

    /// Step a generator: install its isolated activation, run until Yield or
    /// Return, then transfer the activation back. Returns `{ value, done }`.
    fn generator_next(
        &mut self,
        module: &Ir3Module,
        gen_id: u32,
        argument: Value,
        argument_label: crate::ifc_artifacts::Label,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        self.resume_generator(module, gen_id, argument, argument_label, false)
    }

    fn resume_generator(
        &mut self,
        module: &Ir3Module,
        gen_id: u32,
        argument: Value,
        argument_label: crate::ifc_artifacts::Label,
        is_return: bool,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        let phase = {
            let generator = self.generators.get(gen_id as usize).ok_or_else(|| {
                InterpreterError::TypeError {
                    expected: "valid generator".into(),
                    got: format!("generator#{gen_id} not found"),
                }
            })?;
            match generator.phase {
                GeneratorPhase::Completed => {
                    return Ok((
                        self.generator_result_object(
                            if is_return {
                                argument
                            } else {
                                Value::Undefined
                            },
                            true,
                        )?,
                        if is_return {
                            argument_label
                        } else {
                            crate::ifc_artifacts::Label::Public
                        },
                    ));
                }
                GeneratorPhase::Executing => {
                    return Err(InterpreterError::TypeError {
                        expected: "suspended generator".into(),
                        got: "generator already executing".into(),
                    });
                }
                GeneratorPhase::SuspendedStart | GeneratorPhase::SuspendedYield => {}
            }
            generator.phase
        };

        if is_return && phase == GeneratorPhase::SuspendedStart {
            let generator = &mut self.generators[gen_id as usize];
            generator.execution = None;
            generator.resume_dst = None;
            generator.phase = GeneratorPhase::Completed;
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Ok((
                self.generator_result_object(argument, true)?,
                argument_label,
            ));
        }

        // Resuming installs one suspended generator frame on top of the
        // synchronously active caller chain. Apply the same fail-closed depth
        // check used by ordinary calls before moving either execution context.
        self.ensure_call_depth_available()?;

        let (value_count, label_count) = {
            let activation = self.generators[gen_id as usize]
                .execution
                .as_ref()
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "suspended generator activation".into(),
                    got: "generator has no saved execution context".into(),
                })?;
            (activation.registers.len(), activation.register_labels.len())
        };
        if value_count != label_count {
            return Err(InterpreterError::TypeError {
                expected: "generator snapshot with one IFC label per register".into(),
                got: format!("values={value_count}, labels={label_count}"),
            });
        }

        let (resume_dst, activation) = {
            let generator = &mut self.generators[gen_id as usize];
            let activation =
                generator
                    .execution
                    .take()
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "suspended generator activation".into(),
                        got: "generator has no saved execution context".into(),
                    })?;
            let resume_dst = generator.resume_dst.take();
            generator.phase = GeneratorPhase::Executing;
            (resume_dst, activation)
        };

        let caller_execution = self.take_module_execution();
        let caller_bytes = Self::estimate_module_execution_bytes(&caller_execution);
        let previous_suspended_bytes = self.temporarily_suspended_execution_bytes;
        let previous_suspended_call_depth = self.temporarily_suspended_call_depth;
        self.temporarily_suspended_execution_bytes =
            previous_suspended_bytes.saturating_add(caller_bytes);
        self.temporarily_suspended_call_depth =
            previous_suspended_call_depth.saturating_add(caller_execution.call_stack.len());
        self.install_module_execution(activation);

        if let Err(error) = self.sync_estimated_memory_bytes() {
            let activation = self.take_module_execution();
            self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
            self.temporarily_suspended_call_depth = previous_suspended_call_depth;
            self.restore_module_execution(caller_execution);
            let generator = &mut self.generators[gen_id as usize];
            generator.execution = Some(activation);
            generator.resume_dst = resume_dst;
            generator.phase = phase;
            return Err(error);
        }

        let mut argument = Some((argument, argument_label));
        if !is_return
            && phase == GeneratorPhase::SuspendedYield
            && let Some(resume_dst) = resume_dst
            && let Err(error) = {
                let (value, label) = argument.take().expect("unconsumed generator argument");
                self.write_reg_with_label(resume_dst, value, label)
            }
        {
            let activation = self.take_module_execution();
            self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
            self.temporarily_suspended_call_depth = previous_suspended_call_depth;
            self.restore_module_execution(caller_execution);
            let generator = &mut self.generators[gen_id as usize];
            generator.execution = Some(activation);
            generator.resume_dst = Some(resume_dst);
            generator.phase = phase;
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }

        let outcome = if is_return {
            // IteratorClose injects Return at the suspension point. Run the
            // saved finally frames instead of discarding guest cleanup.
            let (value, label) = argument.take().expect("generator return argument");
            self.suspend_current_abrupt_completion();
            self.pending_exception = None;
            self.pending_return = Some(LabeledReturn {
                value: value.clone(),
                label: label.clone(),
            });
            if let Some(target) = self.pop_current_finally_target() {
                self.pending_finally_entry = Some(PendingFinallyEntry {
                    target,
                    mode: FinallyMode::Return,
                });
                self.ip = target;
                self.run_loop_with_mode(module, RunLoopMode::Generator)
            } else {
                Ok(RunLoopExit::GeneratorReturn { value, label })
            }
        } else {
            self.run_loop_with_mode(module, RunLoopMode::Generator)
        };
        let activation = self.take_module_execution();
        let escaped_exception = activation.pending_exception.clone();
        self.temporarily_suspended_execution_bytes = previous_suspended_bytes;
        self.temporarily_suspended_call_depth = previous_suspended_call_depth;
        self.restore_module_execution(caller_execution);

        match outcome {
            Ok(RunLoopExit::GeneratorYield {
                result,
                label,
                resume_dst,
            }) => {
                let generator = &mut self.generators[gen_id as usize];
                generator.execution = Some(activation);
                generator.resume_dst = Some(resume_dst);
                generator.phase = GeneratorPhase::SuspendedYield;
                if let Err(error) = self.sync_estimated_memory_bytes() {
                    let generator = &mut self.generators[gen_id as usize];
                    generator.execution = None;
                    generator.resume_dst = None;
                    generator.phase = GeneratorPhase::Completed;
                    self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                    return Err(error);
                }
                Ok((result, label))
            }
            Ok(RunLoopExit::GeneratorReturn { value, label }) => {
                let generator = &mut self.generators[gen_id as usize];
                generator.execution = None;
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                Ok((self.generator_result_object(value, true)?, label))
            }
            Ok(RunLoopExit::Value(completion)) => {
                let generator = &mut self.generators[gen_id as usize];
                generator.execution = None;
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                Ok((
                    self.generator_result_object(completion.value, true)?,
                    completion.label,
                ))
            }
            Ok(RunLoopExit::GeneratorThrow {
                exception,
                description,
            }) => {
                let generator = &mut self.generators[gen_id as usize];
                generator.execution = None;
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                self.pending_exception = Some(exception);
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                Err(InterpreterError::UncaughtException { value: description })
            }
            Ok(
                RunLoopExit::GeneratorBodyStart
                | RunLoopExit::AsyncAwait
                | RunLoopExit::AsyncGeneratorAwait { .. }
                | RunLoopExit::AsyncThrow { .. },
            ) => {
                let generator = &mut self.generators[gen_id as usize];
                generator.execution = None;
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                Err(InterpreterError::TypeError {
                    expected: "generator body without a second initialization boundary".into(),
                    got: "generator_body_start reached while resuming generator".into(),
                })
            }
            Err(InterpreterError::Halted) => {
                let generator = &mut self.generators[gen_id as usize];
                generator.execution = None;
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                Ok((
                    self.generator_result_object(Value::Undefined, true)?,
                    crate::ifc_artifacts::Label::Public,
                ))
            }
            Err(error) => {
                let generator = &mut self.generators[gen_id as usize];
                generator.execution = None;
                generator.resume_dst = None;
                generator.phase = GeneratorPhase::Completed;
                if matches!(error, InterpreterError::UncaughtException { .. })
                    && let Some(exception) = escaped_exception
                {
                    self.pending_exception = Some(exception);
                }
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                Err(error)
            }
        }
    }

    fn run_loop_labeled(&mut self, module: &Ir3Module) -> Result<LabeledReturn, InterpreterError> {
        match self.run_loop_with_mode(module, RunLoopMode::Normal)? {
            RunLoopExit::Value(completion) => Ok(completion),
            RunLoopExit::GeneratorReturn { value, label }
            | RunLoopExit::GeneratorYield {
                result: value,
                label,
                ..
            } => Ok(LabeledReturn { value, label }),
            RunLoopExit::AsyncThrow { exception } => {
                let description = exception.value.to_string();
                self.pending_exception = Some(exception);
                Err(InterpreterError::UncaughtException { value: description })
            }
            RunLoopExit::GeneratorBodyStart
            | RunLoopExit::AsyncAwait
            | RunLoopExit::AsyncGeneratorAwait { .. } => Err(InterpreterError::TypeError {
                expected: "generator activation".to_string(),
                got: "generator body boundary outside generator invocation".to_string(),
            }),
            RunLoopExit::GeneratorThrow {
                exception,
                description,
            } => {
                self.pending_exception = Some(exception);
                Err(InterpreterError::UncaughtException { value: description })
            }
        }
    }

    fn run_loop(&mut self, module: &Ir3Module) -> Result<Value, InterpreterError> {
        self.run_loop_labeled(module)
            .map(|completion| completion.value)
    }

    fn run_loop_with_mode(
        &mut self,
        module: &Ir3Module,
        mode: RunLoopMode,
    ) -> Result<RunLoopExit, InterpreterError> {
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
            // Calls, exception unwinds, and generator activation swaps move
            // code identity with their execution context. Synthetic inline
            // wrappers keep their appended trampoline when their owner is the
            // active module; foreign frames use the retained original program.
            let active_program = self
                .current_module_specifier
                .as_deref()
                .filter(|specifier| *specifier != module.header.source_label)
                .and_then(|specifier| self.module_state.modules.get(specifier))
                .and_then(|record| record.compiled_module.clone());
            let module = active_program.as_deref().unwrap_or(module);
            if self.ip >= module.instructions.len() {
                // Fell off the end of the instruction stream.
                if !self.call_stack.is_empty() {
                    let generator_root =
                        matches!(mode, RunLoopMode::Generator | RunLoopMode::AsyncGenerator)
                            && self.call_stack.len() == 1;
                    if generator_root {
                        let _ = self.complete_return(
                            Value::Undefined,
                            crate::ifc_artifacts::Label::Public,
                        )?;
                        return Ok(RunLoopExit::GeneratorReturn {
                            value: Value::Undefined,
                            label: crate::ifc_artifacts::Label::Public,
                        });
                    }
                    if let Some(final_value) =
                        self.complete_return(Value::Undefined, crate::ifc_artifacts::Label::Public)?
                    {
                        return Ok(RunLoopExit::Value(final_value));
                    }
                    continue;
                } else {
                    return Ok(RunLoopExit::Value(LabeledReturn {
                        value: self.read_reg(0)?,
                        label: self.read_reg_label(0)?,
                    }));
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

            if matches!(
                &instr,
                Ir3Instruction::AsyncReturn { .. } | Ir3Instruction::AsyncThrow { .. }
            ) && self
                .call_stack
                .last()
                .and_then(|frame| frame.async_function_id)
                .is_none()
            {
                return Err(InterpreterError::TypeError {
                    expected: "async completion in an async activation".to_string(),
                    got: "async completion outside an async function".to_string(),
                });
            }

            match instr {
                Ir3Instruction::LoadInt { dst, value } => {
                    self.write_reg(dst, js_int_to_value(value))?;
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
                    let mut label = self.read_reg_label(src)?;
                    if let Some(object) = self.copy_data_properties_object_id(&value) {
                        label = label.join(&self.observe_property_structure(object, true));
                    }
                    let iterator = self.init_for_in_iterator(value)?;
                    self.write_reg_with_label(dst, iterator, label)?;
                    self.ip += 1;
                }
                Ir3Instruction::ForInNext {
                    iterator,
                    value_dst,
                    done_target,
                } => {
                    let label = self.read_reg_label(iterator)?;
                    let iterator = self.read_reg(iterator)?;
                    if let Some(value) = self.advance_for_in_iterator(iterator)? {
                        self.write_reg_with_label(value_dst, value, label)?;
                        self.ip += 1;
                    } else {
                        self.ip = done_target as usize;
                    }
                }
                Ir3Instruction::ForOfInit { src, dst } => {
                    let value = self.read_reg(src)?;
                    let mut label = self.read_reg_label(src)?;
                    match self.init_for_of_iterator(module, value, &mut label) {
                        Ok(iterator) => {
                            self.write_reg_with_label(dst, iterator, label)?;
                            self.ip += 1;
                        }
                        Err(error) => {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                    }
                }
                Ir3Instruction::ForOfNext {
                    iterator,
                    value_dst,
                    done_target,
                } => {
                    let iterator = self.read_reg(iterator)?;
                    let mut label = crate::ifc_artifacts::Label::Public;
                    match self.advance_for_of_iterator(module, iterator, &mut label) {
                        Ok(Some(value)) => {
                            self.write_reg_with_label(value_dst, value, label)?;
                            self.ip += 1;
                        }
                        Ok(None) => {
                            self.ip = done_target as usize;
                        }
                        Err(error) => {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                    }
                }
                Ir3Instruction::IteratorClose { iterator, reason } => {
                    let iterator = self.read_reg(iterator)?;
                    match self.close_iterator(module, iterator, reason) {
                        Ok(()) => self.ip += 1,
                        Err(error) => {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                    }
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

                    if !Self::is_sync_callable(&callee_val) {
                        let error = InterpreterError::TypeError {
                            expected: "function".into(),
                            got: callee_val.type_name().into(),
                        };
                        match self.route_run_loop_javascript_error(module, error, mode)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_val {
                        match self.dispatch_builtin_function(
                            module,
                            builtin,
                            None,
                            args,
                            callee_label.clone(),
                        ) {
                            Ok((result, result_label)) => {
                                self.write_reg_with_label(dst, result, result_label)?;
                                self.ip += 1;
                            }
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => {}
                                    Some(error) => return Err(error),
                                }
                            }
                        }
                        continue;
                    }

                    let owner_program = self.callable_module(&callee_val)?;
                    let module = owner_program.as_deref().unwrap_or(module);
                    // Resolve function index and optional captured environment.
                    let (func_idx, captured_env, _closure_id) = match &callee_val {
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

                    // Each async invocation owns an isolated activation. It runs
                    // synchronously to its first await, then returns its Promise
                    // without parking the caller's frames or instruction pointer.
                    if let Value::AsyncFunction(_) = &callee_val {
                        let func = module.function_table.get(func_idx as usize).ok_or(
                            InterpreterError::FunctionNotFound {
                                index: func_idx,
                                table_size: module.function_table.len() as u32,
                            },
                        )?;
                        self.validate_function_rest_param(func)?;
                        self.ensure_call_depth_available()?;

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
                        let setup_snapshot = self.snapshot_call_setup(Some(dst), false);
                        let setup_result = (|| -> Result<u32, InterpreterError> {
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
                            let (super_value, super_label) = if let Some(binding) =
                                self.concise_method_super_binding(&callee_val)?
                            {
                                binding
                            } else {
                                (
                                    self.method_super_value(&callee_val, &Value::Undefined)?,
                                    callee_label,
                                )
                            };
                            self.prepare_async_function_activation(
                                module,
                                AsyncCallSetup {
                                    function_index: func_idx,
                                    function_entry: func.entry,
                                    captured_env,
                                    arguments: arg_vals.into_iter().zip(arg_labels).collect(),
                                    this_value: Value::Undefined,
                                    this_label: crate::ifc_artifacts::Label::Public,
                                    super_value,
                                    super_label,
                                    result_register: dst,
                                },
                            )
                        })();
                        let async_function_id = match setup_result {
                            Ok(id) => id,
                            Err(error) => {
                                self.restore_call_setup(setup_snapshot);
                                return Err(error);
                            }
                        };
                        // Guest code can mutate the heap before its first await;
                        // the setup rollback must end before that code executes.
                        self.run_async_function_call(async_function_id, dst)?;
                        continue;
                    }

                    // Generator invocation initializes parameters immediately,
                    // then suspends the isolated activation at the explicit
                    // body boundary without running a body statement.
                    if let Value::GeneratorFunction(_) = &callee_val {
                        let func = module.function_table.get(func_idx as usize).ok_or(
                            InterpreterError::FunctionNotFound {
                                index: func_idx,
                                table_size: module.function_table.len() as u32,
                            },
                        )?;
                        self.validate_function_rest_param(func)?;
                        let function_entry = func.entry;
                        let mut argument_values = Vec::new();
                        let mut argument_labels = Vec::new();
                        for offset in 0..args.count {
                            let reg = args.start.checked_add(offset).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            argument_values.push(self.read_reg(reg)?);
                            argument_labels.push(self.read_reg_label(reg)?);
                        }
                        argument_values.truncate(func.arity as usize);
                        argument_labels.truncate(func.arity as usize);
                        // bd-ur3tk.22: `apply_rest_param` materializes the implicit
                        // rest Array on the shared heap before the pre-call hook runs,
                        // and `alloc_array_from_values` is not atomic on failure. Wrap
                        // rest materialization + the hook in the same setup transaction
                        // the ordinary call path uses (bd-ur3tk.12): on hook denial or a
                        // partial rest-carrier failure, `restore_call_setup` reclaims the
                        // unreachable carrier's heap, eager memory, and profiling
                        // accounting and drops its labeled taint. The transaction ends
                        // before `prepare_generator_activation`, whose isolated parameter
                        // prologue may produce language-visible heap side effects that
                        // must survive.
                        let setup_snapshot = self.snapshot_call_setup(None, false);
                        let setup_result = (|| -> Result<(), InterpreterError> {
                            self.apply_rest_param(
                                module,
                                &mut argument_values,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.apply_rest_param_labels(
                                &mut argument_labels,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.run_pre_call_hook(module, &callee_val, func_idx, &argument_values)
                        })();
                        if let Err(error) = setup_result {
                            self.restore_call_setup(setup_snapshot);
                            return Err(error);
                        }
                        let super_value =
                            self.function_super_value(&callee_val, IR_SUPER_PROTOTYPE_PROPERTY)?;
                        let generator = match self.prepare_generator_activation_inner(
                            module,
                            GeneratorCallSetup {
                                function_index: func_idx,
                                function_entry,
                                captured_env: captured_env.unwrap_or_default(),
                                arguments: argument_values
                                    .into_iter()
                                    .zip(argument_labels)
                                    .collect(),
                                this_value: Value::Undefined,
                                this_label: crate::ifc_artifacts::Label::Public,
                                super_value,
                                super_label: callee_label.clone(),
                            },
                            Some(setup_snapshot),
                        ) {
                            Ok(generator) => generator,
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        if let Err(error) = self.publish_generator(dst, generator) {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        self.ip += 1;
                        continue;
                    }

                    // Async generator function call: create a suspended AsyncGeneratorObject.
                    if let Value::AsyncGeneratorFunction(_) = &callee_val {
                        let func = module.function_table.get(func_idx as usize).ok_or(
                            InterpreterError::FunctionNotFound {
                                index: func_idx,
                                table_size: module.function_table.len() as u32,
                            },
                        )?;
                        self.validate_function_rest_param(func)?;
                        let mut argument_values = Vec::new();
                        let mut argument_labels = Vec::new();
                        for offset in 0..args.count {
                            let reg = args.start.checked_add(offset).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            argument_values.push(self.read_reg(reg)?);
                            argument_labels.push(self.read_reg_label(reg)?);
                        }
                        argument_values.truncate(func.arity as usize);
                        argument_labels.truncate(func.arity as usize);
                        // bd-ur3tk.22: transactional rest-carrier setup for the direct
                        // async-generator branch (see the direct sync-generator branch
                        // for the full rationale). Roll back the unreachable carrier on
                        // hook denial or partial rest materialization, before activation.
                        let setup_snapshot = self.snapshot_call_setup(None, false);
                        let setup_result = (|| -> Result<(), InterpreterError> {
                            self.apply_rest_param(
                                module,
                                &mut argument_values,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.apply_rest_param_labels(
                                &mut argument_labels,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.run_pre_call_hook(module, &callee_val, func_idx, &argument_values)
                        })();
                        if let Err(error) = setup_result {
                            self.restore_call_setup(setup_snapshot);
                            return Err(error);
                        }
                        let (super_value, super_label) = if let Some(binding) =
                            self.concise_method_super_binding(&callee_val)?
                        {
                            binding
                        } else {
                            (
                                self.function_super_value(
                                    &callee_val,
                                    IR_SUPER_PROTOTYPE_PROPERTY,
                                )?,
                                callee_label.clone(),
                            )
                        };
                        let generator = self.prepare_async_generator_activation(
                            module,
                            GeneratorCallSetup {
                                function_index: func_idx,
                                function_entry: func.entry,
                                captured_env: captured_env.unwrap_or_default(),
                                arguments: argument_values
                                    .into_iter()
                                    .zip(argument_labels)
                                    .collect(),
                                this_value: Value::Undefined,
                                this_label: crate::ifc_artifacts::Label::Public,
                                super_value,
                                super_label,
                            },
                            Some(setup_snapshot),
                        );
                        let generator = match generator {
                            Ok(generator) => generator,
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        self.publish_async_generator(dst, generator)?;
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
                                    if builtin_cap == "builtin:ObjectAssign" {
                                        let entered_accessor =
                                            self.execute_object_assign(module, args, dst)?;
                                        if !entered_accessor {
                                            self.ip += 1;
                                        }
                                        continue;
                                    }
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

                            self.ensure_call_depth_available()?;

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
                            let setup_snapshot = self.snapshot_call_setup(None, false);
                            let setup_result = (|| -> Result<(), InterpreterError> {
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
                                let is_concise_method = matches!(
                                    &callee_val,
                                    Value::Closure(closure_id)
                                        if self.closure_method_metadata.contains_key(closure_id)
                                );
                                let (call_this, call_this_label) = if is_concise_method {
                                    (Value::Undefined, crate::ifc_artifacts::Label::Public)
                                } else if captured_env.is_some() {
                                    (frame_this, frame_this_label)
                                } else {
                                    (Value::Undefined, crate::ifc_artifacts::Label::Public)
                                };
                                let (super_value, super_label) = if let Some(binding) =
                                    self.concise_method_super_binding(&callee_val)?
                                {
                                    binding
                                } else {
                                    (
                                        self.function_super_value(
                                            &callee_val,
                                            IR_SUPER_PROTOTYPE_PROPERTY,
                                        )?,
                                        callee_label,
                                    )
                                };

                                self.call_stack.push(CallFrame {
                                    return_ip: self.ip + 1,
                                    return_reg: Some(dst),
                                    register_base: self.register_base,
                                    function_index: Some(func_idx),
                                    this_value: call_this,
                                    saved_module_specifier: self.current_module_specifier.clone(),
                                    this_label: call_this_label,
                                    new_target_value: Value::Undefined,
                                    new_target_label: crate::ifc_artifacts::Label::Public,
                                    super_value,
                                    super_label,
                                    construct_this: None,
                                    derived_constructor: false,
                                    this_initialized: true,
                                    initialize_derived_this_on_return: false,
                                    saved_pending_exception: self.pending_exception.take(),
                                    saved_pending_return: self.pending_return.take(),
                                    saved_suspended_abrupt_depth: self
                                        .suspended_abrupt_completions
                                        .len(),
                                    saved_finally_mode_depth: self.finally_frames.len(),
                                    saved_scope_depth: scope_depth,
                                    saved_scope_chain: saved_chain,
                                    async_function_id: None,
                                    accessor_context_label: crate::ifc_artifacts::Label::Public,
                                });

                                // If calling a closure, restore its captured environment.
                                if let Some(env) = captured_env {
                                    self.scope_chain.frames = env;
                                }

                                // Push a fresh scope for the callee's locals.
                                if let Err(err) = self.scope_chain.push(self.config.max_scope_depth)
                                {
                                    self.rollback_call_setup();
                                    return Err(err);
                                }
                                if let Err(err) = self.sync_estimated_memory_bytes() {
                                    self.rollback_call_setup();
                                    return Err(err);
                                }

                                self.register_base += self.config.max_registers as usize;

                                // Clear all registers in the new frame to prevent data leakage from previous calls
                                let req_len =
                                    self.register_base + self.config.max_registers as usize;
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
                                self.current_module_specifier =
                                    Some(module.header.source_label.clone());
                                self.sync_estimated_memory_bytes()?;
                                Ok(())
                            })();
                            if let Err(error) = setup_result {
                                self.restore_call_setup(setup_snapshot);
                                return Err(error);
                            }
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

                    if !Self::is_sync_callable(&callee_val) {
                        let error = InterpreterError::TypeError {
                            expected: "function".into(),
                            got: callee_val.type_name().into(),
                        };
                        match self.route_run_loop_javascript_error(module, error, mode)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }

                    if let Value::BuiltinFunction(builtin) = &callee_val {
                        match self.dispatch_builtin_function(
                            module,
                            builtin,
                            Some(&receiver_val),
                            args,
                            receiver_label.join(&callee_label),
                        ) {
                            Ok((result, result_label)) => {
                                self.write_reg_with_label(dst, result, result_label)?;
                                self.ip += 1;
                            }
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => {}
                                    Some(error) => return Err(error),
                                }
                            }
                        }
                        continue;
                    }

                    let owner_program = self.callable_module(&callee_val)?;
                    let module = owner_program.as_deref().unwrap_or(module);
                    let (func_idx, captured_env, _closure_id) = match &callee_val {
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

                    let func = module.function_table.get(func_idx as usize).ok_or(
                        InterpreterError::FunctionNotFound {
                            index: func_idx,
                            table_size: module.function_table.len() as u32,
                        },
                    )?;

                    // Method invocation preserves its receiver in the isolated
                    // generator activation while defaults run synchronously.
                    if let Value::GeneratorFunction(_) = &callee_val {
                        self.validate_function_rest_param(func)?;
                        let function_entry = func.entry;
                        let mut argument_values = Vec::new();
                        let mut argument_labels = Vec::new();
                        for offset in 0..args.count {
                            let reg = args.start.checked_add(offset).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            argument_values.push(self.read_reg(reg)?);
                            argument_labels.push(self.read_reg_label(reg)?);
                        }
                        argument_values.truncate(func.arity as usize);
                        argument_labels.truncate(func.arity as usize);
                        // bd-ur3tk.22: transactional rest-carrier setup for the method
                        // sync-generator branch (see the direct sync-generator branch for
                        // the full rationale). Roll back the unreachable carrier on hook
                        // denial or partial rest materialization, before activation.
                        let setup_snapshot = self.snapshot_call_setup(None, false);
                        let setup_result = (|| -> Result<(), InterpreterError> {
                            self.apply_rest_param(
                                module,
                                &mut argument_values,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.apply_rest_param_labels(
                                &mut argument_labels,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.run_pre_call_hook(module, &callee_val, func_idx, &argument_values)
                        })();
                        if let Err(error) = setup_result {
                            self.restore_call_setup(setup_snapshot);
                            return Err(error);
                        }
                        let super_value = self.method_super_value(&callee_val, &receiver_val)?;
                        let generator = match self.prepare_generator_activation_inner(
                            module,
                            GeneratorCallSetup {
                                function_index: func_idx,
                                function_entry,
                                captured_env: captured_env.unwrap_or_default(),
                                arguments: argument_values
                                    .into_iter()
                                    .zip(argument_labels)
                                    .collect(),
                                this_value: receiver_val.clone(),
                                this_label: receiver_label.clone(),
                                super_value,
                                super_label: callee_label.clone(),
                            },
                            Some(setup_snapshot),
                        ) {
                            Ok(generator) => generator,
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        if let Err(error) = self.publish_generator(dst, generator) {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        self.ip += 1;
                        continue;
                    }

                    if let Value::AsyncGeneratorFunction(_) = &callee_val {
                        self.validate_function_rest_param(func)?;
                        let mut argument_values = Vec::new();
                        let mut argument_labels = Vec::new();
                        for offset in 0..args.count {
                            let reg = args.start.checked_add(offset).ok_or(
                                InterpreterError::RegisterOutOfBounds {
                                    register: args.start,
                                    max: self.config.max_registers,
                                },
                            )?;
                            argument_values.push(self.read_reg(reg)?);
                            argument_labels.push(self.read_reg_label(reg)?);
                        }
                        argument_values.truncate(func.arity as usize);
                        argument_labels.truncate(func.arity as usize);
                        // bd-ur3tk.22: transactional rest-carrier setup for the method
                        // async-generator branch (see the direct sync-generator branch
                        // for the full rationale). Roll back the unreachable carrier on
                        // hook denial or partial rest materialization, before activation.
                        let setup_snapshot = self.snapshot_call_setup(None, false);
                        let setup_result = (|| -> Result<(), InterpreterError> {
                            self.apply_rest_param(
                                module,
                                &mut argument_values,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.apply_rest_param_labels(
                                &mut argument_labels,
                                func.rest_param_index,
                                func.arity,
                                args,
                            )?;
                            self.run_pre_call_hook(module, &callee_val, func_idx, &argument_values)
                        })();
                        if let Err(error) = setup_result {
                            self.restore_call_setup(setup_snapshot);
                            return Err(error);
                        }
                        let (super_value, super_label) = if let Some(binding) =
                            self.concise_method_super_binding(&callee_val)?
                        {
                            binding
                        } else {
                            (
                                self.method_super_value(&callee_val, &receiver_val)?,
                                callee_label.clone(),
                            )
                        };
                        let generator = self.prepare_async_generator_activation(
                            module,
                            GeneratorCallSetup {
                                function_index: func_idx,
                                function_entry: func.entry,
                                captured_env: captured_env.unwrap_or_default(),
                                arguments: argument_values
                                    .into_iter()
                                    .zip(argument_labels)
                                    .collect(),
                                this_value: receiver_val.clone(),
                                this_label: receiver_label.clone(),
                                super_value,
                                super_label,
                            },
                            Some(setup_snapshot),
                        );
                        let generator = match generator {
                            Ok(generator) => generator,
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        };
                        self.publish_async_generator(dst, generator)?;
                        self.ip += 1;
                        continue;
                    }

                    self.validate_function_rest_param(func)?;

                    self.ensure_call_depth_available()?;

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
                    let setup_snapshot = self.snapshot_call_setup(Some(dst), false);
                    let setup_result = (|| -> Result<Option<u32>, InterpreterError> {
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

                        let context_label = receiver_label.join(&callee_label);
                        let (super_value, super_label) = if let Some(binding) =
                            self.concise_method_super_binding(&callee_val)?
                        {
                            binding
                        } else {
                            (
                                self.method_super_value(&callee_val, &receiver_val)?,
                                callee_label,
                            )
                        };
                        if matches!(&callee_val, Value::AsyncFunction(_)) {
                            let id = self.prepare_async_function_activation(
                                module,
                                AsyncCallSetup {
                                    function_index: func_idx,
                                    function_entry: func.entry,
                                    captured_env,
                                    arguments: arg_vals.into_iter().zip(arg_labels).collect(),
                                    this_value: receiver_val,
                                    this_label: receiver_label,
                                    super_value,
                                    super_label,
                                    result_register: dst,
                                },
                            )?;
                            return Ok(Some(id));
                        }

                        let scope_depth = self.scope_chain.depth();
                        let captured_env_bytes = captured_env
                            .as_ref()
                            .map(|env| Self::estimate_scope_chain_bytes(env))
                            .unwrap_or(0);
                        let saved_chain =
                            if captured_env.is_some() {
                                Some(self.snapshot_scope_chain_with_temporary_budget(
                                    captured_env_bytes,
                                )?)
                            } else {
                                None
                            };
                        self.call_stack.push(CallFrame {
                            return_ip: self.ip + 1,
                            return_reg: Some(dst),
                            register_base: self.register_base,
                            function_index: Some(func_idx),
                            this_value: receiver_val,
                            saved_module_specifier: self.current_module_specifier.clone(),
                            this_label: receiver_label,
                            new_target_value: Value::Undefined,
                            new_target_label: crate::ifc_artifacts::Label::Public,
                            super_value,
                            super_label,
                            construct_this: None,
                            derived_constructor: false,
                            this_initialized: true,
                            initialize_derived_this_on_return: false,
                            saved_pending_exception: self.pending_exception.take(),
                            saved_pending_return: self.pending_return.take(),
                            saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
                            saved_finally_mode_depth: self.finally_frames.len(),
                            saved_scope_depth: scope_depth,
                            saved_scope_chain: saved_chain,
                            async_function_id: None,
                            accessor_context_label: context_label,
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
                        self.current_module_specifier = Some(module.header.source_label.clone());
                        self.sync_estimated_memory_bytes()?;
                        Ok(None)
                    })();
                    match setup_result {
                        Ok(Some(id)) => {
                            self.run_async_function_call(id, dst)?;
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            self.restore_call_setup(setup_snapshot);
                            return Err(error);
                        }
                    }
                }
                Ir3Instruction::Return { value }
                | Ir3Instruction::AsyncReturn { value_reg: value } => {
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
                        let generator_root =
                            matches!(mode, RunLoopMode::Generator | RunLoopMode::AsyncGenerator)
                                && self.call_stack.len() == 1;
                        if generator_root {
                            let completed_value = return_val.clone();
                            let completed_label = return_label.clone();
                            let _ = self.complete_return(return_val, return_label)?;
                            return Ok(RunLoopExit::GeneratorReturn {
                                value: completed_value,
                                label: completed_label,
                            });
                        }
                        match self.complete_return(return_val, return_label) {
                            Ok(Some(final_value)) => {
                                return Ok(RunLoopExit::Value(final_value));
                            }
                            Ok(None) => {}
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => continue,
                                    Some(error) => return Err(error),
                                }
                            }
                        }
                    }
                }
                Ir3Instruction::HostCall {
                    capability,
                    args,
                    dst,
                } => {
                    // Promise hostcalls are internal only when the complete
                    // tag is in the closed classifier above. The prefix is
                    // used solely to select the result-label dispatch path
                    // after the capability gate succeeds.
                    let is_promise_cap = capability.0.starts_with("promise:");
                    let resuming_object_assign = capability.0 == "builtin:ObjectAssign"
                        && self
                            .copy_data_properties_states
                            .last()
                            .is_some_and(|state| {
                                state.belongs_to(self.ip, self.register_base, self.call_stack.len())
                                    && matches!(
                                        state.write_mode,
                                        CopyDataPropertiesWriteMode::Set { .. }
                                    )
                            });

                    if !resuming_object_assign {
                        // Keep attacker-controlled evidence bounded while
                        // committing the complete pre-shortening tag. Dispatch
                        // below still uses the original capability string.
                        let gate_key = capability_gate_key(&capability.0);
                        let recordable_tag = recordable_capability_tag(gate_key);

                        let allowed = match classify_hostcall_capability(gate_key) {
                            HostcallCapabilityClass::Runtime(required) => {
                                self.config.granted_capabilities.contains(&required)
                            }
                            HostcallCapabilityClass::InternalAllowed => true,
                            HostcallCapabilityClass::Unknown => false,
                        };

                        if !allowed {
                            self.emit_witness(
                                WitnessEventKind::CapabilityChecked,
                                Some(&format!("denied:{recordable_tag}")),
                            );
                            self.hostcall_decisions.push(HostcallDecisionRecord {
                                seq: self.hostcall_decisions.len() as u64,
                                capability: crate::ir_contract::CapabilityTag(
                                    recordable_tag.clone().into_owned(),
                                ),
                                allowed: false,
                                instruction_index: self.ip as u32,
                            });
                            return Err(InterpreterError::CapabilityDenied {
                                capability: recordable_tag.into_owned(),
                            });
                        }

                        self.emit_witness(
                            WitnessEventKind::HostcallDispatched,
                            Some(&format!("cap:{recordable_tag}")),
                        );
                        self.emit_witness(
                            WitnessEventKind::CapabilityChecked,
                            Some(&format!("granted:{recordable_tag}")),
                        );

                        self.hostcall_decisions.push(HostcallDecisionRecord {
                            seq: self.hostcall_decisions.len() as u64,
                            capability: crate::ir_contract::CapabilityTag(
                                recordable_tag.into_owned(),
                            ),
                            allowed: true,
                            instruction_index: self.ip as u32,
                        });
                    }

                    if capability.0 == "builtin:ObjectLiteralSetPrototype" {
                        match self.initialize_object_literal_prototype(args) {
                            Ok((result, label)) => {
                                self.write_reg_with_label(dst, result, label)?;
                                self.ip += 1;
                            }
                            Err(error) => {
                                if let Some(error) =
                                    self.route_run_loop_javascript_error(module, error, mode)?
                                {
                                    return Err(error);
                                }
                            }
                        }
                        continue;
                    }

                    let array_mutator = match capability.0.as_str() {
                        "builtin:ArrayPrototypePush" => {
                            Some(BuiltinFunctionKind::ArrayPrototypePush)
                        }
                        "builtin:ArrayPrototypePop" => Some(BuiltinFunctionKind::ArrayPrototypePop),
                        _ => None,
                    };
                    if let Some(kind) = array_mutator {
                        let receiver = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                        let receiver_label = if args.count == 0 {
                            crate::ifc_artifacts::Label::Public
                        } else {
                            self.read_reg_label(args.start)?
                        };
                        let remaining = RegRange {
                            start: args.start.saturating_add(u32::from(args.count > 0)),
                            count: args.count.saturating_sub(1),
                        };
                        match self.dispatch_array_method(
                            module,
                            kind,
                            Some(&receiver),
                            remaining,
                            receiver_label,
                        ) {
                            Ok((result, label)) => {
                                self.write_reg_with_label(dst, result, label)?;
                                self.ip += 1;
                            }
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => {}
                                    Some(error) => return Err(error),
                                }
                            }
                        }
                        continue;
                    }
                    if Self::is_descriptor_enumeration(&capability.0) {
                        match self.dispatch_descriptor_enumeration(module, &capability.0, args) {
                            Ok((result, label)) => {
                                self.write_reg_with_label(dst, result, label)?;
                                self.ip += 1;
                            }
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => {}
                                    Some(error) => return Err(error),
                                }
                            }
                        }
                        continue;
                    }
                    if let Some(kind) = Self::descriptor_builtin_kind(&capability.0) {
                        match self.dispatch_descriptor_builtin(
                            module,
                            kind,
                            args,
                            crate::ifc_artifacts::Label::Public,
                        ) {
                            Ok((result, label)) => {
                                self.write_reg_with_label(dst, result, label)?;
                                self.ip += 1;
                            }
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => {}
                                    Some(error) => return Err(error),
                                }
                            }
                        }
                        continue;
                    }
                    if let Some(result) = Self::descriptor_factory_value(&capability.0) {
                        self.write_reg(dst, result)?;
                        self.ip += 1;
                        continue;
                    }

                    if capability.0 == "builtin:ObjectAssign" {
                        match self.execute_object_assign(module, args, dst) {
                            Ok(false) => self.ip += 1,
                            Ok(true) => {}
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => {}
                                    Some(error) => return Err(error),
                                }
                            }
                        }
                        continue;
                    }

                    if capability.0 == "builtin:ConstructSuperSpread" {
                        if let Err(error) = self.enter_super_spread_call(module, args, dst) {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        // Constructor return binds the derived receiver and
                        // resumes at this hostcall's successor. Its frame owns
                        // the result destination until then.
                        continue;
                    }

                    // Promise hostcalls return an explicit label for their
                    // Promise-handle result.  Keep this separate from generic
                    // hostcalls, whose current contract remains Public.
                    if is_promise_cap {
                        let outcome = if capability.0 == "promise:constructor" && args.count > 0 {
                            self.construct_promise(module, args)
                        } else {
                            self.dispatch_promise_hostcall(module, &capability.0, args)
                        };
                        match outcome {
                            Ok((result, result_label)) => {
                                self.write_reg_with_label(dst, result, result_label)?;
                                self.ip += 1;
                            }
                            Err(error) => {
                                match self.route_run_loop_javascript_error(module, error, mode)? {
                                    None => {}
                                    Some(error) => return Err(error),
                                }
                            }
                        }
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
                    check_module_load_capability_gate(self, self.ip as u32)?;
                    let spec_val = self.read_reg(specifier)?;
                    let specifier = match spec_val {
                        Value::Str(s) => s,
                        other => {
                            return Err(InterpreterError::ImportSpecifierNotString {
                                got: other.type_name().to_string(),
                            });
                        }
                    };
                    let namespace = self.import_module(module, &specifier)?;
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
                    let read_label = self.read_reg_label(obj)?.join(&self.read_reg_label(key)?);
                    let property_key = Self::executable_property_key(&key_val);
                    self.validate_executable_property_key(&property_key)?;

                    let called_accessor = match &obj_val {
                        Value::Object(oid) => self.load_object_property_or_call_accessor(
                            module,
                            obj_val.clone(),
                            *oid,
                            &property_key,
                            dst,
                            read_label.clone(),
                        )?,
                        // String receivers expose `length` (UTF-16 code-unit
                        // count) and the String.prototype methods wired for
                        // bd-2vzgi; unknown keys yield `undefined` per ES
                        // GetV semantics, matching the engine (bd-7zwar —
                        // previously a fail-closed TypeError).
                        Value::Str(text) => {
                            self.preflight_legacy_property_key_for_hook(&property_key)?;
                            match &property_key {
                                RuntimePropertyKey::String(key) => {
                                    match key
                                        .as_str()
                                        .and_then(|key| Self::string_property_value(text, key))
                                    {
                                        Some(value) => {
                                            self.write_reg(dst, value)?;
                                            false
                                        }
                                        None => {
                                            self.write_reg(dst, Value::Undefined)?;
                                            false
                                        }
                                    }
                                }
                                RuntimePropertyKey::Symbol(_) => {
                                    self.write_reg(dst, Value::Undefined)?;
                                    false
                                }
                            }
                        }
                        Value::Symbol(symbol) => {
                            self.preflight_legacy_property_key_for_hook(&property_key)?;
                            match self.symbol_property_value(*symbol, &property_key) {
                                Some(value) => {
                                    self.write_reg(dst, value)?;
                                    false
                                }
                                None => {
                                    self.write_reg(dst, Value::Undefined)?;
                                    false
                                }
                            }
                        }
                        Value::Generator(_) => {
                            self.preflight_legacy_property_key_for_hook(&property_key)?;
                            let value = match &property_key {
                                RuntimePropertyKey::String(key) if key.as_str() == Some("next") => {
                                    Value::BuiltinFunction(BuiltinFunction::generator_next())
                                }
                                RuntimePropertyKey::String(_) | RuntimePropertyKey::Symbol(_) => {
                                    Value::Undefined
                                }
                            };
                            self.write_reg(dst, value)?;
                            false
                        }
                        Value::AsyncGeneratorObject(_) => {
                            self.preflight_legacy_property_key_for_hook(&property_key)?;
                            let kind = match &property_key {
                                RuntimePropertyKey::String(key) => match key.as_str() {
                                    Some("next") => {
                                        Some(BuiltinFunctionKind::AsyncGeneratorPrototypeNext)
                                    }
                                    Some("return") => {
                                        Some(BuiltinFunctionKind::AsyncGeneratorPrototypeReturn)
                                    }
                                    Some("throw") => {
                                        Some(BuiltinFunctionKind::AsyncGeneratorPrototypeThrow)
                                    }
                                    _ => None,
                                },
                                RuntimePropertyKey::Symbol(symbol)
                                    if *symbol == WellKnownSymbol::AsyncIterator.id() =>
                                {
                                    Some(BuiltinFunctionKind::AsyncIteratorPrototypeAsyncIterator)
                                }
                                RuntimePropertyKey::Symbol(_) => None,
                            };
                            let value = kind.map_or(Value::Undefined, |kind| {
                                Value::BuiltinFunction(BuiltinFunction::promise_method(kind))
                            });
                            let label = self.read_reg_label(obj)?.join(&self.read_reg_label(key)?);
                            self.write_reg_with_label(dst, value, label)?;
                            false
                        }
                        Value::Promise(_) => {
                            self.preflight_legacy_property_key_for_hook(&property_key)?;
                            let kind = match &property_key {
                                RuntimePropertyKey::String(key) => match key.as_str() {
                                    Some("then") => Some(BuiltinFunctionKind::PromisePrototypeThen),
                                    Some("catch") => {
                                        Some(BuiltinFunctionKind::PromisePrototypeCatch)
                                    }
                                    Some("finally") => {
                                        Some(BuiltinFunctionKind::PromisePrototypeFinally)
                                    }
                                    _ => None,
                                },
                                RuntimePropertyKey::Symbol(_) => None,
                            };
                            let value = kind.map_or(Value::Undefined, |kind| {
                                Value::BuiltinFunction(BuiltinFunction::promise_method(kind))
                            });
                            let label = self.read_reg_label(obj)?.join(&self.read_reg_label(key)?);
                            self.write_reg_with_label(dst, value, label)?;
                            false
                        }
                        _ if Self::function_object_key(&obj_val).is_some() => self
                            .load_function_like_property_or_call_accessor(
                                module,
                                obj_val.clone(),
                                &property_key,
                                dst,
                                read_label.clone(),
                            )?,
                        _ => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: obj_val.type_name().to_string(),
                            });
                        }
                    };
                    // Object reads apply their labels before entering a getter;
                    // caller register numbers are no longer valid in that frame.
                    if !called_accessor {
                        self.ip += 1;
                    }
                }
                Ir3Instruction::SetProperty { obj, key, val }
                | Ir3Instruction::SetPropertyStrict { obj, key, val } => {
                    let strict = matches!(instr, Ir3Instruction::SetPropertyStrict { .. });
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let set_val = self.read_reg(val)?;
                    let mut value_label = self
                        .read_reg_label(val)?
                        .join(&self.read_reg_label(obj)?)
                        .join(&self.read_reg_label(key)?);
                    let property_key = Self::executable_property_key(&key_val);
                    self.validate_executable_property_key(&property_key)?;

                    let outcome = self
                        .set_property_for_instruction(
                            module,
                            &obj_val,
                            obj_val.clone(),
                            property_key,
                            set_val,
                            &mut value_label,
                        )
                        .and_then(|accepted| {
                            if strict && !accepted {
                                Err(Self::property_mutation_refused("assignment"))
                            } else {
                                Ok(())
                            }
                        });
                    match outcome {
                        Ok(()) => self.ip += 1,
                        Err(error) => {
                            let error = self.preserve_property_error_label(error, value_label)?;
                            if let Some(error) =
                                self.route_run_loop_javascript_error(module, error, mode)?
                            {
                                return Err(error);
                            }
                        }
                    }
                }
                Ir3Instruction::GetPropertyWithReceiver {
                    obj,
                    key,
                    receiver,
                    dst,
                } => {
                    let base = self.read_reg(obj)?;
                    let receiver_value = self.read_reg(receiver)?;
                    let property_key = Self::executable_property_key(&self.read_reg(key)?);
                    self.validate_executable_property_key(&property_key)?;
                    let object_id = match base {
                        Value::Object(id) => Some(id),
                        ref function if Self::function_object_key(function).is_some() => {
                            self.function_object_id(function)
                        }
                        other => {
                            return Err(InterpreterError::TypeError {
                                expected: "object super base".into(),
                                got: other.type_name().into(),
                            });
                        }
                    };
                    let mut label = self
                        .read_reg_label(obj)?
                        .join(&self.read_reg_label(key)?)
                        .join(&self.read_reg_label(receiver)?);
                    let property = if let Some(id) = object_id {
                        self.run_pre_runtime_property_access_hook(module, id, &property_key)?;
                        label = label.join(&self.runtime_property_label(id, &property_key));
                        self.prototype_chain_lookup_runtime_property(id, &property_key)?
                    } else {
                        None
                    };
                    if !self.load_runtime_property(module, receiver_value, property, dst, label)? {
                        self.ip += 1;
                    }
                }
                Ir3Instruction::SetPropertyWithReceiver {
                    obj,
                    key,
                    receiver,
                    val,
                }
                | Ir3Instruction::SetPropertyWithReceiverStrict {
                    obj,
                    key,
                    receiver,
                    val,
                } => {
                    let strict =
                        matches!(instr, Ir3Instruction::SetPropertyWithReceiverStrict { .. });
                    let base = self.read_reg(obj)?;
                    let receiver_value = self.read_reg(receiver)?;
                    let property_key = Self::executable_property_key(&self.read_reg(key)?);
                    self.validate_executable_property_key(&property_key)?;
                    let mut label = self
                        .read_reg_label(obj)?
                        .join(&self.read_reg_label(key)?)
                        .join(&self.read_reg_label(receiver)?)
                        .join(&self.read_reg_label(val)?);
                    let value = self.read_reg(val)?;
                    let outcome = self
                        .set_property_for_instruction(
                            module,
                            &base,
                            receiver_value,
                            property_key,
                            value,
                            &mut label,
                        )
                        .and_then(|accepted| {
                            if strict && !accepted {
                                Err(Self::property_mutation_refused("assignment"))
                            } else {
                                Ok(())
                            }
                        });
                    match outcome {
                        Ok(()) => self.ip += 1,
                        Err(error) => {
                            let error = self.preserve_property_error_label(error, label)?;
                            if let Some(error) =
                                self.route_run_loop_javascript_error(module, error, mode)?
                            {
                                return Err(error);
                            }
                        }
                    }
                }
                Ir3Instruction::DefineMethod { obj, key, func }
                | Ir3Instruction::DefineAccessor { obj, key, func, .. } => {
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let func_val = self.read_reg(func)?;
                    let property_key = Self::executable_property_key(&key_val);
                    self.validate_executable_property_key(&property_key)?;
                    let definition_label = self
                        .read_reg_label(obj)?
                        .join(&self.read_reg_label(key)?)
                        .join(&self.read_reg_label(func)?);

                    match obj_val {
                        Value::Object(object_id) => {
                            self.run_pre_runtime_property_access_hook(
                                module,
                                object_id,
                                &property_key,
                            )?;
                            match instr {
                                Ir3Instruction::DefineAccessor { kind, .. } => {
                                    self.define_accessor_property(
                                        object_id,
                                        property_key,
                                        func_val,
                                        kind,
                                        definition_label,
                                    )?;
                                }
                                _ => self.define_method_property(
                                    object_id,
                                    property_key,
                                    func_val,
                                    definition_label,
                                )?,
                            }
                        }
                        other => {
                            return Err(InterpreterError::TypeError {
                                expected: "object".to_string(),
                                got: other.type_name().to_string(),
                            });
                        }
                    }
                    self.ip += 1;
                }
                Ir3Instruction::DeleteProperty { obj, key, dst }
                | Ir3Instruction::DeletePropertyStrict { obj, key, dst } => {
                    let strict = matches!(instr, Ir3Instruction::DeletePropertyStrict { .. });
                    let obj_val = self.read_reg(obj)?;
                    let key_val = self.read_reg(key)?;
                    let property_key = Self::executable_property_key(&key_val);
                    self.validate_executable_property_key(&property_key)?;

                    let mut label = self.read_reg_label(obj)?.join(&self.read_reg_label(key)?);
                    let outcome = (|| -> Result<bool, InterpreterError> {
                        let accepted = if let Some(object) =
                            self.property_mutation_target(&obj_val)?
                        {
                            self.materialize_function_descriptor(&obj_val, object, &property_key)?;
                            self.run_pre_runtime_property_access_hook(
                                module,
                                object,
                                &property_key,
                            )?;
                            label = label
                                .join(&self.runtime_property_label(object, &property_key))
                                .join(&self.observe_property_structure(object, false));
                            self.delete_own_runtime_property(object, &property_key)?
                        } else {
                            // String wrapper indices and length are the only
                            // non-configurable own properties on primitives.
                            !matches!((&obj_val, &property_key), (Value::Str(text), RuntimePropertyKey::String(key))
                                if key.as_str() == Some("length")
                                    || key.as_str().and_then(canonical_array_index)
                                        .is_some_and(|index| (index as usize) < text.utf16_len()))
                        };
                        if strict && !accepted {
                            Err(Self::property_mutation_refused("deletion"))
                        } else {
                            Ok(accepted)
                        }
                    })();
                    match outcome {
                        Ok(accepted) => {
                            self.write_reg_with_label(dst, Value::Bool(accepted), label)?;
                            self.ip += 1;
                        }
                        Err(error) => {
                            let error = self.preserve_property_error_label(error, label)?;
                            if let Some(error) =
                                self.route_run_loop_javascript_error(module, error, mode)?
                            {
                                return Err(error);
                            }
                        }
                    }
                }
                Ir3Instruction::DefineOwnProperty {
                    obj,
                    key,
                    val,
                    enumerable,
                    infer_name,
                    accessor_kind,
                } => {
                    let target = self.read_reg(obj)?;
                    let value = self.read_reg(val)?;
                    let key_label = self.read_reg_label(key)?;
                    let key = Self::executable_property_key(&self.read_reg(key)?);
                    self.validate_executable_property_key(&key)?;
                    let mut label = self
                        .read_reg_label(obj)?
                        .join(&self.read_reg_label(val)?)
                        .join(&key_label);
                    let outcome = (|| -> Result<(), InterpreterError> {
                        let object = self.property_mutation_target(&target)?.ok_or_else(|| {
                            InterpreterError::TypeError {
                                expected: "object for own property definition".into(),
                                got: target.type_name().into(),
                            }
                        })?;
                        self.run_pre_runtime_property_access_hook(module, object, &key)?;
                        label = label.join(&self.observe_property_structure(object, false));
                        if infer_name {
                            self.set_function_name_from_property_key(&value, &key)?;
                        }
                        let accepted = if let Some(kind) = accessor_kind {
                            self.define_own_accessor_runtime_property(
                                object,
                                key,
                                value,
                                kind,
                                label.clone(),
                                enumerable,
                            )?
                        } else {
                            self.define_own_data_runtime_property(
                                object,
                                key,
                                value,
                                label.clone(),
                                enumerable,
                            )?
                        };
                        if accepted {
                            Ok(())
                        } else {
                            Err(Self::property_mutation_refused("definition"))
                        }
                    })();
                    match outcome {
                        Ok(()) => self.ip += 1,
                        Err(error) => {
                            let error = self.preserve_property_error_label(error, label)?;
                            if let Some(error) =
                                self.route_run_loop_javascript_error(module, error, mode)?
                            {
                                return Err(error);
                            }
                        }
                    }
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
                    let value = self.read_reg(element)?;
                    let label = self.read_reg_label(element)?;
                    match self.append_array_literal_element(array, value, label) {
                        Ok(()) => self.ip += 1,
                        Err(error) => {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                    }
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
                        if matches!(obj.properties.get("length"), Some(Value::Symbol(_))) {
                            return Err(InterpreterError::TypeError {
                                expected: "array length coercible to number".to_string(),
                                got: "symbol".to_string(),
                            });
                        }
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
                    match self.spread_into_array(module, array, iterable) {
                        Ok(()) => self.ip += 1,
                        Err(error) => {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                    }
                }
                Ir3Instruction::SpreadIntoObject { target, source } => {
                    let state_was_active =
                        self.copy_data_properties_states
                            .last()
                            .is_some_and(|state| {
                                state.belongs_to(self.ip, self.register_base, self.call_stack.len())
                            });
                    let original_source = state_was_active.then(|| {
                        self.copy_data_properties_states
                            .last()
                            .expect("active spread copy state should exist")
                            .source
                            .clone()
                    });
                    if !state_was_active && self.read_reg(source)?.is_nullish() {
                        self.ip += 1;
                        continue;
                    }
                    let entered_getter = self.execute_copy_data_properties(
                        module,
                        target,
                        source,
                        RegRange { start: 0, count: 0 },
                        source,
                        CopyDataPropertiesWriteMode::CreateData,
                    )?;
                    if !entered_getter {
                        if let Some(original_source) = original_source {
                            self.write_reg(source, original_source)?;
                        }
                        self.ip += 1;
                    }
                }
                Ir3Instruction::CopyDataProperties {
                    target,
                    source,
                    excluded,
                    value_dst,
                } => {
                    let entered_getter = self.execute_copy_data_properties(
                        module,
                        target,
                        source,
                        excluded,
                        value_dst,
                        CopyDataPropertiesWriteMode::CreateData,
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
                    let result = self.eval_in_operator(module, lhs, rhs)?;
                    let mut label = self.read_reg_label(lhs)?.join(&self.read_reg_label(rhs)?);
                    if let Some(object) = self.copy_data_properties_object_id(&self.read_reg(rhs)?)
                    {
                        label = label.join(&self.observe_property_structure(object, true));
                    }
                    self.write_reg_with_label(dst, result, label)?;
                    self.ip += 1;
                }
                Ir3Instruction::RegisterDerivedConstructor {
                    constructor,
                    parent,
                    default_constructor,
                } => {
                    let constructor = self.read_reg(constructor)?;
                    let parent_value = self.read_reg(parent)?;
                    let parent_label = self.read_reg_label(parent)?;
                    self.register_derived_constructor_metadata(
                        &constructor,
                        parent_value,
                        parent_label,
                        default_constructor,
                    )?;
                    self.ip += 1;
                }
                Ir3Instruction::ConstructSuper { args, dst } => {
                    if let Err(error) = self.enter_super_constructor_call(
                        module,
                        ConstructorArguments::Registers(args),
                        dst,
                    ) {
                        match self.route_run_loop_javascript_error(module, error, mode)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                }
                Ir3Instruction::ConstructWithNewTarget {
                    callee,
                    new_target,
                    args,
                    dst,
                } => {
                    let callee_value = self.read_reg(callee)?;
                    let callee_label = self.read_reg_label(callee)?;
                    let new_target_value = self.read_reg(new_target)?;
                    let new_target_label = self.read_reg_label(new_target)?;

                    if self.function_prototype_for_value(&callee_value)?.is_none() {
                        return Err(InterpreterError::TypeError {
                            expected: "constructible Reflect.construct target".to_string(),
                            got: callee_value.type_name().to_string(),
                        });
                    }
                    if self
                        .function_prototype_for_value(&new_target_value)?
                        .is_none()
                    {
                        return Err(InterpreterError::TypeError {
                            expected: "constructible Reflect.construct newTarget".to_string(),
                            got: new_target_value.type_name().to_string(),
                        });
                    }

                    if let Err(error) = self.enter_constructor_call(
                        module,
                        callee_value,
                        callee_label,
                        ConstructorArguments::Registers(args),
                        self.ip + 1,
                        Some(dst),
                        new_target_value,
                        new_target_label,
                        false,
                    ) {
                        match self.route_run_loop_javascript_error(module, error, mode)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                }
                Ir3Instruction::Construct { callee, args, dst } => {
                    let callee_val = self.read_reg(callee)?;
                    let callee_label = self.read_reg_label(callee)?;
                    let owner_program = self.callable_module(&callee_val)?;
                    let module = owner_program.as_deref().unwrap_or(module);

                    let (is_derived, is_default_derived) =
                        if matches!(&callee_val, Value::Function(_) | Value::Closure(_)) {
                            let (derived, default_derived, _, _) =
                                self.derived_constructor_metadata(&callee_val)?;
                            (derived, default_derived)
                        } else {
                            (false, false)
                        };
                    if is_derived || is_default_derived {
                        if let Err(error) = self.enter_constructor_call(
                            module,
                            callee_val.clone(),
                            callee_label.clone(),
                            ConstructorArguments::Registers(args),
                            self.ip + 1,
                            Some(dst),
                            callee_val,
                            callee_label,
                            false,
                        ) {
                            match self.route_run_loop_javascript_error(module, error, mode)? {
                                None => continue,
                                Some(error) => return Err(error),
                            }
                        }
                        continue;
                    }

                    // Resolve function index and optional captured environment.
                    let (func_idx, captured_env) = match &callee_val {
                        Value::Function(idx) => (*idx, None),
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

                            self.ensure_call_depth_available()?;

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
                            let setup_snapshot = self.snapshot_call_setup(None, true);
                            let setup_result = (|| -> Result<(), InterpreterError> {
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
                                    saved_module_specifier: self.current_module_specifier.clone(),
                                    this_label: callee_label.clone(),
                                    new_target_value: callee_val.clone(),
                                    new_target_label: callee_label.clone(),
                                    super_value,
                                    super_label: callee_label,
                                    construct_this: Some(this_val.clone()),
                                    derived_constructor: false,
                                    this_initialized: true,
                                    initialize_derived_this_on_return: false,
                                    saved_pending_exception: self.pending_exception.take(),
                                    saved_pending_return: self.pending_return.take(),
                                    saved_suspended_abrupt_depth: self
                                        .suspended_abrupt_completions
                                        .len(),
                                    saved_finally_mode_depth: self.finally_frames.len(),
                                    saved_scope_depth: scope_depth,
                                    saved_scope_chain: saved_chain,
                                    async_function_id: None,
                                    accessor_context_label: crate::ifc_artifacts::Label::Public,
                                });

                                // If calling a closure, restore its captured environment.
                                if let Some(env) = captured_env {
                                    self.scope_chain.frames = env;
                                }
                                if let Err(err) = self.scope_chain.push(self.config.max_scope_depth)
                                {
                                    self.rollback_call_setup();
                                    return Err(err);
                                }
                                if let Err(err) = self.sync_estimated_memory_bytes() {
                                    self.rollback_call_setup();
                                    return Err(err);
                                }

                                self.register_base += self.config.max_registers as usize;
                                let req_len =
                                    self.register_base + self.config.max_registers as usize;
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
                                self.current_module_specifier =
                                    Some(module.header.source_label.clone());
                                self.sync_estimated_memory_bytes()?;
                                Ok(())
                            })();
                            if let Err(error) = setup_result {
                                self.restore_call_setup(setup_snapshot);
                                return Err(error);
                            }
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
                            Value::Symbol(_) => {
                                return Err(InterpreterError::TypeError {
                                    expected: "template substitution coercible to string"
                                        .to_string(),
                                    got: "symbol".to_string(),
                                });
                            }
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
                    if self
                        .call_stack
                        .last()
                        .is_some_and(|frame| frame.derived_constructor && !frame.this_initialized)
                    {
                        let error = InterpreterError::UninitializedBinding {
                            name: "this".to_string(),
                        };
                        match self.route_run_loop_javascript_error(module, error, mode)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
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
                        catch_is_finally: finally_target == Some(catch_target)
                            || matches!(
                                module.instructions.get(catch_target as usize),
                                Some(Ir3Instruction::EnterFinally)
                            ),
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
                Ir3Instruction::Throw { value }
                | Ir3Instruction::AsyncThrow { error_reg: value } => {
                    let thrown = self.read_reg(value)?;
                    let thrown_label = self.read_reg_label(value)?;
                    let exception = LabeledException {
                        value: thrown.clone(),
                        label: thrown_label,
                    };
                    self.suspend_current_abrupt_completion();
                    self.pending_return = None;
                    self.pending_exception = Some(exception.clone());
                    // Walk the catch frame stack to find the nearest valid handler.
                    // Use rposition to find the topmost matching frame by index,
                    // then truncate to remove it and any frames above it — but
                    // NOT frames below it (which belong to outer try blocks).
                    if let Some(frame) = self.pop_exception_target_frame() {
                        self.pending_finally_entry =
                            frame.catch_is_finally.then_some(PendingFinallyEntry {
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
                        if mode == RunLoopMode::Async {
                            return Ok(RunLoopExit::AsyncThrow { exception });
                        }
                        if matches!(mode, RunLoopMode::Generator | RunLoopMode::AsyncGenerator) {
                            return Ok(RunLoopExit::GeneratorThrow {
                                exception,
                                description: desc,
                            });
                        }
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
                                self.pending_finally_entry =
                                    frame.catch_is_finally.then_some(PendingFinallyEntry {
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
                                if mode == RunLoopMode::Async {
                                    return Ok(RunLoopExit::AsyncThrow { exception: thrown });
                                }
                                if matches!(
                                    mode,
                                    RunLoopMode::Generator | RunLoopMode::AsyncGenerator
                                ) {
                                    return Ok(RunLoopExit::GeneratorThrow {
                                        exception: thrown,
                                        description: desc,
                                    });
                                }
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
                            } else {
                                let generator_root = matches!(
                                    mode,
                                    RunLoopMode::Generator | RunLoopMode::AsyncGenerator
                                ) && self.call_stack.len() == 1;
                                if generator_root {
                                    let completed_value = pending_return.value.clone();
                                    let completed_label = pending_return.label.clone();
                                    let _ = self.complete_return(
                                        pending_return.value,
                                        pending_return.label,
                                    )?;
                                    return Ok(RunLoopExit::GeneratorReturn {
                                        value: completed_value,
                                        label: completed_label,
                                    });
                                }
                                match self
                                    .complete_return(pending_return.value, pending_return.label)
                                {
                                    Ok(Some(final_value)) => {
                                        return Ok(RunLoopExit::Value(final_value));
                                    }
                                    Ok(None) => {}
                                    Err(error) => {
                                        match self
                                            .route_run_loop_javascript_error(module, error, mode)?
                                        {
                                            None => continue,
                                            Some(error) => return Err(error),
                                        }
                                    }
                                }
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
                    let captured_env = self.snapshot_scope_chain()?;
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
                    let mut self_capture_rollback = None;
                    if let Some(frame) = captured_env.last() {
                        for (name, binding) in &frame.bindings {
                            if name.starts_with(CLASS_EXPRESSION_CONSTRUCTOR_SELF_CAPTURE_PREFIX)
                                || name.starts_with(FUNCTION_EXPRESSION_SELF_CAPTURE_PREFIX)
                            {
                                let previous = binding.snapshot_state()?;
                                {
                                    let mut state = binding.state_mut()?;
                                    state.value = Value::Closure(closure_id);
                                    state.initialized = true;
                                }
                                self_capture_rollback = Some((binding.clone(), previous));
                                break;
                            }
                        }
                    }
                    self.closures.push(ClosureValue {
                        function_index,
                        module_specifier: self
                            .current_module_specifier
                            .clone()
                            .filter(|owner| self.module_state.modules.contains_key(owner)),
                        captured_env,
                    });
                    if let Err(err) = self
                        .retain_current_module_program(module)
                        .and_then(|()| self.sync_estimated_memory_bytes())
                    {
                        self.closures.pop();
                        self.release_unused_current_module_program();
                        if let Some((binding, previous)) = self_capture_rollback {
                            binding.restore_state(previous)?;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    // Store the closure ID (not function_index) so Call can
                    // look up the correct closure instance.
                    if let Err(err) = self.write_reg(dst, Value::Closure(closure_id)) {
                        self.closures.pop();
                        self.release_unused_current_module_program();
                        if let Some((binding, previous)) = self_capture_rollback {
                            binding.restore_state(previous)?;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.pending_captures.clear();
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
                    let mut self_capture_rollback = None;
                    if let Some(frame) = captured_env.last() {
                        for (name, binding) in &frame.bindings {
                            if name.starts_with(FUNCTION_EXPRESSION_SELF_CAPTURE_PREFIX) {
                                let previous = binding.snapshot_state()?;
                                {
                                    let mut state = binding.state_mut()?;
                                    state.value = Value::GeneratorFunction(closure_id);
                                    state.initialized = true;
                                }
                                self_capture_rollback = Some((binding.clone(), previous));
                                break;
                            }
                        }
                    }
                    self.closures.push(ClosureValue {
                        function_index,
                        module_specifier: self
                            .current_module_specifier
                            .clone()
                            .filter(|owner| self.module_state.modules.contains_key(owner)),
                        captured_env,
                    });
                    if let Err(err) = self
                        .retain_current_module_program(module)
                        .and_then(|()| self.sync_estimated_memory_bytes())
                    {
                        self.closures.pop();
                        self.release_unused_current_module_program();
                        if let Some((binding, previous)) = self_capture_rollback {
                            binding.restore_state(previous)?;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    if let Err(err) = self.write_reg(dst, Value::GeneratorFunction(closure_id)) {
                        self.closures.pop();
                        self.release_unused_current_module_program();
                        if let Some((binding, previous)) = self_capture_rollback {
                            binding.restore_state(previous)?;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    self.pending_captures.clear();
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
                    let mut self_capture_rollback = None;
                    if let Some(frame) = captured_env.last() {
                        for (name, binding) in &frame.bindings {
                            if name.starts_with(FUNCTION_EXPRESSION_SELF_CAPTURE_PREFIX) {
                                let previous = binding.snapshot_state()?;
                                {
                                    let mut state = binding.state_mut()?;
                                    state.value = Value::AsyncFunction(closure_id);
                                    state.initialized = true;
                                }
                                self_capture_rollback = Some((binding.clone(), previous));
                                break;
                            }
                        }
                    }
                    self.closures.push(ClosureValue {
                        function_index,
                        module_specifier: self
                            .current_module_specifier
                            .clone()
                            .filter(|owner| self.module_state.modules.contains_key(owner)),
                        captured_env,
                    });
                    if let Err(err) = self
                        .retain_current_module_program(module)
                        .and_then(|()| self.sync_estimated_memory_bytes())
                    {
                        self.closures.pop();
                        self.release_unused_current_module_program();
                        if let Some((binding, previous)) = self_capture_rollback {
                            binding.restore_state(previous)?;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    if let Err(error) = self.write_reg(dst, Value::AsyncFunction(closure_id)) {
                        self.closures.pop();
                        self.release_unused_current_module_program();
                        if let Some((binding, previous)) = self_capture_rollback {
                            binding.restore_state(previous)?;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(error);
                    }
                    self.pending_captures.clear();
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
                    let mut self_capture_rollback = None;
                    if let Some(frame) = captured_env.last() {
                        for (name, binding) in &frame.bindings {
                            if name.starts_with(FUNCTION_EXPRESSION_SELF_CAPTURE_PREFIX) {
                                let previous = binding.snapshot_state()?;
                                {
                                    let mut state = binding.state_mut()?;
                                    state.value = Value::AsyncGeneratorFunction(closure_id);
                                    state.initialized = true;
                                }
                                self_capture_rollback = Some((binding.clone(), previous));
                                break;
                            }
                        }
                    }
                    self.closures.push(ClosureValue {
                        function_index,
                        module_specifier: self
                            .current_module_specifier
                            .clone()
                            .filter(|owner| self.module_state.modules.contains_key(owner)),
                        captured_env,
                    });
                    if let Err(err) = self
                        .retain_current_module_program(module)
                        .and_then(|()| self.sync_estimated_memory_bytes())
                    {
                        self.closures.pop();
                        self.release_unused_current_module_program();
                        if let Some((binding, previous)) = self_capture_rollback {
                            binding.restore_state(previous)?;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(err);
                    }
                    if let Err(error) =
                        self.write_reg(dst, Value::AsyncGeneratorFunction(closure_id))
                    {
                        self.closures.pop();
                        self.release_unused_current_module_program();
                        if let Some((binding, previous)) = self_capture_rollback {
                            binding.restore_state(previous)?;
                        }
                        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                        return Err(error);
                    }
                    self.pending_captures.clear();
                    self.ip += 1;
                }
                Ir3Instruction::GeneratorBodyStart => {
                    self.ip += 1;
                    if mode == RunLoopMode::Generator {
                        return Ok(RunLoopExit::GeneratorBodyStart);
                    }
                }
                Ir3Instruction::Yield {
                    value,
                    delegate,
                    resume_dst,
                } => {
                    let yielded = self.read_reg(value)?;
                    let yielded_label = self.read_reg_label(value)?;
                    if mode == RunLoopMode::AsyncGenerator {
                        if delegate {
                            return Err(InterpreterError::TypeError {
                                expected: "supported async generator yield".into(),
                                got: "async generator delegated iteration is not yet supported"
                                    .into(),
                            });
                        }
                        self.ip += 1;
                        return Ok(RunLoopExit::AsyncGeneratorAwait {
                            completion: LabeledReturn {
                                value: yielded,
                                label: yielded_label,
                            },
                            kind: AsyncGeneratorAwaitKind::Yield { resume_dst },
                        });
                    }
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
                    let result = Value::Object(result_id);
                    if mode == RunLoopMode::Generator {
                        return Ok(RunLoopExit::GeneratorYield {
                            result,
                            label: yielded_label,
                            resume_dst,
                        });
                    }
                    self.write_reg(resume_dst, Value::Undefined)?;
                    return Ok(RunLoopExit::Value(LabeledReturn {
                        value: result,
                        label: yielded_label,
                    }));
                }
                Ir3Instruction::AwaitValue { promise_reg } => {
                    if mode == RunLoopMode::AsyncGenerator {
                        let completion = LabeledReturn {
                            value: self.read_reg(promise_reg)?,
                            label: self.read_reg_label(promise_reg)?,
                        };
                        self.ip += 1;
                        return Ok(RunLoopExit::AsyncGeneratorAwait {
                            completion,
                            kind: AsyncGeneratorAwaitKind::Body {
                                register: promise_reg,
                            },
                        });
                    }
                    if mode != RunLoopMode::Async
                        || self
                            .call_stack
                            .last()
                            .and_then(|frame| frame.async_function_id)
                            .is_none()
                    {
                        return Err(InterpreterError::TypeError {
                            expected: "await in an async activation".to_string(),
                            got: "await outside an async function".to_string(),
                        });
                    }
                    let awaited_value = self.read_reg(promise_reg)?;
                    let awaited_label = self.read_reg_label(promise_reg)?;
                    let promise_handle = match awaited_value {
                        Value::Promise(handle) => crate::promise_model::PromiseHandle(handle),
                        value => {
                            let handle = self.create_promise_accounted()?;
                            self.resolve_promise_with_value(handle, value, awaited_label.clone())?;
                            handle
                        }
                    };
                    let promise_label = self
                        .promise_store
                        .get(promise_handle)
                        .map_err(|error| InterpreterError::TypeError {
                            expected: "valid awaited promise".to_string(),
                            got: error.to_string(),
                        })?
                        .label
                        .clone();
                    // Even a settled Promise or primitive resumes in a job.
                    // Await never consumes the caller's execution context.
                    self.suspend_async_function_for_await(
                        promise_handle,
                        promise_reg,
                        awaited_label.join(&promise_label),
                    )?;
                    return Ok(RunLoopExit::AsyncAwait);
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
                } => match self.load_scoped_binding(module, name_pool_index) {
                    Ok((value, label)) => {
                        self.write_reg_with_label(dst, value, label)?;
                        self.ip += 1;
                    }
                    Err(error)
                        if matches!(&error, InterpreterError::UninitializedBinding { .. })
                            && self.has_exception_target_frame() =>
                    {
                        match self.route_run_loop_javascript_error(module, error, mode)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                    Err(error) => return Err(error),
                },
                Ir3Instruction::StoreScoped {
                    src,
                    name_pool_index,
                } => match self.store_scoped_binding(module, src, name_pool_index) {
                    Ok(()) => self.ip += 1,
                    Err(error)
                        if matches!(
                            &error,
                            InterpreterError::UninitializedBinding { .. }
                                | InterpreterError::ConstAssignment { .. }
                        ) && self.has_exception_target_frame() =>
                    {
                        match self.route_run_loop_javascript_error(module, error, mode)? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                    Err(error) => return Err(error),
                },
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
                    if let Some((_, binding)) = self.scope_chain.resolve(&name) {
                        previous = Some((binding.clone(), binding.snapshot_state()?));
                        let mut state = binding.state_mut()?;
                        state.value = val;
                        state.label = label;
                        state.initialized = true;
                    }
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        if let Some((binding, old_state)) = previous {
                            binding.restore_state(old_state)?;
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
            // Integer arithmetic is an optimization of Number arithmetic,
            // never a separate wrapping integer domain (bd-9vouw.2).
            (Value::Int(x), Value::Int(y)) => Ok(js_safe_integer_result(*x, *y, x.checked_add(*y))
                .unwrap_or_else(|| js_number_to_value(*x as f64 + *y as f64))),
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
                    Value::Symbol(_) => {
                        return Err(InterpreterError::TypeError {
                            expected: "string concatenation operand coercible to string"
                                .to_string(),
                            got: "symbol".to_string(),
                        });
                    }
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
                    Value::Symbol(_) => {
                        return Err(InterpreterError::TypeError {
                            expected: "string concatenation operand coercible to string"
                                .to_string(),
                            got: "symbol".to_string(),
                        });
                    }
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
                Ok(js_number_to_value(x + y))
            }
        }
    }

    fn eval_arith(&self, lhs: u32, rhs: u32, op: &str) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;

        // Exact safe-integer arithmetic can avoid the floating-point path.
        if let (Value::Int(x), Value::Int(y)) = (&a, &b) {
            let result = match op {
                "sub" => js_safe_integer_result(*x, *y, x.checked_sub(*y)),
                "mul" if (*x == 0 && *y < 0) || (*y == 0 && *x < 0) => {
                    Some(Value::Float(Float64::new(-0.0)))
                }
                "mul" => js_safe_integer_result(*x, *y, x.checked_mul(*y)),
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "sub or mul".to_string(),
                        got: op.to_string(),
                    });
                }
            };
            if let Some(result) = result {
                return Ok(result);
            }
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

        Ok(js_number_to_value(result))
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

        Ok(js_number_to_value(result))
    }

    fn eval_mod(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;

        // The remainder of a negative dividend can be negative zero. Use
        // integer remainder only for values already in the safe range.
        if let (Value::Int(x), Value::Int(y)) = (&a, &b)
            && (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(x)
            && (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(y)
        {
            if *y == 0 {
                // JS: x % 0 = NaN
                return Ok(Value::Float(Float64::new(f64::NAN)));
            }
            let remainder = x % y;
            return Ok(if remainder == 0 && *x < 0 {
                Value::Float(Float64::new(-0.0))
            } else {
                Value::Int(remainder)
            });
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

        Ok(js_number_to_value(result))
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

        // Number::exponentiate differs from IEEE pow for a NaN exponent
        // and for ±1 raised to an infinite exponent (ES2020 6.1.6.1.3).
        let result = if y.is_nan() || (x.abs() == 1.0 && y.is_infinite()) {
            f64::NAN
        } else {
            x.powf(y)
        };
        Ok(js_number_to_value(result))
    }

    fn eval_unary_plus(&self, src: u32) -> Result<Value, InterpreterError> {
        let value = self.read_reg(src)?;
        match &value {
            Value::Int(n) => Ok(js_int_to_value(*n)),
            Value::Float(f) => Ok(Value::Float(*f)),
            _ => {
                let number = Self::coerce_to_float(&value).ok_or(InterpreterError::TypeError {
                    expected: "number-coercible primitive".to_string(),
                    got: value.type_name().to_string(),
                })?;
                Ok(js_number_to_value(number))
            }
        }
    }

    fn eval_unary_neg(&self, src: u32) -> Result<Value, InterpreterError> {
        let value = self.read_reg(src)?;
        match &value {
            Value::Int(0) => Ok(Value::Float(Float64::new(-0.0))),
            Value::Int(n) => Ok(js_safe_integer_result(*n, 0, n.checked_neg())
                .unwrap_or_else(|| js_number_to_value(-(*n as f64)))),
            Value::Float(f) => Ok(Value::Float(Float64::new(-f.inner()))),
            _ => {
                let number = Self::coerce_to_float(&value).ok_or(InterpreterError::TypeError {
                    expected: "number-coercible primitive".to_string(),
                    got: value.type_name().to_string(),
                })?;
                Ok(js_number_to_value(-number))
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

    fn eval_in_operator(
        &self,
        module: &Ir3Module,
        lhs: u32,
        rhs: u32,
    ) -> Result<Value, InterpreterError> {
        let key = Self::executable_property_key(&self.read_reg(lhs)?);
        self.validate_executable_property_key(&key)?;
        let target = self.read_reg(rhs)?;
        match target {
            Value::Object(object_id) => {
                self.heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                self.run_pre_runtime_property_access_hook(module, object_id, &key)?;
                Ok(Value::Bool(
                    self.prototype_chain_has_runtime_key(object_id, &key)?,
                ))
            }
            function_like if Self::function_object_key(&function_like).is_some() => {
                if let Value::Closure(closure_id)
                | Value::AsyncFunction(closure_id)
                | Value::AsyncGeneratorFunction(closure_id) = &function_like
                    && self.closure_method_metadata.contains_key(closure_id)
                    && matches!(
                        &key,
                        RuntimePropertyKey::String(name) if name.as_str() == Some("name")
                    )
                {
                    self.preflight_legacy_property_key_for_hook(&key)?;
                    return Ok(Value::Bool(true));
                }
                let Some(object_id) = self.function_object_id(&function_like) else {
                    self.preflight_legacy_property_key_for_hook(&key)?;
                    return Ok(Value::Bool(
                        self.intrinsic_function_property(&function_like, &key)
                            .is_some(),
                    ));
                };
                self.heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                self.run_pre_runtime_property_access_hook(module, object_id, &key)?;
                Ok(Value::Bool(
                    self.prototype_chain_has_runtime_key(object_id, &key)?
                        || self
                            .intrinsic_function_property(&function_like, &key)
                            .is_some(),
                ))
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

    /// Array literal elements define own data properties, including when an
    /// inherited index is an accessor. Retain length provenance because a
    /// preceding spread controls the position of this element.
    fn append_array_literal_element(
        &mut self,
        array: u32,
        value: Value,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let object = self.expect_object(self.read_reg(array)?, "array literal target")?;
        let length_key = RuntimePropertyKey::String(JsString::from("length"));
        let label = label
            .join(&self.read_reg_label(array)?)
            .join(&self.own_stored_runtime_property_label(object, &length_key));
        let next_index = self.array_like_length(object)?;
        next_index
            .checked_add(1)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Invalid array length".into(),
            })?;
        let retained_bytes = Self::estimate_timer_value_bytes(&value)
            .saturating_add(Self::estimate_label_bytes(&label));
        self.with_array_method_temporary(retained_bytes, |core| {
            let element_key = RuntimePropertyKey::String(JsString::from(next_index.to_string()));
            // Defining the index grows an array's length through its exotic
            // [[DefineOwnProperty]] operation. The length property itself
            // retains its non-enumerable, non-configurable descriptor.
            core.create_data_property_or_throw(object, element_key, value, &label)?;
            core.set_own_runtime_property_label(object, &length_key, &label)?;
            core.write_reg_with_label(array, Value::Object(object), label)
        })
    }

    fn spread_into_array(
        &mut self,
        module: &Ir3Module,
        array: u32,
        iterable: u32,
    ) -> Result<(), InterpreterError> {
        self.expect_object(self.read_reg(array)?, "array literal target")?;
        // Do not stage values in a native Vec: each iterator step can execute
        // arbitrary guest code, mutate later values, throw, or never finish.
        let iterator = {
            let value = self.read_reg(iterable)?;
            let mut label = self.read_reg_label(iterable)?;
            let retained_bytes = Self::estimate_timer_value_bytes(&value)
                .saturating_add(Self::estimate_label_bytes(&label));
            self.with_array_method_temporary(retained_bytes, |core| {
                core.init_for_of_iterator(module, value, &mut label)
            })?
        };
        let handle = self.expect_iterator_handle(iterator)?;
        loop {
            self.charge_array_method_step()?;
            let mut label = self.for_of_iterator_label(handle)?;
            let finished =
                self.with_array_method_temporary(Self::estimate_label_bytes(&label), |core| {
                    // IteratorStep/IteratorValue failures propagate directly.
                    // Array spread must not call return() after these throws.
                    match core.advance_for_of_iterator(
                        module,
                        Value::Iterator(handle),
                        &mut label,
                    )? {
                        Some(value) => {
                            core.append_array_literal_element(array, value, label)?;
                            Ok(false)
                        }
                        None => {
                            let object =
                                core.expect_object(core.read_reg(array)?, "array literal target")?;
                            let length_key = RuntimePropertyKey::String(JsString::from("length"));
                            let label = label
                                .join(&core.read_reg_label(array)?)
                                .join(&core.own_stored_runtime_property_label(object, &length_key));
                            // A spread that yields nothing, or whose final
                            // done flag is private, still controls array shape
                            // and the positions of subsequent literal values.
                            core.with_array_method_temporary(
                                Self::estimate_label_bytes(&label),
                                |core| {
                                    core.set_own_runtime_property_label(
                                        object,
                                        &length_key,
                                        &label,
                                    )?;
                                    core.write_reg_with_label(array, Value::Object(object), label)
                                },
                            )?;
                            Ok(true)
                        }
                    }
                })?;
            if finished {
                return Ok(());
            }
        }
    }

    fn init_for_of_iterator(
        &mut self,
        module: &Ir3Module,
        value: Value,
        label: &mut crate::ifc_artifacts::Label,
    ) -> Result<Value, InterpreterError> {
        if let Value::Iterator(handle) = value {
            *label = label.join(&self.for_of_iterator_label(handle)?);
            self.set_for_of_iterator_label(handle, label.clone())?;
            return Ok(Value::Iterator(handle));
        }

        if matches!(value, Value::Generator(_)) {
            let handle = self.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
                values: Vec::new(),
                array_object: None,
                iterator_object: None,
                iterator_receiver: Some(value),
                next_method: Some(Value::BuiltinFunction(BuiltinFunction::generator_next())),
                label: label.clone(),
                next_index: 0,
                done: false,
                closed: false,
                return_called: false,
            }))?;
            return Ok(Value::Iterator(handle));
        }

        let mut array_object = None;
        let mut iterator_object = None;
        let mut iterator_receiver = None;
        let mut next_method = None;
        let values = if value.is_object_like() {
            let backing = self.iterator_carrier_backing_id(&value, "iterable object")?;
            let iterator_key = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
            let property = match backing {
                Some(object) => {
                    self.prototype_chain_lookup_runtime_property(object, &iterator_key)?
                }
                None => None,
            };
            match property {
                None if backing.is_some_and(|id| self.heap[id.0 as usize].is_array) => {
                    // The intrinsic array iterator is represented directly.
                    // An explicitly present undefined/null override must
                    // still reject instead of selecting this intrinsic.
                    array_object = backing;
                    Vec::new()
                }
                None => {
                    return Err(InterpreterError::TypeError {
                        expected: "iterable with Symbol.iterator".to_string(),
                        got: value.type_name().to_string(),
                    });
                }
                Some(_) => {
                    let method =
                        self.read_iterator_property(module, &value, &iterator_key, label)?;
                    if !Self::is_sync_callable(&method) {
                        return Err(InterpreterError::TypeError {
                            expected: "callable Symbol.iterator method".to_string(),
                            got: method.type_name().to_string(),
                        });
                    }
                    let (completion, iterator_label) = self.with_array_method_temporary(
                        Self::estimate_label_bytes(label),
                        |core| {
                            core.invoke_inline_method_call_with_receiver_label(
                                module,
                                method,
                                value,
                                label.clone(),
                                &[],
                            )
                        },
                    )?;
                    *label = label.join(&iterator_label);
                    let iterator = self.complete_inline_call(completion)?;
                    match iterator {
                        Value::Iterator(_) | Value::Generator(_) => {
                            return self.init_for_of_iterator(module, iterator, label);
                        }
                        iterator => {
                            let backing = self.iterator_carrier_backing_id(
                                &iterator,
                                "object returned by Symbol.iterator",
                            )?;
                            let next = self.read_iterator_property(
                                module,
                                &iterator,
                                &RuntimePropertyKey::String(JsString::from("next")),
                                label,
                            )?;
                            if !Self::is_sync_callable(&next) {
                                return Err(InterpreterError::TypeError {
                                    expected: "callable iterator.next".to_string(),
                                    got: next.type_name().to_string(),
                                });
                            }
                            iterator_object = backing;
                            iterator_receiver = Some(iterator);
                            next_method = Some(next);
                            Vec::new()
                        }
                    }
                }
            }
        } else {
            self.collect_for_of_values(&value)?
        };
        let handle = self.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
            values,
            array_object,
            iterator_object,
            iterator_receiver,
            next_method,
            label: label.clone(),
            next_index: 0,
            done: false,
            closed: false,
            return_called: false,
        }))?;
        Ok(Value::Iterator(handle))
    }

    fn advance_for_of_iterator(
        &mut self,
        module: &Ir3Module,
        iterator: Value,
        label: &mut crate::ifc_artifacts::Label,
    ) -> Result<Option<Value>, InterpreterError> {
        let handle = self.expect_iterator_handle(iterator)?;
        *label = label.join(&self.for_of_iterator_label(handle)?);
        let array_step = match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForOf(state) if !state.closed && !state.done => {
                state.array_object.map(|object| (object, state.next_index))
            }
            _ => None,
        };
        if let Some((array, index)) = array_step {
            let length_key = RuntimePropertyKey::String(JsString::from("length"));
            *label = label.join(&self.runtime_property_label(array, &length_key));
            let length = self.array_like_length(array)? as usize;
            if index >= length {
                if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                    state.done = true;
                }
                self.set_for_of_iterator_label(handle, label.clone())?;
                return Ok(None);
            }
            // Advance before Get so an accessor that resumes this iterator
            // cannot yield the same array index twice.
            if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                state.next_index += 1;
            }
            let value = self.read_iterator_property(
                module,
                &Value::Object(array),
                &RuntimePropertyKey::String(JsString::from(index.to_string())),
                label,
            )?;
            self.set_for_of_iterator_label(handle, label.clone())?;
            return Ok(Some(value));
        }

        let retained_clone_bytes = match self.iterators.get(handle as usize) {
            Some(RuntimeIteratorState::ForOf(state)) => state
                .iterator_receiver
                .as_ref()
                .map(Self::estimate_timer_value_bytes)
                .unwrap_or(0)
                .saturating_add(
                    state
                        .next_method
                        .as_ref()
                        .map(Self::estimate_timer_value_bytes)
                        .unwrap_or(0),
                ),
            _ => 0,
        };
        self.check_temporary_memory_budget(retained_clone_bytes)?;
        let custom_step = match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForOf(state) => {
                if state.closed || state.done {
                    state.done = true;
                    return Ok(None);
                }
                if let Some(next_method) = state.next_method.clone() {
                    let receiver = state.iterator_receiver.clone().ok_or_else(|| {
                        InterpreterError::TypeError {
                            expected: "custom iterator receiver".to_string(),
                            got: "missing iterator object".to_string(),
                        }
                    })?;
                    Some((receiver, next_method))
                } else if let Some(value) = state.values.get(state.next_index).cloned() {
                    state.next_index += 1;
                    return Ok(Some(value));
                } else {
                    state.done = true;
                    return Ok(None);
                }
            }
            RuntimeIteratorState::ForIn(_) => {
                return Err(InterpreterError::TypeError {
                    expected: "for..of iterator".to_string(),
                    got: "for..in iterator".to_string(),
                });
            }
        };

        let (receiver, next_method) = custom_step.expect("captured iterator.next");
        let (completion, result_label) =
            self.with_array_method_temporary(Self::estimate_label_bytes(label), |core| {
                core.invoke_inline_method_call_with_receiver_label(
                    module,
                    next_method,
                    receiver,
                    label.clone(),
                    &[],
                )
            })?;
        *label = label.join(&result_label);
        let result = self.complete_inline_call(completion)?;
        self.iterator_carrier_backing_id(&result, "iterator result object")?;
        let done = self.read_iterator_property(
            module,
            &result,
            &RuntimePropertyKey::String(JsString::from("done")),
            label,
        )?;
        if done.is_truthy() {
            if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                state.done = true;
            }
            self.set_for_of_iterator_label(handle, label.clone())?;
            return Ok(None);
        }
        let value = self.read_iterator_property(
            module,
            &result,
            &RuntimePropertyKey::String(JsString::from("value")),
            label,
        )?;
        self.set_for_of_iterator_label(handle, label.clone())?;
        Ok(Some(value))
    }

    fn read_iterator_property(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        key: &RuntimePropertyKey,
        label: &mut crate::ifc_artifacts::Label,
    ) -> Result<Value, InterpreterError> {
        let Some(backing) =
            self.iterator_carrier_backing_id(receiver, "iterator protocol object")?
        else {
            return Ok(self
                .intrinsic_function_property(receiver, key)
                .unwrap_or(Value::Undefined));
        };
        self.run_pre_runtime_property_access_hook(module, backing, key)?;
        *label = label.join(&self.runtime_property_label(backing, key));
        match self.prototype_chain_lookup_runtime_property(backing, key)? {
            Some(RuntimeProperty::Data(value)) => Ok(value),
            Some(RuntimeProperty::Accessor(accessor)) => match accessor.get {
                Some(getter) => {
                    let (completion, getter_label) = self
                        .invoke_inline_method_call_with_receiver_label(
                            module,
                            getter,
                            receiver.clone(),
                            label.clone(),
                            &[],
                        )?;
                    *label = label.join(&getter_label);
                    self.complete_inline_call(completion)
                }
                None => Ok(Value::Undefined),
            },
            None => Ok(self
                .intrinsic_function_property(receiver, key)
                .unwrap_or(Value::Undefined)),
        }
    }

    fn for_of_iterator_label(
        &self,
        handle: u32,
    ) -> Result<crate::ifc_artifacts::Label, InterpreterError> {
        match self.iterators.get(handle as usize) {
            Some(RuntimeIteratorState::ForOf(state)) => {
                self.check_temporary_memory_budget(Self::estimate_label_bytes(&state.label))?;
                Ok(state.label.clone())
            }
            _ => Err(InterpreterError::TypeError {
                expected: "for..of iterator".to_string(),
                got: "invalid iterator handle".to_string(),
            }),
        }
    }

    fn set_for_of_iterator_label(
        &mut self,
        handle: u32,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let previous = match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForOf(state) => std::mem::replace(&mut state.label, label),
            RuntimeIteratorState::ForIn(_) => unreachable!("validated for-of handle"),
        };
        if let Err(error) = self.sync_estimated_memory_bytes() {
            if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                state.label = previous;
            }
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        Ok(())
    }

    fn close_iterator(
        &mut self,
        module: &Ir3Module,
        iterator: Value,
        reason: IteratorCloseReason,
    ) -> Result<(), InterpreterError> {
        let handle = self.expect_iterator_handle(iterator)?;
        let iterator_receiver = match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForIn(state) => {
                state.closed = true;
                state.done = true;
                None
            }
            RuntimeIteratorState::ForOf(state) => {
                state.closed = true;
                state.done = true;
                if state.return_called {
                    return Ok(());
                }
                state
                    .iterator_receiver
                    .clone()
                    .or_else(|| state.iterator_object.map(Value::Object))
            }
        };

        let Some(iterator_receiver) = iterator_receiver else {
            return Ok(());
        };
        if let Value::Generator(generator_id) = &iterator_receiver {
            if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                state.return_called = true;
            }
            let original_exception = if reason == IteratorCloseReason::Throw {
                self.pending_exception.take()
            } else {
                None
            };
            let outcome = self.resume_generator(
                module,
                *generator_id,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
                true,
            );
            if reason == IteratorCloseReason::Throw {
                self.pending_exception = original_exception;
            }
            return match outcome {
                Ok(_) => Ok(()),
                Err(error)
                    if reason == IteratorCloseReason::Throw
                        && Self::is_js_catchable_error(&error) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
            };
        }
        let Some(iterator_object) =
            self.iterator_carrier_backing_id(&iterator_receiver, "iterator object")?
        else {
            return Ok(());
        };
        let return_property = self.prototype_chain_lookup_runtime_property(
            iterator_object,
            &RuntimePropertyKey::String(JsString::from("return")),
        )?;
        let return_method = match self.read_runtime_property_inline(
            module,
            iterator_receiver.clone(),
            return_property,
        ) {
            Ok(InlineCallCompletion::Value(value)) => value,
            Ok(InlineCallCompletion::Throw(thrown)) => {
                if reason == IteratorCloseReason::Throw {
                    return Ok(());
                }
                return Err(self.rearm_inline_throw(thrown));
            }
            Err(error)
                if reason == IteratorCloseReason::Throw && Self::is_js_catchable_error(&error) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if return_method.is_nullish() {
            return Ok(());
        }
        if !Self::is_sync_callable(&return_method) {
            if reason == IteratorCloseReason::Throw {
                return Ok(());
            }
            return Err(InterpreterError::TypeError {
                expected: "callable iterator.return".to_string(),
                got: return_method.type_name().to_string(),
            });
        }
        if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
            state.return_called = true;
        }

        let close_value =
            match self.invoke_inline_method_call(module, return_method, iterator_receiver, &[]) {
                Ok(InlineCallCompletion::Value(value)) => value,
                Ok(InlineCallCompletion::Throw(thrown)) => {
                    if reason == IteratorCloseReason::Throw {
                        return Ok(());
                    }
                    return Err(self.rearm_inline_throw(thrown));
                }
                Err(error)
                    if reason == IteratorCloseReason::Throw
                        && Self::is_js_catchable_error(&error) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
        if !close_value.is_object_like() {
            if reason == IteratorCloseReason::Throw {
                return Ok(());
            }
            return Err(InterpreterError::TypeError {
                expected: "iterator return method to return an object".to_string(),
                got: close_value.type_name().to_string(),
            });
        }
        Ok(())
    }

    fn is_sync_callable(value: &Value) -> bool {
        matches!(
            value,
            Value::Function(_)
                | Value::Closure(_)
                | Value::GeneratorFunction(_)
                | Value::AsyncFunction(_)
                | Value::AsyncGeneratorFunction(_)
                | Value::BuiltinFunction(_)
        )
    }

    fn is_js_catchable_error(error: &InterpreterError) -> bool {
        matches!(
            error,
            InterpreterError::TypeError { .. }
                | InterpreterError::RangeError { .. }
                | InterpreterError::UninitializedBinding { .. }
                | InterpreterError::ConstAssignment { .. }
                | InterpreterError::UncaughtException { .. }
        )
    }

    fn read_runtime_property_inline(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        property: Option<RuntimeProperty>,
    ) -> Result<InlineCallCompletion, InterpreterError> {
        match property {
            Some(RuntimeProperty::Data(value)) => Ok(InlineCallCompletion::Value(value)),
            Some(RuntimeProperty::Accessor(accessor)) => match accessor.get {
                Some(getter) => self.invoke_inline_method_call(module, getter, receiver, &[]),
                None => Ok(InlineCallCompletion::Value(Value::Undefined)),
            },
            None => Ok(InlineCallCompletion::Value(Value::Undefined)),
        }
    }

    fn complete_inline_call(
        &mut self,
        completion: InlineCallCompletion,
    ) -> Result<Value, InterpreterError> {
        match completion {
            InlineCallCompletion::Value(value) => Ok(value),
            InlineCallCompletion::Throw(thrown) => Err(self.rearm_inline_throw(thrown)),
        }
    }

    fn rearm_inline_throw(&mut self, thrown: LabeledException) -> InterpreterError {
        let description = Self::exception_description(&thrown.value);
        self.pending_return = None;
        self.pending_exception = Some(thrown);
        InterpreterError::UncaughtException { value: description }
    }

    fn exception_description(value: &Value) -> String {
        match value {
            Value::Str(text) => text.to_string(),
            Value::Int(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Undefined => "undefined".to_string(),
            Value::Null => "null".to_string(),
            _ => "[object]".to_string(),
        }
    }

    /// Execute a no-argument method without disturbing the caller's active
    /// abrupt-completion/finally state. A synthetic catch records explicit
    /// JavaScript throws as data so their exact value can be re-armed after
    /// restoring the caller snapshot.
    fn invoke_inline_method_call(
        &mut self,
        module: &Ir3Module,
        callee: Value,
        receiver: Value,
        extra_args: &[Value],
    ) -> Result<InlineCallCompletion, InterpreterError> {
        let arguments = extra_args
            .iter()
            .cloned()
            .map(|value| (value, crate::ifc_artifacts::Label::Public))
            .collect::<Vec<_>>();
        self.invoke_inline_method_call_labeled(module, callee, receiver, &arguments)
            .map(|(completion, _)| completion)
    }

    /// Run a guest callback without discarding argument or completion
    /// provenance at the isolated activation boundary.
    fn invoke_inline_method_call_labeled(
        &mut self,
        module: &Ir3Module,
        callee: Value,
        receiver: Value,
        extra_args: &[(Value, crate::ifc_artifacts::Label)],
    ) -> Result<(InlineCallCompletion, crate::ifc_artifacts::Label), InterpreterError> {
        self.invoke_inline_method_call_with_receiver_label(
            module,
            callee,
            receiver,
            crate::ifc_artifacts::Label::Public,
            extra_args,
        )
    }

    /// Property getters retain the provenance of their selected receiver
    /// inside the isolated activation, including writes of `this` elsewhere.
    fn invoke_inline_method_call_with_receiver_label(
        &mut self,
        module: &Ir3Module,
        callee: Value,
        receiver: Value,
        receiver_label: crate::ifc_artifacts::Label,
        extra_args: &[(Value, crate::ifc_artifacts::Label)],
    ) -> Result<(InlineCallCompletion, crate::ifc_artifacts::Label), InterpreterError> {
        self.invoke_inline_call(module, callee, receiver, receiver_label, extra_args, false)
    }

    /// Native algorithms such as ArraySpeciesCreate use the ordinary
    /// constructor path with the same isolated activation and exact throw
    /// restoration as inline callbacks.
    fn invoke_inline_constructor_call(
        &mut self,
        module: &Ir3Module,
        callee: Value,
        callee_label: crate::ifc_artifacts::Label,
        extra_args: &[(Value, crate::ifc_artifacts::Label)],
    ) -> Result<(InlineCallCompletion, crate::ifc_artifacts::Label), InterpreterError> {
        self.invoke_inline_call(
            module,
            callee,
            Value::Undefined,
            callee_label,
            extra_args,
            true,
        )
    }

    fn invoke_inline_call(
        &mut self,
        module: &Ir3Module,
        callee: Value,
        receiver: Value,
        receiver_label: crate::ifc_artifacts::Label,
        extra_args: &[(Value, crate::ifc_artifacts::Label)],
        construct: bool,
    ) -> Result<(InlineCallCompletion, crate::ifc_artifacts::Label), InterpreterError> {
        self.ensure_call_depth_available()?;
        let owner_program = self.callable_module(&callee)?;
        let module = owner_program.as_deref().unwrap_or(module);
        let wrapper_bytes = Self::retained_module_program_bytes(module)
            .saturating_mul(2)
            .saturating_add(8 * std::mem::size_of::<Ir3Instruction>() as u64);
        self.check_temporary_memory_budget(wrapper_bytes)?;
        let mut wrapper = module.clone();
        let wrapper_start = wrapper.instructions.len();
        let catch_target = u32::try_from(wrapper_start.saturating_add(6)).map_err(|_| {
            InterpreterError::InstructionOutOfBounds {
                ip: wrapper_start,
                count: wrapper.instructions.len(),
            }
        })?;
        wrapper.instructions.push(Ir3Instruction::LoadBool {
            dst: 2,
            value: false,
        });
        wrapper.instructions.push(Ir3Instruction::BeginTry {
            catch_target,
            finally_target: None,
        });
        // Registers: 0 = receiver, 1 = callee, 2 = try-success sentinel,
        // 3.. = call arguments (bd-3ose7 passes resolve/reject capabilities to
        // a thenable's `then`). Arguments are written directly before the run
        // (like receiver/callee), so the wrapper instruction count — and thus
        // `catch_target` — is unchanged.
        let arg_count = u32::try_from(extra_args.len()).map_err(|_| {
            InterpreterError::InstructionOutOfBounds {
                ip: wrapper_start,
                count: extra_args.len(),
            }
        })?;
        let args = RegRange {
            start: 3,
            count: arg_count,
        };
        wrapper.instructions.push(if construct {
            Ir3Instruction::Construct {
                callee: 1,
                args,
                dst: 0,
            }
        } else {
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args,
                dst: 0,
            }
        });
        wrapper.instructions.push(Ir3Instruction::EndTry);
        wrapper.instructions.push(Ir3Instruction::LoadBool {
            dst: 2,
            value: true,
        });
        wrapper
            .instructions
            .push(Ir3Instruction::Return { value: 0 });
        wrapper
            .instructions
            .push(Ir3Instruction::EnterCatch { dst: 0 });
        wrapper
            .instructions
            .push(Ir3Instruction::Return { value: 0 });

        let snapshot = self.take_module_execution();
        let saved_suspended_bytes = self.temporarily_suspended_execution_bytes;
        let saved_suspended_depth = self.temporarily_suspended_call_depth;
        self.temporarily_suspended_execution_bytes = saved_suspended_bytes
            .saturating_add(Self::estimate_module_execution_bytes(&snapshot))
            .saturating_add(wrapper_bytes);
        self.temporarily_suspended_call_depth =
            saved_suspended_depth.saturating_add(snapshot.call_stack.len());
        let saved_active_cjs_context = self.active_cjs_context.clone();
        let result = (|| -> Result<
            (InlineCallCompletion, crate::ifc_artifacts::Label),
            InterpreterError,
        > {
            self.registers.clear();
            self.register_labels.clear();
            self.clear_register_range(0, self.config.max_registers as usize);
            self.call_stack.clear();
            self.ip = wrapper_start;
            self.register_base = 0;
            self.catch_frames.clear();
            self.pending_exception = None;
            self.pending_return = None;
            self.suspended_abrupt_completions.clear();
            self.finally_frames.clear();
            self.pending_finally_entry = None;
            self.copy_data_properties_states.clear();
            self.pending_captures.clear();
            self.scope_chain = snapshot.scope_chain.clone();
            self.current_module_specifier = Some(module.header.source_label.clone());
            self.sync_estimated_memory_bytes()?;
            self.write_reg_with_label(0, receiver, receiver_label.clone())?;
            self.write_reg_with_label(1, callee, if construct {
                receiver_label
            } else {
                crate::ifc_artifacts::Label::Public
            })?;
            for (offset, (arg, label)) in extra_args.iter().enumerate() {
                let reg = 3u32
                    .checked_add(u32::try_from(offset).unwrap_or(u32::MAX))
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: 3,
                        max: self.config.max_registers,
                    })?;
                self.write_reg_with_label(reg, arg.clone(), label.clone())?;
            }
            let LabeledReturn { value, label } = self.run_loop_labeled(&wrapper)?;
            let completion = if matches!(self.read_reg(2)?, Value::Bool(true)) {
                InlineCallCompletion::Value(value)
            } else {
                InlineCallCompletion::Throw(LabeledException {
                    value,
                    label: label.clone(),
                })
            };
            Ok((completion, label))
        })();
        self.temporarily_suspended_execution_bytes = saved_suspended_bytes;
        self.temporarily_suspended_call_depth = saved_suspended_depth;
        self.restore_module_execution(snapshot);
        self.active_cjs_context = saved_active_cjs_context;
        result
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

    fn decode_accessor_definition_key(key: &JsString) -> Option<(AccessorKind, JsString)> {
        let units = key.code_units_vec();
        for (prefix, kind) in [
            (IR_ACCESSOR_GET_PREFIX, AccessorKind::Get),
            (IR_ACCESSOR_SET_PREFIX, AccessorKind::Set),
        ] {
            let prefix = prefix.encode_utf16().collect::<Vec<_>>();
            if units.starts_with(&prefix) {
                return Some((kind, JsString::from_code_units(&units[prefix.len()..])));
            }
        }
        None
    }

    fn prototype_chain_lookup_property(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Option<RuntimeProperty>, InterpreterError> {
        self.prototype_chain_lookup_typed_property(
            object_id,
            &TypedPropertyKey::String(key.to_string()),
        )
    }

    fn prototype_chain_lookup_typed_property(
        &self,
        object_id: ObjectId,
        key: &TypedPropertyKey,
    ) -> Result<Option<RuntimeProperty>, InterpreterError> {
        let key = match key {
            TypedPropertyKey::String(key) => {
                RuntimePropertyKey::String(JsString::from(key.as_str()))
            }
            TypedPropertyKey::Symbol(symbol) => RuntimePropertyKey::Symbol(*symbol),
        };
        self.prototype_chain_lookup_runtime_property(object_id, &key)
    }

    fn prototype_chain_lookup_runtime_property(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
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
            match key {
                RuntimePropertyKey::String(key) => {
                    if let Some(accessor) = object.exact_accessor(key) {
                        return Ok(Some(RuntimeProperty::Accessor(accessor)));
                    }
                    if let Some(val) = object.properties.get_exact(key) {
                        return Ok(Some(RuntimeProperty::Data(val.clone())));
                    }
                }
                RuntimePropertyKey::Symbol(symbol) => {
                    if let Some(property) = object.properties.baseline_symbol_property(*symbol) {
                        return Ok(Some(match property {
                            BaselineSymbolProperty::Data(value) => {
                                RuntimeProperty::Data(value.clone())
                            }
                            BaselineSymbolProperty::Accessor { get, set } => {
                                RuntimeProperty::Accessor(AccessorProperty {
                                    get: get.clone(),
                                    set: set.clone(),
                                })
                            }
                        }));
                    }
                }
            }
            if let Some(property) = self.intrinsic_array_property(id, key) {
                return Ok(Some(property));
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

    fn copy_data_properties_keys(
        &self,
        source: &Value,
    ) -> Result<Vec<RuntimePropertyKey>, InterpreterError> {
        match source {
            Value::Undefined | Value::Null => Err(InterpreterError::TypeError {
                expected: "object-coercible object-rest source".to_string(),
                got: source.type_name().to_string(),
            }),
            Value::Str(text) => Ok((0..text.utf16_len())
                .map(|index| RuntimePropertyKey::String(JsString::from(index.to_string())))
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
                Ok(object.own_runtime_property_keys().into_iter().collect())
            }
        }
    }

    fn copy_data_properties_own_property(
        &self,
        source: &Value,
        key: &RuntimePropertyKey,
        string_units: Option<&[u16]>,
    ) -> Result<Option<RuntimeProperty>, InterpreterError> {
        if let Some(units) = string_units {
            let RuntimePropertyKey::String(key) = key else {
                return Ok(None);
            };
            let Some(key) = key.as_str() else {
                return Ok(None);
            };
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
        if !object.own_property_attributes(key).enumerable {
            return Ok(None);
        }
        Ok(match key {
            RuntimePropertyKey::String(key) => {
                if let Some(accessor) = object.exact_accessor(key) {
                    Some(RuntimeProperty::Accessor(accessor))
                } else {
                    object
                        .properties
                        .get_exact(key)
                        .cloned()
                        .map(RuntimeProperty::Data)
                }
            }
            RuntimePropertyKey::Symbol(symbol) => object
                .properties
                .baseline_symbol_property(*symbol)
                .map(|property| match property {
                    BaselineSymbolProperty::Data(value) => RuntimeProperty::Data(value.clone()),
                    BaselineSymbolProperty::Accessor { get, set } => {
                        RuntimeProperty::Accessor(AccessorProperty {
                            get: get.clone(),
                            set: set.clone(),
                        })
                    }
                }),
        })
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

    /// Apply one copied value according to the operation's target-write
    /// semantics. Object rest/spread use CreateDataProperty; Object.assign
    /// uses Set and therefore may suspend in a target setter.
    fn write_copied_property(
        &mut self,
        module: &Ir3Module,
        state_index: usize,
        key: RuntimePropertyKey,
        value: Value,
        mut label: crate::ifc_artifacts::Label,
    ) -> Result<bool, InterpreterError> {
        let target_id = self.copy_data_properties_states[state_index].target_id;
        let state = &self.copy_data_properties_states[state_index];
        label = label.join(&state.source_label);
        if let Some(source) = self.copy_data_properties_object_id(&state.source) {
            label = label.join(&self.runtime_property_label(source, &key));
        }
        let write_mode = self.copy_data_properties_states[state_index]
            .write_mode
            .clone();
        let CopyDataPropertiesWriteMode::Set {
            target_receiver, ..
        } = write_mode
        else {
            self.create_data_property_or_throw(target_id, key, value, &label)?;
            return Ok(false);
        };
        let accepted = self.set_runtime_property_with_receiver(
            module,
            target_receiver,
            target_id,
            key,
            value,
            label,
        )?;
        if !accepted {
            return Err(Self::property_definition_error());
        }
        Ok(false)
    }

    /// Execute or resume one typed own-property copy. Returns `true` when
    /// control entered a getter or setter; that call returns to this same
    /// instruction and, for getters, writes `value_dst`.
    fn execute_copy_data_properties(
        &mut self,
        module: &Ir3Module,
        target: u32,
        source: u32,
        excluded: RegRange,
        value_dst: u32,
        write_mode: CopyDataPropertiesWriteMode,
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
            let target_id = match &write_mode {
                CopyDataPropertiesWriteMode::CreateData => {
                    let target_value = self.read_reg(target)?;
                    let Value::Object(target_id) = target_value else {
                        return Err(InterpreterError::TypeError {
                            expected: "object CopyDataProperties target".to_string(),
                            got: target_value.type_name().to_string(),
                        });
                    };
                    self.heap
                        .get(target_id.0 as usize)
                        .ok_or(InterpreterError::ObjectNotFound { id: target_id.0 })?;
                    target_id
                }
                CopyDataPropertiesWriteMode::Set {
                    target_receiver, ..
                } => match target_receiver {
                    Value::Object(target_id) => {
                        self.heap
                            .get(target_id.0 as usize)
                            .ok_or(InterpreterError::ObjectNotFound { id: target_id.0 })?;
                        *target_id
                    }
                    function_like if Self::function_object_key(function_like).is_some() => self
                        .ensure_function_object(function_like)?
                        .expect("function-like assign target should have an object carrier"),
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "object Object.assign target".to_string(),
                            got: other.type_name().to_string(),
                        });
                    }
                },
            };
            let source_value = self.read_reg(source)?;
            let mut source_label = self.read_reg_label(source)?;
            if let Some(source_id) = self.copy_data_properties_object_id(&source_value) {
                source_label =
                    source_label.join(&self.observe_property_structure(source_id, false));
            }
            self.join_descriptor_structure_label(target_id, &source_label)?;
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
                excluded_keys.insert(Self::executable_property_key(&self.read_reg(register)?));
            }
            let state = CopyDataPropertiesState {
                instruction_ip,
                register_base,
                call_depth,
                target_id,
                source: source_value,
                source_label,
                string_units,
                keys,
                excluded: excluded_keys,
                next_index: 0,
                write_mode,
                awaiting: None,
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

        if let Some(CopyDataPropertiesAwaiting::Getter(key)) = self.copy_data_properties_states
            [state_index]
            .awaiting
            .take()
        {
            let value = match self.read_reg(value_dst) {
                Ok(value) => value,
                Err(err) => {
                    self.discard_copy_data_properties_state(state_index);
                    return Err(err);
                }
            };
            match self.write_copied_property(
                module,
                state_index,
                key,
                value,
                self.read_reg_label(value_dst)?,
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(err) => {
                    self.discard_copy_data_properties_state(state_index);
                    return Err(err);
                }
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
                        match self.write_copied_property(
                            module,
                            state_index,
                            key,
                            Value::Undefined,
                            crate::ifc_artifacts::Label::Public,
                        ) {
                            Ok(true) => return Ok(true),
                            Ok(false) => continue,
                            Err(err) => {
                                self.discard_copy_data_properties_state(state_index);
                                return Err(err);
                            }
                        }
                    };
                    let getter_label = match &source_value {
                        Value::Object(source_id) => self.runtime_property_label(*source_id, &key),
                        _ => crate::ifc_artifacts::Label::Public,
                    };
                    self.copy_data_properties_states[state_index].awaiting =
                        Some(CopyDataPropertiesAwaiting::Getter(key));
                    if let Err(err) = self.sync_estimated_memory_bytes() {
                        self.discard_copy_data_properties_state(state_index);
                        return Err(err);
                    }
                    if let Err(err) = self.enter_function_call(
                        module,
                        getter,
                        source_value,
                        Vec::new(),
                        AccessorCallReturnSite {
                            return_ip: self.ip,
                            return_reg: Some(value_dst),
                            context_label: getter_label
                                .join(&self.copy_data_properties_states[state_index].source_label),
                        },
                    ) {
                        self.discard_copy_data_properties_state(state_index);
                        return Err(err);
                    }
                    return Ok(true);
                }
            };
            match self.write_copied_property(
                module,
                state_index,
                key,
                value,
                crate::ifc_artifacts::Label::Public,
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(err) => {
                    self.discard_copy_data_properties_state(state_index);
                    return Err(err);
                }
            }
        }
    }

    fn load_runtime_property(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        property: Option<RuntimeProperty>,
        dst: u32,
        read_label: crate::ifc_artifacts::Label,
    ) -> Result<bool, InterpreterError> {
        match property {
            Some(RuntimeProperty::Data(value)) => {
                self.write_reg_with_label(dst, value, read_label)?;
                Ok(false)
            }
            Some(RuntimeProperty::Accessor(accessor)) => {
                if let Some(getter) = accessor.get {
                    self.enter_function_call(
                        module,
                        getter,
                        receiver,
                        Vec::new(),
                        AccessorCallReturnSite {
                            return_ip: self.ip + 1,
                            return_reg: Some(dst),
                            context_label: read_label,
                        },
                    )?;
                    Ok(true)
                } else {
                    self.write_reg_with_label(dst, Value::Undefined, read_label)?;
                    Ok(false)
                }
            }
            None => {
                self.write_reg_with_label(dst, Value::Undefined, read_label)?;
                Ok(false)
            }
        }
    }

    fn load_object_property_or_call_accessor(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        dst: u32,
        read_label: crate::ifc_artifacts::Label,
    ) -> Result<bool, InterpreterError> {
        self.run_pre_runtime_property_access_hook(module, object_id, key)?;
        let property = self.prototype_chain_lookup_runtime_property(object_id, key)?;
        let read_label = read_label.join(&self.runtime_property_label(object_id, key));
        self.load_runtime_property(module, receiver, property, dst, read_label)
    }

    /// The object-literal prototype initializer bypasses ordinary [[Set]],
    /// including an earlier own data property or accessor named `__proto__`.
    fn initialize_object_literal_prototype(
        &mut self,
        args: RegRange,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        let (target, target_label) = self.promise_hostcall_argument(args, 0)?;
        let (value, value_label) = self.promise_hostcall_argument(args, 1)?;
        let object = self.expect_object(target.clone(), "object literal target")?;
        let label = target_label
            .join(&value_label)
            .join(&self.observe_property_structure(object, false));
        let previous_prototype = self.heap[object.0 as usize].prototype;
        let previous_label = self.heap[object.0 as usize]
            .property_structure_label
            .clone();
        let snapshot = self.snapshot_call_setup(None, false);
        let outcome = (|| -> Result<(), InterpreterError> {
            let prototype = match &value {
                Value::Object(_) => Some(Some(
                    self.expect_object(value.clone(), "object literal prototype")?,
                )),
                Value::Null => Some(None),
                function if Self::function_object_key(function).is_some() => {
                    Some(self.ensure_function_object(function)?)
                }
                // Non-object, non-null initializer values are ignored.
                _ => None,
            };
            // Even an ignored primitive can select whether a prototype is
            // installed. Preserve that decision for reads through public aliases.
            self.join_descriptor_structure_label(object, &label)?;
            if let Some(prototype) = prototype {
                self.heap[object.0 as usize].prototype = prototype;
            }
            self.sync_estimated_memory_bytes().map(|_| ())
        })();
        if let Err(error) = outcome {
            self.heap[object.0 as usize].prototype = previous_prototype;
            self.heap[object.0 as usize].property_structure_label = previous_label;
            self.restore_call_setup(snapshot);
            return Err(self.preserve_property_error_label(error, label)?);
        }
        Ok((target, label))
    }

    /// Property mutation observes function own descriptors lazily, while
    /// primitive receivers cannot acquire persistent data properties.
    fn property_mutation_target(
        &mut self,
        value: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        match value {
            Value::Object(object) => Ok(Some(*object)),
            function if Self::function_object_key(function).is_some() => {
                self.ensure_function_object(function)
            }
            Value::Bool(_) | Value::Int(_) | Value::Float(_) | Value::Str(_) | Value::Symbol(_) => {
                Ok(None)
            }
            other => Err(InterpreterError::TypeError {
                expected: "object-coercible property base".into(),
                got: other.type_name().into(),
            }),
        }
    }

    fn set_property_for_instruction(
        &mut self,
        module: &Ir3Module,
        base: &Value,
        receiver: Value,
        key: RuntimePropertyKey,
        value: Value,
        label: &mut crate::ifc_artifacts::Label,
    ) -> Result<bool, InterpreterError> {
        // Legacy hooks cannot observe an exact key they cannot represent.
        // Refuse before a lazy function backing or prototype is allocated.
        self.preflight_legacy_property_key_for_hook(&key)?;
        let Some(lookup_object) = self.property_mutation_target(base)? else {
            return Ok(false);
        };
        self.materialize_function_descriptor(base, lookup_object, &key)?;
        *label = label
            .join(&self.runtime_property_label(lookup_object, &key))
            .join(&self.observe_property_structure(lookup_object, true));
        // A super setter may receive a primitive or nullish `this`. Only a
        // data write requires an object receiver; defer that distinction to
        // OrdinarySetWithOwnDescriptor after finding the inherited property.
        if (matches!(&receiver, Value::Object(_)) || Self::function_object_key(&receiver).is_some())
            && let Some(receiver_object) = self.property_mutation_target(&receiver)?
        {
            self.materialize_function_descriptor(&receiver, receiver_object, &key)?;
            *label = label.join(&self.observe_property_structure(receiver_object, false));
        }
        self.set_runtime_property_with_receiver(
            module,
            receiver,
            lookup_object,
            key,
            value,
            label.clone(),
        )
    }

    fn property_mutation_refused(operation: &str) -> InterpreterError {
        InterpreterError::TypeError {
            expected: format!("successful property {operation}"),
            got: "property descriptor refused the mutation".into(),
        }
    }

    /// Descriptor metadata can itself be secret. A catchable refusal must
    /// retain that provenance just like an explicit throw from a setter.
    fn preserve_property_error_label(
        &mut self,
        error: InterpreterError,
        label: crate::ifc_artifacts::Label,
    ) -> Result<InterpreterError, InterpreterError> {
        if matches!(error, InterpreterError::UncaughtException { .. }) {
            if let Some(exception) = &mut self.pending_exception {
                exception.label = exception.label.join(&label);
            }
            return Ok(error);
        }
        if Self::is_js_catchable_error(&error)
            && !matches!(label, crate::ifc_artifacts::Label::Public)
        {
            let value = self.promise_error_value(&error)?;
            return Ok(self.rearm_inline_throw(LabeledException { value, label }));
        }
        Ok(error)
    }

    fn load_function_like_property_or_call_accessor(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        key: &RuntimePropertyKey,
        dst: u32,
        read_label: crate::ifc_artifacts::Label,
    ) -> Result<bool, InterpreterError> {
        if let (
            Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::Symbol,
                ..
            }),
            RuntimePropertyKey::String(key),
        ) = (&receiver, key)
            && let Some(key) = key.as_str()
            && let Some(value) = Self::symbol_constructor_property_value(key)
        {
            self.write_reg(dst, value)?;
            return Ok(false);
        }

        let method_name = if matches!(key, RuntimePropertyKey::String(key) if key.as_str() == Some("name"))
            && let Value::Closure(closure_id)
            | Value::AsyncFunction(closure_id)
            | Value::AsyncGeneratorFunction(closure_id) = &receiver
        {
            self.closure_method_metadata
                .get(closure_id)
                .map(|metadata| (metadata.name.clone(), metadata.definition_label.clone()))
        } else {
            None
        };
        if let Some((name, label)) = method_name {
            self.write_reg_with_label(dst, Value::Str(name), label.join(&read_label))?;
            return Ok(false);
        }

        if let Some(object_id) = self.function_object_id(&receiver) {
            self.run_pre_runtime_property_access_hook(module, object_id, key)?;
            // A derived constructor inherits static properties, but its lazy
            // own `prototype` must shadow a materialized parent's descriptor.
            // Existing own data/accessor descriptors remain authoritative.
            self.materialize_function_descriptor(&receiver, object_id, key)?;
            if let Some(property) = self.prototype_chain_lookup_runtime_property(object_id, key)? {
                let read_label = read_label.join(&self.runtime_property_label(object_id, key));
                return self.load_runtime_property(
                    module,
                    receiver,
                    Some(property),
                    dst,
                    read_label,
                );
            }
        } else {
            self.preflight_legacy_property_key_for_hook(key)?;
        }

        if matches!(key, RuntimePropertyKey::String(key) if key.as_str() == Some("prototype"))
            && let Some(prototype) = self.function_prototype_for_value(&receiver)?
        {
            self.write_reg(dst, Value::Object(prototype))?;
            return Ok(false);
        }

        if let Some(value) = self.intrinsic_function_property(&receiver, key) {
            self.write_reg_with_label(dst, value, read_label)?;
            return Ok(false);
        }

        self.write_reg(dst, Value::Undefined)?;
        Ok(false)
    }

    #[cfg(test)]
    fn prototype_chain_has_typed_key(
        &self,
        object_id: ObjectId,
        key: &TypedPropertyKey,
    ) -> Result<bool, InterpreterError> {
        let key = match key {
            TypedPropertyKey::String(key) => {
                RuntimePropertyKey::String(JsString::from(key.as_str()))
            }
            TypedPropertyKey::Symbol(symbol) => RuntimePropertyKey::Symbol(*symbol),
        };
        self.prototype_chain_has_runtime_key(object_id, &key)
    }

    fn prototype_chain_has_runtime_key(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
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
            if object.contains_own_runtime_property(key)
                || self.intrinsic_array_property(id, key).is_some()
            {
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
            Value::Symbol(symbol) => crate::object_model::JsValue::Symbol(*symbol),
            Value::Object(id) => {
                crate::object_model::JsValue::Object(crate::object_model::ObjectHandle(id.0))
            }
            Value::Function(idx) => crate::object_model::JsValue::Function(*idx),
            Value::Promise(handle) => crate::object_model::JsValue::Promise(*handle),
            Value::Closure(handle) => crate::object_model::JsValue::Closure(*handle),
            Value::Iterator(handle) => crate::object_model::JsValue::Iterator(*handle),
            Value::GeneratorFunction(handle) => {
                crate::object_model::JsValue::GeneratorFunction(*handle)
            }
            Value::Generator(handle) => crate::object_model::JsValue::Generator(*handle),
            Value::AsyncFunction(handle) => crate::object_model::JsValue::AsyncFunction(*handle),
            Value::AsyncFunctionObject(handle) => {
                crate::object_model::JsValue::AsyncFunctionObject(*handle)
            }
            Value::AsyncGeneratorFunction(handle) => {
                crate::object_model::JsValue::AsyncGeneratorFunction(*handle)
            }
            Value::AsyncGeneratorObject(handle) => {
                crate::object_model::JsValue::AsyncGeneratorObject(*handle)
            }
            Value::BuiltinFunction(builtin) => {
                crate::object_model::JsValue::BuiltinFunction(builtin.clone())
            }
        }
    }

    /// Convert a `JsValue` from `object_model` back to a baseline `Value`.
    #[allow(dead_code)]
    fn js_value_to_value(jv: &crate::object_model::JsValue) -> Value {
        match jv {
            crate::object_model::JsValue::Undefined => Value::Undefined,
            crate::object_model::JsValue::Null => Value::Null,
            crate::object_model::JsValue::Bool(b) => Value::Bool(*b),
            crate::object_model::JsValue::Int(n) => js_int_to_value(*n),
            crate::object_model::JsValue::Str(s) => Value::Str(s.clone()),
            crate::object_model::JsValue::Float(bits) => {
                Value::Float(Float64::new(f64::from_bits(*bits)))
            }
            crate::object_model::JsValue::Object(handle) => Value::Object(ObjectId(handle.0)),
            crate::object_model::JsValue::Function(idx) => Value::Function(*idx),
            crate::object_model::JsValue::Promise(handle) => Value::Promise(*handle),
            crate::object_model::JsValue::Symbol(sym) => Value::Symbol(*sym),
            crate::object_model::JsValue::Closure(handle) => Value::Closure(*handle),
            crate::object_model::JsValue::Iterator(handle) => Value::Iterator(*handle),
            crate::object_model::JsValue::GeneratorFunction(handle) => {
                Value::GeneratorFunction(*handle)
            }
            crate::object_model::JsValue::Generator(handle) => Value::Generator(*handle),
            crate::object_model::JsValue::AsyncFunction(handle) => Value::AsyncFunction(*handle),
            crate::object_model::JsValue::AsyncFunctionObject(handle) => {
                Value::AsyncFunctionObject(*handle)
            }
            crate::object_model::JsValue::AsyncGeneratorFunction(handle) => {
                Value::AsyncGeneratorFunction(*handle)
            }
            crate::object_model::JsValue::AsyncGeneratorObject(handle) => {
                Value::AsyncGeneratorObject(*handle)
            }
            crate::object_model::JsValue::BuiltinFunction(builtin) => {
                Value::BuiltinFunction(builtin.clone())
            }
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

    fn array_like_length(&self, obj_id: ObjectId) -> Result<u32, InterpreterError> {
        let object = self
            .heap
            .get(obj_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: obj_id.0 })?;
        if matches!(object.properties.get("length"), Some(Value::Symbol(_))) {
            return Err(InterpreterError::TypeError {
                expected: "array-like length coercible to number".to_string(),
                got: "symbol".to_string(),
            });
        }
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

    fn register_combinator(
        &mut self,
        state: LabeledPromiseCombinatorState,
    ) -> Result<u64, InterpreterError> {
        // Full transactional charge: map entry + tracker payload + label
        // (bd-ur3tk.21; supersedes the bd-ur3tk.8 label-only charge without
        // double-counting — the label is part of the state estimate).
        let retained_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(Self::estimate_promise_combinator_state_bytes(&state));
        self.check_temporary_memory_budget(retained_bytes)?;
        let requested_bytes = self.estimated_memory_bytes.saturating_add(retained_bytes);
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        let id = self.next_promise_combinator_id;
        self.next_promise_combinator_id = self.next_promise_combinator_id.saturating_add(1);
        self.promise_combinators.insert(id, state);
        self.estimated_memory_bytes = requested_bytes;
        Ok(id)
    }

    fn join_promise_combinator_label(
        &mut self,
        combinator_id: u64,
        label: &crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let Some(state) = self.promise_combinators.get(&combinator_id) else {
            return Ok(());
        };
        let previous_bytes = Self::estimate_label_bytes(&state.accumulated_label);
        let winner = if state.accumulated_label.level() >= label.level() {
            &state.accumulated_label
        } else {
            label
        };
        let next_bytes = Self::estimate_label_bytes(winner);
        // Joining clones the dominant Custom label before the old accumulator
        // is released. Charge that physical peak as well as the retained
        // replacement so a one-byte-short ceiling fails atomically.
        self.check_temporary_memory_budget(next_bytes)?;
        let joined = state.accumulated_label.join(label);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(next_bytes);
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.promise_combinators
            .get_mut(&combinator_id)
            .expect("combinator remained present across label preflight")
            .accumulated_label = joined;
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    fn clone_promise_combinator_label_with_budget(
        &self,
        combinator_id: u64,
    ) -> Result<Option<crate::ifc_artifacts::Label>, InterpreterError> {
        let Some(label) = self
            .promise_combinators
            .get(&combinator_id)
            .map(|state| &state.accumulated_label)
        else {
            return Ok(None);
        };
        self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
        Ok(Some(label.clone()))
    }

    fn remove_promise_combinator(
        &mut self,
        combinator_id: u64,
    ) -> Option<LabeledPromiseCombinatorState> {
        let state = self.promise_combinators.remove(&combinator_id)?;
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_promise_combinator_state_bytes(&state)),
        );
        Some(state)
    }

    #[cfg(test)]
    fn add_combinator_watcher(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        watcher: PromiseCombinatorWatcher,
    ) -> Result<(), InterpreterError> {
        // Map entry (for a fresh key) plus one watcher slot (bd-ur3tk.21).
        let entry_bytes = if self.promise_combinator_watchers.contains_key(&handle) {
            0
        } else {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
        };
        let retained_bytes =
            entry_bytes.saturating_add(std::mem::size_of::<PromiseCombinatorWatcher>() as u64);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(retained_bytes);
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.promise_combinator_watchers
            .entry(handle)
            .or_default()
            .push(watcher);
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    /// Create a pending Promise with its record and witness event charged
    /// transactionally; a ceiling refusal rolls the fresh handle back
    /// (bd-ur3tk.21).
    fn create_promise_accounted(
        &mut self,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        let previous_bytes = self.promise_runtime_memory_bytes();
        let handle = self.promise_store.create();
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_bytes) {
            self.promise_store.rollback_last_created(handle);
            return Err(error);
        }
        Ok(handle)
    }

    /// Register a `.then` reaction with the derived promise, reaction slots,
    /// and any immediate settled-path microtask charged transactionally; a
    /// ceiling refusal restores the pre-registration store and queue
    /// (bd-ur3tk.21).
    fn register_promise_then_accounted(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        on_fulfilled: Option<crate::closure_model::ClosureHandle>,
        on_rejected: Option<crate::closure_model::ClosureHandle>,
        label: crate::ifc_artifacts::Label,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        let previous_bytes = self.promise_runtime_memory_bytes();
        self.check_temporary_memory_budget(previous_bytes)?;
        let store_snapshot = self.promise_store.clone();
        let queue_snapshot = self.event_loop.microtasks.clone();
        let result = self
            .promise_store
            .then(
                handle,
                on_fulfilled,
                on_rejected,
                label,
                &mut self.event_loop.microtasks,
            )
            .map_err(|e| InterpreterError::TypeError {
                expected: "valid promise handle".to_string(),
                got: e.to_string(),
            })?;
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_bytes) {
            self.promise_store = store_snapshot;
            self.event_loop.microtasks = queue_snapshot;
            return Err(error);
        }
        Ok(result)
    }

    /// Install executable callbacks together with their Promise reactions.
    /// Reserve their retained state before mutating the store so a memory
    /// refusal cannot leave a dangling callback or a partially registered pair.
    fn register_executable_promise_reactions(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        registration: PromiseReactionRegistration,
        label: crate::ifc_artifacts::Label,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        if registration.on_fulfilled.is_none() && registration.on_rejected.is_none() {
            return self.register_promise_then_accounted(handle, None, None, label);
        }
        let retained_bytes = Self::estimate_promise_reaction_registration_bytes(&registration);
        self.check_temporary_memory_budget(retained_bytes)?;
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_add(retained_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(retained_bytes);
        let result = self.register_promise_then_accounted(
            handle,
            registration
                .on_fulfilled
                .as_ref()
                .map(|_| crate::closure_model::ClosureHandle(0)),
            registration
                .on_rejected
                .as_ref()
                .map(|_| crate::closure_model::ClosureHandle(1)),
            label,
        );
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_sub(retained_bytes);
        match result {
            Ok(result) => {
                self.promise_reactions.insert(result, registration);
                Ok(result)
            }
            Err(error) => {
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(retained_bytes);
                Err(error)
            }
        }
    }

    fn run_executable_promise_reaction(
        &mut self,
        module: Option<&Ir3Module>,
        result_promise: crate::promise_model::PromiseHandle,
        rejected: bool,
        argument: crate::object_model::JsValue,
        task_label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let registration = self
            .promise_reactions
            .remove(&result_promise)
            .expect("reaction presence checked by the queue dispatcher");
        let retained_bytes = Self::estimate_promise_reaction_registration_bytes(&registration);
        // The moved callback, opposite handler, and saved finally completion
        // remain resident while guest code runs and performs nested allocations.
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_add(retained_bytes);
        let action = if rejected {
            registration.on_rejected
        } else {
            registration.on_fulfilled
        };
        let outcome = self.execute_promise_reaction_action(
            module,
            action,
            result_promise,
            rejected,
            argument,
            task_label,
        );
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_sub(retained_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(retained_bytes);
        outcome
    }

    fn execute_promise_reaction_action(
        &mut self,
        module: Option<&Ir3Module>,
        action: Option<PromiseReactionAction>,
        result_promise: crate::promise_model::PromiseHandle,
        rejected: bool,
        argument: crate::object_model::JsValue,
        task_label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let Some(action) = action else {
            return if rejected {
                self.reject_promise(result_promise, argument, task_label)
            } else {
                self.resolve_promise_with_value(
                    result_promise,
                    Self::js_value_to_value(&argument),
                    task_label,
                )
            };
        };
        let is_finally = matches!(&action, PromiseReactionAction::Finally(_));
        match action {
            PromiseReactionAction::Combinator {
                combinator_id,
                index,
            } => {
                if rejected {
                    self.update_combinator_rejection(
                        combinator_id,
                        index,
                        argument,
                        task_label.clone(),
                    )?;
                } else {
                    self.update_combinator_fulfillment(
                        combinator_id,
                        index,
                        argument,
                        task_label.clone(),
                    )?;
                }
                // Each PerformPromiseThen call creates a derived Promise,
                // even though the aggregate discards this callback's result.
                // The internal element callback returns undefined normally.
                self.fulfill_promise(
                    result_promise,
                    crate::object_model::JsValue::Undefined,
                    task_label,
                )
            }
            PromiseReactionAction::Forward(target) => {
                if !self.promise_is_settled(target) {
                    if rejected {
                        self.reject_promise(target, argument, task_label.clone())?;
                    } else {
                        self.resolve_promise_with_value(
                            target,
                            Self::js_value_to_value(&argument),
                            task_label.clone(),
                        )?;
                    }
                }
                self.fulfill_promise(
                    result_promise,
                    crate::object_model::JsValue::Undefined,
                    task_label,
                )
            }
            PromiseReactionAction::Restore {
                value,
                rejected,
                label,
            } => {
                let label = task_label.join(&label);
                if rejected {
                    self.reject_promise(result_promise, Self::value_to_js_value(&value), label)
                } else {
                    self.resolve_promise_with_value(result_promise, value, label)
                }
            }
            PromiseReactionAction::Call(callee) | PromiseReactionAction::Finally(callee) => {
                let module = module.ok_or_else(|| InterpreterError::TypeError {
                    expected: "module context for Promise reaction".to_string(),
                    got: "missing module context".to_string(),
                })?;
                let arguments = if is_finally {
                    Vec::new()
                } else {
                    vec![(Self::js_value_to_value(&argument), task_label.clone())]
                };
                let completion = self.invoke_inline_method_call_labeled(
                    module,
                    callee,
                    Value::Undefined,
                    &arguments,
                );
                match completion {
                    Ok((InlineCallCompletion::Value(value), return_label)) => {
                        let label = task_label.join(&return_label);
                        if !is_finally {
                            return self.resolve_promise_with_value(result_promise, value, label);
                        }
                        // Finally's thunk runs only after the finalizer result
                        // resolves. The outer reaction then adopts that thunk's
                        // promise, retaining the ordinary Promise job ordering.
                        let finalizer = if let Value::Promise(handle) = value {
                            crate::promise_model::PromiseHandle(handle)
                        } else {
                            let handle = self.create_promise_accounted()?;
                            self.resolve_promise_with_value(handle, value, label.clone())?;
                            handle
                        };
                        let continuation = self.register_executable_promise_reactions(
                            finalizer,
                            PromiseReactionRegistration {
                                on_fulfilled: Some(PromiseReactionAction::Restore {
                                    value: Self::js_value_to_value(&argument),
                                    rejected,
                                    label: task_label,
                                }),
                                on_rejected: None,
                            },
                            label.clone(),
                        )?;
                        self.resolve_promise_with_value(
                            result_promise,
                            Value::Promise(continuation.0),
                            label,
                        )
                    }
                    Ok((InlineCallCompletion::Throw(thrown), _)) => self.reject_promise(
                        result_promise,
                        Self::value_to_js_value(&thrown.value),
                        task_label.join(&thrown.label),
                    ),
                    Err(error) if Self::is_js_catchable_error(&error) => {
                        let reason = self.promise_error_value(&error)?;
                        self.reject_promise(
                            result_promise,
                            Self::value_to_js_value(&reason),
                            task_label,
                        )
                    }
                    // Budgets, cancellation, and policy refusals remain engine
                    // failures; guest catch handlers cannot turn them into work.
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn fulfill_promise(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        value: crate::object_model::JsValue,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        // Transactional settlement (bd-ur3tk.21): the settled payload, replay
        // witness, and every reaction microtask are charged atomically; a
        // ceiling refusal restores the pre-settlement store and queue. The
        // rollback clones are transient double-residency, preflighted first.
        let previous_bytes = self.promise_runtime_memory_bytes();
        self.check_temporary_memory_budget(previous_bytes)?;
        let store_snapshot = self.promise_store.clone();
        let queue_snapshot = self.event_loop.microtasks.clone();
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
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_bytes) {
            self.promise_store = store_snapshot;
            self.event_loop.microtasks = queue_snapshot;
            return Err(error);
        }
        self.notify_promise_settled(handle, PromiseSettlement::Fulfilled(value), label)?;
        Ok(())
    }

    fn reject_promise(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        reason: crate::object_model::JsValue,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        // Mirrors `fulfill_promise` (bd-ur3tk.21).
        let previous_bytes = self.promise_runtime_memory_bytes();
        self.check_temporary_memory_budget(previous_bytes)?;
        let store_snapshot = self.promise_store.clone();
        let queue_snapshot = self.event_loop.microtasks.clone();
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
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_bytes) {
            self.promise_store = store_snapshot;
            self.event_loop.microtasks = queue_snapshot;
            return Err(error);
        }
        self.notify_promise_settled(handle, PromiseSettlement::Rejected(reason), label)?;
        Ok(())
    }

    /// Whether a promise handle has left the pending state.
    fn promise_is_settled(&self, handle: crate::promise_model::PromiseHandle) -> bool {
        self.promise_store
            .get(handle)
            .map(|record| record.state.is_settled())
            .unwrap_or(false)
    }

    /// ES2020 25.6.1.3.2 Promise Resolve Function (bd-3ose7). If `value` is a
    /// thenable (an object whose `then` is a user closure), adopt its eventual
    /// state by enqueuing a PromiseResolveThenableJob carrying `label`;
    /// otherwise fulfill directly. The `label` is preserved through resolution
    /// rather than collapsed to `Public`, keeping data provenance sound.
    fn resolve_promise_with_value(
        &mut self,
        promise: crate::promise_model::PromiseHandle,
        value: Value,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        if let Value::Promise(source) = value {
            if source == promise.0 {
                let error = self.alloc_object_with_properties(&[
                    ("name", Value::str("TypeError")),
                    ("message", Value::str("A promise cannot resolve to itself")),
                ])?;
                return self.reject_promise(
                    promise,
                    Self::value_to_js_value(&Value::Object(error)),
                    label,
                );
            }
            // Resolution adopts a Promise's eventual state, including a
            // pending source; it must never fulfill with the handle itself.
            // Registering the forwarding reactions is itself a queued job,
            // matching PromiseResolveThenableJob ordering.
            self.promise_store
                .get(crate::promise_model::PromiseHandle(source))
                .map_err(|error| InterpreterError::TypeError {
                    expected: "valid promise resolution source".to_string(),
                    got: error.to_string(),
                })?;
            let previous_bytes = self.promise_runtime_memory_bytes();
            self.event_loop
                .microtasks
                .enqueue(crate::promise_model::Microtask::ResolveThenable {
                    promise,
                    then_handler: crate::closure_model::ClosureHandle(0),
                    thenable: crate::object_model::JsValue::Promise(source),
                    label,
                });
            if let Err(error) = self.apply_promise_runtime_memory_delta(previous_bytes) {
                self.event_loop.microtasks.rollback_last_enqueued();
                return Err(error);
            }
            return Ok(());
        }
        let object_id = match &value {
            Value::Object(id) => Some(*id),
            _ => self.function_object_id(&value),
        };
        let mut label = label;
        if let Some(object_id) = object_id {
            let key = RuntimePropertyKey::String(JsString::from("then"));
            label = label.join(&self.runtime_property_label(object_id, &key));
            let property = self.prototype_chain_lookup_runtime_property(object_id, &key)?;
            let then = match property {
                Some(RuntimeProperty::Data(then)) => then,
                Some(RuntimeProperty::Accessor(accessor)) => match accessor.get {
                    Some(getter) => {
                        // Source getters retain their defining executable.
                        // Prefer that owner even when resolution happens in an
                        // importing module or a later Promise reaction.
                        let program = self
                            .callable_module(&getter)?
                            .or_else(|| {
                                self.current_module_specifier
                                    .as_ref()
                                    .and_then(|specifier| {
                                        self.module_state
                                            .modules
                                            .get(specifier)
                                            .and_then(|record| record.compiled_module.clone())
                                    })
                            })
                            .ok_or_else(|| InterpreterError::ModuleEvaluationFailed {
                                specifier: self
                                    .current_module_specifier
                                    .clone()
                                    .unwrap_or_else(|| "<unowned getter>".to_string()),
                                reason: "Promise then getter has no executable owner".to_string(),
                            })?;
                        self.run_pre_runtime_property_access_hook(&program, object_id, &key)?;
                        match self.invoke_inline_method_call_with_receiver_label(
                            &program,
                            getter,
                            value.clone(),
                            label.clone(),
                            &[],
                        ) {
                            Ok((InlineCallCompletion::Value(then), getter_label)) => {
                                label = label.join(&getter_label);
                                then
                            }
                            Ok((InlineCallCompletion::Throw(thrown), _)) => {
                                return self.reject_promise(
                                    promise,
                                    Self::value_to_js_value(&thrown.value),
                                    label.join(&thrown.label),
                                );
                            }
                            Err(error) if Self::is_js_catchable_error(&error) => {
                                let reason = self.promise_error_value(&error)?;
                                return self.reject_promise(
                                    promise,
                                    Self::value_to_js_value(&reason),
                                    label,
                                );
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    None => Value::Undefined,
                },
                None => Value::Undefined,
            };
            if Self::is_sync_callable(&then) {
                // Get(thenable, "then") happens once during resolution. The
                // later job invokes this exact callable even if the property
                // is replaced, deleted, or has a stateful getter.
                self.check_temporary_memory_budget(
                    Self::estimate_timer_value_bytes(&then)
                        .saturating_add(Self::estimate_timer_value_bytes(&value)),
                )?;
                let task = crate::promise_model::Microtask::ResolveThenableValue {
                    promise,
                    then: Self::value_to_js_value(&then),
                    thenable: Self::value_to_js_value(&value),
                    label,
                };
                let previous_bytes = self.promise_runtime_memory_bytes();
                self.event_loop.microtasks.enqueue(task);
                if let Err(error) = self.apply_promise_runtime_memory_delta(previous_bytes) {
                    self.event_loop.microtasks.rollback_last_enqueued();
                    return Err(error);
                }
                return Ok(());
            }
        }
        self.fulfill_promise(promise, Self::value_to_js_value(&value), label)
    }

    /// Apply a resolve/reject capability bound to `promise` (ES
    /// CreateResolvingFunctions). Settling is once-only (`alreadyResolved`): a
    /// second call after the promise leaves the pending state is a silent
    /// no-op. The settlement adopts the resolve/reject argument's own IFC
    /// label so provenance is preserved (bd-3ose7).
    fn apply_promise_capability(
        &mut self,
        promise: crate::promise_model::PromiseHandle,
        args: RegRange,
        is_resolve: bool,
    ) -> Result<Value, InterpreterError> {
        let (argument, argument_label) = self.promise_hostcall_argument(args, 0)?;
        if self.promise_is_settled(promise) {
            return Ok(Value::Undefined);
        }
        if is_resolve {
            self.resolve_promise_with_value(promise, argument, argument_label)?;
        } else {
            self.reject_promise(promise, Self::value_to_js_value(&argument), argument_label)?;
        }
        Ok(Value::Undefined)
    }

    fn create_promise_resolving_functions(
        &mut self,
        promise: crate::promise_model::PromiseHandle,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(u32, Value, Value), InterpreterError> {
        let pair_id = u32::try_from(self.promise_resolving_functions.len()).map_err(|_| {
            InterpreterError::TypeError {
                expected: "available Promise resolving-function identity".to_string(),
                got: "exhausted Promise resolving-function identities".to_string(),
            }
        })?;
        let pair = PromiseResolvingFunctions {
            promise,
            already_resolved: false,
            label,
        };
        self.check_temporary_memory_budget(Self::estimate_promise_resolving_functions_bytes(
            &pair,
        ))?;
        let previous_bytes = self.promise_runtime_memory_bytes();
        self.promise_resolving_functions.insert(pair_id, pair);
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_bytes) {
            self.promise_resolving_functions.remove(&pair_id);
            return Err(error);
        }
        Ok((
            pair_id,
            Value::BuiltinFunction(BuiltinFunction::promise_capability(
                BuiltinFunctionKind::PromiseResolveFunction,
                pair_id,
            )),
            Value::BuiltinFunction(BuiltinFunction::promise_capability(
                BuiltinFunctionKind::PromiseRejectFunction,
                pair_id,
            )),
        ))
    }

    fn apply_promise_resolving_function(
        &mut self,
        pair_id: u32,
        argument: Value,
        argument_label: crate::ifc_artifacts::Label,
        is_resolve: bool,
    ) -> Result<(), InterpreterError> {
        let (promise, label) = {
            let pair = self
                .promise_resolving_functions
                .get_mut(&pair_id)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "valid Promise resolving-function identity".to_string(),
                    got: format!("missing Promise resolving-function pair #{pair_id}"),
                })?;
            if pair.already_resolved {
                return Ok(());
            }
            // Lock out both functions before resolution invokes any thenable.
            // The target may remain pending for arbitrarily many queued jobs.
            pair.already_resolved = true;
            (pair.promise, pair.label.join(&argument_label))
        };
        if is_resolve {
            self.resolve_promise_with_value(promise, argument, label)
        } else {
            self.reject_promise(promise, Self::value_to_js_value(&argument), label)
        }
    }

    /// Preserve JavaScript error identity for native runtime failures while
    /// explicit throws continue to carry their original value and label.
    fn promise_error_value(&mut self, error: &InterpreterError) -> Result<Value, InterpreterError> {
        let name = match error {
            InterpreterError::UncaughtException { value } => return Ok(Value::str(value.clone())),
            InterpreterError::RangeError { .. } => "RangeError",
            InterpreterError::UninitializedBinding { .. } => "ReferenceError",
            _ => "TypeError",
        };
        self.alloc_object_with_properties(&[
            ("name", Value::str(name)),
            ("message", Value::str(error.to_string())),
        ])
        .map(Value::Object)
    }

    fn complete_promise_resolving_call(
        &mut self,
        pair_id: u32,
        outcome: Result<(InlineCallCompletion, crate::ifc_artifacts::Label), InterpreterError>,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        match outcome {
            Ok((InlineCallCompletion::Value(_), _)) => Ok(()),
            Ok((InlineCallCompletion::Throw(thrown), _)) => self.apply_promise_resolving_function(
                pair_id,
                thrown.value,
                label.join(&thrown.label),
                false,
            ),
            Err(error) if Self::is_js_catchable_error(&error) => {
                if self
                    .promise_resolving_functions
                    .get(&pair_id)
                    .is_some_and(|pair| pair.already_resolved)
                {
                    return Ok(());
                }
                let reason = self.promise_error_value(&error)?;
                self.apply_promise_resolving_function(pair_id, reason, label, false)
            }
            Err(error) => Err(error),
        }
    }

    fn construct_promise(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        let (executor, label) = self.promise_hostcall_argument(args, 0)?;
        if !Self::is_sync_callable(&executor) {
            return Err(InterpreterError::TypeError {
                expected: "callable Promise executor".to_string(),
                got: executor.type_name().to_string(),
            });
        }
        let promise = self.create_promise_accounted()?;
        let (pair_id, resolve, reject) =
            match self.create_promise_resolving_functions(promise, label.clone()) {
                Ok(pair) => pair,
                Err(error) => {
                    let previous_bytes = self.promise_runtime_memory_bytes();
                    self.promise_store.rollback_last_created(promise);
                    self.apply_promise_runtime_memory_delta(previous_bytes)?;
                    return Err(error);
                }
            };
        let outcome = self.invoke_inline_method_call_labeled(
            module,
            executor,
            Value::Undefined,
            &[(resolve, label.clone()), (reject, label.clone())],
        );
        self.complete_promise_resolving_call(pair_id, outcome, label.clone())?;
        Ok((Value::Promise(promise.0), label))
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
        // Release the removed key's map entry and watcher slots (bd-ur3tk.21).
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(
                u64::try_from(watchers.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<PromiseCombinatorWatcher>() as u64),
            ),
        );
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
        self.join_promise_combinator_label(combinator_id, &label)?;
        // Tracker growth (recorded values/outcomes) is charged transactionally:
        // a ceiling refusal restores the single mutated state (bd-ur3tk.21).
        // The rollback clone is transient double-residency, preflighted first.
        if let Some(state) = self.promise_combinators.get(&combinator_id) {
            self.check_temporary_memory_budget(Self::estimate_promise_combinator_state_bytes(
                state,
            ))?;
        }
        let state_snapshot = self.promise_combinators.get(&combinator_id).cloned();
        let previous_runtime_bytes = self.promise_runtime_memory_bytes();
        if let Some(state) = self.promise_combinators.get_mut(&combinator_id) {
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
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_runtime_bytes) {
            if let (Some(snapshot), Some(slot)) = (
                state_snapshot,
                self.promise_combinators.get_mut(&combinator_id),
            ) {
                *slot = snapshot;
            }
            return Err(error);
        }

        if let Some(resolution) = resolution {
            let resolution_label = self
                .clone_promise_combinator_label_with_budget(combinator_id)?
                .unwrap_or(label);
            match resolution {
                ResolutionData::Fulfill(handle, value) => {
                    // Race and any invoke the aggregate's resolve function.
                    // A previously fulfilled object may have acquired a
                    // callable `then` before this queued element reaction.
                    self.resolve_promise_with_value(
                        handle,
                        Self::js_value_to_value(&value),
                        resolution_label,
                    )?;
                }
                ResolutionData::FulfillAll(handle, values) => {
                    let value = self.build_promise_all_result(values)?;
                    self.fulfill_promise(handle, value, resolution_label)?;
                }
                ResolutionData::FulfillAllSettled(handle, outcomes, total) => {
                    let value = self.build_promise_all_settled_result(outcomes, total)?;
                    self.fulfill_promise(handle, value, resolution_label)?;
                }
            }
            self.remove_promise_combinator(combinator_id);
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
        self.join_promise_combinator_label(combinator_id, &label)?;
        // Mirrors `update_combinator_fulfillment` (bd-ur3tk.21).
        if let Some(state) = self.promise_combinators.get(&combinator_id) {
            self.check_temporary_memory_budget(Self::estimate_promise_combinator_state_bytes(
                state,
            ))?;
        }
        let state_snapshot = self.promise_combinators.get(&combinator_id).cloned();
        let previous_runtime_bytes = self.promise_runtime_memory_bytes();
        if let Some(state) = self.promise_combinators.get_mut(&combinator_id) {
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
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_runtime_bytes) {
            if let (Some(snapshot), Some(slot)) = (
                state_snapshot,
                self.promise_combinators.get_mut(&combinator_id),
            ) {
                *slot = snapshot;
            }
            return Err(error);
        }

        if let Some(resolution) = resolution {
            let resolution_label = self
                .clone_promise_combinator_label_with_budget(combinator_id)?
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
            self.remove_promise_combinator(combinator_id);
        }
        Ok(())
    }

    /// Promise combinators apply PromiseResolve to every input before
    /// installing their element reactions. Existing native Promises retain
    /// identity; ordinary values and thenables acquire a resolved/adopting
    /// Promise whose reaction still runs in a later microtask.
    fn normalize_promise_combinator_input(
        &mut self,
        input: Value,
        label: crate::ifc_artifacts::Label,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        if let Value::Promise(handle) = input {
            let handle = crate::promise_model::PromiseHandle(handle);
            self.promise_store
                .get(handle)
                .map_err(|error| InterpreterError::TypeError {
                    expected: "valid Promise combinator input".to_string(),
                    got: error.to_string(),
                })?;
            return Ok(handle);
        }
        let handle = self.create_promise_accounted()?;
        self.resolve_promise_with_value(handle, input, label)?;
        Ok(handle)
    }

    fn dispatch_promise_combinator(
        &mut self,
        module: &Ir3Module,
        kind: PromiseCombinatorKind,
        args: RegRange,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        // Create the aggregate before GetIterator. Protocol failures reject
        // the returned Promise; extra arguments do not become input values.
        let (iterable, mut accumulated_label) = self.promise_hostcall_argument(args, 0)?;
        let result_promise = self.create_promise_accounted()?;
        let total = 0;
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

        let retained_label_bytes = Self::estimate_label_bytes(&accumulated_label);
        if let Err(error) = self.check_temporary_memory_budget(retained_label_bytes) {
            let rolled_back = self.promise_store.rollback_last_created(result_promise);
            debug_assert!(
                rolled_back,
                "fresh aggregate Promise must remain rollbackable"
            );
            return Err(error);
        }
        let combinator_state = LabeledPromiseCombinatorState {
            tracker: state,
            accumulated_label: accumulated_label.clone(),
        };
        let combinator_id = match self.register_combinator(combinator_state) {
            Ok(combinator_id) => combinator_id,
            Err(error) => {
                let rolled_back = self.promise_store.rollback_last_created(result_promise);
                debug_assert!(
                    rolled_back,
                    "fresh aggregate Promise must remain rollbackable"
                );
                return Err(error);
            }
        };

        let saved_exception = self.pending_exception.take();
        let saved_return = self.pending_return.take();
        let mut active_iterator = None;
        let mut close_on_error = false;
        let outcome = (|| -> Result<u32, InterpreterError> {
            let iterator = self.init_for_of_iterator(module, iterable, &mut accumulated_label)?;
            active_iterator = Some(iterator.clone());
            let mut total = 0u32;
            loop {
                // Native array/string steps can execute no guest bytecode.
                // Charge every step and poll cancellation inside the loop.
                if self
                    .config
                    .cancellation_token
                    .as_ref()
                    .is_some_and(CancellationToken::is_cancelled)
                {
                    return Err(InterpreterError::Cancelled);
                }
                if self.instructions_executed >= self.config.instruction_budget {
                    return Err(InterpreterError::BudgetExhausted {
                        executed: self.instructions_executed,
                        budget: self.config.instruction_budget,
                    });
                }
                self.instructions_executed += 1;
                // IteratorStep/IteratorValue errors mark the protocol done.
                // Only later element-processing errors require IteratorClose.
                close_on_error = false;
                let next =
                    self.advance_for_of_iterator(module, iterator.clone(), &mut accumulated_label);
                let Some(value) = next? else {
                    break;
                };
                close_on_error = true;
                let index = total;
                total = total
                    .checked_add(1)
                    .ok_or_else(|| InterpreterError::RangeError {
                        message: "Promise combinator input exceeds supported array length"
                            .to_string(),
                    })?;
                let input_label = accumulated_label.clone();
                // Resolve/register this element before reading the next one:
                // its then getter may mutate the iterable synchronously.
                let input = self.normalize_promise_combinator_input(value, input_label.clone())?;
                let source_label = self
                    .promise_store
                    .get(input)
                    .map_err(|error| InterpreterError::TypeError {
                        expected: "valid Promise combinator input".to_string(),
                        got: error.to_string(),
                    })?
                    .label
                    .clone();
                accumulated_label = accumulated_label.join(&source_label);
                self.join_promise_combinator_label(combinator_id, &accumulated_label)?;
                self.register_executable_promise_reactions(
                    input,
                    PromiseReactionRegistration {
                        on_fulfilled: Some(PromiseReactionAction::Combinator {
                            combinator_id,
                            index,
                        }),
                        on_rejected: Some(PromiseReactionAction::Combinator {
                            combinator_id,
                            index,
                        }),
                    },
                    input_label,
                )?;
            }
            self.join_promise_combinator_label(combinator_id, &accumulated_label)?;
            Ok(total)
        })();
        let outcome = match outcome {
            Err(error) if Self::is_js_catchable_error(&error) => {
                let thrown = self.pending_exception.take();
                let close = if close_on_error {
                    match active_iterator {
                        Some(iterator) => {
                            self.close_iterator(module, iterator, IteratorCloseReason::Throw)
                        }
                        None => Ok(()),
                    }
                } else {
                    Ok(())
                };
                self.remove_promise_combinator(combinator_id);
                close.and_then(|()| {
                    let (reason, label) = match thrown {
                        Some(thrown) => (thrown.value, accumulated_label.join(&thrown.label)),
                        None => (self.promise_error_value(&error)?, accumulated_label.clone()),
                    };
                    accumulated_label = label;
                    self.reject_promise(
                        result_promise,
                        Self::value_to_js_value(&reason),
                        accumulated_label.clone(),
                    )?;
                    Ok(None)
                })
            }
            Err(error) => {
                self.remove_promise_combinator(combinator_id);
                Err(error)
            }
            Ok(total) => Ok(Some(total)),
        };
        self.pending_exception = saved_exception;
        self.pending_return = saved_return;
        if let Some(total) = outcome? {
            if total == 0 {
                self.remove_promise_combinator(combinator_id);
                match kind {
                    PromiseCombinatorKind::All | PromiseCombinatorKind::AllSettled => {
                        let empty = self.build_promise_all_result(Vec::new())?;
                        self.fulfill_promise(result_promise, empty, accumulated_label.clone())?;
                    }
                    PromiseCombinatorKind::Any => {
                        let aggregate = self.build_aggregate_error(Vec::new())?;
                        self.reject_promise(result_promise, aggregate, accumulated_label.clone())?;
                    }
                    PromiseCombinatorKind::Race => {}
                }
            } else if let Some(state) = self.promise_combinators.get_mut(&combinator_id) {
                // Reactions are jobs; the final input count is published
                // before any queued element reaction can read the tracker.
                match &mut state.tracker {
                    PromiseCombinatorState::All(tracker) => tracker.total = total,
                    PromiseCombinatorState::AllSettled(tracker) => tracker.total = total,
                    PromiseCombinatorState::Any(tracker) => tracker.total = total,
                    PromiseCombinatorState::Race(_) => {}
                }
            }
        }
        Ok((Value::Promise(result_promise.0), accumulated_label))
    }

    fn register_promise_method(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        method: &str,
        first: Value,
        second: Value,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        let first = Self::is_sync_callable(&first).then_some(first);
        let registration = match method {
            "promise:then" => PromiseReactionRegistration {
                on_fulfilled: first.map(PromiseReactionAction::Call),
                on_rejected: Self::is_sync_callable(&second)
                    .then_some(PromiseReactionAction::Call(second)),
            },
            "promise:catch" => PromiseReactionRegistration {
                on_fulfilled: None,
                on_rejected: first.map(PromiseReactionAction::Call),
            },
            _ => PromiseReactionRegistration {
                on_fulfilled: first.clone().map(PromiseReactionAction::Finally),
                on_rejected: first.map(PromiseReactionAction::Finally),
            },
        };
        let result =
            self.register_executable_promise_reactions(handle, registration, label.clone())?;
        Ok((Value::Promise(result.0), label))
    }

    /// Dispatch a `promise:*` hostcall to the internal promise subsystem.
    ///
    /// Supported capabilities:
    /// - `promise:constructor` — create a pending promise, return its handle.
    /// - `promise:resolve` — return arg0 unchanged if it is a promise;
    ///   otherwise resolve a new promise with arg0. Extra arguments are ignored.
    /// - `promise:reject` — reject a new promise with arg0 as its reason,
    ///   including when arg0 is a promise. Extra arguments are ignored.
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
        module: &Ir3Module,
        cap: &str,
        args: RegRange,
    ) -> Result<(Value, crate::ifc_artifacts::Label), InterpreterError> {
        match cap {
            "promise:constructor" => {
                // Create a new pending promise and return its handle.
                let handle = self.create_promise_accounted()?;
                Ok((
                    Value::Promise(handle.0),
                    crate::ifc_artifacts::Label::Public,
                ))
            }
            "promise:resolve" => {
                let (arg0, arg0_label) = self.promise_hostcall_argument(args, 0)?;
                match arg0 {
                    // PromiseResolve(%Promise%, x) preserves promise identity
                    // and never grants settlement authority to its caller.
                    Value::Promise(h) => Ok((Value::Promise(h), arg0_label)),
                    _ => {
                        // Promise.resolve(value): a pending promise resolved
                        // with `value`, applying thenable assimilation
                        // (ES 25.6.4.5.1). A thenable adopts its eventual state
                        // through a PromiseResolveThenableJob rather than
                        // fulfilling with the object itself (bd-3ose7); a
                        // non-thenable fulfills synchronously, unchanged.
                        let handle = self.create_promise_accounted()?;
                        self.resolve_promise_with_value(handle, arg0, arg0_label.clone())?;
                        Ok((Value::Promise(handle.0), arg0_label))
                    }
                }
            }
            "promise:reject" => {
                let (arg0, arg0_label) = self.promise_hostcall_argument(args, 0)?;
                // Unlike resolution, rejection does not assimilate its reason.
                // A promise argument is retained as the reason of a distinct
                // rejected promise, never treated as a settlement target.
                let js_reason = Self::value_to_js_value(&arg0);
                let handle = self.create_promise_accounted()?;
                self.reject_promise(handle, js_reason, arg0_label.clone())?;
                Ok((Value::Promise(handle.0), arg0_label))
            }
            "promise:then" | "promise:catch" | "promise:finally" => {
                // Non-callable arguments select the spec's identity/thrower
                // reactions. Callable values are retained until their job runs.
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
                let (first, _) = self.promise_hostcall_argument(args, 1)?;
                let (second, _) = self.promise_hostcall_argument(args, 2)?;
                self.register_promise_method(handle, cap, first, second, registration_label)
            }
            "promise:all" => {
                self.dispatch_promise_combinator(module, PromiseCombinatorKind::All, args)
            }
            "promise:race" => {
                self.dispatch_promise_combinator(module, PromiseCombinatorKind::Race, args)
            }
            "promise:allSettled" => {
                self.dispatch_promise_combinator(module, PromiseCombinatorKind::AllSettled, args)
            }
            "promise:any" => {
                self.dispatch_promise_combinator(module, PromiseCombinatorKind::Any, args)
            }
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
        self.run_event_loop_with_turn_limit(module, 10_000)
    }

    fn run_event_loop_with_turn_limit(
        &mut self,
        module: &Ir3Module,
        max_turns: u32,
    ) -> Result<(), InterpreterError> {
        let mut turns = 0;

        while self.event_loop.has_pending_work() {
            if turns == max_turns {
                return Err(InterpreterError::EventLoopTurnLimitExceeded { turns, max_turns });
            }
            turns += 1;

            // Phase 1: Execute one macrotask (if ready). The dequeued task's
            // bytes leave the queue but remain physically live on this stack
            // until the handler returns; keep them charged through the
            // in-flight transfer so nested Promise work observes one coherent
            // runtime component (bd-ur3tk.21).
            let previous_turn_bytes = self.promise_runtime_memory_bytes();
            let turn_result = self.event_loop.turn();
            let released_bytes = turn_result.macrotask.as_ref().map_or(0, |task| {
                (std::mem::size_of::<crate::promise_model::Macrotask>() as u64)
                    .saturating_add(Self::estimate_label_bytes(&task.label))
            });
            self.promise_in_flight_task_bytes = self
                .promise_in_flight_task_bytes
                .saturating_add(released_bytes);
            if let Err(error) = self.apply_promise_runtime_memory_delta(previous_turn_bytes) {
                self.promise_in_flight_task_bytes = self
                    .promise_in_flight_task_bytes
                    .saturating_sub(released_bytes);
                // The selected queue entry has already been consumed. A
                // fatal admission refusal must release its captured callable
                // and arguments rather than leave an unscheduled timer alive.
                if let Some(task) = &turn_result.macrotask
                    && task.source == crate::promise_model::MacrotaskSource::Timer
                {
                    let timer_id = self
                        .active_timers
                        .iter()
                        .find(|(_, timer)| {
                            timer.registration_seq == Some(task.registration_seq)
                                && timer.handler == Some(task.handler.0)
                        })
                        .map(|(timer_id, _)| *timer_id);
                    if let Some(timer_id) = timer_id {
                        self.active_timers.remove(&timer_id);
                        self.timer_invocations.remove(&task.registration_seq);
                    }
                }
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                return Err(error);
            }
            let callback_result = if let Some(macrotask) = turn_result.macrotask {
                self.execute_macrotask_callback(module, &macrotask)
            } else {
                Ok(())
            };
            self.promise_in_flight_task_bytes = self
                .promise_in_flight_task_bytes
                .saturating_sub(released_bytes);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(released_bytes);
            callback_result?;

            // Phase 2: Drain all microtasks enqueued during macrotask execution
            self.drain_microtasks(Some(module))?;
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

        let Some(timer_id) = self
            .active_timers
            .iter()
            .find(|(_, timer)| {
                timer.registration_seq == Some(macrotask.registration_seq)
                    && timer.handler == Some(macrotask.handler.0)
            })
            .map(|(timer_id, _)| *timer_id)
        else {
            return Ok(());
        };

        let timer = self.active_timers[&timer_id].clone();
        let previous_bytes = self.promise_runtime_memory_bytes();
        if !timer.repeating {
            self.active_timers.remove(&timer_id);
        }
        let invocation = self.timer_invocations.remove(&macrotask.registration_seq);
        // The removed callable/argument vector remains live throughout the
        // callback. Transfer its charge rather than rebating the budget while
        // guest code can allocate or schedule further work.
        let retained_bytes = previous_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_add(retained_bytes);
        let outcome = match &invocation {
            Some(invocation) => {
                // A repeating callback retains its callable for the next
                // firing. Account for an owned builtin module path copied
                // into the isolated activation before allocating that copy.
                let callable_bytes = Self::estimate_timer_value_bytes(&invocation.callee);
                match self.check_temporary_memory_budget(callable_bytes) {
                    Err(error) => Err(error),
                    Ok(()) => {
                        self.promise_in_flight_task_bytes = self
                            .promise_in_flight_task_bytes
                            .saturating_add(callable_bytes);
                        self.estimated_memory_bytes =
                            self.estimated_memory_bytes.saturating_add(callable_bytes);
                        let outcome = self
                            .invoke_inline_method_call_labeled(
                                module,
                                invocation.callee.clone(),
                                Value::Undefined,
                                &invocation.arguments,
                            )
                            .and_then(|(mut completion, _)| {
                                if let InlineCallCompletion::Throw(thrown) = &mut completion {
                                    thrown.label = thrown.label.join(&macrotask.label);
                                }
                                self.complete_inline_call(completion).map(|_| ())
                            });
                        self.promise_in_flight_task_bytes = self
                            .promise_in_flight_task_bytes
                            .saturating_sub(callable_bytes);
                        self.estimated_memory_bytes =
                            self.estimated_memory_bytes.saturating_sub(callable_bytes);
                        outcome
                    }
                }
            }
            None => Ok(()),
        };

        // Keep the public ID live during the callback so either cancellation
        // API can suppress rescheduling, including cancellation by a callback
        // that has already enqueued Promise reactions. Each firing receives a
        // new queue sequence, preserving order against other same-time timers.
        let still_active = self
            .active_timers
            .get(&timer_id)
            .is_some_and(|active| active.registration_seq == Some(macrotask.registration_seq));
        if outcome.is_ok()
            && timer.repeating
            && still_active
            && let Some(invocation) = invocation
        {
            let previous_bytes = self.promise_runtime_memory_bytes();
            let sequence = self.event_loop.set_timeout(
                macrotask.handler,
                timer.delay_ms,
                macrotask.label.clone(),
            );
            self.timer_invocations.insert(sequence, invocation);
            self.active_timers
                .get_mut(&timer_id)
                .unwrap()
                .registration_seq = Some(sequence);
            self.promise_in_flight_task_bytes = self
                .promise_in_flight_task_bytes
                .saturating_sub(retained_bytes);
            if let Err(error) = self.apply_promise_runtime_memory_delta(previous_bytes) {
                self.event_loop.macrotasks.rollback_last_scheduled(sequence);
                self.timer_invocations.remove(&sequence);
                self.active_timers.remove(&timer_id);
                self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
                return Err(error);
            }
            return Ok(());
        }

        if still_active {
            self.active_timers.remove(&timer_id);
        }
        self.promise_in_flight_task_bytes = self
            .promise_in_flight_task_bytes
            .saturating_sub(retained_bytes);
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        outcome
    }

    #[cfg(test)]
    fn execute_timer_closure(
        &mut self,
        module: &Ir3Module,
        closure_id: u32,
    ) -> Result<(), InterpreterError> {
        // The same isolated call boundary serves accessors, Promise jobs, and
        // timers. In particular a foreign callback must return to its own
        // trampoline, never to an instruction offset in the importing module.
        let completion = self.invoke_inline_method_call(
            module,
            Value::Closure(closure_id),
            Value::Undefined,
            &[],
        )?;
        self.complete_inline_call(completion).map(|_| ())
    }

    /// Drain all pending microtasks from the queue.
    ///
    /// Each microtask may enqueue additional microtasks; the drain continues
    /// until the queue is empty, matching ES2020 semantics (microtask checkpoint).
    /// A safety bound prevents infinite loops from pathological promise chains.
    fn drain_microtasks(&mut self, module: Option<&Ir3Module>) -> Result<(), InterpreterError> {
        self.drain_microtasks_with_limit(module, 10_000)
    }

    fn drain_microtasks_with_limit(
        &mut self,
        module: Option<&Ir3Module>,
        max_drain: u32,
    ) -> Result<(), InterpreterError> {
        let mut drained = 0u32;

        while drained < max_drain {
            // Dequeue clones a job while its original remains in the replay
            // buffer. Admit that clone before allocating it, and keep its
            // owned payload charged until the job completes or fails.
            let Some(cloned_bytes) = self.event_loop.microtasks.peek_next().map(|task| {
                (std::mem::size_of::<crate::promise_model::Microtask>() as u64).saturating_add(
                    crate::promise_model::estimate_microtask_payload_memory_bytes(task),
                )
            }) else {
                break;
            };
            self.check_temporary_memory_budget(cloned_bytes)?;
            let previous_queue_bytes = self.promise_runtime_memory_bytes();
            let task = self
                .event_loop
                .microtasks
                .dequeue()
                .expect("pending job checked");
            self.promise_in_flight_task_bytes = self
                .promise_in_flight_task_bytes
                .saturating_add(cloned_bytes);
            if let Err(error) = self.apply_promise_runtime_memory_delta(previous_queue_bytes) {
                self.promise_in_flight_task_bytes = self
                    .promise_in_flight_task_bytes
                    .saturating_sub(cloned_bytes);
                self.event_loop.microtasks.rollback_last_dequeued();
                return Err(error);
            }
            drained += 1;
            let outcome = (|| -> Result<(), InterpreterError> {
                match task {
                    crate::promise_model::Microtask::PromiseReaction {
                        handler,
                        argument,
                        result_promise,
                        label: task_label,
                    } => {
                        if self.promise_reactions.contains_key(&result_promise) {
                            self.run_executable_promise_reaction(
                                module,
                                result_promise,
                                handler == Some(crate::closure_model::ClosureHandle(1)),
                                argument,
                                task_label,
                            )?;
                        } else if handler.is_none()
                            && let Some(resumption_context) =
                                self.take_async_resumption_context(result_promise.0)
                        {
                            self.resume_async_function_after_await(
                                resumption_context,
                                Ok(argument),
                                task_label.clone(),
                                module,
                            )?;
                            // The await handler returns undefined. Its internal
                            // continuation is separate from the async result Promise.
                            self.fulfill_promise(
                                result_promise,
                                crate::object_model::JsValue::Undefined,
                                task_label,
                            )?;
                        } else if handler.is_none()
                            && let Some(context) =
                                self.take_async_generator_continuation(result_promise.0)
                        {
                            self.resume_async_generator_task(
                                context,
                                Ok(argument),
                                task_label.clone(),
                            )?;
                            self.fulfill_promise(
                                result_promise,
                                crate::object_model::JsValue::Undefined,
                                task_label,
                            )?;
                        } else {
                            // The identity handler still invokes the derived
                            // Promise's resolve function, including assimilation.
                            self.resolve_promise_with_value(
                                result_promise,
                                Self::js_value_to_value(&argument),
                                task_label,
                            )?;
                        }
                    }
                    crate::promise_model::Microtask::PromiseRejection {
                        reason,
                        result_promise,
                        label: task_label,
                    } => {
                        if self.promise_reactions.contains_key(&result_promise) {
                            self.run_executable_promise_reaction(
                                module,
                                result_promise,
                                true,
                                reason,
                                task_label,
                            )?;
                        } else if let Some(resumption_context) =
                            self.take_async_resumption_context(result_promise.0)
                        {
                            self.resume_async_function_after_await(
                                resumption_context,
                                Err(reason),
                                task_label.clone(),
                                module,
                            )?;
                            // The await handler returns undefined. Its internal
                            // continuation is separate from the async result Promise.
                            self.fulfill_promise(
                                result_promise,
                                crate::object_model::JsValue::Undefined,
                                task_label,
                            )?;
                        } else if let Some(context) =
                            self.take_async_generator_continuation(result_promise.0)
                        {
                            self.resume_async_generator_task(
                                context,
                                Err(reason),
                                task_label.clone(),
                            )?;
                            self.fulfill_promise(
                                result_promise,
                                crate::object_model::JsValue::Undefined,
                                task_label,
                            )?;
                        } else {
                            self.reject_promise(result_promise, reason, task_label)?;
                        }
                    }
                    crate::promise_model::Microtask::ResolveThenableValue {
                        promise,
                        then,
                        thenable,
                        label: task_label,
                    } => {
                        let module = module.ok_or_else(|| InterpreterError::TypeError {
                            expected: "module context for captured thenable job".to_string(),
                            got: "missing module context".to_string(),
                        })?;
                        let (pair_id, resolve_fn, reject_fn) =
                            self.create_promise_resolving_functions(promise, task_label.clone())?;
                        let outcome = self.invoke_inline_method_call_labeled(
                            module,
                            Self::js_value_to_value(&then),
                            Self::js_value_to_value(&thenable),
                            &[
                                (resolve_fn, task_label.clone()),
                                (reject_fn, task_label.clone()),
                            ],
                        );
                        self.complete_promise_resolving_call(pair_id, outcome, task_label)?;
                    }
                    crate::promise_model::Microtask::ResolveThenable {
                        promise,
                        then_handler: _,
                        thenable,
                        label: task_label,
                    } => {
                        // PromiseResolveThenableJob (ES2020 25.6.1.3.1, bd-3ose7):
                        // call `thenable.then(resolve, reject)` with resolve/reject
                        // capabilities bound to `promise`. The user `then` runs
                        // synchronously within this job, so the microtasks it
                        // schedules and the settle it performs are enqueued in
                        // program order (preserving nested-microtask ordering). The
                        // task label is preserved — a throw from `then` rejects the
                        // promise with the thrown value's label, not `Public`.
                        let Some(module) = module else {
                            return Err(InterpreterError::TypeError {
                                expected: "module context for ResolveThenable job".to_string(),
                                got: "missing module context".to_string(),
                            });
                        };
                        let thenable_value = Self::js_value_to_value(&thenable);
                        if let Value::Promise(source) = thenable_value {
                            self.register_executable_promise_reactions(
                                crate::promise_model::PromiseHandle(source),
                                PromiseReactionRegistration {
                                    on_fulfilled: Some(PromiseReactionAction::Forward(promise)),
                                    on_rejected: Some(PromiseReactionAction::Forward(promise)),
                                },
                                task_label,
                            )?;
                            return Ok(());
                        }
                        // Re-read `then` from the thenable (same callable for a
                        // data property); it may be a `Value::Function` or
                        // `Value::Closure`, both of which CallMethod invokes.
                        let then_fn = match thenable_value {
                            Value::Object(object_id) => {
                                self.prototype_chain_get(object_id, "then")?
                            }
                            _ => Value::Undefined,
                        };
                        if !Self::is_sync_callable(&then_fn) {
                            // The thenable's `then` was removed/replaced with a
                            // non-callable after the job was queued: fulfill with
                            // the thenable itself, matching a non-thenable value.
                            if !self.promise_is_settled(promise) {
                                self.fulfill_promise(
                                    promise,
                                    thenable.clone(),
                                    task_label.clone(),
                                )?;
                            }
                            return Ok(());
                        }
                        let (pair_id, resolve_fn, reject_fn) =
                            self.create_promise_resolving_functions(promise, task_label.clone())?;
                        let outcome = self.invoke_inline_method_call_labeled(
                            module,
                            then_fn,
                            thenable_value,
                            &[
                                (resolve_fn, task_label.clone()),
                                (reject_fn, task_label.clone()),
                            ],
                        );
                        self.complete_promise_resolving_call(pair_id, outcome, task_label)?;
                    }
                }
                Ok(())
            })();
            self.promise_in_flight_task_bytes = self
                .promise_in_flight_task_bytes
                .saturating_sub(cloned_bytes);
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(cloned_bytes);
            outcome?;
        }
        // Compaction releases the consumed task slots and payloads retained
        // by the cursor-based buffer (bd-ur3tk.21). A release cannot exceed
        // the ceiling, so the delta application is infallible here.
        let previous_queue_bytes = self.promise_runtime_memory_bytes();
        self.event_loop.microtasks.compact();
        self.apply_promise_runtime_memory_delta(previous_queue_bytes)?;
        if !self.event_loop.microtasks.is_empty() {
            return Err(InterpreterError::MicrotaskLimitExceeded { drained, max_drain });
        }
        Ok(())
    }

    fn executable_property_key(value: &Value) -> RuntimePropertyKey {
        match value {
            Value::Symbol(symbol) => RuntimePropertyKey::Symbol(*symbol),
            Value::Str(text) => RuntimePropertyKey::String(text.clone()),
            Value::Int(number) => RuntimePropertyKey::String(JsString::from(number.to_string())),
            _ => RuntimePropertyKey::String(JsString::from(value.to_string())),
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
            | Value::Symbol(_)
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
            Value::Symbol(_) => None,
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

    fn reject_symbol_numeric_coercion(
        value: &Value,
        expected: &str,
    ) -> Result<(), InterpreterError> {
        if matches!(value, Value::Symbol(_)) {
            return Err(InterpreterError::TypeError {
                expected: expected.to_string(),
                got: "symbol".to_string(),
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
            | (Value::Symbol(_), Value::Symbol(_))
            | (Value::Object(_), Value::Object(_))
            | (Value::Function(_), Value::Function(_))
            | (Value::Closure(_), Value::Closure(_))
            | (Value::AsyncFunction(_), Value::AsyncFunction(_))
            | (Value::AsyncGeneratorFunction(_), Value::AsyncGeneratorFunction(_))
            | (Value::AsyncGeneratorObject(_), Value::AsyncGeneratorObject(_))
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
            (Value::Symbol(_), _) | (_, Value::Symbol(_)) => false,
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
                Self::reject_symbol_numeric_coercion(&arg0, "number-coercible primitive")?;
                let number = Self::coerce_to_float(&arg0).unwrap_or(f64::NAN);
                Ok(Value::Bool(number.is_nan()))
            }
            "number:isFinite" => {
                // Global isFinite: coerces argument to number, then checks finite
                // isFinite(undefined) = false, isFinite("123") = true
                Self::reject_symbol_numeric_coercion(&arg0, "number-coercible primitive")?;
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
            "timer:setTimeout" | "timer:setInterval" => {
                // args[0] = callable, args[1] = delay_ms, args[2..] are
                // captured now and forwarded when this registration fires.
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
                    Value::Symbol(_) => {
                        return Err(InterpreterError::TypeError {
                            expected: "timer delay coercible to number".to_string(),
                            got: "symbol".to_string(),
                        });
                    }
                    _ => 0,
                };
                // Repeating zero-delay timers must advance virtual time;
                // otherwise they can starve every later deadline forever.
                let delay_ms = if cap == "timer:setInterval" {
                    delay_ms.max(1)
                } else {
                    delay_ms
                };

                let timer_id = self.next_timer_id;
                let mut registration_label = crate::ifc_artifacts::Label::Public;
                let invocation = if Self::is_sync_callable(&handler_val) {
                    registration_label = self.promise_hostcall_registration_label(args)?;
                    let mut invocation = TimerInvocation {
                        callee: handler_val,
                        arguments: Vec::new(),
                    };
                    let mut retained_bytes = Self::estimate_timer_invocation_bytes(&invocation)
                        .saturating_add(Self::active_timer_entry_bytes());
                    for index in 2..args.count {
                        let (value, label) = self.promise_hostcall_argument(args, index)?;
                        let label = label.join(&registration_label);
                        retained_bytes = retained_bytes
                            .saturating_add(Self::estimate_timer_argument_bytes(&value, &label));
                        self.check_temporary_memory_budget(retained_bytes)?;
                        invocation.arguments.push((value, label));
                    }
                    if invocation.arguments.is_empty()
                        && matches!(
                            &invocation.callee,
                            Value::BuiltinFunction(BuiltinFunction {
                                kind: BuiltinFunctionKind::PromiseResolveFunction
                                    | BuiltinFunctionKind::PromiseRejectFunction
                                    | BuiltinFunctionKind::PromiseCapabilityResolve
                                    | BuiltinFunctionKind::PromiseCapabilityReject,
                                ..
                            })
                        )
                    {
                        // Native resolving functions observe only their first
                        // value, so an explicit undefined preserves behavior
                        // while retaining scheduling provenance. Guest rest
                        // parameters still receive the original zero arguments.
                        self.check_temporary_memory_budget(retained_bytes.saturating_add(
                            Self::estimate_timer_argument_bytes(
                                &Value::Undefined,
                                &registration_label,
                            ),
                        ))?;
                        invocation
                            .arguments
                            .push((Value::Undefined, registration_label.clone()));
                    }
                    Some(invocation)
                } else {
                    None
                };
                self.check_temporary_memory_budget(
                    Self::active_timer_entry_bytes().saturating_add(
                        invocation
                            .as_ref()
                            .map(Self::estimate_timer_invocation_bytes)
                            .unwrap_or(0),
                    ),
                )?;

                // ClosureHandle remains the queue's opaque token. The private
                // invocation selected by registration_seq carries the actual
                // callable, including native Promise resolving functions.
                let handler_id = invocation
                    .as_ref()
                    .map(|invocation| match &invocation.callee {
                        Value::Closure(id) => *id,
                        _ => timer_id,
                    });

                // Transactional macrotask schedule (bd-ur3tk.21): the heap
                // slot and retained callback are charged eagerly. A refusal
                // removes every registration component without consuming IDs.
                let previous_promise_runtime_bytes = self.promise_runtime_memory_bytes();
                let registration_seq = handler_id.map(|handler| {
                    self.event_loop.set_timeout(
                        crate::closure_model::ClosureHandle(handler),
                        delay_ms,
                        registration_label,
                    )
                });
                if let (Some(sequence), Some(invocation)) = (registration_seq, invocation) {
                    self.timer_invocations.insert(sequence, invocation);
                }
                self.active_timers.insert(
                    timer_id,
                    ActiveTimer {
                        handler: handler_id,
                        delay_ms,
                        repeating: cap == "timer:setInterval",
                        registration_seq,
                    },
                );
                if let Err(error) =
                    self.apply_promise_runtime_memory_delta(previous_promise_runtime_bytes)
                {
                    if let Some(timer) = self.active_timers.remove(&timer_id)
                        && let Some(seq) = timer.registration_seq
                    {
                        self.event_loop.macrotasks.rollback_last_scheduled(seq);
                        self.timer_invocations.remove(&seq);
                    }
                    return Err(error);
                }
                self.next_timer_id = self.next_timer_id.wrapping_add(1);

                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("{}:{}", cap, timer_id)),
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

                let previous_bytes = self.promise_runtime_memory_bytes();
                if let Some(timer) = self.active_timers.remove(&timer_id)
                    && let Some(sequence) = timer.registration_seq
                {
                    self.timer_invocations.remove(&sequence);
                }
                self.apply_promise_runtime_memory_delta(previous_bytes)?;

                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("{}:{}", cap, timer_id)),
                );

                Ok(Value::Undefined)
            }
            _ => Ok(Value::Undefined), // Unknown timer method
        }
    }

    /// Quote one exact JavaScript string as a JSON token. Unpaired UTF-16
    /// surrogates remain distinguishable as `\uXXXX` escapes.
    fn json_quote_js_string(text: &JsString) -> String {
        let mut out = String::with_capacity(text.len().saturating_add(2));
        out.push('"');
        for decoded in char::decode_utf16(text.encode_utf16()) {
            match decoded {
                Ok('"') => out.push_str("\\\""),
                Ok('\\') => out.push_str("\\\\"),
                Ok('\u{0008}') => out.push_str("\\b"),
                Ok('\u{000c}') => out.push_str("\\f"),
                Ok('\n') => out.push_str("\\n"),
                Ok('\r') => out.push_str("\\r"),
                Ok('\t') => out.push_str("\\t"),
                Ok(ch) if ch <= '\u{001f}' => out.push_str(&format!("\\u{:04x}", ch as u32)),
                Ok(ch) => out.push(ch),
                Err(err) => out.push_str(&format!("\\u{:04x}", err.unpaired_surrogate())),
            }
        }
        out.push('"');
        out
    }

    /// Recursively serialize the baseline JSON value surface. `None` means
    /// the value is omitted (or becomes `null` in an array). Object member
    /// names are traversed as exact UTF-16 keys, never through the UTF-8
    /// compatibility projection.
    fn json_stringify_value(&self, value: &Value, visited: &mut Vec<ObjectId>) -> Option<String> {
        let rendered = match value {
            Value::Undefined | Value::Symbol(_) => return None,
            Value::Null => "null".to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Int(value) => value.to_string(),
            Value::Float(value) => {
                if value.inner().is_finite() {
                    value.to_string()
                } else {
                    "null".to_string()
                }
            }
            Value::Str(text) => Self::json_quote_js_string(text),
            Value::Object(object_id) => {
                if visited.contains(object_id) {
                    return None;
                }
                let object = self.heap.get(object_id.0 as usize).cloned()?;
                visited.push(*object_id);
                let rendered = if object.is_array {
                    let length = object
                        .properties
                        .get("length")
                        .and_then(|value| match value {
                            Value::Int(length) if *length >= 0 => Some(*length as usize),
                            _ => None,
                        })
                        .unwrap_or(0);
                    let items = (0..length)
                        .map(|index| {
                            object
                                .properties
                                .get(&index.to_string())
                                .and_then(|value| self.json_stringify_value(value, visited))
                                .unwrap_or_else(|| "null".to_string())
                        })
                        .collect::<Vec<_>>();
                    format!("[{}]", items.join(","))
                } else {
                    let mut members = Vec::new();
                    for key in object.own_exact_property_keys() {
                        if !object
                            .own_property_attributes(&RuntimePropertyKey::String(key.clone()))
                            .enumerable
                        {
                            continue;
                        }
                        if key.as_str().is_some_and(|key| key.starts_with("__")) {
                            continue;
                        }
                        let Some(value) = object.properties.get_exact(&key) else {
                            continue;
                        };
                        if let Some(value) = self.json_stringify_value(value, visited) {
                            members.push(format!("{}:{value}", Self::json_quote_js_string(&key)));
                        }
                    }
                    format!("{{{}}}", members.join(","))
                };
                visited.pop();
                rendered
            }
            Value::Function(_)
            | Value::Closure(_)
            | Value::GeneratorFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::BuiltinFunction(_) => return None,
            Value::Iterator(_)
            | Value::Generator(_)
            | Value::AsyncFunctionObject(_)
            | Value::AsyncGeneratorObject(_)
            | Value::Promise(_) => "{}".to_string(),
        };
        Some(rendered)
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
                    let register = args.start.checked_add(offset).ok_or(
                        InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: self.config.max_registers,
                        },
                    )?;
                    let value_label = self.read_reg_label(register)?;
                    let element_key = RuntimePropertyKey::String(JsString::from(index.to_string()));
                    let previous_label =
                        self.own_stored_runtime_property_label(array_id, &element_key);
                    self.set_own_runtime_property_label(array_id, &element_key, &value_label)?;
                    if let Err(error) = self.set_object_property(array_id, index.to_string(), value)
                    {
                        self.set_own_runtime_property_label(
                            array_id,
                            &element_key,
                            &previous_label,
                        )?;
                        return Err(error);
                    }
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
            "builtin:SymbolFunction" => Ok(Value::BuiltinFunction(BuiltinFunction::symbol(
                BuiltinFunctionKind::Symbol,
            ))),
            "builtin:SymbolFor" => {
                let value = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                let key = self.symbol_registry_key_argument(value)?;
                self.intern_global_symbol(key).map(Value::Symbol)
            }
            "builtin:SymbolKeyFor" => {
                let value = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                let Value::Symbol(symbol) = value else {
                    return Err(InterpreterError::TypeError {
                        expected: "Symbol".to_string(),
                        got: value.type_name().to_string(),
                    });
                };
                Ok(self
                    .symbol_state
                    .key_for(symbol)
                    .cloned()
                    .map(Value::Str)
                    .unwrap_or(Value::Undefined))
            }
            "builtin:SymbolIterator" => Ok(Value::Symbol(WellKnownSymbol::Iterator.id())),
            "builtin:SymbolToPrimitive" => Ok(Value::Symbol(WellKnownSymbol::ToPrimitive.id())),
            "builtin:SymbolHasInstance" => Ok(Value::Symbol(WellKnownSymbol::HasInstance.id())),
            "builtin:SymbolToStringTag" => Ok(Value::Symbol(WellKnownSymbol::ToStringTag.id())),
            "builtin:SymbolSpecies" => Ok(Value::Symbol(WellKnownSymbol::Species.id())),
            "builtin:SymbolIsConcatSpreadable" => {
                Ok(Value::Symbol(WellKnownSymbol::IsConcatSpreadable.id()))
            }
            "builtin:SymbolUnscopables" => Ok(Value::Symbol(WellKnownSymbol::Unscopables.id())),
            "builtin:SymbolAsyncIterator" => Ok(Value::Symbol(WellKnownSymbol::AsyncIterator.id())),
            "builtin:SymbolMatch" => Ok(Value::Symbol(WellKnownSymbol::Match.id())),
            "builtin:SymbolMatchAll" => Ok(Value::Symbol(WellKnownSymbol::MatchAll.id())),
            "builtin:SymbolReplace" => Ok(Value::Symbol(WellKnownSymbol::Replace.id())),
            "builtin:SymbolSearch" => Ok(Value::Symbol(WellKnownSymbol::Search.id())),
            "builtin:SymbolSplit" => Ok(Value::Symbol(WellKnownSymbol::Split.id())),
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
                let values = match self.object_like_storage_id(&this, "object")? {
                    Some(object_id) => self
                        .own_enumerable_keys(object_id)?
                        .into_iter()
                        .map(Value::Str)
                        .collect::<Vec<_>>(),
                    None => Vec::new(),
                };
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            "builtin:ObjectValues" => {
                let this = self.required_arg(args, 0, "object")?;
                let values = match self.object_like_storage_id(&this, "object")? {
                    Some(object_id) => {
                        let keys = self.own_enumerable_keys(object_id)?;
                        let object = self
                            .heap
                            .get(object_id.0 as usize)
                            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                        keys.into_iter()
                            .filter_map(|key| object.properties.get_exact(&key).cloned())
                            .collect::<Vec<_>>()
                    }
                    None => Vec::new(),
                };
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            "builtin:ObjectEntries" => {
                let this = self.required_arg(args, 0, "object")?;
                let entries = match self.object_like_storage_id(&this, "object")? {
                    Some(object_id) => {
                        let keys = self.own_enumerable_keys(object_id)?;
                        let object = self
                            .heap
                            .get(object_id.0 as usize)
                            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                        keys.into_iter()
                            .filter_map(|key| {
                                object
                                    .properties
                                    .get_exact(&key)
                                    .cloned()
                                    .map(|value| (key, value))
                            })
                            .collect::<Vec<_>>()
                    }
                    None => Vec::new(),
                };
                let mut values = Vec::with_capacity(entries.len());
                for (key, value) in entries {
                    let entry = self.alloc_array_from_values(&[Value::Str(key), value])?;
                    values.push(Value::Object(entry));
                }
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            "builtin:ObjectGetOwnPropertyNames" => {
                let this = self.required_arg(args, 0, "object")?;
                if let Value::Closure(closure_id)
                | Value::AsyncFunction(closure_id)
                | Value::AsyncGeneratorFunction(closure_id) = &this
                    && self.closure_method_metadata.contains_key(closure_id)
                {
                    let mut values = vec![Value::str("name")];
                    if let Some(object_id) = self.function_object_id(&this) {
                        values.extend(
                            self.heap[object_id.0 as usize]
                                .own_exact_property_keys()
                                .into_iter()
                                .filter(|key| key.as_str() != Some("name"))
                                .map(Value::Str),
                        );
                    }
                    return Ok(Value::Object(self.alloc_array_from_values(&values)?));
                }
                let values = match self.object_like_storage_id(&this, "object")? {
                    Some(object_id) => {
                        let object = self
                            .heap
                            .get(object_id.0 as usize)
                            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                        object
                            .own_exact_property_keys()
                            .into_iter()
                            .map(Value::Str)
                            .collect::<Vec<_>>()
                    }
                    None => Vec::new(),
                };
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            "builtin:ObjectGetOwnPropertySymbols" => {
                let this = self.required_arg(args, 0, "object")?;
                let values = self
                    .object_like_storage_id(&this, "object")?
                    .map(|object_id| {
                        self.heap[object_id.0 as usize]
                            .properties
                            .baseline_symbol_key_order()
                            .iter()
                            .copied()
                            .map(Value::Symbol)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            "builtin:ReflectOwnKeys" => {
                let this = self.required_arg(args, 0, "object")?;
                let has_virtual_name = if let Value::Closure(closure_id)
                | Value::AsyncFunction(closure_id)
                | Value::AsyncGeneratorFunction(closure_id) = &this
                    && self.closure_method_metadata.contains_key(closure_id)
                {
                    true
                } else {
                    false
                };
                let mut values = if has_virtual_name {
                    vec![Value::str("name")]
                } else {
                    Vec::new()
                };
                values.extend(
                    self.object_like_storage_id(&this, "object")?
                        .map(|object_id| {
                            self.heap[object_id.0 as usize]
                                .own_runtime_property_keys()
                                .into_iter()
                                .filter(|key| {
                                    !matches!(
                                        key,
                                        RuntimePropertyKey::String(key)
                                            if key.as_str() == Some("name")
                                                && has_virtual_name
                                    )
                                })
                                .map(|key| match key {
                                    RuntimePropertyKey::String(key) => Value::Str(key),
                                    RuntimePropertyKey::Symbol(symbol) => Value::Symbol(symbol),
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                );
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            "builtin:ObjectAssign" => self.object_assign(args),

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
                Self::string_char_at_value(&text, index.as_ref())
            }
            "builtin:StringPrototypeCharCodeAt" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                let index = self.optional_arg(args, 1)?;
                Self::string_char_code_at_value(&text, index.as_ref())
            }
            "builtin:StringPrototypeCodePointAt" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                let index = self.optional_arg(args, 1)?;
                Self::string_code_point_at_value(&text, index.as_ref())
            }
            "builtin:StringPrototypeAt" => {
                let receiver = self.required_arg(args, 0, "string")?;
                let text = match &receiver {
                    Value::Str(text) => text.clone(),
                    other => JsString::from(self.value_to_string(other)),
                };
                let index = self.optional_arg(args, 1)?;
                Self::string_at_value(&text, index.as_ref())
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
                        Value::Symbol(_) => {
                            return Err(InterpreterError::TypeError {
                                expected: "String.fromCharCode argument coercible to number"
                                    .to_string(),
                                got: "symbol".to_string(),
                            });
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
                        Value::Symbol(_) => {
                            return Err(InterpreterError::TypeError {
                                expected: "String.fromCodePoint argument coercible to number"
                                    .to_string(),
                                got: "symbol".to_string(),
                            });
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
                        Value::Int(n) => Ok(js_number_to_value((n as f64).abs())),
                        Value::Float(f) => Ok(Value::Float(Float64::new(f.inner().abs()))),
                        Value::Symbol(_) => Err(InterpreterError::TypeError {
                            expected: "Math.abs argument coercible to number".to_string(),
                            got: "symbol".to_string(),
                        }),
                        _ => Ok(Value::Float(Float64::new(f64::NAN))),
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }

            // JSON methods
            "builtin:JsonStringify" => {
                if args.count == 0 {
                    return Ok(Value::str("undefined"));
                }
                let value = self.read_reg(args.start)?;
                let json_str = self
                    .json_stringify_value(&value, &mut Vec::new())
                    .unwrap_or_else(|| "undefined".to_string());
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
                Ok(Value::str(self.qs_stringify_object(object_id, &sep, &eq)?))
            }
            "builtin:QuerystringEscape" => {
                // Node coerces the argument with String() before escaping
                // (bun: qs.escape(42) is '42').
                let value = self.optional_arg(args, 0)?.unwrap_or(Value::Undefined);
                let coerced = match value {
                    Value::Str(s) => s,
                    other => JsString::from(self.value_to_string(&other)),
                };
                Ok(Value::str(node_qs_escape_js(&coerced)?))
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
    fn qs_stringify_primitive(&self, value: &Value) -> JsString {
        match value {
            Value::Str(s) => s.clone(),
            Value::Int(n) => JsString::from(n.to_string()),
            Value::Float(f) if f.inner().is_finite() => JsString::from(self.value_to_string(value)),
            Value::Bool(b) => JsString::from(if *b { "true" } else { "false" }),
            _ => JsString::from(""),
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
    fn qs_stringify_object(
        &self,
        object_id: ObjectId,
        sep: &str,
        eq: &str,
    ) -> Result<String, InterpreterError> {
        let entries: Vec<(JsString, Value)> = self
            .heap
            .get(object_id.0 as usize)
            .map(|object| {
                object
                    .own_exact_property_keys()
                    .into_iter()
                    .filter(|key| !(object.is_array && key.as_str() == Some("length")))
                    .filter_map(|key| {
                        object
                            .properties
                            .get_exact(&key)
                            .cloned()
                            .map(|value| (key, value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut pieces: Vec<String> = Vec::new();
        for (key, value) in entries {
            let key_prefix = format!("{}{eq}", node_qs_escape_js(&key)?);
            if let Value::Object(id) = value
                && self
                    .heap
                    .get(id.0 as usize)
                    .is_some_and(|object| object.is_array)
            {
                for element in self.read_array_like_values(id) {
                    pieces.push(format!(
                        "{key_prefix}{}",
                        node_qs_escape_js(&self.qs_stringify_primitive(&element))?
                    ));
                }
                continue;
            }
            pieces.push(format!(
                "{key_prefix}{}",
                node_qs_escape_js(&self.qs_stringify_primitive(&value))?
            ));
        }
        Ok(pieces.join(sep))
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

    /// Resolve the heap carrier shared by ordinary objects and function-like
    /// values. A function with no user-defined properties has no allocated
    /// sidecar yet, so callers observe an empty own-key set without forcing an
    /// allocation.
    fn object_like_storage_id(
        &self,
        value: &Value,
        expected: &str,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let object_id = match value {
            Value::Object(object_id) => Some(*object_id),
            function_like if Self::function_object_key(function_like).is_some() => {
                self.function_object_id(function_like)
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: expected.to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if let Some(object_id) = object_id {
            self.heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        }
        Ok(object_id)
    }

    /// bd-es2ra: resolve the ordinary-property backing object for an
    /// object-like iterator-protocol carrier. `Value::Object` is its own
    /// backing; function-like carriers resolve through their materialized
    /// function object when one exists. Every other object-like carrier (and
    /// a function that never materialized properties) has no ordinary
    /// property storage, so its protocol properties read as `undefined` —
    /// callers get `Ok(None)`. Primitives reject with the caller's TypeError
    /// expectation, matching the historical messages.
    fn iterator_carrier_backing_id(
        &self,
        value: &Value,
        expected: &str,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        if !value.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: expected.to_string(),
                got: value.type_name().to_string(),
            });
        }
        let object_id = match value {
            Value::Object(object_id) => Some(*object_id),
            function_like => self.function_object_id(function_like),
        };
        if let Some(object_id) = object_id {
            self.heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        }
        Ok(object_id)
    }

    fn own_enumerable_keys(&self, object_id: ObjectId) -> Result<Vec<JsString>, InterpreterError> {
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        Ok(object
            .own_exact_property_keys()
            .into_iter()
            .filter(|key| {
                object
                    .own_property_attributes(&RuntimePropertyKey::String(key.clone()))
                    .enumerable
            })
            .collect())
    }

    /// Execute or resume the source-facing `Object.assign` HostCall. It uses
    /// the same typed key snapshot/descriptor recheck machinery as object
    /// spread, but writes with ordinary Set semantics and can therefore pause
    /// in either a source getter or a target setter.
    fn execute_object_assign(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        dst: u32,
    ) -> Result<bool, InterpreterError> {
        let active = self.copy_data_properties_states.last().and_then(|state| {
            if !state.belongs_to(self.ip, self.register_base, self.call_stack.len()) {
                return None;
            }
            match &state.write_mode {
                CopyDataPropertiesWriteMode::Set {
                    target_receiver,
                    source_arg_offset,
                } => Some((*source_arg_offset, target_receiver.clone())),
                CopyDataPropertiesWriteMode::CreateData => None,
            }
        });

        let (mut source_offset, target_value) = if let Some(active) = active {
            active
        } else {
            let target_value = self.required_arg(args, 0, "object Object.assign target")?;
            match &target_value {
                Value::Object(object_id) => {
                    self.heap
                        .get(object_id.0 as usize)
                        .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                }
                function_like if Self::function_object_key(function_like).is_some() => {}
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "object Object.assign target".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
            (1, target_value)
        };

        while source_offset < args.count {
            let source_reg = args.start.checked_add(source_offset).ok_or(
                InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                },
            )?;
            let state_is_active = self
                .copy_data_properties_states
                .last()
                .is_some_and(|state| {
                    state.belongs_to(self.ip, self.register_base, self.call_stack.len())
                });
            if !state_is_active && self.read_reg(source_reg)?.is_nullish() {
                source_offset = source_offset.saturating_add(1);
                continue;
            }
            let entered_accessor = self.execute_copy_data_properties(
                module,
                args.start,
                source_reg,
                RegRange { start: 0, count: 0 },
                dst,
                CopyDataPropertiesWriteMode::Set {
                    target_receiver: target_value.clone(),
                    source_arg_offset: source_offset,
                },
            )?;
            if entered_accessor {
                return Ok(true);
            }
            source_offset = source_offset.saturating_add(1);
        }

        self.write_reg(dst, target_value)?;
        Ok(false)
    }

    fn object_assign(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let target_value = self.required_arg(args, 0, "object")?;
        let target_id = match &target_value {
            Value::Object(object_id) => self.expect_object(Value::Object(*object_id), "object")?,
            function_like if Self::function_object_key(function_like).is_some() => self
                .ensure_function_object(function_like)?
                .expect("function-like value should allocate an object carrier"),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "object".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        for offset in 1..args.count {
            let source = self.read_arg(args, offset)?;
            if source.is_nullish() {
                continue;
            }
            let Some(source_id) = self.copy_data_properties_object_id(&source) else {
                continue;
            };
            self.heap
                .get(source_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: source_id.0 })?;
            let properties = {
                let object = self
                    .heap
                    .get(source_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: source_id.0 })?;
                // bd-jv7qk: this non-resumable route has no `&Ir3Module` /
                // continuation context, so it cannot invoke a property getter
                // the way the resumable `execute_object_assign` does. Rather
                // than silently dropping an enumerable own accessor key — which
                // would let this route diverge from the resumable one and lose
                // the getter's observable result — fail closed. Both String
                // accessors (`baseline_exact_string_accessors` sidecar) and
                // Symbol accessors are refused here; only data-valued own keys
                // are copyable without running user code.
                let mut copied: Vec<(RuntimePropertyKey, Value)> = Vec::new();
                for key in object.own_runtime_property_keys() {
                    match &key {
                        RuntimePropertyKey::String(string_key) => {
                            if let Some(value) = object.properties.get_exact(string_key).cloned() {
                                copied.push((key, value));
                            } else if object
                                .properties
                                .baseline_exact_string_accessor(string_key)
                                .is_some()
                            {
                                return Err(InterpreterError::TypeError {
                                    expected: "resumable Object.assign for accessor-valued source \
                                               properties (getter must run)"
                                        .to_string(),
                                    got:
                                        "non-resumable Object.assign route cannot invoke a String \
                                          accessor getter"
                                            .to_string(),
                                });
                            }
                        }
                        RuntimePropertyKey::Symbol(symbol) => {
                            match object.properties.baseline_symbol_property(*symbol) {
                                Some(BaselineSymbolProperty::Data(value)) => {
                                    copied.push((key, value.clone()));
                                }
                                Some(BaselineSymbolProperty::Accessor { .. }) => {
                                    return Err(InterpreterError::TypeError {
                                        expected: "resumable Object.assign for accessor-valued \
                                                   source properties (getter must run)"
                                            .to_string(),
                                        got: "non-resumable Object.assign route cannot invoke a \
                                              Symbol accessor getter"
                                            .to_string(),
                                    });
                                }
                                None => {}
                            }
                        }
                    }
                }
                copied
            };
            for (key, value) in properties {
                self.set_object_runtime_property(target_id, key, value)?;
            }
        }
        Ok(target_value)
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

    fn symbol_description(&self, id: SymbolId) -> Option<JsString> {
        well_known_symbol_description(id)
            .map(JsString::from)
            .or_else(|| self.symbol_state.description(id).cloned())
    }

    fn symbol_display_string(&self, id: SymbolId) -> String {
        self.symbol_description(id).map_or_else(
            || "Symbol()".to_string(),
            |description| format!("Symbol({description})"),
        )
    }

    /// Convert a Value to a string representation for console output.
    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::Undefined => "undefined".to_string(),
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Str(s) => s.to_string(),
            Value::Symbol(id) => self.symbol_display_string(*id),
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

    /// Record one own property's IFC value label under the interpreter's
    /// total-memory budget (bd-ojvo1). `Public` is represented as absence, and
    /// projection makes rejection atomic for both the heap and accounting.
    fn set_own_runtime_property_label(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        label: &crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let heap_index = object_id.0 as usize;
        let current = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let previous_bytes = Self::estimate_ordered_label_map_bytes(&current.property_labels);
        if matches!(label, crate::ifc_artifacts::Label::Public) {
            match key {
                RuntimePropertyKey::String(key) => {
                    self.heap[heap_index].property_labels.remove_exact(key);
                }
                RuntimePropertyKey::Symbol(symbol) => {
                    self.heap[heap_index]
                        .property_labels
                        .remove_baseline_symbol_property(*symbol);
                }
            }
            let next_bytes =
                Self::estimate_ordered_label_map_bytes(&self.heap[heap_index].property_labels);
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_bytes)
                .saturating_add(next_bytes);
            return Ok(());
        }
        self.check_temporary_memory_budget(previous_bytes)?;
        let mut projected = current.property_labels.clone();
        match key {
            RuntimePropertyKey::String(key) => {
                projected.insert_exact(key.clone(), label.clone());
            }
            RuntimePropertyKey::Symbol(symbol) => {
                projected.insert_baseline_symbol_property(
                    *symbol,
                    BaselineSymbolProperty::Data(label.clone()),
                );
            }
        }
        let next_bytes = Self::estimate_ordered_label_map_bytes(&projected);
        self.check_temporary_memory_budget(next_bytes)?;
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(next_bytes);
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.heap[heap_index].property_labels = projected;
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    fn own_stored_runtime_property_label(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> crate::ifc_artifacts::Label {
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return crate::ifc_artifacts::Label::Public;
        };
        match key {
            RuntimePropertyKey::String(key) => object
                .property_labels
                .get_exact(key)
                .cloned()
                .unwrap_or(crate::ifc_artifacts::Label::Public),
            RuntimePropertyKey::Symbol(symbol) => object
                .property_labels
                .baseline_symbol_property(*symbol)
                .and_then(|property| match property {
                    BaselineSymbolProperty::Data(label) => Some(label.clone()),
                    BaselineSymbolProperty::Accessor { .. } => None,
                })
                .unwrap_or(crate::ifc_artifacts::Label::Public),
        }
    }

    /// The stored IFC label of an own Symbol-keyed property, or `Public` when
    /// absent or unlabeled.
    /// The stored IFC label of a Symbol-keyed property resolved through the
    /// prototype chain (bd-ojvo1): the label on the FIRST object that owns the
    /// Symbol property (shadowing respected), or `Public` when absent/unlabeled.
    fn runtime_property_label(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> crate::ifc_artifacts::Label {
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut visited = std::collections::BTreeSet::new();
        let mut label = crate::ifc_artifacts::Label::Public;
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                break;
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                break;
            };
            if let Some(structure_label) = &object.property_structure_label {
                label = label.join(structure_label);
            }
            if object.contains_own_runtime_property(key) {
                return label.join(&self.own_stored_runtime_property_label(id, key));
            }
            current = object.prototype;
            depth += 1;
        }
        label
    }

    #[cfg(test)]
    fn set_own_property_label(
        &mut self,
        object_id: ObjectId,
        key: &str,
        label: &crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        self.set_own_runtime_property_label(
            object_id,
            &RuntimePropertyKey::String(JsString::from(key)),
            label,
        )
    }

    #[cfg(test)]
    fn set_own_symbol_property_label(
        &mut self,
        object_id: ObjectId,
        symbol: SymbolId,
        label: &crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        self.set_own_runtime_property_label(object_id, &RuntimePropertyKey::Symbol(symbol), label)
    }

    #[cfg(test)]
    fn own_symbol_property_label(
        &self,
        object_id: ObjectId,
        symbol: SymbolId,
    ) -> crate::ifc_artifacts::Label {
        self.runtime_property_label(object_id, &RuntimePropertyKey::Symbol(symbol))
    }

    #[cfg(test)]
    fn own_property_label(&self, object_id: ObjectId, key: &str) -> crate::ifc_artifacts::Label {
        self.runtime_property_label(object_id, &RuntimePropertyKey::String(JsString::from(key)))
    }

    fn read_reg_label(&self, reg: u32) -> Result<crate::ifc_artifacts::Label, InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + reg as usize;
        let label = self
            .register_labels
            .get(actual_reg)
            .cloned()
            .unwrap_or(crate::ifc_artifacts::Label::Public);
        Ok(self.call_stack.iter().fold(label, |label, frame| {
            label.join(&frame.accessor_context_label)
        }))
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

    fn estimate_js_string_bytes(text: &JsString) -> u64 {
        // retained_bytes does not join a concatenation; estimating
        // through &str would (bd-9vouw.468).
        let projected = text.retained_bytes(MEMORY_ESTIMATE_STRING_BASE_BYTES);
        if text.is_well_formed() {
            projected
        } else {
            projected.saturating_add((text.utf16_len() as u64).saturating_mul(2))
        }
    }

    fn estimate_value_bytes(value: &Value) -> u64 {
        match value {
            Value::Str(text) => Self::estimate_js_string_bytes(text),
            _ => 0,
        }
    }

    fn estimate_property_key_bytes(key: &RuntimePropertyKey) -> u64 {
        match key {
            RuntimePropertyKey::String(key) => Self::estimate_js_string_bytes(key),
            RuntimePropertyKey::Symbol(_) => std::mem::size_of::<SymbolId>() as u64,
        }
    }

    fn estimate_symbol_state_bytes(state: &RuntimeSymbolState) -> u64 {
        state.symbols.values().fold(0u64, |total, record| {
            total
                .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
                .saturating_add(
                    record
                        .description
                        .as_ref()
                        .map(Self::estimate_js_string_bytes)
                        .unwrap_or(0),
                )
                .saturating_add(
                    record
                        .registry_key
                        .as_ref()
                        .map(Self::estimate_js_string_bytes)
                        .unwrap_or(0),
                )
        })
    }

    /// Dynamic bytes retained by an IFC label. Level labels (`Public`,
    /// `Secret`, ...) are inline enum values whose storage is already counted
    /// by their owning slot (register arena, record field, queue entry), so
    /// only a `Custom` label's owned name allocation carries the base charge.
    /// Charging a base per level label made the boot-time register-label
    /// arena a phantom recompute-only constant that no eager path ever
    /// charged, breaking eager==recompute on a fresh core (bd-ur3tk.21).
    fn estimate_label_bytes(label: &crate::ifc_artifacts::Label) -> u64 {
        match label {
            crate::ifc_artifacts::Label::Custom { name, .. } => {
                MEMORY_ESTIMATE_LABEL_BASE_BYTES.saturating_add(name.len() as u64)
            }
            _ => 0,
        }
    }

    fn estimate_closure_method_metadata_entry_bytes(metadata: &ClosureMethodMetadata) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<u32>() as u64)
            .saturating_add(std::mem::size_of::<ObjectId>() as u64)
            .saturating_add(Self::estimate_js_string_bytes(&metadata.name))
            .saturating_add(Self::estimate_label_bytes(&metadata.definition_label))
    }

    fn estimate_scope_frame_bytes(frame: &ScopeFrame) -> u64 {
        let bindings = frame
            .bindings
            .iter()
            .map(|(name, binding)| {
                let state_bytes = binding
                    .state
                    .try_borrow()
                    .map(|state| {
                        Self::estimate_value_bytes(&state.value)
                            .saturating_add(Self::estimate_label_bytes(&state.label))
                    })
                    .unwrap_or(u64::MAX);
                MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES
                    .saturating_add(Self::estimate_string_bytes(name))
                    .saturating_add(state_bytes)
            })
            .sum::<u64>();
        // The frame base is charged only once a frame owns bindings: an empty
        // frame (notably the boot frame created inside `InterpreterCore::new`)
        // is inline interpreter substrate that no eager path charges, and a
        // recompute-only constant would break eager==recompute on a fresh
        // core (bd-ur3tk.21). Binding maps still pay per-entry bases above.
        if frame.bindings.is_empty() {
            bindings
        } else {
            MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES.saturating_add(bindings)
        }
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
            .saturating_add(Self::estimate_label_bytes(&frame.this_label))
            .saturating_add(Self::estimate_value_bytes(&frame.new_target_value))
            .saturating_add(Self::estimate_label_bytes(&frame.new_target_label))
            .saturating_add(Self::estimate_value_bytes(&frame.super_value))
            .saturating_add(Self::estimate_label_bytes(&frame.super_label))
            .saturating_add(Self::estimate_label_bytes(&frame.accessor_context_label))
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
                    .map(Self::estimate_labeled_exception_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_pending_return
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                frame
                    .saved_scope_chain
                    .as_ref()
                    .map_or(0, |frames| Self::estimate_scope_chain_bytes(frames)),
            )
            .saturating_add(
                frame
                    .saved_module_specifier
                    .as_deref()
                    .map(Self::estimate_string_bytes)
                    .unwrap_or(0),
            )
    }

    fn estimate_ordered_label_map_bytes(
        labels: &OrderedStringMap<crate::ifc_artifacts::Label>,
    ) -> u64 {
        let exact_order_is_active = labels.exact_len() != labels.len();
        labels
            .well_formed_data_entries()
            .map(|(key, label)| {
                let owned_key_copies =
                    if exact_order_is_active && canonical_array_index(key).is_none() {
                        4
                    } else {
                        2
                    };
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(
                        Self::estimate_string_bytes(key).saturating_mul(owned_key_copies),
                    )
                    .saturating_add(Self::estimate_label_bytes(label))
            })
            .sum::<u64>()
            .saturating_add(
                labels
                    .exact_only_data_entries()
                    .map(|(key, label)| {
                        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                            .saturating_add(Self::estimate_js_string_bytes(key).saturating_mul(3))
                            .saturating_add(Self::estimate_label_bytes(label))
                    })
                    .sum::<u64>(),
            )
            .saturating_add(
                labels
                    .baseline_symbol_properties()
                    .map(|(_, property)| {
                        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                            .saturating_add(
                                (std::mem::size_of::<SymbolId>() as u64).saturating_mul(2),
                            )
                            .saturating_add(match property {
                                BaselineSymbolProperty::Data(label) => {
                                    Self::estimate_label_bytes(label)
                                }
                                BaselineSymbolProperty::Accessor { get, set } => get
                                    .as_ref()
                                    .map(Self::estimate_label_bytes)
                                    .unwrap_or(0)
                                    .saturating_add(
                                        set.as_ref().map(Self::estimate_label_bytes).unwrap_or(0),
                                    ),
                            })
                    })
                    .sum::<u64>(),
            )
    }

    fn estimate_heap_object_bytes(object: &HeapObject) -> u64 {
        let properties = object
            .properties
            .well_formed_data_entries()
            .map(|(key, value)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_string_bytes(key))
                    // OrderedStringMap owns a second key for its ES-order
                    // index/vector spine in addition to the lookup-map key.
                    .saturating_add(Self::estimate_string_bytes(key))
                    .saturating_add(Self::estimate_value_bytes(value))
            })
            .chain(
                object
                    .properties
                    .exact_only_data_entries()
                    .map(|(key, value)| {
                        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                            .saturating_add(Self::estimate_js_string_bytes(key))
                            .saturating_add(Self::estimate_js_string_bytes(key))
                            .saturating_add(Self::estimate_value_bytes(value))
                    }),
            )
            .sum::<u64>();
        let exact_data_order_well_formed_copies = object
            .properties
            .exact_string_insertion_order()
            .map(|order| {
                order
                    .iter()
                    .filter(|key| key.is_well_formed())
                    .map(Self::estimate_js_string_bytes)
                    .sum::<u64>()
            })
            .unwrap_or(0);
        let accessors =
            object
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
                .chain(object.properties.baseline_exact_string_accessors().map(
                    |(key, accessor)| {
                        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                            .saturating_add(Self::estimate_js_string_bytes(key))
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
                    },
                ))
                .sum::<u64>();
        let own_string_key_order = object
            .properties
            .baseline_string_key_order()
            .map(|order| {
                order
                    .iter()
                    .map(Self::estimate_js_string_bytes)
                    .sum::<u64>()
            })
            .unwrap_or(0);
        let symbol_properties = object
            .properties
            .baseline_symbol_properties()
            .map(|(_, property)| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(match property {
                    BaselineSymbolProperty::Data(value) => Self::estimate_value_bytes(value),
                    BaselineSymbolProperty::Accessor { get, set } => get
                        .as_ref()
                        .map(Self::estimate_value_bytes)
                        .unwrap_or(0)
                        .saturating_add(set.as_ref().map(Self::estimate_value_bytes).unwrap_or(0)),
                })
            })
            .sum::<u64>();
        let symbol_order = (object.properties.baseline_symbol_key_order().len() as u64)
            .saturating_mul(std::mem::size_of::<SymbolId>() as u64);
        let property_labels = Self::estimate_ordered_label_map_bytes(&object.property_labels);
        let property_attributes = object
            .property_attributes
            .keys()
            .map(|key| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_property_key_bytes(key))
                    .saturating_add(std::mem::size_of::<PropertyAttributes>() as u64)
            })
            .sum::<u64>();
        MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES
            .saturating_add(properties)
            .saturating_add(exact_data_order_well_formed_copies)
            .saturating_add(accessors)
            .saturating_add(own_string_key_order)
            .saturating_add(symbol_properties)
            .saturating_add(symbol_order)
            .saturating_add(property_labels)
            .saturating_add(property_attributes)
            .saturating_add(
                object
                    .property_structure_label
                    .as_ref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                object
                    .derived_constructor_parent
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                object
                    .derived_constructor_parent_label
                    .as_ref()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            )
    }

    fn estimate_iterator_bytes(iterator: &RuntimeIteratorState) -> u64 {
        match iterator {
            RuntimeIteratorState::ForIn(state) => {
                let keys = state
                    .keys
                    .iter()
                    .map(Self::estimate_js_string_bytes)
                    .sum::<u64>();
                MEMORY_ESTIMATE_ITERATOR_BASE_BYTES.saturating_add(keys)
            }
            RuntimeIteratorState::ForOf(state) => {
                let values = state
                    .values
                    .iter()
                    .map(Self::estimate_value_bytes)
                    .sum::<u64>();
                MEMORY_ESTIMATE_ITERATOR_BASE_BYTES
                    .saturating_add(values)
                    .saturating_add(
                        (state.values.len() as u64)
                            .saturating_mul(std::mem::size_of::<Value>() as u64),
                    )
                    .saturating_add(
                        state
                            .iterator_receiver
                            .as_ref()
                            .map(Self::estimate_timer_value_bytes)
                            .unwrap_or(0),
                    )
                    .saturating_add(
                        state
                            .next_method
                            .as_ref()
                            .map(Self::estimate_timer_value_bytes)
                            .unwrap_or(0),
                    )
                    .saturating_add(Self::estimate_label_bytes(&state.label))
            }
        }
    }

    fn estimate_copy_data_properties_state_bytes(state: &CopyDataPropertiesState) -> u64 {
        let keys = state
            .keys
            .iter()
            .map(Self::estimate_property_key_bytes)
            .sum::<u64>();
        let excluded = state
            .excluded
            .iter()
            .map(Self::estimate_property_key_bytes)
            .sum::<u64>();
        let awaiting_key = match state.awaiting.as_ref() {
            Some(CopyDataPropertiesAwaiting::Getter(key)) => Self::estimate_property_key_bytes(key),
            None => 0,
        };
        let write_mode = match &state.write_mode {
            CopyDataPropertiesWriteMode::CreateData => 0,
            CopyDataPropertiesWriteMode::Set {
                target_receiver, ..
            } => Self::estimate_value_bytes(target_receiver),
        };
        MEMORY_ESTIMATE_COPY_DATA_PROPERTIES_STATE_BASE_BYTES
            .saturating_add(Self::estimate_value_bytes(&state.source))
            .saturating_add(Self::estimate_label_bytes(&state.source_label))
            .saturating_add(
                state
                    .string_units
                    .as_ref()
                    .map_or(0, |units| (units.len() as u64).saturating_mul(2)),
            )
            .saturating_add(keys)
            .saturating_add(excluded)
            .saturating_add(awaiting_key)
            .saturating_add(write_mode)
    }

    fn estimate_labeled_exception_bytes(exception: &LabeledException) -> u64 {
        Self::estimate_value_bytes(&exception.value)
            .saturating_add(Self::estimate_label_bytes(&exception.label))
    }

    fn estimate_labeled_return_bytes(return_value: &LabeledReturn) -> u64 {
        Self::estimate_value_bytes(&return_value.value)
            .saturating_add(Self::estimate_label_bytes(&return_value.label))
    }

    fn estimate_abrupt_completion_bytes(completion: &AbruptCompletion) -> u64 {
        match completion {
            AbruptCompletion::Exception(exception) => {
                Self::estimate_labeled_exception_bytes(exception)
            }
            AbruptCompletion::Return(return_value) => {
                Self::estimate_labeled_return_bytes(return_value)
            }
        }
    }

    fn estimate_async_function_snapshot_bytes(function: &AsyncFunctionObject) -> u64 {
        (std::mem::size_of::<AsyncFunctionObject>() as u64)
            .saturating_add(
                function
                    .execution
                    .as_ref()
                    .map(Self::estimate_module_execution_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(function.retained_program_bytes)
            .saturating_add(function.register_storage_bytes)
            .saturating_add(Self::estimate_label_bytes(&function.label))
    }

    fn async_function_snapshots_memory_bytes(&self) -> u64 {
        self.async_functions
            .iter()
            .map(Self::estimate_async_function_snapshot_bytes)
            .sum::<u64>()
    }

    /// Payload retained by one combinator tracker plus its accumulated IFC
    /// label. Supersedes the bd-ur3tk.8 label-only slice — the label stays
    /// counted exactly once here, never in a second component (bd-ur3tk.21).
    fn estimate_promise_combinator_state_bytes(state: &LabeledPromiseCombinatorState) -> u64 {
        let tracker_bytes = match &state.tracker {
            PromiseCombinatorState::All(tracker) => tracker
                .values
                .values()
                .map(|value| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(crate::promise_model::estimate_js_value_memory_bytes(value))
                })
                .fold(0u64, u64::saturating_add),
            PromiseCombinatorState::AllSettled(tracker) => tracker
                .outcomes
                .values()
                .map(|outcome| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(Self::estimate_string_bytes(&outcome.status))
                        .saturating_add(crate::promise_model::estimate_js_value_memory_bytes(
                            &outcome.value,
                        ))
                })
                .fold(0u64, u64::saturating_add),
            PromiseCombinatorState::Race(_) => 0,
            PromiseCombinatorState::Any(tracker) => tracker
                .errors
                .values()
                .map(|reason| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(
                        crate::promise_model::estimate_js_value_memory_bytes(reason),
                    )
                })
                .fold(0u64, u64::saturating_add),
        };
        tracker_bytes.saturating_add(Self::estimate_label_bytes(&state.accumulated_label))
    }

    fn promise_combinators_memory_bytes(&self) -> u64 {
        self.promise_combinators
            .values()
            .map(|state| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_promise_combinator_state_bytes(state))
            })
            .fold(0u64, u64::saturating_add)
    }

    fn promise_combinator_watchers_memory_bytes(&self) -> u64 {
        self.promise_combinator_watchers
            .values()
            .map(|watchers| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(
                    u64::try_from(watchers.len())
                        .unwrap_or(u64::MAX)
                        .saturating_mul(std::mem::size_of::<PromiseCombinatorWatcher>() as u64),
                )
            })
            .fold(0u64, u64::saturating_add)
    }

    fn estimate_promise_reaction_registration_bytes(
        registration: &PromiseReactionRegistration,
    ) -> u64 {
        let actions = [&registration.on_fulfilled, &registration.on_rejected]
            .into_iter()
            .flatten()
            .map(|action| {
                let payload = match action {
                    PromiseReactionAction::Call(callee)
                    | PromiseReactionAction::Finally(callee) => Self::estimate_value_bytes(callee),
                    PromiseReactionAction::Forward(_)
                    | PromiseReactionAction::Combinator { .. } => 0,
                    PromiseReactionAction::Restore { value, label, .. } => {
                        Self::estimate_value_bytes(value)
                            .saturating_add(Self::estimate_label_bytes(label))
                    }
                };
                (std::mem::size_of::<PromiseReactionAction>() as u64).saturating_add(payload)
            })
            .fold(0u64, u64::saturating_add);
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(actions)
    }

    fn promise_reactions_memory_bytes(&self) -> u64 {
        self.promise_reactions
            .values()
            .map(Self::estimate_promise_reaction_registration_bytes)
            .fold(0u64, u64::saturating_add)
    }

    fn estimate_promise_resolving_functions_bytes(pair: &PromiseResolvingFunctions) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<PromiseResolvingFunctions>() as u64)
            .saturating_add(Self::estimate_label_bytes(&pair.label))
    }

    fn promise_resolving_functions_memory_bytes(&self) -> u64 {
        self.promise_resolving_functions
            .values()
            .map(Self::estimate_promise_resolving_functions_bytes)
            .fold(0u64, u64::saturating_add)
    }

    fn active_timer_entry_bytes() -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(std::mem::size_of::<ActiveTimer>() as u64)
    }

    fn estimate_timer_invocation_bytes(invocation: &TimerInvocation) -> u64 {
        invocation.arguments.iter().fold(
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(std::mem::size_of::<TimerInvocation>() as u64)
                .saturating_add(Self::estimate_timer_value_bytes(&invocation.callee)),
            |bytes, (value, label)| {
                bytes.saturating_add(Self::estimate_timer_argument_bytes(value, label))
            },
        )
    }

    fn estimate_timer_argument_bytes(value: &Value, label: &crate::ifc_artifacts::Label) -> u64 {
        (std::mem::size_of::<(Value, crate::ifc_artifacts::Label)>() as u64)
            .saturating_add(Self::estimate_timer_value_bytes(value))
            .saturating_add(Self::estimate_label_bytes(label))
    }

    fn estimate_timer_value_bytes(value: &Value) -> u64 {
        match value {
            // Capturing a first-class require clones its owned module path.
            Value::BuiltinFunction(builtin) if !builtin.module_specifier.is_empty() => {
                Self::estimate_string_bytes(&builtin.module_specifier)
            }
            _ => Self::estimate_value_bytes(value),
        }
    }

    fn timers_memory_bytes(&self) -> u64 {
        self.timer_invocations
            .values()
            .map(Self::estimate_timer_invocation_bytes)
            .fold(
                (self.active_timers.len() as u64).saturating_mul(Self::active_timer_entry_bytes()),
                u64::saturating_add,
            )
    }

    /// Resident bytes of the whole Promise runtime: store records/witness,
    /// event-loop queues and witness, combinator trackers with their
    /// accumulated labels, watcher vectors, timers and captured arguments,
    /// and any in-flight macrotask transfer (bd-ur3tk.21).
    fn promise_runtime_memory_bytes(&self) -> u64 {
        self.promise_store
            .estimated_memory_bytes()
            .saturating_add(self.event_loop.estimated_memory_bytes())
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_reactions_memory_bytes())
            .saturating_add(self.promise_resolving_functions_memory_bytes())
            .saturating_add(self.timers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes)
    }

    /// Reprice the Promise runtime after a bracketed mutation, refusing
    /// atomically at the configured ceiling. Callers roll back their local
    /// mutation when this refuses.
    fn apply_promise_runtime_memory_delta(
        &mut self,
        previous_bytes: u64,
    ) -> Result<(), InterpreterError> {
        let next_bytes = self.promise_runtime_memory_bytes();
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(next_bytes);
        if requested_bytes > self.config.max_total_memory_bytes {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    fn estimate_module_execution_bytes(execution: &ModuleExecutionSnapshot) -> u64 {
        execution
            .registers
            .iter()
            .map(Self::estimate_value_bytes)
            .sum::<u64>()
            .saturating_add(
                execution
                    .register_labels
                    .iter()
                    .map(Self::estimate_label_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                execution
                    .call_stack
                    .iter()
                    .map(Self::estimate_call_frame_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(Self::estimate_scope_chain_bytes(
                &execution.scope_chain.frames,
            ))
            .saturating_add(
                execution
                    .copy_data_properties_states
                    .iter()
                    .map(Self::estimate_copy_data_properties_state_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                execution
                    .pending_exception
                    .as_ref()
                    .map(Self::estimate_labeled_exception_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                execution
                    .pending_return
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                execution
                    .suspended_abrupt_completions
                    .iter()
                    .map(Self::estimate_abrupt_completion_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                execution
                    .finally_frames
                    .iter()
                    .filter_map(|frame| frame.completion.as_ref())
                    .map(Self::estimate_abrupt_completion_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                (execution.pending_captures.len() as u64)
                    .saturating_mul(std::mem::size_of::<u32>() as u64),
            )
            .saturating_add(
                execution
                    .current_module_specifier
                    .as_ref()
                    .map(|specifier| Self::estimate_string_bytes(specifier))
                    .unwrap_or(0),
            )
    }

    fn estimate_generator_bytes(generator: &GeneratorObject) -> u64 {
        MEMORY_ESTIMATE_GENERATOR_BASE_BYTES.saturating_add(
            generator
                .execution
                .as_ref()
                .map(Self::estimate_module_execution_bytes)
                .unwrap_or(0),
        )
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
        Self::estimate_symbol_state_bytes(&self.symbol_state)
            .saturating_add(
                self.heap
                    .iter()
                    .map(Self::estimate_heap_object_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                self.registers
                    .iter()
                    .map(Self::estimate_value_bytes)
                    .sum::<u64>(),
            )
            // Keep the installed execution-context estimate symmetric with
            // estimate_module_execution_bytes. Generator activation swaps can
            // then move a context between active and suspended storage without
            // creating an unaccounted transient.
            .saturating_add(
                self.register_labels
                    .iter()
                    .map(Self::estimate_label_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(Self::estimate_scope_chain_bytes(&self.scope_chain.frames))
            .saturating_add(
                self.closures
                    .iter()
                    .map(|closure| {
                        MEMORY_ESTIMATE_CLOSURE_BASE_BYTES
                            .saturating_add(Self::estimate_scope_chain_bytes(&closure.captured_env))
                            .saturating_add(
                                closure
                                    .module_specifier
                                    .as_deref()
                                    .map(Self::estimate_string_bytes)
                                    .unwrap_or(0),
                            )
                    })
                    .sum::<u64>(),
            )
            .saturating_add(
                self.closure_method_metadata
                    .values()
                    .map(Self::estimate_closure_method_metadata_entry_bytes)
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
                self.pending_exception
                    .as_ref()
                    .map(Self::estimate_labeled_exception_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                self.pending_return
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                self.suspended_abrupt_completions
                    .iter()
                    .map(Self::estimate_abrupt_completion_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                self.finally_frames
                    .iter()
                    .filter_map(|frame| frame.completion.as_ref())
                    .map(Self::estimate_abrupt_completion_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                (self.pending_captures.len() as u64)
                    .saturating_mul(std::mem::size_of::<u32>() as u64),
            )
            .saturating_add(
                self.current_module_specifier
                    .as_ref()
                    .map(|specifier| Self::estimate_string_bytes(specifier))
                    .unwrap_or(0),
            )
            .saturating_add(
                self.generators
                    .iter()
                    .map(Self::estimate_generator_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(
                self.async_generators
                    .iter()
                    .map(Self::estimate_async_generator_bytes)
                    .sum::<u64>(),
            )
            .saturating_add(self.async_function_snapshots_memory_bytes())
            .saturating_add(
                (self.async_resumption_contexts.len() as u64)
                    .saturating_mul(Self::async_resumption_context_entry_bytes()),
            )
            .saturating_add(
                (self.async_generator_continuations.len() as u64)
                    .saturating_mul(Self::async_generator_continuation_bytes()),
            )
            .saturating_add(self.promise_runtime_memory_bytes())
            .saturating_add(self.module_state.retained_program_bytes)
            .saturating_add(self.temporarily_suspended_execution_bytes)
            .saturating_add(self.array_method_temporary_bytes)
            .saturating_add(
                (self.array_join_stack.len() as u64)
                    .saturating_mul(std::mem::size_of::<ObjectId>() as u64),
            )
            .saturating_add((self.array_null_prototypes.len() as u64).saturating_mul(
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES + std::mem::size_of::<ObjectId>() as u64,
            ))
            .saturating_add((self.function_null_prototypes.len() as u64).saturating_mul(
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES + std::mem::size_of::<ObjectId>() as u64,
            ))
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

    fn snapshot_call_setup(
        &self,
        result_register: Option<u32>,
        capture_function_prototypes: bool,
    ) -> CallSetupSnapshot {
        let frame_width = self.config.max_registers as usize;
        let callee_register_start = self.register_base.saturating_add(frame_width);
        let callee_register_end = callee_register_start.saturating_add(frame_width);
        let saved_register_end = callee_register_end.min(self.registers.len());
        let saved_label_end = callee_register_end.min(self.register_labels.len());
        let callee_registers = if callee_register_start < saved_register_end {
            self.registers[callee_register_start..saved_register_end].to_vec()
        } else {
            Vec::new()
        };
        let callee_register_labels = if callee_register_start < saved_label_end {
            self.register_labels[callee_register_start..saved_label_end].to_vec()
        } else {
            Vec::new()
        };
        let result_register = result_register
            .filter(|register| *register < self.config.max_registers)
            .map(|register| {
                let index = self.register_base.saturating_add(register as usize);
                CallSetupRegisterSlotSnapshot {
                    index,
                    value: self.registers.get(index).cloned(),
                    label: self.register_labels.get(index).cloned(),
                }
            });

        CallSetupSnapshot {
            heap_len: self.heap.len(),
            function_prototypes: capture_function_prototypes
                .then(|| self.function_prototypes.clone()),
            call_stack_depth: self.call_stack.len(),
            register_base: self.register_base,
            ip: self.ip,
            registers_len: self.registers.len(),
            register_labels_len: self.register_labels.len(),
            callee_register_start,
            callee_registers,
            callee_register_labels,
            result_register,
            async_functions_len: self.async_functions.len(),
            profiling_memory_stats: self
                .profiling_data
                .as_ref()
                .map(crate::profiling::Profiler::memory_stats_snapshot),
            estimated_memory_bytes: self.estimated_memory_bytes,
        }
    }

    fn restore_call_setup(&mut self, snapshot: CallSetupSnapshot) {
        while self.call_stack.len() > snapshot.call_stack_depth {
            self.rollback_call_setup();
        }
        debug_assert_eq!(self.call_stack.len(), snapshot.call_stack_depth);
        self.register_base = snapshot.register_base;
        self.ip = snapshot.ip;

        if self.registers.len() < snapshot.registers_len {
            self.registers
                .resize(snapshot.registers_len, Value::Undefined);
        }
        if !snapshot.callee_registers.is_empty() {
            let end = snapshot
                .callee_register_start
                .saturating_add(snapshot.callee_registers.len());
            self.registers[snapshot.callee_register_start..end]
                .clone_from_slice(&snapshot.callee_registers);
        }
        self.registers.truncate(snapshot.registers_len);

        if self.register_labels.len() < snapshot.register_labels_len {
            self.register_labels.resize(
                snapshot.register_labels_len,
                crate::ifc_artifacts::Label::Public,
            );
        }
        if !snapshot.callee_register_labels.is_empty() {
            let end = snapshot
                .callee_register_start
                .saturating_add(snapshot.callee_register_labels.len());
            self.register_labels[snapshot.callee_register_start..end]
                .clone_from_slice(&snapshot.callee_register_labels);
        }
        self.register_labels.truncate(snapshot.register_labels_len);

        if let Some(result_register) = snapshot.result_register {
            if let Some(value) = result_register.value {
                self.registers[result_register.index] = value;
            }
            if let Some(label) = result_register.label {
                self.register_labels[result_register.index] = label;
            }
        }

        self.async_functions.truncate(snapshot.async_functions_len);
        self.heap.truncate(snapshot.heap_len);
        self.function_objects
            .retain(|_, id| (id.0 as usize) < snapshot.heap_len);
        self.array_null_prototypes
            .retain(|id| (id.0 as usize) < snapshot.heap_len);
        self.function_null_prototypes
            .retain(|id| (id.0 as usize) < snapshot.heap_len);
        if let Some(function_prototypes) = snapshot.function_prototypes {
            self.function_prototypes = function_prototypes;
        }
        if let (Some(profiler), Some(memory_stats)) =
            (&mut self.profiling_data, snapshot.profiling_memory_stats)
        {
            profiler.restore_memory_stats(memory_stats);
        }

        self.estimated_memory_bytes = snapshot.estimated_memory_bytes;
    }

    fn rollback_call_setup(&mut self) {
        if let Some(frame) = self.call_stack.pop() {
            self.current_module_specifier = frame.saved_module_specifier;
            self.register_base = frame.register_base;
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
        let retained_bytes = Self::estimate_iterator_bytes(&iterator);
        self.check_temporary_memory_budget(retained_bytes)?;
        self.iterators.push(iterator);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(retained_bytes);
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

    fn collect_for_in_keys(&self, object_id: ObjectId) -> Result<Vec<JsString>, InterpreterError> {
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
            for key in object.own_exact_property_keys() {
                if seen.insert(key.clone())
                    && object
                        .own_property_attributes(&RuntimePropertyKey::String(key.clone()))
                        .enumerable
                {
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
            Value::Str(text) => {
                // A code point occupies at most one slot per UTF-16 unit.
                // Check both transient Vec representations and their string
                // storage before expanding a potentially large string.
                let per_element = (std::mem::size_of::<JsString>() as u64)
                    .saturating_add(std::mem::size_of::<Value>() as u64)
                    .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
                    .saturating_add(8);
                self.check_temporary_memory_budget(
                    (text.utf16_len() as u64).saturating_mul(per_element),
                )?;
                Ok(text
                    .code_point_elements()
                    .into_iter()
                    .map(Value::Str)
                    .collect())
            }
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

    fn mark_deleted_for_in_iterators(&mut self, object_id: ObjectId, key: &JsString) {
        for iterator in &mut self.iterators {
            if let RuntimeIteratorState::ForIn(state) = iterator
                && state.object_id == object_id
            {
                state.deleted_keys.insert(key.clone());
            }
        }
    }

    fn set_object_property(
        &mut self,
        object_id: ObjectId,
        key: String,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.set_object_runtime_property(
            object_id,
            RuntimePropertyKey::String(JsString::from(key)),
            value,
        )
    }

    #[cfg(test)]
    fn set_object_typed_property(
        &mut self,
        object_id: ObjectId,
        key: TypedPropertyKey,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.validate_runtime_property_key(&key)?;
        let key = match key {
            TypedPropertyKey::String(key) => RuntimePropertyKey::String(JsString::from(key)),
            TypedPropertyKey::Symbol(symbol) => RuntimePropertyKey::Symbol(symbol),
        };
        self.set_object_runtime_property(object_id, key, value)
    }

    fn set_object_runtime_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(&key)?;
        match key {
            RuntimePropertyKey::String(key) => {
                self.set_object_string_property(object_id, key, value)
            }
            RuntimePropertyKey::Symbol(symbol) => {
                self.set_symbol_property(object_id, symbol, BaselineSymbolProperty::Data(value))
            }
        }
    }

    fn inferred_method_name(&self, key: &RuntimePropertyKey) -> JsString {
        match key {
            RuntimePropertyKey::String(name) => name.clone(),
            RuntimePropertyKey::Symbol(symbol) => self.symbol_description(*symbol).map_or_else(
                || JsString::from(""),
                |description| {
                    JsString::from("[")
                        .concat(&description)
                        .concat(&JsString::from("]"))
                },
            ),
        }
    }

    /// Install an ordinary data property and its private per-closure method
    /// identity atomically under the interpreter's total-memory budget.
    fn define_method_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        function: Value,
        definition_label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        self.define_method_or_accessor_property(object_id, key, function, None, definition_label)
    }

    fn define_accessor_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        function: Value,
        kind: AccessorKind,
        definition_label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        self.define_method_or_accessor_property(
            object_id,
            key,
            function,
            Some(kind),
            definition_label,
        )
    }

    fn define_method_or_accessor_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        function: Value,
        accessor_kind: Option<AccessorKind>,
        definition_label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(&key)?;
        let closure_id = match &function {
            Value::Closure(id) | Value::AsyncFunction(id) | Value::AsyncGeneratorFunction(id) => {
                *id
            }
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "fresh closure for concise method definition".to_string(),
                    got: function.type_name().to_string(),
                });
            }
        };
        self.closures
            .get(closure_id as usize)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid concise-method closure".to_string(),
                got: format!("closure#{closure_id} not found"),
            })?;
        if self.closure_method_metadata.contains_key(&closure_id) {
            return Err(InterpreterError::TypeError {
                expected: "unregistered concise-method closure".to_string(),
                got: format!("closure#{closure_id} already has a [[HomeObject]]"),
            });
        }

        let name = self.inferred_method_name(&key);
        let name = match accessor_kind {
            Some(AccessorKind::Get) => JsString::from("get ").concat(&name),
            Some(AccessorKind::Set) => JsString::from("set ").concat(&name),
            None => name,
        };
        // Capture the exact string/Symbol key and definition label before the
        // property write moves them, so the property carrier gets the same IFC
        // provenance as closure_method_metadata.
        let method_key = key.clone();
        let previous_label = self.own_stored_runtime_property_label(object_id, &method_key);
        let method_label = if accessor_kind.is_some() {
            definition_label.join(&previous_label)
        } else {
            definition_label.clone()
        };
        self.closure_method_metadata.insert(
            closure_id,
            ClosureMethodMetadata {
                home_object: object_id,
                name,
                definition_label,
            },
        );

        if let Err(error) =
            self.set_own_runtime_property_label(object_id, &method_key, &method_label)
        {
            self.closure_method_metadata.remove(&closure_id);
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        let definition = match accessor_kind {
            Some(kind) => self.set_object_accessor_property(object_id, key, function, kind),
            None => self.set_plain_data_runtime_property(object_id, key, function),
        };
        if let Err(error) = definition {
            self.set_own_runtime_property_label(object_id, &method_key, &previous_label)?;
            self.closure_method_metadata.remove(&closure_id);
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        Ok(())
    }

    /// Define one own accessor half without converting exact UTF-16 or Symbol
    /// keys to an encoded string. Descriptor replacement keeps creation order.
    fn set_object_accessor_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        function: Value,
        kind: AccessorKind,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(&key)?;
        if let RuntimePropertyKey::Symbol(symbol) = key {
            let object = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let (get, set) = match object.properties.baseline_symbol_property(symbol) {
                Some(BaselineSymbolProperty::Accessor { get, set }) => (get.clone(), set.clone()),
                _ => (None, None),
            };
            let property = match kind {
                AccessorKind::Get => BaselineSymbolProperty::Accessor {
                    get: Some(function),
                    set,
                },
                AccessorKind::Set => BaselineSymbolProperty::Accessor {
                    get,
                    set: Some(function),
                },
            };
            return self.set_symbol_property(object_id, symbol, property);
        }
        let RuntimePropertyKey::String(key) = key else {
            unreachable!()
        };
        let (previous_data, previous_data_position, previous_accessor, order_rollback) = {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let existed =
                object.contains_own_runtime_property(&RuntimePropertyKey::String(key.clone()));
            let order_rollback = object.record_property_definition(&key, existed);
            let previous_data_position = object.properties.exact_string_insertion_position(&key);
            let previous_data = object
                .properties
                .remove_exact_preserving_baseline_order(&key);
            let previous_accessor = object.exact_accessor(&key);
            let mut accessor = previous_accessor.clone().unwrap_or_default();
            match kind {
                AccessorKind::Get => accessor.get = Some(function),
                AccessorKind::Set => accessor.set = Some(function),
            }
            object.insert_exact_accessor(key.clone(), accessor);
            (
                previous_data,
                previous_data_position,
                previous_accessor,
                order_rollback,
            )
        };
        if let Err(error) = self.sync_estimated_memory_bytes() {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            if let Some(previous) = previous_data {
                object.properties.insert_exact_at_string_position(
                    key.clone(),
                    previous,
                    previous_data_position.unwrap_or(0),
                );
            }
            if let Some(previous) = previous_accessor {
                object.insert_exact_accessor(key.clone(), previous);
            } else {
                object.remove_exact_accessor(&key);
            }
            object.rollback_property_definition_order(&key, order_rollback);
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(error);
        }
        Ok(())
    }

    fn set_object_string_property(
        &mut self,
        object_id: ObjectId,
        key: JsString,
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
                let existed = object.contains_own_runtime_property(&RuntimePropertyKey::String(
                    property_key.clone(),
                ));
                let order_rollback = object.record_property_definition(&property_key, existed);
                let previous_data_position = object
                    .properties
                    .exact_string_insertion_position(&property_key);
                let previous_data = object
                    .properties
                    .remove_exact_preserving_baseline_order(&property_key);
                let previous_accessor = object.exact_accessor(&property_key);
                let mut accessor = previous_accessor.clone().unwrap_or_default();
                match kind {
                    AccessorKind::Get => accessor.get = Some(value),
                    AccessorKind::Set => accessor.set = Some(value),
                }
                object.insert_exact_accessor(property_key.clone(), accessor);
                (
                    previous_data,
                    previous_data_position,
                    previous_accessor,
                    property_key,
                    order_rollback,
                )
            } else {
                let existed =
                    object.contains_own_runtime_property(&RuntimePropertyKey::String(key.clone()));
                let order_rollback = object.record_property_definition(&key, existed);
                let previous_accessor = object.remove_exact_accessor(&key);
                let previous_data = object.properties.insert_exact(key.clone(), value);
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
                    object.properties.insert_exact_at_string_position(
                        property_key.clone(),
                        previous,
                        position,
                    );
                } else {
                    object
                        .properties
                        .insert_exact(property_key.clone(), previous);
                }
            } else {
                object
                    .properties
                    .remove_exact_preserving_baseline_order(&property_key);
            }
            if let Some(previous) = previous_accessor {
                object.insert_exact_accessor(property_key.clone(), previous);
            } else {
                object.remove_exact_accessor(&property_key);
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
        self.set_plain_data_runtime_property(
            object_id,
            RuntimePropertyKey::String(JsString::from(key)),
            value,
        )
    }

    fn set_plain_data_runtime_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(&key)?;
        let RuntimePropertyKey::String(key) = key else {
            let RuntimePropertyKey::Symbol(symbol) = key else {
                unreachable!();
            };
            return self.set_symbol_property(
                object_id,
                symbol,
                BaselineSymbolProperty::Data(value),
            );
        };
        let (previous_data, previous_accessor, order_rollback) = {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let existed =
                object.contains_own_runtime_property(&RuntimePropertyKey::String(key.clone()));
            let order_rollback = object.record_property_definition(&key, existed);
            let previous_accessor = object.remove_exact_accessor(&key);
            let previous_data = object.properties.insert_exact(key.clone(), value);
            (previous_data, previous_accessor, order_rollback)
        };
        if let Err(err) = self.sync_estimated_memory_bytes() {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            if let Some(previous) = previous_data {
                object.properties.insert_exact(key.clone(), previous);
            } else {
                object
                    .properties
                    .remove_exact_preserving_baseline_order(&key);
            }
            if let Some(previous) = previous_accessor {
                object.insert_exact_accessor(key.clone(), previous);
            } else {
                object.remove_exact_accessor(&key);
            }
            object.rollback_property_definition_order(&key, order_rollback);
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            return Err(err);
        }
        Ok(())
    }

    fn set_symbol_property(
        &mut self,
        object_id: ObjectId,
        symbol: SymbolId,
        property: BaselineSymbolProperty<Value>,
    ) -> Result<(), InterpreterError> {
        self.validate_runtime_property_key(&TypedPropertyKey::Symbol(symbol))?;
        let previous_memory = self.estimated_memory_bytes;
        let (previous, previous_position) = {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let previous_position = object
                .properties
                .baseline_symbol_key_order()
                .iter()
                .position(|candidate| *candidate == symbol);
            let previous = object
                .properties
                .insert_baseline_symbol_property(symbol, property);
            (previous, previous_position)
        };
        if let Err(err) = self.sync_estimated_memory_bytes() {
            let object = self
                .heap
                .get_mut(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            object.properties.remove_baseline_symbol_property(symbol);
            if let Some(previous) = previous {
                object.properties.restore_baseline_symbol_property(
                    symbol,
                    previous,
                    previous_position.unwrap_or(0),
                );
            }
            self.estimated_memory_bytes = previous_memory;
            return Err(err);
        }
        Ok(())
    }

    fn remove_object_property(
        &mut self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<bool, InterpreterError> {
        self.remove_object_runtime_property(
            object_id,
            &RuntimePropertyKey::String(JsString::from(key)),
        )
    }

    fn remove_object_runtime_property(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        self.validate_executable_property_key(key)?;
        let object = self
            .heap
            .get_mut(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let removed = match key {
            RuntimePropertyKey::String(key) => {
                let removed = object.properties.remove_exact(key);
                let removed_accessor = object.remove_exact_accessor(key);
                if removed.is_some() || removed_accessor.is_some() {
                    object.forget_property_order(key);
                    object.property_labels.remove_exact(key);
                }
                removed.is_some() || removed_accessor.is_some()
            }
            RuntimePropertyKey::Symbol(symbol) => {
                let removed = object
                    .properties
                    .remove_baseline_symbol_property(*symbol)
                    .is_some();
                if removed {
                    object
                        .property_labels
                        .remove_baseline_symbol_property(*symbol);
                }
                removed
            }
        };
        if removed {
            object.property_attributes.remove(key);
        }
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        Ok(removed)
    }

    #[cfg(test)]
    fn remove_object_typed_property(
        &mut self,
        object_id: ObjectId,
        key: &TypedPropertyKey,
    ) -> Result<bool, InterpreterError> {
        self.validate_runtime_property_key(key)?;
        let key = match key {
            TypedPropertyKey::String(key) => {
                RuntimePropertyKey::String(JsString::from(key.as_str()))
            }
            TypedPropertyKey::Symbol(symbol) => RuntimePropertyKey::Symbol(*symbol),
        };
        self.remove_object_runtime_property(object_id, &key)
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
            Value::Closure(closure_id)
            | Value::GeneratorFunction(closure_id)
            | Value::AsyncFunction(closure_id)
            | Value::AsyncGeneratorFunction(closure_id) => {
                Some(FunctionObjectKey::Closure(*closure_id))
            }
            Value::BuiltinFunction(builtin) => Some(FunctionObjectKey::Builtin(builtin.kind)),
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
                if self.closure_method_metadata.contains_key(closure_id) {
                    Ok(None)
                } else {
                    Ok(Some(FunctionObjectKey::Closure(*closure_id)))
                }
            }
            Value::BuiltinFunction(BuiltinFunction {
                kind:
                    BuiltinFunctionKind::FunctionPrototypeCall
                    | BuiltinFunctionKind::FunctionPrototypeApply
                    | BuiltinFunctionKind::ObjectDefineProperty
                    | BuiltinFunctionKind::ObjectGetOwnPropertyDescriptor
                    | BuiltinFunctionKind::ReflectDefineProperty,
                ..
            }) => Ok(None),
            Value::BuiltinFunction(builtin) => Ok(Some(FunctionObjectKey::Builtin(builtin.kind))),
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

    fn derived_constructor_metadata(
        &mut self,
        value: &Value,
    ) -> Result<(bool, bool, Value, crate::ifc_artifacts::Label), InterpreterError> {
        // Inspect derived-constructor flags on an ALREADY-materialized
        // prototype only. A function whose prototype has not been materialized
        // cannot have been registered as a derived constructor (registration
        // materializes it), so it is non-derived by construction. Materializing
        // the prototype here purely to read the flags is a non-transactional
        // heap side effect on paths that later refuse setup (e.g. a denied
        // rest-param allocation): the Construct dispatch probes derived-ness
        // before its call-setup snapshot, so a premature prototype allocation
        // survived rollback and regressed bd-ur3tk.9's "leaves setup unchanged"
        // (denied/malformed constructor rest) heap invariant.
        let Some(function_key) = self.function_prototype_key_for_value(value)? else {
            return Ok((
                false,
                false,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            ));
        };
        let Some(&prototype) = self.function_prototypes.get(&function_key) else {
            return Ok((
                false,
                false,
                Value::Undefined,
                crate::ifc_artifacts::Label::Public,
            ));
        };
        let object = self
            .heap
            .get(prototype.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: prototype.0 })?;
        Ok((
            object.is_derived_constructor,
            object.is_default_derived_constructor,
            object
                .derived_constructor_parent
                .clone()
                .unwrap_or(Value::Undefined),
            object
                .derived_constructor_parent_label
                .clone()
                .unwrap_or(crate::ifc_artifacts::Label::Public),
        ))
    }

    fn register_derived_constructor_metadata(
        &mut self,
        constructor: &Value,
        parent: Value,
        parent_label: crate::ifc_artifacts::Label,
        default_constructor: bool,
    ) -> Result<(), InterpreterError> {
        let snapshot = self.snapshot_call_setup(None, true);
        let mut previous_metadata = None;
        let mut previous_backing = None;
        let outcome = (|| -> Result<(), InterpreterError> {
            let backing = self.ensure_function_object(constructor)?.ok_or_else(|| {
                InterpreterError::TypeError {
                    expected: "constructor function".into(),
                    got: constructor.type_name().into(),
                }
            })?;
            let parent_backing = if matches!(parent, Value::Null) {
                None
            } else {
                Some(self.ensure_function_object(&parent)?.ok_or_else(|| {
                    InterpreterError::TypeError {
                        expected: "superclass constructor or null".into(),
                        got: parent.type_name().into(),
                    }
                })?)
            };
            let prototype = self
                .function_prototype_for_value(constructor)?
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "constructor prototype".into(),
                    got: constructor.type_name().into(),
                })?;
            let object = &self.heap[prototype.0 as usize];
            previous_metadata = Some((
                prototype,
                object.derived_constructor_parent.clone(),
                object.derived_constructor_parent_label.clone(),
                object.is_derived_constructor,
                object.is_default_derived_constructor,
            ));
            let object = &self.heap[backing.0 as usize];
            previous_backing = Some((
                backing,
                object.prototype,
                object.property_structure_label.clone(),
            ));
            // ClassDefinitionEvaluation links the constructor itself as well
            // as its instance prototype. Static inheritance and accessor
            // [[HomeObject]] super reads use this first link.
            self.join_descriptor_structure_label(backing, &parent_label)?;
            self.heap[backing.0 as usize].prototype = parent_backing;
            let object = &mut self.heap[prototype.0 as usize];
            object.derived_constructor_parent = Some(parent);
            object.derived_constructor_parent_label = Some(parent_label);
            object.is_derived_constructor = true;
            object.is_default_derived_constructor = default_constructor;
            self.sync_estimated_memory_bytes()?;
            Ok(())
        })();
        if let Err(error) = outcome {
            if let Some((prototype, parent, label, derived, default)) = previous_metadata {
                let object = &mut self.heap[prototype.0 as usize];
                object.derived_constructor_parent = parent;
                object.derived_constructor_parent_label = label;
                object.is_derived_constructor = derived;
                object.is_default_derived_constructor = default;
            }
            if let Some((backing, prototype, label)) = previous_backing {
                self.heap[backing.0 as usize].prototype = prototype;
                self.heap[backing.0 as usize].property_structure_label = label;
            }
            self.restore_call_setup(snapshot);
            return Err(error);
        }
        Ok(())
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

    /// Resolve a concise method's lexical `super` base from its private
    /// `[[HomeObject]]`. The object's current prototype is consulted at call
    /// time, so moving the method to another receiver does not retarget
    /// `super`.
    fn concise_method_super_binding(
        &self,
        callee: &Value,
    ) -> Result<Option<(Value, crate::ifc_artifacts::Label)>, InterpreterError> {
        let (Value::Closure(closure_id)
        | Value::AsyncFunction(closure_id)
        | Value::AsyncGeneratorFunction(closure_id)) = callee
        else {
            return Ok(None);
        };
        let Some(metadata) = self.closure_method_metadata.get(closure_id) else {
            return Ok(None);
        };
        let home = self.heap.get(metadata.home_object.0 as usize).ok_or(
            InterpreterError::ObjectNotFound {
                id: metadata.home_object.0,
            },
        )?;
        Ok(Some((
            home.prototype.map(Value::Object).unwrap_or(Value::Null),
            metadata
                .definition_label
                .join(&self.observe_property_structure(metadata.home_object, false)),
        )))
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
            return Some(js_int_to_value(value));
        }
        token.parse::<f64>().ok().map(js_number_to_value)
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
        self.array_null_prototypes
            .retain(|id| (id.0 as usize) < heap_len);
        self.function_null_prototypes
            .retain(|id| (id.0 as usize) < heap_len);
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
                core.take_execution_result(
                    LabeledReturn {
                        value: Value::Undefined,
                        label: crate::ifc_artifacts::Label::Public,
                    },
                    Some(requested_hook_action),
                )
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
                core.take_execution_result(
                    LabeledReturn {
                        value: Value::Undefined,
                        label: crate::ifc_artifacts::Label::Public,
                    },
                    Some(requested_hook_action),
                )
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

/// Exact-string entry point for `querystring.escape`/`stringify`. Node rejects
/// a component containing an unpaired UTF-16 surrogate instead of silently
/// replacing that unit before percent-encoding it.
fn node_qs_escape_js(input: &JsString) -> Result<String, InterpreterError> {
    let Some(input) = input.as_str() else {
        return Err(InterpreterError::TypeError {
            expected: "well-formed querystring component".to_string(),
            got: "string containing an unpaired UTF-16 surrogate".to_string(),
        });
    };
    Ok(node_qs_escape(input))
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
mod recordable_capability_tag_tests {
    use super::{
        CAPABILITY_TAG_DIGEST_PREFIX, CAPABILITY_TAG_RECORD_BYTE_CAP, ContentHash,
        recordable_capability_tag,
    };

    fn digest_marker(tag: &str) -> String {
        format!(
            "{CAPABILITY_TAG_DIGEST_PREFIX}{}>:",
            ContentHash::compute(tag.as_bytes()).to_hex()
        )
    }

    /// Ordinary short tags retain their exact serialized representation and
    /// do not allocate.
    #[test]
    fn recordable_tag_passthrough_for_short_tags() {
        let tag = "promise:resolve";
        let recorded = recordable_capability_tag(tag);
        assert_eq!(recorded.as_ref(), tag);
        assert!(matches!(recorded, std::borrow::Cow::Borrowed(_)));
    }

    /// Overlong tags remain bounded while committing their complete original
    /// bytes into the recorded representation.
    #[test]
    fn recordable_tag_hashes_and_truncates_overlong_tags() {
        let tag = "promise:".to_string() + &"X".repeat(CAPABILITY_TAG_RECORD_BYTE_CAP * 64);
        let marker = digest_marker(&tag);
        let recorded = recordable_capability_tag(&tag);

        assert!(recorded.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);
        assert!(recorded.starts_with(&marker));
        assert!(tag.starts_with(&recorded[marker.len()..]));
        assert!(matches!(recorded, std::borrow::Cow::Owned(_)));
    }

    /// The retained display prefix must stop on a UTF-8 character boundary.
    #[test]
    fn recordable_tag_truncation_respects_utf8_boundaries() {
        // U+1234 (ETHIOPIC SYLLABLE SEE) is 3 bytes in UTF-8 (E1 88 B4).
        let tag: String =
            std::iter::repeat_n('\u{1234}', CAPABILITY_TAG_RECORD_BYTE_CAP * 4).collect();
        let marker = digest_marker(&tag);
        let recorded = recordable_capability_tag(&tag);

        assert!(recorded.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);
        assert!(recorded.starts_with(&marker));
        assert!(tag.starts_with(&recorded[marker.len()..]));
    }

    /// Distinct complete tags with the same retained display prefix must
    /// remain distinct in decision logs and compression-sketch inputs.
    #[test]
    fn recordable_tag_digest_disambiguates_shared_long_prefix() {
        let shared = "X".repeat(CAPABILITY_TAG_RECORD_BYTE_CAP * 2);
        let first = format!("{shared}:first");
        let second = format!("{shared}:second");
        let first_marker = digest_marker(&first);
        let second_marker = digest_marker(&second);
        let first_recorded = recordable_capability_tag(&first);
        let second_recorded = recordable_capability_tag(&second);

        assert_ne!(first_marker, second_marker);
        assert_eq!(
            &first_recorded[first_marker.len()..],
            &second_recorded[second_marker.len()..]
        );
        assert_ne!(first_recorded, second_recorded);
    }

    /// An ordinary input equal to an encoded long-tag representation must be
    /// escaped rather than colliding with that long tag's identity.
    #[test]
    fn recordable_tag_reserved_prefix_cannot_impersonate_encoding() {
        let long_tag = "X".repeat(CAPABILITY_TAG_RECORD_BYTE_CAP * 2);
        let encoded_long = recordable_capability_tag(&long_tag).into_owned();
        assert!(encoded_long.starts_with(CAPABILITY_TAG_DIGEST_PREFIX));
        assert!(encoded_long.len() <= CAPABILITY_TAG_RECORD_BYTE_CAP);

        let escaped_short = recordable_capability_tag(&encoded_long);
        assert!(matches!(escaped_short, std::borrow::Cow::Owned(_)));
        assert_ne!(escaped_short.as_ref(), encoded_long);
        assert!(escaped_short.starts_with(&digest_marker(&encoded_long)));
    }
}

/// Regressions for transactional Promise-runtime memory accounting
/// (bd-ur3tk.21): PromiseStore records/witness, event-loop queues, combinator
/// trackers, and watcher vectors are charged eagerly at every mutation and
/// stay byte-equal to the recomputed estimate, with one-byte-short refusals
/// rolling every owner back.
#[cfg(test)]
mod promise_runtime_accounting_tests_bd_ur3tk_21 {
    use super::*;
    use crate::capability::RuntimeCapability;
    use crate::ifc_artifacts::Label;
    use crate::object_model::JsValue;
    use std::collections::BTreeSet;

    fn accounting_core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        InterpreterCore::new(config, "bd-ur3tk-21")
    }

    fn assert_eager_matches_recompute(core: &InterpreterCore, context: &str) {
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "eager estimate must equal recompute {context}"
        );
    }

    #[test]
    fn create_then_settle_drain_stay_byte_equal_bd_ur3tk_21() {
        let mut core = accounting_core();
        assert_eager_matches_recompute(&core, "on a fresh core");
        let baseline = core.estimated_memory_bytes();

        let promise = core.create_promise_accounted().expect("create fits");
        assert_eager_matches_recompute(&core, "after create");
        assert!(
            core.estimated_memory_bytes() > baseline,
            "the record and creation witness must be charged"
        );

        let derived = core
            .register_promise_then_accounted(promise, None, None, Label::Public)
            .expect("then fits");
        assert_eager_matches_recompute(&core, "after pending .then registration");

        core.fulfill_promise(
            promise,
            JsValue::Str("x".repeat(4096).into()),
            Label::Public,
        )
        .expect("fulfill fits");
        assert_eager_matches_recompute(&core, "after settlement with a 4KB payload");
        assert!(
            core.promise_store
                .get(derived)
                .expect("derived promise")
                .state
                == crate::promise_model::PromiseState::Pending,
            "derived promise settles only after the drain"
        );

        core.drain_microtasks(None)
            .expect("drain executes the identity reaction");
        assert_eager_matches_recompute(&core, "after drain + compact");
        assert!(
            core.promise_store
                .get(derived)
                .expect("derived promise")
                .state
                .is_settled(),
            "identity reaction must settle the derived promise"
        );
        assert_eq!(
            core.promise_in_flight_task_bytes, 0,
            "no in-flight transfer may survive the drain"
        );
    }

    #[test]
    fn settled_then_enqueues_transactionally_bd_ur3tk_21() {
        let mut core = accounting_core();
        let promise = core.create_promise_accounted().expect("create fits");
        core.fulfill_promise(promise, JsValue::Str("value".into()), Label::Public)
            .expect("fulfill fits");
        assert_eager_matches_recompute(&core, "after pre-settlement");

        // .then on an already-settled promise takes the immediate-enqueue path.
        core.register_promise_then_accounted(promise, None, None, Label::Public)
            .expect("settled then fits");
        assert_eager_matches_recompute(&core, "after settled-path .then");
        assert!(
            !core.event_loop.microtasks.is_empty(),
            "settled-path then must enqueue the reaction"
        );
    }

    #[test]
    fn one_byte_short_create_refuses_atomically_bd_ur3tk_21() {
        // Learn the exact growth of one create on a probe core.
        let mut probe = accounting_core();
        let before = probe.estimated_memory_bytes();
        probe.create_promise_accounted().expect("probe create");
        let growth = probe.estimated_memory_bytes() - before;
        assert!(growth > 0, "create must have a positive charge");

        let mut core = accounting_core();
        let baseline = core.estimated_memory_bytes();
        let record_count = core.promise_store.len();
        core.config.max_total_memory_bytes = baseline + growth - 1;
        let refusal = core.create_promise_accounted();
        assert!(
            matches!(refusal, Err(InterpreterError::MemoryBudgetExceeded { .. })),
            "one byte short must refuse: {refusal:?}"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            baseline,
            "a refused create must not leak charge"
        );
        assert_eq!(
            core.promise_store.len(),
            record_count,
            "a refused create must roll the fresh record back"
        );
        assert_eager_matches_recompute(&core, "after refused create");

        // The exact ceiling admits the same create.
        core.config.max_total_memory_bytes = baseline + growth;
        core.create_promise_accounted()
            .expect("exact ceiling must admit the create");
        assert_eager_matches_recompute(&core, "after exact-ceiling create");
    }

    #[test]
    fn refused_then_restores_store_and_queue_bd_ur3tk_21() {
        let mut core = accounting_core();
        let promise = core.create_promise_accounted().expect("create fits");
        assert_eager_matches_recompute(&core, "before clamped then");
        let baseline = core.estimated_memory_bytes();
        let record_count = core.promise_store.len();

        // No headroom at all: the derived promise + reaction slots must refuse
        // and restore the pre-registration store and queue exactly.
        core.config.max_total_memory_bytes = baseline;
        let refusal = core.register_promise_then_accounted(promise, None, None, Label::Public);
        assert!(
            matches!(refusal, Err(InterpreterError::MemoryBudgetExceeded { .. })),
            "clamped then must refuse: {refusal:?}"
        );
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(core.promise_store.len(), record_count);
        assert!(core.event_loop.microtasks.is_empty());
        assert_eager_matches_recompute(&core, "after refused then");
    }

    #[test]
    fn combinator_completion_stays_byte_equal_bd_ur3tk_21() {
        let mut core = accounting_core();
        let first = core.create_promise_accounted().expect("first input");
        let second = core.create_promise_accounted().expect("second input");
        let result = core.create_promise_accounted().expect("result promise");

        let combinator_id = core
            .register_combinator(LabeledPromiseCombinatorState {
                tracker: PromiseCombinatorState::All(crate::promise_model::PromiseAllTracker {
                    result_promise: result,
                    values: std::collections::BTreeMap::new(),
                    total: 2,
                    resolved_count: 0,
                    settled: false,
                }),
                accumulated_label: Label::Public,
            })
            .expect("combinator fits");
        core.add_combinator_watcher(
            first,
            PromiseCombinatorWatcher {
                combinator_id,
                index: 0,
            },
        )
        .expect("first watcher fits");
        core.add_combinator_watcher(
            second,
            PromiseCombinatorWatcher {
                combinator_id,
                index: 1,
            },
        )
        .expect("second watcher fits");
        assert_eager_matches_recompute(&core, "after combinator registration");

        core.fulfill_promise(first, JsValue::Str("a".repeat(512).into()), Label::Public)
            .expect("first fulfillment");
        assert_eager_matches_recompute(&core, "after first tracked fulfillment");

        core.fulfill_promise(second, JsValue::Str("b".repeat(512).into()), Label::Public)
            .expect("second fulfillment completes the aggregate");
        assert_eager_matches_recompute(&core, "after aggregate completion");
        assert!(
            core.promise_combinators.is_empty(),
            "a completed combinator must be removed"
        );
        assert!(
            core.promise_combinator_watchers.is_empty(),
            "settled inputs must release their watcher slots"
        );
        assert!(
            core.promise_store
                .get(result)
                .expect("result promise")
                .state
                .is_settled(),
            "aggregate result must settle"
        );
    }

    #[test]
    fn timer_schedule_and_idle_loop_stay_byte_equal_bd_ur3tk_21() {
        let mut core = accounting_core();
        // Schedule directly on the queue, then resynchronize — the loop's
        // turn/in-flight bookkeeping is what this test pins.
        core.event_loop
            .set_timeout(crate::closure_model::ClosureHandle(0), 0, Label::Public);
        core.sync_estimated_memory_bytes()
            .expect("resync after direct schedule");
        assert_eager_matches_recompute(&core, "after scheduled macrotask");

        let module = Ir3Module {
            header: crate::ir_contract::IrHeader {
                schema_version: crate::ir_contract::IrSchemaVersion::CURRENT,
                level: crate::ir_contract::IrLevel::Ir3,
                source_hash: None,
                source_label: "bd-ur3tk-21".to_string(),
            },
            instructions: vec![Ir3Instruction::Halt],
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
        };
        core.run_event_loop_until_idle(&module)
            .expect("idle loop drains the scheduled turn");
        assert_eq!(
            core.promise_in_flight_task_bytes, 0,
            "the in-flight transfer must be returned after the handler"
        );
        assert_eager_matches_recompute(&core, "after the event loop went idle");
    }
}

#[cfg(test)]
#[path = "baseline_interpreter/inline_tests.rs"]
mod tests;
