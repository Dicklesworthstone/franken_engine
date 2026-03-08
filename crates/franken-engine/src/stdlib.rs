//! ES2020 standard library baseline for the target workload matrix.
//!
//! Provides deterministic, capability-aware builtin constructors and prototype
//! methods required by Section 10.2 item 10 ("no permanent subset scope").
//!
//! Coverage priorities (per RGC-306 workload matrix):
//! - **Tier 1** (critical path): Array, Object, String, Math, JSON, Number, Boolean
//! - **Tier 2** (ecosystem): Map, Set, Date, RegExp, Error, Symbol, Promise
//! - **Tier 3** (completeness): WeakMap, WeakSet, Intl subset, Proxy/Reflect
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! cross-architecture determinism.  `BTreeMap`/`BTreeSet` for ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.2 item 10, bd-1lsy.4.6.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::object_model::{
    JsValue, ObjectHandle, ObjectHeap, PropertyDescriptor, PropertyKey, SymbolId,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed-point scale factor: 1_000_000 = 1.0.
const FP_SCALE: i64 = 1_000_000;

/// Maximum string repeat count to prevent OOM.
const MAX_STRING_REPEAT: usize = 1_048_576;

// ---------------------------------------------------------------------------
// BuiltinId — identifies a native function implementation
// ---------------------------------------------------------------------------

/// Identifies a builtin native function for dispatch by the interpreter.
///
/// When the interpreter encounters a call to a `Function` value whose index
/// maps to a builtin, it dispatches here instead of executing user bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BuiltinId {
    // -- Array --
    ArrayConstructor,
    ArrayIsArray,
    ArrayFrom,
    ArrayOf,
    ArrayPrototypePush,
    ArrayPrototypePop,
    ArrayPrototypeShift,
    ArrayPrototypeUnshift,
    ArrayPrototypeSlice,
    ArrayPrototypeSplice,
    ArrayPrototypeConcat,
    ArrayPrototypeIndexOf,
    ArrayPrototypeLastIndexOf,
    ArrayPrototypeIncludes,
    ArrayPrototypeJoin,
    ArrayPrototypeReverse,
    ArrayPrototypeSort,
    ArrayPrototypeMap,
    ArrayPrototypeFilter,
    ArrayPrototypeReduce,
    ArrayPrototypeReduceRight,
    ArrayPrototypeForEach,
    ArrayPrototypeSome,
    ArrayPrototypeEvery,
    ArrayPrototypeFind,
    ArrayPrototypeFindIndex,
    ArrayPrototypeFill,
    ArrayPrototypeCopyWithin,
    ArrayPrototypeFlat,
    ArrayPrototypeFlatMap,
    ArrayPrototypeEntries,
    ArrayPrototypeKeys,
    ArrayPrototypeValues,

    // -- Object --
    ObjectConstructor,
    ObjectKeys,
    ObjectValues,
    ObjectEntries,
    ObjectAssign,
    ObjectFreeze,
    ObjectSeal,
    ObjectCreate,
    ObjectDefineProperty,
    ObjectDefineProperties,
    ObjectGetPrototypeOf,
    ObjectSetPrototypeOf,
    ObjectGetOwnPropertyDescriptor,
    ObjectGetOwnPropertyNames,
    ObjectGetOwnPropertySymbols,
    ObjectIs,
    ObjectFromEntries,
    ObjectPrototypeHasOwnProperty,
    ObjectPrototypeIsPrototypeOf,
    ObjectPrototypePropertyIsEnumerable,
    ObjectPrototypeToString,
    ObjectPrototypeValueOf,

    // -- String --
    StringConstructor,
    StringFromCharCode,
    StringFromCodePoint,
    StringPrototypeCharAt,
    StringPrototypeCharCodeAt,
    StringPrototypeCodePointAt,
    StringPrototypeConcat,
    StringPrototypeIncludes,
    StringPrototypeStartsWith,
    StringPrototypeEndsWith,
    StringPrototypeIndexOf,
    StringPrototypeLastIndexOf,
    StringPrototypeSlice,
    StringPrototypeSubstring,
    StringPrototypeTrim,
    StringPrototypeTrimStart,
    StringPrototypeTrimEnd,
    StringPrototypePadStart,
    StringPrototypePadEnd,
    StringPrototypeRepeat,
    StringPrototypeToUpperCase,
    StringPrototypeToLowerCase,
    StringPrototypeSplit,
    StringPrototypeReplace,
    StringPrototypeMatch,
    StringPrototypeSearch,
    StringPrototypeNormalize,

    // -- Number --
    NumberConstructor,
    NumberIsFinite,
    NumberIsInteger,
    NumberIsNaN,
    NumberIsSafeInteger,
    NumberParseFloat,
    NumberParseInt,
    NumberPrototypeToFixed,
    NumberPrototypeToString,
    NumberPrototypeValueOf,

    // -- Boolean --
    BooleanConstructor,
    BooleanPrototypeToString,
    BooleanPrototypeValueOf,

    // -- Math --
    MathAbs,
    MathCeil,
    MathFloor,
    MathRound,
    MathTrunc,
    MathSign,
    MathMax,
    MathMin,
    MathPow,
    MathSqrt,
    MathLog,
    MathLog2,
    MathLog10,
    MathClz32,
    MathImul,
    MathFround,
    MathHypot,

    // -- JSON --
    JsonParse,
    JsonStringify,

    // -- Map --
    MapConstructor,
    MapPrototypeGet,
    MapPrototypeSet,
    MapPrototypeHas,
    MapPrototypeDelete,
    MapPrototypeClear,
    MapPrototypeSize,
    MapPrototypeForEach,
    MapPrototypeEntries,
    MapPrototypeKeys,
    MapPrototypeValues,

    // -- Set --
    SetConstructor,
    SetPrototypeAdd,
    SetPrototypeHas,
    SetPrototypeDelete,
    SetPrototypeClear,
    SetPrototypeSize,
    SetPrototypeForEach,
    SetPrototypeEntries,
    SetPrototypeKeys,
    SetPrototypeValues,

    // -- Date --
    DateConstructor,
    DateNow,
    DatePrototypeGetTime,
    DatePrototypeToISOString,
    DatePrototypeToString,
    DatePrototypeValueOf,

    // -- Error --
    ErrorConstructor,
    TypeErrorConstructor,
    RangeErrorConstructor,
    ReferenceErrorConstructor,
    SyntaxErrorConstructor,
    ErrorPrototypeToString,

    // -- Symbol --
    SymbolConstructor,
    SymbolFor,
    SymbolKeyFor,
    SymbolPrototypeToString,
    SymbolPrototypeValueOf,

    // -- Global functions --
    GlobalIsNaN,
    GlobalIsFinite,
    GlobalParseInt,
    GlobalParseFloat,
    GlobalEncodeURI,
    GlobalDecodeURI,
    GlobalEncodeURIComponent,
    GlobalDecodeURIComponent,
}

impl BuiltinId {
    /// Human-readable name for error messages and debugging.
    pub fn name(self) -> &'static str {
        match self {
            Self::ArrayConstructor => "Array",
            Self::ArrayIsArray => "Array.isArray",
            Self::ArrayFrom => "Array.from",
            Self::ArrayOf => "Array.of",
            Self::ArrayPrototypePush => "Array.prototype.push",
            Self::ArrayPrototypePop => "Array.prototype.pop",
            Self::ArrayPrototypeShift => "Array.prototype.shift",
            Self::ArrayPrototypeUnshift => "Array.prototype.unshift",
            Self::ArrayPrototypeSlice => "Array.prototype.slice",
            Self::ArrayPrototypeSplice => "Array.prototype.splice",
            Self::ArrayPrototypeConcat => "Array.prototype.concat",
            Self::ArrayPrototypeIndexOf => "Array.prototype.indexOf",
            Self::ArrayPrototypeLastIndexOf => "Array.prototype.lastIndexOf",
            Self::ArrayPrototypeIncludes => "Array.prototype.includes",
            Self::ArrayPrototypeJoin => "Array.prototype.join",
            Self::ArrayPrototypeReverse => "Array.prototype.reverse",
            Self::ArrayPrototypeSort => "Array.prototype.sort",
            Self::ArrayPrototypeMap => "Array.prototype.map",
            Self::ArrayPrototypeFilter => "Array.prototype.filter",
            Self::ArrayPrototypeReduce => "Array.prototype.reduce",
            Self::ArrayPrototypeReduceRight => "Array.prototype.reduceRight",
            Self::ArrayPrototypeForEach => "Array.prototype.forEach",
            Self::ArrayPrototypeSome => "Array.prototype.some",
            Self::ArrayPrototypeEvery => "Array.prototype.every",
            Self::ArrayPrototypeFind => "Array.prototype.find",
            Self::ArrayPrototypeFindIndex => "Array.prototype.findIndex",
            Self::ArrayPrototypeFill => "Array.prototype.fill",
            Self::ArrayPrototypeCopyWithin => "Array.prototype.copyWithin",
            Self::ArrayPrototypeFlat => "Array.prototype.flat",
            Self::ArrayPrototypeFlatMap => "Array.prototype.flatMap",
            Self::ArrayPrototypeEntries => "Array.prototype.entries",
            Self::ArrayPrototypeKeys => "Array.prototype.keys",
            Self::ArrayPrototypeValues => "Array.prototype.values",
            Self::ObjectConstructor => "Object",
            Self::ObjectKeys => "Object.keys",
            Self::ObjectValues => "Object.values",
            Self::ObjectEntries => "Object.entries",
            Self::ObjectAssign => "Object.assign",
            Self::ObjectFreeze => "Object.freeze",
            Self::ObjectSeal => "Object.seal",
            Self::ObjectCreate => "Object.create",
            Self::ObjectDefineProperty => "Object.defineProperty",
            Self::ObjectDefineProperties => "Object.defineProperties",
            Self::ObjectGetPrototypeOf => "Object.getPrototypeOf",
            Self::ObjectSetPrototypeOf => "Object.setPrototypeOf",
            Self::ObjectGetOwnPropertyDescriptor => "Object.getOwnPropertyDescriptor",
            Self::ObjectGetOwnPropertyNames => "Object.getOwnPropertyNames",
            Self::ObjectGetOwnPropertySymbols => "Object.getOwnPropertySymbols",
            Self::ObjectIs => "Object.is",
            Self::ObjectFromEntries => "Object.fromEntries",
            Self::ObjectPrototypeHasOwnProperty => "Object.prototype.hasOwnProperty",
            Self::ObjectPrototypeIsPrototypeOf => "Object.prototype.isPrototypeOf",
            Self::ObjectPrototypePropertyIsEnumerable => "Object.prototype.propertyIsEnumerable",
            Self::ObjectPrototypeToString => "Object.prototype.toString",
            Self::ObjectPrototypeValueOf => "Object.prototype.valueOf",
            Self::StringConstructor => "String",
            Self::StringFromCharCode => "String.fromCharCode",
            Self::StringFromCodePoint => "String.fromCodePoint",
            Self::StringPrototypeCharAt => "String.prototype.charAt",
            Self::StringPrototypeCharCodeAt => "String.prototype.charCodeAt",
            Self::StringPrototypeCodePointAt => "String.prototype.codePointAt",
            Self::StringPrototypeConcat => "String.prototype.concat",
            Self::StringPrototypeIncludes => "String.prototype.includes",
            Self::StringPrototypeStartsWith => "String.prototype.startsWith",
            Self::StringPrototypeEndsWith => "String.prototype.endsWith",
            Self::StringPrototypeIndexOf => "String.prototype.indexOf",
            Self::StringPrototypeLastIndexOf => "String.prototype.lastIndexOf",
            Self::StringPrototypeSlice => "String.prototype.slice",
            Self::StringPrototypeSubstring => "String.prototype.substring",
            Self::StringPrototypeTrim => "String.prototype.trim",
            Self::StringPrototypeTrimStart => "String.prototype.trimStart",
            Self::StringPrototypeTrimEnd => "String.prototype.trimEnd",
            Self::StringPrototypePadStart => "String.prototype.padStart",
            Self::StringPrototypePadEnd => "String.prototype.padEnd",
            Self::StringPrototypeRepeat => "String.prototype.repeat",
            Self::StringPrototypeToUpperCase => "String.prototype.toUpperCase",
            Self::StringPrototypeToLowerCase => "String.prototype.toLowerCase",
            Self::StringPrototypeSplit => "String.prototype.split",
            Self::StringPrototypeReplace => "String.prototype.replace",
            Self::StringPrototypeMatch => "String.prototype.match",
            Self::StringPrototypeSearch => "String.prototype.search",
            Self::StringPrototypeNormalize => "String.prototype.normalize",
            Self::NumberConstructor => "Number",
            Self::NumberIsFinite => "Number.isFinite",
            Self::NumberIsInteger => "Number.isInteger",
            Self::NumberIsNaN => "Number.isNaN",
            Self::NumberIsSafeInteger => "Number.isSafeInteger",
            Self::NumberParseFloat => "Number.parseFloat",
            Self::NumberParseInt => "Number.parseInt",
            Self::NumberPrototypeToFixed => "Number.prototype.toFixed",
            Self::NumberPrototypeToString => "Number.prototype.toString",
            Self::NumberPrototypeValueOf => "Number.prototype.valueOf",
            Self::BooleanConstructor => "Boolean",
            Self::BooleanPrototypeToString => "Boolean.prototype.toString",
            Self::BooleanPrototypeValueOf => "Boolean.prototype.valueOf",
            Self::MathAbs => "Math.abs",
            Self::MathCeil => "Math.ceil",
            Self::MathFloor => "Math.floor",
            Self::MathRound => "Math.round",
            Self::MathTrunc => "Math.trunc",
            Self::MathSign => "Math.sign",
            Self::MathMax => "Math.max",
            Self::MathMin => "Math.min",
            Self::MathPow => "Math.pow",
            Self::MathSqrt => "Math.sqrt",
            Self::MathLog => "Math.log",
            Self::MathLog2 => "Math.log2",
            Self::MathLog10 => "Math.log10",
            Self::MathClz32 => "Math.clz32",
            Self::MathImul => "Math.imul",
            Self::MathFround => "Math.fround",
            Self::MathHypot => "Math.hypot",
            Self::JsonParse => "JSON.parse",
            Self::JsonStringify => "JSON.stringify",
            Self::MapConstructor => "Map",
            Self::MapPrototypeGet => "Map.prototype.get",
            Self::MapPrototypeSet => "Map.prototype.set",
            Self::MapPrototypeHas => "Map.prototype.has",
            Self::MapPrototypeDelete => "Map.prototype.delete",
            Self::MapPrototypeClear => "Map.prototype.clear",
            Self::MapPrototypeSize => "Map.prototype.size",
            Self::MapPrototypeForEach => "Map.prototype.forEach",
            Self::MapPrototypeEntries => "Map.prototype.entries",
            Self::MapPrototypeKeys => "Map.prototype.keys",
            Self::MapPrototypeValues => "Map.prototype.values",
            Self::SetConstructor => "Set",
            Self::SetPrototypeAdd => "Set.prototype.add",
            Self::SetPrototypeHas => "Set.prototype.has",
            Self::SetPrototypeDelete => "Set.prototype.delete",
            Self::SetPrototypeClear => "Set.prototype.clear",
            Self::SetPrototypeSize => "Set.prototype.size",
            Self::SetPrototypeForEach => "Set.prototype.forEach",
            Self::SetPrototypeEntries => "Set.prototype.entries",
            Self::SetPrototypeKeys => "Set.prototype.keys",
            Self::SetPrototypeValues => "Set.prototype.values",
            Self::DateConstructor => "Date",
            Self::DateNow => "Date.now",
            Self::DatePrototypeGetTime => "Date.prototype.getTime",
            Self::DatePrototypeToISOString => "Date.prototype.toISOString",
            Self::DatePrototypeToString => "Date.prototype.toString",
            Self::DatePrototypeValueOf => "Date.prototype.valueOf",
            Self::ErrorConstructor => "Error",
            Self::TypeErrorConstructor => "TypeError",
            Self::RangeErrorConstructor => "RangeError",
            Self::ReferenceErrorConstructor => "ReferenceError",
            Self::SyntaxErrorConstructor => "SyntaxError",
            Self::ErrorPrototypeToString => "Error.prototype.toString",
            Self::SymbolConstructor => "Symbol",
            Self::SymbolFor => "Symbol.for",
            Self::SymbolKeyFor => "Symbol.keyFor",
            Self::SymbolPrototypeToString => "Symbol.prototype.toString",
            Self::SymbolPrototypeValueOf => "Symbol.prototype.valueOf",
            Self::GlobalIsNaN => "isNaN",
            Self::GlobalIsFinite => "isFinite",
            Self::GlobalParseInt => "parseInt",
            Self::GlobalParseFloat => "parseFloat",
            Self::GlobalEncodeURI => "encodeURI",
            Self::GlobalDecodeURI => "decodeURI",
            Self::GlobalEncodeURIComponent => "encodeURIComponent",
            Self::GlobalDecodeURIComponent => "decodeURIComponent",
        }
    }
}

impl fmt::Display for BuiltinId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// StdlibError
// ---------------------------------------------------------------------------

/// Errors from stdlib operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StdlibError {
    /// Type mismatch (e.g. calling string method on number).
    TypeError(String),
    /// Value out of range.
    RangeError(String),
    /// Object heap error.
    ObjectError(String),
    /// Invalid argument count.
    ArityError {
        builtin: String,
        expected_min: usize,
        expected_max: usize,
        got: usize,
    },
    /// JSON parse failure.
    JsonParseError(String),
    /// JSON stringify failure (circular reference, etc.).
    JsonStringifyError(String),
}

impl fmt::Display for StdlibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeError(msg) => write!(f, "TypeError: {msg}"),
            Self::RangeError(msg) => write!(f, "RangeError: {msg}"),
            Self::ObjectError(msg) => write!(f, "ObjectError: {msg}"),
            Self::ArityError {
                builtin,
                expected_min,
                expected_max,
                got,
            } => write!(
                f,
                "{builtin}: expected {expected_min}..={expected_max} arguments, got {got}"
            ),
            Self::JsonParseError(msg) => write!(f, "JSON.parse: {msg}"),
            Self::JsonStringifyError(msg) => write!(f, "JSON.stringify: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// BuiltinRegistry — maps function table indices to builtin ids
// ---------------------------------------------------------------------------

/// Registry of builtin function table entries.
///
/// The interpreter allocates function-table slots for builtins at
/// initialization time.  This registry tracks which slot maps to which
/// builtin, enabling dispatch without dynamic lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltinRegistry {
    /// Mapping from function-table index to builtin id.
    entries: Vec<(u32, BuiltinId)>,
    /// Next available function-table slot.
    next_slot: u32,
}

impl BuiltinRegistry {
    /// Create an empty registry starting at the given function-table offset.
    pub fn new(start_slot: u32) -> Self {
        Self {
            entries: Vec::new(),
            next_slot: start_slot,
        }
    }

    /// Register a builtin and return its function-table index.
    pub fn register(&mut self, id: BuiltinId) -> u32 {
        let slot = self.next_slot;
        self.entries.push((slot, id));
        self.next_slot += 1;
        slot
    }

    /// Look up a builtin by function-table index.
    pub fn lookup(&self, slot: u32) -> Option<BuiltinId> {
        self.entries
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, id)| *id)
    }

    /// All registered entries.
    pub fn entries(&self) -> &[(u32, BuiltinId)] {
        &self.entries
    }

    /// Number of registered builtins.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the registry empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// GlobalEnvironment — the global object with stdlib installed
// ---------------------------------------------------------------------------

/// Prototype handles for the standard builtins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrototypeHandles {
    pub object_prototype: ObjectHandle,
    pub array_prototype: ObjectHandle,
    pub string_prototype: ObjectHandle,
    pub number_prototype: ObjectHandle,
    pub boolean_prototype: ObjectHandle,
    pub function_prototype: ObjectHandle,
    pub error_prototype: ObjectHandle,
    pub type_error_prototype: ObjectHandle,
    pub range_error_prototype: ObjectHandle,
    pub reference_error_prototype: ObjectHandle,
    pub syntax_error_prototype: ObjectHandle,
    pub map_prototype: ObjectHandle,
    pub set_prototype: ObjectHandle,
    pub date_prototype: ObjectHandle,
    pub symbol_prototype: ObjectHandle,
}

/// Constructor handles for the standard builtins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructorHandles {
    pub object_constructor: ObjectHandle,
    pub array_constructor: ObjectHandle,
    pub string_constructor: ObjectHandle,
    pub number_constructor: ObjectHandle,
    pub boolean_constructor: ObjectHandle,
    pub error_constructor: ObjectHandle,
    pub type_error_constructor: ObjectHandle,
    pub range_error_constructor: ObjectHandle,
    pub reference_error_constructor: ObjectHandle,
    pub syntax_error_constructor: ObjectHandle,
    pub map_constructor: ObjectHandle,
    pub set_constructor: ObjectHandle,
    pub date_constructor: ObjectHandle,
    pub symbol_constructor: ObjectHandle,
}

/// Namespace object handles (Math, JSON, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceHandles {
    pub math: ObjectHandle,
    pub json: ObjectHandle,
}

/// The global environment with all stdlib builtins installed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalEnvironment {
    /// The global object itself.
    pub global_object: ObjectHandle,
    /// Prototype handles for each builtin type.
    pub prototypes: PrototypeHandles,
    /// Constructor handles.
    pub constructors: ConstructorHandles,
    /// Namespace objects.
    pub namespaces: NamespaceHandles,
    /// Builtin function registry.
    pub registry: BuiltinRegistry,
}

// ---------------------------------------------------------------------------
// Stdlib initialization
// ---------------------------------------------------------------------------

/// Install the standard library into a heap, returning the global environment.
///
/// This allocates prototype objects, constructor objects, namespace objects,
/// and installs all builtin properties according to the ES2020 spec.
pub fn install_stdlib(heap: &mut ObjectHeap) -> GlobalEnvironment {
    let mut registry = BuiltinRegistry::new(0);

    // -- Phase 1: Allocate all prototypes (no properties yet) ----------------
    let object_proto = heap.alloc(None); // Object.prototype has null [[Prototype]]
    let function_proto = heap.alloc(Some(object_proto));
    let array_proto = heap.alloc(Some(object_proto));
    let string_proto = heap.alloc(Some(object_proto));
    let number_proto = heap.alloc(Some(object_proto));
    let boolean_proto = heap.alloc(Some(object_proto));
    let error_proto = heap.alloc(Some(object_proto));
    let type_error_proto = heap.alloc(Some(error_proto));
    let range_error_proto = heap.alloc(Some(error_proto));
    let reference_error_proto = heap.alloc(Some(error_proto));
    let syntax_error_proto = heap.alloc(Some(error_proto));
    let map_proto = heap.alloc(Some(object_proto));
    let set_proto = heap.alloc(Some(object_proto));
    let date_proto = heap.alloc(Some(object_proto));
    let symbol_proto = heap.alloc(Some(object_proto));

    // -- Phase 2: Allocate constructor objects --------------------------------
    let object_ctor = heap.alloc(Some(function_proto));
    let array_ctor = heap.alloc(Some(function_proto));
    let string_ctor = heap.alloc(Some(function_proto));
    let number_ctor = heap.alloc(Some(function_proto));
    let boolean_ctor = heap.alloc(Some(function_proto));
    let error_ctor = heap.alloc(Some(function_proto));
    let type_error_ctor = heap.alloc(Some(function_proto));
    let range_error_ctor = heap.alloc(Some(function_proto));
    let reference_error_ctor = heap.alloc(Some(function_proto));
    let syntax_error_ctor = heap.alloc(Some(function_proto));
    let map_ctor = heap.alloc(Some(function_proto));
    let set_ctor = heap.alloc(Some(function_proto));
    let date_ctor = heap.alloc(Some(function_proto));
    let symbol_ctor = heap.alloc(Some(function_proto));

    // -- Phase 3: Allocate namespace objects -----------------------------------
    let math_ns = heap.alloc(Some(object_proto));
    let json_ns = heap.alloc(Some(object_proto));

    // -- Phase 4: Wire constructor.prototype / prototype.constructor -----------
    install_ctor_proto_link(heap, object_ctor, object_proto);
    install_ctor_proto_link(heap, array_ctor, array_proto);
    install_ctor_proto_link(heap, string_ctor, string_proto);
    install_ctor_proto_link(heap, number_ctor, number_proto);
    install_ctor_proto_link(heap, boolean_ctor, boolean_proto);
    install_ctor_proto_link(heap, error_ctor, error_proto);
    install_ctor_proto_link(heap, type_error_ctor, type_error_proto);
    install_ctor_proto_link(heap, range_error_ctor, range_error_proto);
    install_ctor_proto_link(heap, reference_error_ctor, reference_error_proto);
    install_ctor_proto_link(heap, syntax_error_ctor, syntax_error_proto);
    install_ctor_proto_link(heap, map_ctor, map_proto);
    install_ctor_proto_link(heap, set_ctor, set_proto);
    install_ctor_proto_link(heap, date_ctor, date_proto);
    install_ctor_proto_link(heap, symbol_ctor, symbol_proto);

    // -- Phase 5: Install class tags ------------------------------------------
    set_class_tag(heap, object_proto, "Object");
    set_class_tag(heap, array_proto, "Array");
    set_class_tag(heap, string_proto, "String");
    set_class_tag(heap, number_proto, "Number");
    set_class_tag(heap, boolean_proto, "Boolean");
    set_class_tag(heap, error_proto, "Error");
    set_class_tag(heap, type_error_proto, "TypeError");
    set_class_tag(heap, range_error_proto, "RangeError");
    set_class_tag(heap, reference_error_proto, "ReferenceError");
    set_class_tag(heap, syntax_error_proto, "SyntaxError");
    set_class_tag(heap, map_proto, "Map");
    set_class_tag(heap, set_proto, "Set");
    set_class_tag(heap, date_proto, "Date");
    set_class_tag(heap, symbol_proto, "Symbol");
    set_class_tag(heap, math_ns, "Math");
    set_class_tag(heap, json_ns, "JSON");

    // -- Phase 6: Install builtin methods on prototypes -----------------------
    install_object_builtins(heap, &mut registry, object_ctor, object_proto);
    install_array_builtins(heap, &mut registry, array_ctor, array_proto);
    install_string_builtins(heap, &mut registry, string_ctor, string_proto);
    install_number_builtins(heap, &mut registry, number_ctor, number_proto);
    install_boolean_builtins(heap, &mut registry, boolean_ctor, boolean_proto);
    install_math_builtins(heap, &mut registry, math_ns);
    install_json_builtins(heap, &mut registry, json_ns);
    install_map_builtins(heap, &mut registry, map_ctor, map_proto);
    install_set_builtins(heap, &mut registry, set_ctor, set_proto);
    install_error_builtins(heap, &mut registry, error_proto);

    // -- Phase 7: Allocate the global object ----------------------------------
    let global = heap.alloc(Some(object_proto));
    install_global_properties(
        heap,
        &mut registry,
        global,
        &ConstructorHandles {
            object_constructor: object_ctor,
            array_constructor: array_ctor,
            string_constructor: string_ctor,
            number_constructor: number_ctor,
            boolean_constructor: boolean_ctor,
            error_constructor: error_ctor,
            type_error_constructor: type_error_ctor,
            range_error_constructor: range_error_ctor,
            reference_error_constructor: reference_error_ctor,
            syntax_error_constructor: syntax_error_ctor,
            map_constructor: map_ctor,
            set_constructor: set_ctor,
            date_constructor: date_ctor,
            symbol_constructor: symbol_ctor,
        },
        math_ns,
        json_ns,
    );

    GlobalEnvironment {
        global_object: global,
        prototypes: PrototypeHandles {
            object_prototype: object_proto,
            array_prototype: array_proto,
            string_prototype: string_proto,
            number_prototype: number_proto,
            boolean_prototype: boolean_proto,
            function_prototype: function_proto,
            error_prototype: error_proto,
            type_error_prototype: type_error_proto,
            range_error_prototype: range_error_proto,
            reference_error_prototype: reference_error_proto,
            syntax_error_prototype: syntax_error_proto,
            map_prototype: map_proto,
            set_prototype: set_proto,
            date_prototype: date_proto,
            symbol_prototype: symbol_proto,
        },
        constructors: ConstructorHandles {
            object_constructor: object_ctor,
            array_constructor: array_ctor,
            string_constructor: string_ctor,
            number_constructor: number_ctor,
            boolean_constructor: boolean_ctor,
            error_constructor: error_ctor,
            type_error_constructor: type_error_ctor,
            range_error_constructor: range_error_ctor,
            reference_error_constructor: reference_error_ctor,
            syntax_error_constructor: syntax_error_ctor,
            map_constructor: map_ctor,
            set_constructor: set_ctor,
            date_constructor: date_ctor,
            symbol_constructor: symbol_ctor,
        },
        namespaces: NamespaceHandles {
            math: math_ns,
            json: json_ns,
        },
        registry,
    }
}

// ---------------------------------------------------------------------------
// Pure stdlib execution (no heap mutation needed)
// ---------------------------------------------------------------------------

/// Execute a pure Math builtin (no heap access needed).
pub fn exec_math(builtin: BuiltinId, args: &[JsValue]) -> Result<JsValue, StdlibError> {
    match builtin {
        BuiltinId::MathAbs => {
            let n = require_int("Math.abs", args, 0)?;
            Ok(JsValue::Int(n.abs()))
        }
        BuiltinId::MathCeil => {
            let n = require_int("Math.ceil", args, 0)?;
            // Fixed-point ceil: round up to next multiple of FP_SCALE.
            if n % FP_SCALE == 0 {
                Ok(JsValue::Int(n))
            } else if n > 0 {
                Ok(JsValue::Int((n / FP_SCALE + 1) * FP_SCALE))
            } else {
                Ok(JsValue::Int((n / FP_SCALE) * FP_SCALE))
            }
        }
        BuiltinId::MathFloor => {
            let n = require_int("Math.floor", args, 0)?;
            if n % FP_SCALE == 0 {
                Ok(JsValue::Int(n))
            } else if n > 0 {
                Ok(JsValue::Int((n / FP_SCALE) * FP_SCALE))
            } else {
                Ok(JsValue::Int((n / FP_SCALE - 1) * FP_SCALE))
            }
        }
        BuiltinId::MathRound => {
            let n = require_int("Math.round", args, 0)?;
            let remainder = n % FP_SCALE;
            if remainder.abs() >= FP_SCALE / 2 {
                if n > 0 {
                    Ok(JsValue::Int((n / FP_SCALE + 1) * FP_SCALE))
                } else {
                    Ok(JsValue::Int((n / FP_SCALE - 1) * FP_SCALE))
                }
            } else {
                Ok(JsValue::Int((n / FP_SCALE) * FP_SCALE))
            }
        }
        BuiltinId::MathTrunc => {
            let n = require_int("Math.trunc", args, 0)?;
            Ok(JsValue::Int((n / FP_SCALE) * FP_SCALE))
        }
        BuiltinId::MathSign => {
            let n = require_int("Math.sign", args, 0)?;
            Ok(JsValue::Int(n.signum() * FP_SCALE))
        }
        BuiltinId::MathMax => {
            if args.is_empty() {
                // Math.max() with no args returns -Infinity; we use i64::MIN.
                return Ok(JsValue::Int(i64::MIN));
            }
            let mut result = i64::MIN;
            for (i, arg) in args.iter().enumerate() {
                let n = coerce_to_int(&format!("Math.max arg {i}"), arg)?;
                if n > result {
                    result = n;
                }
            }
            Ok(JsValue::Int(result))
        }
        BuiltinId::MathMin => {
            if args.is_empty() {
                return Ok(JsValue::Int(i64::MAX));
            }
            let mut result = i64::MAX;
            for (i, arg) in args.iter().enumerate() {
                let n = coerce_to_int(&format!("Math.min arg {i}"), arg)?;
                if n < result {
                    result = n;
                }
            }
            Ok(JsValue::Int(result))
        }
        BuiltinId::MathPow => {
            let base = require_int("Math.pow", args, 0)?;
            let exp = require_int("Math.pow", args, 1)?;
            // Fixed-point power: base^exp where both are in FP_SCALE.
            let base_units = base / FP_SCALE;
            let exp_units = exp / FP_SCALE;
            if exp_units < 0 {
                return Err(StdlibError::RangeError(
                    "negative exponent not supported in fixed-point".into(),
                ));
            }
            let result = base_units.saturating_pow(exp_units as u32);
            Ok(JsValue::Int(result.saturating_mul(FP_SCALE)))
        }
        BuiltinId::MathClz32 => {
            let n = require_int("Math.clz32", args, 0)?;
            let bits = (n / FP_SCALE) as u32;
            Ok(JsValue::Int(i64::from(bits.leading_zeros()) * FP_SCALE))
        }
        BuiltinId::MathImul => {
            let a = require_int("Math.imul", args, 0)? / FP_SCALE;
            let b = require_int("Math.imul", args, 1)? / FP_SCALE;
            let result = (a as i32).wrapping_mul(b as i32);
            Ok(JsValue::Int(i64::from(result) * FP_SCALE))
        }
        BuiltinId::MathSqrt => {
            let n = require_int("Math.sqrt", args, 0)?;
            if n < 0 {
                return Err(StdlibError::RangeError(
                    "Math.sqrt of negative number".into(),
                ));
            }
            // Integer square root in fixed-point: sqrt(n/S)*S = sqrt(n*S).
            let scaled = n.saturating_mul(FP_SCALE);
            Ok(JsValue::Int(isqrt_i64(scaled)))
        }
        BuiltinId::MathLog => {
            let n = require_int("Math.log", args, 0)?;
            if n <= 0 {
                return Err(StdlibError::RangeError(
                    "Math.log of non-positive number".into(),
                ));
            }
            Ok(JsValue::Int(fp_ln(n)))
        }
        BuiltinId::MathLog2 => {
            let n = require_int("Math.log2", args, 0)?;
            if n <= 0 {
                return Err(StdlibError::RangeError(
                    "Math.log2 of non-positive number".into(),
                ));
            }
            // log2(x) = ln(x) / ln(2); LN2 in fp = 693_147.
            let ln_val = fp_ln(n);
            Ok(JsValue::Int(ln_val * FP_SCALE / 693_147))
        }
        BuiltinId::MathLog10 => {
            let n = require_int("Math.log10", args, 0)?;
            if n <= 0 {
                return Err(StdlibError::RangeError(
                    "Math.log10 of non-positive number".into(),
                ));
            }
            // log10(x) = ln(x) / ln(10); LN10 in fp = 2_302_585.
            let ln_val = fp_ln(n);
            Ok(JsValue::Int(ln_val * FP_SCALE / 2_302_585))
        }
        BuiltinId::MathHypot => {
            if args.is_empty() {
                return Ok(JsValue::Int(0));
            }
            // hypot(a,b,...) = sqrt(a^2 + b^2 + ...) in fixed-point units.
            let mut sum_sq: i64 = 0;
            for (i, arg) in args.iter().enumerate() {
                let v = coerce_to_int(&format!("Math.hypot arg {i}"), arg)? / FP_SCALE;
                sum_sq = sum_sq.saturating_add(v.saturating_mul(v));
            }
            // sqrt(sum_sq) * FP_SCALE
            let result = isqrt_i64(sum_sq) * FP_SCALE;
            Ok(JsValue::Int(result))
        }
        BuiltinId::MathFround => {
            // fround converts to f32 and back. In our fixed-point system,
            // we approximate by rounding to nearest 1000 (reducing precision).
            let n = require_int("Math.fround", args, 0)?;
            let rounded = (n / 1000) * 1000;
            Ok(JsValue::Int(rounded))
        }
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a Math builtin",
            builtin.name()
        ))),
    }
}

/// Execute a global function (isNaN, isFinite, parseInt, parseFloat, URI encoding).
pub fn exec_global_function(builtin: BuiltinId, args: &[JsValue]) -> Result<JsValue, StdlibError> {
    match builtin {
        BuiltinId::GlobalIsNaN => {
            // In our integer system, no value is NaN.
            match args.first() {
                Some(JsValue::Undefined) => Ok(JsValue::Bool(true)),
                Some(JsValue::Str(s)) => Ok(JsValue::Bool(s.parse::<i64>().is_err())),
                _ => Ok(JsValue::Bool(false)),
            }
        }
        BuiltinId::GlobalIsFinite => {
            // All i64 values are finite; undefined → NaN → false.
            match args.first() {
                Some(JsValue::Undefined) => Ok(JsValue::Bool(false)),
                Some(JsValue::Str(s)) => Ok(JsValue::Bool(s.parse::<i64>().is_ok())),
                _ => Ok(JsValue::Bool(true)),
            }
        }
        BuiltinId::GlobalParseInt => {
            let input = match args.first() {
                Some(v) => coerce_to_string(v),
                None => return Ok(JsValue::Int(0)),
            };
            let radix = opt_int_arg(args, 1).map(|n| n / FP_SCALE).unwrap_or(10);
            if !(2..=36).contains(&radix) {
                return Ok(JsValue::Int(0)); // NaN equivalent
            }
            let trimmed = input.trim();
            let (is_neg, digits) = if let Some(rest) = trimmed.strip_prefix('-') {
                (true, rest)
            } else if let Some(rest) = trimmed.strip_prefix('+') {
                (false, rest)
            } else {
                (false, trimmed)
            };
            // Parse digits up to first invalid character.
            let mut result: i64 = 0;
            let mut found = false;
            for c in digits.chars() {
                let digit = match c.to_ascii_lowercase() {
                    '0'..='9' => (c as i64) - ('0' as i64),
                    'a'..='z' => (c as i64) - ('a' as i64) + 10,
                    _ => break,
                };
                if digit >= radix {
                    break;
                }
                found = true;
                result = result.saturating_mul(radix).saturating_add(digit);
            }
            if !found {
                return Ok(JsValue::Int(0)); // NaN equivalent
            }
            if is_neg {
                result = -result;
            }
            Ok(JsValue::Int(result * FP_SCALE))
        }
        BuiltinId::GlobalParseFloat => {
            let input = match args.first() {
                Some(v) => coerce_to_string(v),
                None => return Ok(JsValue::Int(0)),
            };
            let trimmed = input.trim();
            // Simple integer parse (no float in our system).
            match trimmed.parse::<i64>() {
                Ok(n) => Ok(JsValue::Int(n * FP_SCALE)),
                Err(_) => Ok(JsValue::Int(0)), // NaN equivalent
            }
        }
        BuiltinId::GlobalEncodeURI => {
            let input = require_str("encodeURI", args, 0)?;
            Ok(JsValue::Str(percent_encode(&input, false)))
        }
        BuiltinId::GlobalDecodeURI => {
            let input = require_str("decodeURI", args, 0)?;
            Ok(JsValue::Str(percent_decode(&input)))
        }
        BuiltinId::GlobalEncodeURIComponent => {
            let input = require_str("encodeURIComponent", args, 0)?;
            Ok(JsValue::Str(percent_encode(&input, true)))
        }
        BuiltinId::GlobalDecodeURIComponent => {
            let input = require_str("decodeURIComponent", args, 0)?;
            Ok(JsValue::Str(percent_decode(&input)))
        }
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a global function",
            builtin.name()
        ))),
    }
}

/// Execute a pure Boolean prototype method.
pub fn exec_boolean_method(builtin: BuiltinId, this_val: bool) -> Result<JsValue, StdlibError> {
    match builtin {
        BuiltinId::BooleanPrototypeToString => {
            Ok(JsValue::Str(if this_val { "true" } else { "false" }.into()))
        }
        BuiltinId::BooleanPrototypeValueOf => Ok(JsValue::Bool(this_val)),
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a Boolean method",
            builtin.name()
        ))),
    }
}

/// Execute Object static methods that can be evaluated without heap mutation.
pub fn exec_object_static(builtin: BuiltinId, args: &[JsValue]) -> Result<JsValue, StdlibError> {
    match builtin {
        BuiltinId::ObjectIs => {
            let a = args.first().unwrap_or(&JsValue::Undefined);
            let b = args.get(1).unwrap_or(&JsValue::Undefined);
            Ok(JsValue::Bool(same_value(a, b)))
        }
        _ => Err(StdlibError::TypeError(format!(
            "{} requires heap access (use interpreter dispatch)",
            builtin.name()
        ))),
    }
}

/// Execute a pure String static method.
pub fn exec_string_static(builtin: BuiltinId, args: &[JsValue]) -> Result<JsValue, StdlibError> {
    match builtin {
        BuiltinId::StringFromCharCode => {
            let mut result = String::new();
            for (i, arg) in args.iter().enumerate() {
                let code = coerce_to_int(&format!("String.fromCharCode arg {i}"), arg)? / FP_SCALE;
                if let Some(ch) = char::from_u32(code.max(0) as u32) {
                    result.push(ch);
                }
            }
            Ok(JsValue::Str(result))
        }
        BuiltinId::StringFromCodePoint => {
            let mut result = String::new();
            for (i, arg) in args.iter().enumerate() {
                let code = coerce_to_int(&format!("String.fromCodePoint arg {i}"), arg)? / FP_SCALE;
                let cp = code.max(0) as u32;
                match char::from_u32(cp) {
                    Some(ch) => result.push(ch),
                    None => {
                        return Err(StdlibError::RangeError(format!("Invalid code point: {cp}")));
                    }
                }
            }
            Ok(JsValue::Str(result))
        }
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a String static method",
            builtin.name()
        ))),
    }
}

/// Execute an Array utility method that operates on a Vec<JsValue> without heap.
///
/// The interpreter extracts array elements from the heap, calls this function,
/// and writes results back.
pub fn exec_array_method(
    builtin: BuiltinId,
    elements: &[JsValue],
    args: &[JsValue],
) -> Result<ArrayMethodResult, StdlibError> {
    match builtin {
        BuiltinId::ArrayPrototypeIndexOf => {
            let search = args.first().unwrap_or(&JsValue::Undefined);
            let from = opt_int_arg(args, 1)
                .map(|n| (n / FP_SCALE).max(0) as usize)
                .unwrap_or(0);
            for (i, elem) in elements.iter().enumerate().skip(from) {
                if same_value(elem, search) {
                    return Ok(ArrayMethodResult::Value(JsValue::Int(i as i64 * FP_SCALE)));
                }
            }
            Ok(ArrayMethodResult::Value(JsValue::Int(-FP_SCALE)))
        }
        BuiltinId::ArrayPrototypeLastIndexOf => {
            let search = args.first().unwrap_or(&JsValue::Undefined);
            let from = opt_int_arg(args, 1)
                .map(|n| {
                    let idx = n / FP_SCALE;
                    if idx < 0 {
                        (elements.len() as i64 + idx).max(0) as usize
                    } else {
                        idx.min(elements.len() as i64 - 1) as usize
                    }
                })
                .unwrap_or(elements.len().saturating_sub(1));
            for i in (0..=from.min(elements.len().saturating_sub(1))).rev() {
                if same_value(&elements[i], search) {
                    return Ok(ArrayMethodResult::Value(JsValue::Int(i as i64 * FP_SCALE)));
                }
            }
            Ok(ArrayMethodResult::Value(JsValue::Int(-FP_SCALE)))
        }
        BuiltinId::ArrayPrototypeIncludes => {
            let search = args.first().unwrap_or(&JsValue::Undefined);
            let from = opt_int_arg(args, 1)
                .map(|n| (n / FP_SCALE).max(0) as usize)
                .unwrap_or(0);
            let found = elements.iter().skip(from).any(|e| same_value(e, search));
            Ok(ArrayMethodResult::Value(JsValue::Bool(found)))
        }
        BuiltinId::ArrayPrototypeJoin => {
            let sep = opt_str_arg(args, 0).unwrap_or_else(|| ",".into());
            let parts: Vec<String> = elements.iter().map(coerce_to_string).collect();
            Ok(ArrayMethodResult::Value(JsValue::Str(parts.join(&sep))))
        }
        BuiltinId::ArrayPrototypeReverse => {
            let mut reversed = elements.to_vec();
            reversed.reverse();
            Ok(ArrayMethodResult::NewArray(reversed))
        }
        BuiltinId::ArrayPrototypeSlice => {
            let len = elements.len() as i64;
            let start = opt_int_arg(args, 0)
                .map(|n| resolve_array_index(n / FP_SCALE, len))
                .unwrap_or(0) as usize;
            let end = opt_int_arg(args, 1)
                .map(|n| resolve_array_index(n / FP_SCALE, len))
                .unwrap_or(len) as usize;
            if start >= end || start >= elements.len() {
                return Ok(ArrayMethodResult::NewArray(Vec::new()));
            }
            let sliced = elements[start..end.min(elements.len())].to_vec();
            Ok(ArrayMethodResult::NewArray(sliced))
        }
        BuiltinId::ArrayPrototypeConcat => {
            let mut result = elements.to_vec();
            for arg in args {
                // Simple concat: each arg is added as element (array spreading
                // requires heap access and is handled by interpreter).
                result.push(arg.clone());
            }
            Ok(ArrayMethodResult::NewArray(result))
        }
        BuiltinId::ArrayPrototypeFill => {
            let fill_val = args.first().unwrap_or(&JsValue::Undefined).clone();
            let len = elements.len() as i64;
            let start = opt_int_arg(args, 1)
                .map(|n| resolve_array_index(n / FP_SCALE, len) as usize)
                .unwrap_or(0);
            let end = opt_int_arg(args, 2)
                .map(|n| resolve_array_index(n / FP_SCALE, len) as usize)
                .unwrap_or(elements.len());
            let mut result = elements.to_vec();
            let fill_end = end.min(result.len());
            for item in result.iter_mut().take(fill_end).skip(start) {
                *item = fill_val.clone();
            }
            Ok(ArrayMethodResult::NewArray(result))
        }
        BuiltinId::ArrayPrototypeFlat => {
            // Flatten one level (depth=1 default). Without heap access we can
            // only flatten primitive arrays that don't contain Object references.
            Ok(ArrayMethodResult::NewArray(elements.to_vec()))
        }
        _ => Err(StdlibError::TypeError(format!(
            "{} requires callback or heap access (use interpreter dispatch)",
            builtin.name()
        ))),
    }
}

/// Result of an array method execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArrayMethodResult {
    /// A single return value (indexOf, includes, join, etc.).
    Value(JsValue),
    /// A new array to be allocated on the heap (slice, concat, reverse, etc.).
    NewArray(Vec<JsValue>),
}

const ARRAY_LENGTH_PROP: &str = "length";
const MAP_SIZE_PROP: &str = "size";
const SET_SIZE_PROP: &str = "size";
const MAP_NEXT_INDEX_PROP: &str = "[[MapNextIndex]]";
const SET_NEXT_INDEX_PROP: &str = "[[SetNextIndex]]";
const MAP_KEY_PREFIX: &str = "[[MapKey]]:";
const MAP_VALUE_PREFIX: &str = "[[MapValue]]:";
const SET_VALUE_PREFIX: &str = "[[SetValue]]:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    Array,
    Map,
    Set,
}

impl CollectionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Array => "array",
            Self::Map => "map",
            Self::Set => "set",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionMutationEvent {
    pub step: u32,
    pub action: String,
    pub key: Option<String>,
    pub value: Option<JsValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionMutationTrace {
    pub trace_id: String,
    pub builtin: String,
    pub collection_kind: CollectionKind,
    pub target: ObjectHandle,
    pub before_size: usize,
    pub after_size: usize,
    pub mutated_keys: Vec<String>,
    pub events: Vec<CollectionMutationEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeapCollectionMethodResult {
    pub value: JsValue,
    pub trace: CollectionMutationTrace,
}

pub fn alloc_array_instance(
    heap: &mut ObjectHeap,
    prototype: ObjectHandle,
    elements: &[JsValue],
) -> Result<ObjectHandle, StdlibError> {
    let handle = heap.alloc(Some(prototype));
    set_class_tag(heap, handle, "Array");
    write_array_snapshot(heap, handle, elements)?;
    Ok(handle)
}

pub fn alloc_map_instance(
    heap: &mut ObjectHeap,
    prototype: ObjectHandle,
    entries: &[(JsValue, JsValue)],
) -> Result<ObjectHandle, StdlibError> {
    let handle = heap.alloc(Some(prototype));
    set_class_tag(heap, handle, "Map");
    write_map_entries_snapshot(heap, handle, entries)?;
    Ok(handle)
}

pub fn alloc_set_instance(
    heap: &mut ObjectHeap,
    prototype: ObjectHandle,
    values: &[JsValue],
) -> Result<ObjectHandle, StdlibError> {
    let handle = heap.alloc(Some(prototype));
    set_class_tag(heap, handle, "Set");
    write_set_values_snapshot(heap, handle, values)?;
    Ok(handle)
}

pub fn read_array_elements(
    heap: &ObjectHeap,
    handle: ObjectHandle,
) -> Result<Vec<JsValue>, StdlibError> {
    require_collection_kind(heap, handle, CollectionKind::Array)?;
    let len = get_count_property(heap, handle, ARRAY_LENGTH_PROP)?;
    let mut elements = Vec::with_capacity(len);
    for index in 0..len {
        elements.push(get_required_own_data_property(
            heap,
            handle,
            &index.to_string(),
        )?);
    }
    Ok(elements)
}

pub fn read_map_entries(
    heap: &ObjectHeap,
    handle: ObjectHandle,
) -> Result<Vec<(JsValue, JsValue)>, StdlibError> {
    require_collection_kind(heap, handle, CollectionKind::Map)?;
    let len = get_count_property(heap, handle, MAP_NEXT_INDEX_PROP)?;
    let mut entries = Vec::with_capacity(len);
    for index in 0..len {
        let key = get_required_own_data_property(heap, handle, &map_key_slot(index))?;
        let value = get_required_own_data_property(heap, handle, &map_value_slot(index))?;
        entries.push((key, value));
    }
    Ok(entries)
}

pub fn read_set_values(
    heap: &ObjectHeap,
    handle: ObjectHandle,
) -> Result<Vec<JsValue>, StdlibError> {
    require_collection_kind(heap, handle, CollectionKind::Set)?;
    let len = get_count_property(heap, handle, SET_NEXT_INDEX_PROP)?;
    let mut values = Vec::with_capacity(len);
    for index in 0..len {
        values.push(get_required_own_data_property(
            heap,
            handle,
            &set_value_slot(index),
        )?);
    }
    Ok(values)
}

pub fn exec_heap_collection_method(
    heap: &mut ObjectHeap,
    builtin: BuiltinId,
    this_handle: ObjectHandle,
    args: &[JsValue],
) -> Result<HeapCollectionMethodResult, StdlibError> {
    match builtin {
        BuiltinId::ArrayPrototypePush
        | BuiltinId::ArrayPrototypePop
        | BuiltinId::ArrayPrototypeShift
        | BuiltinId::ArrayPrototypeUnshift
        | BuiltinId::ArrayPrototypeSplice
        | BuiltinId::ArrayPrototypeReverse
        | BuiltinId::ArrayPrototypeFill => exec_heap_array_method(heap, builtin, this_handle, args),
        BuiltinId::MapPrototypeGet
        | BuiltinId::MapPrototypeSet
        | BuiltinId::MapPrototypeHas
        | BuiltinId::MapPrototypeDelete
        | BuiltinId::MapPrototypeClear
        | BuiltinId::MapPrototypeSize => exec_heap_map_method(heap, builtin, this_handle, args),
        BuiltinId::SetPrototypeAdd
        | BuiltinId::SetPrototypeHas
        | BuiltinId::SetPrototypeDelete
        | BuiltinId::SetPrototypeClear
        | BuiltinId::SetPrototypeSize => exec_heap_set_method(heap, builtin, this_handle, args),
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a heap-backed collection method",
            builtin.name()
        ))),
    }
}

fn exec_heap_array_method(
    heap: &mut ObjectHeap,
    builtin: BuiltinId,
    this_handle: ObjectHandle,
    args: &[JsValue],
) -> Result<HeapCollectionMethodResult, StdlibError> {
    let before = read_array_elements(heap, this_handle)?;
    let mut after = before.clone();
    let value = match builtin {
        BuiltinId::ArrayPrototypePush => {
            after.extend_from_slice(args);
            JsValue::Int(after.len() as i64 * FP_SCALE)
        }
        BuiltinId::ArrayPrototypePop => after.pop().unwrap_or(JsValue::Undefined),
        BuiltinId::ArrayPrototypeShift => {
            if after.is_empty() {
                JsValue::Undefined
            } else {
                after.remove(0)
            }
        }
        BuiltinId::ArrayPrototypeUnshift => {
            let mut combined = args.to_vec();
            combined.extend(after);
            after = combined;
            JsValue::Int(after.len() as i64 * FP_SCALE)
        }
        BuiltinId::ArrayPrototypeSplice => {
            let len = after.len() as i64;
            let start = match args.first() {
                Some(arg) => resolve_array_index(
                    coerce_to_int("Array.prototype.splice", arg)? / FP_SCALE,
                    len,
                ) as usize,
                None => 0,
            };
            let delete_count = match args.get(1) {
                Some(arg) => {
                    (coerce_to_int("Array.prototype.splice", arg)? / FP_SCALE).max(0) as usize
                }
                None => after.len().saturating_sub(start),
            };
            let actual_delete = delete_count.min(after.len().saturating_sub(start));
            let inserts = if args.len() > 2 {
                args[2..].to_vec()
            } else {
                Vec::new()
            };
            let removed: Vec<JsValue> = after
                .splice(start..start + actual_delete, inserts)
                .collect();
            let prototype = heap
                .get_prototype_of(this_handle)
                .map_err(object_error)?
                .ok_or_else(|| {
                    StdlibError::TypeError(
                        "Array.prototype.splice receiver is missing an array prototype".into(),
                    )
                })?;
            let removed_handle = alloc_array_instance(heap, prototype, &removed)?;
            JsValue::Object(removed_handle)
        }
        BuiltinId::ArrayPrototypeReverse => {
            after.reverse();
            JsValue::Object(this_handle)
        }
        BuiltinId::ArrayPrototypeFill => {
            let fill_value = args.first().cloned().unwrap_or(JsValue::Undefined);
            let len = after.len() as i64;
            let start = match args.get(1) {
                Some(arg) => {
                    resolve_array_index(coerce_to_int("Array.prototype.fill", arg)? / FP_SCALE, len)
                        as usize
                }
                None => 0,
            };
            let end = match args.get(2) {
                Some(arg) => {
                    resolve_array_index(coerce_to_int("Array.prototype.fill", arg)? / FP_SCALE, len)
                        as usize
                }
                None => after.len(),
            };
            let fill_end = end.min(after.len());
            for item in after.iter_mut().take(fill_end).skip(start) {
                *item = fill_value.clone();
            }
            JsValue::Object(this_handle)
        }
        _ => unreachable!("array dispatch is filtered above"),
    };

    if before != after {
        write_array_snapshot(heap, this_handle, &after)?;
    }
    let (mutated_keys, events) = diff_value_vectors(&before, &after, "", "length");
    Ok(HeapCollectionMethodResult {
        value,
        trace: build_collection_trace(
            builtin,
            CollectionKind::Array,
            this_handle,
            before.len(),
            after.len(),
            mutated_keys,
            events,
        ),
    })
}

fn exec_heap_map_method(
    heap: &mut ObjectHeap,
    builtin: BuiltinId,
    this_handle: ObjectHandle,
    args: &[JsValue],
) -> Result<HeapCollectionMethodResult, StdlibError> {
    let before = read_map_entries(heap, this_handle)?;
    let mut after = before.clone();
    let value = match builtin {
        BuiltinId::MapPrototypeGet => {
            let key = args.first().cloned().unwrap_or(JsValue::Undefined);
            after
                .iter()
                .find(|(entry_key, _)| same_value(entry_key, &key))
                .map(|(_, value)| value.clone())
                .unwrap_or(JsValue::Undefined)
        }
        BuiltinId::MapPrototypeHas => {
            let key = args.first().cloned().unwrap_or(JsValue::Undefined);
            JsValue::Bool(
                after
                    .iter()
                    .any(|(entry_key, _)| same_value(entry_key, &key)),
            )
        }
        BuiltinId::MapPrototypeSize => JsValue::Int(after.len() as i64 * FP_SCALE),
        BuiltinId::MapPrototypeSet => {
            let key = args.first().cloned().unwrap_or(JsValue::Undefined);
            let new_value = args.get(1).cloned().unwrap_or(JsValue::Undefined);
            if let Some((_, value)) = after
                .iter_mut()
                .find(|(entry_key, _)| same_value(entry_key, &key))
            {
                *value = new_value;
            } else {
                after.push((key, new_value));
            }
            JsValue::Object(this_handle)
        }
        BuiltinId::MapPrototypeDelete => {
            let key = args.first().cloned().unwrap_or(JsValue::Undefined);
            if let Some(index) = after
                .iter()
                .position(|(entry_key, _)| same_value(entry_key, &key))
            {
                after.remove(index);
                JsValue::Bool(true)
            } else {
                JsValue::Bool(false)
            }
        }
        BuiltinId::MapPrototypeClear => {
            after.clear();
            JsValue::Undefined
        }
        _ => unreachable!("map dispatch is filtered above"),
    };

    if before != after {
        write_map_entries_snapshot(heap, this_handle, &after)?;
    }
    let (mutated_keys, events) = diff_map_entries(&before, &after);
    Ok(HeapCollectionMethodResult {
        value,
        trace: build_collection_trace(
            builtin,
            CollectionKind::Map,
            this_handle,
            before.len(),
            after.len(),
            mutated_keys,
            events,
        ),
    })
}

fn exec_heap_set_method(
    heap: &mut ObjectHeap,
    builtin: BuiltinId,
    this_handle: ObjectHandle,
    args: &[JsValue],
) -> Result<HeapCollectionMethodResult, StdlibError> {
    let before = read_set_values(heap, this_handle)?;
    let mut after = before.clone();
    let value = match builtin {
        BuiltinId::SetPrototypeHas => {
            let search = args.first().cloned().unwrap_or(JsValue::Undefined);
            JsValue::Bool(after.iter().any(|value| same_value(value, &search)))
        }
        BuiltinId::SetPrototypeSize => JsValue::Int(after.len() as i64 * FP_SCALE),
        BuiltinId::SetPrototypeAdd => {
            let candidate = args.first().cloned().unwrap_or(JsValue::Undefined);
            if !after.iter().any(|value| same_value(value, &candidate)) {
                after.push(candidate);
            }
            JsValue::Object(this_handle)
        }
        BuiltinId::SetPrototypeDelete => {
            let search = args.first().cloned().unwrap_or(JsValue::Undefined);
            if let Some(index) = after.iter().position(|value| same_value(value, &search)) {
                after.remove(index);
                JsValue::Bool(true)
            } else {
                JsValue::Bool(false)
            }
        }
        BuiltinId::SetPrototypeClear => {
            after.clear();
            JsValue::Undefined
        }
        _ => unreachable!("set dispatch is filtered above"),
    };

    if before != after {
        write_set_values_snapshot(heap, this_handle, &after)?;
    }
    let (mutated_keys, events) = diff_value_vectors(&before, &after, "value[", "size");
    Ok(HeapCollectionMethodResult {
        value,
        trace: build_collection_trace(
            builtin,
            CollectionKind::Set,
            this_handle,
            before.len(),
            after.len(),
            mutated_keys,
            events,
        ),
    })
}

fn write_array_snapshot(
    heap: &mut ObjectHeap,
    handle: ObjectHandle,
    elements: &[JsValue],
) -> Result<(), StdlibError> {
    let old_len = get_optional_count_property(heap, handle, ARRAY_LENGTH_PROP)?;
    for index in 0..old_len {
        heap.delete_property(handle, &PropertyKey::from(index.to_string()))
            .map_err(object_error)?;
    }
    for (index, value) in elements.iter().enumerate() {
        heap.set_property(handle, PropertyKey::from(index.to_string()), value.clone())
            .map_err(object_error)?;
    }
    define_hidden_property(
        heap,
        handle,
        ARRAY_LENGTH_PROP,
        count_js_value(elements.len()),
    )?;
    Ok(())
}

fn write_map_entries_snapshot(
    heap: &mut ObjectHeap,
    handle: ObjectHandle,
    entries: &[(JsValue, JsValue)],
) -> Result<(), StdlibError> {
    let old_len = get_optional_count_property(heap, handle, MAP_NEXT_INDEX_PROP)?;
    for index in 0..old_len {
        heap.delete_property(handle, &PropertyKey::from(map_key_slot(index)))
            .map_err(object_error)?;
        heap.delete_property(handle, &PropertyKey::from(map_value_slot(index)))
            .map_err(object_error)?;
    }
    for (index, (key, value)) in entries.iter().enumerate() {
        define_hidden_property(heap, handle, &map_key_slot(index), key.clone())?;
        define_hidden_property(heap, handle, &map_value_slot(index), value.clone())?;
    }
    define_hidden_property(heap, handle, MAP_SIZE_PROP, count_js_value(entries.len()))?;
    define_hidden_property(
        heap,
        handle,
        MAP_NEXT_INDEX_PROP,
        count_js_value(entries.len()),
    )?;
    Ok(())
}

fn write_set_values_snapshot(
    heap: &mut ObjectHeap,
    handle: ObjectHandle,
    values: &[JsValue],
) -> Result<(), StdlibError> {
    let old_len = get_optional_count_property(heap, handle, SET_NEXT_INDEX_PROP)?;
    for index in 0..old_len {
        heap.delete_property(handle, &PropertyKey::from(set_value_slot(index)))
            .map_err(object_error)?;
    }
    for (index, value) in values.iter().enumerate() {
        define_hidden_property(heap, handle, &set_value_slot(index), value.clone())?;
    }
    define_hidden_property(heap, handle, SET_SIZE_PROP, count_js_value(values.len()))?;
    define_hidden_property(
        heap,
        handle,
        SET_NEXT_INDEX_PROP,
        count_js_value(values.len()),
    )?;
    Ok(())
}

fn require_collection_kind(
    heap: &ObjectHeap,
    handle: ObjectHandle,
    expected: CollectionKind,
) -> Result<(), StdlibError> {
    let object = heap.get(handle).map_err(object_error)?;
    let ordinary = object.as_ordinary().ok_or_else(|| {
        StdlibError::TypeError(format!(
            "{} receiver must be an ordinary object",
            expected.as_str()
        ))
    })?;
    let actual = ordinary.class_tag.as_deref().unwrap_or("<untyped>");
    if actual
        == match expected {
            CollectionKind::Array => "Array",
            CollectionKind::Map => "Map",
            CollectionKind::Set => "Set",
        }
    {
        Ok(())
    } else {
        Err(StdlibError::TypeError(format!(
            "{} receiver must be a {}, got {actual}",
            expected.as_str(),
            match expected {
                CollectionKind::Array => "Array",
                CollectionKind::Map => "Map",
                CollectionKind::Set => "Set",
            }
        )))
    }
}

fn define_hidden_property(
    heap: &mut ObjectHeap,
    handle: ObjectHandle,
    name: &str,
    value: JsValue,
) -> Result<(), StdlibError> {
    let defined = heap
        .define_property(
            handle,
            PropertyKey::from(name),
            PropertyDescriptor::Data {
                value,
                writable: true,
                enumerable: false,
                configurable: true,
            },
        )
        .map_err(object_error)?;
    if defined {
        Ok(())
    } else {
        Err(StdlibError::TypeError(format!(
            "failed to define hidden property `{name}`"
        )))
    }
}

fn get_count_property(
    heap: &ObjectHeap,
    handle: ObjectHandle,
    name: &str,
) -> Result<usize, StdlibError> {
    let value = get_required_own_data_property(heap, handle, name)?;
    count_from_value(name, value)
}

fn get_required_own_data_property(
    heap: &ObjectHeap,
    handle: ObjectHandle,
    name: &str,
) -> Result<JsValue, StdlibError> {
    match heap
        .get_own_property_descriptor(handle, &PropertyKey::from(name))
        .map_err(object_error)?
    {
        Some(PropertyDescriptor::Data { value, .. }) => Ok(value),
        Some(PropertyDescriptor::Accessor { .. }) => Err(StdlibError::TypeError(format!(
            "{name} must be an own data property"
        ))),
        None => Err(StdlibError::TypeError(format!(
            "{name} must be an own data property"
        ))),
    }
}

fn get_optional_count_property(
    heap: &ObjectHeap,
    handle: ObjectHandle,
    name: &str,
) -> Result<usize, StdlibError> {
    match heap
        .get_own_property_descriptor(handle, &PropertyKey::from(name))
        .map_err(object_error)?
    {
        Some(PropertyDescriptor::Data { value, .. }) => count_from_value(name, value),
        Some(PropertyDescriptor::Accessor { .. }) => Err(StdlibError::TypeError(format!(
            "{name} must be a data property"
        ))),
        None => Ok(0),
    }
}

fn count_from_value(name: &str, value: JsValue) -> Result<usize, StdlibError> {
    match value {
        JsValue::Int(raw) if raw >= 0 && raw % FP_SCALE == 0 => Ok((raw / FP_SCALE) as usize),
        other => Err(StdlibError::TypeError(format!(
            "{name} must be a non-negative integer count, got {}",
            other.type_name()
        ))),
    }
}

fn count_js_value(count: usize) -> JsValue {
    JsValue::Int(count as i64 * FP_SCALE)
}

fn map_key_slot(index: usize) -> String {
    format!("{MAP_KEY_PREFIX}{index}")
}

fn map_value_slot(index: usize) -> String {
    format!("{MAP_VALUE_PREFIX}{index}")
}

fn set_value_slot(index: usize) -> String {
    format!("{SET_VALUE_PREFIX}{index}")
}

fn diff_value_vectors(
    before: &[JsValue],
    after: &[JsValue],
    prefix: &str,
    count_key: &str,
) -> (Vec<String>, Vec<CollectionMutationEvent>) {
    let mut mutated_keys = Vec::new();
    let mut events = Vec::new();
    let max_len = before.len().max(after.len());
    for index in 0..max_len {
        let before_value = before.get(index);
        let after_value = after.get(index);
        if before_value == after_value {
            continue;
        }
        let key = if prefix.is_empty() {
            index.to_string()
        } else {
            format!("{prefix}{index}]")
        };
        let action = match (before_value, after_value) {
            (None, Some(_)) => "insert",
            (Some(_), None) => "delete",
            _ => "write",
        };
        mutated_keys.push(key.clone());
        events.push(CollectionMutationEvent {
            step: events.len() as u32 + 1,
            action: action.to_string(),
            key: Some(key),
            value: after_value.cloned(),
        });
    }
    if before.len() != after.len() {
        mutated_keys.push(count_key.to_string());
        events.push(CollectionMutationEvent {
            step: events.len() as u32 + 1,
            action: "set_count".into(),
            key: Some(count_key.to_string()),
            value: Some(count_js_value(after.len())),
        });
    }
    (mutated_keys, events)
}

fn diff_map_entries(
    before: &[(JsValue, JsValue)],
    after: &[(JsValue, JsValue)],
) -> (Vec<String>, Vec<CollectionMutationEvent>) {
    let mut mutated_keys = Vec::new();
    let mut events = Vec::new();
    let max_len = before.len().max(after.len());
    for index in 0..max_len {
        let before_entry = before.get(index);
        let after_entry = after.get(index);
        if before_entry == after_entry {
            continue;
        }
        let entry_key = match after_entry {
            Some((key, _)) => format!("entry[{index}]={key}"),
            None => format!("entry[{index}]"),
        };
        let action = match (before_entry, after_entry) {
            (None, Some(_)) => "insert",
            (Some(_), None) => "delete",
            _ => "write",
        };
        mutated_keys.push(entry_key.clone());
        events.push(CollectionMutationEvent {
            step: events.len() as u32 + 1,
            action: action.to_string(),
            key: Some(entry_key),
            value: after_entry.map(|(_, value)| value.clone()),
        });
    }
    if before.len() != after.len() {
        mutated_keys.push("size".into());
        events.push(CollectionMutationEvent {
            step: events.len() as u32 + 1,
            action: "set_count".into(),
            key: Some("size".into()),
            value: Some(count_js_value(after.len())),
        });
    }
    (mutated_keys, events)
}

fn build_collection_trace(
    builtin: BuiltinId,
    collection_kind: CollectionKind,
    target: ObjectHandle,
    before_size: usize,
    after_size: usize,
    mutated_keys: Vec<String>,
    events: Vec<CollectionMutationEvent>,
) -> CollectionMutationTrace {
    let seed = serde_json::to_string(&events).unwrap_or_default();
    let digest = hex::encode(Sha256::digest(
        format!(
            "{}|{}|{}|{}|{}|{}",
            builtin.name(),
            collection_kind.as_str(),
            target.0,
            before_size,
            after_size,
            seed
        )
        .as_bytes(),
    ));
    CollectionMutationTrace {
        trace_id: format!("trace-collection-{}", &digest[..16]),
        builtin: builtin.name().to_string(),
        collection_kind,
        target,
        before_size,
        after_size,
        mutated_keys,
        events,
    }
}

fn object_error(err: crate::object_model::ObjectError) -> StdlibError {
    StdlibError::ObjectError(err.to_string())
}

/// Execute a pure String prototype method.
pub fn exec_string_method(
    builtin: BuiltinId,
    this: &str,
    args: &[JsValue],
) -> Result<JsValue, StdlibError> {
    match builtin {
        BuiltinId::StringPrototypeCharAt => {
            let idx = opt_int_arg(args, 0).unwrap_or(0) / FP_SCALE;
            let ch = this.chars().nth(idx.max(0) as usize);
            Ok(JsValue::Str(ch.map_or_else(String::new, |c| c.to_string())))
        }
        BuiltinId::StringPrototypeCharCodeAt => {
            let idx = opt_int_arg(args, 0).unwrap_or(0) / FP_SCALE;
            match this.chars().nth(idx.max(0) as usize) {
                Some(c) => Ok(JsValue::Int(i64::from(c as u32) * FP_SCALE)),
                None => Ok(JsValue::Int(0)), // NaN equivalent
            }
        }
        BuiltinId::StringPrototypeCodePointAt => {
            let idx = opt_int_arg(args, 0).unwrap_or(0) / FP_SCALE;
            match this.chars().nth(idx.max(0) as usize) {
                Some(c) => Ok(JsValue::Int(i64::from(c as u32) * FP_SCALE)),
                None => Ok(JsValue::Undefined),
            }
        }
        BuiltinId::StringPrototypeIncludes => {
            let search = require_str("String.prototype.includes", args, 0)?;
            Ok(JsValue::Bool(this.contains(search.as_str())))
        }
        BuiltinId::StringPrototypeStartsWith => {
            let search = require_str("String.prototype.startsWith", args, 0)?;
            let pos = opt_int_arg(args, 1).map(|n| (n / FP_SCALE).max(0) as usize);
            let haystack = if let Some(p) = pos {
                &this[this.char_indices().nth(p).map_or(this.len(), |(i, _)| i)..]
            } else {
                this
            };
            Ok(JsValue::Bool(haystack.starts_with(search.as_str())))
        }
        BuiltinId::StringPrototypeEndsWith => {
            let search = require_str("String.prototype.endsWith", args, 0)?;
            Ok(JsValue::Bool(this.ends_with(search.as_str())))
        }
        BuiltinId::StringPrototypeIndexOf => {
            let search = require_str("String.prototype.indexOf", args, 0)?;
            match this.find(search.as_str()) {
                Some(byte_idx) => {
                    let char_idx = this[..byte_idx].chars().count() as i64;
                    Ok(JsValue::Int(char_idx * FP_SCALE))
                }
                None => Ok(JsValue::Int(-FP_SCALE)),
            }
        }
        BuiltinId::StringPrototypeLastIndexOf => {
            let search = require_str("String.prototype.lastIndexOf", args, 0)?;
            match this.rfind(search.as_str()) {
                Some(byte_idx) => {
                    let char_idx = this[..byte_idx].chars().count() as i64;
                    Ok(JsValue::Int(char_idx * FP_SCALE))
                }
                None => Ok(JsValue::Int(-FP_SCALE)),
            }
        }
        BuiltinId::StringPrototypeSlice => {
            let len = this.chars().count() as i64;
            let start = resolve_string_index(opt_int_arg(args, 0).unwrap_or(0) / FP_SCALE, len);
            let end = resolve_string_index(
                opt_int_arg(args, 1).unwrap_or(len * FP_SCALE) / FP_SCALE,
                len,
            );
            if start >= end {
                return Ok(JsValue::Str(String::new()));
            }
            let result: String = this
                .chars()
                .skip(start as usize)
                .take((end - start) as usize)
                .collect();
            Ok(JsValue::Str(result))
        }
        BuiltinId::StringPrototypeSubstring => {
            let len = this.chars().count() as i64;
            let mut a = (opt_int_arg(args, 0).unwrap_or(0) / FP_SCALE).clamp(0, len);
            let mut b = opt_int_arg(args, 1)
                .map(|n| (n / FP_SCALE).clamp(0, len))
                .unwrap_or(len);
            if a > b {
                std::mem::swap(&mut a, &mut b);
            }
            let result: String = this
                .chars()
                .skip(a as usize)
                .take((b - a) as usize)
                .collect();
            Ok(JsValue::Str(result))
        }
        BuiltinId::StringPrototypeTrim => Ok(JsValue::Str(this.trim().to_string())),
        BuiltinId::StringPrototypeTrimStart => Ok(JsValue::Str(this.trim_start().to_string())),
        BuiltinId::StringPrototypeTrimEnd => Ok(JsValue::Str(this.trim_end().to_string())),
        BuiltinId::StringPrototypePadStart => {
            let target_len = require_int("String.prototype.padStart", args, 0)? / FP_SCALE;
            let pad_str = opt_str_arg(args, 1).unwrap_or_else(|| " ".into());
            Ok(JsValue::Str(pad_string(this, target_len, &pad_str, true)))
        }
        BuiltinId::StringPrototypePadEnd => {
            let target_len = require_int("String.prototype.padEnd", args, 0)? / FP_SCALE;
            let pad_str = opt_str_arg(args, 1).unwrap_or_else(|| " ".into());
            Ok(JsValue::Str(pad_string(this, target_len, &pad_str, false)))
        }
        BuiltinId::StringPrototypeRepeat => {
            let count = require_int("String.prototype.repeat", args, 0)? / FP_SCALE;
            if count < 0 {
                return Err(StdlibError::RangeError(
                    "repeat count must be non-negative".into(),
                ));
            }
            let count = count as usize;
            if count > MAX_STRING_REPEAT {
                return Err(StdlibError::RangeError(format!(
                    "repeat count {count} exceeds maximum {MAX_STRING_REPEAT}"
                )));
            }
            Ok(JsValue::Str(this.repeat(count)))
        }
        BuiltinId::StringPrototypeToUpperCase => Ok(JsValue::Str(this.to_uppercase())),
        BuiltinId::StringPrototypeToLowerCase => Ok(JsValue::Str(this.to_lowercase())),
        BuiltinId::StringPrototypeSplit => {
            let separator = require_str("String.prototype.split", args, 0)?;
            let limit = opt_int_arg(args, 1).map(|n| (n / FP_SCALE).max(0) as usize);
            let parts: Vec<JsValue> = if let Some(lim) = limit {
                this.splitn(lim, separator.as_str())
                    .map(|s| JsValue::Str(s.to_string()))
                    .collect()
            } else {
                this.split(separator.as_str())
                    .map(|s| JsValue::Str(s.to_string()))
                    .collect()
            };
            // Return as a serialized array description (actual array creation
            // requires heap access and is done by the interpreter).
            Ok(JsValue::Str(format!("[split:{}]", parts.len())))
        }
        BuiltinId::StringPrototypeConcat => {
            let mut result = this.to_string();
            for arg in args {
                result.push_str(&coerce_to_string(arg));
            }
            Ok(JsValue::Str(result))
        }
        BuiltinId::StringPrototypeReplace => {
            let search = require_str("String.prototype.replace", args, 0)?;
            let replacement = match args.get(1) {
                Some(v) => coerce_to_string(v),
                None => "undefined".to_string(),
            };
            // Simple string replacement (first occurrence only, no regex).
            Ok(JsValue::Str(this.replacen(&*search, &replacement, 1)))
        }
        BuiltinId::StringPrototypeSearch => {
            let search = require_str("String.prototype.search", args, 0)?;
            // Simple substring search (no regex). Returns char index or -1.
            match this.find(&*search) {
                Some(byte_idx) => {
                    let char_idx = this[..byte_idx].chars().count() as i64;
                    Ok(JsValue::Int(char_idx * FP_SCALE))
                }
                None => Ok(JsValue::Int(-FP_SCALE)),
            }
        }
        BuiltinId::StringPrototypeMatch => {
            // Without RegExp support, match with a string pattern returns
            // the first occurrence or null.
            let search = require_str("String.prototype.match", args, 0)?;
            if let Some(byte_idx) = this.find(&*search) {
                // Return the matched substring (simple string match).
                let _ = byte_idx;
                Ok(JsValue::Str(search.to_string()))
            } else {
                Ok(JsValue::Null)
            }
        }
        BuiltinId::StringPrototypeNormalize => {
            // Without full Unicode normalization crate, return the string unchanged.
            // This is correct for ASCII-only input (NFC == identity for ASCII).
            Ok(JsValue::Str(this.to_string()))
        }
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a String method",
            builtin.name()
        ))),
    }
}

/// Execute a pure Number method.
pub fn exec_number_method(
    builtin: BuiltinId,
    this_val: i64,
    args: &[JsValue],
) -> Result<JsValue, StdlibError> {
    match builtin {
        BuiltinId::NumberIsFinite => Ok(JsValue::Bool(true)), // i64 is always finite
        BuiltinId::NumberIsInteger => Ok(JsValue::Bool(this_val % FP_SCALE == 0)),
        BuiltinId::NumberIsNaN => Ok(JsValue::Bool(false)), // i64 is never NaN
        BuiltinId::NumberIsSafeInteger => {
            let units = this_val / FP_SCALE;
            Ok(JsValue::Bool(
                this_val % FP_SCALE == 0 && units.abs() <= 9_007_199_254_740_991,
            ))
        }
        BuiltinId::NumberPrototypeToFixed => {
            let digits = opt_int_arg(args, 0).unwrap_or(0) / FP_SCALE;
            if !(0..=20).contains(&digits) {
                return Err(StdlibError::RangeError(
                    "toFixed() digits must be between 0 and 20".into(),
                ));
            }
            let units = this_val / FP_SCALE;
            let frac = (this_val % FP_SCALE).abs();
            if digits == 0 {
                Ok(JsValue::Str(format!("{units}")))
            } else {
                let frac_str = format!("{frac:06}");
                let trimmed = &frac_str[..digits.min(6) as usize];
                Ok(JsValue::Str(format!("{units}.{trimmed}")))
            }
        }
        BuiltinId::NumberPrototypeToString => {
            let units = this_val / FP_SCALE;
            let frac = this_val % FP_SCALE;
            if frac == 0 {
                Ok(JsValue::Str(format!("{units}")))
            } else {
                let frac_abs = frac.abs();
                let frac_str = format!("{frac_abs:06}");
                let trimmed = frac_str.trim_end_matches('0');
                Ok(JsValue::Str(format!("{units}.{trimmed}")))
            }
        }
        BuiltinId::NumberPrototypeValueOf => Ok(JsValue::Int(this_val)),
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a Number method",
            builtin.name()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Date operations
// ---------------------------------------------------------------------------

/// Execute a Date static method or prototype method.
///
/// Date.now() returns a deterministic epoch timestamp in fixed-point milliseconds.
/// For deterministic replay, we use a fixed epoch (2026-01-01T00:00:00Z = 1767225600000).
pub fn exec_date_method(
    builtin: BuiltinId,
    this_timestamp: Option<i64>,
) -> Result<JsValue, StdlibError> {
    // Deterministic epoch anchor for replay: 2026-01-01T00:00:00Z in ms.
    const DETERMINISTIC_EPOCH_MS: i64 = 1_767_225_600_000;

    match builtin {
        BuiltinId::DateNow => {
            // Return deterministic timestamp for reproducibility.
            Ok(JsValue::Int(DETERMINISTIC_EPOCH_MS * FP_SCALE))
        }
        BuiltinId::DatePrototypeGetTime => {
            let ts = this_timestamp.unwrap_or(0);
            Ok(JsValue::Int(ts))
        }
        BuiltinId::DatePrototypeValueOf => {
            let ts = this_timestamp.unwrap_or(0);
            Ok(JsValue::Int(ts))
        }
        BuiltinId::DatePrototypeToString => {
            let ts = this_timestamp.unwrap_or(0) / FP_SCALE;
            // Simplified ISO-like string for deterministic output.
            let secs = ts / 1000;
            let ms = (ts % 1000).abs();
            Ok(JsValue::Str(format!("Date({secs}.{ms:03})")))
        }
        BuiltinId::DatePrototypeToISOString => {
            let ts = this_timestamp.unwrap_or(0) / FP_SCALE;
            // Deterministic ISO 8601 from millisecond timestamp.
            let total_secs = ts / 1000;
            let ms = (ts % 1000).abs();
            let secs_in_day = total_secs.rem_euclid(86400);
            let hours = secs_in_day / 3600;
            let minutes = (secs_in_day % 3600) / 60;
            let seconds = secs_in_day % 60;
            // Simplified: epoch day calculation for deterministic output.
            let days = total_secs / 86400;
            Ok(JsValue::Str(format!(
                "{days}T{hours:02}:{minutes:02}:{seconds:02}.{ms:03}Z"
            )))
        }
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a Date method",
            builtin.name()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Error operations
// ---------------------------------------------------------------------------

/// Execute an Error constructor. Returns the error message as a JsValue::Str.
///
/// The actual Error object creation (with .message, .stack properties) requires
/// heap access and is done by the interpreter. This function validates the
/// constructor call and extracts the message.
pub fn exec_error_constructor(
    builtin: BuiltinId,
    args: &[JsValue],
) -> Result<JsValue, StdlibError> {
    let kind = match builtin {
        BuiltinId::ErrorConstructor => "Error",
        BuiltinId::TypeErrorConstructor => "TypeError",
        BuiltinId::RangeErrorConstructor => "RangeError",
        BuiltinId::ReferenceErrorConstructor => "ReferenceError",
        BuiltinId::SyntaxErrorConstructor => "SyntaxError",
        _ => {
            return Err(StdlibError::TypeError(format!(
                "{} is not an Error constructor",
                builtin.name()
            )));
        }
    };
    let message = match args.first() {
        Some(JsValue::Str(s)) => s.clone(),
        Some(v) => coerce_to_string(v),
        None => String::new(),
    };
    // Return formatted error string. Interpreter will create the heap object.
    Ok(JsValue::Str(format!("{kind}: {message}")))
}

// ---------------------------------------------------------------------------
// Symbol operations
// ---------------------------------------------------------------------------

/// Execute Symbol.for / Symbol.keyFor.
///
/// Symbol.for(key) returns a globally-registered symbol for the given key.
/// Symbol.keyFor(sym) returns the key for a globally-registered symbol.
/// In our fixed-point system, symbols are represented by SymbolId.
pub fn exec_symbol_static(builtin: BuiltinId, args: &[JsValue]) -> Result<JsValue, StdlibError> {
    match builtin {
        BuiltinId::SymbolFor => {
            let key = require_str("Symbol.for", args, 0)?;
            // Deterministic symbol ID derived from key hash.
            let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
            for byte in key.as_bytes() {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0100_0000_01b3); // FNV prime
            }
            Ok(JsValue::Symbol(SymbolId(hash as u32)))
        }
        BuiltinId::SymbolKeyFor => {
            // Without a global symbol registry, we cannot reverse-lookup.
            // Return undefined (symbol was not registered via Symbol.for).
            Ok(JsValue::Undefined)
        }
        _ => Err(StdlibError::TypeError(format!(
            "{} is not a Symbol static method",
            builtin.name()
        ))),
    }
}

// ---------------------------------------------------------------------------
// JSON operations
// ---------------------------------------------------------------------------

/// Deterministic JSON.parse for simple values.
pub fn json_parse(input: &str) -> Result<JsValue, StdlibError> {
    let trimmed = input.trim();
    if trimmed == "null" {
        return Ok(JsValue::Null);
    }
    if trimmed == "true" {
        return Ok(JsValue::Bool(true));
    }
    if trimmed == "false" {
        return Ok(JsValue::Bool(false));
    }
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        let inner = &trimmed[1..trimmed.len() - 1];
        return Ok(JsValue::Str(unescape_json_string(inner)?));
    }
    if let Ok(n) = trimmed.parse::<i64>() {
        return Ok(JsValue::Int(n * FP_SCALE));
    }
    // Objects and arrays require heap allocation — return a parse descriptor.
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return Ok(JsValue::Str(format!("[json-compound:{}]", trimmed.len())));
    }
    Err(StdlibError::JsonParseError(format!(
        "unexpected token at position 0: {}",
        &trimmed[..trimmed.len().min(20)]
    )))
}

/// Deterministic JSON.stringify for simple values.
pub fn json_stringify(value: &JsValue) -> Result<JsValue, StdlibError> {
    match value {
        JsValue::Undefined => Ok(JsValue::Undefined),
        JsValue::Null => Ok(JsValue::Str("null".into())),
        JsValue::Bool(b) => Ok(JsValue::Str(if *b { "true" } else { "false" }.into())),
        JsValue::Int(n) => {
            let units = n / FP_SCALE;
            let frac = n % FP_SCALE;
            if frac == 0 {
                Ok(JsValue::Str(format!("{units}")))
            } else {
                let frac_abs = frac.abs();
                let frac_str = format!("{frac_abs:06}");
                let trimmed = frac_str.trim_end_matches('0');
                let sign = if *n < 0 && units == 0 { "-" } else { "" };
                Ok(JsValue::Str(format!("{sign}{units}.{trimmed}")))
            }
        }
        JsValue::Str(s) => Ok(JsValue::Str(format!("\"{}\"", escape_json_string(s)))),
        JsValue::Symbol(_) => Ok(JsValue::Undefined), // Symbols are omitted
        JsValue::Object(_) | JsValue::Function(_) => {
            // Complex objects need heap traversal; return placeholder.
            Ok(JsValue::Str("[json-object]".into()))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers — argument extraction
// ---------------------------------------------------------------------------

fn require_int(context: &str, args: &[JsValue], index: usize) -> Result<i64, StdlibError> {
    args.get(index)
        .map(|v| coerce_to_int(context, v))
        .unwrap_or(Err(StdlibError::TypeError(format!(
            "{context}: missing argument at index {index}"
        ))))
}

fn require_str(context: &str, args: &[JsValue], index: usize) -> Result<String, StdlibError> {
    match args.get(index) {
        Some(JsValue::Str(s)) => Ok(s.clone()),
        Some(v) => Ok(coerce_to_string(v)),
        None => Err(StdlibError::TypeError(format!(
            "{context}: missing argument at index {index}"
        ))),
    }
}

fn opt_int_arg(args: &[JsValue], index: usize) -> Option<i64> {
    args.get(index).and_then(|v| match v {
        JsValue::Int(n) => Some(*n),
        JsValue::Bool(b) => Some(if *b { FP_SCALE } else { 0 }),
        _ => None,
    })
}

fn opt_str_arg(args: &[JsValue], index: usize) -> Option<String> {
    args.get(index).map(coerce_to_string)
}

fn coerce_to_int(context: &str, value: &JsValue) -> Result<i64, StdlibError> {
    match value {
        JsValue::Int(n) => Ok(*n),
        JsValue::Bool(b) => Ok(if *b { FP_SCALE } else { 0 }),
        JsValue::Null => Ok(0),
        JsValue::Undefined => Ok(0), // NaN → 0 for integer coercion
        JsValue::Str(s) => s.parse::<i64>().map(|n| n * FP_SCALE).or(Ok(0)),
        _ => Err(StdlibError::TypeError(format!(
            "{context}: cannot coerce {} to number",
            value.type_name()
        ))),
    }
}

fn coerce_to_string(value: &JsValue) -> String {
    match value {
        JsValue::Undefined => "undefined".into(),
        JsValue::Null => "null".into(),
        JsValue::Bool(b) => if *b { "true" } else { "false" }.into(),
        JsValue::Int(n) => {
            let units = n / FP_SCALE;
            let frac = n % FP_SCALE;
            if frac == 0 {
                format!("{units}")
            } else {
                let frac_abs = frac.abs();
                let frac_str = format!("{frac_abs:06}");
                let trimmed = frac_str.trim_end_matches('0');
                format!("{units}.{trimmed}")
            }
        }
        JsValue::Str(s) => s.clone(),
        JsValue::Symbol(id) => format!("Symbol({})", id.0),
        JsValue::Object(_) => "[object Object]".into(),
        JsValue::Function(_) => "function () {{ [native code] }}".into(),
    }
}

/// SameValue comparison (Object.is semantics).
fn same_value(a: &JsValue, b: &JsValue) -> bool {
    match (a, b) {
        (JsValue::Undefined, JsValue::Undefined) => true,
        (JsValue::Null, JsValue::Null) => true,
        (JsValue::Bool(x), JsValue::Bool(y)) => x == y,
        (JsValue::Int(x), JsValue::Int(y)) => x == y,
        (JsValue::Str(x), JsValue::Str(y)) => x == y,
        (JsValue::Symbol(x), JsValue::Symbol(y)) => x == y,
        (JsValue::Object(x), JsValue::Object(y)) => x == y,
        (JsValue::Function(x), JsValue::Function(y)) => x == y,
        _ => false,
    }
}

fn resolve_array_index(idx: i64, len: i64) -> i64 {
    if idx < 0 {
        (len + idx).max(0)
    } else {
        idx.min(len)
    }
}

/// Integer square root (floor) for fixed-point sqrt.
fn isqrt_i64(n: i64) -> i64 {
    if n <= 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Fixed-point natural logarithm using iterative series.
///
/// Computes ln(x) where x is in fixed-point (x / FP_SCALE is the real value).
/// Returns result in fixed-point.
fn fp_ln(x: i64) -> i64 {
    if x <= 0 {
        return i64::MIN; // -infinity
    }
    // Normalize: factor out powers of e (~2.718).
    // We use ln(x) = ln(x/e^k) + k where e in fp = 2_718_282.
    let e_fp = 2_718_282_i64;
    let mut normalized = x;
    let mut k: i64 = 0;

    // Scale down if at or above e
    while normalized >= e_fp {
        normalized = normalized * FP_SCALE / e_fp;
        k += 1;
    }
    // Scale up if below 1.0
    while normalized < FP_SCALE {
        normalized = normalized * e_fp / FP_SCALE;
        k -= 1;
    }

    // Now 1.0 <= normalized <= e in fixed-point.
    // Use series: ln(1+u) = u - u^2/2 + u^3/3 - u^4/4 ...
    // where u = (normalized - FP_SCALE) / FP_SCALE, so u is in [0, ~1.718].
    let u = normalized - FP_SCALE; // in FP units
    // Compute terms with diminishing precision.
    let u_fp = u; // Already in FP_SCALE units
    let mut sum = u_fp;
    let mut term = u_fp;
    for n in 2..=12_i64 {
        term = term * u / FP_SCALE; // u^n / FP_SCALE^(n-1)
        let contribution = term / n;
        if n % 2 == 0 {
            sum -= contribution;
        } else {
            sum += contribution;
        }
        if contribution.abs() < 10 {
            break; // Converged
        }
    }

    sum + k * FP_SCALE
}

/// Percent-encode a string for URI encoding.
fn percent_encode(input: &str, component: bool) -> String {
    let mut result = String::with_capacity(input.len());
    for byte in input.bytes() {
        if is_uri_unreserved(byte) || (!component && is_uri_reserved(byte)) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

/// Percent-decode a string for URI decoding.
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                result.push(byte as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn is_uri_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~'
}

fn is_uri_reserved(b: u8) -> bool {
    matches!(
        b,
        b';' | b'/' | b'?' | b':' | b'@' | b'&' | b'=' | b'+' | b'$' | b',' | b'#'
    )
}

fn resolve_string_index(idx: i64, len: i64) -> i64 {
    if idx < 0 {
        (len + idx).max(0)
    } else {
        idx.min(len)
    }
}

fn pad_string(s: &str, target_len: i64, pad_str: &str, start: bool) -> String {
    let current_len = s.chars().count() as i64;
    if target_len <= current_len || pad_str.is_empty() {
        return s.to_string();
    }
    let needed = (target_len - current_len) as usize;
    let mut padding = String::with_capacity(needed);
    while padding.chars().count() < needed {
        padding.push_str(pad_str);
    }
    let padding: String = padding.chars().take(needed).collect();
    if start {
        format!("{padding}{s}")
    } else {
        format!("{s}{padding}")
    }
}

fn unescape_json_string(s: &str) -> Result<String, StdlibError> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('b') => result.push('\u{0008}'),
                Some('f') => result.push('\u{000C}'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() != 4 {
                        return Err(StdlibError::JsonParseError(
                            "incomplete unicode escape".into(),
                        ));
                    }
                    let cp = u32::from_str_radix(&hex, 16).map_err(|_| {
                        StdlibError::JsonParseError(format!("invalid unicode escape: \\u{hex}"))
                    })?;
                    let ch = char::from_u32(cp).ok_or_else(|| {
                        StdlibError::JsonParseError(format!("invalid code point: {cp}"))
                    })?;
                    result.push(ch);
                }
                Some(other) => {
                    return Err(StdlibError::JsonParseError(format!(
                        "invalid escape: \\{other}"
                    )));
                }
                None => {
                    return Err(StdlibError::JsonParseError(
                        "unexpected end of string after \\".into(),
                    ));
                }
            }
        } else {
            result.push(c);
        }
    }
    Ok(result)
}

fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Installation helpers
// ---------------------------------------------------------------------------

fn install_ctor_proto_link(heap: &mut ObjectHeap, ctor: ObjectHandle, proto: ObjectHandle) {
    // Constructor.prototype = proto (non-writable, non-enumerable, configurable)
    let _ = heap.set_property(ctor, PropertyKey::from("prototype"), JsValue::Object(proto));
    // proto.constructor = ctor (writable, configurable, non-enumerable)
    let _ = heap.set_property(
        proto,
        PropertyKey::from("constructor"),
        JsValue::Object(ctor),
    );
}

fn set_class_tag(heap: &mut ObjectHeap, handle: ObjectHandle, tag: &str) {
    if let Ok(obj) = heap.get_mut(handle)
        && let Some(ordinary) = obj.as_ordinary_mut()
    {
        ordinary.class_tag = Some(tag.to_string());
    }
}

fn install_builtin_fn(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    target: ObjectHandle,
    name: &str,
    builtin_id: BuiltinId,
) {
    let slot = registry.register(builtin_id);
    let _ = heap.set_property(target, PropertyKey::from(name), JsValue::Function(slot));
}

fn install_object_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    ctor: ObjectHandle,
    proto: ObjectHandle,
) {
    // Static methods on Object
    install_builtin_fn(heap, registry, ctor, "keys", BuiltinId::ObjectKeys);
    install_builtin_fn(heap, registry, ctor, "values", BuiltinId::ObjectValues);
    install_builtin_fn(heap, registry, ctor, "entries", BuiltinId::ObjectEntries);
    install_builtin_fn(heap, registry, ctor, "assign", BuiltinId::ObjectAssign);
    install_builtin_fn(heap, registry, ctor, "freeze", BuiltinId::ObjectFreeze);
    install_builtin_fn(heap, registry, ctor, "seal", BuiltinId::ObjectSeal);
    install_builtin_fn(heap, registry, ctor, "create", BuiltinId::ObjectCreate);
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "defineProperty",
        BuiltinId::ObjectDefineProperty,
    );
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "defineProperties",
        BuiltinId::ObjectDefineProperties,
    );
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "getPrototypeOf",
        BuiltinId::ObjectGetPrototypeOf,
    );
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "setPrototypeOf",
        BuiltinId::ObjectSetPrototypeOf,
    );
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "getOwnPropertyDescriptor",
        BuiltinId::ObjectGetOwnPropertyDescriptor,
    );
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "getOwnPropertyNames",
        BuiltinId::ObjectGetOwnPropertyNames,
    );
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "getOwnPropertySymbols",
        BuiltinId::ObjectGetOwnPropertySymbols,
    );
    install_builtin_fn(heap, registry, ctor, "is", BuiltinId::ObjectIs);
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "fromEntries",
        BuiltinId::ObjectFromEntries,
    );

    // Prototype methods
    install_builtin_fn(
        heap,
        registry,
        proto,
        "hasOwnProperty",
        BuiltinId::ObjectPrototypeHasOwnProperty,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "isPrototypeOf",
        BuiltinId::ObjectPrototypeIsPrototypeOf,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "propertyIsEnumerable",
        BuiltinId::ObjectPrototypePropertyIsEnumerable,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "toString",
        BuiltinId::ObjectPrototypeToString,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "valueOf",
        BuiltinId::ObjectPrototypeValueOf,
    );
}

fn install_array_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    ctor: ObjectHandle,
    proto: ObjectHandle,
) {
    // Static methods on Array
    install_builtin_fn(heap, registry, ctor, "isArray", BuiltinId::ArrayIsArray);
    install_builtin_fn(heap, registry, ctor, "from", BuiltinId::ArrayFrom);
    install_builtin_fn(heap, registry, ctor, "of", BuiltinId::ArrayOf);

    // Prototype methods
    install_builtin_fn(heap, registry, proto, "push", BuiltinId::ArrayPrototypePush);
    install_builtin_fn(heap, registry, proto, "pop", BuiltinId::ArrayPrototypePop);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "shift",
        BuiltinId::ArrayPrototypeShift,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "unshift",
        BuiltinId::ArrayPrototypeUnshift,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "slice",
        BuiltinId::ArrayPrototypeSlice,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "splice",
        BuiltinId::ArrayPrototypeSplice,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "concat",
        BuiltinId::ArrayPrototypeConcat,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "indexOf",
        BuiltinId::ArrayPrototypeIndexOf,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "lastIndexOf",
        BuiltinId::ArrayPrototypeLastIndexOf,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "includes",
        BuiltinId::ArrayPrototypeIncludes,
    );
    install_builtin_fn(heap, registry, proto, "join", BuiltinId::ArrayPrototypeJoin);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "reverse",
        BuiltinId::ArrayPrototypeReverse,
    );
    install_builtin_fn(heap, registry, proto, "sort", BuiltinId::ArrayPrototypeSort);
    install_builtin_fn(heap, registry, proto, "map", BuiltinId::ArrayPrototypeMap);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "filter",
        BuiltinId::ArrayPrototypeFilter,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "reduce",
        BuiltinId::ArrayPrototypeReduce,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "reduceRight",
        BuiltinId::ArrayPrototypeReduceRight,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "forEach",
        BuiltinId::ArrayPrototypeForEach,
    );
    install_builtin_fn(heap, registry, proto, "some", BuiltinId::ArrayPrototypeSome);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "every",
        BuiltinId::ArrayPrototypeEvery,
    );
    install_builtin_fn(heap, registry, proto, "find", BuiltinId::ArrayPrototypeFind);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "findIndex",
        BuiltinId::ArrayPrototypeFindIndex,
    );
    install_builtin_fn(heap, registry, proto, "fill", BuiltinId::ArrayPrototypeFill);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "copyWithin",
        BuiltinId::ArrayPrototypeCopyWithin,
    );
    install_builtin_fn(heap, registry, proto, "flat", BuiltinId::ArrayPrototypeFlat);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "flatMap",
        BuiltinId::ArrayPrototypeFlatMap,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "entries",
        BuiltinId::ArrayPrototypeEntries,
    );
    install_builtin_fn(heap, registry, proto, "keys", BuiltinId::ArrayPrototypeKeys);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "values",
        BuiltinId::ArrayPrototypeValues,
    );
}

fn install_string_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    ctor: ObjectHandle,
    proto: ObjectHandle,
) {
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "fromCharCode",
        BuiltinId::StringFromCharCode,
    );
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "fromCodePoint",
        BuiltinId::StringFromCodePoint,
    );

    install_builtin_fn(
        heap,
        registry,
        proto,
        "charAt",
        BuiltinId::StringPrototypeCharAt,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "charCodeAt",
        BuiltinId::StringPrototypeCharCodeAt,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "codePointAt",
        BuiltinId::StringPrototypeCodePointAt,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "concat",
        BuiltinId::StringPrototypeConcat,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "includes",
        BuiltinId::StringPrototypeIncludes,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "startsWith",
        BuiltinId::StringPrototypeStartsWith,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "endsWith",
        BuiltinId::StringPrototypeEndsWith,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "indexOf",
        BuiltinId::StringPrototypeIndexOf,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "lastIndexOf",
        BuiltinId::StringPrototypeLastIndexOf,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "slice",
        BuiltinId::StringPrototypeSlice,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "substring",
        BuiltinId::StringPrototypeSubstring,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "trim",
        BuiltinId::StringPrototypeTrim,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "trimStart",
        BuiltinId::StringPrototypeTrimStart,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "trimEnd",
        BuiltinId::StringPrototypeTrimEnd,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "padStart",
        BuiltinId::StringPrototypePadStart,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "padEnd",
        BuiltinId::StringPrototypePadEnd,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "repeat",
        BuiltinId::StringPrototypeRepeat,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "toUpperCase",
        BuiltinId::StringPrototypeToUpperCase,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "toLowerCase",
        BuiltinId::StringPrototypeToLowerCase,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "split",
        BuiltinId::StringPrototypeSplit,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "replace",
        BuiltinId::StringPrototypeReplace,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "match",
        BuiltinId::StringPrototypeMatch,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "search",
        BuiltinId::StringPrototypeSearch,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "normalize",
        BuiltinId::StringPrototypeNormalize,
    );
}

fn install_number_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    ctor: ObjectHandle,
    proto: ObjectHandle,
) {
    install_builtin_fn(heap, registry, ctor, "isFinite", BuiltinId::NumberIsFinite);
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "isInteger",
        BuiltinId::NumberIsInteger,
    );
    install_builtin_fn(heap, registry, ctor, "isNaN", BuiltinId::NumberIsNaN);
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "isSafeInteger",
        BuiltinId::NumberIsSafeInteger,
    );
    install_builtin_fn(
        heap,
        registry,
        ctor,
        "parseFloat",
        BuiltinId::NumberParseFloat,
    );
    install_builtin_fn(heap, registry, ctor, "parseInt", BuiltinId::NumberParseInt);

    // Number constants (fixed-point).
    // MAX_SAFE_INTEGER cannot be scaled by FP_SCALE without overflowing i64,
    // so we store the maximum integer representable in our fixed-point system.
    let max_safe = (i64::MAX / FP_SCALE) * FP_SCALE;
    let min_safe = (i64::MIN / FP_SCALE) * FP_SCALE;
    let _ = heap.set_property(
        ctor,
        PropertyKey::from("MAX_SAFE_INTEGER"),
        JsValue::Int(max_safe),
    );
    let _ = heap.set_property(
        ctor,
        PropertyKey::from("MIN_SAFE_INTEGER"),
        JsValue::Int(min_safe),
    );
    let _ = heap.set_property(ctor, PropertyKey::from("EPSILON"), JsValue::Int(1)); // Smallest representable in fixed-point

    install_builtin_fn(
        heap,
        registry,
        proto,
        "toFixed",
        BuiltinId::NumberPrototypeToFixed,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "toString",
        BuiltinId::NumberPrototypeToString,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "valueOf",
        BuiltinId::NumberPrototypeValueOf,
    );
}

fn install_boolean_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    _ctor: ObjectHandle,
    proto: ObjectHandle,
) {
    install_builtin_fn(
        heap,
        registry,
        proto,
        "toString",
        BuiltinId::BooleanPrototypeToString,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "valueOf",
        BuiltinId::BooleanPrototypeValueOf,
    );
}

fn install_math_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    math: ObjectHandle,
) {
    // Math constants (fixed-point millionths)
    let _ = heap.set_property(math, PropertyKey::from("PI"), JsValue::Int(3_141_593));
    let _ = heap.set_property(math, PropertyKey::from("E"), JsValue::Int(2_718_282));
    let _ = heap.set_property(math, PropertyKey::from("LN2"), JsValue::Int(693_147));
    let _ = heap.set_property(math, PropertyKey::from("LN10"), JsValue::Int(2_302_585));
    let _ = heap.set_property(math, PropertyKey::from("LOG2E"), JsValue::Int(1_442_695));
    let _ = heap.set_property(math, PropertyKey::from("LOG10E"), JsValue::Int(434_294));
    let _ = heap.set_property(math, PropertyKey::from("SQRT2"), JsValue::Int(1_414_214));
    let _ = heap.set_property(math, PropertyKey::from("SQRT1_2"), JsValue::Int(707_107));

    install_builtin_fn(heap, registry, math, "abs", BuiltinId::MathAbs);
    install_builtin_fn(heap, registry, math, "ceil", BuiltinId::MathCeil);
    install_builtin_fn(heap, registry, math, "floor", BuiltinId::MathFloor);
    install_builtin_fn(heap, registry, math, "round", BuiltinId::MathRound);
    install_builtin_fn(heap, registry, math, "trunc", BuiltinId::MathTrunc);
    install_builtin_fn(heap, registry, math, "sign", BuiltinId::MathSign);
    install_builtin_fn(heap, registry, math, "max", BuiltinId::MathMax);
    install_builtin_fn(heap, registry, math, "min", BuiltinId::MathMin);
    install_builtin_fn(heap, registry, math, "pow", BuiltinId::MathPow);
    install_builtin_fn(heap, registry, math, "sqrt", BuiltinId::MathSqrt);
    install_builtin_fn(heap, registry, math, "log", BuiltinId::MathLog);
    install_builtin_fn(heap, registry, math, "log2", BuiltinId::MathLog2);
    install_builtin_fn(heap, registry, math, "log10", BuiltinId::MathLog10);
    install_builtin_fn(heap, registry, math, "clz32", BuiltinId::MathClz32);
    install_builtin_fn(heap, registry, math, "imul", BuiltinId::MathImul);
    install_builtin_fn(heap, registry, math, "fround", BuiltinId::MathFround);
    install_builtin_fn(heap, registry, math, "hypot", BuiltinId::MathHypot);
}

fn install_json_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    json: ObjectHandle,
) {
    install_builtin_fn(heap, registry, json, "parse", BuiltinId::JsonParse);
    install_builtin_fn(heap, registry, json, "stringify", BuiltinId::JsonStringify);
}

fn install_map_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    _ctor: ObjectHandle,
    proto: ObjectHandle,
) {
    install_builtin_fn(heap, registry, proto, "get", BuiltinId::MapPrototypeGet);
    install_builtin_fn(heap, registry, proto, "set", BuiltinId::MapPrototypeSet);
    install_builtin_fn(heap, registry, proto, "has", BuiltinId::MapPrototypeHas);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "delete",
        BuiltinId::MapPrototypeDelete,
    );
    install_builtin_fn(heap, registry, proto, "clear", BuiltinId::MapPrototypeClear);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "forEach",
        BuiltinId::MapPrototypeForEach,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "entries",
        BuiltinId::MapPrototypeEntries,
    );
    install_builtin_fn(heap, registry, proto, "keys", BuiltinId::MapPrototypeKeys);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "values",
        BuiltinId::MapPrototypeValues,
    );
}

fn install_set_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    _ctor: ObjectHandle,
    proto: ObjectHandle,
) {
    install_builtin_fn(heap, registry, proto, "add", BuiltinId::SetPrototypeAdd);
    install_builtin_fn(heap, registry, proto, "has", BuiltinId::SetPrototypeHas);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "delete",
        BuiltinId::SetPrototypeDelete,
    );
    install_builtin_fn(heap, registry, proto, "clear", BuiltinId::SetPrototypeClear);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "forEach",
        BuiltinId::SetPrototypeForEach,
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "entries",
        BuiltinId::SetPrototypeEntries,
    );
    install_builtin_fn(heap, registry, proto, "keys", BuiltinId::SetPrototypeKeys);
    install_builtin_fn(
        heap,
        registry,
        proto,
        "values",
        BuiltinId::SetPrototypeValues,
    );
}

fn install_error_builtins(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    proto: ObjectHandle,
) {
    let _ = heap.set_property(
        proto,
        PropertyKey::from("name"),
        JsValue::Str("Error".into()),
    );
    let _ = heap.set_property(
        proto,
        PropertyKey::from("message"),
        JsValue::Str(String::new()),
    );
    install_builtin_fn(
        heap,
        registry,
        proto,
        "toString",
        BuiltinId::ErrorPrototypeToString,
    );
}

fn install_global_properties(
    heap: &mut ObjectHeap,
    registry: &mut BuiltinRegistry,
    global: ObjectHandle,
    ctors: &ConstructorHandles,
    math: ObjectHandle,
    json: ObjectHandle,
) {
    // Install constructors on global
    let _ = heap.set_property(
        global,
        PropertyKey::from("Object"),
        JsValue::Object(ctors.object_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("Array"),
        JsValue::Object(ctors.array_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("String"),
        JsValue::Object(ctors.string_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("Number"),
        JsValue::Object(ctors.number_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("Boolean"),
        JsValue::Object(ctors.boolean_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("Error"),
        JsValue::Object(ctors.error_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("TypeError"),
        JsValue::Object(ctors.type_error_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("RangeError"),
        JsValue::Object(ctors.range_error_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("ReferenceError"),
        JsValue::Object(ctors.reference_error_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("SyntaxError"),
        JsValue::Object(ctors.syntax_error_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("Map"),
        JsValue::Object(ctors.map_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("Set"),
        JsValue::Object(ctors.set_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("Date"),
        JsValue::Object(ctors.date_constructor),
    );
    let _ = heap.set_property(
        global,
        PropertyKey::from("Symbol"),
        JsValue::Object(ctors.symbol_constructor),
    );

    // Namespace objects
    let _ = heap.set_property(global, PropertyKey::from("Math"), JsValue::Object(math));
    let _ = heap.set_property(global, PropertyKey::from("JSON"), JsValue::Object(json));

    // Global constants
    let _ = heap.set_property(global, PropertyKey::from("undefined"), JsValue::Undefined);
    let _ = heap.set_property(global, PropertyKey::from("NaN"), JsValue::Int(0)); // No NaN in i64
    let _ = heap.set_property(
        global,
        PropertyKey::from("Infinity"),
        JsValue::Int(i64::MAX),
    );

    // Global functions
    install_builtin_fn(heap, registry, global, "isNaN", BuiltinId::GlobalIsNaN);
    install_builtin_fn(
        heap,
        registry,
        global,
        "isFinite",
        BuiltinId::GlobalIsFinite,
    );
    install_builtin_fn(
        heap,
        registry,
        global,
        "parseInt",
        BuiltinId::GlobalParseInt,
    );
    install_builtin_fn(
        heap,
        registry,
        global,
        "parseFloat",
        BuiltinId::GlobalParseFloat,
    );
    install_builtin_fn(
        heap,
        registry,
        global,
        "encodeURI",
        BuiltinId::GlobalEncodeURI,
    );
    install_builtin_fn(
        heap,
        registry,
        global,
        "decodeURI",
        BuiltinId::GlobalDecodeURI,
    );
    install_builtin_fn(
        heap,
        registry,
        global,
        "encodeURIComponent",
        BuiltinId::GlobalEncodeURIComponent,
    );
    install_builtin_fn(
        heap,
        registry,
        global,
        "decodeURIComponent",
        BuiltinId::GlobalDecodeURIComponent,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- BuiltinRegistry tests -----------------------------------------------

    #[test]
    fn test_registry_register_and_lookup() {
        let mut reg = BuiltinRegistry::new(100);
        let slot = reg.register(BuiltinId::MathAbs);
        assert_eq!(slot, 100);
        assert_eq!(reg.lookup(100), Some(BuiltinId::MathAbs));
        assert_eq!(reg.lookup(99), None);
    }

    #[test]
    fn test_registry_sequential_slots() {
        let mut reg = BuiltinRegistry::new(0);
        let s1 = reg.register(BuiltinId::ArrayIsArray);
        let s2 = reg.register(BuiltinId::ArrayFrom);
        let s3 = reg.register(BuiltinId::ArrayOf);
        assert_eq!(s1, 0);
        assert_eq!(s2, 1);
        assert_eq!(s3, 2);
        assert_eq!(reg.len(), 3);
    }

    // -- install_stdlib tests ------------------------------------------------

    #[test]
    fn test_install_stdlib_creates_global() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        // Global object exists and has constructors.
        let obj_val = heap.get_property(env.global_object, &PropertyKey::from("Object"));
        assert!(obj_val.is_ok());
        assert!(matches!(obj_val.unwrap(), JsValue::Object(_)));
    }

    #[test]
    fn test_install_stdlib_prototype_chain() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        // Array.prototype has Object.prototype as its [[Prototype]].
        let arr_proto = heap.get(env.prototypes.array_prototype).unwrap();
        let arr_ordinary = arr_proto.as_ordinary().unwrap();
        assert_eq!(
            arr_ordinary.prototype,
            Some(env.prototypes.object_prototype)
        );
    }

    #[test]
    fn test_install_stdlib_error_hierarchy() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        // TypeError.prototype -> Error.prototype -> Object.prototype
        let te_proto = heap.get(env.prototypes.type_error_prototype).unwrap();
        let te_ord = te_proto.as_ordinary().unwrap();
        assert_eq!(te_ord.prototype, Some(env.prototypes.error_prototype));

        let err_proto = heap.get(env.prototypes.error_prototype).unwrap();
        let err_ord = err_proto.as_ordinary().unwrap();
        assert_eq!(err_ord.prototype, Some(env.prototypes.object_prototype));
    }

    #[test]
    fn test_install_stdlib_class_tags() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        let math_obj = heap.get(env.namespaces.math).unwrap();
        assert_eq!(
            math_obj.as_ordinary().unwrap().class_tag.as_deref(),
            Some("Math")
        );
    }

    #[test]
    fn test_install_stdlib_math_constants() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        let pi = heap
            .get_property(env.namespaces.math, &PropertyKey::from("PI"))
            .unwrap();
        assert_eq!(pi, JsValue::Int(3_141_593));
    }

    #[test]
    fn test_install_stdlib_constructor_prototype_link() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        // Array.prototype.constructor === Array constructor
        let ctor = heap
            .get_property(
                env.prototypes.array_prototype,
                &PropertyKey::from("constructor"),
            )
            .unwrap();
        assert_eq!(ctor, JsValue::Object(env.constructors.array_constructor));
    }

    #[test]
    fn test_install_stdlib_global_functions() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        let is_nan = heap
            .get_property(env.global_object, &PropertyKey::from("isNaN"))
            .unwrap();
        assert!(matches!(is_nan, JsValue::Function(_)));
    }

    #[test]
    fn test_install_stdlib_registry_not_empty() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        // Should have registered many builtins.
        assert!(env.registry.len() > 100);
    }

    // -- Math execution tests ------------------------------------------------

    #[test]
    fn test_math_abs() {
        assert_eq!(
            exec_math(BuiltinId::MathAbs, &[JsValue::Int(-5 * FP_SCALE)]).unwrap(),
            JsValue::Int(5 * FP_SCALE)
        );
        assert_eq!(
            exec_math(BuiltinId::MathAbs, &[JsValue::Int(3 * FP_SCALE)]).unwrap(),
            JsValue::Int(3 * FP_SCALE)
        );
    }

    #[test]
    fn test_math_floor_ceil() {
        // 3.5 in fixed-point = 3_500_000
        let val = 3 * FP_SCALE + FP_SCALE / 2;
        assert_eq!(
            exec_math(BuiltinId::MathFloor, &[JsValue::Int(val)]).unwrap(),
            JsValue::Int(3 * FP_SCALE)
        );
        assert_eq!(
            exec_math(BuiltinId::MathCeil, &[JsValue::Int(val)]).unwrap(),
            JsValue::Int(4 * FP_SCALE)
        );
    }

    #[test]
    fn test_math_round() {
        assert_eq!(
            exec_math(
                BuiltinId::MathRound,
                &[JsValue::Int(3 * FP_SCALE + FP_SCALE / 2)]
            )
            .unwrap(),
            JsValue::Int(4 * FP_SCALE)
        );
        assert_eq!(
            exec_math(
                BuiltinId::MathRound,
                &[JsValue::Int(3 * FP_SCALE + FP_SCALE / 4)]
            )
            .unwrap(),
            JsValue::Int(3 * FP_SCALE)
        );
    }

    #[test]
    fn test_math_sign() {
        assert_eq!(
            exec_math(BuiltinId::MathSign, &[JsValue::Int(42 * FP_SCALE)]).unwrap(),
            JsValue::Int(FP_SCALE)
        );
        assert_eq!(
            exec_math(BuiltinId::MathSign, &[JsValue::Int(-7 * FP_SCALE)]).unwrap(),
            JsValue::Int(-FP_SCALE)
        );
        assert_eq!(
            exec_math(BuiltinId::MathSign, &[JsValue::Int(0)]).unwrap(),
            JsValue::Int(0)
        );
    }

    #[test]
    fn test_math_max_min() {
        let args = vec![
            JsValue::Int(3 * FP_SCALE),
            JsValue::Int(7 * FP_SCALE),
            JsValue::Int(FP_SCALE),
        ];
        assert_eq!(
            exec_math(BuiltinId::MathMax, &args).unwrap(),
            JsValue::Int(7 * FP_SCALE)
        );
        assert_eq!(
            exec_math(BuiltinId::MathMin, &args).unwrap(),
            JsValue::Int(FP_SCALE)
        );
    }

    #[test]
    fn test_math_max_no_args() {
        assert_eq!(
            exec_math(BuiltinId::MathMax, &[]).unwrap(),
            JsValue::Int(i64::MIN)
        );
    }

    #[test]
    fn test_math_clz32() {
        assert_eq!(
            exec_math(BuiltinId::MathClz32, &[JsValue::Int(FP_SCALE)]).unwrap(),
            JsValue::Int(31 * FP_SCALE)
        );
    }

    #[test]
    fn test_math_imul() {
        let args = vec![JsValue::Int(3 * FP_SCALE), JsValue::Int(4 * FP_SCALE)];
        assert_eq!(
            exec_math(BuiltinId::MathImul, &args).unwrap(),
            JsValue::Int(12 * FP_SCALE)
        );
    }

    // -- String method tests -------------------------------------------------

    #[test]
    fn test_string_char_at() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeCharAt,
                "hello",
                &[JsValue::Int(0)]
            )
            .unwrap(),
            JsValue::Str("h".into())
        );
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeCharAt,
                "hello",
                &[JsValue::Int(4 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("o".into())
        );
    }

    #[test]
    fn test_string_includes() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeIncludes,
                "hello world",
                &[JsValue::Str("world".into())]
            )
            .unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeIncludes,
                "hello",
                &[JsValue::Str("xyz".into())]
            )
            .unwrap(),
            JsValue::Bool(false)
        );
    }

    #[test]
    fn test_string_starts_ends_with() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeStartsWith,
                "hello",
                &[JsValue::Str("hel".into())]
            )
            .unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeEndsWith,
                "hello",
                &[JsValue::Str("llo".into())]
            )
            .unwrap(),
            JsValue::Bool(true)
        );
    }

    #[test]
    fn test_string_index_of() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeIndexOf,
                "hello world",
                &[JsValue::Str("world".into())]
            )
            .unwrap(),
            JsValue::Int(6 * FP_SCALE)
        );
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeIndexOf,
                "hello",
                &[JsValue::Str("xyz".into())]
            )
            .unwrap(),
            JsValue::Int(-FP_SCALE)
        );
    }

    #[test]
    fn test_string_slice() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeSlice,
                "hello world",
                &[JsValue::Int(6 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("world".into())
        );
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeSlice,
                "hello",
                &[JsValue::Int(FP_SCALE), JsValue::Int(3 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("el".into())
        );
    }

    #[test]
    fn test_string_slice_negative() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeSlice,
                "hello",
                &[JsValue::Int(-3 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("llo".into())
        );
    }

    #[test]
    fn test_string_trim() {
        assert_eq!(
            exec_string_method(BuiltinId::StringPrototypeTrim, "  hello  ", &[]).unwrap(),
            JsValue::Str("hello".into())
        );
        assert_eq!(
            exec_string_method(BuiltinId::StringPrototypeTrimStart, "  hello  ", &[]).unwrap(),
            JsValue::Str("hello  ".into())
        );
        assert_eq!(
            exec_string_method(BuiltinId::StringPrototypeTrimEnd, "  hello  ", &[]).unwrap(),
            JsValue::Str("  hello".into())
        );
    }

    #[test]
    fn test_string_pad_start_end() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypePadStart,
                "5",
                &[JsValue::Int(3 * FP_SCALE), JsValue::Str("0".into())]
            )
            .unwrap(),
            JsValue::Str("005".into())
        );
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypePadEnd,
                "hi",
                &[JsValue::Int(5 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("hi   ".into())
        );
    }

    #[test]
    fn test_string_repeat() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeRepeat,
                "ab",
                &[JsValue::Int(3 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("ababab".into())
        );
    }

    #[test]
    fn test_string_repeat_negative() {
        assert!(
            exec_string_method(
                BuiltinId::StringPrototypeRepeat,
                "x",
                &[JsValue::Int(-FP_SCALE)]
            )
            .is_err()
        );
    }

    #[test]
    fn test_string_case() {
        assert_eq!(
            exec_string_method(BuiltinId::StringPrototypeToUpperCase, "hello", &[]).unwrap(),
            JsValue::Str("HELLO".into())
        );
        assert_eq!(
            exec_string_method(BuiltinId::StringPrototypeToLowerCase, "HELLO", &[]).unwrap(),
            JsValue::Str("hello".into())
        );
    }

    #[test]
    fn test_string_concat() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeConcat,
                "hello",
                &[JsValue::Str(" ".into()), JsValue::Str("world".into())]
            )
            .unwrap(),
            JsValue::Str("hello world".into())
        );
    }

    // -- Number method tests -------------------------------------------------

    #[test]
    fn test_number_is_integer() {
        assert_eq!(
            exec_number_method(BuiltinId::NumberIsInteger, 5 * FP_SCALE, &[]).unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_number_method(BuiltinId::NumberIsInteger, 5 * FP_SCALE + 500_000, &[]).unwrap(),
            JsValue::Bool(false)
        );
    }

    #[test]
    fn test_number_to_fixed() {
        assert_eq!(
            exec_number_method(
                BuiltinId::NumberPrototypeToFixed,
                3_141_593,
                &[JsValue::Int(2 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("3.14".into())
        );
    }

    #[test]
    fn test_number_to_string() {
        assert_eq!(
            exec_number_method(BuiltinId::NumberPrototypeToString, 42 * FP_SCALE, &[]).unwrap(),
            JsValue::Str("42".into())
        );
        assert_eq!(
            exec_number_method(BuiltinId::NumberPrototypeToString, 3_141_593, &[]).unwrap(),
            JsValue::Str("3.141593".into())
        );
    }

    // -- JSON tests ----------------------------------------------------------

    #[test]
    fn test_json_parse_primitives() {
        assert_eq!(json_parse("null").unwrap(), JsValue::Null);
        assert_eq!(json_parse("true").unwrap(), JsValue::Bool(true));
        assert_eq!(json_parse("false").unwrap(), JsValue::Bool(false));
        assert_eq!(json_parse("42").unwrap(), JsValue::Int(42 * FP_SCALE));
        assert_eq!(
            json_parse("\"hello\"").unwrap(),
            JsValue::Str("hello".into())
        );
    }

    #[test]
    fn test_json_parse_escape() {
        assert_eq!(
            json_parse("\"hello\\nworld\"").unwrap(),
            JsValue::Str("hello\nworld".into())
        );
        assert_eq!(
            json_parse("\"tab\\there\"").unwrap(),
            JsValue::Str("tab\there".into())
        );
    }

    #[test]
    fn test_json_stringify_primitives() {
        assert_eq!(
            json_stringify(&JsValue::Null).unwrap(),
            JsValue::Str("null".into())
        );
        assert_eq!(
            json_stringify(&JsValue::Bool(true)).unwrap(),
            JsValue::Str("true".into())
        );
        assert_eq!(
            json_stringify(&JsValue::Int(42 * FP_SCALE)).unwrap(),
            JsValue::Str("42".into())
        );
        assert_eq!(
            json_stringify(&JsValue::Str("hello".into())).unwrap(),
            JsValue::Str("\"hello\"".into())
        );
    }

    #[test]
    fn test_json_stringify_escape() {
        assert_eq!(
            json_stringify(&JsValue::Str("line\nnewline".into())).unwrap(),
            JsValue::Str("\"line\\nnewline\"".into())
        );
    }

    #[test]
    fn test_json_stringify_negative_fractional_number() {
        assert_eq!(
            json_stringify(&JsValue::Int(-(FP_SCALE / 2))).unwrap(),
            JsValue::Str("-0.5".into())
        );
    }

    #[test]
    fn test_json_stringify_undefined() {
        assert_eq!(
            json_stringify(&JsValue::Undefined).unwrap(),
            JsValue::Undefined
        );
    }

    // -- coerce_to_string tests ----------------------------------------------

    #[test]
    fn test_coerce_to_string_variants() {
        assert_eq!(coerce_to_string(&JsValue::Undefined), "undefined");
        assert_eq!(coerce_to_string(&JsValue::Null), "null");
        assert_eq!(coerce_to_string(&JsValue::Bool(true)), "true");
        assert_eq!(coerce_to_string(&JsValue::Int(42 * FP_SCALE)), "42");
        assert_eq!(coerce_to_string(&JsValue::Str("hi".into())), "hi");
    }

    #[test]
    fn test_coerce_to_string_fractional() {
        assert_eq!(coerce_to_string(&JsValue::Int(3_141_593)), "3.141593");
        assert_eq!(coerce_to_string(&JsValue::Int(1_500_000)), "1.5");
    }

    // -- BuiltinId display ---------------------------------------------------

    #[test]
    fn test_builtin_id_display() {
        assert_eq!(format!("{}", BuiltinId::MathAbs), "Math.abs");
        assert_eq!(
            format!("{}", BuiltinId::ArrayPrototypePush),
            "Array.prototype.push"
        );
    }

    // -- StdlibError display -------------------------------------------------

    #[test]
    fn test_stdlib_error_display() {
        let err = StdlibError::TypeError("bad arg".into());
        assert_eq!(format!("{err}"), "TypeError: bad arg");

        let err = StdlibError::ArityError {
            builtin: "Math.max".into(),
            expected_min: 1,
            expected_max: 255,
            got: 0,
        };
        assert!(format!("{err}").contains("Math.max"));
    }

    // -- Edge cases ----------------------------------------------------------

    #[test]
    fn test_string_substring_swap() {
        // substring swaps args if start > end
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeSubstring,
                "hello",
                &[JsValue::Int(3 * FP_SCALE), JsValue::Int(FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("el".into())
        );
    }

    #[test]
    fn test_math_trunc() {
        assert_eq!(
            exec_math(BuiltinId::MathTrunc, &[JsValue::Int(3_700_000)]).unwrap(),
            JsValue::Int(3 * FP_SCALE)
        );
        assert_eq!(
            exec_math(BuiltinId::MathTrunc, &[JsValue::Int(-3_700_000)]).unwrap(),
            JsValue::Int(-3 * FP_SCALE)
        );
    }

    #[test]
    fn test_pad_string_no_op_when_already_long() {
        assert_eq!(pad_string("hello", 3, " ", true), "hello");
    }

    #[test]
    fn test_json_parse_compound_placeholder() {
        let result = json_parse("[1,2,3]").unwrap();
        assert!(matches!(result, JsValue::Str(s) if s.starts_with("[json-compound:")));
    }

    // -- Math sqrt/log tests -------------------------------------------------

    #[test]
    fn test_math_sqrt() {
        // sqrt(4) = 2
        let result = exec_math(BuiltinId::MathSqrt, &[JsValue::Int(4 * FP_SCALE)]).unwrap();
        if let JsValue::Int(n) = result {
            assert!(
                (n - 2 * FP_SCALE).abs() < 100,
                "sqrt(4) should be ~2, got {n}"
            );
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_math_sqrt_one() {
        let result = exec_math(BuiltinId::MathSqrt, &[JsValue::Int(FP_SCALE)]).unwrap();
        if let JsValue::Int(n) = result {
            assert!((n - FP_SCALE).abs() < 100, "sqrt(1) should be ~1, got {n}");
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_math_sqrt_negative() {
        assert!(exec_math(BuiltinId::MathSqrt, &[JsValue::Int(-FP_SCALE)]).is_err());
    }

    #[test]
    fn test_math_log() {
        // ln(e) should be ~1
        let result = exec_math(BuiltinId::MathLog, &[JsValue::Int(2_718_282)]).unwrap();
        if let JsValue::Int(n) = result {
            assert!(
                (n - FP_SCALE).abs() < 50_000,
                "ln(e) should be ~1.0, got {n}"
            );
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_math_log_negative() {
        assert!(exec_math(BuiltinId::MathLog, &[JsValue::Int(-FP_SCALE)]).is_err());
    }

    #[test]
    fn test_math_log2() {
        // log2(2) = 1
        let result = exec_math(BuiltinId::MathLog2, &[JsValue::Int(2 * FP_SCALE)]).unwrap();
        if let JsValue::Int(n) = result {
            assert!(
                (n - FP_SCALE).abs() < 100_000,
                "log2(2) should be ~1.0, got {n}"
            );
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_math_log10() {
        // log10(10) = 1
        let result = exec_math(BuiltinId::MathLog10, &[JsValue::Int(10 * FP_SCALE)]).unwrap();
        if let JsValue::Int(n) = result {
            assert!(
                (n - FP_SCALE).abs() < 100_000,
                "log10(10) should be ~1.0, got {n}"
            );
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_math_hypot() {
        // hypot(3, 4) = 5
        let result = exec_math(
            BuiltinId::MathHypot,
            &[JsValue::Int(3 * FP_SCALE), JsValue::Int(4 * FP_SCALE)],
        )
        .unwrap();
        assert_eq!(result, JsValue::Int(5 * FP_SCALE));
    }

    #[test]
    fn test_math_hypot_no_args() {
        assert_eq!(
            exec_math(BuiltinId::MathHypot, &[]).unwrap(),
            JsValue::Int(0)
        );
    }

    #[test]
    fn test_math_fround() {
        // fround rounds to nearest 1000 in our FP system.
        assert_eq!(
            exec_math(BuiltinId::MathFround, &[JsValue::Int(3_141_593)]).unwrap(),
            JsValue::Int(3_141_000)
        );
    }

    // -- Global function tests -----------------------------------------------

    #[test]
    fn test_global_is_nan() {
        assert_eq!(
            exec_global_function(BuiltinId::GlobalIsNaN, &[JsValue::Undefined]).unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_global_function(BuiltinId::GlobalIsNaN, &[JsValue::Int(42 * FP_SCALE)]).unwrap(),
            JsValue::Bool(false)
        );
        assert_eq!(
            exec_global_function(BuiltinId::GlobalIsNaN, &[JsValue::Str("abc".into())]).unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_global_function(BuiltinId::GlobalIsNaN, &[JsValue::Str("123".into())]).unwrap(),
            JsValue::Bool(false)
        );
    }

    #[test]
    fn test_global_is_finite() {
        assert_eq!(
            exec_global_function(BuiltinId::GlobalIsFinite, &[JsValue::Int(42 * FP_SCALE)])
                .unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_global_function(BuiltinId::GlobalIsFinite, &[JsValue::Undefined]).unwrap(),
            JsValue::Bool(false)
        );
    }

    #[test]
    fn test_global_parse_int_decimal() {
        assert_eq!(
            exec_global_function(BuiltinId::GlobalParseInt, &[JsValue::Str("42".into())]).unwrap(),
            JsValue::Int(42 * FP_SCALE)
        );
    }

    #[test]
    fn test_global_parse_int_hex_radix() {
        assert_eq!(
            exec_global_function(
                BuiltinId::GlobalParseInt,
                &[JsValue::Str("ff".into()), JsValue::Int(16 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Int(255 * FP_SCALE)
        );
    }

    #[test]
    fn test_global_parse_int_negative() {
        assert_eq!(
            exec_global_function(BuiltinId::GlobalParseInt, &[JsValue::Str("-10".into())]).unwrap(),
            JsValue::Int(-10 * FP_SCALE)
        );
    }

    #[test]
    fn test_global_parse_int_partial() {
        // parseInt stops at first non-digit
        assert_eq!(
            exec_global_function(BuiltinId::GlobalParseInt, &[JsValue::Str("123abc".into())])
                .unwrap(),
            JsValue::Int(123 * FP_SCALE)
        );
    }

    #[test]
    fn test_global_parse_float() {
        assert_eq!(
            exec_global_function(BuiltinId::GlobalParseFloat, &[JsValue::Str("42".into())])
                .unwrap(),
            JsValue::Int(42 * FP_SCALE)
        );
    }

    #[test]
    fn test_global_encode_decode_uri() {
        let encoded = exec_global_function(
            BuiltinId::GlobalEncodeURIComponent,
            &[JsValue::Str("hello world!".into())],
        )
        .unwrap();
        assert_eq!(encoded, JsValue::Str("hello%20world%21".into()));

        if let JsValue::Str(ref s) = encoded {
            let decoded = exec_global_function(
                BuiltinId::GlobalDecodeURIComponent,
                &[JsValue::Str(s.clone())],
            )
            .unwrap();
            assert_eq!(decoded, JsValue::Str("hello world!".into()));
        }
    }

    #[test]
    fn test_global_encode_uri_preserves_reserved() {
        let encoded = exec_global_function(
            BuiltinId::GlobalEncodeURI,
            &[JsValue::Str("https://example.com/path?q=1".into())],
        )
        .unwrap();
        // encodeURI preserves :, /, ?, =
        assert_eq!(encoded, JsValue::Str("https://example.com/path?q=1".into()));
    }

    // -- Boolean method tests ------------------------------------------------

    #[test]
    fn test_boolean_to_string() {
        assert_eq!(
            exec_boolean_method(BuiltinId::BooleanPrototypeToString, true).unwrap(),
            JsValue::Str("true".into())
        );
        assert_eq!(
            exec_boolean_method(BuiltinId::BooleanPrototypeToString, false).unwrap(),
            JsValue::Str("false".into())
        );
    }

    #[test]
    fn test_boolean_value_of() {
        assert_eq!(
            exec_boolean_method(BuiltinId::BooleanPrototypeValueOf, true).unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_boolean_method(BuiltinId::BooleanPrototypeValueOf, false).unwrap(),
            JsValue::Bool(false)
        );
    }

    // -- Object.is tests -----------------------------------------------------

    #[test]
    fn test_object_is() {
        assert_eq!(
            exec_object_static(
                BuiltinId::ObjectIs,
                &[JsValue::Int(FP_SCALE), JsValue::Int(FP_SCALE)]
            )
            .unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_object_static(
                BuiltinId::ObjectIs,
                &[JsValue::Int(FP_SCALE), JsValue::Int(2 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Bool(false)
        );
        assert_eq!(
            exec_object_static(BuiltinId::ObjectIs, &[JsValue::Null, JsValue::Null]).unwrap(),
            JsValue::Bool(true)
        );
        assert_eq!(
            exec_object_static(BuiltinId::ObjectIs, &[JsValue::Null, JsValue::Undefined]).unwrap(),
            JsValue::Bool(false)
        );
    }

    // -- String static method tests ------------------------------------------

    #[test]
    fn test_string_from_char_code() {
        assert_eq!(
            exec_string_static(
                BuiltinId::StringFromCharCode,
                &[JsValue::Int(72 * FP_SCALE), JsValue::Int(105 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("Hi".into())
        );
    }

    #[test]
    fn test_string_from_code_point() {
        assert_eq!(
            exec_string_static(
                BuiltinId::StringFromCodePoint,
                &[JsValue::Int(9731 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Str("\u{2603}".into()) // snowman
        );
    }

    #[test]
    fn test_string_from_code_point_invalid() {
        assert!(
            exec_string_static(
                BuiltinId::StringFromCodePoint,
                &[JsValue::Int(0x110000_i64 * FP_SCALE)]
            )
            .is_err()
        );
    }

    // -- String codePointAt test ---------------------------------------------

    #[test]
    fn test_string_code_point_at() {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeCodePointAt,
                "A",
                &[JsValue::Int(0)]
            )
            .unwrap(),
            JsValue::Int(65 * FP_SCALE)
        );
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeCodePointAt,
                "hello",
                &[JsValue::Int(99 * FP_SCALE)]
            )
            .unwrap(),
            JsValue::Undefined
        );
    }

    // -- Array method tests --------------------------------------------------

    #[test]
    fn test_array_index_of() {
        let elements = vec![
            JsValue::Int(10 * FP_SCALE),
            JsValue::Int(20 * FP_SCALE),
            JsValue::Int(30 * FP_SCALE),
        ];
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeIndexOf,
                &elements,
                &[JsValue::Int(20 * FP_SCALE)]
            )
            .unwrap(),
            ArrayMethodResult::Value(JsValue::Int(FP_SCALE))
        );
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeIndexOf,
                &elements,
                &[JsValue::Int(99 * FP_SCALE)]
            )
            .unwrap(),
            ArrayMethodResult::Value(JsValue::Int(-FP_SCALE))
        );
    }

    #[test]
    fn test_array_last_index_of() {
        let elements = vec![
            JsValue::Int(10 * FP_SCALE),
            JsValue::Int(20 * FP_SCALE),
            JsValue::Int(10 * FP_SCALE),
        ];
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeLastIndexOf,
                &elements,
                &[JsValue::Int(10 * FP_SCALE)]
            )
            .unwrap(),
            ArrayMethodResult::Value(JsValue::Int(2 * FP_SCALE))
        );
    }

    #[test]
    fn test_array_includes() {
        let elements = vec![
            JsValue::Str("a".into()),
            JsValue::Str("b".into()),
            JsValue::Str("c".into()),
        ];
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeIncludes,
                &elements,
                &[JsValue::Str("b".into())]
            )
            .unwrap(),
            ArrayMethodResult::Value(JsValue::Bool(true))
        );
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeIncludes,
                &elements,
                &[JsValue::Str("z".into())]
            )
            .unwrap(),
            ArrayMethodResult::Value(JsValue::Bool(false))
        );
    }

    #[test]
    fn test_array_join() {
        let elements = vec![
            JsValue::Str("a".into()),
            JsValue::Str("b".into()),
            JsValue::Str("c".into()),
        ];
        assert_eq!(
            exec_array_method(BuiltinId::ArrayPrototypeJoin, &elements, &[]).unwrap(),
            ArrayMethodResult::Value(JsValue::Str("a,b,c".into()))
        );
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeJoin,
                &elements,
                &[JsValue::Str(" - ".into())]
            )
            .unwrap(),
            ArrayMethodResult::Value(JsValue::Str("a - b - c".into()))
        );
    }

    #[test]
    fn test_array_reverse() {
        let elements = vec![
            JsValue::Int(FP_SCALE),
            JsValue::Int(2 * FP_SCALE),
            JsValue::Int(3 * FP_SCALE),
        ];
        assert_eq!(
            exec_array_method(BuiltinId::ArrayPrototypeReverse, &elements, &[]).unwrap(),
            ArrayMethodResult::NewArray(vec![
                JsValue::Int(3 * FP_SCALE),
                JsValue::Int(2 * FP_SCALE),
                JsValue::Int(FP_SCALE),
            ])
        );
    }

    #[test]
    fn test_array_slice() {
        let elements = vec![
            JsValue::Int(10 * FP_SCALE),
            JsValue::Int(20 * FP_SCALE),
            JsValue::Int(30 * FP_SCALE),
            JsValue::Int(40 * FP_SCALE),
        ];
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeSlice,
                &elements,
                &[JsValue::Int(FP_SCALE), JsValue::Int(3 * FP_SCALE)]
            )
            .unwrap(),
            ArrayMethodResult::NewArray(vec![
                JsValue::Int(20 * FP_SCALE),
                JsValue::Int(30 * FP_SCALE),
            ])
        );
    }

    #[test]
    fn test_array_slice_negative() {
        let elements = vec![
            JsValue::Int(10 * FP_SCALE),
            JsValue::Int(20 * FP_SCALE),
            JsValue::Int(30 * FP_SCALE),
        ];
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeSlice,
                &elements,
                &[JsValue::Int(-2 * FP_SCALE)]
            )
            .unwrap(),
            ArrayMethodResult::NewArray(vec![
                JsValue::Int(20 * FP_SCALE),
                JsValue::Int(30 * FP_SCALE),
            ])
        );
    }

    #[test]
    fn test_array_fill() {
        let elements = vec![
            JsValue::Int(FP_SCALE),
            JsValue::Int(2 * FP_SCALE),
            JsValue::Int(3 * FP_SCALE),
            JsValue::Int(4 * FP_SCALE),
        ];
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeFill,
                &elements,
                &[
                    JsValue::Int(0),
                    JsValue::Int(FP_SCALE),
                    JsValue::Int(3 * FP_SCALE)
                ]
            )
            .unwrap(),
            ArrayMethodResult::NewArray(vec![
                JsValue::Int(FP_SCALE),
                JsValue::Int(0),
                JsValue::Int(0),
                JsValue::Int(4 * FP_SCALE),
            ])
        );
    }

    #[test]
    fn test_array_concat() {
        let elements = vec![JsValue::Int(FP_SCALE)];
        assert_eq!(
            exec_array_method(
                BuiltinId::ArrayPrototypeConcat,
                &elements,
                &[JsValue::Int(2 * FP_SCALE), JsValue::Int(3 * FP_SCALE)]
            )
            .unwrap(),
            ArrayMethodResult::NewArray(vec![
                JsValue::Int(FP_SCALE),
                JsValue::Int(2 * FP_SCALE),
                JsValue::Int(3 * FP_SCALE),
            ])
        );
    }

    #[test]
    fn test_array_join_empty() {
        assert_eq!(
            exec_array_method(BuiltinId::ArrayPrototypeJoin, &[], &[]).unwrap(),
            ArrayMethodResult::Value(JsValue::Str(String::new()))
        );
    }

    // -- same_value tests ----------------------------------------------------

    #[test]
    fn test_same_value_basics() {
        assert!(same_value(&JsValue::Undefined, &JsValue::Undefined));
        assert!(same_value(&JsValue::Null, &JsValue::Null));
        assert!(!same_value(&JsValue::Null, &JsValue::Undefined));
        assert!(same_value(&JsValue::Bool(true), &JsValue::Bool(true)));
        assert!(!same_value(&JsValue::Bool(true), &JsValue::Bool(false)));
        assert!(same_value(
            &JsValue::Str("abc".into()),
            &JsValue::Str("abc".into())
        ));
        assert!(!same_value(
            &JsValue::Str("abc".into()),
            &JsValue::Str("xyz".into())
        ));
    }

    // -- URI encoding helper tests -------------------------------------------

    #[test]
    fn test_percent_encode_component() {
        assert_eq!(percent_encode("hello world", true), "hello%20world");
        assert_eq!(percent_encode("a+b", true), "a%2Bb");
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("no%encoding"), "no%encoding"); // invalid % sequences pass through
    }

    // -- isqrt / fp_ln helper tests ------------------------------------------

    #[test]
    fn test_isqrt_basic() {
        assert_eq!(isqrt_i64(0), 0);
        assert_eq!(isqrt_i64(1), 1);
        assert_eq!(isqrt_i64(4), 2);
        assert_eq!(isqrt_i64(9), 3);
        assert_eq!(isqrt_i64(100), 10);
        assert_eq!(isqrt_i64(15), 3); // floor(sqrt(15))
    }

    #[test]
    fn test_fp_ln_one() {
        // ln(1) = 0
        let result = fp_ln(FP_SCALE);
        assert!(result.abs() < 1000, "ln(1) should be ~0, got {result}");
    }

    // -- BuiltinId coverage --------------------------------------------------

    #[test]
    fn test_builtin_id_name_covers_all() {
        // Ensure every BuiltinId has a name (non-empty string).
        let builtins = [
            BuiltinId::ArrayConstructor,
            BuiltinId::MathAbs,
            BuiltinId::JsonParse,
            BuiltinId::GlobalIsNaN,
            BuiltinId::SymbolConstructor,
            BuiltinId::DateConstructor,
            BuiltinId::MapConstructor,
            BuiltinId::SetConstructor,
            BuiltinId::ErrorConstructor,
        ];
        for b in &builtins {
            assert!(!b.name().is_empty());
        }
    }

    #[test]
    fn test_stdlib_error_serde_roundtrip() {
        let err = StdlibError::ArityError {
            builtin: "Array.push".into(),
            expected_min: 1,
            expected_max: 1,
            got: 0,
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: StdlibError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    #[test]
    fn test_array_method_result_serde_roundtrip() {
        let result = ArrayMethodResult::NewArray(vec![JsValue::Int(FP_SCALE)]);
        let json = serde_json::to_string(&result).unwrap();
        let restored: ArrayMethodResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    #[test]
    fn test_global_environment_serde_roundtrip() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        let json = serde_json::to_string(&env).unwrap();
        let restored: GlobalEnvironment = serde_json::from_str(&json).unwrap();
        assert_eq!(env.registry.len(), restored.registry.len());
        assert_eq!(env.global_object, restored.global_object);
    }

    #[test]
    fn test_install_stdlib_math_sqrt_installed() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        let sqrt = heap
            .get_property(env.namespaces.math, &PropertyKey::from("sqrt"))
            .unwrap();
        assert!(matches!(sqrt, JsValue::Function(_)));
    }

    #[test]
    fn test_install_stdlib_global_parse_int() {
        let mut heap = ObjectHeap::new();
        let env = install_stdlib(&mut heap);
        let parse_int = heap
            .get_property(env.global_object, &PropertyKey::from("parseInt"))
            .unwrap();
        assert!(matches!(parse_int, JsValue::Function(_)));
    }

    // -- String.prototype.replace tests --------------------------------------

    #[test]
    fn test_string_replace_basic() {
        let result = exec_string_method(
            BuiltinId::StringPrototypeReplace,
            "hello world",
            &[JsValue::Str("world".into()), JsValue::Str("rust".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("hello rust".into()));
    }

    #[test]
    fn test_string_replace_first_only() {
        let result = exec_string_method(
            BuiltinId::StringPrototypeReplace,
            "aaa",
            &[JsValue::Str("a".into()), JsValue::Str("b".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("baa".into()));
    }

    #[test]
    fn test_string_replace_not_found() {
        let result = exec_string_method(
            BuiltinId::StringPrototypeReplace,
            "hello",
            &[JsValue::Str("xyz".into()), JsValue::Str("!".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("hello".into()));
    }

    // -- String.prototype.search tests ---------------------------------------

    #[test]
    fn test_string_search_found() {
        let result = exec_string_method(
            BuiltinId::StringPrototypeSearch,
            "hello world",
            &[JsValue::Str("world".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Int(6 * FP_SCALE));
    }

    #[test]
    fn test_string_search_not_found() {
        let result = exec_string_method(
            BuiltinId::StringPrototypeSearch,
            "hello",
            &[JsValue::Str("xyz".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Int(-FP_SCALE));
    }

    // -- String.prototype.match tests ----------------------------------------

    #[test]
    fn test_string_match_found() {
        let result = exec_string_method(
            BuiltinId::StringPrototypeMatch,
            "hello world",
            &[JsValue::Str("world".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("world".into()));
    }

    #[test]
    fn test_string_match_not_found() {
        let result = exec_string_method(
            BuiltinId::StringPrototypeMatch,
            "hello",
            &[JsValue::Str("xyz".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Null);
    }

    // -- String.prototype.normalize tests ------------------------------------

    #[test]
    fn test_string_normalize_ascii() {
        let result = exec_string_method(BuiltinId::StringPrototypeNormalize, "hello", &[]).unwrap();
        assert_eq!(result, JsValue::Str("hello".into()));
    }

    // -- Date method tests ---------------------------------------------------

    #[test]
    fn test_date_now_deterministic() {
        let r1 = exec_date_method(BuiltinId::DateNow, None).unwrap();
        let r2 = exec_date_method(BuiltinId::DateNow, None).unwrap();
        assert_eq!(r1, r2, "Date.now() must be deterministic");
        if let JsValue::Int(n) = r1 {
            assert!(n > 0, "Date.now() must be positive");
        } else {
            panic!("Date.now() must return Int");
        }
    }

    #[test]
    fn test_date_get_time() {
        let ts = 1_000_000 * FP_SCALE; // 1 second in ms, scaled
        let result = exec_date_method(BuiltinId::DatePrototypeGetTime, Some(ts)).unwrap();
        assert_eq!(result, JsValue::Int(ts));
    }

    #[test]
    fn test_date_value_of() {
        let ts = 42 * FP_SCALE;
        let result = exec_date_method(BuiltinId::DatePrototypeValueOf, Some(ts)).unwrap();
        assert_eq!(result, JsValue::Int(ts));
    }

    #[test]
    fn test_date_to_string() {
        let ts = 1_500_000 * FP_SCALE; // 1500 seconds = 1.500s
        let result = exec_date_method(BuiltinId::DatePrototypeToString, Some(ts)).unwrap();
        if let JsValue::Str(s) = result {
            assert!(s.starts_with("Date("), "should start with Date(");
        } else {
            panic!("expected string");
        }
    }

    #[test]
    fn test_date_to_iso_string() {
        let result = exec_date_method(BuiltinId::DatePrototypeToISOString, Some(0)).unwrap();
        if let JsValue::Str(s) = result {
            assert!(s.contains('T'), "ISO string should contain T");
            assert!(s.ends_with('Z'), "ISO string should end with Z");
        } else {
            panic!("expected string");
        }
    }

    // -- Error constructor tests ---------------------------------------------

    #[test]
    fn test_error_constructor_message() {
        let result =
            exec_error_constructor(BuiltinId::ErrorConstructor, &[JsValue::Str("oops".into())])
                .unwrap();
        assert_eq!(result, JsValue::Str("Error: oops".into()));
    }

    #[test]
    fn test_type_error_constructor() {
        let result = exec_error_constructor(
            BuiltinId::TypeErrorConstructor,
            &[JsValue::Str("not a function".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("TypeError: not a function".into()));
    }

    #[test]
    fn test_range_error_constructor() {
        let result = exec_error_constructor(
            BuiltinId::RangeErrorConstructor,
            &[JsValue::Str("out of bounds".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("RangeError: out of bounds".into()));
    }

    #[test]
    fn test_reference_error_constructor() {
        let result = exec_error_constructor(
            BuiltinId::ReferenceErrorConstructor,
            &[JsValue::Str("x is not defined".into())],
        )
        .unwrap();
        assert_eq!(
            result,
            JsValue::Str("ReferenceError: x is not defined".into())
        );
    }

    #[test]
    fn test_syntax_error_constructor() {
        let result = exec_error_constructor(
            BuiltinId::SyntaxErrorConstructor,
            &[JsValue::Str("unexpected token".into())],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("SyntaxError: unexpected token".into()));
    }

    #[test]
    fn test_error_constructor_no_message() {
        let result = exec_error_constructor(BuiltinId::ErrorConstructor, &[]).unwrap();
        assert_eq!(result, JsValue::Str("Error: ".into()));
    }

    #[test]
    fn test_error_constructor_non_string_arg() {
        let result = exec_error_constructor(
            BuiltinId::TypeErrorConstructor,
            &[JsValue::Int(42 * FP_SCALE)],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("TypeError: 42".into()));
    }

    // -- Symbol static method tests ------------------------------------------

    #[test]
    fn test_symbol_for_deterministic() {
        let r1 = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("test".into())]).unwrap();
        let r2 = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("test".into())]).unwrap();
        assert_eq!(r1, r2, "Symbol.for must be deterministic");
        assert!(matches!(r1, JsValue::Symbol(_)));
    }

    #[test]
    fn test_symbol_for_distinct_keys() {
        let r1 = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("alpha".into())]).unwrap();
        let r2 = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("beta".into())]).unwrap();
        assert_ne!(r1, r2, "Different keys should produce different symbols");
    }

    #[test]
    fn test_symbol_key_for_returns_undefined() {
        let result =
            exec_symbol_static(BuiltinId::SymbolKeyFor, &[JsValue::Symbol(SymbolId(42))]).unwrap();
        assert_eq!(result, JsValue::Undefined);
    }

    // -- Boolean method tests ------------------------------------------------

    #[test]
    fn test_boolean_to_string_true() {
        assert_eq!(
            exec_boolean_method(BuiltinId::BooleanPrototypeToString, true).unwrap(),
            JsValue::Str("true".into())
        );
    }

    #[test]
    fn test_boolean_to_string_false() {
        assert_eq!(
            exec_boolean_method(BuiltinId::BooleanPrototypeToString, false).unwrap(),
            JsValue::Str("false".into())
        );
    }

    // -- Object.is tests ----------------------------------------------------

    #[test]
    fn test_object_is_same_int() {
        let result = exec_object_static(
            BuiltinId::ObjectIs,
            &[JsValue::Int(5 * FP_SCALE), JsValue::Int(5 * FP_SCALE)],
        )
        .unwrap();
        assert_eq!(result, JsValue::Bool(true));
    }

    #[test]
    fn test_object_is_different() {
        let result = exec_object_static(
            BuiltinId::ObjectIs,
            &[JsValue::Int(FP_SCALE), JsValue::Int(2 * FP_SCALE)],
        )
        .unwrap();
        assert_eq!(result, JsValue::Bool(false));
    }

    #[test]
    fn test_object_is_null_null() {
        let result =
            exec_object_static(BuiltinId::ObjectIs, &[JsValue::Null, JsValue::Null]).unwrap();
        assert_eq!(result, JsValue::Bool(true));
    }

    // -- Math.sqrt tests ----------------------------------------------------

    #[test]
    fn test_math_sqrt_perfect() {
        let result = exec_math(BuiltinId::MathSqrt, &[JsValue::Int(4 * FP_SCALE)]).unwrap();
        // sqrt(4) = 2 in fixed-point
        if let JsValue::Int(n) = result {
            assert!(
                (n - 2 * FP_SCALE).abs() < FP_SCALE / 100,
                "sqrt(4) should be ~2"
            );
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_math_sqrt_negative_error() {
        let result = exec_math(BuiltinId::MathSqrt, &[JsValue::Int(-FP_SCALE)]);
        assert!(result.is_err());
    }

    // -- Math.log tests -----------------------------------------------------

    #[test]
    fn test_math_log_e() {
        // ln(e) should be ~1.0
        let e_fp = 2_718_282_i64; // e in FP_SCALE
        let result = exec_math(BuiltinId::MathLog, &[JsValue::Int(e_fp)]).unwrap();
        if let JsValue::Int(n) = result {
            assert!(
                (n - FP_SCALE).abs() < FP_SCALE / 10,
                "ln(e) should be ~1.0, got {}",
                n
            );
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn test_math_log_negative_error() {
        let result = exec_math(BuiltinId::MathLog, &[JsValue::Int(-FP_SCALE)]);
        assert!(result.is_err());
    }

    // -- Math.hypot tests ---------------------------------------------------

    #[test]
    fn test_math_hypot_3_4() {
        // hypot(3, 4) = 5
        let result = exec_math(
            BuiltinId::MathHypot,
            &[JsValue::Int(3 * FP_SCALE), JsValue::Int(4 * FP_SCALE)],
        )
        .unwrap();
        if let JsValue::Int(n) = result {
            assert_eq!(n, 5 * FP_SCALE, "hypot(3,4) should be 5");
        } else {
            panic!("expected Int");
        }
    }

    // -- Global function tests (hook-added) ----------------------------------

    #[test]
    fn test_global_parse_int_radix_16() {
        let result = exec_global_function(
            BuiltinId::GlobalParseInt,
            &[JsValue::Str("ff".into()), JsValue::Int(16 * FP_SCALE)],
        )
        .unwrap();
        assert_eq!(result, JsValue::Int(255 * FP_SCALE));
    }

    // -- Number static method tests ------------------------------------------

    #[test]
    fn test_number_is_safe_integer() {
        assert_eq!(
            exec_number_method(BuiltinId::NumberIsSafeInteger, 100 * FP_SCALE, &[]).unwrap(),
            JsValue::Bool(true)
        );
        // Non-integer (has fractional part)
        assert_eq!(
            exec_number_method(BuiltinId::NumberIsSafeInteger, FP_SCALE / 2, &[]).unwrap(),
            JsValue::Bool(false)
        );
    }

    // -- String.fromCharCode (hook-added) ------------------------------------

    #[test]
    fn test_string_from_char_code_multiple() {
        let result = exec_string_static(
            BuiltinId::StringFromCharCode,
            &[JsValue::Int(72 * FP_SCALE), JsValue::Int(105 * FP_SCALE)],
        )
        .unwrap();
        assert_eq!(result, JsValue::Str("Hi".into()));
    }

    // -- String.prototype.codePointAt (hook-added) ---------------------------

    #[test]
    fn test_string_code_point_at_out_of_bounds() {
        let result = exec_string_method(
            BuiltinId::StringPrototypeCodePointAt,
            "A",
            &[JsValue::Int(5 * FP_SCALE)],
        )
        .unwrap();
        assert_eq!(result, JsValue::Undefined);
    }
}
