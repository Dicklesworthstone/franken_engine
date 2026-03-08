#![forbid(unsafe_code)]

//! Core iterator protocol substrate and replay-visible state model.
//!
//! Implements the ES2020 iterator protocol (§7.4) with deterministic replay
//! support for `for..of`, `for..in`, spread, destructuring, and collection
//! operations. Every iteration step produces a replay-visible event that can
//! be captured and verified during deterministic replay.
//!
//! Plan reference: bd-1lsy.4.8.1 [RGC-308A].

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::object_model::{PropertyKey, SymbolId, WellKnownSymbol};

// ---------------------------------------------------------------------------
// Schema versioning
// ---------------------------------------------------------------------------

pub const ITERATOR_PROTOCOL_SCHEMA_VERSION: &str = "franken-engine.iterator-protocol.v1";
pub const ITERATOR_PROTOCOL_BEAD_ID: &str = "bd-1lsy.4.8.1";

// ---------------------------------------------------------------------------
// Iterator protocol value types
// ---------------------------------------------------------------------------

/// A replay-safe representation of a runtime value for iterator protocol
/// operations. This is intentionally opaque rather than aliasing the full
/// runtime value type, so the protocol substrate can be tested, serialized,
/// and replayed independently of the runtime evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IteratorValue {
    /// Undefined value (used for the `value` field when `done: true`).
    Undefined,
    /// Null value.
    Null,
    /// Boolean value.
    Boolean(bool),
    /// Integer value (safe integer range).
    Integer(i64),
    /// String value.
    String(String),
    /// Fixed-point millionths for deterministic float representation.
    FixedPoint(i64),
    /// An opaque object reference tracked by the runtime.
    ObjectRef(EngineObjectId),
    /// An array of values (for destructuring spread).
    Array(Vec<IteratorValue>),
}

impl fmt::Display for IteratorValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => write!(f, "undefined"),
            Self::Null => write!(f, "null"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "\"{s}\""),
            Self::FixedPoint(m) => {
                let whole = m / 1_000_000;
                let frac = (m % 1_000_000).unsigned_abs();
                write!(f, "{whole}.{frac:06}")
            }
            Self::ObjectRef(id) => write!(f, "Object({id})"),
            Self::Array(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IteratorResult — the { value, done } completion record
// ---------------------------------------------------------------------------

/// ES2020 §7.4.1 IteratorResult interface: `{ value: any, done: boolean }`.
///
/// Every call to `iterator.next()` returns an IteratorResult. The protocol
/// terminates when `done` is `true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IteratorResult {
    /// The produced value. When `done` is `true`, this is typically `Undefined`.
    pub value: IteratorValue,
    /// Whether the iterator has been exhausted.
    pub done: bool,
}

impl IteratorResult {
    /// Create a non-done result with the given value.
    pub fn value(v: IteratorValue) -> Self {
        Self {
            value: v,
            done: false,
        }
    }

    /// Create a done result (value = undefined).
    pub fn done() -> Self {
        Self {
            value: IteratorValue::Undefined,
            done: true,
        }
    }

    /// Create a done result with a final value (e.g. generator return).
    pub fn done_with(v: IteratorValue) -> Self {
        Self {
            value: v,
            done: true,
        }
    }
}

// ---------------------------------------------------------------------------
// IteratorRecord — the stateful iterator handle
// ---------------------------------------------------------------------------

/// ES2020 §7.4.1 Iterator Record: `{ [[Iterator]], [[NextMethod]], [[Done]] }`.
///
/// Tracks the state of an active iteration session. The runtime creates one
/// per `for..of`, spread, or destructuring evaluation that consumes an
/// iterable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IteratorRecord {
    /// Unique id for this iterator record, used for replay correlation.
    pub record_id: EngineObjectId,
    /// Reference to the iterator object (the result of calling `@@iterator`).
    pub iterator_ref: EngineObjectId,
    /// Reference to the `next` method captured at iterator creation time.
    pub next_method_ref: EngineObjectId,
    /// Whether the iterator has been marked done.
    pub done: bool,
    /// The kind of iteration protocol used.
    pub kind: IterationKind,
    /// Step counter for replay ordering.
    pub step_count: u64,
}

/// The kind of iteration operation that created this record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IterationKind {
    /// `for..of` loop iteration.
    ForOf,
    /// `for..in` key enumeration (uses [[Enumerate]], not @@iterator).
    ForIn,
    /// Array/object destructuring `[a, b, ...rest] = iterable`.
    Destructuring,
    /// Spread in array literal `[...iterable]`.
    ArraySpread,
    /// Spread in function call `fn(...iterable)`.
    CallSpread,
    /// `yield*` delegation in a generator.
    YieldDelegate,
    /// `Array.from(iterable)` or similar collection constructor.
    CollectionConstruction,
    /// `Promise.all(iterable)` and similar Promise combinators.
    PromiseCombinator,
}

impl fmt::Display for IterationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForOf => write!(f, "for_of"),
            Self::ForIn => write!(f, "for_in"),
            Self::Destructuring => write!(f, "destructuring"),
            Self::ArraySpread => write!(f, "array_spread"),
            Self::CallSpread => write!(f, "call_spread"),
            Self::YieldDelegate => write!(f, "yield_delegate"),
            Self::CollectionConstruction => write!(f, "collection_construction"),
            Self::PromiseCombinator => write!(f, "promise_combinator"),
        }
    }
}

// ---------------------------------------------------------------------------
// Replay-visible iteration events
// ---------------------------------------------------------------------------

/// A single replay-visible event emitted during iterator protocol evaluation.
/// The replay system captures these to enable deterministic re-execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IterationEvent {
    /// The iterator record this event belongs to.
    pub record_id: EngineObjectId,
    /// Monotonic step index within this iteration (0-based).
    pub step_index: u64,
    /// The kind of protocol operation performed.
    pub operation: IterationOperation,
    /// Whether this event completed normally or abruptly.
    pub completion: IterationCompletion,
}

/// The specific iterator protocol operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterationOperation {
    /// GetIterator (§7.4.1): looked up `@@iterator` or `@@asyncIterator` and
    /// called it to obtain the iterator object.
    GetIterator {
        /// Which symbol was used to obtain the iterator.
        symbol: IteratorSymbolKind,
        /// The iterable source object reference.
        iterable_ref: EngineObjectId,
    },
    /// IteratorNext (§7.4.2): called `iterator.next(argument)`.
    IteratorNext {
        /// The result of calling `next()`.
        result: IteratorResult,
    },
    /// IteratorComplete (§7.4.3): read the `done` property.
    IteratorComplete {
        /// The boolean `done` value.
        done: bool,
    },
    /// IteratorValue (§7.4.4): read the `value` property.
    IteratorValue {
        /// The extracted value.
        value: IteratorValue,
    },
    /// IteratorClose (§7.4.6): called `iterator.return()` for early exit.
    IteratorClose {
        /// Whether the close was triggered by a normal completion or abrupt.
        reason: CloseReason,
        /// Whether `return()` existed and was called.
        return_called: bool,
    },
    /// EnumerateObjectProperties (§13.7.5.15): for `for..in` enumeration.
    EnumerateProperties {
        /// The object being enumerated.
        object_ref: EngineObjectId,
        /// The enumerated keys in deterministic order.
        keys: Vec<String>,
    },
}

/// Which well-known symbol was used to obtain the iterator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IteratorSymbolKind {
    /// `Symbol.iterator` — sync iteration.
    Iterator,
    /// `Symbol.asyncIterator` — async iteration.
    AsyncIterator,
}

impl IteratorSymbolKind {
    /// Get the well-known symbol for this kind.
    pub fn well_known_symbol(self) -> WellKnownSymbol {
        match self {
            Self::Iterator => WellKnownSymbol::Iterator,
            Self::AsyncIterator => WellKnownSymbol::AsyncIterator,
        }
    }

    /// Get the property key for looking up the iterator method.
    pub fn property_key(self) -> PropertyKey {
        self.well_known_symbol().key()
    }

    /// Get the symbol id for this kind.
    pub fn symbol_id(self) -> SymbolId {
        self.well_known_symbol().id()
    }
}

/// The reason an iterator was closed early.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReason {
    /// `break` statement in a `for..of` loop.
    Break,
    /// `return` statement inside a `for..of` loop body.
    Return,
    /// An exception was thrown during iteration.
    Throw,
    /// Destructuring consumed fewer elements than available.
    DestructuringExhausted,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Break => write!(f, "break"),
            Self::Return => write!(f, "return"),
            Self::Throw => write!(f, "throw"),
            Self::DestructuringExhausted => write!(f, "destructuring_exhausted"),
        }
    }
}

/// Whether an iteration operation completed normally or abruptly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterationCompletion {
    /// The operation completed normally.
    Normal,
    /// The iterable did not have a `@@iterator` method.
    NotIterable,
    /// The `next()` method returned a non-object result.
    InvalidResult,
    /// The `return()` method (for IteratorClose) threw an exception.
    CloseThrew,
    /// A runtime exception occurred during the operation.
    Abrupt {
        /// Error classification for replay diagnostics.
        error_kind: IterationErrorKind,
    },
}

/// Classification of iteration errors for replay diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterationErrorKind {
    /// The target is not iterable (no `@@iterator` method).
    NotIterable,
    /// The iterator method did not return an object.
    IteratorMethodNotObject,
    /// The `next()` method did not exist or was not callable.
    NextNotCallable,
    /// The `next()` result was not an object.
    NextResultNotObject,
    /// The `done` property was not boolean-coercible.
    DoneNotBoolean,
    /// A user exception was thrown during iteration body execution.
    UserException,
}

impl fmt::Display for IterationErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotIterable => write!(f, "not_iterable"),
            Self::IteratorMethodNotObject => write!(f, "iterator_method_not_object"),
            Self::NextNotCallable => write!(f, "next_not_callable"),
            Self::NextResultNotObject => write!(f, "next_result_not_object"),
            Self::DoneNotBoolean => write!(f, "done_not_boolean"),
            Self::UserException => write!(f, "user_exception"),
        }
    }
}

// ---------------------------------------------------------------------------
// Iteration trace — full replay-visible session record
// ---------------------------------------------------------------------------

/// Complete trace of an iteration session for deterministic replay.
///
/// Captures every protocol operation from `GetIterator` through final
/// `IteratorClose` (if applicable), enabling bit-stable replay verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IterationTrace {
    /// Schema version for serialization compatibility.
    pub schema_version: String,
    /// The bead id that defined this protocol substrate.
    pub bead_id: String,
    /// Unique id for this trace (for cross-referencing with other artifacts).
    pub trace_id: EngineObjectId,
    /// The iterator record that produced this trace.
    pub record_id: EngineObjectId,
    /// The kind of iteration that produced this trace.
    pub kind: IterationKind,
    /// All events in the order they occurred.
    pub events: Vec<IterationEvent>,
    /// Whether the iteration completed (done=true reached or close called).
    pub completed: bool,
    /// Total number of values produced (not counting the final done result).
    pub values_produced: u64,
}

impl IterationTrace {
    /// Create a new empty trace for an iteration session.
    pub fn new(
        trace_id: EngineObjectId,
        record_id: EngineObjectId,
        kind: IterationKind,
    ) -> Self {
        Self {
            schema_version: ITERATOR_PROTOCOL_SCHEMA_VERSION.to_string(),
            bead_id: ITERATOR_PROTOCOL_BEAD_ID.to_string(),
            trace_id,
            record_id,
            kind,
            events: Vec::new(),
            completed: false,
            values_produced: 0,
        }
    }

    /// Record an event and update trace state.
    pub fn record_event(&mut self, event: IterationEvent) {
        // Count produced values (non-done IteratorNext results)
        if let IterationOperation::IteratorNext { ref result } = event.operation {
            if !result.done {
                self.values_produced += 1;
            }
        }
        // Mark completed on done or close
        match &event.operation {
            IterationOperation::IteratorNext { result } if result.done => {
                self.completed = true;
            }
            IterationOperation::IteratorClose { .. } => {
                self.completed = true;
            }
            _ => {}
        }
        self.events.push(event);
    }
}

// ---------------------------------------------------------------------------
// For..in enumeration state
// ---------------------------------------------------------------------------

/// State model for `for..in` key enumeration.
///
/// Unlike `for..of` which uses `@@iterator`, `for..in` uses the internal
/// `[[Enumerate]]` method which walks the prototype chain and yields
/// enumerable string-keyed properties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForInEnumerationState {
    /// The object being enumerated.
    pub object_ref: EngineObjectId,
    /// The complete set of enumerable keys collected at enumeration start,
    /// in the order they will be yielded.
    pub keys: Vec<String>,
    /// Current position in the key list.
    pub current_index: usize,
    /// Keys that were deleted during enumeration (they should be skipped).
    pub deleted_keys: BTreeMap<String, bool>,
    /// Whether the enumeration has completed.
    pub done: bool,
}

impl ForInEnumerationState {
    /// Create a new enumeration state for the given object and key list.
    pub fn new(object_ref: EngineObjectId, keys: Vec<String>) -> Self {
        Self {
            object_ref,
            keys,
            current_index: 0,
            deleted_keys: BTreeMap::new(),
            done: false,
        }
    }

    /// Advance to the next key, skipping deleted keys.
    pub fn next_key(&mut self) -> Option<String> {
        while self.current_index < self.keys.len() {
            let key = &self.keys[self.current_index];
            self.current_index += 1;
            if !self.deleted_keys.contains_key(key) {
                return Some(key.clone());
            }
        }
        self.done = true;
        None
    }

    /// Mark a key as deleted (should be skipped if not yet yielded).
    pub fn mark_deleted(&mut self, key: &str) {
        self.deleted_keys.insert(key.to_string(), true);
    }

    /// Whether all keys have been yielded.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Number of keys remaining (including potentially deleted ones).
    pub fn remaining_count(&self) -> usize {
        self.keys.len().saturating_sub(self.current_index)
    }
}

// ---------------------------------------------------------------------------
// Iterator protocol error type
// ---------------------------------------------------------------------------

/// Errors that can occur during iterator protocol operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IteratorProtocolError {
    /// Error classification.
    pub kind: IterationErrorKind,
    /// Human-readable message.
    pub message: String,
    /// The iterator record id (if available).
    pub record_id: Option<EngineObjectId>,
    /// The step at which the error occurred.
    pub step_index: Option<u64>,
}

impl fmt::Display for IteratorProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IteratorProtocolError({}): {}", self.kind, self.message)
    }
}

impl IteratorProtocolError {
    /// Create a "not iterable" error.
    pub fn not_iterable(target_desc: &str) -> Self {
        Self {
            kind: IterationErrorKind::NotIterable,
            message: format!("{target_desc} is not iterable"),
            record_id: None,
            step_index: None,
        }
    }

    /// Create a "next not callable" error.
    pub fn next_not_callable(record_id: EngineObjectId) -> Self {
        Self {
            kind: IterationErrorKind::NextNotCallable,
            message: "iterator.next is not a function".to_string(),
            record_id: Some(record_id),
            step_index: None,
        }
    }

    /// Create a "next result not object" error.
    pub fn next_result_not_object(record_id: EngineObjectId, step: u64) -> Self {
        Self {
            kind: IterationErrorKind::NextResultNotObject,
            message: "iterator.next() did not return an object".to_string(),
            record_id: Some(record_id),
            step_index: Some(step),
        }
    }

    /// Create an "iterator method not object" error.
    pub fn iterator_method_not_object(target_desc: &str) -> Self {
        Self {
            kind: IterationErrorKind::IteratorMethodNotObject,
            message: format!("{target_desc}[Symbol.iterator]() did not return an object"),
            record_id: None,
            step_index: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Iterator protocol operations (pure logic layer)
// ---------------------------------------------------------------------------

/// Validate an IteratorResult: `done` must be boolean, `value` must exist.
/// Returns `(value, done)` pair on success.
pub fn validate_iterator_result(result: &IteratorResult) -> Result<(), IteratorProtocolError> {
    // In the protocol substrate, IteratorResult is already well-typed,
    // so validation always succeeds. The runtime layer performs the
    // actual type checking against raw JS values before constructing
    // the IteratorResult.
    let _ = result;
    Ok(())
}

/// Create a "normal" iteration event for recording.
pub fn make_get_iterator_event(
    record_id: EngineObjectId,
    step_index: u64,
    symbol_kind: IteratorSymbolKind,
    iterable_ref: EngineObjectId,
) -> IterationEvent {
    IterationEvent {
        record_id,
        step_index,
        operation: IterationOperation::GetIterator {
            symbol: symbol_kind,
            iterable_ref,
        },
        completion: IterationCompletion::Normal,
    }
}

/// Create an IteratorNext event.
pub fn make_next_event(
    record_id: EngineObjectId,
    step_index: u64,
    result: IteratorResult,
) -> IterationEvent {
    IterationEvent {
        record_id,
        step_index,
        operation: IterationOperation::IteratorNext { result },
        completion: IterationCompletion::Normal,
    }
}

/// Create an IteratorClose event.
pub fn make_close_event(
    record_id: EngineObjectId,
    step_index: u64,
    reason: CloseReason,
    return_called: bool,
) -> IterationEvent {
    IterationEvent {
        record_id,
        step_index,
        operation: IterationOperation::IteratorClose {
            reason,
            return_called,
        },
        completion: IterationCompletion::Normal,
    }
}

/// Create a ForIn enumeration event.
pub fn make_enumerate_event(
    record_id: EngineObjectId,
    step_index: u64,
    object_ref: EngineObjectId,
    keys: Vec<String>,
) -> IterationEvent {
    IterationEvent {
        record_id,
        step_index,
        operation: IterationOperation::EnumerateProperties { object_ref, keys },
        completion: IterationCompletion::Normal,
    }
}

/// Create an abrupt-completion event.
pub fn make_abrupt_event(
    record_id: EngineObjectId,
    step_index: u64,
    operation: IterationOperation,
    error_kind: IterationErrorKind,
) -> IterationEvent {
    IterationEvent {
        record_id,
        step_index,
        operation,
        completion: IterationCompletion::Abrupt { error_kind },
    }
}

// ---------------------------------------------------------------------------
// Spread collector — collects all values from an iterable
// ---------------------------------------------------------------------------

/// Collects values from an iteration trace into a flat array.
/// Used for array spread `[...iterable]` and call spread `fn(...iterable)`.
pub fn collect_spread_values(trace: &IterationTrace) -> Vec<IteratorValue> {
    let mut values = Vec::new();
    for event in &trace.events {
        if let IterationOperation::IteratorNext { result } = &event.operation {
            if !result.done {
                values.push(result.value.clone());
            }
        }
    }
    values
}

// ---------------------------------------------------------------------------
// Trace summary for operator diagnostics
// ---------------------------------------------------------------------------

/// Human-readable summary of an iteration trace.
pub fn render_iteration_summary(trace: &IterationTrace) -> String {
    let mut lines = vec![
        format!("schema_version: {}", trace.schema_version),
        format!("trace_id: {}", trace.trace_id),
        format!("record_id: {}", trace.record_id),
        format!("kind: {}", trace.kind),
        format!("events: {}", trace.events.len()),
        format!("values_produced: {}", trace.values_produced),
        format!("completed: {}", trace.completed),
    ];

    let abrupt_count = trace
        .events
        .iter()
        .filter(|e| !matches!(e.completion, IterationCompletion::Normal))
        .count();
    if abrupt_count > 0 {
        lines.push(format!("abrupt_completions: {abrupt_count}"));
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{ObjectDomain, derive_id};

    fn test_schema_id() -> crate::engine_object_id::SchemaId {
        crate::engine_object_id::SchemaId::from_definition(
            ITERATOR_PROTOCOL_SCHEMA_VERSION.as_bytes(),
        )
    }

    fn test_id(label: &str) -> EngineObjectId {
        derive_id(
            ObjectDomain::EvidenceRecord,
            "iterator-protocol-test",
            &test_schema_id(),
            label.as_bytes(),
        )
        .expect("derive_id should succeed")
    }

    // -- IteratorResult --

    #[test]
    fn iterator_result_value_creates_non_done() {
        let result = IteratorResult::value(IteratorValue::Integer(42));
        assert!(!result.done);
        assert_eq!(result.value, IteratorValue::Integer(42));
    }

    #[test]
    fn iterator_result_done_creates_undefined() {
        let result = IteratorResult::done();
        assert!(result.done);
        assert_eq!(result.value, IteratorValue::Undefined);
    }

    #[test]
    fn iterator_result_done_with_value() {
        let result = IteratorResult::done_with(IteratorValue::String("final".into()));
        assert!(result.done);
        assert_eq!(result.value, IteratorValue::String("final".into()));
    }

    // -- IteratorValue Display --

    #[test]
    fn iterator_value_display_undefined() {
        assert_eq!(IteratorValue::Undefined.to_string(), "undefined");
    }

    #[test]
    fn iterator_value_display_null() {
        assert_eq!(IteratorValue::Null.to_string(), "null");
    }

    #[test]
    fn iterator_value_display_boolean() {
        assert_eq!(IteratorValue::Boolean(true).to_string(), "true");
        assert_eq!(IteratorValue::Boolean(false).to_string(), "false");
    }

    #[test]
    fn iterator_value_display_integer() {
        assert_eq!(IteratorValue::Integer(42).to_string(), "42");
        assert_eq!(IteratorValue::Integer(-7).to_string(), "-7");
    }

    #[test]
    fn iterator_value_display_string() {
        assert_eq!(
            IteratorValue::String("hello".into()).to_string(),
            "\"hello\""
        );
    }

    #[test]
    fn iterator_value_display_fixed_point() {
        assert_eq!(
            IteratorValue::FixedPoint(3_141_592).to_string(),
            "3.141592"
        );
    }

    #[test]
    fn iterator_value_display_array() {
        let arr = IteratorValue::Array(vec![
            IteratorValue::Integer(1),
            IteratorValue::Integer(2),
        ]);
        assert_eq!(arr.to_string(), "[1, 2]");
    }

    #[test]
    fn iterator_value_display_empty_array() {
        assert_eq!(IteratorValue::Array(vec![]).to_string(), "[]");
    }

    // -- IterationKind Display --

    #[test]
    fn iteration_kind_display_all_variants() {
        assert_eq!(IterationKind::ForOf.to_string(), "for_of");
        assert_eq!(IterationKind::ForIn.to_string(), "for_in");
        assert_eq!(IterationKind::Destructuring.to_string(), "destructuring");
        assert_eq!(IterationKind::ArraySpread.to_string(), "array_spread");
        assert_eq!(IterationKind::CallSpread.to_string(), "call_spread");
        assert_eq!(IterationKind::YieldDelegate.to_string(), "yield_delegate");
        assert_eq!(
            IterationKind::CollectionConstruction.to_string(),
            "collection_construction"
        );
        assert_eq!(
            IterationKind::PromiseCombinator.to_string(),
            "promise_combinator"
        );
    }

    // -- IteratorSymbolKind --

    #[test]
    fn iterator_symbol_kind_well_known_symbol() {
        assert_eq!(
            IteratorSymbolKind::Iterator.well_known_symbol(),
            WellKnownSymbol::Iterator
        );
        assert_eq!(
            IteratorSymbolKind::AsyncIterator.well_known_symbol(),
            WellKnownSymbol::AsyncIterator
        );
    }

    #[test]
    fn iterator_symbol_kind_property_key() {
        let key = IteratorSymbolKind::Iterator.property_key();
        assert_eq!(key, WellKnownSymbol::Iterator.key());
    }

    // -- CloseReason Display --

    #[test]
    fn close_reason_display() {
        assert_eq!(CloseReason::Break.to_string(), "break");
        assert_eq!(CloseReason::Return.to_string(), "return");
        assert_eq!(CloseReason::Throw.to_string(), "throw");
        assert_eq!(
            CloseReason::DestructuringExhausted.to_string(),
            "destructuring_exhausted"
        );
    }

    // -- IterationErrorKind Display --

    #[test]
    fn iteration_error_kind_display() {
        assert_eq!(IterationErrorKind::NotIterable.to_string(), "not_iterable");
        assert_eq!(
            IterationErrorKind::NextNotCallable.to_string(),
            "next_not_callable"
        );
    }

    // -- IteratorProtocolError --

    #[test]
    fn error_not_iterable() {
        let err = IteratorProtocolError::not_iterable("number");
        assert_eq!(err.kind, IterationErrorKind::NotIterable);
        assert!(err.message.contains("number"));
        assert!(err.message.contains("not iterable"));
        assert!(err.record_id.is_none());
    }

    #[test]
    fn error_next_not_callable() {
        let id = test_id("rec1");
        let err = IteratorProtocolError::next_not_callable(id.clone());
        assert_eq!(err.kind, IterationErrorKind::NextNotCallable);
        assert_eq!(err.record_id, Some(id));
    }

    #[test]
    fn error_next_result_not_object() {
        let id = test_id("rec2");
        let err = IteratorProtocolError::next_result_not_object(id.clone(), 5);
        assert_eq!(err.kind, IterationErrorKind::NextResultNotObject);
        assert_eq!(err.step_index, Some(5));
    }

    #[test]
    fn error_iterator_method_not_object() {
        let err = IteratorProtocolError::iterator_method_not_object("Array");
        assert_eq!(err.kind, IterationErrorKind::IteratorMethodNotObject);
        assert!(err.message.contains("Array"));
    }

    #[test]
    fn error_display() {
        let err = IteratorProtocolError::not_iterable("42");
        let display = err.to_string();
        assert!(display.contains("IteratorProtocolError"));
        assert!(display.contains("not_iterable"));
        assert!(display.contains("42 is not iterable"));
    }

    // -- IterationTrace --

    #[test]
    fn trace_new_is_empty() {
        let trace = IterationTrace::new(test_id("t1"), test_id("r1"), IterationKind::ForOf);
        assert_eq!(trace.schema_version, ITERATOR_PROTOCOL_SCHEMA_VERSION);
        assert_eq!(trace.bead_id, ITERATOR_PROTOCOL_BEAD_ID);
        assert!(trace.events.is_empty());
        assert!(!trace.completed);
        assert_eq!(trace.values_produced, 0);
        assert_eq!(trace.kind, IterationKind::ForOf);
    }

    #[test]
    fn trace_record_next_value_increments_count() {
        let trace_id = test_id("t2");
        let record_id = test_id("r2");
        let mut trace = IterationTrace::new(trace_id, record_id.clone(), IterationKind::ForOf);

        trace.record_event(make_next_event(
            record_id.clone(),
            0,
            IteratorResult::value(IteratorValue::Integer(1)),
        ));
        assert_eq!(trace.values_produced, 1);
        assert!(!trace.completed);

        trace.record_event(make_next_event(
            record_id.clone(),
            1,
            IteratorResult::value(IteratorValue::Integer(2)),
        ));
        assert_eq!(trace.values_produced, 2);
        assert!(!trace.completed);

        trace.record_event(make_next_event(record_id, 2, IteratorResult::done()));
        assert_eq!(trace.values_produced, 2);
        assert!(trace.completed);
        assert_eq!(trace.events.len(), 3);
    }

    #[test]
    fn trace_completes_on_close() {
        let record_id = test_id("r3");
        let mut trace =
            IterationTrace::new(test_id("t3"), record_id.clone(), IterationKind::ForOf);

        trace.record_event(make_next_event(
            record_id.clone(),
            0,
            IteratorResult::value(IteratorValue::Integer(1)),
        ));
        trace.record_event(make_close_event(record_id, 1, CloseReason::Break, true));
        assert!(trace.completed);
        assert_eq!(trace.values_produced, 1);
    }

    // -- Event constructors --

    #[test]
    fn get_iterator_event() {
        let id = test_id("r4");
        let iterable = test_id("iter1");
        let event =
            make_get_iterator_event(id.clone(), 0, IteratorSymbolKind::Iterator, iterable.clone());
        assert_eq!(event.record_id, id);
        assert_eq!(event.step_index, 0);
        assert!(matches!(
            event.operation,
            IterationOperation::GetIterator {
                symbol: IteratorSymbolKind::Iterator,
                ..
            }
        ));
        assert_eq!(event.completion, IterationCompletion::Normal);
    }

    #[test]
    fn enumerate_event() {
        let id = test_id("r5");
        let obj = test_id("obj1");
        let keys = vec!["a".to_string(), "b".to_string()];
        let event = make_enumerate_event(id.clone(), 0, obj.clone(), keys.clone());
        if let IterationOperation::EnumerateProperties {
            object_ref,
            keys: event_keys,
        } = &event.operation
        {
            assert_eq!(*object_ref, obj);
            assert_eq!(*event_keys, keys);
        } else {
            panic!("expected EnumerateProperties");
        }
    }

    #[test]
    fn abrupt_event() {
        let id = test_id("r6");
        let event = make_abrupt_event(
            id.clone(),
            2,
            IterationOperation::IteratorNext {
                result: IteratorResult::done(),
            },
            IterationErrorKind::NextResultNotObject,
        );
        assert!(matches!(
            event.completion,
            IterationCompletion::Abrupt {
                error_kind: IterationErrorKind::NextResultNotObject
            }
        ));
    }

    // -- ForInEnumerationState --

    #[test]
    fn for_in_enumeration_yields_keys_in_order() {
        let obj = test_id("obj2");
        let keys = vec!["a".into(), "b".into(), "c".into()];
        let mut state = ForInEnumerationState::new(obj, keys);

        assert_eq!(state.next_key(), Some("a".into()));
        assert_eq!(state.next_key(), Some("b".into()));
        assert_eq!(state.next_key(), Some("c".into()));
        assert_eq!(state.next_key(), None);
        assert!(state.is_done());
    }

    #[test]
    fn for_in_enumeration_skips_deleted_keys() {
        let obj = test_id("obj3");
        let keys = vec!["a".into(), "b".into(), "c".into()];
        let mut state = ForInEnumerationState::new(obj, keys);

        state.mark_deleted("b");
        assert_eq!(state.next_key(), Some("a".into()));
        assert_eq!(state.next_key(), Some("c".into()));
        assert_eq!(state.next_key(), None);
    }

    #[test]
    fn for_in_enumeration_remaining_count() {
        let obj = test_id("obj4");
        let keys = vec!["x".into(), "y".into(), "z".into()];
        let mut state = ForInEnumerationState::new(obj, keys);

        assert_eq!(state.remaining_count(), 3);
        state.next_key();
        assert_eq!(state.remaining_count(), 2);
        state.next_key();
        assert_eq!(state.remaining_count(), 1);
        state.next_key();
        assert_eq!(state.remaining_count(), 0);
    }

    #[test]
    fn for_in_empty_keys() {
        let obj = test_id("obj5");
        let mut state = ForInEnumerationState::new(obj, vec![]);
        assert_eq!(state.next_key(), None);
        assert!(state.is_done());
        assert_eq!(state.remaining_count(), 0);
    }

    // -- Spread collection --

    #[test]
    fn collect_spread_values_from_trace() {
        let record_id = test_id("r7");
        let mut trace = IterationTrace::new(
            test_id("t7"),
            record_id.clone(),
            IterationKind::ArraySpread,
        );
        trace.record_event(make_next_event(
            record_id.clone(),
            0,
            IteratorResult::value(IteratorValue::Integer(10)),
        ));
        trace.record_event(make_next_event(
            record_id.clone(),
            1,
            IteratorResult::value(IteratorValue::Integer(20)),
        ));
        trace.record_event(make_next_event(record_id, 2, IteratorResult::done()));

        let values = collect_spread_values(&trace);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], IteratorValue::Integer(10));
        assert_eq!(values[1], IteratorValue::Integer(20));
    }

    #[test]
    fn collect_spread_values_empty_iterable() {
        let record_id = test_id("r8");
        let mut trace = IterationTrace::new(
            test_id("t8"),
            record_id.clone(),
            IterationKind::ArraySpread,
        );
        trace.record_event(make_next_event(record_id, 0, IteratorResult::done()));

        let values = collect_spread_values(&trace);
        assert!(values.is_empty());
    }

    // -- Serde round-trip --

    #[test]
    fn iterator_result_serde_round_trip() {
        let result = IteratorResult::value(IteratorValue::String("test".into()));
        let json = serde_json::to_string(&result).expect("serialize");
        let deserialized: IteratorResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, deserialized);
    }

    #[test]
    fn iteration_trace_serde_round_trip() {
        let record_id = test_id("r9");
        let mut trace = IterationTrace::new(
            test_id("t9"),
            record_id.clone(),
            IterationKind::Destructuring,
        );
        trace.record_event(make_get_iterator_event(
            record_id.clone(),
            0,
            IteratorSymbolKind::Iterator,
            test_id("iterable9"),
        ));
        trace.record_event(make_next_event(
            record_id.clone(),
            1,
            IteratorResult::value(IteratorValue::Integer(1)),
        ));
        trace.record_event(make_close_event(
            record_id,
            2,
            CloseReason::DestructuringExhausted,
            true,
        ));

        let json = serde_json::to_string(&trace).expect("serialize");
        let deserialized: IterationTrace = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(trace, deserialized);
    }

    #[test]
    fn iteration_event_serde_round_trip() {
        let id = test_id("r10");
        let events = vec![
            make_get_iterator_event(id.clone(), 0, IteratorSymbolKind::AsyncIterator, test_id("ai")),
            make_next_event(id.clone(), 1, IteratorResult::value(IteratorValue::Null)),
            make_close_event(id.clone(), 2, CloseReason::Throw, false),
            make_enumerate_event(id.clone(), 3, test_id("obj10"), vec!["key".into()]),
            make_abrupt_event(
                id,
                4,
                IterationOperation::IteratorNext {
                    result: IteratorResult::done(),
                },
                IterationErrorKind::UserException,
            ),
        ];
        for event in &events {
            let json = serde_json::to_string(event).expect("serialize");
            let deser: IterationEvent = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*event, deser);
        }
    }

    // -- ForInEnumerationState serde --

    #[test]
    fn for_in_state_serde_round_trip() {
        let mut state = ForInEnumerationState::new(
            test_id("obj11"),
            vec!["a".into(), "b".into(), "c".into()],
        );
        state.next_key();
        state.mark_deleted("c");

        let json = serde_json::to_string(&state).expect("serialize");
        let deser: ForInEnumerationState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, deser);
    }

    // -- Error serde --

    #[test]
    fn iterator_error_serde_round_trip() {
        let err = IteratorProtocolError::next_result_not_object(test_id("r11"), 3);
        let json = serde_json::to_string(&err).expect("serialize");
        let deser: IteratorProtocolError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, deser);
    }

    // -- Summary rendering --

    #[test]
    fn render_summary_includes_key_fields() {
        let record_id = test_id("r12");
        let mut trace =
            IterationTrace::new(test_id("t12"), record_id.clone(), IterationKind::ForOf);
        trace.record_event(make_next_event(
            record_id.clone(),
            0,
            IteratorResult::value(IteratorValue::Integer(1)),
        ));
        trace.record_event(make_next_event(record_id, 1, IteratorResult::done()));

        let summary = render_iteration_summary(&trace);
        assert!(summary.contains("schema_version:"));
        assert!(summary.contains("kind: for_of"));
        assert!(summary.contains("values_produced: 1"));
        assert!(summary.contains("completed: true"));
        assert!(summary.contains("events: 2"));
    }

    #[test]
    fn render_summary_with_abrupt_completions() {
        let record_id = test_id("r13");
        let mut trace =
            IterationTrace::new(test_id("t13"), record_id.clone(), IterationKind::ForOf);
        trace.record_event(make_abrupt_event(
            record_id,
            0,
            IterationOperation::IteratorNext {
                result: IteratorResult::done(),
            },
            IterationErrorKind::NotIterable,
        ));

        let summary = render_iteration_summary(&trace);
        assert!(summary.contains("abrupt_completions: 1"));
    }

    // -- validate_iterator_result --

    #[test]
    fn validate_well_formed_result() {
        let result = IteratorResult::value(IteratorValue::Integer(1));
        assert!(validate_iterator_result(&result).is_ok());
    }

    #[test]
    fn validate_done_result() {
        let result = IteratorResult::done();
        assert!(validate_iterator_result(&result).is_ok());
    }

    // -- IteratorValue variants --

    #[test]
    fn iterator_value_object_ref_display() {
        let id = test_id("obj_display");
        let val = IteratorValue::ObjectRef(id);
        let display = val.to_string();
        assert!(display.starts_with("Object("));
    }

    #[test]
    fn iterator_value_nested_array() {
        let val = IteratorValue::Array(vec![
            IteratorValue::Array(vec![IteratorValue::Integer(1)]),
            IteratorValue::String("x".into()),
        ]);
        let display = val.to_string();
        assert!(display.contains("[1]"));
        assert!(display.contains("\"x\""));
    }

    // -- IteratorRecord fields --

    #[test]
    fn iterator_record_construction() {
        let record = IteratorRecord {
            record_id: test_id("rec_test"),
            iterator_ref: test_id("iter_obj"),
            next_method_ref: test_id("next_fn"),
            done: false,
            kind: IterationKind::ForOf,
            step_count: 0,
        };
        assert!(!record.done);
        assert_eq!(record.step_count, 0);
        assert_eq!(record.kind, IterationKind::ForOf);
    }

    #[test]
    fn iterator_record_serde_round_trip() {
        let record = IteratorRecord {
            record_id: test_id("rec_serde"),
            iterator_ref: test_id("iter_serde"),
            next_method_ref: test_id("next_serde"),
            done: true,
            kind: IterationKind::CallSpread,
            step_count: 42,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let deser: IteratorRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, deser);
    }

    // -- Fixed-point edge cases --

    #[test]
    fn fixed_point_zero() {
        assert_eq!(IteratorValue::FixedPoint(0).to_string(), "0.000000");
    }

    #[test]
    fn fixed_point_negative() {
        assert_eq!(IteratorValue::FixedPoint(-1_500_000).to_string(), "-1.500000");
    }

    #[test]
    fn fixed_point_small_fraction() {
        assert_eq!(IteratorValue::FixedPoint(1).to_string(), "0.000001");
    }
}
