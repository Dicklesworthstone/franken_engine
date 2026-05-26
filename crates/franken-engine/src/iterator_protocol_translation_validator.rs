#![forbid(unsafe_code)]

//! Iterator-protocol translation validation (G.6.D — bd-cixqu.7.9.4).
//!
//! `for..of` / `for..in` / `IteratorClose` are IR1 opcodes lowered by
//! `iterator_protocol.rs`. G.6.D proves the lowering preserves ECMAScript
//! iterator semantics, including the critical `IteratorClose` (`.return()`)
//! call on *abrupt* completion (break / return / throw inside `for..of`).
//!
//! ECMAScript semantics modelled here:
//!   * `for..of` performs `GetIterator` (`[Symbol.iterator]()`), then repeated
//!     `IteratorNext` (`.next()`) until `done`. On **abrupt** completion
//!     (`break`, `return`, or a `throw`) it must perform `IteratorClose`
//!     (`.return()`). On **normal** exhaustion (`done: true`) it must *not*
//!     call `.return()`.
//!   * `for..in` enumerates the own + inherited enumerable string keys (in
//!     insertion / prototype-chain order, de-duplicated). It does **not** use
//!     the iterator protocol, so no `IteratorClose` is emitted.
//!
//! Validation strategy mirrors G.6.A: a single abstract iterator-protocol
//! evaluator is run over two views of the same program — a **reference** view
//! dictated by ECMAScript semantics, and a **target** view dictated by the IR
//! markers actually emitted by the lowering (`GetIterator` emitted?,
//! `IteratorClose` emitted on the abrupt path?, prototype keys enumerated?).
//! Equivalence holds iff the observable [`IterTrace`] event sequences match. A
//! "preserving-looking" transformation that drops the `IteratorClose` on an
//! early-exit path (a `.return()` leak — generators never finalised, locks
//! never released) therefore diverges from the reference and is **rejected**.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Source-level model
// ---------------------------------------------------------------------------

/// The kind of iterable a `for..of` ranges over. The `usize` is the element
/// count produced before natural exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterSource {
    Array(usize),
    MapLike(usize),
    SetLike(usize),
    /// A user-defined iterable with a `[Symbol.iterator]` returning a custom
    /// iterator (whose `.return()` must be honoured on early exit).
    Custom(usize),
}

impl IterSource {
    pub fn element_count(&self) -> usize {
        match self {
            IterSource::Array(n)
            | IterSource::MapLike(n)
            | IterSource::SetLike(n)
            | IterSource::Custom(n) => *n,
        }
    }
}

/// How a loop terminates. `usize` is the zero-based element index at which the
/// abrupt completion occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoopExit {
    /// Run to natural exhaustion.
    Complete,
    /// `break` at element index.
    BreakAt(usize),
    /// `return` at element index.
    ReturnAt(usize),
    /// `throw` at element index (the body raises at `site`).
    ThrowAt(usize, u32),
}

/// A source statement in the iterator subset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterStmt {
    /// An ordinary statement.
    Plain { site: u32 },
    /// `for (x of source) { ... }`.
    ForOf {
        loop_id: u32,
        source: IterSource,
        exit: LoopExit,
    },
    /// `for (k in object) { ... }`. `own_keys` then `proto_keys` model the
    /// enumeration order (own keys first, then prototype-chain keys, with
    /// duplicates of own keys suppressed).
    ForIn {
        loop_id: u32,
        own_keys: Vec<u32>,
        proto_keys: Vec<u32>,
        exit: LoopExit,
    },
}

// ---------------------------------------------------------------------------
// Iterator-protocol abstract state (the witness)
// ---------------------------------------------------------------------------

/// Why an iterator was closed via `IteratorClose` (`.return()`). Mirrors the
/// engine's abrupt `CloseReason` (Break / Return / Throw).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReason {
    Break,
    Return,
    Throw,
}

/// Abstract iterator-protocol state recorded after each event: how many
/// iterators are currently open (un-closed) and the last close reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IterState {
    pub open_iterators: usize,
    pub last_close: Option<CloseReason>,
}

impl IterState {
    fn initial() -> Self {
        Self {
            open_iterators: 0,
            last_close: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Observable iterator trace (the validation witness)
// ---------------------------------------------------------------------------

/// An observable event in the iterator-protocol trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterEventKind {
    /// `GetIterator` — `[Symbol.iterator]()` was invoked.
    GetIterator { loop_id: u32 },
    /// `IteratorNext` — `.next()` was invoked for element `step`.
    IteratorNext { loop_id: u32, step: usize },
    /// The loop body executed for element `step`.
    BodyStep { loop_id: u32, step: usize },
    /// `IteratorClose` — `.return()` was invoked on abrupt completion.
    IteratorClose { loop_id: u32, reason: CloseReason },
    /// The iterator reported `done: true` (natural exhaustion, no close).
    IteratorDone { loop_id: u32 },
    /// `for..in` enumerated a property key.
    ForInKey { loop_id: u32, key: u32 },
    /// Normal program completion.
    Complete,
    /// A `return` propagated out of the top level.
    ReturnOut,
    /// A `throw` propagated out of the top level.
    Propagate { site: u32 },
}

/// A trace event with the iterator-protocol state it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IterEvent {
    pub kind: IterEventKind,
    pub state_after: IterState,
}

/// An ordered iterator-protocol trace. Two traces are *equivalent* iff their
/// event-kind sequences are identical.
pub type IterTrace = Vec<IterEvent>;

// ---------------------------------------------------------------------------
// Lowered (target) model — IR markers actually emitted
// ---------------------------------------------------------------------------

/// A lowered statement carrying the iterator IR markers actually emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoweredIterStmt {
    Plain {
        site: u32,
    },
    ForOf {
        loop_id: u32,
        source: IterSource,
        exit: LoopExit,
        /// `GetIterator` (`[Symbol.iterator]()`) was emitted.
        get_iterator_emitted: bool,
        /// `IteratorClose` (`.return()`) was emitted on the abrupt path.
        iterator_close_emitted: bool,
    },
    ForIn {
        loop_id: u32,
        own_keys: Vec<u32>,
        proto_keys: Vec<u32>,
        exit: LoopExit,
        /// Prototype-chain keys are enumerated (not just own keys).
        proto_keys_enumerated: bool,
    },
}

// ---------------------------------------------------------------------------
// Evaluation view — the unified abstract interpreter operates on this
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum EvalStmt {
    /// A filler statement with no observable iterator-protocol effect.
    Plain,
    ForOf {
        loop_id: u32,
        source: IterSource,
        exit: LoopExit,
        /// Effective: a `GetIterator` step is observable.
        get_iterator: bool,
        /// Effective: `IteratorClose` runs on abrupt completion.
        close_on_abrupt: bool,
    },
    ForIn {
        loop_id: u32,
        keys: Vec<u32>,
        exit: LoopExit,
    },
}

fn dedup_keys(own: &[u32], proto: &[u32], include_proto: bool) -> Vec<u32> {
    let mut out: Vec<u32> = own.to_vec();
    if include_proto {
        for k in proto {
            if !out.contains(k) {
                out.push(*k);
            }
        }
    }
    out
}

fn to_reference_eval(stmts: &[IterStmt]) -> Vec<EvalStmt> {
    stmts
        .iter()
        .map(|s| match s {
            IterStmt::Plain { .. } => EvalStmt::Plain,
            IterStmt::ForOf {
                loop_id,
                source,
                exit,
            } => EvalStmt::ForOf {
                loop_id: *loop_id,
                source: *source,
                exit: *exit,
                get_iterator: true,
                close_on_abrupt: true,
            },
            IterStmt::ForIn {
                loop_id,
                own_keys,
                proto_keys,
                exit,
            } => EvalStmt::ForIn {
                loop_id: *loop_id,
                keys: dedup_keys(own_keys, proto_keys, true),
                exit: *exit,
            },
        })
        .collect()
}

fn to_target_eval(stmts: &[LoweredIterStmt]) -> Vec<EvalStmt> {
    stmts
        .iter()
        .map(|s| match s {
            LoweredIterStmt::Plain { .. } => EvalStmt::Plain,
            LoweredIterStmt::ForOf {
                loop_id,
                source,
                exit,
                get_iterator_emitted,
                iterator_close_emitted,
            } => EvalStmt::ForOf {
                loop_id: *loop_id,
                source: *source,
                exit: *exit,
                get_iterator: *get_iterator_emitted,
                close_on_abrupt: *iterator_close_emitted,
            },
            LoweredIterStmt::ForIn {
                loop_id,
                own_keys,
                proto_keys,
                exit,
                proto_keys_enumerated,
            } => EvalStmt::ForIn {
                loop_id: *loop_id,
                keys: dedup_keys(own_keys, proto_keys, *proto_keys_enumerated),
                exit: *exit,
            },
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Abstract iterator-protocol interpreter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Completion {
    Normal,
    Returning,
    Throwing(u32),
}

struct Interp {
    trace: IterTrace,
    state: IterState,
}

impl Interp {
    fn new() -> Self {
        Self {
            trace: Vec::new(),
            state: IterState::initial(),
        }
    }

    fn emit(&mut self, kind: IterEventKind) {
        self.trace.push(IterEvent {
            kind,
            state_after: self.state,
        });
    }

    fn run_seq(&mut self, stmts: &[EvalStmt]) -> Completion {
        for s in stmts {
            let comp = match s {
                EvalStmt::Plain => Completion::Normal,
                EvalStmt::ForOf {
                    loop_id,
                    source,
                    exit,
                    get_iterator,
                    close_on_abrupt,
                } => self.run_for_of(*loop_id, *source, *exit, *get_iterator, *close_on_abrupt),
                EvalStmt::ForIn {
                    loop_id,
                    keys,
                    exit,
                } => self.run_for_in(*loop_id, keys, *exit),
            };
            if comp != Completion::Normal {
                return comp;
            }
        }
        Completion::Normal
    }

    fn run_for_of(
        &mut self,
        loop_id: u32,
        source: IterSource,
        exit: LoopExit,
        get_iterator: bool,
        close_on_abrupt: bool,
    ) -> Completion {
        if get_iterator {
            self.state.open_iterators += 1;
            self.emit(IterEventKind::GetIterator { loop_id });
        }
        let n = source.element_count();

        for step in 0..n {
            // Determine whether this step terminates the loop abruptly.
            let abrupt = match exit {
                LoopExit::BreakAt(s) if s == step => Some((CloseReason::Break, Completion::Normal)),
                LoopExit::ReturnAt(s) if s == step => {
                    Some((CloseReason::Return, Completion::Returning))
                }
                LoopExit::ThrowAt(s, site) if s == step => {
                    Some((CloseReason::Throw, Completion::Throwing(site)))
                }
                _ => None,
            };

            self.emit(IterEventKind::IteratorNext { loop_id, step });

            if let Some((reason, completion)) = abrupt {
                // Body runs (partially) then completes abruptly.
                self.emit(IterEventKind::BodyStep { loop_id, step });
                if get_iterator && close_on_abrupt {
                    self.state.open_iterators -= 1;
                    self.state.last_close = Some(reason);
                    self.emit(IterEventKind::IteratorClose { loop_id, reason });
                } else if get_iterator {
                    // The iterator was opened but never closed — protocol break.
                    // The frame stays open (observable in `open_iterators`).
                }
                return completion;
            }

            self.emit(IterEventKind::BodyStep { loop_id, step });
        }

        // Natural exhaustion: `done: true`, no IteratorClose.
        if get_iterator {
            self.state.open_iterators -= 1;
        }
        self.emit(IterEventKind::IteratorDone { loop_id });
        Completion::Normal
    }

    fn run_for_in(&mut self, loop_id: u32, keys: &[u32], exit: LoopExit) -> Completion {
        for (idx, key) in keys.iter().enumerate() {
            let abrupt = match exit {
                LoopExit::BreakAt(s) if s == idx => Some(Completion::Normal),
                LoopExit::ReturnAt(s) if s == idx => Some(Completion::Returning),
                LoopExit::ThrowAt(s, site) if s == idx => Some(Completion::Throwing(site)),
                _ => None,
            };
            self.emit(IterEventKind::ForInKey { loop_id, key: *key });
            if let Some(c) = abrupt {
                // for..in does not use IteratorClose.
                return c;
            }
        }
        Completion::Normal
    }
}

fn interpret(stmts: &[EvalStmt]) -> IterTrace {
    let mut interp = Interp::new();
    match interp.run_seq(stmts) {
        Completion::Normal => interp.emit(IterEventKind::Complete),
        Completion::Returning => interp.emit(IterEventKind::ReturnOut),
        Completion::Throwing(site) => interp.emit(IterEventKind::Propagate { site }),
    }
    interp.trace
}

/// Reference (ECMAScript-defined) iterator trace.
pub fn reference_trace(program: &[IterStmt]) -> IterTrace {
    interpret(&to_reference_eval(program))
}

/// Target (IR-defined) iterator trace.
pub fn target_trace(lowered: &[LoweredIterStmt]) -> IterTrace {
    interpret(&to_target_eval(lowered))
}

/// Faithfully lower a source program: every iterator IR marker is emitted.
pub fn faithful_lower(program: &[IterStmt]) -> Vec<LoweredIterStmt> {
    program
        .iter()
        .map(|s| match s {
            IterStmt::Plain { site } => LoweredIterStmt::Plain { site: *site },
            IterStmt::ForOf {
                loop_id,
                source,
                exit,
            } => LoweredIterStmt::ForOf {
                loop_id: *loop_id,
                source: *source,
                exit: *exit,
                get_iterator_emitted: true,
                iterator_close_emitted: true,
            },
            IterStmt::ForIn {
                loop_id,
                own_keys,
                proto_keys,
                exit,
            } => LoweredIterStmt::ForIn {
                loop_id: *loop_id,
                own_keys: own_keys.clone(),
                proto_keys: proto_keys.clone(),
                exit: *exit,
                proto_keys_enumerated: true,
            },
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Semantics-breaking transforms (negative-case generators)
// ---------------------------------------------------------------------------

/// A transformation that looks structure-preserving but breaks iterator
/// semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticsBreakingTransform {
    /// Drop `IteratorClose`: `.return()` is never called on abrupt exit (a
    /// resource / generator-finalisation leak).
    DropIteratorClose,
    /// Drop `GetIterator`: `[Symbol.iterator]()` is never invoked.
    DropGetIterator,
    /// Drop prototype-chain key enumeration from `for..in`.
    DropForInProtoKeys,
}

/// Apply a transform to the first lowered loop that admits it.
pub fn apply_transform(
    lowered: &[LoweredIterStmt],
    transform: SemanticsBreakingTransform,
) -> Option<Vec<LoweredIterStmt>> {
    let mut out = lowered.to_vec();
    let mut applied = false;
    for s in out.iter_mut() {
        match (s, transform) {
            (
                LoweredIterStmt::ForOf {
                    iterator_close_emitted,
                    ..
                },
                SemanticsBreakingTransform::DropIteratorClose,
            ) => {
                *iterator_close_emitted = false;
                applied = true;
                break;
            }
            (
                LoweredIterStmt::ForOf {
                    get_iterator_emitted,
                    ..
                },
                SemanticsBreakingTransform::DropGetIterator,
            ) => {
                *get_iterator_emitted = false;
                applied = true;
                break;
            }
            (
                LoweredIterStmt::ForIn {
                    proto_keys_enumerated,
                    proto_keys,
                    ..
                },
                SemanticsBreakingTransform::DropForInProtoKeys,
            ) if !proto_keys.is_empty() => {
                *proto_keys_enumerated = false;
                applied = true;
                break;
            }
            _ => {}
        }
    }
    if applied { Some(out) } else { None }
}

// ---------------------------------------------------------------------------
// Validation lemmas + result
// ---------------------------------------------------------------------------

/// Iterator-protocol validation lemma classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterLemma {
    /// `GetIterator` is invoked exactly once per `for..of`.
    GetIteratorPresence,
    /// `IteratorClose` is invoked on every abrupt `for..of` exit and never on
    /// natural exhaustion.
    IteratorCloseOnAbrupt,
    /// Every opened iterator is eventually closed (no leak): the trace ends
    /// with zero open iterators.
    NoIteratorLeak,
    /// `for..in` enumerates the full own + prototype key set.
    ForInKeyEnumeration,
    /// Source and target iterator traces are equivalent.
    IteratorFlowEquivalence,
}

/// A structured validation event (bd-cixqu.45 diagnostic discipline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationEvent {
    pub lemma: IterLemma,
    pub verified: bool,
    pub detail: String,
}

/// Result of iterator-protocol translation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IterValidationResult {
    pub validation_successful: bool,
    pub verified_lemmas: Vec<IterLemma>,
    pub failed_lemmas: Vec<IterLemma>,
    pub flow_equivalence_proven: bool,
    pub first_divergence: Option<usize>,
    pub events: Vec<ValidationEvent>,
}

impl IterValidationResult {
    /// Render the event log as JSONL for the bd-cixqu.45 diagnostic surface.
    pub fn events_jsonl(&self) -> String {
        self.events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Translation-validation context for the iterator subset.
#[derive(Debug, Clone)]
pub struct IterValidationContext {
    source: Vec<IterStmt>,
    lowered: Vec<LoweredIterStmt>,
}

impl IterValidationContext {
    pub fn new(source: Vec<IterStmt>, lowered: Vec<LoweredIterStmt>) -> Self {
        Self { source, lowered }
    }

    /// Build a context whose lowering is the faithful lowering of the source.
    pub fn faithful(source: Vec<IterStmt>) -> Self {
        let lowered = faithful_lower(&source);
        Self { source, lowered }
    }

    pub fn validate(&self) -> IterValidationResult {
        let reference = reference_trace(&self.source);
        let target = target_trace(&self.lowered);

        let mut verified = Vec::new();
        let mut failed = Vec::new();
        let mut events = Vec::new();

        // GetIterator presence: counts agree.
        let get_ok = count_kind(&reference, |k| {
            matches!(k, IterEventKind::GetIterator { .. })
        }) == count_kind(&target, |k| matches!(k, IterEventKind::GetIterator { .. }));
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IterLemma::GetIteratorPresence,
            get_ok,
            "GetIterator invoked once per for..of in both source and target",
        );

        // IteratorClose on abrupt: the close events (with reasons) agree.
        let close_ok = close_events(&reference) == close_events(&target);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IterLemma::IteratorCloseOnAbrupt,
            close_ok,
            "IteratorClose (.return()) runs on every abrupt exit, never on natural exhaustion",
        );

        // No iterator leak: both traces end with zero open iterators.
        let leak_ok = reference.last().map(|e| e.state_after.open_iterators) == Some(0)
            && target.last().map(|e| e.state_after.open_iterators) == Some(0);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IterLemma::NoIteratorLeak,
            leak_ok,
            "every opened iterator is closed (trace ends with zero open iterators)",
        );

        // for..in key enumeration: the enumerated key sequences agree.
        let forin_ok = for_in_keys(&reference) == for_in_keys(&target);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IterLemma::ForInKeyEnumeration,
            forin_ok,
            "for..in enumerates the full own + prototype key set in order",
        );

        // Full flow equivalence.
        let first_divergence = first_divergence(&reference, &target);
        let flow_ok = first_divergence.is_none();
        record(
            &mut events,
            &mut verified,
            &mut failed,
            IterLemma::IteratorFlowEquivalence,
            flow_ok,
            "source and target iterator traces are equivalent",
        );

        IterValidationResult {
            validation_successful: failed.is_empty(),
            verified_lemmas: verified,
            failed_lemmas: failed,
            flow_equivalence_proven: flow_ok,
            first_divergence,
            events,
        }
    }
}

fn record(
    events: &mut Vec<ValidationEvent>,
    verified: &mut Vec<IterLemma>,
    failed: &mut Vec<IterLemma>,
    lemma: IterLemma,
    ok: bool,
    detail: &str,
) {
    events.push(ValidationEvent {
        lemma,
        verified: ok,
        detail: detail.to_string(),
    });
    if ok {
        verified.push(lemma);
    } else {
        failed.push(lemma);
    }
}

fn count_kind(trace: &IterTrace, pred: impl Fn(&IterEventKind) -> bool) -> usize {
    trace.iter().filter(|e| pred(&e.kind)).count()
}

fn close_events(trace: &IterTrace) -> Vec<(u32, CloseReason)> {
    trace
        .iter()
        .filter_map(|e| match e.kind {
            IterEventKind::IteratorClose { loop_id, reason } => Some((loop_id, reason)),
            _ => None,
        })
        .collect()
}

fn for_in_keys(trace: &IterTrace) -> Vec<(u32, u32)> {
    trace
        .iter()
        .filter_map(|e| match e.kind {
            IterEventKind::ForInKey { loop_id, key } => Some((loop_id, key)),
            _ => None,
        })
        .collect()
}

fn first_divergence(reference: &IterTrace, target: &IterTrace) -> Option<usize> {
    let max = reference.len().max(target.len());
    for i in 0..max {
        match (reference.get(i), target.get(i)) {
            (Some(a), Some(b)) if a.kind == b.kind => continue,
            _ => return Some(i),
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Test-program generator (≥50 programs across the required categories)
// ---------------------------------------------------------------------------

/// The iterator category a generated program exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IterCategory {
    ForOfArray,
    ForOfMap,
    ForOfSet,
    ForOfCustom,
    ForInProtoChain,
    BreakInForOf,
    ReturnInForOf,
    ThrowInForOf,
}

/// A generated iterator test program tagged with its category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IterTestProgram {
    pub name: String,
    pub category: IterCategory,
    pub program: Vec<IterStmt>,
}

/// Generate ≥50 iterator programs covering: for..of over Array / Map / Set /
/// custom iterable, for..in over an object with a prototype chain, and
/// break / return / throw inside for..of (each of which must call `.return()`).
pub fn generate_iterator_test_programs() -> Vec<IterTestProgram> {
    let mut out = Vec::new();
    let mut id = 0u32;
    let mut fresh = || {
        let v = id;
        id += 1;
        v
    };

    for variant in 0..7u32 {
        let n = 3 + (variant as usize % 3); // 3..5 elements

        // for..of over Array / Map / Set / custom, run to completion.
        for (cat, src) in [
            (IterCategory::ForOfArray, IterSource::Array(n)),
            (IterCategory::ForOfMap, IterSource::MapLike(n)),
            (IterCategory::ForOfSet, IterSource::SetLike(n)),
            (IterCategory::ForOfCustom, IterSource::Custom(n)),
        ] {
            let lid = fresh();
            out.push(IterTestProgram {
                name: format!("{cat:?}_v{variant}"),
                category: cat,
                program: vec![IterStmt::ForOf {
                    loop_id: lid,
                    source: src,
                    exit: LoopExit::Complete,
                }],
            });
        }

        // for..in over an object with a prototype chain.
        {
            let lid = fresh();
            out.push(IterTestProgram {
                name: format!("for_in_proto_v{variant}"),
                category: IterCategory::ForInProtoChain,
                program: vec![IterStmt::ForIn {
                    loop_id: lid,
                    own_keys: vec![lid * 10, lid * 10 + 1],
                    proto_keys: vec![lid * 10 + 1, lid * 10 + 2], // overlaps own (deduped)
                    exit: LoopExit::Complete,
                }],
            });
        }

        // break inside for..of (must IteratorClose with Break).
        {
            let lid = fresh();
            out.push(IterTestProgram {
                name: format!("break_in_for_of_v{variant}"),
                category: IterCategory::BreakInForOf,
                program: vec![IterStmt::ForOf {
                    loop_id: lid,
                    source: IterSource::Custom(n),
                    exit: LoopExit::BreakAt(1),
                }],
            });
        }

        // return inside for..of (must IteratorClose with Return).
        {
            let lid = fresh();
            out.push(IterTestProgram {
                name: format!("return_in_for_of_v{variant}"),
                category: IterCategory::ReturnInForOf,
                program: vec![IterStmt::ForOf {
                    loop_id: lid,
                    source: IterSource::Custom(n),
                    exit: LoopExit::ReturnAt(1),
                }],
            });
        }

        // throw inside for..of (must IteratorClose with Throw).
        {
            let lid = fresh();
            out.push(IterTestProgram {
                name: format!("throw_in_for_of_v{variant}"),
                category: IterCategory::ThrowInForOf,
                program: vec![IterStmt::ForOf {
                    loop_id: lid,
                    source: IterSource::Custom(n),
                    exit: LoopExit::ThrowAt(1, lid * 10 + 9),
                }],
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn for_of(loop_id: u32, n: usize, exit: LoopExit) -> Vec<IterStmt> {
        vec![IterStmt::ForOf {
            loop_id,
            source: IterSource::Custom(n),
            exit,
        }]
    }

    #[test]
    fn faithful_for_of_completion_validates() {
        let ctx = IterValidationContext::faithful(for_of(1, 3, LoopExit::Complete));
        let r = ctx.validate();
        assert!(r.validation_successful, "{:?}", r.failed_lemmas);
        assert!(r.flow_equivalence_proven);
    }

    #[test]
    fn natural_exhaustion_does_not_close() {
        let trace = reference_trace(&for_of(1, 3, LoopExit::Complete));
        assert!(
            !trace
                .iter()
                .any(|e| matches!(e.kind, IterEventKind::IteratorClose { .. }))
        );
        assert!(
            trace
                .iter()
                .any(|e| matches!(e.kind, IterEventKind::IteratorDone { loop_id: 1 }))
        );
    }

    #[test]
    fn break_closes_with_break_reason() {
        let trace = reference_trace(&for_of(1, 5, LoopExit::BreakAt(2)));
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            IterEventKind::IteratorClose {
                loop_id: 1,
                reason: CloseReason::Break
            }
        )));
        // No IteratorDone — the loop did not exhaust.
        assert!(
            !trace
                .iter()
                .any(|e| matches!(e.kind, IterEventKind::IteratorDone { .. }))
        );
    }

    #[test]
    fn return_closes_with_return_reason() {
        let trace = reference_trace(&for_of(1, 5, LoopExit::ReturnAt(0)));
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            IterEventKind::IteratorClose {
                loop_id: 1,
                reason: CloseReason::Return
            }
        )));
        assert!(matches!(
            trace.last().unwrap().kind,
            IterEventKind::ReturnOut
        ));
    }

    #[test]
    fn throw_closes_with_throw_reason_and_propagates() {
        let trace = reference_trace(&for_of(1, 5, LoopExit::ThrowAt(1, 99)));
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            IterEventKind::IteratorClose {
                loop_id: 1,
                reason: CloseReason::Throw
            }
        )));
        assert!(matches!(
            trace.last().unwrap().kind,
            IterEventKind::Propagate { site: 99 }
        ));
    }

    #[test]
    fn no_open_iterator_after_faithful_run() {
        for exit in [
            LoopExit::Complete,
            LoopExit::BreakAt(1),
            LoopExit::ReturnAt(1),
            LoopExit::ThrowAt(1, 7),
        ] {
            let trace = reference_trace(&for_of(1, 4, exit));
            assert_eq!(trace.last().unwrap().state_after.open_iterators, 0);
        }
    }

    #[test]
    fn negative_drop_iterator_close_on_break_rejects() {
        let src = for_of(1, 5, LoopExit::BreakAt(2));
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropIteratorClose).unwrap();
        let r = IterValidationContext::new(src, broken).validate();
        assert!(!r.validation_successful, "dropping .return() must reject");
        assert!(r.failed_lemmas.contains(&IterLemma::IteratorCloseOnAbrupt));
        assert!(r.failed_lemmas.contains(&IterLemma::NoIteratorLeak));
    }

    #[test]
    fn negative_drop_iterator_close_inert_on_completion() {
        // On a naturally-exhausting loop there is no IteratorClose to drop, so
        // the transform is behaviourally inert and validation still passes.
        let src = for_of(1, 3, LoopExit::Complete);
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropIteratorClose).unwrap();
        let r = IterValidationContext::new(src, broken).validate();
        assert!(r.validation_successful);
    }

    #[test]
    fn negative_drop_get_iterator_rejects() {
        let src = for_of(1, 3, LoopExit::Complete);
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropGetIterator).unwrap();
        let r = IterValidationContext::new(src, broken).validate();
        assert!(!r.validation_successful);
        assert!(r.failed_lemmas.contains(&IterLemma::GetIteratorPresence));
    }

    #[test]
    fn negative_drop_for_in_proto_keys_rejects() {
        let src = vec![IterStmt::ForIn {
            loop_id: 1,
            own_keys: vec![1, 2],
            proto_keys: vec![3, 4],
            exit: LoopExit::Complete,
        }];
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropForInProtoKeys).unwrap();
        let r = IterValidationContext::new(src, broken).validate();
        assert!(!r.validation_successful);
        assert!(r.failed_lemmas.contains(&IterLemma::ForInKeyEnumeration));
    }

    #[test]
    fn for_in_dedups_own_over_proto() {
        let src = vec![IterStmt::ForIn {
            loop_id: 1,
            own_keys: vec![10, 11],
            proto_keys: vec![11, 12], // 11 duplicates an own key
            exit: LoopExit::Complete,
        }];
        let trace = reference_trace(&src);
        let keys: Vec<u32> = trace
            .iter()
            .filter_map(|e| match e.kind {
                IterEventKind::ForInKey { key, .. } => Some(key),
                _ => None,
            })
            .collect();
        assert_eq!(keys, vec![10, 11, 12]); // 11 enumerated once
    }

    #[test]
    fn all_generated_programs_validate_faithfully() {
        let programs = generate_iterator_test_programs();
        assert!(
            programs.len() >= 50,
            "expected >=50 programs, got {}",
            programs.len()
        );
        for p in &programs {
            let r = IterValidationContext::faithful(p.program.clone()).validate();
            assert!(
                r.validation_successful,
                "program {} ({:?}) failed: {:?}",
                p.name, p.category, r.failed_lemmas
            );
        }
    }

    #[test]
    fn every_category_is_covered() {
        use IterCategory::*;
        let programs = generate_iterator_test_programs();
        for cat in [
            ForOfArray,
            ForOfMap,
            ForOfSet,
            ForOfCustom,
            ForInProtoChain,
            BreakInForOf,
            ReturnInForOf,
            ThrowInForOf,
        ] {
            assert!(
                programs.iter().any(|p| p.category == cat),
                "category {cat:?} not covered"
            );
        }
    }

    #[test]
    fn negative_transforms_reject_across_corpus() {
        let programs = generate_iterator_test_programs();
        let transforms = [
            SemanticsBreakingTransform::DropIteratorClose,
            SemanticsBreakingTransform::DropGetIterator,
            SemanticsBreakingTransform::DropForInProtoKeys,
        ];
        for &tr in &transforms {
            let mut rejected = false;
            for p in &programs {
                let lowered = faithful_lower(&p.program);
                if let Some(broken) = apply_transform(&lowered, tr) {
                    let r = IterValidationContext::new(p.program.clone(), broken).validate();
                    if !r.validation_successful {
                        rejected = true;
                    }
                }
            }
            assert!(rejected, "transform {tr:?} never rejected across corpus");
        }
    }

    #[test]
    fn faithful_lower_trace_equals_reference() {
        for p in generate_iterator_test_programs() {
            assert_eq!(
                reference_trace(&p.program),
                target_trace(&faithful_lower(&p.program)),
                "faithful lowering diverged for {}",
                p.name
            );
        }
    }

    #[test]
    fn events_jsonl_round_trips() {
        let r = IterValidationContext::faithful(for_of(1, 3, LoopExit::BreakAt(1))).validate();
        let jsonl = r.events_jsonl();
        assert_eq!(r.events.len(), 5);
        for line in jsonl.lines() {
            let parsed: ValidationEvent = serde_json::from_str(line).unwrap();
            assert!(parsed.verified);
        }
    }

    #[test]
    fn serde_round_trip_result() {
        let r = IterValidationContext::faithful(for_of(1, 4, LoopExit::ThrowAt(2, 5))).validate();
        let json = serde_json::to_string(&r).unwrap();
        let back: IterValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn first_divergence_set_on_reject() {
        let src = for_of(1, 5, LoopExit::BreakAt(2));
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropIteratorClose).unwrap();
        let r = IterValidationContext::new(src, broken).validate();
        assert!(r.first_divergence.is_some());
    }

    #[test]
    fn empty_program_completes() {
        let trace = reference_trace(&[]);
        assert_eq!(trace.len(), 1);
        assert!(matches!(trace[0].kind, IterEventKind::Complete));
    }

    #[test]
    fn next_called_per_element_until_exit() {
        let trace = reference_trace(&for_of(1, 4, LoopExit::BreakAt(2)));
        let nexts = trace
            .iter()
            .filter(|e| matches!(e.kind, IterEventKind::IteratorNext { .. }))
            .count();
        // Steps 0, 1, 2 each get a .next() before the break at step 2.
        assert_eq!(nexts, 3);
    }

    #[test]
    fn validation_exposes_verified_lemmas() {
        let r = IterValidationContext::faithful(for_of(1, 3, LoopExit::Complete)).validate();
        assert!(r.verified_lemmas.contains(&IterLemma::NoIteratorLeak));
        assert!(
            r.verified_lemmas
                .contains(&IterLemma::IteratorFlowEquivalence)
        );
    }
}
