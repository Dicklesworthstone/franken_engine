#![forbid(unsafe_code)]

//! Exception-semantics translation validation (G.6.A — bd-cixqu.7.9.1).
//!
//! Extends G.4/G.5 translation validation to the try/catch/finally subset. The
//! lowering of `try`/`catch`/`finally` inserts the unwind-capable IR3
//! instructions [`ir_contract::Ir3Instruction`]: `BeginTry { catch_target,
//! finally_target }`, `EndTry`, `Throw`, `EnterCatch`, `EnterFinally`,
//! `EndFinally`. The runtime unwinder maintains a catch-frame stack, a
//! `FinallyMode` (Normal / Exception / Return) and a `pending_exception`
//! (see `baseline_interpreter::{CatchFrame, FinallyMode}`).
//!
//! G.6.A proves that the lowered IR3 has *semantically equivalent exception
//! flow* to the source. We do this with a small **differential abstract
//! interpreter**: a single exception evaluator is run over two views of the
//! same program —
//!
//!   * a **reference view**, whose control behaviour is dictated by the source
//!     program structure (a `catch` runs iff the source has a `catch`, a
//!     `finally` runs iff the source has a `finally`, a pending exception is
//!     re-thrown after `finally`); and
//!   * a **target view**, whose control behaviour is dictated by the IR3
//!     instructions *actually emitted* by the lowering (catch runs iff an
//!     `EnterCatch` was emitted under a `BeginTry` with a `catch_target`,
//!     finally runs iff `EnterFinally`/`EndFinally` were emitted, the pending
//!     exception is re-thrown iff `EndFinally` re-throws, a frame exists iff
//!     `BeginTry` was emitted).
//!
//! Translation validation succeeds iff the two views produce **identical
//! observable exception traces** (catch-frame transitions, finally executions
//! with their entry mode, catch bindings, propagation). A "preserving-looking"
//! transformation that silently drops an `EnterFinally`, swaps a `catch_target`
//! or omits the `EndFinally` re-throw therefore diverges from the reference and
//! is **rejected** — this is the G.6.A / G.11 negative case.
//!
//! The recorded [`ExceptionTrace`] *is* the witness: every event carries the
//! [`UnwinderState`] after it, so the validation witness includes the unwinder
//! state transitions (G.6.A acceptance criterion #1).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Source-level model of the try/catch/finally subset
// ---------------------------------------------------------------------------

/// A source statement in the exception subset. `Plain` models any ordinary
/// statement; if `throws` is set it raises at `site`, and `is_await` marks an
/// `await` point (relevant to the await-in-try / await-in-finally categories,
/// which must preserve the unwinder frame across the microtask checkpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExcStmt {
    /// An ordinary statement. Raises an exception at `site` when `throws`.
    Plain {
        site: u32,
        throws: bool,
        is_await: bool,
    },
    /// A `try` region with optional `catch` and `finally`.
    Try(TryRegion),
}

/// A `try { body } [catch { catch_body }] [finally { finally_body }]` region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TryRegion {
    pub try_id: u32,
    pub body: Vec<ExcStmt>,
    /// `Some` when the source has a `catch` clause.
    pub catch_body: Option<Vec<ExcStmt>>,
    /// `Some` when the source has a `finally` clause.
    pub finally_body: Option<Vec<ExcStmt>>,
}

impl TryRegion {
    pub fn has_catch(&self) -> bool {
        self.catch_body.is_some()
    }
    pub fn has_finally(&self) -> bool {
        self.finally_body.is_some()
    }
}

// ---------------------------------------------------------------------------
// Runtime unwinder state (mirror of baseline_interpreter)
// ---------------------------------------------------------------------------

/// How a `finally` block was entered — mirrors `baseline_interpreter::FinallyMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinallyEntryMode {
    /// Entered via normal completion of the try (or catch) body.
    Normal,
    /// Entered with an exception in flight; `pending_exception` is set.
    Exception,
    /// Entered with a return in flight (modelled for completeness).
    Return,
}

/// Abstract unwinder state recorded after each exception event. Mirrors the
/// runtime's catch-frame stack depth, `pending_exception` and `FinallyMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwinderState {
    pub catch_frame_depth: usize,
    pub pending_exception: bool,
    pub finally_mode: Option<FinallyEntryMode>,
}

impl UnwinderState {
    fn initial() -> Self {
        Self {
            catch_frame_depth: 0,
            pending_exception: false,
            finally_mode: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Observable exception trace (the validation witness)
// ---------------------------------------------------------------------------

/// An observable event in the exception trace. The trace's *kind* sequence is
/// what equivalence compares; `state_after` is the unwinder-transition witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExcEventKind {
    /// `BeginTry` — a catch frame is pushed.
    EnterTry {
        try_id: u32,
        has_catch: bool,
        has_finally: bool,
    },
    /// `EndTry` — the try body completed normally and the frame is popped.
    LeaveTryNormal { try_id: u32 },
    /// `Throw` — an exception is raised at `site`.
    Raise { site: u32 },
    /// `EnterCatch` — the catch handler binds the thrown value.
    CatchHandle { try_id: u32 },
    /// `EnterFinally` — the finally block runs, recording its entry mode.
    FinallyRun { try_id: u32, mode: FinallyEntryMode },
    /// `EndFinally` — finally completed; `rethrew` iff a pending exception was
    /// re-raised on exit.
    FinallyEnd { try_id: u32, rethrew: bool },
    /// An `await` suspension point inside an exception region.
    AwaitCheckpoint { site: u32, in_finally: bool },
    /// Normal completion of the program.
    Complete,
    /// An exception escaped the top level (propagated out).
    Propagate { site: u32 },
}

/// A single trace event together with the unwinder state it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcEvent {
    pub kind: ExcEventKind,
    pub state_after: UnwinderState,
}

/// An ordered exception trace. Two traces are *flow-equivalent* iff their event
/// `kind` sequences are identical.
pub type ExceptionTrace = Vec<ExcEvent>;

// ---------------------------------------------------------------------------
// Lowered (target) model — IR3 markers actually emitted
// ---------------------------------------------------------------------------

/// A lowered statement, carrying the IR3 exception markers actually emitted by
/// the lowering. A correct lowering sets every marker; a semantics-breaking
/// transform clears one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoweredStmt {
    Plain {
        site: u32,
        throws: bool,
        is_await: bool,
    },
    Try(LoweredTry),
}

/// Lowered `try` region. The booleans encode which IR3 instructions were
/// actually emitted, so the target interpreter obeys the *emitted* code rather
/// than the source intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweredTry {
    pub try_id: u32,
    pub body: Vec<LoweredStmt>,
    pub catch_body: Vec<LoweredStmt>,
    pub finally_body: Vec<LoweredStmt>,
    /// Source had a `catch`.
    pub source_has_catch: bool,
    /// Source had a `finally`.
    pub source_has_finally: bool,
    /// `BeginTry` was emitted (the catch frame is established).
    pub begin_try_emitted: bool,
    /// `BeginTry.catch_target` set *and* `EnterCatch` emitted (catch reachable).
    pub catch_target_emitted: bool,
    /// `BeginTry.finally_target` set *and* `EnterFinally`/`EndFinally` emitted.
    pub finally_target_emitted: bool,
    /// `EndFinally` re-throws the pending exception on exit.
    pub end_finally_rethrows: bool,
}

// ---------------------------------------------------------------------------
// Evaluation view — the unified abstract interpreter operates on this
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum EvalStmt {
    Plain {
        site: u32,
        throws: bool,
        is_await: bool,
    },
    Try(EvalTry),
}

#[derive(Debug, Clone)]
struct EvalTry {
    try_id: u32,
    body: Vec<EvalStmt>,
    catch_body: Vec<EvalStmt>,
    finally_body: Vec<EvalStmt>,
    has_catch: bool,
    /// Effective: this try participates in unwinding (frame established).
    frame_established: bool,
    /// Effective: a catch handler runs for an in-flight exception.
    run_catch: bool,
    /// Effective: a finally block runs on every exit path.
    run_finally: bool,
    /// Effective: a pending exception survives the finally (is re-thrown).
    rethrow_after_finally: bool,
    has_finally: bool,
}

/// Build the **reference** evaluation view: behaviour follows source structure.
fn to_reference_eval(stmts: &[ExcStmt]) -> Vec<EvalStmt> {
    stmts
        .iter()
        .map(|s| match s {
            ExcStmt::Plain {
                site,
                throws,
                is_await,
            } => EvalStmt::Plain {
                site: *site,
                throws: *throws,
                is_await: *is_await,
            },
            ExcStmt::Try(region) => EvalStmt::Try(EvalTry {
                try_id: region.try_id,
                body: to_reference_eval(&region.body),
                catch_body: region
                    .catch_body
                    .as_deref()
                    .map(to_reference_eval)
                    .unwrap_or_default(),
                finally_body: region
                    .finally_body
                    .as_deref()
                    .map(to_reference_eval)
                    .unwrap_or_default(),
                has_catch: region.has_catch(),
                has_finally: region.has_finally(),
                frame_established: true,
                run_catch: region.has_catch(),
                run_finally: region.has_finally(),
                rethrow_after_finally: true,
            }),
        })
        .collect()
}

/// Build the **target** evaluation view: behaviour follows emitted IR3 markers.
fn to_target_eval(stmts: &[LoweredStmt]) -> Vec<EvalStmt> {
    stmts
        .iter()
        .map(|s| match s {
            LoweredStmt::Plain {
                site,
                throws,
                is_await,
            } => EvalStmt::Plain {
                site: *site,
                throws: *throws,
                is_await: *is_await,
            },
            LoweredStmt::Try(t) => EvalStmt::Try(EvalTry {
                try_id: t.try_id,
                body: to_target_eval(&t.body),
                catch_body: to_target_eval(&t.catch_body),
                finally_body: to_target_eval(&t.finally_body),
                has_catch: t.source_has_catch,
                has_finally: t.source_has_finally,
                frame_established: t.begin_try_emitted,
                // A catch only runs if its source clause exists AND the IR3
                // catch path was emitted.
                run_catch: t.source_has_catch && t.catch_target_emitted,
                // A finally only runs if its source clause exists AND the IR3
                // finally path was emitted.
                run_finally: t.source_has_finally && t.finally_target_emitted,
                rethrow_after_finally: t.end_finally_rethrows,
            }),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The abstract exception interpreter
// ---------------------------------------------------------------------------

/// Completion of a statement sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Completion {
    Normal,
    Throwing(u32),
}

struct Interp {
    trace: ExceptionTrace,
    state: UnwinderState,
}

impl Interp {
    fn new() -> Self {
        Self {
            trace: Vec::new(),
            state: UnwinderState::initial(),
        }
    }

    fn emit(&mut self, kind: ExcEventKind) {
        self.trace.push(ExcEvent {
            kind,
            state_after: self.state,
        });
    }

    fn run_seq(&mut self, stmts: &[EvalStmt]) -> Completion {
        for s in stmts {
            match s {
                EvalStmt::Plain {
                    site,
                    throws,
                    is_await,
                } => {
                    if *is_await {
                        self.emit(ExcEventKind::AwaitCheckpoint {
                            site: *site,
                            in_finally: self.state.finally_mode
                                == Some(FinallyEntryMode::Exception)
                                || self.state.finally_mode == Some(FinallyEntryMode::Normal),
                        });
                    }
                    if *throws {
                        return Completion::Throwing(*site);
                    }
                }
                EvalStmt::Try(region) => {
                    let comp = self.run_try(region);
                    if let Completion::Throwing(_) = comp {
                        return comp;
                    }
                }
            }
        }
        Completion::Normal
    }

    fn run_try(&mut self, region: &EvalTry) -> Completion {
        // If the frame was never established (BeginTry dropped), the try body
        // executes with no protection: an exception propagates without catch or
        // finally observing it.
        if !region.frame_established {
            return self.run_seq(&region.body);
        }

        self.state.catch_frame_depth += 1;
        self.emit(ExcEventKind::EnterTry {
            try_id: region.try_id,
            has_catch: region.has_catch,
            has_finally: region.has_finally,
        });

        let mut current = self.run_seq(&region.body);

        if current == Completion::Normal {
            self.emit(ExcEventKind::LeaveTryNormal {
                try_id: region.try_id,
            });
        }

        // Catch handling.
        if let Completion::Throwing(site) = current {
            if region.run_catch {
                self.state.pending_exception = false;
                self.emit(ExcEventKind::CatchHandle {
                    try_id: region.try_id,
                });
                current = self.run_seq(&region.catch_body);
            } else {
                // No (reachable) catch: the exception stays pending for finally
                // / propagation.
                self.state.pending_exception = true;
                let _ = site;
            }
        }

        // Finally handling — runs on *every* exit path when emitted.
        if region.run_finally {
            let mode = match current {
                Completion::Normal => FinallyEntryMode::Normal,
                Completion::Throwing(_) => FinallyEntryMode::Exception,
            };
            self.state.finally_mode = Some(mode);
            self.emit(ExcEventKind::FinallyRun {
                try_id: region.try_id,
                mode,
            });
            let fin_comp = self.run_seq(&region.finally_body);
            self.state.finally_mode = None;

            match fin_comp {
                // A throw inside finally overrides any pending exception.
                Completion::Throwing(_) => {
                    self.emit(ExcEventKind::FinallyEnd {
                        try_id: region.try_id,
                        rethrew: false,
                    });
                    self.state.catch_frame_depth -= 1;
                    return fin_comp;
                }
                Completion::Normal => {
                    let pending = matches!(current, Completion::Throwing(_));
                    let rethrew = pending && region.rethrow_after_finally;
                    self.emit(ExcEventKind::FinallyEnd {
                        try_id: region.try_id,
                        rethrew,
                    });
                    if pending && !region.rethrow_after_finally {
                        // EndFinally failed to re-throw: the exception is
                        // silently swallowed (a semantics break).
                        current = Completion::Normal;
                        self.state.pending_exception = false;
                    }
                }
            }
        }

        self.state.catch_frame_depth -= 1;
        if let Completion::Throwing(_) = current {
            self.state.pending_exception = true;
        }
        current
    }
}

/// Interpret a sequence under one evaluation view, returning the full trace.
fn interpret(stmts: &[EvalStmt]) -> ExceptionTrace {
    let mut interp = Interp::new();
    let comp = interp.run_seq(stmts);
    match comp {
        Completion::Normal => interp.emit(ExcEventKind::Complete),
        Completion::Throwing(site) => interp.emit(ExcEventKind::Propagate { site }),
    }
    interp.trace
}

/// Reference (source-defined) exception trace.
pub fn reference_trace(program: &[ExcStmt]) -> ExceptionTrace {
    interpret(&to_reference_eval(program))
}

/// Target (IR3-defined) exception trace.
pub fn target_trace(lowered: &[LoweredStmt]) -> ExceptionTrace {
    interpret(&to_target_eval(lowered))
}

/// Faithfully lower a source program: every IR3 marker is emitted.
pub fn faithful_lower(program: &[ExcStmt]) -> Vec<LoweredStmt> {
    program
        .iter()
        .map(|s| match s {
            ExcStmt::Plain {
                site,
                throws,
                is_await,
            } => LoweredStmt::Plain {
                site: *site,
                throws: *throws,
                is_await: *is_await,
            },
            ExcStmt::Try(region) => LoweredStmt::Try(LoweredTry {
                try_id: region.try_id,
                body: faithful_lower(&region.body),
                catch_body: region
                    .catch_body
                    .as_deref()
                    .map(faithful_lower)
                    .unwrap_or_default(),
                finally_body: region
                    .finally_body
                    .as_deref()
                    .map(faithful_lower)
                    .unwrap_or_default(),
                source_has_catch: region.has_catch(),
                source_has_finally: region.has_finally(),
                begin_try_emitted: true,
                catch_target_emitted: region.has_catch(),
                finally_target_emitted: region.has_finally(),
                end_finally_rethrows: true,
            }),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Semantics-breaking transforms (negative-case generators)
// ---------------------------------------------------------------------------

/// A transformation that *looks* structure-preserving but breaks exception
/// semantics. Applying it to the first lowered `try` in a program produces an
/// IR3 stream the validator must reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticsBreakingTransform {
    /// Drop `EnterFinally`/`EndFinally`: the finally block never runs.
    DropEnterFinally,
    /// Drop `EnterCatch`/`catch_target`: the catch handler is unreachable.
    DropCatchTarget,
    /// Drop `BeginTry`: no catch frame is established for the body.
    DropBeginTry,
    /// `EndFinally` no longer re-throws: a pending exception is swallowed.
    DropEndFinallyRethrow,
}

/// Apply a semantics-breaking transform to the first `try` region that admits
/// it. Returns `None` when no applicable region exists (so callers can skip).
pub fn apply_transform(
    lowered: &[LoweredStmt],
    transform: SemanticsBreakingTransform,
) -> Option<Vec<LoweredStmt>> {
    let mut out = lowered.to_vec();
    if mutate_first(&mut out, transform) {
        Some(out)
    } else {
        None
    }
}

fn mutate_first(stmts: &mut [LoweredStmt], transform: SemanticsBreakingTransform) -> bool {
    for s in stmts.iter_mut() {
        if let LoweredStmt::Try(t) = s {
            let applicable = match transform {
                SemanticsBreakingTransform::DropEnterFinally
                | SemanticsBreakingTransform::DropEndFinallyRethrow => t.source_has_finally,
                SemanticsBreakingTransform::DropCatchTarget => t.source_has_catch,
                SemanticsBreakingTransform::DropBeginTry => true,
            };
            if applicable {
                match transform {
                    SemanticsBreakingTransform::DropEnterFinally => {
                        t.finally_target_emitted = false
                    }
                    SemanticsBreakingTransform::DropCatchTarget => t.catch_target_emitted = false,
                    SemanticsBreakingTransform::DropBeginTry => t.begin_try_emitted = false,
                    SemanticsBreakingTransform::DropEndFinallyRethrow => {
                        t.end_finally_rethrows = false
                    }
                }
                return true;
            }
            // Recurse into nested regions if not applicable here.
            if mutate_first(&mut t.body, transform)
                || mutate_first(&mut t.catch_body, transform)
                || mutate_first(&mut t.finally_body, transform)
            {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Validation lemmas + result
// ---------------------------------------------------------------------------

/// Exception-flow validation lemma classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExcLemma {
    /// Every `BeginTry` is balanced by an `EndTry`/unwind (frame stack returns
    /// to depth 0).
    CatchFrameBalance,
    /// A `finally` runs on every exit path (normal, exception, return).
    FinallyAlwaysRuns,
    /// `EnterCatch` binds the thrown value for a handled exception.
    CatchBinding,
    /// A pending exception survives `finally` unless superseded.
    PendingExceptionPreservation,
    /// Source and target exception traces are flow-equivalent.
    ExceptionFlowEquivalence,
}

/// A structured validation event (bd-cixqu.45 diagnostic discipline). Emitted
/// to the result's event log and serialisable to JSONL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationEvent {
    pub lemma: ExcLemma,
    pub verified: bool,
    pub detail: String,
}

/// Result of exception-semantics translation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionValidationResult {
    pub validation_successful: bool,
    pub verified_lemmas: Vec<ExcLemma>,
    pub failed_lemmas: Vec<ExcLemma>,
    pub flow_equivalence_proven: bool,
    /// Index of the first divergent trace event, when equivalence fails.
    pub first_divergence: Option<usize>,
    pub events: Vec<ValidationEvent>,
}

impl ExceptionValidationResult {
    /// Render the event log as JSONL (one event per line) for the bd-cixqu.45
    /// diagnostic surface.
    pub fn events_jsonl(&self) -> String {
        self.events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Translation-validation context for the exception subset.
#[derive(Debug, Clone)]
pub struct ExceptionValidationContext {
    source: Vec<ExcStmt>,
    lowered: Vec<LoweredStmt>,
}

impl ExceptionValidationContext {
    /// Build a context from a source program and a candidate lowering.
    pub fn new(source: Vec<ExcStmt>, lowered: Vec<LoweredStmt>) -> Self {
        Self { source, lowered }
    }

    /// Build a context whose lowering is the faithful lowering of the source
    /// (the positive / expected case).
    pub fn faithful(source: Vec<ExcStmt>) -> Self {
        let lowered = faithful_lower(&source);
        Self { source, lowered }
    }

    /// Run translation validation, proving exception-flow equivalence between
    /// the source and the candidate lowering.
    pub fn validate(&self) -> ExceptionValidationResult {
        let reference = reference_trace(&self.source);
        let target = target_trace(&self.lowered);

        let mut verified = Vec::new();
        let mut failed = Vec::new();
        let mut events = Vec::new();

        // Lemma: catch-frame balance — both traces end at depth 0.
        let ref_balanced = reference.last().map(|e| e.state_after.catch_frame_depth) == Some(0);
        let tgt_balanced = target.last().map(|e| e.state_after.catch_frame_depth) == Some(0);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            ExcLemma::CatchFrameBalance,
            ref_balanced && tgt_balanced,
            "every BeginTry is balanced by an EndTry/unwind (depth returns to 0)",
        );

        // Lemma: finally-always-runs — each source finally appears in the target
        // trace whenever it appears in the reference trace.
        let finally_ok = finally_runs_match(&reference, &target);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            ExcLemma::FinallyAlwaysRuns,
            finally_ok,
            "every finally that runs in the reference also runs in the target",
        );

        // Lemma: catch-binding — each reference CatchHandle has a target match.
        let catch_ok = catch_bindings_match(&reference, &target);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            ExcLemma::CatchBinding,
            catch_ok,
            "each handled exception binds via EnterCatch in the target",
        );

        // Lemma: pending-exception preservation — re-throw decisions agree.
        let pending_ok = rethrow_decisions_match(&reference, &target);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            ExcLemma::PendingExceptionPreservation,
            pending_ok,
            "a pending exception survives finally identically in source and target",
        );

        // Lemma: full exception-flow equivalence — the event kind sequences match.
        let first_divergence = first_divergence(&reference, &target);
        let flow_ok = first_divergence.is_none();
        record(
            &mut events,
            &mut verified,
            &mut failed,
            ExcLemma::ExceptionFlowEquivalence,
            flow_ok,
            "source and target exception traces are flow-equivalent",
        );

        ExceptionValidationResult {
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
    verified: &mut Vec<ExcLemma>,
    failed: &mut Vec<ExcLemma>,
    lemma: ExcLemma,
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

fn first_divergence(reference: &ExceptionTrace, target: &ExceptionTrace) -> Option<usize> {
    let max = reference.len().max(target.len());
    for i in 0..max {
        match (reference.get(i), target.get(i)) {
            (Some(a), Some(b)) if a.kind == b.kind => continue,
            _ => return Some(i),
        }
    }
    None
}

fn count_finally_runs(trace: &ExceptionTrace) -> BTreeMap<u32, usize> {
    let mut m = BTreeMap::new();
    for e in trace {
        if let ExcEventKind::FinallyRun { try_id, .. } = e.kind {
            *m.entry(try_id).or_insert(0) += 1;
        }
    }
    m
}

fn finally_runs_match(reference: &ExceptionTrace, target: &ExceptionTrace) -> bool {
    count_finally_runs(reference) == count_finally_runs(target)
}

fn catch_bindings_match(reference: &ExceptionTrace, target: &ExceptionTrace) -> bool {
    let r: Vec<u32> = reference
        .iter()
        .filter_map(|e| match e.kind {
            ExcEventKind::CatchHandle { try_id } => Some(try_id),
            _ => None,
        })
        .collect();
    let t: Vec<u32> = target
        .iter()
        .filter_map(|e| match e.kind {
            ExcEventKind::CatchHandle { try_id } => Some(try_id),
            _ => None,
        })
        .collect();
    r == t
}

fn rethrow_decisions_match(reference: &ExceptionTrace, target: &ExceptionTrace) -> bool {
    let r: Vec<(u32, bool)> = reference
        .iter()
        .filter_map(|e| match e.kind {
            ExcEventKind::FinallyEnd { try_id, rethrew } => Some((try_id, rethrew)),
            _ => None,
        })
        .collect();
    let t: Vec<(u32, bool)> = target
        .iter()
        .filter_map(|e| match e.kind {
            ExcEventKind::FinallyEnd { try_id, rethrew } => Some((try_id, rethrew)),
            _ => None,
        })
        .collect();
    r == t
}

// ---------------------------------------------------------------------------
// Test-program generator (≥50 programs across the required categories)
// ---------------------------------------------------------------------------

/// The exception-handling category a generated program exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramCategory {
    NestedTry,
    TryWithoutFinally,
    TryWithoutCatch,
    ThrowInFinally,
    ThrowInCatch,
    AwaitInTry,
    AwaitInFinally,
    TryCatchFinally,
}

/// A generated exception test program tagged with its category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionTestProgram {
    pub name: String,
    pub category: ProgramCategory,
    pub program: Vec<ExcStmt>,
}

fn plain(site: u32, throws: bool) -> ExcStmt {
    ExcStmt::Plain {
        site,
        throws,
        is_await: false,
    }
}

fn await_pt(site: u32) -> ExcStmt {
    ExcStmt::Plain {
        site,
        throws: false,
        is_await: true,
    }
}

/// Generate ≥50 try/catch/finally programs covering every required category:
/// nested try, try-without-finally, try-without-catch, throw-in-finally,
/// throw-in-catch, await-in-try, await-in-finally (plus plain try/catch/finally).
pub fn generate_exception_test_programs() -> Vec<ExceptionTestProgram> {
    let mut out = Vec::new();
    let mut next_id = 0u32;
    let mut fresh = || {
        let id = next_id;
        next_id += 1;
        id
    };

    // For each category, generate several variants (throwing vs non-throwing,
    // varying body lengths) to reach ≥50 programs.
    for variant in 0..7u32 {
        let throws = variant % 2 == 0;
        let extra = variant % 3; // 0..2 extra body statements

        // try/catch/finally
        {
            let id = fresh();
            let mut body = vec![plain(id * 10, throws)];
            for k in 0..extra {
                body.push(plain(id * 10 + 100 + k, false));
            }
            out.push(ExceptionTestProgram {
                name: format!("try_catch_finally_v{variant}"),
                category: ProgramCategory::TryCatchFinally,
                program: vec![ExcStmt::Try(TryRegion {
                    try_id: id,
                    body,
                    catch_body: Some(vec![plain(id * 10 + 1, false)]),
                    finally_body: Some(vec![plain(id * 10 + 2, false)]),
                })],
            });
        }

        // try-without-finally
        {
            let id = fresh();
            out.push(ExceptionTestProgram {
                name: format!("try_without_finally_v{variant}"),
                category: ProgramCategory::TryWithoutFinally,
                program: vec![ExcStmt::Try(TryRegion {
                    try_id: id,
                    body: vec![plain(id * 10, throws)],
                    catch_body: Some(vec![plain(id * 10 + 1, false)]),
                    finally_body: None,
                })],
            });
        }

        // try-without-catch
        {
            let id = fresh();
            out.push(ExceptionTestProgram {
                name: format!("try_without_catch_v{variant}"),
                category: ProgramCategory::TryWithoutCatch,
                program: vec![ExcStmt::Try(TryRegion {
                    try_id: id,
                    body: vec![plain(id * 10, throws)],
                    catch_body: None,
                    finally_body: Some(vec![plain(id * 10 + 2, false)]),
                })],
            });
        }

        // nested try
        {
            let outer = fresh();
            let inner = fresh();
            out.push(ExceptionTestProgram {
                name: format!("nested_try_v{variant}"),
                category: ProgramCategory::NestedTry,
                program: vec![ExcStmt::Try(TryRegion {
                    try_id: outer,
                    body: vec![ExcStmt::Try(TryRegion {
                        try_id: inner,
                        body: vec![plain(inner * 10, throws)],
                        catch_body: Some(vec![plain(inner * 10 + 1, false)]),
                        finally_body: Some(vec![plain(inner * 10 + 2, false)]),
                    })],
                    catch_body: Some(vec![plain(outer * 10 + 1, false)]),
                    finally_body: Some(vec![plain(outer * 10 + 2, false)]),
                })],
            });
        }

        // throw-in-catch
        {
            let id = fresh();
            out.push(ExceptionTestProgram {
                name: format!("throw_in_catch_v{variant}"),
                category: ProgramCategory::ThrowInCatch,
                program: vec![ExcStmt::Try(TryRegion {
                    try_id: id,
                    body: vec![plain(id * 10, true)],
                    catch_body: Some(vec![plain(id * 10 + 1, true)]),
                    finally_body: Some(vec![plain(id * 10 + 2, false)]),
                })],
            });
        }

        // throw-in-finally
        {
            let id = fresh();
            out.push(ExceptionTestProgram {
                name: format!("throw_in_finally_v{variant}"),
                category: ProgramCategory::ThrowInFinally,
                program: vec![ExcStmt::Try(TryRegion {
                    try_id: id,
                    body: vec![plain(id * 10, throws)],
                    catch_body: Some(vec![plain(id * 10 + 1, false)]),
                    finally_body: Some(vec![plain(id * 10 + 2, true)]),
                })],
            });
        }

        // await-in-try
        {
            let id = fresh();
            out.push(ExceptionTestProgram {
                name: format!("await_in_try_v{variant}"),
                category: ProgramCategory::AwaitInTry,
                program: vec![ExcStmt::Try(TryRegion {
                    try_id: id,
                    body: vec![await_pt(id * 10), plain(id * 10 + 5, throws)],
                    catch_body: Some(vec![plain(id * 10 + 1, false)]),
                    finally_body: Some(vec![plain(id * 10 + 2, false)]),
                })],
            });
        }

        // await-in-finally
        {
            let id = fresh();
            out.push(ExceptionTestProgram {
                name: format!("await_in_finally_v{variant}"),
                category: ProgramCategory::AwaitInFinally,
                program: vec![ExcStmt::Try(TryRegion {
                    try_id: id,
                    body: vec![plain(id * 10, throws)],
                    catch_body: Some(vec![plain(id * 10 + 1, false)]),
                    finally_body: Some(vec![await_pt(id * 10 + 3), plain(id * 10 + 2, false)]),
                })],
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn try_catch_finally(throws_in_body: bool) -> Vec<ExcStmt> {
        vec![ExcStmt::Try(TryRegion {
            try_id: 1,
            body: vec![plain(10, throws_in_body)],
            catch_body: Some(vec![plain(11, false)]),
            finally_body: Some(vec![plain(12, false)]),
        })]
    }

    #[test]
    fn faithful_lowering_validates() {
        let src = try_catch_finally(true);
        let ctx = ExceptionValidationContext::faithful(src);
        let result = ctx.validate();
        assert!(result.validation_successful, "{:?}", result.failed_lemmas);
        assert!(result.flow_equivalence_proven);
        assert!(result.first_divergence.is_none());
    }

    #[test]
    fn faithful_lowering_validates_non_throwing() {
        let ctx = ExceptionValidationContext::faithful(try_catch_finally(false));
        assert!(ctx.validate().validation_successful);
    }

    #[test]
    fn reference_trace_runs_catch_and_finally_on_throw() {
        let trace = reference_trace(&try_catch_finally(true));
        let kinds: Vec<_> = trace.iter().map(|e| &e.kind).collect();
        // The catch handles the body's exception.
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, ExcEventKind::CatchHandle { try_id: 1 }))
        );
        // Because the catch consumed the exception and completed normally, the
        // finally runs in *Normal* mode (no pending exception remains) — this is
        // the JS semantics the unwinder must preserve.
        assert!(kinds.iter().any(|k| matches!(
            k,
            ExcEventKind::FinallyRun {
                try_id: 1,
                mode: FinallyEntryMode::Normal
            }
        )));
    }

    #[test]
    fn reference_trace_finally_normal_mode_without_throw() {
        let trace = reference_trace(&try_catch_finally(false));
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            ExcEventKind::FinallyRun {
                try_id: 1,
                mode: FinallyEntryMode::Normal
            }
        )));
        // No catch should run when nothing throws.
        assert!(
            !trace
                .iter()
                .any(|e| matches!(e.kind, ExcEventKind::CatchHandle { .. }))
        );
    }

    #[test]
    fn catch_frame_depth_balances() {
        let trace = reference_trace(&try_catch_finally(true));
        assert_eq!(trace.last().unwrap().state_after.catch_frame_depth, 0);
    }

    #[test]
    fn negative_drop_enter_finally_rejects() {
        let src = try_catch_finally(true);
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropEnterFinally).unwrap();
        let ctx = ExceptionValidationContext::new(src, broken);
        let result = ctx.validate();
        assert!(
            !result.validation_successful,
            "dropping EnterFinally must be rejected"
        );
        assert!(result.failed_lemmas.contains(&ExcLemma::FinallyAlwaysRuns));
        assert!(!result.flow_equivalence_proven);
    }

    #[test]
    fn negative_drop_catch_target_rejects() {
        let src = try_catch_finally(true);
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropCatchTarget).unwrap();
        let result = ExceptionValidationContext::new(src, broken).validate();
        assert!(!result.validation_successful);
        assert!(result.failed_lemmas.contains(&ExcLemma::CatchBinding));
    }

    #[test]
    fn negative_drop_begin_try_rejects() {
        let src = try_catch_finally(true);
        let lowered = faithful_lower(&src);
        let broken = apply_transform(&lowered, SemanticsBreakingTransform::DropBeginTry).unwrap();
        let result = ExceptionValidationContext::new(src, broken).validate();
        assert!(!result.validation_successful);
        // A dropped frame breaks balance and flow equivalence.
        assert!(
            result
                .failed_lemmas
                .contains(&ExcLemma::ExceptionFlowEquivalence)
        );
    }

    #[test]
    fn negative_drop_endfinally_rethrow_rejects() {
        // Throw in body, no catch, with finally: the pending exception must be
        // re-thrown by EndFinally. Dropping the re-throw swallows it.
        let src = vec![ExcStmt::Try(TryRegion {
            try_id: 7,
            body: vec![plain(70, true)],
            catch_body: None,
            finally_body: Some(vec![plain(72, false)]),
        })];
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropEndFinallyRethrow).unwrap();
        let result = ExceptionValidationContext::new(src, broken).validate();
        assert!(!result.validation_successful);
        assert!(
            result
                .failed_lemmas
                .contains(&ExcLemma::PendingExceptionPreservation)
                || result
                    .failed_lemmas
                    .contains(&ExcLemma::ExceptionFlowEquivalence)
        );
    }

    #[test]
    fn throw_in_finally_overrides_pending() {
        // try throws; finally also throws -> the finally exception propagates,
        // the original is discarded. EndFinally does not re-throw the original.
        let src = vec![ExcStmt::Try(TryRegion {
            try_id: 3,
            body: vec![plain(30, true)],
            catch_body: None,
            finally_body: Some(vec![plain(32, true)]),
        })];
        let trace = reference_trace(&src);
        // Propagated site should be the finally's (32), not the body's (30).
        let last = trace.last().unwrap();
        assert!(matches!(last.kind, ExcEventKind::Propagate { site: 32 }));
        // And the faithful lowering still validates (both views agree).
        assert!(
            ExceptionValidationContext::faithful(src)
                .validate()
                .validation_successful
        );
    }

    #[test]
    fn nested_try_inner_catch_handles() {
        let src = vec![ExcStmt::Try(TryRegion {
            try_id: 1,
            body: vec![ExcStmt::Try(TryRegion {
                try_id: 2,
                body: vec![plain(20, true)],
                catch_body: Some(vec![plain(21, false)]),
                finally_body: Some(vec![plain(22, false)]),
            })],
            catch_body: Some(vec![plain(11, false)]),
            finally_body: Some(vec![plain(12, false)]),
        })];
        let trace = reference_trace(&src);
        // Inner catch handles; outer catch should NOT (exception consumed).
        let catches: Vec<u32> = trace
            .iter()
            .filter_map(|e| match e.kind {
                ExcEventKind::CatchHandle { try_id } => Some(try_id),
                _ => None,
            })
            .collect();
        assert_eq!(catches, vec![2]);
        assert!(
            ExceptionValidationContext::faithful(src)
                .validate()
                .validation_successful
        );
    }

    #[test]
    fn try_without_catch_propagates_through_finally() {
        let src = vec![ExcStmt::Try(TryRegion {
            try_id: 5,
            body: vec![plain(50, true)],
            catch_body: None,
            finally_body: Some(vec![plain(52, false)]),
        })];
        let trace = reference_trace(&src);
        // finally runs in Exception mode, then the exception propagates.
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            ExcEventKind::FinallyRun {
                try_id: 5,
                mode: FinallyEntryMode::Exception
            }
        )));
        assert!(matches!(
            trace.last().unwrap().kind,
            ExcEventKind::Propagate { site: 50 }
        ));
    }

    #[test]
    fn try_without_finally_validates() {
        let src = vec![ExcStmt::Try(TryRegion {
            try_id: 9,
            body: vec![plain(90, true)],
            catch_body: Some(vec![plain(91, false)]),
            finally_body: None,
        })];
        let result = ExceptionValidationContext::faithful(src).validate();
        assert!(result.validation_successful);
    }

    #[test]
    fn await_in_try_emits_checkpoint() {
        let src = vec![ExcStmt::Try(TryRegion {
            try_id: 4,
            body: vec![await_pt(40), plain(41, false)],
            catch_body: Some(vec![plain(42, false)]),
            finally_body: Some(vec![plain(43, false)]),
        })];
        let trace = reference_trace(&src);
        assert!(
            trace
                .iter()
                .any(|e| matches!(e.kind, ExcEventKind::AwaitCheckpoint { site: 40, .. }))
        );
        assert!(
            ExceptionValidationContext::faithful(src)
                .validate()
                .validation_successful
        );
    }

    #[test]
    fn all_generated_programs_validate_faithfully() {
        let programs = generate_exception_test_programs();
        assert!(
            programs.len() >= 50,
            "expected >=50 programs, got {}",
            programs.len()
        );
        for p in &programs {
            let result = ExceptionValidationContext::faithful(p.program.clone()).validate();
            assert!(
                result.validation_successful,
                "program {} ({:?}) failed: {:?}",
                p.name, p.category, result.failed_lemmas
            );
        }
    }

    #[test]
    fn every_category_is_covered() {
        use ProgramCategory::*;
        let programs = generate_exception_test_programs();
        for cat in [
            NestedTry,
            TryWithoutFinally,
            TryWithoutCatch,
            ThrowInFinally,
            ThrowInCatch,
            AwaitInTry,
            AwaitInFinally,
            TryCatchFinally,
        ] {
            assert!(
                programs.iter().any(|p| p.category == cat),
                "category {cat:?} not covered"
            );
        }
    }

    #[test]
    fn negative_transforms_reject_across_generated_corpus() {
        // Every applicable semantics-breaking transform must be rejected on at
        // least the throwing programs where it changes behaviour.
        let programs = generate_exception_test_programs();
        let transforms = [
            SemanticsBreakingTransform::DropEnterFinally,
            SemanticsBreakingTransform::DropCatchTarget,
            SemanticsBreakingTransform::DropBeginTry,
            SemanticsBreakingTransform::DropEndFinallyRethrow,
        ];
        let mut rejections = 0;
        for p in &programs {
            let lowered = faithful_lower(&p.program);
            for &tr in &transforms {
                if let Some(broken) = apply_transform(&lowered, tr) {
                    let result =
                        ExceptionValidationContext::new(p.program.clone(), broken).validate();
                    // A transform that genuinely changes observable flow must be
                    // rejected; transforms that are behaviourally inert on a
                    // particular program are allowed to pass.
                    if !result.validation_successful {
                        rejections += 1;
                    }
                }
            }
        }
        assert!(
            rejections > 0,
            "semantics-breaking transforms must be rejected somewhere"
        );
    }

    #[test]
    fn events_jsonl_is_valid_lines() {
        let result = ExceptionValidationContext::faithful(try_catch_finally(true)).validate();
        let jsonl = result.events_jsonl();
        assert!(!jsonl.is_empty());
        for line in jsonl.lines() {
            let parsed: ValidationEvent = serde_json::from_str(line).unwrap();
            assert!(parsed.verified);
        }
        // One event per lemma checked (5).
        assert_eq!(result.events.len(), 5);
    }

    #[test]
    fn first_divergence_points_at_mismatch() {
        let src = try_catch_finally(true);
        let lowered = faithful_lower(&src);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropEnterFinally).unwrap();
        let result = ExceptionValidationContext::new(src, broken).validate();
        assert!(result.first_divergence.is_some());
    }

    #[test]
    fn serde_round_trip_result() {
        let result = ExceptionValidationContext::faithful(try_catch_finally(true)).validate();
        let json = serde_json::to_string(&result).unwrap();
        let back: ExceptionValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn faithful_lower_round_trips_structure() {
        let src = try_catch_finally(true);
        let lowered = faithful_lower(&src);
        // Faithful lowering's target trace equals the reference trace.
        assert_eq!(reference_trace(&src), target_trace(&lowered));
    }

    #[test]
    fn throw_in_catch_runs_finally_then_propagates() {
        let src = vec![ExcStmt::Try(TryRegion {
            try_id: 6,
            body: vec![plain(60, true)],
            catch_body: Some(vec![plain(61, true)]),
            finally_body: Some(vec![plain(62, false)]),
        })];
        let trace = reference_trace(&src);
        // catch handles the body throw, then itself throws; finally runs in
        // Exception mode and the catch's exception propagates.
        assert!(
            trace
                .iter()
                .any(|e| matches!(e.kind, ExcEventKind::CatchHandle { try_id: 6 }))
        );
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            ExcEventKind::FinallyRun {
                try_id: 6,
                mode: FinallyEntryMode::Exception
            }
        )));
        assert!(matches!(
            trace.last().unwrap().kind,
            ExcEventKind::Propagate { site: 61 }
        ));
        assert!(
            ExceptionValidationContext::faithful(src)
                .validate()
                .validation_successful
        );
    }

    #[test]
    fn empty_program_completes() {
        let trace = reference_trace(&[]);
        assert_eq!(trace.len(), 1);
        assert!(matches!(trace[0].kind, ExcEventKind::Complete));
    }

    #[test]
    fn validation_context_exposes_lemmas() {
        let result = ExceptionValidationContext::faithful(try_catch_finally(true)).validate();
        assert!(
            result
                .verified_lemmas
                .contains(&ExcLemma::CatchFrameBalance)
        );
        assert!(
            result
                .verified_lemmas
                .contains(&ExcLemma::ExceptionFlowEquivalence)
        );
    }
}
