#![forbid(unsafe_code)]

//! G.6.B — Translation validation for `async`/`await` + microtask checkpoint
//! preservation (`bd-cixqu.7.9.2`, FE-CLAIM-017 / FE-CLAIM-018).
//!
//! ## What this proves
//! Async-function lowering turns every `await` into a continuation point: the
//! runtime suspends, drains a microtask checkpoint, then resumes the
//! continuation with its captured IFC context. This module is a *translation
//! validator* — for every async function it independently derives the observable
//! schedule from (a) the **source** async semantics and (b) the **lowered IR3**
//! instruction stream, then proves the two schedules are identical along three
//! axes the lowering must preserve:
//!
//! 1. **Observable behavior** — the ordered sequence of observable values the
//!    function produces, and its terminal completion (resolve value vs reject).
//! 2. **Microtask scheduling** — every `await` is exactly one microtask
//!    boundary; `Promise.all([...])` schedules one checkpoint per branch plus a
//!    single join checkpoint; the *order* of checkpoints relative to
//!    observations is preserved.
//! 3. **IFC label propagation** — the security (pc) label is monotone
//!    non-decreasing across every suspend/resume edge. A resume must never carry
//!    a label *below* its suspend, and must never lose a label join the source
//!    performed. Downgrading across suspension is the canonical way async
//!    lowering can silently leak, so it is a first-class, fail-closed rejection.
//!
//! The validator is the analogue of [`crate::full_ir_translation_validator`]'s
//! `break_witness` discipline (G.11 negative-test composition): a
//! "preserving-looking but broken" lowering must be **rejected**, not merely
//! flagged. [`break_lowering`] produces one mutant per [`EquivalenceViolation`]
//! variant so the rejection surface is exhaustively tested.
//!
//! ## Determinism
//! Labels are fixed-width `u8` lattice points (`0` = public, higher = more
//! restricted; the join is `max`). All ordering is positional. The
//! [`AsyncTranslationProof`] is content-addressed via
//! [`ContentHash`](crate::hash_tiers::ContentHash) so a validated program freezes
//! as a golden replay artifact.
//!
//! Per the `bd-cixqu.45` logging discipline both validated and rejected programs
//! emit a counts-only [`AsyncTranslationEvent`] line to `events.jsonl`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Source-level async model
// ---------------------------------------------------------------------------

/// A source-level operation in an abstract `async function` body.
///
/// Each variant carries the IFC label of the value it observes/awaits so the
/// validator can track label propagation. `Return`/`Throw` terminate the
/// function; any operations after the first terminator are unreachable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncSourceOp {
    /// A synchronous computation step producing an observable value at `label`.
    Compute { label: u8 },
    /// `await <expr>` where the awaited value carries `label`. One microtask
    /// boundary; the resumed continuation joins `label` into the pc label.
    Await { label: u8 },
    /// `for (..) { await <expr>; }` — `iterations` sequential awaits, each a
    /// distinct microtask boundary, each resuming at `label`.
    AwaitInLoop { iterations: u32, label: u8 },
    /// `await Promise.all([p0, p1, ...])` — concurrent awaits joined into one
    /// result. Each branch resolves on its own microtask; a final join
    /// microtask combines them, lifting the pc label to the lattice join of all
    /// branch labels.
    ParallelAwait { branch_labels: Vec<u8> },
    /// `try { await <expr> } catch (e) { <handler> }`. The awaited value carries
    /// `body_label`; when `rejects` is true the await throws and control
    /// transfers to the catch handler running at `handler_label` (the rejection
    /// is *caught* — the function does not reject). When `rejects` is false the
    /// body continues normally.
    TryAwait {
        body_label: u8,
        rejects: bool,
        handler_label: u8,
    },
    /// `return <expr>` — the function resolves with a value at `label` (joined
    /// with the current pc label).
    Return { label: u8 },
    /// An uncaught `throw` — the async function rejects; the rejection
    /// propagates out of the function.
    Throw,
}

/// Terminal completion of an async function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Completion {
    /// Resolved with a value carrying the given IFC label.
    Resolved { label: u8 },
    /// Rejected (an uncaught rejection propagated out).
    Rejected,
}

// ---------------------------------------------------------------------------
// Observable schedule (the common comparison surface)
// ---------------------------------------------------------------------------

/// A single observable event in an async function's execution schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceEvent {
    /// An observable value was produced carrying `label`.
    Observe { label: u8 },
    /// A microtask checkpoint at an await suspend/resume edge. `suspend_label`
    /// is the pc label captured at suspension; `resume_label` is the pc label
    /// the continuation resumes with (must be `>= suspend_label`).
    Checkpoint { suspend_label: u8, resume_label: u8 },
}

/// The observable schedule derived from one semantics (source or lowered IR3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulingTrace {
    /// Ordered observable events (observations + microtask checkpoints).
    pub events: Vec<TraceEvent>,
    /// Terminal completion of the function.
    pub completion: Completion,
}

impl SchedulingTrace {
    /// Number of microtask checkpoints in this schedule.
    #[must_use]
    pub fn microtask_checkpoints(&self) -> u32 {
        self.events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Checkpoint { .. }))
            .count() as u32
    }

    /// The highest IFC label observed anywhere in this schedule (lattice join of
    /// every label that appears).
    #[must_use]
    pub fn max_ifc_label(&self) -> u8 {
        let mut hi = match self.completion {
            Completion::Resolved { label } => label,
            Completion::Rejected => 0,
        };
        for e in &self.events {
            match e {
                TraceEvent::Observe { label } => hi = hi.max(*label),
                TraceEvent::Checkpoint {
                    suspend_label,
                    resume_label,
                } => hi = hi.max(*suspend_label).max(*resume_label),
            }
        }
        hi
    }
}

// ---------------------------------------------------------------------------
// Lowered IR3 model
// ---------------------------------------------------------------------------

/// An abstract lowered IR3 instruction relevant to async/await scheduling.
///
/// This mirrors the structurally-significant shape of the real
/// [`crate::ir_contract`] async continuation lowering while dropping register
/// operands, so a stream can be compared structurally and frozen as a golden
/// artifact. Completion is encoded as a trailing `Resolve`/`Reject` op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncIr3Op {
    /// An observable computation result at `label`.
    Observe { label: u8 },
    /// A plain `await` suspend → microtask drain → resume edge.
    AwaitCheckpoint { suspend_label: u8, resume_label: u8 },
    /// One branch of a `Promise.all` resolving on its own microtask.
    ParallelBranchCheckpoint { suspend_label: u8, resume_label: u8 },
    /// The `Promise.all` join microtask combining all branches.
    ParallelJoinCheckpoint { suspend_label: u8, resume_label: u8 },
    /// A catch-handler observation produced after a rejected (but caught) await.
    CatchObserve { label: u8 },
    /// The function resolves with a value at `label`.
    ResolveCompletion { label: u8 },
    /// The function rejects (uncaught rejection propagates out).
    RejectCompletion,
}

// ---------------------------------------------------------------------------
// Source semantics
// ---------------------------------------------------------------------------

/// Derive the observable schedule directly from the source async semantics.
///
/// This is the reference oracle: the pc label starts public (`0`) and joins
/// (`max`) with every value the function observes or awaits, modelling
/// implicit-flow label propagation. Each await emits one checkpoint capturing
/// the suspend/resume pc labels.
#[must_use]
pub fn source_semantics(source: &[AsyncSourceOp]) -> SchedulingTrace {
    let mut events = Vec::new();
    let mut pc: u8 = 0;
    let mut completion = Completion::Resolved { label: 0 };
    let mut completed = false;

    for op in source {
        if completed {
            break;
        }
        match op {
            AsyncSourceOp::Compute { label } => {
                pc = pc.max(*label);
                events.push(TraceEvent::Observe { label: pc });
            }
            AsyncSourceOp::Await { label } => {
                let suspend = pc;
                pc = pc.max(*label);
                events.push(TraceEvent::Checkpoint {
                    suspend_label: suspend,
                    resume_label: pc,
                });
            }
            AsyncSourceOp::AwaitInLoop { iterations, label } => {
                for _ in 0..*iterations {
                    let suspend = pc;
                    pc = pc.max(*label);
                    events.push(TraceEvent::Checkpoint {
                        suspend_label: suspend,
                        resume_label: pc,
                    });
                }
            }
            AsyncSourceOp::ParallelAwait { branch_labels } => {
                let suspend = pc;
                for bl in branch_labels {
                    events.push(TraceEvent::Checkpoint {
                        suspend_label: suspend,
                        resume_label: suspend.max(*bl),
                    });
                }
                let join = branch_labels.iter().fold(pc, |acc, b| acc.max(*b));
                events.push(TraceEvent::Checkpoint {
                    suspend_label: suspend,
                    resume_label: join,
                });
                pc = join;
            }
            AsyncSourceOp::TryAwait {
                body_label,
                rejects,
                handler_label,
            } => {
                let suspend = pc;
                let body_resume = pc.max(*body_label);
                events.push(TraceEvent::Checkpoint {
                    suspend_label: suspend,
                    resume_label: body_resume,
                });
                if *rejects {
                    pc = body_resume.max(*handler_label);
                } else {
                    pc = body_resume;
                }
                events.push(TraceEvent::Observe { label: pc });
            }
            AsyncSourceOp::Return { label } => {
                completion = Completion::Resolved {
                    label: pc.max(*label),
                };
                completed = true;
            }
            AsyncSourceOp::Throw => {
                completion = Completion::Rejected;
                completed = true;
            }
        }
    }

    if !completed {
        completion = Completion::Resolved { label: pc };
    }

    SchedulingTrace { events, completion }
}

// ---------------------------------------------------------------------------
// Lowering (IR3 emission) and lowered semantics
// ---------------------------------------------------------------------------

/// Lower a source async function to its IR3 continuation form.
///
/// This is an *independent* structural transformation (it does not replay the
/// reference trace): it walks the source and emits IR3 ops following the
/// async-lowering rules, tracking its own pc label. A correct lowering yields a
/// stream whose [`ir3_semantics`] schedule matches [`source_semantics`]; the
/// validator proves that equivalence and [`break_lowering`] perturbs it.
#[must_use]
pub fn lower(source: &[AsyncSourceOp]) -> Vec<AsyncIr3Op> {
    let mut out = Vec::new();
    let mut pc: u8 = 0;
    let mut completion: Option<Completion> = None;

    for op in source {
        if completion.is_some() {
            break;
        }
        match op {
            AsyncSourceOp::Compute { label } => {
                pc = pc.max(*label);
                out.push(AsyncIr3Op::Observe { label: pc });
            }
            AsyncSourceOp::Await { label } => {
                let suspend = pc;
                pc = pc.max(*label);
                out.push(AsyncIr3Op::AwaitCheckpoint {
                    suspend_label: suspend,
                    resume_label: pc,
                });
            }
            AsyncSourceOp::AwaitInLoop { iterations, label } => {
                for _ in 0..*iterations {
                    let suspend = pc;
                    pc = pc.max(*label);
                    out.push(AsyncIr3Op::AwaitCheckpoint {
                        suspend_label: suspend,
                        resume_label: pc,
                    });
                }
            }
            AsyncSourceOp::ParallelAwait { branch_labels } => {
                let suspend = pc;
                for bl in branch_labels {
                    out.push(AsyncIr3Op::ParallelBranchCheckpoint {
                        suspend_label: suspend,
                        resume_label: suspend.max(*bl),
                    });
                }
                let join = branch_labels.iter().fold(pc, |acc, b| acc.max(*b));
                out.push(AsyncIr3Op::ParallelJoinCheckpoint {
                    suspend_label: suspend,
                    resume_label: join,
                });
                pc = join;
            }
            AsyncSourceOp::TryAwait {
                body_label,
                rejects,
                handler_label,
            } => {
                let suspend = pc;
                let body_resume = pc.max(*body_label);
                out.push(AsyncIr3Op::AwaitCheckpoint {
                    suspend_label: suspend,
                    resume_label: body_resume,
                });
                if *rejects {
                    pc = body_resume.max(*handler_label);
                    out.push(AsyncIr3Op::CatchObserve { label: pc });
                } else {
                    pc = body_resume;
                    out.push(AsyncIr3Op::Observe { label: pc });
                }
            }
            AsyncSourceOp::Return { label } => {
                completion = Some(Completion::Resolved {
                    label: pc.max(*label),
                });
            }
            AsyncSourceOp::Throw => {
                completion = Some(Completion::Rejected);
            }
        }
    }

    match completion {
        Some(Completion::Resolved { label }) => out.push(AsyncIr3Op::ResolveCompletion { label }),
        Some(Completion::Rejected) => out.push(AsyncIr3Op::RejectCompletion),
        None => out.push(AsyncIr3Op::ResolveCompletion { label: pc }),
    }

    out
}

/// Derive the observable schedule from a lowered IR3 instruction stream.
///
/// This is independent of [`source_semantics`]: it interprets the lowered ops
/// directly. Equivalence of the two schedules is what the validator proves.
#[must_use]
pub fn ir3_semantics(ir3: &[AsyncIr3Op]) -> SchedulingTrace {
    let mut events = Vec::new();
    let mut completion = Completion::Resolved { label: 0 };
    let mut completed = false;

    for op in ir3 {
        if completed {
            break;
        }
        match op {
            AsyncIr3Op::Observe { label } | AsyncIr3Op::CatchObserve { label } => {
                events.push(TraceEvent::Observe { label: *label });
            }
            AsyncIr3Op::AwaitCheckpoint {
                suspend_label,
                resume_label,
            }
            | AsyncIr3Op::ParallelBranchCheckpoint {
                suspend_label,
                resume_label,
            }
            | AsyncIr3Op::ParallelJoinCheckpoint {
                suspend_label,
                resume_label,
            } => {
                events.push(TraceEvent::Checkpoint {
                    suspend_label: *suspend_label,
                    resume_label: *resume_label,
                });
            }
            AsyncIr3Op::ResolveCompletion { label } => {
                completion = Completion::Resolved { label: *label };
                completed = true;
            }
            AsyncIr3Op::RejectCompletion => {
                completion = Completion::Rejected;
                completed = true;
            }
        }
    }

    SchedulingTrace { events, completion }
}

// ---------------------------------------------------------------------------
// Equivalence violations (ordered, fail-closed)
// ---------------------------------------------------------------------------

/// A reason an async lowering failed translation validation. Classification is
/// by *first divergence* between the source and lowered schedules; for a
/// diverging checkpoint, an IFC downgrade is reported in preference to a generic
/// schedule mismatch (it is the security-critical case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivalenceViolation {
    /// The schedules agree on their common prefix but have different lengths
    /// (the lowering added or dropped events — e.g. a missing microtask
    /// checkpoint).
    EventCountMismatch {
        source_len: usize,
        lowered_len: usize,
    },
    /// An observable value differs at `index`.
    ObservableValueMismatch {
        index: usize,
        source_label: u8,
        lowered_label: u8,
    },
    /// The event *kind* differs at `index` (e.g. source scheduled a microtask
    /// checkpoint where the lowering produced an observation), or two
    /// checkpoints differ in a non-downgrade way (e.g. suspend label).
    MicrotaskScheduleMismatch { index: usize, detail: String },
    /// A resume carries an IFC label *below* its suspend, or below the label the
    /// source resumed with — a label downgrade across suspension. Fail-closed.
    IfcLabelDowngraded {
        index: usize,
        suspend_label: u8,
        source_resume: u8,
        lowered_resume: u8,
    },
    /// The terminal completion differs (resolve vs reject, or resolve label).
    CompletionMismatch {
        source: Completion,
        lowered: Completion,
    },
}

impl EquivalenceViolation {
    /// Stable machine-readable code for the `bd-cixqu.45` event log.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::EventCountMismatch { .. } => "event_count_mismatch",
            Self::ObservableValueMismatch { .. } => "observable_value_mismatch",
            Self::MicrotaskScheduleMismatch { .. } => "microtask_schedule_mismatch",
            Self::IfcLabelDowngraded { .. } => "ifc_label_downgraded",
            Self::CompletionMismatch { .. } => "completion_mismatch",
        }
    }

    /// Human-readable detail string.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::EventCountMismatch {
                source_len,
                lowered_len,
            } => format!("event count {source_len} (source) vs {lowered_len} (lowered)"),
            Self::ObservableValueMismatch {
                index,
                source_label,
                lowered_label,
            } => format!(
                "observable @{index}: source label {source_label} vs lowered {lowered_label}"
            ),
            Self::MicrotaskScheduleMismatch { index, detail } => {
                format!("microtask schedule @{index}: {detail}")
            }
            Self::IfcLabelDowngraded {
                index,
                suspend_label,
                source_resume,
                lowered_resume,
            } => format!(
                "ifc downgrade @{index}: suspend {suspend_label}, source resume {source_resume}, lowered resume {lowered_resume}"
            ),
            Self::CompletionMismatch { source, lowered } => {
                format!("completion: source {source:?} vs lowered {lowered:?}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The translation validator
// ---------------------------------------------------------------------------

/// A content-addressed proof that a lowering preserves async/await semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncTranslationProof {
    /// The program this proof is for.
    pub program_name: String,
    /// The feature category exercised.
    pub category: AsyncFeatureCategory,
    /// Number of source operations.
    pub source_op_count: usize,
    /// Number of lowered IR3 ops.
    pub lowered_op_count: usize,
    /// Number of microtask checkpoints in the (identical) schedule.
    pub microtask_checkpoints: u32,
    /// Highest IFC label propagated anywhere in the schedule.
    pub max_ifc_label: u8,
    /// The (identical) terminal completion.
    pub completion: Completion,
    /// Content hash over the canonical (source, lowered, trace) bytes.
    pub proof_hash: ContentHash,
}

/// Canonical bytes a proof hash is computed over (deterministic field order).
#[derive(Serialize)]
struct ProofPreimage<'a> {
    program_name: &'a str,
    category: AsyncFeatureCategory,
    source: &'a [AsyncSourceOp],
    lowered: &'a [AsyncIr3Op],
    trace: &'a SchedulingTrace,
}

/// Prove that `lowered` preserves the async semantics of `source`.
///
/// Returns an [`AsyncTranslationProof`] when the lowered schedule is identical
/// to the source schedule along all three preserved axes, or the first
/// [`EquivalenceViolation`]. Pure and deterministic.
///
/// # Errors
/// Returns an [`EquivalenceViolation`] identifying the first axis along which
/// the lowered schedule diverges from the source schedule.
pub fn verify_async_translation(
    program_name: &str,
    category: AsyncFeatureCategory,
    source: &[AsyncSourceOp],
    lowered: &[AsyncIr3Op],
) -> Result<AsyncTranslationProof, EquivalenceViolation> {
    let src_trace = source_semantics(source);
    let low_trace = ir3_semantics(lowered);

    let common = src_trace.events.len().min(low_trace.events.len());
    for i in 0..common {
        let s = src_trace.events[i];
        let l = low_trace.events[i];
        match (s, l) {
            (TraceEvent::Observe { label: sl }, TraceEvent::Observe { label: ll }) => {
                if sl != ll {
                    return Err(EquivalenceViolation::ObservableValueMismatch {
                        index: i,
                        source_label: sl,
                        lowered_label: ll,
                    });
                }
            }
            (
                TraceEvent::Checkpoint {
                    suspend_label: ss,
                    resume_label: sr,
                },
                TraceEvent::Checkpoint {
                    suspend_label: ls,
                    resume_label: lr,
                },
            ) => {
                // Security-critical case first: a resume that drops below its
                // own suspend, or below the label the source resumed with, is a
                // label downgrade across suspension.
                if lr < ls || lr < sr {
                    return Err(EquivalenceViolation::IfcLabelDowngraded {
                        index: i,
                        suspend_label: ls,
                        source_resume: sr,
                        lowered_resume: lr,
                    });
                }
                if ss != ls || sr != lr {
                    return Err(EquivalenceViolation::MicrotaskScheduleMismatch {
                        index: i,
                        detail: format!(
                            "checkpoint labels source (s={ss},r={sr}) vs lowered (s={ls},r={lr})"
                        ),
                    });
                }
            }
            (TraceEvent::Observe { .. }, TraceEvent::Checkpoint { .. }) => {
                return Err(EquivalenceViolation::MicrotaskScheduleMismatch {
                    index: i,
                    detail: "source observed a value where lowering scheduled a microtask".into(),
                });
            }
            (TraceEvent::Checkpoint { .. }, TraceEvent::Observe { .. }) => {
                return Err(EquivalenceViolation::MicrotaskScheduleMismatch {
                    index: i,
                    detail: "source scheduled a microtask where lowering observed a value".into(),
                });
            }
        }
    }

    if src_trace.events.len() != low_trace.events.len() {
        return Err(EquivalenceViolation::EventCountMismatch {
            source_len: src_trace.events.len(),
            lowered_len: low_trace.events.len(),
        });
    }

    if src_trace.completion != low_trace.completion {
        return Err(EquivalenceViolation::CompletionMismatch {
            source: src_trace.completion,
            lowered: low_trace.completion,
        });
    }

    let preimage = ProofPreimage {
        program_name,
        category,
        source,
        lowered,
        trace: &src_trace,
    };
    let bytes = serde_json::to_vec(&preimage)
        .expect("ProofPreimage is always serialisable (no maps, no non-finite floats)");

    Ok(AsyncTranslationProof {
        program_name: program_name.to_string(),
        category,
        source_op_count: source.len(),
        lowered_op_count: lowered.len(),
        microtask_checkpoints: src_trace.microtask_checkpoints(),
        max_ifc_label: src_trace.max_ifc_label(),
        completion: src_trace.completion,
        proof_hash: ContentHash::compute(&bytes),
    })
}

/// Lower `program` and prove its lowering preserves async semantics.
///
/// # Errors
/// Propagates the first [`EquivalenceViolation`] from
/// [`verify_async_translation`].
pub fn verify_program(
    program: &AsyncProgram,
) -> Result<AsyncTranslationProof, EquivalenceViolation> {
    let lowered = lower(&program.source);
    verify_async_translation(&program.name, program.category, &program.source, &lowered)
}

// ---------------------------------------------------------------------------
// Negative-test mutators (G.11 composition)
// ---------------------------------------------------------------------------

/// A semantics-breaking mutation of a lowered IR3 stream. Each variant targets a
/// distinct [`EquivalenceViolation`] so the rejection surface is exhaustively
/// covered by negative tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoweringMutation {
    /// Delete the first microtask checkpoint (changes the schedule length).
    DropCheckpoint,
    /// Set the first checkpoint's resume label below its suspend label
    /// (an IFC downgrade across suspension).
    DowngradeResumeLabel,
    /// Corrupt the first observable value's label.
    CorruptObservable,
    /// Flip the completion between resolve and reject.
    SwapCompletion,
    /// Replace the first checkpoint with an observation (schedule-shape change).
    DropMicrotaskShape,
}

impl LoweringMutation {
    /// All mutation kinds, for exhaustive negative-test enumeration.
    pub const ALL: [LoweringMutation; 5] = [
        LoweringMutation::DropCheckpoint,
        LoweringMutation::DowngradeResumeLabel,
        LoweringMutation::CorruptObservable,
        LoweringMutation::SwapCompletion,
        LoweringMutation::DropMicrotaskShape,
    ];
}

/// Produce a broken lowering by applying `mutation` to a correct one.
///
/// Returns `None` when the lowering has no op the mutation can target (e.g. a
/// program with no checkpoint for [`LoweringMutation::DropCheckpoint`]). A
/// `Some` result is guaranteed to be rejected by [`verify_async_translation`].
#[must_use]
pub fn break_lowering(
    lowered: &[AsyncIr3Op],
    mutation: LoweringMutation,
) -> Option<Vec<AsyncIr3Op>> {
    let is_checkpoint = |op: &AsyncIr3Op| {
        matches!(
            op,
            AsyncIr3Op::AwaitCheckpoint { .. }
                | AsyncIr3Op::ParallelBranchCheckpoint { .. }
                | AsyncIr3Op::ParallelJoinCheckpoint { .. }
        )
    };
    let mut out = lowered.to_vec();
    match mutation {
        LoweringMutation::DropCheckpoint => {
            let idx = out.iter().position(is_checkpoint)?;
            out.remove(idx);
            Some(out)
        }
        LoweringMutation::DowngradeResumeLabel => {
            let idx = out.iter().position(|op| match op {
                AsyncIr3Op::AwaitCheckpoint { suspend_label, .. }
                | AsyncIr3Op::ParallelBranchCheckpoint { suspend_label, .. }
                | AsyncIr3Op::ParallelJoinCheckpoint { suspend_label, .. } => *suspend_label > 0,
                _ => false,
            })?;
            // Downgrade the resume to below the suspend label.
            match &mut out[idx] {
                AsyncIr3Op::AwaitCheckpoint {
                    suspend_label,
                    resume_label,
                }
                | AsyncIr3Op::ParallelBranchCheckpoint {
                    suspend_label,
                    resume_label,
                }
                | AsyncIr3Op::ParallelJoinCheckpoint {
                    suspend_label,
                    resume_label,
                } => {
                    *resume_label = suspend_label.saturating_sub(1);
                }
                _ => unreachable!("position predicate restricts to checkpoints"),
            }
            Some(out)
        }
        LoweringMutation::CorruptObservable => {
            let idx = out.iter().position(|op| {
                matches!(
                    op,
                    AsyncIr3Op::Observe { .. } | AsyncIr3Op::CatchObserve { .. }
                )
            })?;
            match &mut out[idx] {
                AsyncIr3Op::Observe { label } | AsyncIr3Op::CatchObserve { label } => {
                    *label = label.wrapping_add(7).wrapping_add(1);
                }
                _ => unreachable!("position predicate restricts to observations"),
            }
            Some(out)
        }
        LoweringMutation::SwapCompletion => {
            let idx = out.iter().position(|op| {
                matches!(
                    op,
                    AsyncIr3Op::ResolveCompletion { .. } | AsyncIr3Op::RejectCompletion
                )
            })?;
            out[idx] = match &out[idx] {
                AsyncIr3Op::ResolveCompletion { .. } => AsyncIr3Op::RejectCompletion,
                AsyncIr3Op::RejectCompletion => AsyncIr3Op::ResolveCompletion { label: 0 },
                _ => unreachable!("position predicate restricts to completions"),
            };
            Some(out)
        }
        LoweringMutation::DropMicrotaskShape => {
            let idx = out.iter().position(is_checkpoint)?;
            // Replace the checkpoint with an observation: same length, different
            // schedule shape.
            out[idx] = AsyncIr3Op::Observe { label: 0 };
            Some(out)
        }
    }
}

// ---------------------------------------------------------------------------
// Program corpus
// ---------------------------------------------------------------------------

/// The async feature category a generated program exercises (G.6.B coverage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AsyncFeatureCategory {
    /// A single top-level `await`.
    SimpleAwait,
    /// `await` inside a loop.
    AwaitInLoop,
    /// `await Promise.all([...])`.
    ParallelAwait,
    /// An uncaught rejection propagating through awaits.
    ErrorPropagation,
    /// `await` inside `try`/`catch`.
    AwaitTryCatch,
}

impl AsyncFeatureCategory {
    /// All categories the G.6.B corpus must cover.
    pub const ALL: [AsyncFeatureCategory; 5] = [
        AsyncFeatureCategory::SimpleAwait,
        AsyncFeatureCategory::AwaitInLoop,
        AsyncFeatureCategory::ParallelAwait,
        AsyncFeatureCategory::ErrorPropagation,
        AsyncFeatureCategory::AwaitTryCatch,
    ];

    /// Stable string for logging/manifests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SimpleAwait => "simple_await",
            Self::AwaitInLoop => "await_in_loop",
            Self::ParallelAwait => "parallel_await",
            Self::ErrorPropagation => "error_propagation",
            Self::AwaitTryCatch => "await_try_catch",
        }
    }
}

/// A generated async program: a named source body in one feature category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncProgram {
    pub name: String,
    pub category: AsyncFeatureCategory,
    pub source: Vec<AsyncSourceOp>,
}

/// Generate the standard G.6.B corpus of async programs.
///
/// Produces at least 50 programs spread across all five
/// [`AsyncFeatureCategory`] variants, parameterised deterministically over label
/// and shape so the corpus is reproducible. Every program is constructed to be
/// well-formed (its canonical [`lower`]ing passes [`verify_program`]).
#[must_use]
pub fn generate_async_programs() -> Vec<AsyncProgram> {
    let mut programs = Vec::new();

    // --- SimpleAwait: a compute, one await, a return (12 programs) ---
    for (i, (cl, al, rl)) in [
        (0u8, 0u8, 0u8),
        (0, 1, 1),
        (1, 0, 1),
        (0, 2, 2),
        (1, 2, 2),
        (2, 1, 2),
        (0, 3, 3),
        (2, 3, 3),
        (3, 0, 3),
        (1, 4, 4),
        (4, 2, 4),
        (0, 5, 5),
    ]
    .into_iter()
    .enumerate()
    {
        programs.push(AsyncProgram {
            name: format!("simple_await_{i:02}"),
            category: AsyncFeatureCategory::SimpleAwait,
            source: vec![
                AsyncSourceOp::Compute { label: cl },
                AsyncSourceOp::Await { label: al },
                AsyncSourceOp::Return { label: rl },
            ],
        });
    }

    // --- AwaitInLoop: a compute, an awaiting loop, a return (12 programs) ---
    for (i, (iters, al)) in [
        (1u32, 0u8),
        (2, 0),
        (1, 1),
        (3, 1),
        (2, 2),
        (4, 1),
        (3, 2),
        (5, 0),
        (2, 3),
        (6, 1),
        (4, 2),
        (3, 3),
    ]
    .into_iter()
    .enumerate()
    {
        programs.push(AsyncProgram {
            name: format!("await_in_loop_{i:02}"),
            category: AsyncFeatureCategory::AwaitInLoop,
            source: vec![
                AsyncSourceOp::Compute { label: 0 },
                AsyncSourceOp::AwaitInLoop {
                    iterations: iters,
                    label: al,
                },
                AsyncSourceOp::Return { label: al },
            ],
        });
    }

    // --- ParallelAwait: Promise.all over varied branch labels (12 programs) ---
    let parallel_shapes: [Vec<u8>; 12] = [
        vec![0, 0],
        vec![0, 1],
        vec![1, 0],
        vec![1, 2],
        vec![2, 1, 0],
        vec![0, 1, 2],
        vec![3, 3],
        vec![0, 2, 4],
        vec![1, 1, 1],
        vec![4, 0, 2, 1],
        vec![2, 3, 1, 0],
        vec![5, 1, 3],
    ];
    for (i, branch_labels) in parallel_shapes.into_iter().enumerate() {
        let ret = branch_labels.iter().copied().max().unwrap_or(0);
        programs.push(AsyncProgram {
            name: format!("parallel_await_{i:02}"),
            category: AsyncFeatureCategory::ParallelAwait,
            source: vec![
                AsyncSourceOp::Compute { label: 0 },
                AsyncSourceOp::ParallelAwait { branch_labels },
                AsyncSourceOp::Return { label: ret },
            ],
        });
    }

    // --- ErrorPropagation: awaits then an uncaught throw (12 programs) ---
    for (i, (cl, al)) in [
        (0u8, 0u8),
        (0, 1),
        (1, 0),
        (1, 2),
        (2, 1),
        (0, 3),
        (3, 0),
        (2, 3),
        (1, 4),
        (4, 1),
        (0, 5),
        (3, 2),
    ]
    .into_iter()
    .enumerate()
    {
        programs.push(AsyncProgram {
            name: format!("error_propagation_{i:02}"),
            category: AsyncFeatureCategory::ErrorPropagation,
            source: vec![
                AsyncSourceOp::Compute { label: cl },
                AsyncSourceOp::Await { label: al },
                AsyncSourceOp::Throw,
            ],
        });
    }

    // --- AwaitTryCatch: try/catch around an await, caught and uncaught (12) ---
    for (i, (body, rejects, handler)) in [
        (0u8, false, 0u8),
        (1, false, 0),
        (0, true, 1),
        (1, true, 2),
        (2, false, 1),
        (2, true, 0),
        (3, true, 1),
        (0, true, 3),
        (1, false, 2),
        (3, false, 0),
        (4, true, 2),
        (2, true, 3),
    ]
    .into_iter()
    .enumerate()
    {
        programs.push(AsyncProgram {
            name: format!("await_try_catch_{i:02}"),
            category: AsyncFeatureCategory::AwaitTryCatch,
            source: vec![
                AsyncSourceOp::Compute { label: 0 },
                AsyncSourceOp::TryAwait {
                    body_label: body,
                    rejects,
                    handler_label: handler,
                },
                AsyncSourceOp::Return { label: 0 },
            ],
        });
    }

    programs
}

// ---------------------------------------------------------------------------
// bd-cixqu.45 structured logging
// ---------------------------------------------------------------------------

/// A structured, counts-only translation-validation event emitted as one JSONL
/// line per the `bd-cixqu.45` logging discipline. Both validated and rejected
/// programs emit an event so a gate run produces an auditable trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncTranslationEvent {
    /// `async_translation_validated` or `async_translation_rejected`.
    pub event: String,
    /// The program identifier.
    pub program_name: String,
    /// The async feature category exercised.
    pub category: String,
    /// Number of source operations.
    pub source_op_count: usize,
    /// Number of microtask checkpoints in the schedule.
    pub microtask_checkpoints: u32,
    /// Highest IFC label propagated in the schedule.
    pub max_ifc_label: u8,
    /// Whether the lowering passed translation validation.
    pub validated: bool,
    /// `validated`, or the rejection [`EquivalenceViolation::code`].
    pub outcome: String,
    /// Human-readable detail.
    pub detail: String,
    /// Hex content hash of the proof, or empty when rejected.
    pub proof_hash: String,
}

impl AsyncTranslationEvent {
    /// Build the event for a validated program.
    #[must_use]
    pub fn validated(proof: &AsyncTranslationProof) -> Self {
        Self {
            event: "async_translation_validated".to_string(),
            program_name: proof.program_name.clone(),
            category: proof.category.as_str().to_string(),
            source_op_count: proof.source_op_count,
            microtask_checkpoints: proof.microtask_checkpoints,
            max_ifc_label: proof.max_ifc_label,
            validated: true,
            outcome: "validated".to_string(),
            detail: format!(
                "{} checkpoints, max label {}",
                proof.microtask_checkpoints, proof.max_ifc_label
            ),
            proof_hash: proof.proof_hash.to_hex(),
        }
    }

    /// Build the event for a rejected program.
    #[must_use]
    pub fn rejected(
        program_name: &str,
        category: AsyncFeatureCategory,
        source_op_count: usize,
        violation: &EquivalenceViolation,
    ) -> Self {
        Self {
            event: "async_translation_rejected".to_string(),
            program_name: program_name.to_string(),
            category: category.as_str().to_string(),
            source_op_count,
            microtask_checkpoints: 0,
            max_ifc_label: 0,
            validated: false,
            outcome: violation.code().to_string(),
            detail: violation.detail(),
            proof_hash: String::new(),
        }
    }

    /// Serialise to a single JSONL line (no trailing newline).
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).expect("AsyncTranslationEvent is always serialisable")
    }
}

/// Append a structured event as one line to an `events.jsonl` file, creating it
/// if absent. This is the production-shaped logging sink the `bd-cixqu.45`
/// discipline expects each translation-validation outcome to emit.
///
/// # Errors
/// Returns any I/O error from opening or writing the log file.
pub fn append_event_line(path: &Path, event: &AsyncTranslationEvent) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", event.to_jsonl())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple(c: u8, a: u8, r: u8) -> Vec<AsyncSourceOp> {
        vec![
            AsyncSourceOp::Compute { label: c },
            AsyncSourceOp::Await { label: a },
            AsyncSourceOp::Return { label: r },
        ]
    }

    // --- source semantics ---

    #[test]
    fn simple_await_schedule_has_one_checkpoint() {
        let trace = source_semantics(&simple(0, 1, 1));
        assert_eq!(trace.microtask_checkpoints(), 1);
        assert_eq!(trace.completion, Completion::Resolved { label: 1 });
    }

    #[test]
    fn pc_label_is_monotone_non_decreasing() {
        let src = vec![
            AsyncSourceOp::Compute { label: 1 },
            AsyncSourceOp::Await { label: 0 },
            AsyncSourceOp::Await { label: 2 },
            AsyncSourceOp::Return { label: 0 },
        ];
        let trace = source_semantics(&src);
        let mut floor = 0u8;
        for e in &trace.events {
            match e {
                TraceEvent::Observe { label } => {
                    assert!(*label >= floor);
                    floor = *label;
                }
                TraceEvent::Checkpoint {
                    suspend_label,
                    resume_label,
                } => {
                    assert!(*suspend_label >= floor);
                    assert!(*resume_label >= *suspend_label);
                    floor = *resume_label;
                }
            }
        }
        // Awaiting a label-0 value after pc=1 must not downgrade pc.
        assert_eq!(trace.completion, Completion::Resolved { label: 2 });
    }

    #[test]
    fn await_in_loop_emits_one_checkpoint_per_iteration() {
        let src = vec![
            AsyncSourceOp::AwaitInLoop {
                iterations: 4,
                label: 2,
            },
            AsyncSourceOp::Return { label: 0 },
        ];
        assert_eq!(source_semantics(&src).microtask_checkpoints(), 4);
    }

    #[test]
    fn parallel_await_emits_branch_plus_join_checkpoints() {
        let src = vec![
            AsyncSourceOp::ParallelAwait {
                branch_labels: vec![1, 2, 0],
            },
            AsyncSourceOp::Return { label: 0 },
        ];
        let trace = source_semantics(&src);
        // 3 branches + 1 join.
        assert_eq!(trace.microtask_checkpoints(), 4);
        // Join lifts pc to the lattice join of all branch labels.
        assert_eq!(trace.completion, Completion::Resolved { label: 2 });
    }

    #[test]
    fn uncaught_throw_rejects() {
        let src = vec![
            AsyncSourceOp::Await { label: 3 },
            AsyncSourceOp::Throw,
            AsyncSourceOp::Return { label: 0 },
        ];
        let trace = source_semantics(&src);
        assert_eq!(trace.completion, Completion::Rejected);
        // The unreachable Return after Throw must not execute.
        assert_eq!(trace.microtask_checkpoints(), 1);
    }

    #[test]
    fn caught_rejection_does_not_reject_function() {
        let src = vec![
            AsyncSourceOp::TryAwait {
                body_label: 1,
                rejects: true,
                handler_label: 2,
            },
            AsyncSourceOp::Return { label: 0 },
        ];
        let trace = source_semantics(&src);
        assert_eq!(trace.completion, Completion::Resolved { label: 2 });
    }

    #[test]
    fn try_await_caught_runs_handler_at_joined_label() {
        let src = vec![AsyncSourceOp::TryAwait {
            body_label: 3,
            rejects: true,
            handler_label: 1,
        }];
        let trace = source_semantics(&src);
        // Handler observes at max(body, handler) = 3.
        assert!(matches!(
            trace.events.last(),
            Some(TraceEvent::Observe { label: 3 })
        ));
    }

    // --- lowering round-trips through both semantics ---

    #[test]
    fn lowering_preserves_source_schedule_for_all_categories() {
        for program in generate_async_programs() {
            let src_trace = source_semantics(&program.source);
            let low_trace = ir3_semantics(&lower(&program.source));
            assert_eq!(
                src_trace, low_trace,
                "schedule mismatch for {}",
                program.name
            );
        }
    }

    #[test]
    fn every_generated_program_validates() {
        for program in generate_async_programs() {
            let proof = verify_program(&program)
                .unwrap_or_else(|e| panic!("{} should validate: {e:?}", program.name));
            assert_eq!(proof.program_name, program.name);
            assert_eq!(proof.category, program.category);
        }
    }

    #[test]
    fn lower_terminates_after_throw() {
        let src = vec![
            AsyncSourceOp::Await { label: 1 },
            AsyncSourceOp::Throw,
            AsyncSourceOp::Await { label: 2 },
        ];
        let lowered = lower(&src);
        assert!(matches!(lowered.last(), Some(AsyncIr3Op::RejectCompletion)));
        // Only the first await's checkpoint should have been emitted.
        let checkpoints = lowered
            .iter()
            .filter(|o| matches!(o, AsyncIr3Op::AwaitCheckpoint { .. }))
            .count();
        assert_eq!(checkpoints, 1);
    }

    // --- corpus breadth ---

    #[test]
    fn corpus_meets_minimum_size_and_breadth() {
        let programs = generate_async_programs();
        assert!(
            programs.len() >= 50,
            "expected >=50 generated programs, got {}",
            programs.len()
        );
        for category in AsyncFeatureCategory::ALL {
            let count = programs.iter().filter(|p| p.category == category).count();
            assert!(count >= 5, "category {:?} under-covered: {count}", category);
        }
    }

    #[test]
    fn corpus_program_names_are_unique() {
        let programs = generate_async_programs();
        let mut names: Vec<&str> = programs.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        let len = names.len();
        names.dedup();
        assert_eq!(names.len(), len, "duplicate program names in corpus");
    }

    #[test]
    fn corpus_is_deterministic() {
        let a = generate_async_programs();
        let b = generate_async_programs();
        assert_eq!(a, b);
    }

    // --- proof determinism & content addressing ---

    #[test]
    fn proof_hash_is_deterministic() {
        let p = &generate_async_programs()[0];
        let h1 = verify_program(p).unwrap().proof_hash;
        let h2 = verify_program(p).unwrap().proof_hash;
        assert_eq!(h1, h2);
    }

    #[test]
    fn distinct_programs_have_distinct_proof_hashes() {
        let programs = generate_async_programs();
        let mut hashes: Vec<String> = programs
            .iter()
            .map(|p| verify_program(p).unwrap().proof_hash.to_hex())
            .collect();
        let total = hashes.len();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), total, "proof hash collision across corpus");
    }

    #[test]
    fn proof_reports_checkpoint_and_label_counts() {
        let program = AsyncProgram {
            name: "p".into(),
            category: AsyncFeatureCategory::ParallelAwait,
            source: vec![
                AsyncSourceOp::ParallelAwait {
                    branch_labels: vec![1, 3, 2],
                },
                AsyncSourceOp::Return { label: 0 },
            ],
        };
        let proof = verify_program(&program).unwrap();
        assert_eq!(proof.microtask_checkpoints, 4); // 3 branches + join
        assert_eq!(proof.max_ifc_label, 3);
    }

    // --- negative tests: each mutation is rejected with the right code ---

    #[test]
    fn drop_checkpoint_is_rejected() {
        let program = &generate_async_programs()[1]; // simple await with a checkpoint
        let lowered = lower(&program.source);
        let broken = break_lowering(&lowered, LoweringMutation::DropCheckpoint).unwrap();
        let err =
            verify_async_translation(&program.name, program.category, &program.source, &broken)
                .unwrap_err();
        // Dropping a checkpoint either shortens the schedule or shifts a kind.
        assert!(matches!(
            err,
            EquivalenceViolation::EventCountMismatch { .. }
                | EquivalenceViolation::MicrotaskScheduleMismatch { .. }
        ));
    }

    #[test]
    fn downgrade_resume_label_is_rejected_as_ifc_downgrade() {
        // Pick a program whose await has a non-zero suspend label.
        let program = AsyncProgram {
            name: "downgrade".into(),
            category: AsyncFeatureCategory::SimpleAwait,
            source: vec![
                AsyncSourceOp::Compute { label: 2 },
                AsyncSourceOp::Await { label: 3 },
                AsyncSourceOp::Return { label: 0 },
            ],
        };
        let lowered = lower(&program.source);
        let broken = break_lowering(&lowered, LoweringMutation::DowngradeResumeLabel).unwrap();
        let err =
            verify_async_translation(&program.name, program.category, &program.source, &broken)
                .unwrap_err();
        assert!(matches!(
            err,
            EquivalenceViolation::IfcLabelDowngraded { .. }
        ));
        assert_eq!(err.code(), "ifc_label_downgraded");
    }

    #[test]
    fn corrupt_observable_is_rejected() {
        let program = &generate_async_programs()[2];
        let lowered = lower(&program.source);
        let broken = break_lowering(&lowered, LoweringMutation::CorruptObservable).unwrap();
        let err =
            verify_async_translation(&program.name, program.category, &program.source, &broken)
                .unwrap_err();
        assert!(matches!(
            err,
            EquivalenceViolation::ObservableValueMismatch { .. }
        ));
    }

    #[test]
    fn swap_completion_is_rejected() {
        let program = &generate_async_programs()[0];
        let lowered = lower(&program.source);
        let broken = break_lowering(&lowered, LoweringMutation::SwapCompletion).unwrap();
        let err =
            verify_async_translation(&program.name, program.category, &program.source, &broken)
                .unwrap_err();
        assert!(matches!(
            err,
            EquivalenceViolation::CompletionMismatch { .. }
        ));
    }

    #[test]
    fn drop_microtask_shape_is_rejected() {
        let program = &generate_async_programs()[3];
        let lowered = lower(&program.source);
        let broken = break_lowering(&lowered, LoweringMutation::DropMicrotaskShape).unwrap();
        let err =
            verify_async_translation(&program.name, program.category, &program.source, &broken)
                .unwrap_err();
        assert!(matches!(
            err,
            EquivalenceViolation::MicrotaskScheduleMismatch { .. }
        ));
    }

    #[test]
    fn every_mutation_rejects_some_program() {
        // For each mutation kind, at least one corpus program is broken by it.
        for mutation in LoweringMutation::ALL {
            let mut rejected_any = false;
            for program in generate_async_programs() {
                let lowered = lower(&program.source);
                if let Some(broken) = break_lowering(&lowered, mutation)
                    && verify_async_translation(
                        &program.name,
                        program.category,
                        &program.source,
                        &broken,
                    )
                    .is_err()
                {
                    rejected_any = true;
                    break;
                }
            }
            assert!(rejected_any, "mutation {mutation:?} rejected no program");
        }
    }

    #[test]
    fn parallel_await_downgrade_in_join_is_rejected() {
        // A join checkpoint that fails to lift pc to the branch join is a leak.
        let source = vec![
            AsyncSourceOp::ParallelAwait {
                branch_labels: vec![3, 1],
            },
            AsyncSourceOp::Return { label: 0 },
        ];
        let mut lowered = lower(&source);
        // Find the join checkpoint and downgrade its resume below source resume.
        for op in &mut lowered {
            if let AsyncIr3Op::ParallelJoinCheckpoint { resume_label, .. } = op {
                *resume_label = 0;
            }
        }
        let err =
            verify_async_translation("p", AsyncFeatureCategory::ParallelAwait, &source, &lowered)
                .unwrap_err();
        assert!(matches!(
            err,
            EquivalenceViolation::IfcLabelDowngraded { .. }
        ));
    }

    // --- event logging (bd-cixqu.45) ---

    #[test]
    fn validated_event_carries_proof_hash() {
        let program = &generate_async_programs()[1];
        let proof = verify_program(program).unwrap();
        let event = AsyncTranslationEvent::validated(&proof);
        assert_eq!(event.event, "async_translation_validated");
        assert!(event.validated);
        assert_eq!(event.outcome, "validated");
        assert_eq!(event.proof_hash, proof.proof_hash.to_hex());
    }

    #[test]
    fn rejected_event_carries_violation_code() {
        let program = &generate_async_programs()[0];
        let lowered = lower(&program.source);
        let broken = break_lowering(&lowered, LoweringMutation::SwapCompletion).unwrap();
        let err =
            verify_async_translation(&program.name, program.category, &program.source, &broken)
                .unwrap_err();
        let event = AsyncTranslationEvent::rejected(
            &program.name,
            program.category,
            program.source.len(),
            &err,
        );
        assert_eq!(event.event, "async_translation_rejected");
        assert!(!event.validated);
        assert_eq!(event.outcome, "completion_mismatch");
        assert!(event.proof_hash.is_empty());
    }

    #[test]
    fn event_jsonl_round_trips() {
        let proof = verify_program(&generate_async_programs()[0]).unwrap();
        let event = AsyncTranslationEvent::validated(&proof);
        let line = event.to_jsonl();
        assert!(!line.contains('\n'));
        let parsed: AsyncTranslationEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn append_event_line_writes_one_line_per_event() {
        let dir = std::env::temp_dir().join(format!("g6b_events_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&path);
        for program in generate_async_programs().iter().take(3) {
            let proof = verify_program(program).unwrap();
            let event = AsyncTranslationEvent::validated(&proof);
            append_event_line(&path, &event).unwrap();
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 3);
        for line in contents.lines() {
            let _: AsyncTranslationEvent = serde_json::from_str(line).unwrap();
        }
        let _ = std::fs::remove_file(&path);
    }

    // --- violation surface helpers ---

    #[test]
    fn violation_codes_are_stable_and_distinct() {
        let v = [
            EquivalenceViolation::EventCountMismatch {
                source_len: 1,
                lowered_len: 2,
            },
            EquivalenceViolation::ObservableValueMismatch {
                index: 0,
                source_label: 0,
                lowered_label: 1,
            },
            EquivalenceViolation::MicrotaskScheduleMismatch {
                index: 0,
                detail: "x".into(),
            },
            EquivalenceViolation::IfcLabelDowngraded {
                index: 0,
                suspend_label: 2,
                source_resume: 2,
                lowered_resume: 1,
            },
            EquivalenceViolation::CompletionMismatch {
                source: Completion::Resolved { label: 0 },
                lowered: Completion::Rejected,
            },
        ];
        let mut codes: Vec<&str> = v.iter().map(|x| x.code()).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total);
        for x in &v {
            assert!(!x.detail().is_empty());
        }
    }

    #[test]
    fn identity_lowering_validates_empty_async_fn() {
        // An async fn with no awaits resolves immediately; schedule is empty.
        let source = vec![AsyncSourceOp::Return { label: 0 }];
        let proof = verify_async_translation(
            "empty",
            AsyncFeatureCategory::SimpleAwait,
            &source,
            &lower(&source),
        )
        .unwrap();
        assert_eq!(proof.microtask_checkpoints, 0);
        assert_eq!(proof.completion, Completion::Resolved { label: 0 });
    }

    #[test]
    fn implicit_resolve_when_no_terminator() {
        let source = vec![
            AsyncSourceOp::Compute { label: 2 },
            AsyncSourceOp::Await { label: 1 },
        ];
        let trace = source_semantics(&source);
        assert_eq!(trace.completion, Completion::Resolved { label: 2 });
        // lowering agrees.
        assert_eq!(ir3_semantics(&lower(&source)), trace);
    }

    #[test]
    fn error_propagation_program_completion_is_reject() {
        let program = generate_async_programs()
            .into_iter()
            .find(|p| p.category == AsyncFeatureCategory::ErrorPropagation)
            .unwrap();
        let proof = verify_program(&program).unwrap();
        assert_eq!(proof.completion, Completion::Rejected);
    }

    #[test]
    fn category_as_str_round_trip_is_unique() {
        let mut seen: Vec<&str> = AsyncFeatureCategory::ALL
            .iter()
            .map(|c| c.as_str())
            .collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total);
    }
}
