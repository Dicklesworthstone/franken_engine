#![forbid(unsafe_code)]

//! Hostcall + capability-witness translation validation (G.6.E — bd-cixqu.7.9.5).
//!
//! Every hostcall is dispatched through the capability membrane; the witness
//! emission is part of the lowering's emit phase. G.6.E proves the lowering
//! preserves hostcall + capability-witness semantics across every hostcall
//! family: for each hostcall the lowered IR3 emits identical capability
//! witnesses, identical hostcall arguments, and identical post-call state as
//! the source semantics, and an *ambient-authority* hostcall (one whose
//! required capability is not in the declared grant set) is **rejected**
//! fail-closed.
//!
//! Validation strategy mirrors G.6.A/G.6.D: a single abstract hostcall
//! evaluator is run over a **reference** view (capability membrane always
//! enforced, witness always emitted) and a **target** view (gated on the IR
//! markers actually emitted by the lowering — capability witness emitted?
//! arguments preserved? post-call state emitted?). Equivalence holds iff the
//! observable [`HostTrace`] event sequences match.
//!
//! The security-critical negative case: a "preserving-looking" transformation
//! that drops the capability witness lets a hostcall cross the membrane without
//! a check — for an ambient-authority hostcall it would dispatch instead of
//! failing closed. That divergence from the reference is **rejected**.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Capabilities + hostcall families
// ---------------------------------------------------------------------------

/// Capability kinds gating hostcalls. Mirrors the closed capability enum used
/// by the engine's capability membrane (see `unified_authority_algebra`); kept
/// local so this validator stays self-contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Capability {
    FsRead,
    FsWrite,
    NetConnect,
    ProcSpawn,
    PolicyRequest,
    Eval,
    ClockRead,
    EnvRead,
}

/// Hostcall families dispatched through the membrane (`fs.*`, `net.*`,
/// `proc.*`, `policy.*`, `eval`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HostFamily {
    FsRead,
    FsWrite,
    NetConnect,
    ProcSpawn,
    PolicyRequest,
    Eval,
    ClockRead,
    EnvRead,
}

impl HostFamily {
    /// The capability a hostcall of this family requires.
    pub fn required_capability(&self) -> Capability {
        match self {
            HostFamily::FsRead => Capability::FsRead,
            HostFamily::FsWrite => Capability::FsWrite,
            HostFamily::NetConnect => Capability::NetConnect,
            HostFamily::ProcSpawn => Capability::ProcSpawn,
            HostFamily::PolicyRequest => Capability::PolicyRequest,
            HostFamily::Eval => Capability::Eval,
            HostFamily::ClockRead => Capability::ClockRead,
            HostFamily::EnvRead => Capability::EnvRead,
        }
    }
}

// ---------------------------------------------------------------------------
// Source-level model
// ---------------------------------------------------------------------------

/// A source statement in the hostcall subset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStmt {
    /// A hostcall site. `args` are the (abstract) argument tokens.
    Hostcall {
        call_id: u32,
        family: HostFamily,
        args: Vec<u32>,
    },
    /// An `async` wrapper: hostcalls inside preserve the membrane across the
    /// microtask checkpoint.
    AsyncWrap { wrap_id: u32, body: Vec<HostStmt> },
    /// A nested block.
    Block { body: Vec<HostStmt> },
}

/// A complete program: a declared capability grant set plus a statement body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProgram {
    pub granted: BTreeSet<Capability>,
    pub body: Vec<HostStmt>,
}

// ---------------------------------------------------------------------------
// Observable hostcall trace (the witness)
// ---------------------------------------------------------------------------

/// Abstract state recorded after each event: number of capability witnesses
/// emitted so far and number of membrane crossings (dispatches).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostState {
    pub witnesses_emitted: usize,
    pub dispatches: usize,
}

impl HostState {
    fn initial() -> Self {
        Self {
            witnesses_emitted: 0,
            dispatches: 0,
        }
    }
}

/// An observable event in the hostcall trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostEventKind {
    /// The capability membrane checked `cap` for this hostcall; `granted` is
    /// whether the declared grant set contained it. This is the witness.
    CapabilityWitness {
        call_id: u32,
        cap: Capability,
        granted: bool,
    },
    /// The hostcall was dispatched across the membrane with these arguments.
    HostcallDispatch {
        call_id: u32,
        family: HostFamily,
        args: Vec<u32>,
    },
    /// Post-call state observed after a successful dispatch.
    PostCallState { call_id: u32 },
    /// Fail-closed rejection: the required capability was not granted
    /// (ambient-authority violation).
    AmbientAuthorityViolation { call_id: u32, cap: Capability },
    /// Entry into an `async` wrapper (microtask checkpoint).
    AsyncCheckpoint { wrap_id: u32 },
    /// Normal completion.
    Complete,
}

/// A trace event with the hostcall state it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEvent {
    pub kind: HostEventKind,
    pub state_after: HostState,
}

/// An ordered hostcall trace; two traces are equivalent iff their event-kind
/// sequences are identical.
pub type HostTrace = Vec<HostEvent>;

// ---------------------------------------------------------------------------
// Lowered (target) model — IR markers actually emitted
// ---------------------------------------------------------------------------

/// A lowered statement carrying the hostcall IR markers actually emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoweredHostStmt {
    Hostcall {
        call_id: u32,
        family: HostFamily,
        args: Vec<u32>,
        /// The capability witness (membrane check) was emitted.
        witness_emitted: bool,
        /// The post-call state instruction was emitted.
        post_state_emitted: bool,
    },
    AsyncWrap {
        wrap_id: u32,
        body: Vec<LoweredHostStmt>,
    },
    Block {
        body: Vec<LoweredHostStmt>,
    },
}

// ---------------------------------------------------------------------------
// Evaluation view
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum EvalStmt {
    Hostcall {
        call_id: u32,
        family: HostFamily,
        args: Vec<u32>,
        emit_witness: bool,
        emit_post_state: bool,
    },
    AsyncWrap {
        wrap_id: u32,
        body: Vec<EvalStmt>,
    },
    Block {
        body: Vec<EvalStmt>,
    },
}

fn to_reference_eval(stmts: &[HostStmt]) -> Vec<EvalStmt> {
    stmts
        .iter()
        .map(|s| match s {
            HostStmt::Hostcall {
                call_id,
                family,
                args,
            } => EvalStmt::Hostcall {
                call_id: *call_id,
                family: *family,
                args: args.clone(),
                emit_witness: true,
                emit_post_state: true,
            },
            HostStmt::AsyncWrap { wrap_id, body } => EvalStmt::AsyncWrap {
                wrap_id: *wrap_id,
                body: to_reference_eval(body),
            },
            HostStmt::Block { body } => EvalStmt::Block {
                body: to_reference_eval(body),
            },
        })
        .collect()
}

fn to_target_eval(stmts: &[LoweredHostStmt]) -> Vec<EvalStmt> {
    stmts
        .iter()
        .map(|s| match s {
            LoweredHostStmt::Hostcall {
                call_id,
                family,
                args,
                witness_emitted,
                post_state_emitted,
            } => EvalStmt::Hostcall {
                call_id: *call_id,
                family: *family,
                args: args.clone(),
                emit_witness: *witness_emitted,
                emit_post_state: *post_state_emitted,
            },
            LoweredHostStmt::AsyncWrap { wrap_id, body } => EvalStmt::AsyncWrap {
                wrap_id: *wrap_id,
                body: to_target_eval(body),
            },
            LoweredHostStmt::Block { body } => EvalStmt::Block {
                body: to_target_eval(body),
            },
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Abstract hostcall interpreter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Completion {
    Normal,
    /// Fail-closed: an ambient-authority violation halted execution.
    Violation,
}

struct Interp<'a> {
    granted: &'a BTreeSet<Capability>,
    trace: HostTrace,
    state: HostState,
}

impl<'a> Interp<'a> {
    fn new(granted: &'a BTreeSet<Capability>) -> Self {
        Self {
            granted,
            trace: Vec::new(),
            state: HostState::initial(),
        }
    }

    fn emit(&mut self, kind: HostEventKind) {
        self.trace.push(HostEvent {
            kind,
            state_after: self.state,
        });
    }

    fn run_seq(&mut self, stmts: &[EvalStmt]) -> Completion {
        for s in stmts {
            let comp = self.run_stmt(s);
            if comp != Completion::Normal {
                return comp;
            }
        }
        Completion::Normal
    }

    fn run_stmt(&mut self, stmt: &EvalStmt) -> Completion {
        match stmt {
            EvalStmt::Hostcall {
                call_id,
                family,
                args,
                emit_witness,
                emit_post_state,
            } => {
                let cap = family.required_capability();
                let is_granted = self.granted.contains(&cap);

                if *emit_witness {
                    self.state.witnesses_emitted += 1;
                    self.emit(HostEventKind::CapabilityWitness {
                        call_id: *call_id,
                        cap,
                        granted: is_granted,
                    });

                    // With the witness emitted, the membrane is enforced.
                    if !is_granted {
                        self.emit(HostEventKind::AmbientAuthorityViolation {
                            call_id: *call_id,
                            cap,
                        });
                        return Completion::Violation;
                    }
                }
                // Without an emitted witness the membrane is bypassed entirely:
                // the hostcall dispatches regardless of the grant set (the
                // security break the negative case must catch).

                self.state.dispatches += 1;
                self.emit(HostEventKind::HostcallDispatch {
                    call_id: *call_id,
                    family: *family,
                    args: args.clone(),
                });
                if *emit_post_state {
                    self.emit(HostEventKind::PostCallState { call_id: *call_id });
                }
                Completion::Normal
            }
            EvalStmt::AsyncWrap { wrap_id, body } => {
                self.emit(HostEventKind::AsyncCheckpoint { wrap_id: *wrap_id });
                self.run_seq(body)
            }
            EvalStmt::Block { body } => self.run_seq(body),
        }
    }
}

fn interpret(granted: &BTreeSet<Capability>, stmts: &[EvalStmt]) -> HostTrace {
    let mut interp = Interp::new(granted);
    if interp.run_seq(stmts) == Completion::Normal {
        interp.emit(HostEventKind::Complete);
    }
    interp.trace
}

/// Reference (membrane-enforced) hostcall trace.
pub fn reference_trace(program: &HostProgram) -> HostTrace {
    interpret(&program.granted, &to_reference_eval(&program.body))
}

/// Target (IR-defined) hostcall trace for a candidate lowering.
pub fn target_trace(granted: &BTreeSet<Capability>, lowered: &[LoweredHostStmt]) -> HostTrace {
    interpret(granted, &to_target_eval(lowered))
}

/// Faithfully lower a program: every hostcall emits its capability witness and
/// post-call state.
pub fn faithful_lower(program: &HostProgram) -> Vec<LoweredHostStmt> {
    fn lower(stmts: &[HostStmt]) -> Vec<LoweredHostStmt> {
        stmts
            .iter()
            .map(|s| match s {
                HostStmt::Hostcall {
                    call_id,
                    family,
                    args,
                } => LoweredHostStmt::Hostcall {
                    call_id: *call_id,
                    family: *family,
                    args: args.clone(),
                    witness_emitted: true,
                    post_state_emitted: true,
                },
                HostStmt::AsyncWrap { wrap_id, body } => LoweredHostStmt::AsyncWrap {
                    wrap_id: *wrap_id,
                    body: lower(body),
                },
                HostStmt::Block { body } => LoweredHostStmt::Block { body: lower(body) },
            })
            .collect()
    }
    lower(&program.body)
}

// ---------------------------------------------------------------------------
// Semantics-breaking transforms (negative-case generators)
// ---------------------------------------------------------------------------

/// A transformation that looks structure-preserving but breaks hostcall /
/// capability semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticsBreakingTransform {
    /// Drop the capability witness: the hostcall crosses the membrane without a
    /// check (capability bypass — the security-critical break).
    DropCapabilityWitness,
    /// Drop the post-call state instruction.
    DropPostCallState,
    /// Mutate the hostcall arguments.
    MutateArgs,
}

/// Apply a transform to the first lowered hostcall that admits it.
pub fn apply_transform(
    lowered: &[LoweredHostStmt],
    transform: SemanticsBreakingTransform,
) -> Option<Vec<LoweredHostStmt>> {
    let mut out = lowered.to_vec();
    if mutate_first(&mut out, transform) {
        Some(out)
    } else {
        None
    }
}

fn mutate_first(stmts: &mut [LoweredHostStmt], transform: SemanticsBreakingTransform) -> bool {
    for s in stmts.iter_mut() {
        match s {
            LoweredHostStmt::Hostcall {
                witness_emitted,
                post_state_emitted,
                args,
                ..
            } => {
                match transform {
                    SemanticsBreakingTransform::DropCapabilityWitness => *witness_emitted = false,
                    SemanticsBreakingTransform::DropPostCallState => *post_state_emitted = false,
                    SemanticsBreakingTransform::MutateArgs => args.push(0xDEAD_BEEF),
                }
                return true;
            }
            LoweredHostStmt::AsyncWrap { body, .. } | LoweredHostStmt::Block { body } => {
                if mutate_first(body, transform) {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Validation lemmas + result
// ---------------------------------------------------------------------------

/// Hostcall / capability validation lemma classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostLemma {
    /// Every hostcall emits exactly one capability witness.
    WitnessForEveryHostcall,
    /// Ambient-authority hostcalls are rejected fail-closed in both views.
    FailClosedOnAmbientAuthority,
    /// Hostcall arguments are preserved identically.
    ArgumentPreservation,
    /// Post-call state is emitted identically.
    PostCallStatePreservation,
    /// Source and target hostcall traces are equivalent.
    HostcallFlowEquivalence,
}

/// A structured validation event (bd-cixqu.45 diagnostic discipline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationEvent {
    pub lemma: HostLemma,
    pub verified: bool,
    pub detail: String,
}

/// Result of hostcall + capability-witness translation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostValidationResult {
    pub validation_successful: bool,
    pub verified_lemmas: Vec<HostLemma>,
    pub failed_lemmas: Vec<HostLemma>,
    pub flow_equivalence_proven: bool,
    pub first_divergence: Option<usize>,
    pub events: Vec<ValidationEvent>,
}

impl HostValidationResult {
    /// Render the event log as JSONL for the bd-cixqu.45 diagnostic surface.
    pub fn events_jsonl(&self) -> String {
        self.events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Translation-validation context for the hostcall subset.
#[derive(Debug, Clone)]
pub struct HostValidationContext {
    program: HostProgram,
    lowered: Vec<LoweredHostStmt>,
}

impl HostValidationContext {
    pub fn new(program: HostProgram, lowered: Vec<LoweredHostStmt>) -> Self {
        Self { program, lowered }
    }

    /// Build a context whose lowering is the faithful lowering of the source.
    pub fn faithful(program: HostProgram) -> Self {
        let lowered = faithful_lower(&program);
        Self { program, lowered }
    }

    pub fn validate(&self) -> HostValidationResult {
        let reference = reference_trace(&self.program);
        let target = target_trace(&self.program.granted, &self.lowered);

        let mut verified = Vec::new();
        let mut failed = Vec::new();
        let mut events = Vec::new();

        // Witness for every hostcall: the witness-count equals the number of
        // hostcalls reachable in the reference, and target matches it.
        let ref_witnesses = count(&reference, |k| {
            matches!(k, HostEventKind::CapabilityWitness { .. })
        });
        let tgt_witnesses = count(&target, |k| {
            matches!(k, HostEventKind::CapabilityWitness { .. })
        });
        // In the reference every reachable hostcall emits exactly one witness
        // (then either dispatches or fails closed), so witnesses equal the
        // reachable-hostcall count; the target must match the reference count.
        let witness_ok =
            ref_witnesses == tgt_witnesses && ref_witnesses == reachable_hostcalls(&reference);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            HostLemma::WitnessForEveryHostcall,
            witness_ok,
            "every reachable hostcall emits exactly one capability witness",
        );

        // Fail-closed: ambient-authority violations match between views.
        let ref_viol = violations(&reference);
        let tgt_viol = violations(&target);
        record(
            &mut events,
            &mut verified,
            &mut failed,
            HostLemma::FailClosedOnAmbientAuthority,
            ref_viol == tgt_viol,
            "ambient-authority hostcalls are rejected fail-closed identically",
        );

        // Argument preservation.
        record(
            &mut events,
            &mut verified,
            &mut failed,
            HostLemma::ArgumentPreservation,
            dispatch_args(&reference) == dispatch_args(&target),
            "dispatched hostcall arguments are preserved identically",
        );

        // Post-call state preservation.
        record(
            &mut events,
            &mut verified,
            &mut failed,
            HostLemma::PostCallStatePreservation,
            count(&reference, |k| {
                matches!(k, HostEventKind::PostCallState { .. })
            }) == count(&target, |k| {
                matches!(k, HostEventKind::PostCallState { .. })
            }),
            "post-call state is emitted identically",
        );

        // Full flow equivalence.
        let first_divergence = first_divergence(&reference, &target);
        let flow_ok = first_divergence.is_none();
        record(
            &mut events,
            &mut verified,
            &mut failed,
            HostLemma::HostcallFlowEquivalence,
            flow_ok,
            "source and target hostcall traces are equivalent",
        );

        HostValidationResult {
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
    verified: &mut Vec<HostLemma>,
    failed: &mut Vec<HostLemma>,
    lemma: HostLemma,
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

fn count(trace: &HostTrace, pred: impl Fn(&HostEventKind) -> bool) -> usize {
    trace.iter().filter(|e| pred(&e.kind)).count()
}

fn reachable_hostcalls(trace: &HostTrace) -> usize {
    // A hostcall is reachable if it either dispatched or was rejected.
    count(trace, |k| {
        matches!(
            k,
            HostEventKind::HostcallDispatch { .. }
                | HostEventKind::AmbientAuthorityViolation { .. }
        )
    })
}

fn violations(trace: &HostTrace) -> Vec<(u32, Capability)> {
    trace
        .iter()
        .filter_map(|e| match e.kind {
            HostEventKind::AmbientAuthorityViolation { call_id, cap } => Some((call_id, cap)),
            _ => None,
        })
        .collect()
}

fn dispatch_args(trace: &HostTrace) -> Vec<(u32, Vec<u32>)> {
    trace
        .iter()
        .filter_map(|e| match &e.kind {
            HostEventKind::HostcallDispatch { call_id, args, .. } => Some((*call_id, args.clone())),
            _ => None,
        })
        .collect()
}

fn first_divergence(reference: &HostTrace, target: &HostTrace) -> Option<usize> {
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

/// The hostcall category a generated program exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostCategory {
    SingleHostcall,
    NestedHostcalls,
    HostcallInAsync,
    DeclaredCapability,
    AmbientAuthorityRejection,
}

/// A generated hostcall test program tagged with its category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostTestProgram {
    pub name: String,
    pub category: HostCategory,
    pub program: HostProgram,
}

fn all_capabilities() -> BTreeSet<Capability> {
    [
        Capability::FsRead,
        Capability::FsWrite,
        Capability::NetConnect,
        Capability::ProcSpawn,
        Capability::PolicyRequest,
        Capability::Eval,
        Capability::ClockRead,
        Capability::EnvRead,
    ]
    .into_iter()
    .collect()
}

const FAMILIES: [HostFamily; 8] = [
    HostFamily::FsRead,
    HostFamily::FsWrite,
    HostFamily::NetConnect,
    HostFamily::ProcSpawn,
    HostFamily::PolicyRequest,
    HostFamily::Eval,
    HostFamily::ClockRead,
    HostFamily::EnvRead,
];

/// Generate ≥50 hostcall programs covering: single hostcall (every family),
/// nested hostcalls, hostcall in async, hostcall with the declared capability,
/// and ambient-authority rejection (capability withheld).
pub fn generate_hostcall_test_programs() -> Vec<HostTestProgram> {
    let mut out = Vec::new();
    let mut id = 0u32;
    let mut fresh = || {
        let v = id;
        id += 1;
        v
    };

    // Single hostcall per family, with the capability declared.
    for family in FAMILIES {
        let cid = fresh();
        out.push(HostTestProgram {
            name: format!("single_{family:?}"),
            category: HostCategory::SingleHostcall,
            program: HostProgram {
                granted: all_capabilities(),
                body: vec![HostStmt::Hostcall {
                    call_id: cid,
                    family,
                    args: vec![cid, cid + 1],
                }],
            },
        });
    }

    // Declared-capability single grants (only the needed capability).
    for family in FAMILIES {
        let cid = fresh();
        out.push(HostTestProgram {
            name: format!("declared_{family:?}"),
            category: HostCategory::DeclaredCapability,
            program: HostProgram {
                granted: [family.required_capability()].into_iter().collect(),
                body: vec![HostStmt::Hostcall {
                    call_id: cid,
                    family,
                    args: vec![cid],
                }],
            },
        });
    }

    // Ambient-authority rejection: capability withheld.
    for family in FAMILIES {
        let cid = fresh();
        out.push(HostTestProgram {
            name: format!("ambient_reject_{family:?}"),
            category: HostCategory::AmbientAuthorityRejection,
            program: HostProgram {
                granted: BTreeSet::new(), // nothing granted
                body: vec![HostStmt::Hostcall {
                    call_id: cid,
                    family,
                    args: vec![cid],
                }],
            },
        });
    }

    // Nested hostcalls.
    for variant in 0..16u32 {
        let a = fresh();
        let b = fresh();
        let fam_a = FAMILIES[variant as usize % FAMILIES.len()];
        let fam_b = FAMILIES[(variant as usize + 1) % FAMILIES.len()];
        out.push(HostTestProgram {
            name: format!("nested_v{variant}"),
            category: HostCategory::NestedHostcalls,
            program: HostProgram {
                granted: all_capabilities(),
                body: vec![HostStmt::Block {
                    body: vec![
                        HostStmt::Hostcall {
                            call_id: a,
                            family: fam_a,
                            args: vec![a],
                        },
                        HostStmt::Hostcall {
                            call_id: b,
                            family: fam_b,
                            args: vec![b, a],
                        },
                    ],
                }],
            },
        });
    }

    // Hostcall in async.
    for variant in 0..16u32 {
        let wrap = fresh();
        let cid = fresh();
        let fam = FAMILIES[variant as usize % FAMILIES.len()];
        out.push(HostTestProgram {
            name: format!("async_v{variant}"),
            category: HostCategory::HostcallInAsync,
            program: HostProgram {
                granted: all_capabilities(),
                body: vec![HostStmt::AsyncWrap {
                    wrap_id: wrap,
                    body: vec![HostStmt::Hostcall {
                        call_id: cid,
                        family: fam,
                        args: vec![cid],
                    }],
                }],
            },
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog(granted: BTreeSet<Capability>, body: Vec<HostStmt>) -> HostProgram {
        HostProgram { granted, body }
    }

    fn single(family: HostFamily, granted: BTreeSet<Capability>) -> HostProgram {
        prog(
            granted,
            vec![HostStmt::Hostcall {
                call_id: 1,
                family,
                args: vec![1, 2],
            }],
        )
    }

    #[test]
    fn faithful_granted_hostcall_validates() {
        let p = single(HostFamily::FsRead, all_capabilities());
        let r = HostValidationContext::faithful(p).validate();
        assert!(r.validation_successful, "{:?}", r.failed_lemmas);
        assert!(r.flow_equivalence_proven);
    }

    #[test]
    fn granted_hostcall_dispatches_with_witness() {
        let trace = reference_trace(&single(HostFamily::NetConnect, all_capabilities()));
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            HostEventKind::CapabilityWitness {
                cap: Capability::NetConnect,
                granted: true,
                ..
            }
        )));
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            HostEventKind::HostcallDispatch {
                family: HostFamily::NetConnect,
                ..
            }
        )));
    }

    #[test]
    fn ambient_authority_is_rejected_fail_closed() {
        // Capability withheld -> violation, no dispatch.
        let p = single(HostFamily::FsWrite, BTreeSet::new());
        let trace = reference_trace(&p);
        assert!(trace.iter().any(|e| matches!(
            e.kind,
            HostEventKind::AmbientAuthorityViolation {
                cap: Capability::FsWrite,
                ..
            }
        )));
        assert!(
            !trace
                .iter()
                .any(|e| matches!(e.kind, HostEventKind::HostcallDispatch { .. }))
        );
        // The faithful lowering reproduces the fail-closed behaviour.
        assert!(
            HostValidationContext::faithful(p)
                .validate()
                .validation_successful
        );
    }

    #[test]
    fn negative_drop_witness_on_ambient_is_rejected() {
        // The security-critical case: dropping the capability witness lets an
        // ambient-authority hostcall dispatch instead of failing closed.
        let p = single(HostFamily::ProcSpawn, BTreeSet::new());
        let lowered = faithful_lower(&p);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropCapabilityWitness).unwrap();
        let r = HostValidationContext::new(p, broken).validate();
        assert!(
            !r.validation_successful,
            "capability bypass must be rejected"
        );
        assert!(
            r.failed_lemmas
                .contains(&HostLemma::FailClosedOnAmbientAuthority)
        );
        assert!(
            r.failed_lemmas
                .contains(&HostLemma::WitnessForEveryHostcall)
        );
    }

    #[test]
    fn negative_drop_witness_on_granted_is_rejected() {
        // Even when the capability is granted, the witness MUST be emitted.
        let p = single(HostFamily::FsRead, all_capabilities());
        let lowered = faithful_lower(&p);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropCapabilityWitness).unwrap();
        let r = HostValidationContext::new(p, broken).validate();
        assert!(!r.validation_successful);
        assert!(
            r.failed_lemmas
                .contains(&HostLemma::WitnessForEveryHostcall)
        );
    }

    #[test]
    fn negative_mutate_args_is_rejected() {
        let p = single(HostFamily::Eval, all_capabilities());
        let lowered = faithful_lower(&p);
        let broken = apply_transform(&lowered, SemanticsBreakingTransform::MutateArgs).unwrap();
        let r = HostValidationContext::new(p, broken).validate();
        assert!(!r.validation_successful);
        assert!(r.failed_lemmas.contains(&HostLemma::ArgumentPreservation));
    }

    #[test]
    fn negative_drop_post_state_is_rejected() {
        let p = single(HostFamily::ClockRead, all_capabilities());
        let lowered = faithful_lower(&p);
        let broken =
            apply_transform(&lowered, SemanticsBreakingTransform::DropPostCallState).unwrap();
        let r = HostValidationContext::new(p, broken).validate();
        assert!(!r.validation_successful);
        assert!(
            r.failed_lemmas
                .contains(&HostLemma::PostCallStatePreservation)
        );
    }

    #[test]
    fn async_wrap_emits_checkpoint() {
        let p = prog(
            all_capabilities(),
            vec![HostStmt::AsyncWrap {
                wrap_id: 9,
                body: vec![HostStmt::Hostcall {
                    call_id: 1,
                    family: HostFamily::FsRead,
                    args: vec![1],
                }],
            }],
        );
        let trace = reference_trace(&p);
        assert!(
            trace
                .iter()
                .any(|e| matches!(e.kind, HostEventKind::AsyncCheckpoint { wrap_id: 9 }))
        );
        assert!(
            HostValidationContext::faithful(p)
                .validate()
                .validation_successful
        );
    }

    #[test]
    fn nested_hostcalls_validate() {
        let p = prog(
            all_capabilities(),
            vec![HostStmt::Block {
                body: vec![
                    HostStmt::Hostcall {
                        call_id: 1,
                        family: HostFamily::FsRead,
                        args: vec![1],
                    },
                    HostStmt::Hostcall {
                        call_id: 2,
                        family: HostFamily::NetConnect,
                        args: vec![2],
                    },
                ],
            }],
        );
        assert!(
            HostValidationContext::faithful(p)
                .validate()
                .validation_successful
        );
    }

    #[test]
    fn second_hostcall_after_ambient_is_not_reached() {
        // Fail-closed halts execution: a hostcall after an ambient violation
        // does not run.
        let p = prog(
            BTreeSet::new(),
            vec![
                HostStmt::Hostcall {
                    call_id: 1,
                    family: HostFamily::FsRead,
                    args: vec![1],
                },
                HostStmt::Hostcall {
                    call_id: 2,
                    family: HostFamily::NetConnect,
                    args: vec![2],
                },
            ],
        );
        let trace = reference_trace(&p);
        assert!(
            !trace
                .iter()
                .any(|e| matches!(e.kind, HostEventKind::CapabilityWitness { call_id: 2, .. }))
        );
    }

    #[test]
    fn all_generated_programs_validate_faithfully() {
        let programs = generate_hostcall_test_programs();
        assert!(
            programs.len() >= 50,
            "expected >=50 programs, got {}",
            programs.len()
        );
        for p in &programs {
            let r = HostValidationContext::faithful(p.program.clone()).validate();
            assert!(
                r.validation_successful,
                "program {} ({:?}) failed: {:?}",
                p.name, p.category, r.failed_lemmas
            );
        }
    }

    #[test]
    fn every_category_is_covered() {
        use HostCategory::*;
        let programs = generate_hostcall_test_programs();
        for cat in [
            SingleHostcall,
            NestedHostcalls,
            HostcallInAsync,
            DeclaredCapability,
            AmbientAuthorityRejection,
        ] {
            assert!(
                programs.iter().any(|p| p.category == cat),
                "category {cat:?} not covered"
            );
        }
    }

    #[test]
    fn negative_transforms_reject_across_corpus() {
        let programs = generate_hostcall_test_programs();
        let transforms = [
            SemanticsBreakingTransform::DropCapabilityWitness,
            SemanticsBreakingTransform::DropPostCallState,
            SemanticsBreakingTransform::MutateArgs,
        ];
        for &tr in &transforms {
            let mut rejected = false;
            for p in &programs {
                let lowered = faithful_lower(&p.program);
                if let Some(broken) = apply_transform(&lowered, tr) {
                    let r = HostValidationContext::new(p.program.clone(), broken).validate();
                    if !r.validation_successful {
                        rejected = true;
                    }
                }
            }
            assert!(rejected, "transform {tr:?} never rejected across corpus");
        }
    }

    #[test]
    fn every_family_maps_to_distinct_capability() {
        let caps: BTreeSet<Capability> = FAMILIES.iter().map(|f| f.required_capability()).collect();
        assert_eq!(caps.len(), FAMILIES.len());
    }

    #[test]
    fn faithful_lower_trace_equals_reference() {
        for p in generate_hostcall_test_programs() {
            assert_eq!(
                reference_trace(&p.program),
                target_trace(&p.program.granted, &faithful_lower(&p.program)),
                "faithful lowering diverged for {}",
                p.name
            );
        }
    }

    #[test]
    fn events_jsonl_round_trips() {
        let r = HostValidationContext::faithful(single(HostFamily::FsRead, all_capabilities()))
            .validate();
        assert_eq!(r.events.len(), 5);
        for line in r.events_jsonl().lines() {
            let parsed: ValidationEvent = serde_json::from_str(line).unwrap();
            assert!(parsed.verified);
        }
    }

    #[test]
    fn serde_round_trip_result() {
        let r = HostValidationContext::faithful(single(HostFamily::PolicyRequest, BTreeSet::new()))
            .validate();
        let json = serde_json::to_string(&r).unwrap();
        let back: HostValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn first_divergence_set_on_reject() {
        let p = single(HostFamily::FsRead, all_capabilities());
        let lowered = faithful_lower(&p);
        let broken = apply_transform(&lowered, SemanticsBreakingTransform::MutateArgs).unwrap();
        let r = HostValidationContext::new(p, broken).validate();
        assert!(r.first_divergence.is_some());
    }

    #[test]
    fn empty_program_completes() {
        let p = prog(all_capabilities(), vec![]);
        let trace = reference_trace(&p);
        assert_eq!(trace.len(), 1);
        assert!(matches!(trace[0].kind, HostEventKind::Complete));
    }
}
