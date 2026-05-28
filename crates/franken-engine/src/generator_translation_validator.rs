#![forbid(unsafe_code)]

//! Generator + async-generator translation validation (Track G.6.C,
//! bd-cixqu.7.9.3).
//!
//! Generator and async-generator functions produce iterators that resume
//! across `yield`/`await`; the runtime lowers the body to a resumable state
//! machine (one resume point per suspension). G.6.C proves that the lowered
//! state machine is *semantically equivalent* to the source-level yield
//! semantics: driving the state machine to completion produces exactly the
//! same observable effect trace as the source.
//!
//! ## Method (translation validation, not testing)
//!
//! The validator is oracle-based on the *source* semantics:
//!
//! 1. [`source_trace`] computes the ground-truth observable sequence directly
//!    from the source spec (each `yield` surfaces its value; `yield*` surfaces
//!    every delegated value in order; `await` is an ordering-significant
//!    microtask checkpoint; the body ends with a `return` completion).
//! 2. [`lower_to_state_machine`] is the "compiler under test": it lowers the
//!    source to a [`GeneratorStateMachine`] (linear chain of resume states).
//! 3. [`replay_state_machine`] drives the state machine, collecting the effects
//!    it emits on each resume.
//! 4. [`validate_lowering`] compares the two traces. Equivalence holds iff the
//!    machine's trace equals the source trace, element for element.
//!
//! Because the validator checks an *arbitrary* state machine against the source
//! (not just the canonical lowering), it actually detects broken lowerings:
//! [`apply_mutation`] perturbs a machine (drop a yield, reorder, lose the
//! return value, duplicate a yield) and [`validate_lowering`] then reports a
//! concrete [`TraceDivergence`] — the checker is not vacuously true.
//!
//! Per bd-cixqu.45, [`validate_corpus`] emits a [`GeneratorValidationEvent`]
//! per program into a drainable buffer.
//!
//! Anchoring: G.4 (pure-expression TV) -> G.5 (statements/control flow,
//! `statement_translation_validator`) -> G.6.C (this).

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

/// Upper bound on resume steps when replaying a state machine; protects against
/// a malformed (cyclic) machine looping forever.
const REPLAY_STEP_BUDGET: usize = 1_000_000;

// ---------------------------------------------------------------------------
// Source-level model
// ---------------------------------------------------------------------------

/// Sync generator (`function*`) vs async generator (`async function*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GeneratorKind {
    Sync,
    Async,
}

impl GeneratorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Async => "async",
        }
    }
}

/// A source-level step inside a generator body, in execution order. Values are
/// identified by opaque small ids — the validator reasons about *order and
/// identity*, not concrete runtime values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeneratorStep {
    /// `yield <value>`.
    Yield(u32),
    /// `yield* <delegate>` — delegates to a sub-iterator producing this
    /// sequence of values; each surfaces as a `Yield` in the flattened trace.
    YieldDelegate(Vec<u32>),
    /// `await <expr>` (async generators only) — a microtask suspension point
    /// that produces no surfaced value but IS a resume boundary, so its order
    /// relative to yields is observable.
    Await,
}

/// Source-level specification of a generator body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorSource {
    pub program_id: String,
    pub kind: GeneratorKind,
    pub steps: Vec<GeneratorStep>,
    /// Optional `return <value>` completion value (surfaced as `{done:true}`).
    pub return_value: Option<u32>,
}

impl GeneratorSource {
    pub fn new(
        program_id: impl Into<String>,
        kind: GeneratorKind,
        steps: Vec<GeneratorStep>,
        return_value: Option<u32>,
    ) -> Self {
        Self {
            program_id: program_id.into(),
            kind,
            steps,
            return_value,
        }
    }

    /// Count of surfaced yields (delegated values count individually).
    pub fn yield_count(&self) -> usize {
        self.steps
            .iter()
            .map(|s| match s {
                GeneratorStep::Yield(_) => 1,
                GeneratorStep::YieldDelegate(vs) => vs.len(),
                GeneratorStep::Await => 0,
            })
            .sum()
    }

    /// Count of await checkpoints.
    pub fn await_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| matches!(s, GeneratorStep::Await))
            .count()
    }
}

// ---------------------------------------------------------------------------
// Observable effect trace (the semantics being compared)
// ---------------------------------------------------------------------------

/// One observable effect of driving a generator to completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeneratorEffect {
    /// Surfaced `{ value, done: false }` carrying the value id.
    Yield(u32),
    /// An await suspension/resume boundary (async only); ordering-significant.
    AwaitCheckpoint,
    /// Final `{ value, done: true }` completion.
    Return(Option<u32>),
}

/// Ground-truth observable sequence computed directly from the source spec.
/// `yield*` is flattened (each delegated value surfaces in order); the trace
/// always ends with exactly one `Return`.
pub fn source_trace(src: &GeneratorSource) -> Vec<GeneratorEffect> {
    let mut trace = Vec::new();
    for step in &src.steps {
        match step {
            GeneratorStep::Yield(v) => trace.push(GeneratorEffect::Yield(*v)),
            GeneratorStep::YieldDelegate(vs) => {
                for v in vs {
                    trace.push(GeneratorEffect::Yield(*v));
                }
            }
            GeneratorStep::Await => trace.push(GeneratorEffect::AwaitCheckpoint),
        }
    }
    trace.push(GeneratorEffect::Return(src.return_value));
    trace
}

/// Canonical content digest of an effect trace (prefix-free, big-endian
/// length/tag framing) — a stable witness over the observable behaviour.
pub fn trace_digest(trace: &[GeneratorEffect]) -> ContentHash {
    let mut buf = Vec::with_capacity(trace.len() * 6 + 8);
    buf.extend_from_slice(&(trace.len() as u64).to_be_bytes());
    for effect in trace {
        match effect {
            GeneratorEffect::Yield(v) => {
                buf.push(0x01);
                buf.extend_from_slice(&v.to_be_bytes());
            }
            GeneratorEffect::AwaitCheckpoint => buf.push(0x02),
            GeneratorEffect::Return(r) => {
                buf.push(0x03);
                match r {
                    Some(v) => {
                        buf.push(0x01);
                        buf.extend_from_slice(&v.to_be_bytes());
                    }
                    None => buf.push(0x00),
                }
            }
        }
    }
    ContentHash::compute(&buf)
}

// ---------------------------------------------------------------------------
// Lowered state machine (the compiler output under validation)
// ---------------------------------------------------------------------------

/// Effect emitted when a state is entered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateEffect {
    Yield(u32),
    Await,
    Return(Option<u32>),
}

/// One state of the lowered generator state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorState {
    pub id: u32,
    /// Effect emitted on entering this state (`None` = pure transition state).
    pub on_enter: Option<StateEffect>,
    /// State to resume into next, or `None` if terminal.
    pub resume: Option<u32>,
}

/// A resumable generator state machine: the IR-level lowering of a generator
/// body. Canonically a linear chain (resume = next id) ending in a terminal
/// `Return` state, but the validator accepts arbitrary shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorStateMachine {
    pub kind: GeneratorKind,
    pub states: Vec<GeneratorState>,
    pub initial: u32,
}

/// Lower a source generator to its canonical state machine. Each `yield`
/// becomes one resume state; each `yield*` value becomes its own resume state
/// (the desugared delegation loop body); each `await` becomes a checkpoint
/// state; a terminal state carries the `return` completion. States are chained
/// in source order.
pub fn lower_to_state_machine(src: &GeneratorSource) -> GeneratorStateMachine {
    let mut effects: Vec<StateEffect> = Vec::new();
    for step in &src.steps {
        match step {
            GeneratorStep::Yield(v) => effects.push(StateEffect::Yield(*v)),
            GeneratorStep::YieldDelegate(vs) => {
                for v in vs {
                    effects.push(StateEffect::Yield(*v));
                }
            }
            GeneratorStep::Await => effects.push(StateEffect::Await),
        }
    }
    effects.push(StateEffect::Return(src.return_value));

    let n = effects.len();
    let states: Vec<GeneratorState> = effects
        .into_iter()
        .enumerate()
        .map(|(i, effect)| GeneratorState {
            id: i as u32,
            on_enter: Some(effect),
            // Last state is terminal; others resume into the next.
            resume: if i + 1 < n {
                Some((i + 1) as u32)
            } else {
                None
            },
        })
        .collect();

    GeneratorStateMachine {
        kind: src.kind,
        states,
        initial: 0,
    }
}

/// Drive a state machine from its initial state, collecting the observable
/// effects emitted at each resume. Fails closed on malformed machines.
pub fn replay_state_machine(
    sm: &GeneratorStateMachine,
) -> Result<Vec<GeneratorEffect>, GeneratorValidationError> {
    if sm.states.is_empty() {
        return Err(GeneratorValidationError::EmptyStateMachine);
    }
    let mut effects = Vec::new();
    let mut current = Some(sm.initial);
    let mut steps = 0usize;
    while let Some(id) = current {
        steps += 1;
        if steps > REPLAY_STEP_BUDGET {
            return Err(GeneratorValidationError::StepBudgetExceeded);
        }
        let state = sm
            .states
            .iter()
            .find(|s| s.id == id)
            .ok_or(GeneratorValidationError::MissingState { id })?;
        if let Some(effect) = &state.on_enter {
            effects.push(match effect {
                StateEffect::Yield(v) => GeneratorEffect::Yield(*v),
                StateEffect::Await => GeneratorEffect::AwaitCheckpoint,
                StateEffect::Return(r) => GeneratorEffect::Return(*r),
            });
        }
        current = state.resume;
    }
    Ok(effects)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Where a machine trace diverged from the source trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceDivergence {
    /// Traces differ in length (e.g. a yield was dropped or duplicated).
    LengthMismatch { source: usize, machine: usize },
    /// Traces differ at a specific index (e.g. yields reordered).
    EffectMismatch { index: usize },
}

/// Result witness of validating one generator lowering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationWitness {
    pub program_id: String,
    pub kind: GeneratorKind,
    pub equivalent: bool,
    pub source_effects: usize,
    pub machine_effects: usize,
    /// Digest of the *source* effect trace (the equivalence target).
    pub source_digest: ContentHash,
    /// Digest of the machine's replayed trace.
    pub machine_digest: ContentHash,
    pub divergence: Option<TraceDivergence>,
}

/// Validate a *specific* state machine against the source semantics — the real
/// translation-validation entry point (the lowering is the compiler, `sm` is
/// its output, which may be canonical or externally produced/mutated).
pub fn validate_lowering(
    src: &GeneratorSource,
    sm: &GeneratorStateMachine,
) -> Result<ValidationWitness, GeneratorValidationError> {
    let expected = source_trace(src);
    let actual = replay_state_machine(sm)?;

    let divergence = first_divergence(&expected, &actual);
    Ok(ValidationWitness {
        program_id: src.program_id.clone(),
        kind: src.kind,
        equivalent: divergence.is_none(),
        source_effects: expected.len(),
        machine_effects: actual.len(),
        source_digest: trace_digest(&expected),
        machine_digest: trace_digest(&actual),
        divergence,
    })
}

/// Validate the *canonical* lowering of a source (compiler + checker together).
pub fn validate_generator(
    src: &GeneratorSource,
) -> Result<ValidationWitness, GeneratorValidationError> {
    let sm = lower_to_state_machine(src);
    validate_lowering(src, &sm)
}

fn first_divergence(
    expected: &[GeneratorEffect],
    actual: &[GeneratorEffect],
) -> Option<TraceDivergence> {
    for (index, (e, a)) in expected.iter().zip(actual.iter()).enumerate() {
        if e != a {
            return Some(TraceDivergence::EffectMismatch { index });
        }
    }
    if expected.len() != actual.len() {
        return Some(TraceDivergence::LengthMismatch {
            source: expected.len(),
            machine: actual.len(),
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Lowering mutations (negative-test / adversarial coverage)
// ---------------------------------------------------------------------------

/// A perturbation of a (correct) state machine, modelling a broken lowering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoweringMutation {
    /// Drop the yield/await state at the given chain position (re-linking the
    /// chain so the machine still terminates) — models a lost suspension.
    DropState(usize),
    /// Swap the effects of two states — models reordered yields.
    SwapEffects(usize, usize),
    /// Replace the terminal return value with a different one — models a lost
    /// completion value.
    CorruptReturn(Option<u32>),
    /// Duplicate the effect at a position into the next state — models an
    /// over-emitted yield.
    DuplicateEffect(usize),
}

/// Apply a mutation, returning a new (broken) machine. Out-of-range positions
/// return the machine unchanged.
pub fn apply_mutation(
    sm: &GeneratorStateMachine,
    mutation: &LoweringMutation,
) -> GeneratorStateMachine {
    let mut effects: Vec<Option<StateEffect>> =
        sm.states.iter().map(|s| s.on_enter.clone()).collect();

    match mutation {
        LoweringMutation::DropState(pos) => {
            if *pos < effects.len() {
                effects.remove(*pos);
            }
        }
        LoweringMutation::SwapEffects(a, b) => {
            if *a < effects.len() && *b < effects.len() {
                effects.swap(*a, *b);
            }
        }
        LoweringMutation::CorruptReturn(new_value) => {
            if let Some(last) = effects.last_mut() {
                *last = Some(StateEffect::Return(*new_value));
            }
        }
        LoweringMutation::DuplicateEffect(pos) => {
            if *pos < effects.len() {
                let dup = effects[*pos].clone();
                effects.insert(*pos + 1, dup);
            }
        }
    }

    rechain(sm.kind, effects, sm.initial)
}

/// Rebuild a linear-chained machine from an ordered list of state effects.
fn rechain(
    kind: GeneratorKind,
    effects: Vec<Option<StateEffect>>,
    initial: u32,
) -> GeneratorStateMachine {
    let n = effects.len();
    let states = effects
        .into_iter()
        .enumerate()
        .map(|(i, on_enter)| GeneratorState {
            id: i as u32,
            on_enter,
            resume: if i + 1 < n {
                Some((i + 1) as u32)
            } else {
                None
            },
        })
        .collect();
    GeneratorStateMachine {
        kind,
        states,
        initial,
    }
}

// ---------------------------------------------------------------------------
// Corpus + batch validation (bd-cixqu.45 logging)
// ---------------------------------------------------------------------------

/// Generate the G.6.C validation corpus: ≥50 generator programs spanning the
/// four required feature areas — (1) multi-yield sync generators, (2) sync
/// generators with a return value, (3) async generators with interleaved
/// await+yield, and (4) `yield*` delegation.
pub fn generate_generator_corpus() -> Vec<GeneratorSource> {
    let mut corpus = Vec::new();

    // (1) Multi-yield sync generators: 1..=15 yields, no return value.
    for n in 1..=15u32 {
        let steps = (0..n).map(GeneratorStep::Yield).collect();
        corpus.push(GeneratorSource::new(
            format!("sync-multiyield-{n}"),
            GeneratorKind::Sync,
            steps,
            None,
        ));
    }

    // (2) Sync generators with a return value: 1..=15 yields + return.
    for n in 1..=15u32 {
        let steps = (0..n).map(GeneratorStep::Yield).collect();
        corpus.push(GeneratorSource::new(
            format!("sync-return-{n}"),
            GeneratorKind::Sync,
            steps,
            Some(1000 + n),
        ));
    }

    // (3) Async generators with interleaved await + yield: 1..=12 cycles.
    for n in 1..=12u32 {
        let mut steps = Vec::new();
        for i in 0..n {
            steps.push(GeneratorStep::Await);
            steps.push(GeneratorStep::Yield(i));
        }
        corpus.push(GeneratorSource::new(
            format!("async-await-yield-{n}"),
            GeneratorKind::Async,
            steps,
            if n % 2 == 0 { Some(2000 + n) } else { None },
        ));
    }

    // (4) yield* delegation: a leading yield, a delegated run of 1..=10, then a
    //     trailing yield + return.
    for n in 1..=10u32 {
        let delegated: Vec<u32> = (0..n).map(|k| 500 + k).collect();
        let steps = vec![
            GeneratorStep::Yield(1),
            GeneratorStep::YieldDelegate(delegated),
            GeneratorStep::Yield(2),
        ];
        corpus.push(GeneratorSource::new(
            format!("yield-delegate-{n}"),
            GeneratorKind::Sync,
            steps,
            Some(3000 + n),
        ));
    }

    corpus // 15 + 15 + 12 + 10 = 52
}

/// One bd-cixqu.45 validation event (serde round-trippable; collected, not
/// written here — the caller owns the sink).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorValidationEvent {
    pub program_id: String,
    pub kind: String,
    pub yield_count: usize,
    pub await_count: usize,
    pub equivalent: bool,
    pub source_effects: usize,
    pub machine_effects: usize,
    pub trace_digest_hex: String,
    pub divergence: Option<String>,
}

/// Report of validating a whole corpus, with one event per program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorValidationReport {
    pub total: usize,
    pub equivalent: usize,
    pub events: Vec<GeneratorValidationEvent>,
}

impl GeneratorValidationReport {
    /// All programs validated as equivalent.
    pub fn all_equivalent(&self) -> bool {
        self.total == self.equivalent
    }
}

/// Validate every program in a corpus via its canonical lowering, emitting a
/// [`GeneratorValidationEvent`] per program.
pub fn validate_corpus(
    corpus: &[GeneratorSource],
) -> Result<GeneratorValidationReport, GeneratorValidationError> {
    let mut events = Vec::with_capacity(corpus.len());
    let mut equivalent = 0usize;
    for src in corpus {
        let witness = validate_generator(src)?;
        if witness.equivalent {
            equivalent += 1;
        }
        events.push(GeneratorValidationEvent {
            program_id: src.program_id.clone(),
            kind: src.kind.as_str().to_string(),
            yield_count: src.yield_count(),
            await_count: src.await_count(),
            equivalent: witness.equivalent,
            source_effects: witness.source_effects,
            machine_effects: witness.machine_effects,
            trace_digest_hex: hex_digest(&witness.source_digest),
            divergence: witness.divergence.as_ref().map(|d| format!("{d:?}")),
        });
    }
    Ok(GeneratorValidationReport {
        total: corpus.len(),
        equivalent,
        events,
    })
}

fn hex_digest(hash: &ContentHash) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in hash.as_bytes() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeneratorValidationError {
    EmptyStateMachine,
    MissingState { id: u32 },
    StepBudgetExceeded,
}

impl std::fmt::Display for GeneratorValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyStateMachine => write!(f, "generator state machine has no states"),
            Self::MissingState { id } => {
                write!(
                    f,
                    "generator state machine resume targets missing state {id}"
                )
            }
            Self::StepBudgetExceeded => {
                write!(f, "generator replay exceeded step budget (likely a cycle)")
            }
        }
    }
}

impl std::error::Error for GeneratorValidationError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sync(steps: Vec<GeneratorStep>, ret: Option<u32>) -> GeneratorSource {
        GeneratorSource::new("t", GeneratorKind::Sync, steps, ret)
    }

    // ----- source_trace -----

    #[test]
    fn source_trace_flattens_yields_then_return() {
        let src = sync(
            vec![GeneratorStep::Yield(7), GeneratorStep::Yield(9)],
            Some(3),
        );
        assert_eq!(
            source_trace(&src),
            vec![
                GeneratorEffect::Yield(7),
                GeneratorEffect::Yield(9),
                GeneratorEffect::Return(Some(3)),
            ]
        );
    }

    #[test]
    fn source_trace_expands_yield_delegate_in_order() {
        let src = sync(
            vec![
                GeneratorStep::Yield(1),
                GeneratorStep::YieldDelegate(vec![10, 11, 12]),
                GeneratorStep::Yield(2),
            ],
            None,
        );
        assert_eq!(
            source_trace(&src),
            vec![
                GeneratorEffect::Yield(1),
                GeneratorEffect::Yield(10),
                GeneratorEffect::Yield(11),
                GeneratorEffect::Yield(12),
                GeneratorEffect::Yield(2),
                GeneratorEffect::Return(None),
            ]
        );
    }

    #[test]
    fn source_trace_records_await_checkpoints_in_order() {
        let src = GeneratorSource::new(
            "a",
            GeneratorKind::Async,
            vec![
                GeneratorStep::Await,
                GeneratorStep::Yield(5),
                GeneratorStep::Await,
            ],
            None,
        );
        assert_eq!(
            source_trace(&src),
            vec![
                GeneratorEffect::AwaitCheckpoint,
                GeneratorEffect::Yield(5),
                GeneratorEffect::AwaitCheckpoint,
                GeneratorEffect::Return(None),
            ]
        );
    }

    #[test]
    fn empty_generator_traces_only_return() {
        let src = sync(vec![], None);
        assert_eq!(source_trace(&src), vec![GeneratorEffect::Return(None)]);
    }

    // ----- lowering + replay round-trip -----

    #[test]
    fn canonical_lowering_replays_to_source_trace() {
        let src = sync(
            vec![
                GeneratorStep::Yield(1),
                GeneratorStep::YieldDelegate(vec![2, 3]),
                GeneratorStep::Yield(4),
            ],
            Some(99),
        );
        let sm = lower_to_state_machine(&src);
        let replayed = replay_state_machine(&sm).unwrap();
        assert_eq!(replayed, source_trace(&src));
    }

    #[test]
    fn lowering_has_one_state_per_effect_plus_return() {
        let src = sync(
            vec![
                GeneratorStep::Yield(1),
                GeneratorStep::YieldDelegate(vec![2, 3]),
            ],
            None,
        );
        let sm = lower_to_state_machine(&src);
        // 1 + 2 delegated + 1 return = 4 states.
        assert_eq!(sm.states.len(), 4);
        assert_eq!(sm.states[0].id, 0);
        assert!(sm.states.last().unwrap().resume.is_none());
    }

    #[test]
    fn lowering_preserves_generator_kind() {
        let src = GeneratorSource::new("a", GeneratorKind::Async, vec![GeneratorStep::Await], None);
        assert_eq!(lower_to_state_machine(&src).kind, GeneratorKind::Async);
    }

    // ----- validation (positive) -----

    #[test]
    fn validate_generator_accepts_canonical_lowering() {
        for src in generate_generator_corpus() {
            let w = validate_generator(&src).unwrap();
            assert!(w.equivalent, "program {} should validate", src.program_id);
            assert!(w.divergence.is_none());
            assert_eq!(w.source_digest, w.machine_digest);
        }
    }

    #[test]
    fn witness_reports_effect_counts() {
        let src = sync(
            vec![GeneratorStep::Yield(1), GeneratorStep::Yield(2)],
            Some(0),
        );
        let w = validate_generator(&src).unwrap();
        assert_eq!(w.source_effects, 3); // 2 yields + return
        assert_eq!(w.machine_effects, 3);
    }

    // ----- validation (negative: broken lowerings are detected) -----

    #[test]
    fn dropped_yield_is_detected() {
        let src = sync(
            vec![
                GeneratorStep::Yield(1),
                GeneratorStep::Yield(2),
                GeneratorStep::Yield(3),
            ],
            None,
        );
        let sm = lower_to_state_machine(&src);
        let broken = apply_mutation(&sm, &LoweringMutation::DropState(1)); // drop Yield(2)
        let w = validate_lowering(&src, &broken).unwrap();
        assert!(!w.equivalent);
        // First mismatch at index 1 (source Yield(2) vs machine Yield(3)).
        assert_eq!(
            w.divergence,
            Some(TraceDivergence::EffectMismatch { index: 1 })
        );
    }

    #[test]
    fn reordered_yields_are_detected() {
        let src = sync(
            vec![GeneratorStep::Yield(10), GeneratorStep::Yield(20)],
            None,
        );
        let sm = lower_to_state_machine(&src);
        let broken = apply_mutation(&sm, &LoweringMutation::SwapEffects(0, 1));
        let w = validate_lowering(&src, &broken).unwrap();
        assert!(!w.equivalent);
        assert_eq!(
            w.divergence,
            Some(TraceDivergence::EffectMismatch { index: 0 })
        );
    }

    #[test]
    fn corrupted_return_value_is_detected() {
        let src = sync(vec![GeneratorStep::Yield(1)], Some(42));
        let sm = lower_to_state_machine(&src);
        let broken = apply_mutation(&sm, &LoweringMutation::CorruptReturn(Some(43)));
        let w = validate_lowering(&src, &broken).unwrap();
        assert!(!w.equivalent);
        assert_eq!(
            w.divergence,
            Some(TraceDivergence::EffectMismatch { index: 1 })
        );
    }

    #[test]
    fn dropped_return_value_is_detected() {
        let src = sync(vec![GeneratorStep::Yield(1)], Some(42));
        let sm = lower_to_state_machine(&src);
        let broken = apply_mutation(&sm, &LoweringMutation::CorruptReturn(None));
        let w = validate_lowering(&src, &broken).unwrap();
        assert!(!w.equivalent);
    }

    #[test]
    fn over_emitted_yield_is_detected() {
        let src = sync(vec![GeneratorStep::Yield(1), GeneratorStep::Yield(2)], None);
        let sm = lower_to_state_machine(&src);
        let broken = apply_mutation(&sm, &LoweringMutation::DuplicateEffect(0));
        let w = validate_lowering(&src, &broken).unwrap();
        assert!(!w.equivalent);
        // Index 1: source Yield(2) vs machine duplicated Yield(1).
        assert_eq!(
            w.divergence,
            Some(TraceDivergence::EffectMismatch { index: 1 })
        );
    }

    #[test]
    fn pure_length_mismatch_when_tail_dropped() {
        // Manually build a machine that is a strict prefix of the source.
        let src = sync(vec![GeneratorStep::Yield(1), GeneratorStep::Yield(2)], None);
        let sm = GeneratorStateMachine {
            kind: GeneratorKind::Sync,
            states: vec![GeneratorState {
                id: 0,
                on_enter: Some(StateEffect::Yield(1)),
                resume: None,
            }],
            initial: 0,
        };
        let w = validate_lowering(&src, &sm).unwrap();
        assert!(!w.equivalent);
        assert_eq!(
            w.divergence,
            Some(TraceDivergence::LengthMismatch {
                source: 3,
                machine: 1
            })
        );
    }

    // ----- replay error handling -----

    #[test]
    fn empty_state_machine_is_rejected() {
        let sm = GeneratorStateMachine {
            kind: GeneratorKind::Sync,
            states: vec![],
            initial: 0,
        };
        assert_eq!(
            replay_state_machine(&sm),
            Err(GeneratorValidationError::EmptyStateMachine)
        );
    }

    #[test]
    fn missing_resume_target_is_rejected() {
        let sm = GeneratorStateMachine {
            kind: GeneratorKind::Sync,
            states: vec![GeneratorState {
                id: 0,
                on_enter: Some(StateEffect::Yield(1)),
                resume: Some(99), // nonexistent
            }],
            initial: 0,
        };
        assert_eq!(
            replay_state_machine(&sm),
            Err(GeneratorValidationError::MissingState { id: 99 })
        );
    }

    #[test]
    fn cyclic_machine_hits_step_budget() {
        let sm = GeneratorStateMachine {
            kind: GeneratorKind::Sync,
            states: vec![
                GeneratorState {
                    id: 0,
                    on_enter: None,
                    resume: Some(1),
                },
                GeneratorState {
                    id: 1,
                    on_enter: None,
                    resume: Some(0),
                },
            ],
            initial: 0,
        };
        assert_eq!(
            replay_state_machine(&sm),
            Err(GeneratorValidationError::StepBudgetExceeded)
        );
    }

    // ----- corpus + bd-cixqu.45 events -----

    #[test]
    fn corpus_has_at_least_fifty_programs_across_four_categories() {
        let corpus = generate_generator_corpus();
        assert!(corpus.len() >= 50, "corpus = {}", corpus.len());
        let cats = |prefix: &str| {
            corpus
                .iter()
                .filter(|s| s.program_id.starts_with(prefix))
                .count()
        };
        assert!(cats("sync-multiyield-") > 0);
        assert!(cats("sync-return-") > 0);
        assert!(cats("async-await-yield-") > 0);
        assert!(cats("yield-delegate-") > 0);
        // Async category is genuinely async.
        assert!(corpus.iter().any(|s| s.kind == GeneratorKind::Async));
    }

    #[test]
    fn validate_corpus_all_equivalent_and_emits_events() {
        let corpus = generate_generator_corpus();
        let report = validate_corpus(&corpus).unwrap();
        assert_eq!(report.total, corpus.len());
        assert!(report.all_equivalent());
        assert_eq!(report.events.len(), corpus.len());
        // Events carry per-program structure.
        let async_event = report
            .events
            .iter()
            .find(|e| e.kind == "async")
            .expect("async event present");
        assert!(async_event.await_count > 0);
        assert!(async_event.equivalent);
        assert!(async_event.divergence.is_none());
    }

    #[test]
    fn corpus_yield_delegate_programs_have_expanded_yields() {
        let corpus = generate_generator_corpus();
        let report = validate_corpus(&corpus).unwrap();
        let deleg = report
            .events
            .iter()
            .find(|e| e.program_id == "yield-delegate-10")
            .unwrap();
        // 1 leading + 10 delegated + 1 trailing = 12 yields.
        assert_eq!(deleg.yield_count, 12);
    }

    // ----- digest + serde -----

    #[test]
    fn trace_digest_distinguishes_order() {
        let a = vec![GeneratorEffect::Yield(1), GeneratorEffect::Yield(2)];
        let b = vec![GeneratorEffect::Yield(2), GeneratorEffect::Yield(1)];
        assert_ne!(trace_digest(&a), trace_digest(&b));
    }

    #[test]
    fn trace_digest_distinguishes_return_presence() {
        let a = vec![GeneratorEffect::Return(None)];
        let b = vec![GeneratorEffect::Return(Some(0))];
        assert_ne!(trace_digest(&a), trace_digest(&b));
    }

    #[test]
    fn witness_serde_round_trip() {
        let src = sync(vec![GeneratorStep::Yield(1)], Some(2));
        let w = validate_generator(&src).unwrap();
        let json = serde_json::to_string(&w).unwrap();
        let restored: ValidationWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, restored);
    }

    #[test]
    fn event_serde_round_trip() {
        let report = validate_corpus(&generate_generator_corpus()).unwrap();
        let json = serde_json::to_string(&report.events[0]).unwrap();
        let restored: GeneratorValidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(report.events[0], restored);
    }

    #[test]
    fn error_display_is_descriptive() {
        assert!(format!("{}", GeneratorValidationError::MissingState { id: 7 }).contains('7'));
        assert!(format!("{}", GeneratorValidationError::StepBudgetExceeded).contains("budget"));
    }

    #[test]
    fn mutation_out_of_range_is_noop() {
        let src = sync(vec![GeneratorStep::Yield(1)], None);
        let sm = lower_to_state_machine(&src);
        let same = apply_mutation(&sm, &LoweringMutation::DropState(999));
        assert!(validate_lowering(&src, &same).unwrap().equivalent);
    }
}
