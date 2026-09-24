//! End-to-end capture->replay coverage for the interpreter `NondeterminismTrace`
//! (bd-bg9l1.1).
//!
//! Background
//! ----------
//! Before this test the deterministic-replay guarantee had ZERO end-to-end
//! coverage. The interpreter wrote its `NondeterminismTrace` at nine private
//! `capture()` sites but the trace was never exposed: it was not a field of
//! `ExecutionResult` and had no getter, so no test or production code ever read
//! back what a real execution captured. `ReplayEngine::replay_next` was only
//! ever exercised as a passive byte-comparator over hand-built traces — it had
//! never been fed a trace produced by an actual `execute()` call. A bug where
//! the interpreter captured the wrong source tag, the wrong bytes, the wrong
//! order, or dropped an event entirely would have passed every existing replay
//! test.
//!
//! The prerequisite source change (this change set) adds a finalised
//! `nondeterminism_trace` field to `ExecutionResult`. These tests then close
//! the loop the bead describes:
//!
//!   real source -> compile -> execute() -> extract trace
//!                -> re-execute() and cross-validate against the recorded trace
//!                   through the real `ReplayEngine`
//!                -> assert identical outcome.
//!
//! No mocks: the source string is parsed, lowered through the full IR0->IR3
//! pipeline, and run on a real `QuickJsLane`.

use frankenengine_engine::baseline_interpreter::{ExecutionResult, QuickJsLane};
use frankenengine_engine::deterministic_replay::{
    NondeterminismSource, ReplayEngine, ReplayError, ReplayMode,
};
use frankenengine_engine::ir_contract::Ir3Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

/// A program that reads the clock (`performance.now()`, captured as a
/// `TimerRead` event against the deterministic instruction-tick clock) and
/// also resolves properties. Clock reads are genuine nondeterminism and are
/// recorded event by event; property resolutions are a pure function of the
/// program, so since bd-9vouw.18 they are folded into the trace's
/// `deterministic_witness` instead of being appended as events.
const PROPERTY_HEAVY_SOURCE: &str = r#"
var config = { mode: 1, level: 2, name: 3 };
var nested = { inner: config };
var t0 = performance.now();
var a = config.mode;
var b = config.level;
var t1 = performance.now();
var c = config.name;
var missing = config.unknown;
var deep = nested.inner;
var t2 = performance.now();
a;
"#;

/// A loop whose only work is property access, parameterised by iteration
/// count, for the constant-memory check.
fn property_loop_source(iterations: u32) -> String {
    format!(
        "var o = {{ x: 1, y: 2 }}; var s = 0; \
         for (var i = 0; i < {iterations}; i++) {{ o.x = (o.x + o.y + i) % 1000003; s = s + o.x; }} s;"
    )
}

/// Parse + lower a real source string to an executable IR3 module.
fn compile(source: &str) -> Ir3Module {
    let tree = parse_script(source).expect("test source should parse as a script");
    let ir0 = frankenengine_engine::ir_contract::Ir0Module::from_syntax_tree(
        tree,
        "nondeterminism_trace_capture_replay.js",
    );
    let context = LoweringContext::new("ndt-trace", "ndt-decision", "ndt-policy");
    lower_ir0_to_ir3(&ir0, &context)
        .expect("test source should lower IR0->IR3")
        .ir3
}

/// Execute a real source string on a fresh interpreter lane and return the
/// full `ExecutionResult`, including the captured (and finalised) trace.
fn execute(source: &str, trace_id: &str) -> ExecutionResult {
    let module = compile(source);
    QuickJsLane::new()
        .execute(&module, trace_id)
        .expect("execution should succeed")
}

// ---------------------------------------------------------------------------
// 1. The trace is actually exposed and non-empty for a real execution.
// ---------------------------------------------------------------------------

#[test]
fn real_execution_exposes_a_non_empty_finalised_trace() {
    let result = execute(PROPERTY_HEAVY_SOURCE, "ndt-expose");
    let trace = &result.nondeterminism_trace;

    // Guards against a vacuous round-trip: if the field were never populated
    // (the original bug) this is exactly zero.
    assert!(
        trace.event_count() > 0,
        "a property-access program must capture at least one nondeterminism event; \
         got {} (trace field is write-only / not wired?)",
        trace.event_count()
    );

    // `take_execution_result` must finalise the trace so it is replay-ready.
    assert!(
        trace.is_finalised(),
        "exposed trace must be finalised (capture_ended_vts set) for replay"
    );
    trace
        .validate_for_replay()
        .expect("a finalised trace must validate for replay");

    // Sequence numbers are dense and monotonic from zero (capture order).
    for (idx, event) in trace.events.iter().enumerate() {
        assert_eq!(
            event.sequence, idx as u64,
            "trace sequence numbers must be dense and in capture order"
        );
        assert_eq!(
            event.component, "baseline_interpreter",
            "interpreter-captured events must be attributed to baseline_interpreter"
        );
    }

    // Each performance.now() call is one recorded TimerRead event.
    let timer_reads = trace
        .events
        .iter()
        .filter(|e| e.source == NondeterminismSource::TimerRead)
        .count();
    assert_eq!(
        timer_reads,
        3,
        "each of the three performance.now() calls must be recorded; sources seen: {:?}",
        trace
            .events
            .iter()
            .map(|e| e.source.as_str())
            .collect::<Vec<_>>()
    );

    // bd-9vouw.18: property resolutions are witnessed, never recorded as events.
    assert!(
        !trace
            .events
            .iter()
            .any(|e| e.source == NondeterminismSource::PropertyResolution),
        "property resolution must be folded into the deterministic witness, not recorded"
    );
    assert!(
        trace.deterministic_witness.event_count >= 5,
        "the five property reads must be folded into the witness; got {}",
        trace.deterministic_witness.event_count
    );
}

// ---------------------------------------------------------------------------
// 1b. bd-9vouw.18: recorded events do not grow with property-access work, the
//     witness does, and a different resolution path changes the witness.
// ---------------------------------------------------------------------------

#[test]
fn property_access_work_does_not_grow_recorded_events() {
    let small = execute(&property_loop_source(10), "ndt-loop-small");
    let large = execute(&property_loop_source(1_000), "ndt-loop-large");

    assert_eq!(
        small.nondeterminism_trace.events.len(),
        large.nondeterminism_trace.events.len(),
        "a 100x longer property loop must not record more events"
    );
    assert!(
        large.nondeterminism_trace.deterministic_witness.event_count
            >= 100 * small.nondeterminism_trace.deterministic_witness.event_count / 2,
        "the witness must still count every folded resolution: small {} large {}",
        small.nondeterminism_trace.deterministic_witness.event_count,
        large.nondeterminism_trace.deterministic_witness.event_count
    );
    assert_ne!(
        small.nondeterminism_trace.deterministic_witness.digest,
        large.nondeterminism_trace.deterministic_witness.digest,
        "different resolution histories must produce different digests"
    );
}

#[test]
fn witness_distinguishes_resolution_paths_with_identical_results() {
    // Same completion value (1), different property resolved: own vs inherited.
    let own = execute("var o = { k: 1 }; o.k;", "ndt-own");
    let inherited = execute(
        "function P() {} P.prototype.k = 1; var o = new P(); o.k;",
        "ndt-inherited",
    );
    assert_ne!(
        own.nondeterminism_trace.deterministic_witness,
        inherited.nondeterminism_trace.deterministic_witness,
        "own-property and prototype-chain resolution must witness differently"
    );
}

// ---------------------------------------------------------------------------
// 2. Re-execution is deterministic: the same source captures a byte-identical
//    trace. This is the core deterministic-replay guarantee and directly
//    catches "wrong bytes / wrong order / missing event" regressions.
// ---------------------------------------------------------------------------

#[test]
fn re_execution_captures_a_byte_identical_trace() {
    let first = execute(PROPERTY_HEAVY_SOURCE, "ndt-determinism");
    let second = execute(PROPERTY_HEAVY_SOURCE, "ndt-determinism");

    assert_eq!(
        first.nondeterminism_trace.events.len(),
        second.nondeterminism_trace.events.len(),
        "two runs of the same source must capture the same number of events"
    );
    // Event-for-event equality: source tag, opaque bytes, sequence and order.
    assert_eq!(
        first.nondeterminism_trace.events, second.nondeterminism_trace.events,
        "two runs of the same source must capture byte-identical, identically \
         ordered trace events"
    );
    assert_eq!(
        first.nondeterminism_trace.deterministic_witness,
        second.nondeterminism_trace.deterministic_witness,
        "two runs of the same source must fold an identical deterministic witness"
    );
}

// ---------------------------------------------------------------------------
// 3. The headline e2e: a real re-execution is cross-validated against the
//    recorded trace, event by event, through the real ReplayEngine in Strict
//    mode. If the second run captured a divergent tag/bytes/order or a missing
//    or extra event, the ReplayEngine rejects it.
// ---------------------------------------------------------------------------

#[test]
fn re_execution_replays_against_recorded_trace_without_divergence() {
    // Recorded run.
    let recorded = execute(PROPERTY_HEAVY_SOURCE, "ndt-record");
    assert!(
        recorded.nondeterminism_trace.event_count() > 0,
        "recorded trace must be non-empty for a meaningful replay"
    );

    // Independent live re-execution of the interpreter.
    let live = execute(PROPERTY_HEAVY_SOURCE, "ndt-live");

    // Strict replay: every divergence is a hard error.
    let mut engine = ReplayEngine::new(recorded.nondeterminism_trace.clone(), ReplayMode::Strict);

    for event in &live.nondeterminism_trace.events {
        let replayed = engine
            .replay_next(event.source.clone(), &event.value)
            .unwrap_or_else(|err| {
                panic!(
                    "strict replay of a faithful re-execution must not diverge at \
                     sequence {}: {err}",
                    event.sequence
                )
            });
        assert_eq!(
            replayed, event.value,
            "strict replay must echo the recorded bytes for sequence {}",
            event.sequence
        );
    }

    assert_eq!(
        engine.divergence_count(),
        0,
        "a faithful re-execution must produce zero divergences"
    );
    assert!(
        engine.is_complete(),
        "replay must consume the entire recorded trace (no missing/extra events): \
         {} of {} events replayed",
        engine.replayed_events,
        recorded.nondeterminism_trace.event_count()
    );
}

// ---------------------------------------------------------------------------
// 4. Negative controls: prove the replay round-trip is NOT vacuous — the
//    ReplayEngine genuinely detects corrupted bytes and a wrong source tag.
//    Without these, test 3 could pass even if replay_next ignored its inputs.
// ---------------------------------------------------------------------------

#[test]
fn strict_replay_rejects_corrupted_bytes() {
    let recorded = execute(PROPERTY_HEAVY_SOURCE, "ndt-corrupt");
    let trace = recorded.nondeterminism_trace;
    let first = trace
        .events
        .first()
        .expect("trace must have at least one event");

    let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::Strict);

    // Flip a byte (or supply a non-empty value for an empty one) so the live
    // value no longer matches the recorded bytes.
    let mut corrupted = first.value.clone();
    if let Some(byte) = corrupted.first_mut() {
        *byte ^= 0xFF;
    } else {
        corrupted.push(0xAB);
    }

    let err = engine
        .replay_next(first.source.clone(), &corrupted)
        .expect_err("strict replay must reject a byte-divergent live value");
    assert!(
        matches!(err, ReplayError::CriticalDivergence { sequence, .. } if sequence == first.sequence),
        "corrupted bytes must surface as a CriticalDivergence at the diverging sequence, got {err:?}"
    );
    assert_eq!(
        engine.divergence_count(),
        1,
        "the divergence must be recorded on the engine"
    );
}

#[test]
fn strict_replay_rejects_wrong_source_tag() {
    let recorded = execute(PROPERTY_HEAVY_SOURCE, "ndt-source-mismatch");
    let trace = recorded.nondeterminism_trace;
    let first = trace
        .events
        .first()
        .expect("trace must have at least one event");

    // Pick any source variant that differs from the recorded one.
    let wrong_source = NondeterminismSource::ALL
        .iter()
        .find(|s| **s != first.source)
        .expect("there is more than one nondeterminism source")
        .clone();

    let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::Strict);
    let err = engine
        .replay_next(wrong_source.clone(), &first.value)
        .expect_err("strict replay must reject a mismatched source tag");
    assert!(
        matches!(
            err,
            ReplayError::SourceMismatch { sequence, ref expected, ref actual }
                if sequence == first.sequence
                    && *expected == first.source
                    && *actual == wrong_source
        ),
        "wrong source tag must surface as a SourceMismatch, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. An unfinalised hand-built trace cannot be replayed — confirms the
//    finalisation that `take_execution_result` performs is load-bearing.
// ---------------------------------------------------------------------------

#[test]
fn unfinalised_trace_is_rejected_for_replay() {
    use frankenengine_engine::deterministic_replay::NondeterminismTrace;

    let mut trace = NondeterminismTrace::new("ndt-unfinalised");
    trace.capture(
        NondeterminismSource::PropertyResolution,
        b"property_found:key=x".to_vec(),
        0,
        "test",
    );
    // Deliberately NOT finalised.
    assert!(!trace.is_finalised());

    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let err = engine
        .replay_next(
            NondeterminismSource::PropertyResolution,
            b"property_found:key=x",
        )
        .expect_err("an unfinalised trace must not be replayable");
    assert!(
        matches!(err, ReplayError::TraceNotFinalised),
        "expected TraceNotFinalised, got {err:?}"
    );
}
