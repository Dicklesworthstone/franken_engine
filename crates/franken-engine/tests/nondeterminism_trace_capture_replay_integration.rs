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

/// A property-access-heavy program. Each `obj.key` member read drives the
/// interpreter through `GetProperty -> proxy_aware_get_property ->
/// prototype_chain_get`, which captures a `PropertyResolution` nondeterminism
/// event (found / not-found) — giving us a non-empty trace from real source.
const PROPERTY_HEAVY_SOURCE: &str = r#"
var config = { mode: 1, level: 2, name: 3 };
var nested = { inner: config };
var a = config.mode;
var b = config.level;
var c = config.name;
var missing = config.unknown;
var deep = nested.inner;
a;
"#;

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

    // The reads in PROPERTY_HEAVY_SOURCE are prototype-chain resolutions.
    assert!(
        trace
            .events
            .iter()
            .any(|e| e.source == NondeterminismSource::PropertyResolution),
        "property access should capture PropertyResolution events; sources seen: {:?}",
        trace
            .events
            .iter()
            .map(|e| e.source.as_str())
            .collect::<Vec<_>>()
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
        .replay_next(NondeterminismSource::PropertyResolution, b"property_found:key=x")
        .expect_err("an unfinalised trace must not be replayable");
    assert!(
        matches!(err, ReplayError::TraceNotFinalised),
        "expected TraceNotFinalised, got {err:?}"
    );
}
