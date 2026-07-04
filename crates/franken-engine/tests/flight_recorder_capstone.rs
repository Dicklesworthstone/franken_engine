//! E3.TEST — Flight Recorder + time-travel debugger test+verify capstone
//! (bd-fqlfw.3.6).
//!
//! The layer-level suites already pin the flight-recorder index contract
//! (`runtime_explain_bundle_integration`: links resolve, missing/stale
//! flagged not invented, no payload duplication against existing bundlers),
//! the operator views (`runtime_explain_views_integration`), the navigation
//! cursor (`replay_time_travel_integration`), and the debugger protocol
//! (`time_travel_debugger_integration`: breakpoints, `why`, robot
//! round-trip). This capstone adds the cross-layer assertions those suites
//! cannot make alone:
//!
//! 1. **Reconstruction fidelity** — the debugger's re-run-from-scratch state
//!    producer (E3.T5d) reconstructs EXACTLY the state the interpreter
//!    originally observed at a sampled tick, on the same trace the original
//!    run recorded. This is the "reconstructed == originally-observed"
//!    acceptance line of the E3.TEST bead.
//! 2. **Live-reconstruction robot determinism** — two independent robot
//!    sessions over the same recorded trace, each lazily reconstructing
//!    state via real re-execution, emit byte-identical transcripts.
//!
//! The `frankenctl run --explain` fixed-input byte-identity E2E and the
//! `frankenctl explain` link re-verification run in the operator gate
//! (`scripts/run_dw_flight_recorder.sh ci`), which drives the real release
//! binary; its preserved bundle is re-verified by
//! `scripts/e2e/dw_flight_recorder_replay.sh`.

use std::collections::BTreeSet;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::deterministic_replay::{NondeterminismTrace, ReplayMode};
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::replay_time_travel::{TimeTravelConfig, TimeTravelCursor};
use frankenengine_engine::time_travel_debugger::{
    InterpreterStateSnapshot, ReplayStateProducer, RobotSession, TimeTravelDebugger,
};

/// A small but non-trivial frozen program: heap objects, nesting, and
/// register traffic, so a state snapshot has real content to disagree on.
const FROZEN_SOURCE: &str = "const point = { x: 1, y: 2 };\n\
                             const wrap = { inner: point, tag: 3 };\n\
                             const sum = point.x + point.y + wrap.tag;\n";

fn lowered_module(label: &str) -> Ir3Module {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(FROZEN_SOURCE, ParseGoal::Script, &ParserOptions::default())
        .expect("frozen source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, label);
    lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            "flight-capstone".to_string(),
            "flight-capstone".to_string(),
            "flight-capstone".to_string(),
        ),
    )
    .expect("frozen source should lower")
    .ir3
}

fn interpreter_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

/// Original run: observe state at `tick` with the interpreter's own capture
/// seam, and keep the recorded nondeterminism trace.
fn original_observation(
    module: &Ir3Module,
    tick: u64,
) -> (Option<InterpreterStateSnapshot>, NondeterminismTrace) {
    let mut core = InterpreterCore::new(interpreter_config(), "flight-capstone");
    core.arm_state_capture_at_tick(tick);
    let result = core.execute(module).expect("frozen program should execute");
    (
        core.take_captured_state()
            .map(InterpreterStateSnapshot::from_captured),
        result.nondeterminism_trace,
    )
}

#[test]
fn debugger_reconstruction_matches_originally_observed_state_at_sampled_ticks() {
    let module = lowered_module("flight-capstone-reconstruction");

    // Sample tick 0 (always a boundary) plus the final trace tick when the
    // program recorded nondeterminism events.
    let (observed_t0, trace) = original_observation(&module, 0);
    let observed_t0 = observed_t0.expect("tick-0 observation should land");
    let mut sample_ticks = vec![0u64];
    let final_tick = trace.event_count() as u64;
    if final_tick > 0 {
        sample_ticks.push(final_tick);
    }

    let producer = ReplayStateProducer::new(module.clone(), interpreter_config(), trace);
    for tick in sample_ticks {
        let (observed, _) = original_observation(&module, tick);
        let Some(observed) = observed else {
            // No instruction boundary landed exactly on this tick; the
            // producer must fail closed the same way rather than invent
            // state.
            let error = producer
                .snapshot_at(tick)
                .expect_err("producer must fail closed where the original run observed nothing");
            assert!(
                error.contains("unavailable"),
                "fail-closed error should say the state is unavailable, got: {error}"
            );
            continue;
        };
        let reconstructed = producer
            .snapshot_at(tick)
            .expect("producer should reconstruct a tick the original run observed");
        assert_eq!(
            reconstructed, observed,
            "re-run-from-scratch reconstruction must equal the originally observed state at tick {tick}"
        );
    }
    assert_eq!(
        producer
            .snapshot_at(0)
            .expect("repeat reconstruction should stay available"),
        observed_t0,
        "reconstruction must be stable across repeated re-runs"
    );
}

#[test]
fn robot_sessions_with_live_reconstruction_emit_byte_identical_transcripts() {
    let module = lowered_module("flight-capstone-robot");
    let (_, trace) = original_observation(&module, 0);

    let make_session = || {
        let cursor = TimeTravelCursor::new(
            trace.clone(),
            ReplayMode::Strict,
            TimeTravelConfig::default(),
        )
        .expect("cursor should open over the recorded trace");
        let debugger = TimeTravelDebugger::new(cursor, Vec::new());
        RobotSession::new_with_producer(
            debugger,
            ReplayStateProducer::new(module.clone(), interpreter_config(), trace.clone()),
        )
    };

    let script = [
        r#"{"cmd":"state"}"#,
        r#"{"cmd":"inspect","tick":0}"#,
        r#"{"cmd":"inspect","tick":0}"#,
        r#"{"cmd":"list_breakpoints"}"#,
    ];
    let drive = |mut session: RobotSession| -> Vec<String> {
        script
            .iter()
            .map(|line| session.handle_line(line))
            .collect()
    };

    let first = drive(make_session());
    let second = drive(make_session());
    assert_eq!(
        first, second,
        "independent live-reconstruction sessions must transcribe identically"
    );
    assert!(
        first[1].contains("\"ok\":true") && first[1].contains("\"kind\":\"inspection\""),
        "inspect must serve reconstructed state, got: {}",
        first[1]
    );
    assert_eq!(
        first[1], first[2],
        "cached second inspect must be byte-identical to the reconstructing first"
    );
}
