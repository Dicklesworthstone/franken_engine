//! Integration tests for `replay_time_travel` (E3.T5a, `bd-fqlfw.3.5.1`).
//!
//! Proves the bead's acceptance criteria against the public API only:
//! `back` and `goto <tick>` reconstruct exact state with no perturbation of
//! behavior, backward navigation is bounded by one checkpoint interval of
//! re-execution, and checkpoint storage stays sparse (zero per-tick storage).

use frankenengine_engine::deterministic_replay::{
    NondeterminismSource, NondeterminismTrace, ReplayMode,
};
use frankenengine_engine::replay_time_travel::{
    CursorState, TimeTravelConfig, TimeTravelCursor, TimeTravelError,
};

/// Build a realistic mixed-source trace. Includes duplicate virtual
/// timestamps (two events in the same logical instant) and variable-length
/// payloads to exercise the engine's value path.
fn make_trace(events: usize) -> NondeterminismTrace {
    let mut trace = NondeterminismTrace::new("tt-integration-session");
    let mut virtual_ts: u64 = 0;
    for index in 0..events {
        // Advance the clock on most ticks; every fifth event shares the
        // previous timestamp to model same-instant decisions.
        if !index.is_multiple_of(5) || index == 0 {
            virtual_ts = virtual_ts.saturating_add(7);
        }
        let source = NondeterminismSource::ALL[index % NondeterminismSource::ALL.len()].clone();
        let payload: Vec<u8> = (0..(index % 5 + 1))
            .map(|byte| byte as u8 ^ index as u8)
            .collect();
        trace.capture(
            source,
            payload,
            virtual_ts,
            format!("itest-component-{index}"),
        );
    }
    trace.finalise(virtual_ts);
    trace
}

fn make_cursor(events: usize, interval: u64, mode: ReplayMode) -> TimeTravelCursor {
    TimeTravelCursor::new(
        make_trace(events),
        mode,
        TimeTravelConfig {
            checkpoint_interval: interval,
        },
    )
    .expect("cursor construction should succeed for a finalised trace")
}

/// Ground-truth fingerprints from a single uninterrupted forward pass.
fn forward_truth(events: usize, interval: u64, mode: ReplayMode) -> Vec<CursorState> {
    let mut cursor = make_cursor(events, interval, mode);
    let mut states = vec![cursor.observable_state()];
    while !cursor.at_end() {
        cursor.step_forward().expect("forward step should succeed");
        states.push(cursor.observable_state());
    }
    states
}

/// Deterministic pseudo-random sequence (LCG) — no `rand`, replay-friendly.
fn lcg_sequence(seed: u64, len: usize, modulus: u64) -> Vec<u64> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state % modulus
        })
        .collect()
}

#[test]
fn goto_reconstructs_exact_state_for_every_tick() {
    let events = 60;
    let interval = 8;
    let truth = forward_truth(events, interval, ReplayMode::Strict);
    let mut cursor = make_cursor(events, interval, ReplayMode::Strict);
    cursor.run_to_end().expect("run_to_end should succeed");
    for target in (0..=events as u64).rev() {
        cursor.goto_tick(target).expect("goto should succeed");
        assert_eq!(
            cursor.observable_state(),
            truth[target as usize],
            "exact-state reconstruction failed at tick {target}"
        );
    }
}

#[test]
fn random_order_navigation_matches_forward_truth() {
    let events = 47;
    let interval = 6;
    let truth = forward_truth(events, interval, ReplayMode::Strict);
    let mut cursor = make_cursor(events, interval, ReplayMode::Strict);
    for target in lcg_sequence(0x5EED, 120, events as u64 + 1) {
        cursor.goto_tick(target).expect("goto should succeed");
        assert_eq!(
            cursor.observable_state(),
            truth[target as usize],
            "random-order reconstruction failed at tick {target}"
        );
    }
}

#[test]
fn back_chain_from_end_to_origin_matches_truth() {
    let events = 30;
    let interval = 4;
    let truth = forward_truth(events, interval, ReplayMode::Strict);
    let mut cursor = make_cursor(events, interval, ReplayMode::Strict);
    cursor.run_to_end().expect("run_to_end should succeed");
    for expected_tick in (0..events as u64).rev() {
        let tick = cursor.back().expect("back should succeed");
        assert_eq!(tick, expected_tick);
        assert_eq!(cursor.observable_state(), truth[expected_tick as usize]);
    }
    assert!(matches!(cursor.back(), Err(TimeTravelError::AtOrigin)));
}

#[test]
fn backward_rerun_cost_is_bounded_by_checkpoint_interval() {
    let events = 100;
    for interval in [1u64, 3, 8, 25] {
        let mut cursor = make_cursor(events, interval, ReplayMode::Strict);
        cursor.run_to_end().expect("run_to_end should succeed");
        for target in lcg_sequence(0xB0B + interval, 60, events as u64 + 1) {
            let current = cursor.current_tick();
            cursor.goto_tick(target).expect("goto should succeed");
            if target < current {
                assert!(
                    cursor.last_rerun_steps() < interval,
                    "interval {interval}: backward goto to {target} re-ran {} steps",
                    cursor.last_rerun_steps()
                );
            }
        }
    }
}

#[test]
fn checkpoint_storage_stays_sparse() {
    let events = 90;
    let interval = 9;
    let mut cursor = make_cursor(events, interval, ReplayMode::Strict);
    cursor.run_to_end().expect("run_to_end should succeed");
    // Tick-0 baseline + one checkpoint per interval multiple: zero per-tick
    // storage.
    let expected_max = events as u64 / interval + 1;
    assert!(
        (cursor.checkpoint_count() as u64) <= expected_max,
        "checkpoint count {} exceeds sparse bound {expected_max}",
        cursor.checkpoint_count()
    );
}

#[test]
fn navigation_state_is_invariant_across_checkpoint_intervals() {
    let events = 40;
    let reference = forward_truth(events, 64, ReplayMode::Strict);
    for interval in [1u64, 2, 7, 13, 1000] {
        let mut cursor = make_cursor(events, interval, ReplayMode::Strict);
        cursor.run_to_end().expect("run_to_end should succeed");
        for target in [0u64, 1, 19, 39, 40, 5, 33] {
            cursor.goto_tick(target).expect("goto should succeed");
            assert_eq!(
                cursor.observable_state(),
                reference[target as usize],
                "interval {interval} diverged at tick {target}"
            );
        }
    }
}

#[test]
fn zigzag_navigation_never_perturbs_terminal_state() {
    let events = 35;
    let truth = forward_truth(events, 5, ReplayMode::Strict);
    let mut cursor = make_cursor(events, 5, ReplayMode::Strict);
    for target in lcg_sequence(0xA11CE, 40, events as u64 + 1) {
        cursor.goto_tick(target).expect("goto should succeed");
    }
    cursor.run_to_end().expect("run_to_end should succeed");
    assert_eq!(cursor.observable_state(), truth[events]);
    assert_eq!(
        cursor.engine().divergence_count(),
        0,
        "self-driven navigation must not fabricate divergences"
    );
}

#[test]
fn all_replay_modes_navigate_identically_on_clean_traces() {
    let events = 24;
    for mode in [
        ReplayMode::Strict,
        ReplayMode::BestEffort,
        ReplayMode::Validate,
    ] {
        let truth = forward_truth(events, 4, mode);
        let mut cursor = make_cursor(events, 4, mode);
        cursor.run_to_end().expect("run_to_end should succeed");
        cursor.goto_tick(13).expect("goto should succeed");
        assert_eq!(cursor.observable_state(), truth[13]);
    }
}

#[test]
fn out_of_range_and_origin_errors_are_fail_closed() {
    let mut cursor = make_cursor(10, 4, ReplayMode::Strict);
    assert!(matches!(
        cursor.goto_tick(11),
        Err(TimeTravelError::TickOutOfRange {
            requested: 11,
            max: 10
        })
    ));
    assert!(matches!(cursor.back(), Err(TimeTravelError::AtOrigin)));
    // Errors must not move the cursor.
    assert_eq!(cursor.current_tick(), 0);
}

#[test]
fn empty_trace_supports_origin_navigation_only() {
    let mut trace = NondeterminismTrace::new("empty-itest");
    trace.finalise(0);
    let mut cursor = TimeTravelCursor::new(trace, ReplayMode::Strict, TimeTravelConfig::default())
        .expect("cursor construction should succeed");
    assert!(cursor.at_end());
    assert_eq!(cursor.goto_tick(0).expect("goto 0 should succeed"), 0);
    assert!(matches!(
        cursor.goto_tick(1),
        Err(TimeTravelError::TickOutOfRange { .. })
    ));
}
