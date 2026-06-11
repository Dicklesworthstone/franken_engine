//! Reverse-via-re-run time-travel navigation over the deterministic replay
//! engine, with sparse checkpointing (E3.T5a, `bd-fqlfw.3.5.1`).
//!
//! The cursor wraps [`ReplayEngine`] and navigates a finalised
//! [`NondeterminismTrace`] in both directions. Backward navigation never
//! mutates state in reverse: it restores the nearest sparse checkpoint at or
//! before the target tick and deterministically re-runs forward, so a `back`
//! or `goto` costs at most one checkpoint interval of re-execution (O(K))
//! while storing no per-tick state.
//!
//! Navigation is self-driving: each forward step re-feeds the recorded event
//! value into [`ReplayEngine::replay_next`], so in `Strict` mode a navigation
//! pass can never fabricate a divergence — reconstructed state is exactly the
//! state the original forward pass had at that tick.
//!
//! A *tick* is the number of trace events consumed; tick 0 is the origin
//! (nothing replayed) and tick `trace.event_count()` is the end.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::deterministic_replay::{
    NondeterminismTrace, ReplayEngine, ReplayError, ReplayMode, TraceEvent,
};

/// Default sparse-checkpoint interval (ticks between checkpoints).
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 64;

/// Configuration for the time-travel cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TimeTravelConfig {
    /// Record a checkpoint every `checkpoint_interval` ticks. Must be >= 1.
    pub checkpoint_interval: u64,
}

impl Default for TimeTravelConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
        }
    }
}

impl TimeTravelConfig {
    /// Validate structural invariants. Fail-closed: an interval of zero would
    /// make the sparse index degenerate, so it is rejected at construction.
    pub fn validate(&self) -> Result<(), TimeTravelError> {
        if self.checkpoint_interval == 0 {
            return Err(TimeTravelError::InvalidConfig {
                detail: "checkpoint_interval must be >= 1".to_string(),
            });
        }
        Ok(())
    }
}

/// A sparse snapshot of replay-engine state at a specific tick.
///
/// Deliberately stores only the engine's navigation scalars plus the
/// divergence log — never the trace itself — so checkpoint storage is
/// O(checkpoint count), not O(ticks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseCheckpoint {
    /// Tick this checkpoint was taken at (== events consumed == cursor).
    pub tick: u64,
    /// Engine cursor index into the trace event vector.
    pub cursor: usize,
    /// Engine virtual timestamp at this tick.
    pub virtual_ts: u64,
    /// Engine replayed-event counter at this tick.
    pub replayed_events: u64,
    /// Divergence log as of this tick (usually empty for self-driven runs).
    pub divergences: Vec<crate::deterministic_replay::ReplayDivergence>,
}

/// Externally observable cursor state at a tick, used to prove exact
/// reconstruction in tests and downstream debugger surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorState {
    pub tick: u64,
    pub virtual_ts: u64,
    pub replayed_events: u64,
    pub divergence_count: u64,
    pub at_end: bool,
}

/// Errors from time-travel navigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeTravelError {
    /// Underlying replay-engine error.
    Replay(ReplayError),
    /// Requested tick is beyond the end of the trace.
    TickOutOfRange { requested: u64, max: u64 },
    /// `back` requested at tick 0.
    AtOrigin,
    /// Invalid configuration.
    InvalidConfig { detail: String },
}

impl std::fmt::Display for TimeTravelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replay(err) => write!(f, "replay error during time-travel: {err}"),
            Self::TickOutOfRange { requested, max } => {
                write!(f, "tick {requested} out of range (max {max})")
            }
            Self::AtOrigin => f.write_str("already at tick 0; cannot step back"),
            Self::InvalidConfig { detail } => write!(f, "invalid time-travel config: {detail}"),
        }
    }
}

impl From<ReplayError> for TimeTravelError {
    fn from(err: ReplayError) -> Self {
        Self::Replay(err)
    }
}

/// Bidirectional cursor over a finalised nondeterminism trace.
///
/// Forward steps re-feed recorded values (deterministic self-drive); backward
/// steps restore the nearest sparse checkpoint and re-run forward. The trace
/// is owned once by the wrapped engine and never duplicated into checkpoints.
#[derive(Debug, Clone)]
pub struct TimeTravelCursor {
    engine: ReplayEngine,
    config: TimeTravelConfig,
    /// Sparse checkpoint index keyed by tick. Tick 0 is always present.
    checkpoints: BTreeMap<u64, SparseCheckpoint>,
    /// Forward re-run steps performed by the most recent `goto`/`back`
    /// (diagnostics for the O(K) bound; 0 for forward-only navigation).
    last_rerun_steps: u64,
}

impl TimeTravelCursor {
    /// Build a cursor over a finalised trace. Fails closed on an unfinalised
    /// trace or a degenerate config.
    pub fn new(
        trace: NondeterminismTrace,
        mode: ReplayMode,
        config: TimeTravelConfig,
    ) -> Result<Self, TimeTravelError> {
        config.validate()?;
        trace.validate_for_replay()?;
        let engine = ReplayEngine::new(trace, mode);
        let mut cursor = Self {
            engine,
            config,
            checkpoints: BTreeMap::new(),
            last_rerun_steps: 0,
        };
        // Tick-0 baseline checkpoint guarantees backward navigation always
        // finds a restore point.
        cursor.checkpoints.insert(0, cursor.snapshot());
        Ok(cursor)
    }

    /// Current tick (events consumed so far).
    pub fn current_tick(&self) -> u64 {
        self.engine.cursor as u64
    }

    /// Total ticks in the trace (== event count).
    pub fn total_ticks(&self) -> u64 {
        self.engine.trace.events.len() as u64
    }

    /// Engine virtual timestamp at the current tick.
    pub fn virtual_ts(&self) -> u64 {
        self.engine.virtual_ts
    }

    /// Whether the cursor sits at the end of the trace.
    pub fn at_end(&self) -> bool {
        self.engine.is_complete()
    }

    /// Replay mode of the wrapped engine.
    pub fn mode(&self) -> ReplayMode {
        self.engine.mode
    }

    /// Read-only view of the wrapped engine.
    pub fn engine(&self) -> &ReplayEngine {
        &self.engine
    }

    /// Number of sparse checkpoints currently held.
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Ticks at which checkpoints are held, ascending.
    pub fn checkpoint_ticks(&self) -> Vec<u64> {
        self.checkpoints.keys().copied().collect()
    }

    /// Forward re-run steps performed by the most recent backward navigation.
    pub fn last_rerun_steps(&self) -> u64 {
        self.last_rerun_steps
    }

    /// Externally observable state at the current tick.
    pub fn observable_state(&self) -> CursorState {
        CursorState {
            tick: self.current_tick(),
            virtual_ts: self.engine.virtual_ts,
            replayed_events: self.engine.replayed_events,
            divergence_count: self.engine.divergences.len() as u64,
            at_end: self.at_end(),
        }
    }

    fn snapshot(&self) -> SparseCheckpoint {
        SparseCheckpoint {
            tick: self.current_tick(),
            cursor: self.engine.cursor,
            virtual_ts: self.engine.virtual_ts,
            replayed_events: self.engine.replayed_events,
            divergences: self.engine.divergences.clone(),
        }
    }

    fn restore(&mut self, checkpoint: &SparseCheckpoint) {
        self.engine.cursor = checkpoint.cursor;
        self.engine.virtual_ts = checkpoint.virtual_ts;
        self.engine.replayed_events = checkpoint.replayed_events;
        self.engine.divergences = checkpoint.divergences.clone();
    }

    /// Advance one tick by re-feeding the recorded event into the engine.
    /// Returns a reference to the event that was replayed.
    pub fn step_forward(&mut self) -> Result<&TraceEvent, TimeTravelError> {
        let index = self.engine.cursor;
        if index >= self.engine.trace.events.len() {
            return Err(TimeTravelError::TickOutOfRange {
                requested: (index as u64).saturating_add(1),
                max: self.total_ticks(),
            });
        }
        let (source, value) = {
            let event = &self.engine.trace.events[index];
            (event.source.clone(), event.value.clone())
        };
        self.engine.replay_next(source, &value)?;

        let tick = self.current_tick();
        if tick.is_multiple_of(self.config.checkpoint_interval) {
            let snapshot = self.snapshot();
            self.checkpoints.insert(tick, snapshot);
        }
        Ok(&self.engine.trace.events[index])
    }

    /// Step back exactly one tick via checkpoint-restore + re-run.
    /// Returns the new current tick.
    pub fn back(&mut self) -> Result<u64, TimeTravelError> {
        let current = self.current_tick();
        if current == 0 {
            return Err(TimeTravelError::AtOrigin);
        }
        self.goto_tick(current.saturating_sub(1))
    }

    /// Navigate to an absolute tick (0..=total_ticks), forward or backward.
    /// Backward targets restore the nearest checkpoint at or before the
    /// target and re-run forward, bounded by one checkpoint interval.
    /// Returns the new current tick.
    pub fn goto_tick(&mut self, target: u64) -> Result<u64, TimeTravelError> {
        let max = self.total_ticks();
        if target > max {
            return Err(TimeTravelError::TickOutOfRange {
                requested: target,
                max,
            });
        }
        let current = self.current_tick();
        if target < current {
            let checkpoint = self
                .checkpoints
                .range(..=target)
                .next_back()
                .map(|(_, checkpoint)| checkpoint.clone())
                .expect("tick-0 baseline checkpoint always exists");
            self.restore(&checkpoint);
            let mut rerun_steps: u64 = 0;
            while self.current_tick() < target {
                self.step_forward()?;
                rerun_steps = rerun_steps.saturating_add(1);
            }
            self.last_rerun_steps = rerun_steps;
        } else {
            while self.current_tick() < target {
                self.step_forward()?;
            }
            self.last_rerun_steps = 0;
        }
        Ok(self.current_tick())
    }

    /// Run forward to the end of the trace. Returns the terminal tick.
    pub fn run_to_end(&mut self) -> Result<u64, TimeTravelError> {
        let max = self.total_ticks();
        self.goto_tick(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_replay::{DivergenceSeverity, NondeterminismSource};

    fn make_trace(events: usize) -> NondeterminismTrace {
        let mut trace = NondeterminismTrace::new("tt-test-session");
        for index in 0..events {
            let source = NondeterminismSource::ALL[index % NondeterminismSource::ALL.len()].clone();
            trace.capture(
                source,
                vec![index as u8, (index / 7) as u8],
                (index as u64).saturating_add(1) * 10,
                format!("component-{index}"),
            );
        }
        trace.finalise(events as u64 * 10);
        trace
    }

    fn make_cursor(events: usize, interval: u64) -> TimeTravelCursor {
        TimeTravelCursor::new(
            make_trace(events),
            ReplayMode::Strict,
            TimeTravelConfig {
                checkpoint_interval: interval,
            },
        )
        .expect("cursor construction should succeed for finalised trace")
    }

    /// Forward-pass fingerprints for every tick 0..=N, used as ground truth.
    fn forward_fingerprints(events: usize, interval: u64) -> Vec<CursorState> {
        let mut cursor = make_cursor(events, interval);
        let mut states = vec![cursor.observable_state()];
        while !cursor.at_end() {
            cursor.step_forward().expect("forward step should succeed");
            states.push(cursor.observable_state());
        }
        states
    }

    #[test]
    fn default_config_uses_documented_interval() {
        assert_eq!(
            TimeTravelConfig::default().checkpoint_interval,
            DEFAULT_CHECKPOINT_INTERVAL
        );
    }

    #[test]
    fn zero_interval_config_rejected() {
        let result = TimeTravelCursor::new(
            make_trace(4),
            ReplayMode::Strict,
            TimeTravelConfig {
                checkpoint_interval: 0,
            },
        );
        assert!(matches!(result, Err(TimeTravelError::InvalidConfig { .. })));
    }

    #[test]
    fn unfinalised_trace_fails_closed() {
        let trace = NondeterminismTrace::new("unfinalised");
        let result = TimeTravelCursor::new(trace, ReplayMode::Strict, TimeTravelConfig::default());
        assert!(matches!(
            result,
            Err(TimeTravelError::Replay(ReplayError::TraceNotFinalised))
        ));
    }

    #[test]
    fn new_cursor_seeds_tick_zero_checkpoint() {
        let cursor = make_cursor(8, 4);
        assert_eq!(cursor.checkpoint_ticks(), vec![0]);
        assert_eq!(cursor.current_tick(), 0);
    }

    #[test]
    fn step_forward_advances_tick_and_virtual_ts() {
        let mut cursor = make_cursor(5, 64);
        let event = cursor.step_forward().expect("step should succeed");
        assert_eq!(event.sequence, 0);
        assert_eq!(cursor.current_tick(), 1);
        assert_eq!(cursor.virtual_ts(), 10);
    }

    #[test]
    fn step_forward_at_end_errors() {
        let mut cursor = make_cursor(2, 64);
        cursor.run_to_end().expect("run_to_end should succeed");
        let result = cursor.step_forward();
        assert!(matches!(
            result,
            Err(TimeTravelError::TickOutOfRange { .. })
        ));
    }

    #[test]
    fn self_driven_walk_introduces_no_divergences_in_strict_mode() {
        let mut cursor = make_cursor(22, 4);
        cursor.run_to_end().expect("run_to_end should succeed");
        assert_eq!(cursor.engine().divergence_count(), 0);
        assert!(cursor.at_end());
    }

    #[test]
    fn checkpoints_recorded_at_interval_multiples() {
        let mut cursor = make_cursor(10, 3);
        cursor.run_to_end().expect("run_to_end should succeed");
        assert_eq!(cursor.checkpoint_ticks(), vec![0, 3, 6, 9]);
    }

    #[test]
    fn checkpoint_snapshot_matches_engine_scalars() {
        let mut cursor = make_cursor(6, 2);
        cursor.goto_tick(4).expect("goto should succeed");
        let checkpoint = cursor
            .checkpoints
            .get(&4)
            .expect("checkpoint at tick 4 should exist");
        assert_eq!(checkpoint.tick, 4);
        assert_eq!(checkpoint.cursor, 4);
        assert_eq!(checkpoint.virtual_ts, 40);
        assert_eq!(checkpoint.replayed_events, 4);
        assert!(checkpoint.divergences.is_empty());
    }

    #[test]
    fn back_at_origin_errors() {
        let mut cursor = make_cursor(3, 64);
        assert!(matches!(cursor.back(), Err(TimeTravelError::AtOrigin)));
    }

    #[test]
    fn back_reconstructs_exact_prior_state() {
        let truth = forward_fingerprints(12, 4);
        let mut cursor = make_cursor(12, 4);
        cursor.goto_tick(9).expect("goto should succeed");
        let new_tick = cursor.back().expect("back should succeed");
        assert_eq!(new_tick, 8);
        assert_eq!(cursor.observable_state(), truth[8]);
    }

    #[test]
    fn goto_forward_reaches_target() {
        let mut cursor = make_cursor(10, 64);
        let tick = cursor.goto_tick(7).expect("goto should succeed");
        assert_eq!(tick, 7);
        assert_eq!(cursor.current_tick(), 7);
    }

    #[test]
    fn goto_backward_reconstructs_every_tick_exactly() {
        let events = 25;
        let interval = 4;
        let truth = forward_fingerprints(events, interval);
        let mut cursor = make_cursor(events, interval);
        cursor.run_to_end().expect("run_to_end should succeed");
        for target in (0..=events as u64).rev() {
            cursor.goto_tick(target).expect("goto should succeed");
            assert_eq!(
                cursor.observable_state(),
                truth[target as usize],
                "state mismatch at tick {target}"
            );
        }
    }

    #[test]
    fn goto_same_tick_is_noop() {
        let mut cursor = make_cursor(8, 4);
        cursor.goto_tick(5).expect("goto should succeed");
        let before = cursor.observable_state();
        cursor.goto_tick(5).expect("goto should succeed");
        assert_eq!(cursor.observable_state(), before);
        assert_eq!(cursor.last_rerun_steps(), 0);
    }

    #[test]
    fn goto_beyond_end_errors() {
        let mut cursor = make_cursor(4, 64);
        let result = cursor.goto_tick(5);
        assert!(matches!(
            result,
            Err(TimeTravelError::TickOutOfRange {
                requested: 5,
                max: 4
            })
        ));
    }

    #[test]
    fn goto_origin_restores_initial_state() {
        let truth = forward_fingerprints(9, 3);
        let mut cursor = make_cursor(9, 3);
        cursor.run_to_end().expect("run_to_end should succeed");
        cursor.goto_tick(0).expect("goto should succeed");
        assert_eq!(cursor.observable_state(), truth[0]);
        assert_eq!(cursor.virtual_ts(), 0);
    }

    #[test]
    fn backward_rerun_cost_bounded_by_interval() {
        let interval = 5;
        let mut cursor = make_cursor(31, interval);
        cursor.run_to_end().expect("run_to_end should succeed");
        for target in (0..31).rev() {
            cursor.goto_tick(target).expect("goto should succeed");
            assert!(
                cursor.last_rerun_steps() < interval,
                "rerun cost {} at tick {target} exceeds interval bound {interval}",
                cursor.last_rerun_steps()
            );
        }
    }

    #[test]
    fn zigzag_navigation_does_not_perturb_terminal_state() {
        let events = 18;
        let truth = forward_fingerprints(events, 4);
        let mut cursor = make_cursor(events, 4);
        // Deterministic zigzag: forward, backward, forward again.
        cursor.goto_tick(11).expect("goto should succeed");
        cursor.goto_tick(2).expect("goto should succeed");
        cursor.goto_tick(15).expect("goto should succeed");
        cursor.back().expect("back should succeed");
        cursor.run_to_end().expect("run_to_end should succeed");
        assert_eq!(cursor.observable_state(), truth[events]);
    }

    #[test]
    fn total_ticks_matches_event_count() {
        let cursor = make_cursor(13, 64);
        assert_eq!(cursor.total_ticks(), 13);
    }

    #[test]
    fn virtual_ts_tracks_replayed_event() {
        let mut cursor = make_cursor(7, 64);
        cursor.goto_tick(3).expect("goto should succeed");
        // Events carry virtual_ts (index+1)*10.
        assert_eq!(cursor.virtual_ts(), 30);
    }

    #[test]
    fn works_in_best_effort_and_validate_modes() {
        for mode in [ReplayMode::BestEffort, ReplayMode::Validate] {
            let mut cursor = TimeTravelCursor::new(
                make_trace(10),
                mode,
                TimeTravelConfig {
                    checkpoint_interval: 3,
                },
            )
            .expect("cursor construction should succeed");
            cursor.run_to_end().expect("run_to_end should succeed");
            cursor.goto_tick(4).expect("goto should succeed");
            assert_eq!(cursor.current_tick(), 4);
            assert_eq!(cursor.mode(), mode);
            assert_eq!(cursor.engine().divergence_count(), 0);
        }
    }

    #[test]
    fn empty_finalised_trace_is_navigable() {
        let mut trace = NondeterminismTrace::new("empty");
        trace.finalise(0);
        let mut cursor =
            TimeTravelCursor::new(trace, ReplayMode::Strict, TimeTravelConfig::default())
                .expect("cursor construction should succeed");
        assert!(cursor.at_end());
        assert_eq!(cursor.total_ticks(), 0);
        assert_eq!(cursor.goto_tick(0).expect("goto 0 should succeed"), 0);
        assert!(matches!(
            cursor.step_forward(),
            Err(TimeTravelError::TickOutOfRange { .. })
        ));
    }

    #[test]
    fn sparse_checkpoint_serde_round_trip() {
        let mut cursor = make_cursor(6, 2);
        cursor.run_to_end().expect("run_to_end should succeed");
        let checkpoint = cursor
            .checkpoints
            .get(&4)
            .expect("checkpoint at tick 4 should exist");
        let json = serde_json::to_string(checkpoint).expect("serialize should succeed");
        let decoded: SparseCheckpoint =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(&decoded, checkpoint);
    }

    #[test]
    fn interval_one_checkpoints_every_tick_and_zero_rerun_cost() {
        let mut cursor = make_cursor(8, 1);
        cursor.run_to_end().expect("run_to_end should succeed");
        assert_eq!(cursor.checkpoint_count(), 9); // ticks 0..=8
        cursor.goto_tick(3).expect("goto should succeed");
        assert_eq!(cursor.last_rerun_steps(), 0);
    }

    #[test]
    fn error_display_is_nonempty_and_specific() {
        let cases = [
            TimeTravelError::Replay(ReplayError::TraceNotFinalised),
            TimeTravelError::TickOutOfRange {
                requested: 9,
                max: 4,
            },
            TimeTravelError::AtOrigin,
            TimeTravelError::InvalidConfig {
                detail: "x".to_string(),
            },
        ];
        for case in cases {
            assert!(!case.to_string().is_empty());
        }
        assert!(
            TimeTravelError::TickOutOfRange {
                requested: 9,
                max: 4
            }
            .to_string()
            .contains('9')
        );
    }

    #[test]
    fn cursor_state_serde_round_trip() {
        let mut cursor = make_cursor(5, 2);
        cursor.goto_tick(5).expect("goto should succeed");
        let state = cursor.observable_state();
        let json = serde_json::to_string(&state).expect("serialize should succeed");
        let decoded: CursorState = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(decoded, state);
    }

    #[test]
    fn divergence_log_restored_with_checkpoint() {
        // Simulate a divergence recorded before navigation by snapshotting a
        // cursor whose engine carries one, then proving restore round-trips it.
        let mut cursor = make_cursor(10, 3);
        cursor.goto_tick(6).expect("goto should succeed");
        cursor
            .engine
            .divergences
            .push(crate::deterministic_replay::ReplayDivergence {
                sequence: 99,
                source: NondeterminismSource::TimerRead,
                expected_value: vec![1],
                actual_value: vec![2],
                virtual_ts: 990,
                severity: DivergenceSeverity::Warning,
            });
        let snapshot = cursor.snapshot();
        cursor.goto_tick(9).expect("goto should succeed");
        cursor.restore(&snapshot);
        assert_eq!(cursor.engine().divergence_count(), 1);
        assert_eq!(cursor.current_tick(), 6);
    }

    #[test]
    fn checkpoints_persist_across_backward_navigation() {
        let mut cursor = make_cursor(20, 5);
        cursor.run_to_end().expect("run_to_end should succeed");
        let before = cursor.checkpoint_ticks();
        cursor.goto_tick(1).expect("goto should succeed");
        assert_eq!(cursor.checkpoint_ticks(), before);
    }

    #[test]
    fn observable_state_reports_at_end() {
        let mut cursor = make_cursor(3, 64);
        assert!(!cursor.observable_state().at_end);
        cursor.run_to_end().expect("run_to_end should succeed");
        assert!(cursor.observable_state().at_end);
    }
}
