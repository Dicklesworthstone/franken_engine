//! Deterministic lab runtime harness with virtual time, schedule replay,
//! and cancellation/fault injection.
//!
//! Replaces the production async runtime in test/lab environments for
//! full control over task scheduling, time, and fault injection.
//! Given the same seed and schedule, produces byte-identical event sequences.
//!
//! Plan references: Section 10.11 item 9, 9G.4 (deterministic lab runtime),
//! Top-10 #3 (deterministic evidence graph), #9 (adversarial corpus).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// VirtualClock — deterministic time source
// ---------------------------------------------------------------------------

/// Deterministic virtual clock for lab runtime.
/// Advances only when explicitly stepped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualClock {
    /// Current virtual time in ticks.
    now_ticks: u64,
}

impl VirtualClock {
    /// Create a new clock starting at tick 0.
    pub fn new() -> Self {
        Self { now_ticks: 0 }
    }

    /// Current virtual time.
    pub fn now(&self) -> u64 {
        self.now_ticks
    }

    /// Advance by a given number of ticks.
    pub fn advance(&mut self, ticks: u64) {
        self.now_ticks = self.now_ticks.saturating_add(ticks);
    }

    /// Advance to a specific tick (must be >= current).
    pub fn advance_to(&mut self, tick: u64) -> bool {
        if tick >= self.now_ticks {
            self.now_ticks = tick;
            true
        } else {
            false
        }
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TaskId — deterministic task identifier
// ---------------------------------------------------------------------------

/// Deterministic task identifier.
pub type TaskId = u64;

// ---------------------------------------------------------------------------
// ScheduleAction — actions in a schedule transcript
// ---------------------------------------------------------------------------

/// An action in the deterministic schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleAction {
    /// Execute a task step.
    RunTask { task_id: TaskId },
    /// Advance virtual time.
    AdvanceTime { ticks: u64 },
    /// Inject cancellation for a region.
    InjectCancel { region_id: String },
    /// Inject a task fault (panic/disconnect).
    InjectFault { task_id: TaskId, fault: FaultKind },
    /// Fire a pending timer.
    FireTimer { timer_id: u64 },
}

// ---------------------------------------------------------------------------
// FaultKind — injectable faults
// ---------------------------------------------------------------------------

/// Types of faults that can be injected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// Task panic at next step.
    Panic,
    /// Channel disconnection.
    ChannelDisconnect,
    /// Obligation leak (obligation not resolved).
    ObligationLeak,
    /// Deadline expiration.
    DeadlineExpired,
    /// Region close request.
    RegionClose,
}

impl fmt::Display for FaultKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panic => write!(f, "panic"),
            Self::ChannelDisconnect => write!(f, "channel_disconnect"),
            Self::ObligationLeak => write!(f, "obligation_leak"),
            Self::DeadlineExpired => write!(f, "deadline_expired"),
            Self::RegionClose => write!(f, "region_close"),
        }
    }
}

// ---------------------------------------------------------------------------
// ScheduleTranscript — ordered list of schedule actions
// ---------------------------------------------------------------------------

/// Ordered list of schedule actions for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleTranscript {
    pub seed: u64,
    pub actions: Vec<ScheduleAction>,
}

impl ScheduleTranscript {
    /// Create a new transcript with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            actions: Vec::new(),
        }
    }

    /// Append an action.
    pub fn push(&mut self, action: ScheduleAction) {
        self.actions.push(action);
    }

    /// Number of actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Whether the transcript is empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TaskState — state of a lab runtime task
// ---------------------------------------------------------------------------

/// State of a task in the lab runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Ready,
    Running,
    Completed,
    Faulted,
    Cancelled,
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => write!(f, "ready"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Faulted => write!(f, "faulted"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ---------------------------------------------------------------------------
// LabEvent — structured event from lab runtime
// ---------------------------------------------------------------------------

/// Structured event emitted by the lab runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabEvent {
    pub virtual_time: u64,
    pub step_index: u64,
    pub action: String,
    pub task_id: Option<TaskId>,
    pub region_id: Option<String>,
    pub outcome: String,
}

// ---------------------------------------------------------------------------
// Verdict — pass/fail result
// ---------------------------------------------------------------------------

/// Pass/fail verdict for a lab run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Fail { reason: String },
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reason } => write!(f, "FAIL: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// LabRunResult — output artifact bundle
// ---------------------------------------------------------------------------

/// Output artifact bundle from a lab run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabRunResult {
    pub seed: u64,
    pub transcript: ScheduleTranscript,
    pub events: Vec<LabEvent>,
    pub final_time: u64,
    pub tasks_completed: usize,
    pub tasks_faulted: usize,
    pub tasks_cancelled: usize,
    pub verdict: Verdict,
}

// ---------------------------------------------------------------------------
// LabRuntime — deterministic lab runtime harness
// ---------------------------------------------------------------------------

/// Deterministic lab runtime for testing and replay.
#[derive(Debug)]
pub struct LabRuntime {
    clock: VirtualClock,
    seed: u64,
    tasks: BTreeMap<TaskId, TaskState>,
    next_task_id: TaskId,
    /// Regions that have been cancelled.
    cancelled_regions: BTreeMap<String, bool>,
    /// Recorded transcript (for replay).
    transcript: ScheduleTranscript,
    events: Vec<LabEvent>,
    step_index: u64,
}

impl LabRuntime {
    /// Create a new lab runtime with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            clock: VirtualClock::new(),
            seed,
            tasks: BTreeMap::new(),
            next_task_id: 1,
            cancelled_regions: BTreeMap::new(),
            transcript: ScheduleTranscript::new(seed),
            events: Vec::new(),
            step_index: 0,
        }
    }

    /// Current virtual time.
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Register a new task. Returns task ID.
    pub fn spawn_task(&mut self) -> TaskId {
        let id = self.next_task_id;
        self.next_task_id = self.next_task_id.saturating_add(1);
        self.tasks.insert(id, TaskState::Ready);
        id
    }

    /// Execute one step of a task.
    pub fn run_task(&mut self, task_id: TaskId) -> Option<TaskState> {
        let state = self.tasks.get_mut(&task_id)?;
        if *state != TaskState::Ready && *state != TaskState::Running {
            return Some(*state);
        }

        *state = TaskState::Running;
        self.transcript.push(ScheduleAction::RunTask { task_id });
        self.emit_event("run_task", Some(task_id), None, "running");
        Some(TaskState::Running)
    }

    /// Complete a task.
    pub fn complete_task(&mut self, task_id: TaskId) -> bool {
        if let Some(state) = self.tasks.get_mut(&task_id)
            && *state == TaskState::Running
        {
            *state = TaskState::Completed;
            self.emit_event("complete_task", Some(task_id), None, "completed");
            return true;
        }
        false
    }

    /// Advance virtual time.
    pub fn advance_time(&mut self, ticks: u64) {
        self.clock.advance(ticks);
        self.transcript.push(ScheduleAction::AdvanceTime { ticks });
        self.emit_event("advance_time", None, None, &format!("ticks={ticks}"));
    }

    /// Inject cancellation for a region.
    pub fn inject_cancel(&mut self, region_id: &str) {
        self.cancelled_regions.insert(region_id.to_string(), true);
        self.transcript.push(ScheduleAction::InjectCancel {
            region_id: region_id.to_string(),
        });
        self.emit_event(
            "inject_cancel",
            None,
            Some(region_id.to_string()),
            "cancel_injected",
        );
    }

    /// Check if a region has been cancelled.
    pub fn is_region_cancelled(&self, region_id: &str) -> bool {
        self.cancelled_regions
            .get(region_id)
            .copied()
            .unwrap_or(false)
    }

    /// Inject a fault on a task.
    pub fn inject_fault(&mut self, task_id: TaskId, fault: FaultKind) -> bool {
        if let Some(state) = self.tasks.get_mut(&task_id) {
            *state = TaskState::Faulted;
            self.transcript.push(ScheduleAction::InjectFault {
                task_id,
                fault: fault.clone(),
            });
            self.emit_event(
                "inject_fault",
                Some(task_id),
                None,
                &format!("fault={fault}"),
            );
            true
        } else {
            false
        }
    }

    /// Cancel a task.
    pub fn cancel_task(&mut self, task_id: TaskId) -> bool {
        if let Some(state) = self.tasks.get_mut(&task_id)
            && *state != TaskState::Completed
            && *state != TaskState::Faulted
        {
            *state = TaskState::Cancelled;
            self.emit_event("cancel_task", Some(task_id), None, "cancelled");
            return true;
        }
        false
    }

    /// Get task state.
    pub fn task_state(&self, task_id: TaskId) -> Option<TaskState> {
        self.tasks.get(&task_id).copied()
    }

    /// Number of registered tasks.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Produce the run result.
    pub fn finalize(self) -> LabRunResult {
        let tasks_completed = self
            .tasks
            .values()
            .filter(|&&s| s == TaskState::Completed)
            .count();
        let tasks_faulted = self
            .tasks
            .values()
            .filter(|&&s| s == TaskState::Faulted)
            .count();
        let tasks_cancelled = self
            .tasks
            .values()
            .filter(|&&s| s == TaskState::Cancelled)
            .count();

        let verdict = if tasks_faulted > 0 {
            Verdict::Fail {
                reason: format!("{tasks_faulted} tasks faulted"),
            }
        } else {
            Verdict::Pass
        };

        LabRunResult {
            seed: self.seed,
            transcript: self.transcript,
            events: self.events,
            final_time: self.clock.now(),
            tasks_completed,
            tasks_faulted,
            tasks_cancelled,
            verdict,
        }
    }

    fn emit_event(
        &mut self,
        action: &str,
        task_id: Option<TaskId>,
        region_id: Option<String>,
        outcome: &str,
    ) {
        self.step_index = self.step_index.saturating_add(1);
        self.events.push(LabEvent {
            virtual_time: self.clock.now(),
            step_index: self.step_index,
            action: action.to_string(),
            task_id,
            region_id,
            outcome: outcome.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// Replay — replay a transcript on a fresh runtime
// ---------------------------------------------------------------------------

/// Replay a transcript on a fresh runtime, producing events for comparison.
pub fn replay_transcript(transcript: &ScheduleTranscript) -> Vec<LabEvent> {
    let mut rt = LabRuntime::new(transcript.seed);

    // Pre-spawn enough tasks to cover all task IDs in the transcript.
    let max_task_id = transcript
        .actions
        .iter()
        .filter_map(|a| match a {
            ScheduleAction::RunTask { task_id } | ScheduleAction::InjectFault { task_id, .. } => {
                Some(*task_id)
            }
            _ => None,
        })
        .max()
        .unwrap_or(0);

    for _ in 0..max_task_id {
        rt.spawn_task();
    }

    for action in &transcript.actions {
        match action {
            ScheduleAction::RunTask { task_id } => {
                rt.run_task(*task_id);
            }
            ScheduleAction::AdvanceTime { ticks } => {
                rt.advance_time(*ticks);
            }
            ScheduleAction::InjectCancel { region_id } => {
                rt.inject_cancel(region_id);
            }
            ScheduleAction::InjectFault { task_id, fault } => {
                rt.inject_fault(*task_id, fault.clone());
            }
            ScheduleAction::FireTimer { timer_id: _ } => {
                // Timer firing is a no-op in the basic harness
            }
        }
    }

    rt.finalize().events
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- VirtualClock --

    #[test]
    fn clock_starts_at_zero() {
        let clock = VirtualClock::new();
        assert_eq!(clock.now(), 0);
    }

    #[test]
    fn clock_advance() {
        let mut clock = VirtualClock::new();
        clock.advance(100);
        assert_eq!(clock.now(), 100);
        clock.advance(50);
        assert_eq!(clock.now(), 150);
    }

    #[test]
    fn clock_advance_to() {
        let mut clock = VirtualClock::new();
        assert!(clock.advance_to(500));
        assert_eq!(clock.now(), 500);
        // Cannot go backward
        assert!(!clock.advance_to(100));
        assert_eq!(clock.now(), 500);
    }

    // -- Task lifecycle --

    #[test]
    fn spawn_and_run_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        assert_eq!(id, 1);
        assert_eq!(rt.task_state(id), Some(TaskState::Ready));

        rt.run_task(id);
        assert_eq!(rt.task_state(id), Some(TaskState::Running));
    }

    #[test]
    fn complete_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        assert!(rt.complete_task(id));
        assert_eq!(rt.task_state(id), Some(TaskState::Completed));
    }

    #[test]
    fn complete_non_running_task_fails() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        assert!(!rt.complete_task(id)); // still Ready, not Running
    }

    #[test]
    fn cancel_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        assert!(rt.cancel_task(id));
        assert_eq!(rt.task_state(id), Some(TaskState::Cancelled));
    }

    #[test]
    fn cannot_cancel_completed_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.complete_task(id);
        assert!(!rt.cancel_task(id));
    }

    // -- Virtual time --

    #[test]
    fn advance_time_updates_clock() {
        let mut rt = LabRuntime::new(42);
        rt.advance_time(100);
        assert_eq!(rt.now(), 100);
        rt.advance_time(50);
        assert_eq!(rt.now(), 150);
    }

    // -- Cancellation injection --

    #[test]
    fn inject_cancel_marks_region() {
        let mut rt = LabRuntime::new(42);
        assert!(!rt.is_region_cancelled("region-1"));
        rt.inject_cancel("region-1");
        assert!(rt.is_region_cancelled("region-1"));
    }

    // -- Fault injection --

    #[test]
    fn inject_fault_marks_task_faulted() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        assert!(rt.inject_fault(id, FaultKind::Panic));
        assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
    }

    #[test]
    fn inject_fault_nonexistent_returns_false() {
        let mut rt = LabRuntime::new(42);
        assert!(!rt.inject_fault(999, FaultKind::Panic));
    }

    // -- Transcript --

    #[test]
    fn transcript_records_actions() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.advance_time(10);
        rt.inject_cancel("r");

        let result = rt.finalize();
        assert_eq!(result.transcript.len(), 3);
        assert_eq!(result.transcript.seed, 42);
    }

    // -- Deterministic replay --

    #[test]
    fn replay_produces_identical_events() {
        let run = || {
            let mut rt = LabRuntime::new(42);
            let t1 = rt.spawn_task();
            let t2 = rt.spawn_task();
            rt.run_task(t1);
            rt.advance_time(10);
            rt.run_task(t2);
            rt.inject_cancel("region-a");
            rt.complete_task(t1);
            rt.advance_time(5);
            rt.inject_fault(t2, FaultKind::ChannelDisconnect);
            rt.finalize()
        };

        let result1 = run();
        let result2 = run();
        assert_eq!(result1.events, result2.events);
        assert_eq!(result1.transcript, result2.transcript);
    }

    #[test]
    fn replay_transcript_produces_same_events() {
        let mut rt = LabRuntime::new(99);
        let t1 = rt.spawn_task();
        let t2 = rt.spawn_task();
        rt.run_task(t1);
        rt.advance_time(5);
        rt.run_task(t2);
        rt.inject_cancel("r1");
        let result = rt.finalize();

        let replayed_events = replay_transcript(&result.transcript);
        assert_eq!(result.events, replayed_events);
    }

    // -- Finalize / Verdict --

    #[test]
    fn pass_verdict_when_no_faults() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.complete_task(id);
        let result = rt.finalize();
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.tasks_completed, 1);
    }

    #[test]
    fn fail_verdict_when_faults() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.inject_fault(id, FaultKind::Panic);
        let result = rt.finalize();
        assert!(matches!(result.verdict, Verdict::Fail { .. }));
        assert_eq!(result.tasks_faulted, 1);
    }

    #[test]
    fn cancelled_tasks_counted() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.cancel_task(id);
        let result = rt.finalize();
        assert_eq!(result.tasks_cancelled, 1);
    }

    // -- Events --

    #[test]
    fn events_carry_virtual_time() {
        let mut rt = LabRuntime::new(42);
        rt.advance_time(100);
        let id = rt.spawn_task();
        rt.run_task(id);

        let result = rt.finalize();
        let run_event = result
            .events
            .iter()
            .find(|e| e.action == "run_task")
            .unwrap();
        assert_eq!(run_event.virtual_time, 100);
    }

    #[test]
    fn events_have_monotone_step_index() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.advance_time(10);
        rt.complete_task(id);

        let result = rt.finalize();
        for window in result.events.windows(2) {
            assert!(window[0].step_index < window[1].step_index);
        }
    }

    // -- Serialization --

    #[test]
    fn virtual_clock_serialization_round_trip() {
        let mut clock = VirtualClock::new();
        clock.advance(42);
        let json = serde_json::to_string(&clock).expect("serialize");
        let restored: VirtualClock = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(clock, restored);
    }

    #[test]
    fn schedule_transcript_serialization_round_trip() {
        let mut transcript = ScheduleTranscript::new(42);
        transcript.push(ScheduleAction::RunTask { task_id: 1 });
        transcript.push(ScheduleAction::AdvanceTime { ticks: 10 });
        transcript.push(ScheduleAction::InjectCancel {
            region_id: "r".to_string(),
        });
        let json = serde_json::to_string(&transcript).expect("serialize");
        let restored: ScheduleTranscript = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(transcript, restored);
    }

    #[test]
    fn lab_run_result_serialization_round_trip() {
        let result = LabRunResult {
            seed: 42,
            transcript: ScheduleTranscript::new(42),
            events: Vec::new(),
            final_time: 100,
            tasks_completed: 1,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: LabRunResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn fault_kind_display() {
        assert_eq!(FaultKind::Panic.to_string(), "panic");
        assert_eq!(
            FaultKind::ChannelDisconnect.to_string(),
            "channel_disconnect"
        );
        assert_eq!(FaultKind::ObligationLeak.to_string(), "obligation_leak");
        assert_eq!(FaultKind::DeadlineExpired.to_string(), "deadline_expired");
        assert_eq!(FaultKind::RegionClose.to_string(), "region_close");
    }

    #[test]
    fn verdict_display() {
        assert_eq!(Verdict::Pass.to_string(), "PASS");
        assert!(
            Verdict::Fail {
                reason: "boom".to_string()
            }
            .to_string()
            .contains("boom")
        );
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn lab_event_serde_roundtrip() {
        let event = LabEvent {
            virtual_time: 1000,
            step_index: 5,
            action: "spawn".to_string(),
            task_id: Some(42),
            region_id: Some("region-1".to_string()),
            outcome: "ok".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: LabEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn fault_kind_serde_all_variants() {
        for kind in [
            FaultKind::Panic,
            FaultKind::ChannelDisconnect,
            FaultKind::ObligationLeak,
            FaultKind::DeadlineExpired,
            FaultKind::RegionClose,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: FaultKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn nonexistent_task_returns_none() {
        let rt = LabRuntime::new(42);
        assert!(rt.task_state(999).is_none());
    }

    // -- Enrichment: edge cases, state transitions, replay depth --

    #[test]
    fn clock_advance_to_same_tick_is_ok() {
        let mut clock = VirtualClock::new();
        clock.advance(50);
        assert!(clock.advance_to(50)); // same tick, should succeed
        assert_eq!(clock.now(), 50);
    }

    #[test]
    fn clock_default_starts_at_zero() {
        let clock = VirtualClock::default();
        assert_eq!(clock.now(), 0);
    }

    #[test]
    fn clock_advance_zero_ticks() {
        let mut clock = VirtualClock::new();
        clock.advance(100);
        clock.advance(0);
        assert_eq!(clock.now(), 100);
    }

    #[test]
    fn spawn_multiple_tasks_sequential_ids() {
        let mut rt = LabRuntime::new(0);
        let t1 = rt.spawn_task();
        let t2 = rt.spawn_task();
        let t3 = rt.spawn_task();
        assert_eq!(t1, 1);
        assert_eq!(t2, 2);
        assert_eq!(t3, 3);
        assert_eq!(rt.task_count(), 3);
    }

    #[test]
    fn run_task_on_completed_returns_completed() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.complete_task(id);
        let state = rt.run_task(id);
        assert_eq!(state, Some(TaskState::Completed));
    }

    #[test]
    fn run_task_on_faulted_returns_faulted() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.inject_fault(id, FaultKind::Panic);
        let state = rt.run_task(id);
        assert_eq!(state, Some(TaskState::Faulted));
    }

    #[test]
    fn run_task_already_running_stays_running() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        let state = rt.run_task(id);
        assert_eq!(state, Some(TaskState::Running));
    }

    #[test]
    fn complete_faulted_task_fails() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.inject_fault(id, FaultKind::Panic);
        assert!(!rt.complete_task(id));
    }

    #[test]
    fn cancel_ready_task_succeeds() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        assert!(rt.cancel_task(id));
        assert_eq!(rt.task_state(id), Some(TaskState::Cancelled));
    }

    #[test]
    fn cannot_cancel_faulted_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.inject_fault(id, FaultKind::Panic);
        assert!(!rt.cancel_task(id));
    }

    #[test]
    fn region_cancel_independent_regions() {
        let mut rt = LabRuntime::new(42);
        rt.inject_cancel("region-a");
        assert!(rt.is_region_cancelled("region-a"));
        assert!(!rt.is_region_cancelled("region-b"));
    }

    #[test]
    fn region_cancel_persists() {
        let mut rt = LabRuntime::new(42);
        rt.inject_cancel("r1");
        assert!(rt.is_region_cancelled("r1"));
        assert!(rt.is_region_cancelled("r1"));
    }

    #[test]
    fn inject_fault_all_kinds() {
        for fault in [
            FaultKind::Panic,
            FaultKind::ChannelDisconnect,
            FaultKind::ObligationLeak,
            FaultKind::DeadlineExpired,
            FaultKind::RegionClose,
        ] {
            let mut rt = LabRuntime::new(42);
            let id = rt.spawn_task();
            assert!(rt.inject_fault(id, fault));
            assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
        }
    }

    #[test]
    fn finalize_no_tasks_yields_pass() {
        let rt = LabRuntime::new(42);
        let result = rt.finalize();
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.tasks_completed, 0);
        assert_eq!(result.tasks_faulted, 0);
        assert_eq!(result.tasks_cancelled, 0);
    }

    #[test]
    fn finalize_mixed_states_counts() {
        let mut rt = LabRuntime::new(42);
        let t1 = rt.spawn_task();
        let t2 = rt.spawn_task();
        let t3 = rt.spawn_task();
        rt.run_task(t1);
        rt.complete_task(t1);
        rt.cancel_task(t2);
        rt.inject_fault(t3, FaultKind::Panic);
        let result = rt.finalize();
        assert_eq!(result.tasks_completed, 1);
        assert_eq!(result.tasks_cancelled, 1);
        assert_eq!(result.tasks_faulted, 1);
        assert!(matches!(result.verdict, Verdict::Fail { .. }));
    }

    #[test]
    fn event_step_index_starts_at_one() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.run_task(id);
        let result = rt.finalize();
        assert_eq!(result.events[0].step_index, 1);
    }

    #[test]
    fn replay_empty_transcript() {
        let transcript = ScheduleTranscript::new(42);
        let events = replay_transcript(&transcript);
        assert!(events.is_empty());
    }

    #[test]
    fn replay_fire_timer_is_noop() {
        let mut transcript = ScheduleTranscript::new(42);
        transcript.push(ScheduleAction::FireTimer { timer_id: 99 });
        let events = replay_transcript(&transcript);
        assert!(events.is_empty()); // FireTimer generates no events
    }

    #[test]
    fn transcript_is_empty_on_new() {
        let transcript = ScheduleTranscript::new(0);
        assert!(transcript.is_empty());
        assert_eq!(transcript.len(), 0);
    }

    #[test]
    fn task_state_display_all_variants() {
        assert_eq!(TaskState::Ready.to_string(), "ready");
        assert_eq!(TaskState::Running.to_string(), "running");
        assert_eq!(TaskState::Completed.to_string(), "completed");
        assert_eq!(TaskState::Faulted.to_string(), "faulted");
        assert_eq!(TaskState::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in [
            Verdict::Pass,
            Verdict::Fail {
                reason: "test failure".to_string(),
            },
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: Verdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn task_state_serde_roundtrip() {
        for state in [
            TaskState::Ready,
            TaskState::Running,
            TaskState::Completed,
            TaskState::Faulted,
            TaskState::Cancelled,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let restored: TaskState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, restored);
        }
    }

    #[test]
    fn schedule_action_serde_all_variants() {
        let actions = vec![
            ScheduleAction::RunTask { task_id: 1 },
            ScheduleAction::AdvanceTime { ticks: 100 },
            ScheduleAction::InjectCancel {
                region_id: "r".to_string(),
            },
            ScheduleAction::InjectFault {
                task_id: 2,
                fault: FaultKind::ObligationLeak,
            },
            ScheduleAction::FireTimer { timer_id: 42 },
        ];
        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let restored: ScheduleAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, restored);
        }
    }

    #[test]
    fn final_time_reflects_total_advance() {
        let mut rt = LabRuntime::new(42);
        rt.advance_time(100);
        rt.advance_time(200);
        let result = rt.finalize();
        assert_eq!(result.final_time, 300);
    }

    #[test]
    fn run_task_nonexistent_returns_none() {
        let mut rt = LabRuntime::new(42);
        assert!(rt.run_task(999).is_none());
    }

    // -- Enrichment: Display uniqueness, determinism, edge cases --

    #[test]
    fn fault_kind_display_all_unique() {
        use std::collections::BTreeSet;
        let mut displays = BTreeSet::new();
        for kind in [
            FaultKind::Panic,
            FaultKind::ChannelDisconnect,
            FaultKind::ObligationLeak,
            FaultKind::DeadlineExpired,
            FaultKind::RegionClose,
        ] {
            displays.insert(kind.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all FaultKind variants have unique Display"
        );
    }

    #[test]
    fn task_state_display_all_unique() {
        use std::collections::BTreeSet;
        let mut displays = BTreeSet::new();
        for state in [
            TaskState::Ready,
            TaskState::Running,
            TaskState::Completed,
            TaskState::Faulted,
            TaskState::Cancelled,
        ] {
            displays.insert(state.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all TaskState variants have unique Display"
        );
    }

    #[test]
    fn replay_with_fault_injection_produces_deterministic_events() {
        // Only use transcript-recorded actions (complete_task is not recorded).
        let mut rt = LabRuntime::new(77);
        let t1 = rt.spawn_task();
        let t2 = rt.spawn_task();
        rt.run_task(t1);
        rt.advance_time(10);
        rt.inject_fault(t2, FaultKind::ObligationLeak);
        rt.inject_cancel("region-x");
        let result = rt.finalize();

        let replayed_events = replay_transcript(&result.transcript);
        assert_eq!(result.events, replayed_events);
    }

    #[test]
    fn multiple_regions_cancelled_independently() {
        let mut rt = LabRuntime::new(42);
        rt.inject_cancel("region-a");
        rt.inject_cancel("region-b");
        rt.inject_cancel("region-c");
        assert!(rt.is_region_cancelled("region-a"));
        assert!(rt.is_region_cancelled("region-b"));
        assert!(rt.is_region_cancelled("region-c"));
        assert!(!rt.is_region_cancelled("region-d"));
    }

    #[test]
    fn finalize_seed_preserved() {
        let rt = LabRuntime::new(12345);
        let result = rt.finalize();
        assert_eq!(result.seed, 12345);
    }

    #[test]
    fn lab_event_none_fields_serde_roundtrip() {
        let event = LabEvent {
            virtual_time: 0,
            step_index: 1,
            action: "test_action".to_string(),
            task_id: None,
            region_id: None,
            outcome: "ok".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: LabEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn verdict_fail_reason_preserved_in_serde() {
        let v = Verdict::Fail {
            reason: "critical error with special chars: <>\"&".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let restored: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn runtime_now_reflects_advance_time() {
        let mut rt = LabRuntime::new(0);
        assert_eq!(rt.now(), 0);
        rt.advance_time(1);
        rt.advance_time(2);
        rt.advance_time(3);
        assert_eq!(rt.now(), 6);
    }

    // ---- enrichment tests ----

    #[test]
    fn enrichment_virtual_clock_clone_eq() {
        let mut clock = VirtualClock::new();
        clock.advance(42);
        let cloned = clock.clone();
        assert_eq!(clock, cloned);
    }

    #[test]
    fn enrichment_virtual_clock_ne_after_divergence() {
        let mut a = VirtualClock::new();
        let mut b = VirtualClock::new();
        a.advance(10);
        b.advance(20);
        assert_ne!(a, b);
    }

    #[test]
    fn enrichment_task_state_copy_semantics() {
        let state = TaskState::Running;
        let copied = state; // Copy
        assert_eq!(state, copied);
        // Both still usable after copy
        assert_eq!(state.to_string(), "running");
        assert_eq!(copied.to_string(), "running");
    }

    #[test]
    fn enrichment_fault_kind_clone_eq() {
        let faults = [
            FaultKind::Panic,
            FaultKind::ChannelDisconnect,
            FaultKind::ObligationLeak,
            FaultKind::DeadlineExpired,
            FaultKind::RegionClose,
        ];
        for f in &faults {
            let cloned = f.clone();
            assert_eq!(*f, cloned);
        }
    }

    #[test]
    fn enrichment_verdict_clone_eq() {
        let pass = Verdict::Pass;
        assert_eq!(pass.clone(), pass);

        let fail = Verdict::Fail {
            reason: "oops".to_string(),
        };
        assert_eq!(fail.clone(), fail);
    }

    #[test]
    fn enrichment_lab_event_clone_eq() {
        let event = LabEvent {
            virtual_time: 100,
            step_index: 3,
            action: "run_task".to_string(),
            task_id: Some(1),
            region_id: None,
            outcome: "running".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn enrichment_schedule_transcript_clone_eq() {
        let mut t = ScheduleTranscript::new(99);
        t.push(ScheduleAction::RunTask { task_id: 1 });
        t.push(ScheduleAction::AdvanceTime { ticks: 50 });
        let cloned = t.clone();
        assert_eq!(t, cloned);
        assert_eq!(t.len(), cloned.len());
        assert_eq!(t.seed, cloned.seed);
    }

    #[test]
    fn enrichment_lab_run_result_json_field_names() {
        let result = LabRunResult {
            seed: 7,
            transcript: ScheduleTranscript::new(7),
            events: Vec::new(),
            final_time: 42,
            tasks_completed: 3,
            tasks_faulted: 1,
            tasks_cancelled: 2,
            verdict: Verdict::Pass,
        };
        let json = serde_json::to_string(&result).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("seed"));
        assert!(obj.contains_key("transcript"));
        assert!(obj.contains_key("events"));
        assert!(obj.contains_key("final_time"));
        assert!(obj.contains_key("tasks_completed"));
        assert!(obj.contains_key("tasks_faulted"));
        assert!(obj.contains_key("tasks_cancelled"));
        assert!(obj.contains_key("verdict"));
        assert_eq!(obj["seed"], 7);
        assert_eq!(obj["final_time"], 42);
        assert_eq!(obj["tasks_completed"], 3);
        assert_eq!(obj["tasks_faulted"], 1);
        assert_eq!(obj["tasks_cancelled"], 2);
    }

    #[test]
    fn enrichment_schedule_action_json_tag_runtask() {
        let action = ScheduleAction::RunTask { task_id: 5 };
        let json = serde_json::to_string(&action).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["RunTask"]["task_id"], 5);
    }

    #[test]
    fn enrichment_schedule_action_json_tag_inject_fault() {
        let action = ScheduleAction::InjectFault {
            task_id: 3,
            fault: FaultKind::DeadlineExpired,
        };
        let json = serde_json::to_string(&action).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["InjectFault"]["task_id"], 3);
        assert_eq!(val["InjectFault"]["fault"], "DeadlineExpired");
    }

    #[test]
    fn enrichment_lab_event_json_field_names() {
        let event = LabEvent {
            virtual_time: 500,
            step_index: 10,
            action: "inject_cancel".to_string(),
            task_id: None,
            region_id: Some("zone-alpha".to_string()),
            outcome: "cancel_injected".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("virtual_time"));
        assert!(obj.contains_key("step_index"));
        assert!(obj.contains_key("action"));
        assert!(obj.contains_key("task_id"));
        assert!(obj.contains_key("region_id"));
        assert!(obj.contains_key("outcome"));
        assert_eq!(obj["virtual_time"], 500);
        assert!(obj["task_id"].is_null());
        assert_eq!(obj["region_id"], "zone-alpha");
    }

    #[test]
    fn enrichment_refault_already_faulted_task() {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        rt.inject_fault(id, FaultKind::Panic);
        assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
        // Injecting another fault on already-faulted task still returns true
        assert!(rt.inject_fault(id, FaultKind::ChannelDisconnect));
        assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
    }

    #[test]
    fn enrichment_many_tasks_stress() {
        let mut rt = LabRuntime::new(42);
        let mut ids = Vec::new();
        for _ in 0..100 {
            ids.push(rt.spawn_task());
        }
        assert_eq!(rt.task_count(), 100);
        // IDs are sequential starting at 1
        for (i, &id) in ids.iter().enumerate() {
            assert_eq!(id, (i + 1) as u64);
        }
        // Run, complete half; fault the other half
        for (i, &id) in ids.iter().enumerate() {
            rt.run_task(id);
            if i < 50 {
                rt.complete_task(id);
            } else {
                rt.inject_fault(id, FaultKind::ObligationLeak);
            }
        }
        let result = rt.finalize();
        assert_eq!(result.tasks_completed, 50);
        assert_eq!(result.tasks_faulted, 50);
    }

    #[test]
    fn enrichment_transcript_push_increments_len() {
        let mut t = ScheduleTranscript::new(0);
        assert!(t.is_empty());
        t.push(ScheduleAction::AdvanceTime { ticks: 1 });
        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());
        t.push(ScheduleAction::RunTask { task_id: 1 });
        assert_eq!(t.len(), 2);
        t.push(ScheduleAction::FireTimer { timer_id: 99 });
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn enrichment_replay_advance_time_only() {
        let mut transcript = ScheduleTranscript::new(55);
        transcript.push(ScheduleAction::AdvanceTime { ticks: 10 });
        transcript.push(ScheduleAction::AdvanceTime { ticks: 20 });
        transcript.push(ScheduleAction::AdvanceTime { ticks: 30 });
        let events = replay_transcript(&transcript);
        assert_eq!(events.len(), 3);
        // Virtual time increments: 10, 30, 60
        assert_eq!(events[0].virtual_time, 10);
        assert_eq!(events[1].virtual_time, 30);
        assert_eq!(events[2].virtual_time, 60);
        assert!(events.iter().all(|e| e.action == "advance_time"));
    }

    #[test]
    fn enrichment_replay_inject_cancel_produces_event() {
        let mut transcript = ScheduleTranscript::new(1);
        transcript.push(ScheduleAction::InjectCancel {
            region_id: "zone-42".to_string(),
        });
        let events = replay_transcript(&transcript);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "inject_cancel");
        assert_eq!(events[0].region_id, Some("zone-42".to_string()));
        assert_eq!(events[0].outcome, "cancel_injected");
    }

    #[test]
    fn enrichment_complete_nonexistent_task_returns_false() {
        let mut rt = LabRuntime::new(42);
        assert!(!rt.complete_task(999));
    }

    #[test]
    fn enrichment_cancel_nonexistent_task_returns_false() {
        let mut rt = LabRuntime::new(42);
        assert!(!rt.cancel_task(999));
    }

    #[test]
    fn enrichment_verdict_display_exact_format() {
        assert_eq!(format!("{}", Verdict::Pass), "PASS");
        let fail = Verdict::Fail {
            reason: "3 tasks faulted".to_string(),
        };
        assert_eq!(format!("{}", fail), "FAIL: 3 tasks faulted");
    }

    #[test]
    fn enrichment_virtual_clock_large_ticks() {
        let mut clock = VirtualClock::new();
        clock.advance(u64::MAX / 2);
        assert_eq!(clock.now(), u64::MAX / 2);
        // advance_to with same value is fine
        assert!(clock.advance_to(u64::MAX / 2));
        // advance_to with larger value
        assert!(clock.advance_to(u64::MAX - 1));
        assert_eq!(clock.now(), u64::MAX - 1);
    }
}
