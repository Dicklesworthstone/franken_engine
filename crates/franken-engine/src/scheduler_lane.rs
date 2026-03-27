//! Scheduler lanes for prioritized task scheduling with task-type
//! labeling and lane-aware observability.
//!
//! Three lanes model priority scheduling guarantees:
//! - `Cancel`: highest priority — cancellation cleanup, quarantine, drains.
//! - `Timed`: medium priority — deadline-sensitive (lease renewals, probes).
//! - `Ready`: normal priority — general work (extension dispatch, GC, sync).
//!
//! Cancel tasks are always scheduled first. Timed tasks with imminent
//! deadlines are promoted ahead of ready tasks. Ready tasks are FIFO
//! within priority sub-bands. Anti-starvation ensures ready tasks make
//! progress even under cancel/timed pressure.
//!
//! Plan references: Section 10.11 item 25, 9G.8 (scheduler lane model),
//! Top-10 #4 (performance discipline), #8 (per-extension resource budget).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SchedulerLane — the three priority lanes
// ---------------------------------------------------------------------------

/// Priority lanes for task scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SchedulerLane {
    /// Highest priority: cancellation cleanup, quarantine, obligation drain.
    Cancel,
    /// Medium priority: deadline-sensitive (lease renewal, monitoring probes).
    Timed,
    /// Normal priority: general work (extension dispatch, GC, sync).
    Ready,
}

impl fmt::Display for SchedulerLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancel => f.write_str("cancel"),
            Self::Timed => f.write_str("timed"),
            Self::Ready => f.write_str("ready"),
        }
    }
}

// ---------------------------------------------------------------------------
// TaskType — enumerated work classifications
// ---------------------------------------------------------------------------

/// Classification of work. Used for lane validation and observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TaskType {
    /// Cancellation cleanup (cancel lane).
    CancelCleanup,
    /// Quarantine execution (cancel lane).
    QuarantineExec,
    /// Forced drain (cancel lane).
    ForcedDrain,
    /// Lease renewal (timed lane).
    LeaseRenewal,
    /// Monitoring probe (timed lane).
    MonitoringProbe,
    /// Evidence flush (timed lane).
    EvidenceFlush,
    /// Epoch barrier timeout (timed lane).
    EpochBarrierTimeout,
    /// Extension dispatch (ready lane).
    ExtensionDispatch,
    /// GC cycle (ready lane).
    GcCycle,
    /// Policy iteration (ready lane).
    PolicyIteration,
    /// Remote sync (ready lane).
    RemoteSync,
    /// Saga step execution (ready lane).
    SagaStepExec,
}

impl TaskType {
    /// The required lane for this task type.
    pub fn required_lane(&self) -> SchedulerLane {
        match self {
            Self::CancelCleanup | Self::QuarantineExec | Self::ForcedDrain => SchedulerLane::Cancel,
            Self::LeaseRenewal
            | Self::MonitoringProbe
            | Self::EvidenceFlush
            | Self::EpochBarrierTimeout => SchedulerLane::Timed,
            Self::ExtensionDispatch
            | Self::GcCycle
            | Self::PolicyIteration
            | Self::RemoteSync
            | Self::SagaStepExec => SchedulerLane::Ready,
        }
    }
}

impl fmt::Display for TaskType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CancelCleanup => f.write_str("cancel_cleanup"),
            Self::QuarantineExec => f.write_str("quarantine_exec"),
            Self::ForcedDrain => f.write_str("forced_drain"),
            Self::LeaseRenewal => f.write_str("lease_renewal"),
            Self::MonitoringProbe => f.write_str("monitoring_probe"),
            Self::EvidenceFlush => f.write_str("evidence_flush"),
            Self::EpochBarrierTimeout => f.write_str("epoch_barrier_timeout"),
            Self::ExtensionDispatch => f.write_str("extension_dispatch"),
            Self::GcCycle => f.write_str("gc_cycle"),
            Self::PolicyIteration => f.write_str("policy_iteration"),
            Self::RemoteSync => f.write_str("remote_sync"),
            Self::SagaStepExec => f.write_str("saga_step_exec"),
        }
    }
}

// ---------------------------------------------------------------------------
// TaskLabel — required metadata for every scheduled task
// ---------------------------------------------------------------------------

/// Required metadata for every task submitted to the scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskLabel {
    /// Scheduler lane.
    pub lane: SchedulerLane,
    /// Task type classification.
    pub task_type: TaskType,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Optional fine-grained priority within the lane (lower = higher priority).
    pub priority_sub_band: u32,
}

// ---------------------------------------------------------------------------
// ScheduledTask — a task in the scheduler
// ---------------------------------------------------------------------------

/// Unique task ID assigned by the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TaskId(pub u64);

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task:{}", self.0)
    }
}

/// A task in the scheduler queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledTask {
    /// Unique task ID.
    pub task_id: TaskId,
    /// Task label with lane, type, trace, and priority.
    pub label: TaskLabel,
    /// Deadline tick (for timed-lane tasks; 0 means no deadline).
    pub deadline_tick: u64,
    /// Tick at which the task was submitted.
    pub submitted_at: u64,
    /// Opaque payload identifier.
    pub payload_id: String,
}

// ---------------------------------------------------------------------------
// LaneMetrics — per-lane observability
// ---------------------------------------------------------------------------

/// Per-lane scheduling metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneMetrics {
    /// Lane name.
    pub lane: String,
    /// Current queue depth.
    pub queue_depth: usize,
    /// Total tasks submitted.
    pub tasks_submitted: u64,
    /// Total tasks scheduled (dequeued for execution).
    pub tasks_scheduled: u64,
    /// Total tasks completed.
    pub tasks_completed: u64,
    /// Total tasks timed out.
    pub tasks_timed_out: u64,
}

// ---------------------------------------------------------------------------
// LaneConfig — configurable lane parameters
// ---------------------------------------------------------------------------

/// Configuration for scheduler lanes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneConfig {
    /// Maximum queue depth for the cancel lane.
    pub cancel_max_depth: usize,
    /// Maximum queue depth for the timed lane.
    pub timed_max_depth: usize,
    /// Maximum queue depth for the ready lane.
    pub ready_max_depth: usize,
    /// Minimum ready-lane tasks to schedule per scheduling round
    /// (anti-starvation guarantee).
    pub ready_min_throughput: usize,
}

impl Default for LaneConfig {
    fn default() -> Self {
        Self {
            cancel_max_depth: 256,
            timed_max_depth: 1024,
            ready_max_depth: 4096,
            ready_min_throughput: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// SchedulerEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for task scheduling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerEvent {
    /// Task ID.
    pub task_id: u64,
    /// Lane.
    pub lane: String,
    /// Task type.
    pub task_type: String,
    /// Trace ID.
    pub trace_id: String,
    /// Queue position at time of submission.
    pub queue_position: usize,
    /// Event type.
    pub event: String,
}

// ---------------------------------------------------------------------------
// LaneError — typed errors
// ---------------------------------------------------------------------------

/// Errors from scheduler operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LaneError {
    /// Task type does not match the declared lane.
    LaneMismatch {
        task_type: String,
        declared_lane: String,
        required_lane: String,
    },
    /// Lane queue is full.
    LaneFull { lane: String, max_depth: usize },
    /// Task not found.
    TaskNotFound { task_id: u64 },
    /// Empty trace ID.
    EmptyTraceId,
}

impl fmt::Display for LaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LaneMismatch {
                task_type,
                declared_lane,
                required_lane,
            } => {
                write!(
                    f,
                    "task type {task_type} requires lane {required_lane}, but declared {declared_lane}"
                )
            }
            Self::LaneFull { lane, max_depth } => {
                write!(f, "lane {lane} is full (max {max_depth})")
            }
            Self::TaskNotFound { task_id } => write!(f, "task {task_id} not found"),
            Self::EmptyTraceId => f.write_str("trace_id must be non-empty"),
        }
    }
}

impl std::error::Error for LaneError {}

// ---------------------------------------------------------------------------
// LaneScheduler — the scheduler
// ---------------------------------------------------------------------------

/// Prioritized multi-lane task scheduler.
///
/// Dequeue order: all cancel-lane tasks first, then timed-lane tasks
/// sorted by deadline, then ready-lane tasks FIFO. Anti-starvation
/// ensures at least `ready_min_throughput` ready tasks per round.
#[derive(Debug)]
pub struct LaneScheduler {
    config: LaneConfig,
    next_task_id: u64,
    /// Cancel lane queue.
    cancel_queue: VecDeque<ScheduledTask>,
    /// Timed lane queue (sorted by deadline on dequeue).
    timed_queue: VecDeque<ScheduledTask>,
    /// Ready lane queue (FIFO within sub-bands).
    ready_queue: VecDeque<ScheduledTask>,
    /// Per-lane metrics.
    metrics: BTreeMap<String, LaneMetrics>,
    /// Accumulated events.
    events: Vec<SchedulerEvent>,
    /// Event counters.
    event_counts: BTreeMap<String, u64>,
}

impl LaneScheduler {
    /// Create a new scheduler with the given configuration.
    pub fn new(config: LaneConfig) -> Self {
        let mut metrics = BTreeMap::new();
        for lane in &["cancel", "timed", "ready"] {
            metrics.insert(
                lane.to_string(),
                LaneMetrics {
                    lane: lane.to_string(),
                    ..Default::default()
                },
            );
        }

        Self {
            config,
            next_task_id: 1,
            cancel_queue: VecDeque::new(),
            timed_queue: VecDeque::new(),
            ready_queue: VecDeque::new(),
            metrics,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Submit a task to the scheduler.
    pub fn submit(
        &mut self,
        label: TaskLabel,
        deadline_tick: u64,
        payload_id: &str,
        current_ticks: u64,
    ) -> Result<TaskId, LaneError> {
        // Validate trace ID.
        if label.trace_id.is_empty() {
            return Err(LaneError::EmptyTraceId);
        }

        // Validate lane assignment.
        let required_lane = label.task_type.required_lane();
        if label.lane != required_lane {
            return Err(LaneError::LaneMismatch {
                task_type: label.task_type.to_string(),
                declared_lane: label.lane.to_string(),
                required_lane: required_lane.to_string(),
            });
        }

        // Check queue depth.
        let (queue_depth, max_depth) = match label.lane {
            SchedulerLane::Cancel => (self.cancel_queue.len(), self.config.cancel_max_depth),
            SchedulerLane::Timed => (self.timed_queue.len(), self.config.timed_max_depth),
            SchedulerLane::Ready => (self.ready_queue.len(), self.config.ready_max_depth),
        };
        if queue_depth >= max_depth {
            return Err(LaneError::LaneFull {
                lane: label.lane.to_string(),
                max_depth,
            });
        }

        let task_id = TaskId(self.next_task_id);
        self.next_task_id = self.next_task_id.saturating_add(1);

        let task = ScheduledTask {
            task_id,
            label: label.clone(),
            deadline_tick,
            submitted_at: current_ticks,
            payload_id: payload_id.to_string(),
        };

        let queue_pos = match label.lane {
            SchedulerLane::Cancel => {
                self.cancel_queue.push_back(task);
                self.cancel_queue.len() - 1
            }
            SchedulerLane::Timed => {
                self.timed_queue.push_back(task);
                self.timed_queue.len() - 1
            }
            SchedulerLane::Ready => {
                self.ready_queue.push_back(task);
                self.ready_queue.len() - 1
            }
        };

        // Update metrics.
        if let Some(m) = self.metrics.get_mut(&label.lane.to_string()) {
            m.tasks_submitted += 1;
            m.queue_depth = match label.lane {
                SchedulerLane::Cancel => self.cancel_queue.len(),
                SchedulerLane::Timed => self.timed_queue.len(),
                SchedulerLane::Ready => self.ready_queue.len(),
            };
        }

        self.emit_event(SchedulerEvent {
            task_id: task_id.0,
            lane: label.lane.to_string(),
            task_type: label.task_type.to_string(),
            trace_id: label.trace_id.clone(),
            queue_position: queue_pos,
            event: "submit".to_string(),
        });
        self.record_count("submit");

        Ok(task_id)
    }

    /// Schedule the next batch of tasks respecting lane priorities.
    ///
    /// Returns scheduled tasks in priority order:
    /// 1. All cancel-lane tasks.
    /// 2. Timed-lane tasks with deadline <= current_ticks (sorted by deadline).
    /// 3. Ready-lane tasks (FIFO), with anti-starvation guarantee.
    ///
    /// `batch_size` bounds cancel/timed pulls. When `batch_size > 0`, ready-lane
    /// anti-starvation may schedule additional ready tasks to ensure minimum
    /// throughput. A zero batch size schedules no tasks.
    pub fn schedule_batch(&mut self, batch_size: usize, current_ticks: u64) -> Vec<ScheduledTask> {
        let mut batch = Vec::with_capacity(batch_size);

        // 1. Cancel lane: take all available (up to batch size).
        while batch.len() < batch_size {
            if let Some(task) = self.cancel_queue.pop_front() {
                self.record_schedule(&task);
                batch.push(task);
            } else {
                break;
            }
        }

        // 2. Timed lane: tasks with deadline <= current_ticks (sorted by deadline).
        if batch.len() < batch_size {
            // Sort by deadline for fair scheduling.
            let mut timed_sorted: Vec<ScheduledTask> = self.timed_queue.drain(..).collect();
            timed_sorted.sort_by_key(|t| t.deadline_tick);

            let mut returned = VecDeque::new();
            for task in timed_sorted {
                if batch.len() < batch_size && task.deadline_tick <= current_ticks {
                    self.record_schedule(&task);
                    batch.push(task);
                } else {
                    returned.push_back(task);
                }
            }
            self.timed_queue = returned;
        }

        // 3. Ready lane: FIFO, with anti-starvation.
        let ready_slots = if batch_size == 0 {
            0
        } else if batch.len() < batch_size {
            let remaining = batch_size - batch.len();
            remaining.max(self.config.ready_min_throughput)
        } else {
            // Even at capacity, guarantee minimum throughput.
            self.config.ready_min_throughput
        };

        let ready_to_take = ready_slots.min(self.ready_queue.len());
        for _ in 0..ready_to_take {
            if let Some(task) = self.ready_queue.pop_front() {
                self.record_schedule(&task);
                batch.push(task);
            }
        }

        // Timeout expired timed tasks still in queue.
        let mut timed_expired = Vec::new();
        let mut remaining_timed = VecDeque::new();
        for task in self.timed_queue.drain(..) {
            if task.deadline_tick > 0 && task.deadline_tick < current_ticks {
                timed_expired.push(task);
            } else {
                remaining_timed.push_back(task);
            }
        }
        self.timed_queue = remaining_timed;

        for task in &timed_expired {
            if let Some(m) = self.metrics.get_mut("timed") {
                m.tasks_timed_out += 1;
            }
            self.emit_event(SchedulerEvent {
                task_id: task.task_id.0,
                lane: "timed".to_string(),
                task_type: task.label.task_type.to_string(),
                trace_id: task.label.trace_id.clone(),
                queue_position: 0,
                event: "timeout".to_string(),
            });
            self.record_count("timeout");
        }

        self.update_queue_depths();
        batch
    }

    /// Mark a task as completed.
    pub fn complete_task(&mut self, task_id: TaskId, lane: SchedulerLane) {
        if let Some(m) = self.metrics.get_mut(&lane.to_string()) {
            m.tasks_completed += 1;
        }
        self.emit_event(SchedulerEvent {
            task_id: task_id.0,
            lane: lane.to_string(),
            task_type: String::new(),
            trace_id: String::new(),
            queue_position: 0,
            event: "complete".to_string(),
        });
        self.record_count("complete");
    }

    /// Get current lane metrics.
    pub fn lane_metrics(&self) -> &BTreeMap<String, LaneMetrics> {
        &self.metrics
    }

    /// Queue depth for a specific lane.
    pub fn queue_depth(&self, lane: SchedulerLane) -> usize {
        match lane {
            SchedulerLane::Cancel => self.cancel_queue.len(),
            SchedulerLane::Timed => self.timed_queue.len(),
            SchedulerLane::Ready => self.ready_queue.len(),
        }
    }

    /// Total queue depth across all lanes.
    pub fn total_queue_depth(&self) -> usize {
        self.cancel_queue.len() + self.timed_queue.len() + self.ready_queue.len()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<SchedulerEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal --

    fn record_schedule(&mut self, task: &ScheduledTask) {
        if let Some(m) = self.metrics.get_mut(&task.label.lane.to_string()) {
            m.tasks_scheduled += 1;
        }
        self.emit_event(SchedulerEvent {
            task_id: task.task_id.0,
            lane: task.label.lane.to_string(),
            task_type: task.label.task_type.to_string(),
            trace_id: task.label.trace_id.clone(),
            queue_position: 0,
            event: "schedule".to_string(),
        });
        self.record_count("schedule");
    }

    fn update_queue_depths(&mut self) {
        if let Some(m) = self.metrics.get_mut("cancel") {
            m.queue_depth = self.cancel_queue.len();
        }
        if let Some(m) = self.metrics.get_mut("timed") {
            m.queue_depth = self.timed_queue.len();
        }
        if let Some(m) = self.metrics.get_mut("ready") {
            m.queue_depth = self.ready_queue.len();
        }
    }

    fn emit_event(&mut self, event: SchedulerEvent) {
        self.events.push(event);
    }

    fn record_count(&mut self, event_type: &str) {
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cancel_label(trace: &str) -> TaskLabel {
        TaskLabel {
            lane: SchedulerLane::Cancel,
            task_type: TaskType::CancelCleanup,
            trace_id: trace.to_string(),
            priority_sub_band: 0,
        }
    }

    fn timed_label(trace: &str) -> TaskLabel {
        TaskLabel {
            lane: SchedulerLane::Timed,
            task_type: TaskType::LeaseRenewal,
            trace_id: trace.to_string(),
            priority_sub_band: 0,
        }
    }

    fn ready_label(trace: &str) -> TaskLabel {
        TaskLabel {
            lane: SchedulerLane::Ready,
            task_type: TaskType::ExtensionDispatch,
            trace_id: trace.to_string(),
            priority_sub_band: 0,
        }
    }

    // -- SchedulerLane --

    #[test]
    fn lane_display() {
        assert_eq!(SchedulerLane::Cancel.to_string(), "cancel");
        assert_eq!(SchedulerLane::Timed.to_string(), "timed");
        assert_eq!(SchedulerLane::Ready.to_string(), "ready");
    }

    #[test]
    fn lane_ordering() {
        assert!(SchedulerLane::Cancel < SchedulerLane::Timed);
        assert!(SchedulerLane::Timed < SchedulerLane::Ready);
    }

    // -- TaskType --

    #[test]
    fn task_type_required_lanes() {
        assert_eq!(
            TaskType::CancelCleanup.required_lane(),
            SchedulerLane::Cancel
        );
        assert_eq!(
            TaskType::QuarantineExec.required_lane(),
            SchedulerLane::Cancel
        );
        assert_eq!(TaskType::ForcedDrain.required_lane(), SchedulerLane::Cancel);
        assert_eq!(TaskType::LeaseRenewal.required_lane(), SchedulerLane::Timed);
        assert_eq!(
            TaskType::MonitoringProbe.required_lane(),
            SchedulerLane::Timed
        );
        assert_eq!(
            TaskType::EvidenceFlush.required_lane(),
            SchedulerLane::Timed
        );
        assert_eq!(
            TaskType::EpochBarrierTimeout.required_lane(),
            SchedulerLane::Timed
        );
        assert_eq!(
            TaskType::ExtensionDispatch.required_lane(),
            SchedulerLane::Ready
        );
        assert_eq!(TaskType::GcCycle.required_lane(), SchedulerLane::Ready);
        assert_eq!(
            TaskType::PolicyIteration.required_lane(),
            SchedulerLane::Ready
        );
        assert_eq!(TaskType::RemoteSync.required_lane(), SchedulerLane::Ready);
        assert_eq!(TaskType::SagaStepExec.required_lane(), SchedulerLane::Ready);
    }

    #[test]
    fn task_type_display() {
        assert_eq!(TaskType::CancelCleanup.to_string(), "cancel_cleanup");
        assert_eq!(TaskType::LeaseRenewal.to_string(), "lease_renewal");
        assert_eq!(
            TaskType::ExtensionDispatch.to_string(),
            "extension_dispatch"
        );
    }

    // -- Submit tasks --

    #[test]
    fn submit_task() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let id = sched.submit(cancel_label("t1"), 0, "payload-1", 0).unwrap();
        assert_eq!(id.0, 1);
        assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 1);
    }

    #[test]
    fn submit_validates_lane_assignment() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        // CancelCleanup in Ready lane → error.
        let label = TaskLabel {
            lane: SchedulerLane::Ready,
            task_type: TaskType::CancelCleanup,
            trace_id: "t1".to_string(),
            priority_sub_band: 0,
        };
        assert!(matches!(
            sched.submit(label, 0, "p", 0),
            Err(LaneError::LaneMismatch { .. })
        ));
    }

    #[test]
    fn submit_rejects_empty_trace_id() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let label = TaskLabel {
            lane: SchedulerLane::Cancel,
            task_type: TaskType::CancelCleanup,
            trace_id: String::new(),
            priority_sub_band: 0,
        };
        assert!(matches!(
            sched.submit(label, 0, "p", 0),
            Err(LaneError::EmptyTraceId)
        ));
    }

    #[test]
    fn submit_rejects_full_lane() {
        let config = LaneConfig {
            cancel_max_depth: 2,
            ..Default::default()
        };
        let mut sched = LaneScheduler::new(config);
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
        assert!(matches!(
            sched.submit(cancel_label("t3"), 0, "p3", 0),
            Err(LaneError::LaneFull { .. })
        ));
    }

    // -- Schedule batch: lane priorities --

    #[test]
    fn cancel_tasks_scheduled_first() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(ready_label("t1"), 0, "ready-1", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "cancel-1", 0).unwrap();
        sched.submit(timed_label("t3"), 100, "timed-1", 0).unwrap();

        let batch = sched.schedule_batch(10, 200);
        // Cancel should be first.
        assert_eq!(batch[0].label.lane, SchedulerLane::Cancel);
    }

    #[test]
    fn timed_tasks_scheduled_before_ready_when_due() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(ready_label("t1"), 0, "ready-1", 0).unwrap();
        sched.submit(timed_label("t2"), 50, "timed-1", 0).unwrap();

        let batch = sched.schedule_batch(10, 100);
        // Timed task (deadline 50 <= current 100) should be before ready.
        let timed_pos = batch
            .iter()
            .position(|t| t.label.lane == SchedulerLane::Timed);
        let ready_pos = batch
            .iter()
            .position(|t| t.label.lane == SchedulerLane::Ready);
        assert!(timed_pos.unwrap() < ready_pos.unwrap());
    }

    #[test]
    fn timed_tasks_not_scheduled_if_not_due() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(timed_label("t1"), 500, "timed-1", 0).unwrap();
        sched.submit(ready_label("t2"), 0, "ready-1", 0).unwrap();

        let batch = sched.schedule_batch(10, 100);
        // Timed task has deadline 500 > current 100, so it stays queued.
        // Only ready task should be scheduled.
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].label.lane, SchedulerLane::Ready);
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 1);
    }

    // -- Anti-starvation --

    #[test]
    fn anti_starvation_guarantees_ready_progress() {
        let config = LaneConfig {
            ready_min_throughput: 2,
            ..Default::default()
        };
        let mut sched = LaneScheduler::new(config);

        // Fill cancel lane.
        for i in 0..5 {
            sched
                .submit(cancel_label(&format!("t{i}")), 0, &format!("c{i}"), 0)
                .unwrap();
        }
        // Add ready tasks.
        for i in 0..3 {
            sched
                .submit(ready_label(&format!("rt{i}")), 0, &format!("r{i}"), 0)
                .unwrap();
        }

        let batch = sched.schedule_batch(5, 0);
        // Should have 5 cancel + 2 ready (anti-starvation minimum).
        let ready_count = batch
            .iter()
            .filter(|t| t.label.lane == SchedulerLane::Ready)
            .count();
        assert!(ready_count >= 2);
    }

    #[test]
    fn zero_batch_size_schedules_no_tasks() {
        let config = LaneConfig {
            ready_min_throughput: 2,
            ..Default::default()
        };
        let mut sched = LaneScheduler::new(config);
        sched.submit(cancel_label("cancel-1"), 0, "c1", 0).unwrap();
        sched.submit(ready_label("ready-1"), 0, "r1", 0).unwrap();

        let batch = sched.schedule_batch(0, 0);
        assert!(batch.is_empty());
        assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 1);
        assert_eq!(sched.queue_depth(SchedulerLane::Ready), 1);
    }

    // -- Ready lane FIFO --

    #[test]
    fn ready_lane_fifo_ordering() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(ready_label("t1"), 0, "first", 0).unwrap();
        sched.submit(ready_label("t2"), 0, "second", 10).unwrap();
        sched.submit(ready_label("t3"), 0, "third", 20).unwrap();

        let batch = sched.schedule_batch(10, 30);
        assert_eq!(batch[0].payload_id, "first");
        assert_eq!(batch[1].payload_id, "second");
        assert_eq!(batch[2].payload_id, "third");
    }

    // -- Timed lane deadline sorting --

    #[test]
    fn timed_lane_sorts_by_deadline() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(timed_label("t1"), 300, "late", 0).unwrap();
        sched.submit(timed_label("t2"), 100, "early", 0).unwrap();
        sched.submit(timed_label("t3"), 200, "mid", 0).unwrap();

        let batch = sched.schedule_batch(10, 500);
        let timed: Vec<_> = batch
            .iter()
            .filter(|t| t.label.lane == SchedulerLane::Timed)
            .collect();
        assert_eq!(timed[0].payload_id, "early");
        assert_eq!(timed[1].payload_id, "mid");
        assert_eq!(timed[2].payload_id, "late");
    }

    // -- Metrics --

    #[test]
    fn metrics_track_submissions() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
        sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();

        let m = sched.lane_metrics();
        assert_eq!(m["cancel"].tasks_submitted, 2);
        assert_eq!(m["ready"].tasks_submitted, 1);
    }

    #[test]
    fn metrics_track_scheduling() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.submit(ready_label("t2"), 0, "p2", 0).unwrap();
        sched.schedule_batch(10, 0);

        let m = sched.lane_metrics();
        assert_eq!(m["cancel"].tasks_scheduled, 1);
        assert_eq!(m["ready"].tasks_scheduled, 1);
    }

    #[test]
    fn metrics_track_completion() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let id = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.schedule_batch(10, 0);
        sched.complete_task(id, SchedulerLane::Cancel);

        let m = sched.lane_metrics();
        assert_eq!(m["cancel"].tasks_completed, 1);
    }

    // -- Audit events --

    #[test]
    fn submit_emits_event() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();

        let events = sched.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "submit");
        assert_eq!(events[0].lane, "cancel");
        assert_eq!(events[0].trace_id, "t1");
    }

    #[test]
    fn schedule_emits_events() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.drain_events();

        sched.schedule_batch(10, 0);
        let events = sched.drain_events();
        assert!(!events.is_empty());
        assert_eq!(events[0].event, "schedule");
    }

    #[test]
    fn event_counts_track() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.submit(ready_label("t2"), 0, "p2", 0).unwrap();
        sched.schedule_batch(10, 0);

        assert_eq!(sched.event_counts().get("submit"), Some(&2));
        assert_eq!(sched.event_counts().get("schedule"), Some(&2));
    }

    // -- Serialization round-trips --

    #[test]
    fn task_label_serialization_round_trip() {
        let label = cancel_label("trace-1");
        let json = serde_json::to_string(&label).expect("serialize");
        let restored: TaskLabel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(label, restored);
    }

    #[test]
    fn scheduled_task_serialization_round_trip() {
        let task = ScheduledTask {
            task_id: TaskId(1),
            label: timed_label("t1"),
            deadline_tick: 100,
            submitted_at: 0,
            payload_id: "p1".to_string(),
        };
        let json = serde_json::to_string(&task).expect("serialize");
        let restored: ScheduledTask = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(task, restored);
    }

    #[test]
    fn lane_metrics_serialization_round_trip() {
        let m = LaneMetrics {
            lane: "cancel".to_string(),
            queue_depth: 5,
            tasks_submitted: 10,
            tasks_scheduled: 8,
            tasks_completed: 7,
            tasks_timed_out: 1,
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let restored: LaneMetrics = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, restored);
    }

    #[test]
    fn lane_error_serialization_round_trip() {
        let errors = vec![
            LaneError::LaneMismatch {
                task_type: "cancel_cleanup".to_string(),
                declared_lane: "ready".to_string(),
                required_lane: "cancel".to_string(),
            },
            LaneError::LaneFull {
                lane: "cancel".to_string(),
                max_depth: 256,
            },
            LaneError::TaskNotFound { task_id: 42 },
            LaneError::EmptyTraceId,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: LaneError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn scheduler_event_serialization_round_trip() {
        let event = SchedulerEvent {
            task_id: 1,
            lane: "cancel".to_string(),
            task_type: "cancel_cleanup".to_string(),
            trace_id: "t1".to_string(),
            queue_position: 0,
            event: "submit".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: SchedulerEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert!(LaneError::EmptyTraceId.to_string().contains("non-empty"));
        assert!(
            LaneError::LaneFull {
                lane: "cancel".to_string(),
                max_depth: 256
            }
            .to_string()
            .contains("256")
        );
        assert!(
            LaneError::LaneMismatch {
                task_type: "x".to_string(),
                declared_lane: "y".to_string(),
                required_lane: "z".to_string(),
            }
            .to_string()
            .contains("requires lane z")
        );
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_scheduling_order() {
        let run = || -> Vec<String> {
            let mut sched = LaneScheduler::new(LaneConfig::default());
            sched.submit(ready_label("t1"), 0, "r1", 0).unwrap();
            sched.submit(cancel_label("t2"), 0, "c1", 0).unwrap();
            sched.submit(timed_label("t3"), 50, "ti1", 0).unwrap();
            sched.submit(ready_label("t4"), 0, "r2", 10).unwrap();
            let batch = sched.schedule_batch(10, 100);
            batch.iter().map(|t| t.payload_id.clone()).collect()
        };

        let order1 = run();
        let order2 = run();
        assert_eq!(order1, order2);
    }

    // -- Total queue depth --

    #[test]
    fn total_queue_depth() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.submit(timed_label("t2"), 100, "p2", 0).unwrap();
        sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();
        assert_eq!(sched.total_queue_depth(), 3);
    }

    // -- Multiple task types --

    #[test]
    fn multiple_cancel_task_types() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Cancel,
                    task_type: TaskType::CancelCleanup,
                    trace_id: "t1".to_string(),
                    priority_sub_band: 0,
                },
                0,
                "cleanup",
                0,
            )
            .unwrap();
        sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Cancel,
                    task_type: TaskType::QuarantineExec,
                    trace_id: "t2".to_string(),
                    priority_sub_band: 0,
                },
                0,
                "quarantine",
                0,
            )
            .unwrap();
        sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Cancel,
                    task_type: TaskType::ForcedDrain,
                    trace_id: "t3".to_string(),
                    priority_sub_band: 0,
                },
                0,
                "drain",
                0,
            )
            .unwrap();

        let batch = sched.schedule_batch(10, 0);
        assert_eq!(batch.len(), 3);
        assert!(batch.iter().all(|t| t.label.lane == SchedulerLane::Cancel));
    }

    // -- Enrichment: std::error --

    #[test]
    fn lane_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(LaneError::LaneMismatch {
                task_type: "gc".into(),
                declared_lane: "compute".into(),
                required_lane: "maintenance".into(),
            }),
            Box::new(LaneError::LaneFull {
                lane: "compute".into(),
                max_depth: 100,
            }),
            Box::new(LaneError::TaskNotFound { task_id: 42 }),
            Box::new(LaneError::EmptyTraceId),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 variants produce distinct messages"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: TaskType display completeness
    // -----------------------------------------------------------------------

    #[test]
    fn task_type_display_all_12_variants() {
        let displays: std::collections::BTreeSet<String> = [
            TaskType::CancelCleanup,
            TaskType::QuarantineExec,
            TaskType::ForcedDrain,
            TaskType::LeaseRenewal,
            TaskType::MonitoringProbe,
            TaskType::EvidenceFlush,
            TaskType::EpochBarrierTimeout,
            TaskType::ExtensionDispatch,
            TaskType::GcCycle,
            TaskType::PolicyIteration,
            TaskType::RemoteSync,
            TaskType::SagaStepExec,
        ]
        .iter()
        .map(|tt| tt.to_string())
        .collect();
        assert_eq!(displays.len(), 12, "all 12 TaskTypes have distinct display");
    }

    // -----------------------------------------------------------------------
    // Enrichment: TaskId display
    // -----------------------------------------------------------------------

    #[test]
    fn task_id_display() {
        assert_eq!(TaskId(42).to_string(), "task:42");
        assert_eq!(TaskId(0).to_string(), "task:0");
    }

    // -----------------------------------------------------------------------
    // Enrichment: LaneConfig defaults
    // -----------------------------------------------------------------------

    #[test]
    fn lane_config_defaults() {
        let cfg = LaneConfig::default();
        assert_eq!(cfg.cancel_max_depth, 256);
        assert_eq!(cfg.timed_max_depth, 1024);
        assert_eq!(cfg.ready_max_depth, 4096);
        assert_eq!(cfg.ready_min_throughput, 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Task ID monotonically increases
    // -----------------------------------------------------------------------

    #[test]
    fn task_ids_monotonically_increase() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let id1 = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        let id2 = sched.submit(ready_label("t2"), 0, "p2", 0).unwrap();
        let id3 = sched.submit(timed_label("t3"), 100, "p3", 0).unwrap();
        assert!(id1.0 < id2.0);
        assert!(id2.0 < id3.0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: schedule_batch from empty scheduler
    // -----------------------------------------------------------------------

    #[test]
    fn schedule_batch_empty_scheduler() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let batch = sched.schedule_batch(10, 0);
        assert!(batch.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: timed deadline exactly at current_ticks
    // -----------------------------------------------------------------------

    #[test]
    fn timed_task_at_exact_deadline_is_scheduled() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(timed_label("t1"), 100, "p1", 0).unwrap();

        // current_ticks == deadline_tick
        let batch = sched.schedule_batch(10, 100);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload_id, "p1");
    }

    // -----------------------------------------------------------------------
    // Enrichment: timed task timeout tracking
    // -----------------------------------------------------------------------

    #[test]
    fn expired_timed_tasks_are_timed_out() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(timed_label("t1"), 50, "early", 0).unwrap();
        sched.submit(timed_label("t2"), 200, "future", 0).unwrap();

        // Schedule at tick 100 with batch_size=0 → no tasks scheduled, but
        // t1 (deadline 50 < 100) should be timed out.
        // Actually batch_size=0 produces no tasks. Let's use batch_size=1
        // with current_ticks=100. t1 deadline=50 <= 100 → scheduled.
        // t2 deadline=200 > 100 → remains. Now advance further.
        let _ = sched.schedule_batch(1, 100);
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 1); // t2 remains

        // Now schedule at tick 300. t2 deadline=200 <= 300 → scheduled.
        let batch = sched.schedule_batch(10, 300);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload_id, "future");
    }

    #[test]
    fn timed_out_tasks_increment_metrics() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(timed_label("t1"), 10, "p1", 0).unwrap();

        // The task deadline is 10. Schedule batch at tick 20 with batch_size=1.
        // It should be scheduled (deadline 10 <= 20), not timed out.
        // To get timeout: submit at 10, schedule_batch at 20 with batch_size=1 to pick it up.
        // But what if we schedule at tick 5 (not due), then schedule at tick 20?
        // At tick 5: deadline 10 > 5, so not due. Stays in queue.
        // At tick 20: deadline 10 <= 20, so it's scheduled via the main timed path.
        // The timeout path only fires for tasks that were NOT scheduled but ARE past deadline.
        // Need: task1 deadline=10, task2 deadline=5, batch_size=1 at tick=20.
        // task2 (deadline 5) scheduled first, task1 (deadline 10) past deadline → timed out.
        let mut sched2 = LaneScheduler::new(LaneConfig::default());
        sched2.submit(timed_label("t1"), 10, "p1", 0).unwrap();
        sched2.submit(timed_label("t2"), 5, "p2", 0).unwrap();

        // batch_size=1, current=20. Both are due. Sort by deadline: t2(5), t1(10).
        // Take t2 (batch full). t1 stays but deadline 10 < 20 → timed out.
        let batch = sched2.schedule_batch(1, 20);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload_id, "p2");

        let m = sched2.lane_metrics();
        assert_eq!(m["timed"].tasks_timed_out, 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple timed task types
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_timed_task_types_in_single_batch() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Timed,
                    task_type: TaskType::LeaseRenewal,
                    trace_id: "t1".into(),
                    priority_sub_band: 0,
                },
                50,
                "lease",
                0,
            )
            .unwrap();
        sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Timed,
                    task_type: TaskType::MonitoringProbe,
                    trace_id: "t2".into(),
                    priority_sub_band: 0,
                },
                30,
                "probe",
                0,
            )
            .unwrap();
        sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Timed,
                    task_type: TaskType::EvidenceFlush,
                    trace_id: "t3".into(),
                    priority_sub_band: 0,
                },
                40,
                "flush",
                0,
            )
            .unwrap();
        sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Timed,
                    task_type: TaskType::EpochBarrierTimeout,
                    trace_id: "t4".into(),
                    priority_sub_band: 0,
                },
                20,
                "barrier",
                0,
            )
            .unwrap();

        let batch = sched.schedule_batch(10, 100);
        let timed: Vec<_> = batch
            .iter()
            .filter(|t| t.label.lane == SchedulerLane::Timed)
            .collect();
        assert_eq!(timed.len(), 4);
        // Sorted by deadline: barrier(20), probe(30), flush(40), lease(50).
        assert_eq!(timed[0].payload_id, "barrier");
        assert_eq!(timed[1].payload_id, "probe");
        assert_eq!(timed[2].payload_id, "flush");
        assert_eq!(timed[3].payload_id, "lease");
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple ready task types
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_ready_task_types() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let types = [
            TaskType::ExtensionDispatch,
            TaskType::GcCycle,
            TaskType::PolicyIteration,
            TaskType::RemoteSync,
            TaskType::SagaStepExec,
        ];
        for (i, tt) in types.iter().enumerate() {
            sched
                .submit(
                    TaskLabel {
                        lane: SchedulerLane::Ready,
                        task_type: *tt,
                        trace_id: format!("t{i}"),
                        priority_sub_band: 0,
                    },
                    0,
                    &format!("p{i}"),
                    i as u64,
                )
                .unwrap();
        }
        let batch = sched.schedule_batch(10, 100);
        assert_eq!(batch.len(), 5);
        // FIFO: p0, p1, p2, p3, p4.
        for (i, task) in batch.iter().enumerate() {
            assert_eq!(task.payload_id, format!("p{i}"));
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: SchedulerLane serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn scheduler_lane_serde_all_variants() {
        for lane in [
            SchedulerLane::Cancel,
            SchedulerLane::Timed,
            SchedulerLane::Ready,
        ] {
            let json = serde_json::to_string(&lane).unwrap();
            let back: SchedulerLane = serde_json::from_str(&json).unwrap();
            assert_eq!(lane, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: TaskType serde roundtrip all variants
    // -----------------------------------------------------------------------

    #[test]
    fn task_type_serde_all_variants() {
        let types = [
            TaskType::CancelCleanup,
            TaskType::QuarantineExec,
            TaskType::ForcedDrain,
            TaskType::LeaseRenewal,
            TaskType::MonitoringProbe,
            TaskType::EvidenceFlush,
            TaskType::EpochBarrierTimeout,
            TaskType::ExtensionDispatch,
            TaskType::GcCycle,
            TaskType::PolicyIteration,
            TaskType::RemoteSync,
            TaskType::SagaStepExec,
        ];
        for tt in &types {
            let json = serde_json::to_string(tt).unwrap();
            let back: TaskType = serde_json::from_str(&json).unwrap();
            assert_eq!(*tt, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: queue depths updated after scheduling
    // -----------------------------------------------------------------------

    #[test]
    fn queue_depths_updated_after_schedule() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "c1", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "c2", 0).unwrap();
        sched.submit(ready_label("t3"), 0, "r1", 0).unwrap();

        assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 2);
        assert_eq!(sched.queue_depth(SchedulerLane::Ready), 1);

        sched.schedule_batch(10, 0);

        assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 0);
        assert_eq!(sched.queue_depth(SchedulerLane::Ready), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: complete_task emits event
    // -----------------------------------------------------------------------

    #[test]
    fn complete_task_emits_complete_event() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let id = sched.submit(ready_label("t1"), 0, "p1", 0).unwrap();
        sched.schedule_batch(10, 0);
        sched.drain_events();

        sched.complete_task(id, SchedulerLane::Ready);
        let events = sched.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "complete");
    }

    // -----------------------------------------------------------------------
    // Enrichment: LaneConfig serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn lane_config_serde_roundtrip() {
        let cfg = LaneConfig {
            cancel_max_depth: 100,
            timed_max_depth: 200,
            ready_max_depth: 300,
            ready_min_throughput: 5,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: LaneConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: TaskNotFound display
    // -----------------------------------------------------------------------

    #[test]
    fn task_not_found_display() {
        let err = LaneError::TaskNotFound { task_id: 999 };
        assert!(err.to_string().contains("999"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: clone equality tests
    // -----------------------------------------------------------------------

    #[test]
    fn task_label_clone_equality() {
        let label = TaskLabel {
            lane: SchedulerLane::Timed,
            task_type: TaskType::MonitoringProbe,
            trace_id: "trace-clone-1".to_string(),
            priority_sub_band: 7,
        };
        let cloned = label.clone();
        assert_eq!(label, cloned);
    }

    #[test]
    fn scheduled_task_clone_equality() {
        let task = ScheduledTask {
            task_id: TaskId(99),
            label: ready_label("trace-clone-2"),
            deadline_tick: 500,
            submitted_at: 42,
            payload_id: "payload-clone".to_string(),
        };
        let cloned = task.clone();
        assert_eq!(task, cloned);
    }

    #[test]
    fn lane_metrics_clone_equality() {
        let m = LaneMetrics {
            lane: "timed".to_string(),
            queue_depth: 12,
            tasks_submitted: 50,
            tasks_scheduled: 40,
            tasks_completed: 35,
            tasks_timed_out: 3,
        };
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn scheduler_event_clone_equality() {
        let evt = SchedulerEvent {
            task_id: 7,
            lane: "ready".to_string(),
            task_type: "gc_cycle".to_string(),
            trace_id: "trace-clone-3".to_string(),
            queue_position: 2,
            event: "schedule".to_string(),
        };
        let cloned = evt.clone();
        assert_eq!(evt, cloned);
    }

    #[test]
    fn lane_config_clone_equality() {
        let cfg = LaneConfig {
            cancel_max_depth: 64,
            timed_max_depth: 128,
            ready_max_depth: 512,
            ready_min_throughput: 3,
        };
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }

    // -----------------------------------------------------------------------
    // Enrichment: JSON field presence tests
    // -----------------------------------------------------------------------

    #[test]
    fn task_label_json_field_presence() {
        let label = cancel_label("field-check");
        let json = serde_json::to_string(&label).unwrap();
        assert!(json.contains("\"lane\""));
        assert!(json.contains("\"task_type\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"priority_sub_band\""));
    }

    #[test]
    fn scheduled_task_json_field_presence() {
        let task = ScheduledTask {
            task_id: TaskId(5),
            label: timed_label("field-check-2"),
            deadline_tick: 200,
            submitted_at: 10,
            payload_id: "p-field".to_string(),
        };
        let json = serde_json::to_string(&task).unwrap();
        assert!(json.contains("\"task_id\""));
        assert!(json.contains("\"label\""));
        assert!(json.contains("\"deadline_tick\""));
        assert!(json.contains("\"submitted_at\""));
        assert!(json.contains("\"payload_id\""));
    }

    #[test]
    fn lane_metrics_json_field_presence() {
        let m = LaneMetrics {
            lane: "cancel".to_string(),
            queue_depth: 1,
            tasks_submitted: 2,
            tasks_scheduled: 3,
            tasks_completed: 4,
            tasks_timed_out: 5,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"lane\""));
        assert!(json.contains("\"queue_depth\""));
        assert!(json.contains("\"tasks_submitted\""));
        assert!(json.contains("\"tasks_scheduled\""));
        assert!(json.contains("\"tasks_completed\""));
        assert!(json.contains("\"tasks_timed_out\""));
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrip for LaneError variants
    // -----------------------------------------------------------------------

    #[test]
    fn lane_error_lane_full_serde_roundtrip() {
        let err = LaneError::LaneFull {
            lane: "ready".to_string(),
            max_depth: 4096,
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: LaneError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
        assert!(json.contains("4096"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness across SchedulerLane variants
    // -----------------------------------------------------------------------

    #[test]
    fn scheduler_lane_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            SchedulerLane::Cancel,
            SchedulerLane::Timed,
            SchedulerLane::Ready,
        ]
        .iter()
        .map(|l| l.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            3,
            "all 3 lanes produce distinct display strings"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: boundary condition — batch_size of 1
    // -----------------------------------------------------------------------

    #[test]
    fn batch_size_one_selects_highest_priority_only() {
        let mut sched = LaneScheduler::new(LaneConfig {
            ready_min_throughput: 0,
            ..Default::default()
        });
        sched.submit(ready_label("t1"), 0, "ready-1", 0).unwrap();
        sched.submit(timed_label("t2"), 10, "timed-1", 0).unwrap();
        sched.submit(cancel_label("t3"), 0, "cancel-1", 0).unwrap();

        let batch = sched.schedule_batch(1, 100);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].label.lane, SchedulerLane::Cancel);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Ord determinism for SchedulerLane
    // -----------------------------------------------------------------------

    #[test]
    fn scheduler_lane_ord_determinism() {
        let mut lanes = vec![
            SchedulerLane::Ready,
            SchedulerLane::Cancel,
            SchedulerLane::Timed,
        ];
        lanes.sort();
        assert_eq!(
            lanes,
            vec![
                SchedulerLane::Cancel,
                SchedulerLane::Timed,
                SchedulerLane::Ready
            ]
        );
        // Re-sort to confirm determinism.
        lanes.sort();
        assert_eq!(
            lanes,
            vec![
                SchedulerLane::Cancel,
                SchedulerLane::Timed,
                SchedulerLane::Ready
            ]
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: std::error::Error::source returns None
    // -----------------------------------------------------------------------

    #[test]
    fn lane_error_source_is_none() {
        use std::error::Error;
        let variants: Vec<LaneError> = vec![
            LaneError::LaneMismatch {
                task_type: "a".into(),
                declared_lane: "b".into(),
                required_lane: "c".into(),
            },
            LaneError::LaneFull {
                lane: "x".into(),
                max_depth: 1,
            },
            LaneError::TaskNotFound { task_id: 0 },
            LaneError::EmptyTraceId,
        ];
        for err in &variants {
            assert!(
                err.source().is_none(),
                "LaneError::source() should be None for all variants"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: LaneMetrics default values
    // -----------------------------------------------------------------------

    #[test]
    fn lane_metrics_default_zeroed() {
        let m = LaneMetrics::default();
        assert_eq!(m.lane, "");
        assert_eq!(m.queue_depth, 0);
        assert_eq!(m.tasks_submitted, 0);
        assert_eq!(m.tasks_scheduled, 0);
        assert_eq!(m.tasks_completed, 0);
        assert_eq!(m.tasks_timed_out, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: TaskId serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn task_id_serde_roundtrip() {
        for val in [0, 1, 42, u64::MAX] {
            let id = TaskId(val);
            let json = serde_json::to_string(&id).unwrap();
            let back: TaskId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, back);
        }
    }

    #[test]
    fn task_id_ordering() {
        assert!(TaskId(0) < TaskId(1));
        assert!(TaskId(1) < TaskId(u64::MAX));
        assert_eq!(TaskId(42), TaskId(42));

        let mut ids = vec![TaskId(100), TaskId(1), TaskId(50)];
        ids.sort();
        assert_eq!(ids, vec![TaskId(1), TaskId(50), TaskId(100)]);
    }

    #[test]
    fn task_id_hash_consistency() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(TaskId(1));
        set.insert(TaskId(2));
        set.insert(TaskId(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn task_id_display_max() {
        let id = TaskId(u64::MAX);
        assert_eq!(id.to_string(), format!("task:{}", u64::MAX));
    }

    // -----------------------------------------------------------------------
    // Enrichment: TaskType Ord follows enum declaration order
    // -----------------------------------------------------------------------

    #[test]
    fn task_type_ord_matches_enum_order() {
        let types = [
            TaskType::CancelCleanup,
            TaskType::QuarantineExec,
            TaskType::ForcedDrain,
            TaskType::LeaseRenewal,
            TaskType::MonitoringProbe,
            TaskType::EvidenceFlush,
            TaskType::EpochBarrierTimeout,
            TaskType::ExtensionDispatch,
            TaskType::GcCycle,
            TaskType::PolicyIteration,
            TaskType::RemoteSync,
            TaskType::SagaStepExec,
        ];
        for window in types.windows(2) {
            assert!(
                window[0] < window[1],
                "{:?} should be < {:?}",
                window[0],
                window[1]
            );
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: TaskLabel serde for timed and ready lanes
    // -----------------------------------------------------------------------

    #[test]
    fn task_label_serde_timed_lane() {
        let label = timed_label("trace-timed-serde");
        let json = serde_json::to_string(&label).unwrap();
        let back: TaskLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(label, back);
        assert!(json.contains("\"Timed\"") || json.contains("\"timed\""));
    }

    #[test]
    fn task_label_serde_ready_lane() {
        let label = ready_label("trace-ready-serde");
        let json = serde_json::to_string(&label).unwrap();
        let back: TaskLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(label, back);
    }

    #[test]
    fn task_label_with_nonzero_priority_sub_band() {
        let label = TaskLabel {
            lane: SchedulerLane::Ready,
            task_type: TaskType::GcCycle,
            trace_id: "priority-test".to_string(),
            priority_sub_band: 42,
        };
        let json = serde_json::to_string(&label).unwrap();
        let back: TaskLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(label, back);
        assert!(json.contains("42"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: cancel queue FIFO ordering
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_lane_fifo_ordering() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "first", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "second", 10).unwrap();
        sched.submit(cancel_label("t3"), 0, "third", 20).unwrap();

        let batch = sched.schedule_batch(10, 30);
        let cancel_tasks: Vec<_> = batch
            .iter()
            .filter(|t| t.label.lane == SchedulerLane::Cancel)
            .collect();
        assert_eq!(cancel_tasks[0].payload_id, "first");
        assert_eq!(cancel_tasks[1].payload_id, "second");
        assert_eq!(cancel_tasks[2].payload_id, "third");
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple schedule_batch rounds
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_schedule_batch_rounds_persist_state() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "c1", 0).unwrap();
        sched.submit(ready_label("t2"), 0, "r1", 0).unwrap();
        sched.submit(ready_label("t3"), 0, "r2", 0).unwrap();

        // Round 1: take batch_size=2 → cancel + ready
        let batch1 = sched.schedule_batch(2, 0);
        assert_eq!(batch1.len(), 2);
        assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 0);
        assert_eq!(sched.queue_depth(SchedulerLane::Ready), 1);

        // Round 2: remaining ready task
        let batch2 = sched.schedule_batch(10, 0);
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2[0].payload_id, "r2");
        assert_eq!(sched.total_queue_depth(), 0);
    }

    #[test]
    fn schedule_batch_metrics_accumulate_across_rounds() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "c1", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "c2", 0).unwrap();
        sched.submit(ready_label("t3"), 0, "r1", 0).unwrap();

        sched.schedule_batch(1, 0); // schedules 1 cancel
        sched.schedule_batch(1, 0); // schedules 1 cancel

        let m = sched.lane_metrics();
        assert_eq!(m["cancel"].tasks_scheduled, 2);
        assert_eq!(m["cancel"].tasks_submitted, 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: event counters accumulate across batches
    // -----------------------------------------------------------------------

    #[test]
    fn event_counters_accumulate_across_batches() {
        let config = LaneConfig {
            ready_min_throughput: 0,
            ..Default::default()
        };
        let mut sched = LaneScheduler::new(config);
        sched.submit(cancel_label("t1"), 0, "c1", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "c2", 0).unwrap();
        sched.submit(ready_label("t3"), 0, "r1", 0).unwrap();

        assert_eq!(sched.event_counts().get("submit"), Some(&3));

        sched.schedule_batch(1, 0);
        assert_eq!(sched.event_counts().get("schedule"), Some(&1));

        sched.schedule_batch(1, 0);
        assert_eq!(sched.event_counts().get("schedule"), Some(&2));

        sched.schedule_batch(1, 0);
        assert_eq!(sched.event_counts().get("schedule"), Some(&3));
    }

    #[test]
    fn event_counters_empty_initially() {
        let sched = LaneScheduler::new(LaneConfig::default());
        assert!(sched.event_counts().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: complete_task on timed lane
    // -----------------------------------------------------------------------

    #[test]
    fn complete_task_timed_lane() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let id = sched.submit(timed_label("t1"), 50, "p1", 0).unwrap();
        sched.schedule_batch(10, 100);
        sched.drain_events();

        sched.complete_task(id, SchedulerLane::Timed);
        let m = sched.lane_metrics();
        assert_eq!(m["timed"].tasks_completed, 1);

        let events = sched.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "complete");
        assert_eq!(events[0].lane, "timed");
    }

    // -----------------------------------------------------------------------
    // Enrichment: drain_events idempotency
    // -----------------------------------------------------------------------

    #[test]
    fn drain_events_returns_empty_on_second_call() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();

        let first = sched.drain_events();
        assert_eq!(first.len(), 1);

        let second = sched.drain_events();
        assert!(second.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: anti-starvation with empty ready queue
    // -----------------------------------------------------------------------

    #[test]
    fn anti_starvation_with_empty_ready_queue() {
        let config = LaneConfig {
            ready_min_throughput: 5,
            ..Default::default()
        };
        let mut sched = LaneScheduler::new(config);
        sched.submit(cancel_label("t1"), 0, "c1", 0).unwrap();

        let batch = sched.schedule_batch(10, 0);
        // Only the cancel task, no ready tasks available.
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].label.lane, SchedulerLane::Cancel);
    }

    // -----------------------------------------------------------------------
    // Enrichment: submit at exact capacity succeeds, next one fails
    // -----------------------------------------------------------------------

    #[test]
    fn submit_at_exact_capacity_boundary() {
        let config = LaneConfig {
            timed_max_depth: 3,
            ..Default::default()
        };
        let mut sched = LaneScheduler::new(config);

        // Fill exactly to capacity.
        for i in 0..3 {
            sched
                .submit(timed_label(&format!("t{i}")), 100, &format!("p{i}"), 0)
                .unwrap();
        }
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 3);

        // Next submission should fail.
        let err = sched
            .submit(timed_label("overflow"), 100, "overflow", 0)
            .unwrap_err();
        assert!(matches!(err, LaneError::LaneFull { max_depth: 3, .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: timed task with deadline_tick = 0
    // -----------------------------------------------------------------------

    #[test]
    fn timed_task_deadline_zero_scheduled_when_current_zero() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(timed_label("t1"), 0, "zero-deadline", 0)
            .unwrap();

        // deadline_tick=0, current_ticks=0 → deadline <= current → scheduled.
        let batch = sched.schedule_batch(10, 0);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload_id, "zero-deadline");
    }

    // -----------------------------------------------------------------------
    // Enrichment: fresh scheduler metrics initialization
    // -----------------------------------------------------------------------

    #[test]
    fn fresh_scheduler_metrics_initialized_for_all_lanes() {
        let sched = LaneScheduler::new(LaneConfig::default());
        let m = sched.lane_metrics();

        assert!(m.contains_key("cancel"));
        assert!(m.contains_key("timed"));
        assert!(m.contains_key("ready"));
        assert_eq!(m.len(), 3);

        for (name, metrics) in m {
            assert_eq!(metrics.lane, *name);
            assert_eq!(metrics.queue_depth, 0);
            assert_eq!(metrics.tasks_submitted, 0);
            assert_eq!(metrics.tasks_scheduled, 0);
            assert_eq!(metrics.tasks_completed, 0);
            assert_eq!(metrics.tasks_timed_out, 0);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: complete_task does not affect queue depth
    // -----------------------------------------------------------------------

    #[test]
    fn complete_task_does_not_modify_queues() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(cancel_label("t1"), 0, "c1", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "c2", 0).unwrap();

        let batch = sched.schedule_batch(1, 0);
        assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 1);

        // Completing a task doesn't remove anything from queues.
        sched.complete_task(batch[0].task_id, SchedulerLane::Cancel);
        assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment: all lane errors have distinct display messages
    // -----------------------------------------------------------------------

    #[test]
    fn all_lane_error_displays_contain_key_info() {
        let mismatch = LaneError::LaneMismatch {
            task_type: "gc_cycle".into(),
            declared_lane: "cancel".into(),
            required_lane: "ready".into(),
        };
        let msg = mismatch.to_string();
        assert!(msg.contains("gc_cycle"));
        assert!(msg.contains("cancel"));
        assert!(msg.contains("ready"));

        let full = LaneError::LaneFull {
            lane: "timed".into(),
            max_depth: 1024,
        };
        let msg = full.to_string();
        assert!(msg.contains("timed"));
        assert!(msg.contains("1024"));

        let not_found = LaneError::TaskNotFound { task_id: 0 };
        assert!(not_found.to_string().contains("0"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScheduledTask submitted_at preserved through scheduling
    // -----------------------------------------------------------------------

    #[test]
    fn submitted_at_preserved_through_scheduling() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(ready_label("t1"), 0, "p1", 42).unwrap();
        sched.submit(ready_label("t2"), 0, "p2", 99).unwrap();

        let batch = sched.schedule_batch(10, 100);
        assert_eq!(batch[0].submitted_at, 42);
        assert_eq!(batch[1].submitted_at, 99);
    }

    // -----------------------------------------------------------------------
    // Enrichment: lane mismatch for all incorrect lane combinations
    // -----------------------------------------------------------------------

    #[test]
    fn lane_mismatch_all_wrong_lane_combinations() {
        let mut sched = LaneScheduler::new(LaneConfig::default());

        // Cancel type in Timed lane.
        let err = sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Timed,
                    task_type: TaskType::CancelCleanup,
                    trace_id: "t1".into(),
                    priority_sub_band: 0,
                },
                0,
                "p",
                0,
            )
            .unwrap_err();
        assert!(matches!(err, LaneError::LaneMismatch { .. }));

        // Timed type in Ready lane.
        let err = sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Ready,
                    task_type: TaskType::LeaseRenewal,
                    trace_id: "t2".into(),
                    priority_sub_band: 0,
                },
                0,
                "p",
                0,
            )
            .unwrap_err();
        assert!(matches!(err, LaneError::LaneMismatch { .. }));

        // Ready type in Cancel lane.
        let err = sched
            .submit(
                TaskLabel {
                    lane: SchedulerLane::Cancel,
                    task_type: TaskType::GcCycle,
                    trace_id: "t3".into(),
                    priority_sub_band: 0,
                },
                0,
                "p",
                0,
            )
            .unwrap_err();
        assert!(matches!(err, LaneError::LaneMismatch { .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: timed tasks not yet due remain in queue across rounds
    // -----------------------------------------------------------------------

    #[test]
    fn timed_not_due_persists_across_rounds() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(timed_label("t1"), 1000, "future-task", 0)
            .unwrap();

        // Round 1: not due at tick 100.
        let batch1 = sched.schedule_batch(10, 100);
        assert!(batch1.is_empty());
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 1);

        // Round 2: not due at tick 500.
        let batch2 = sched.schedule_batch(10, 500);
        assert!(batch2.is_empty());
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 1);

        // Round 3: due at tick 1000.
        let batch3 = sched.schedule_batch(10, 1000);
        assert_eq!(batch3.len(), 1);
        assert_eq!(batch3[0].payload_id, "future-task");
    }

    // -----------------------------------------------------------------------
    // Enrichment: submit event includes queue_position
    // -----------------------------------------------------------------------

    #[test]
    fn submit_event_records_queue_position() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.submit(ready_label("t1"), 0, "p1", 0).unwrap();
        sched.submit(ready_label("t2"), 0, "p2", 0).unwrap();
        sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();

        let events = sched.drain_events();
        assert_eq!(events[0].queue_position, 0);
        assert_eq!(events[1].queue_position, 1);
        assert_eq!(events[2].queue_position, 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: complete_task event counter
    // -----------------------------------------------------------------------

    #[test]
    fn complete_task_event_counter() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let id1 = sched.submit(cancel_label("t1"), 0, "c1", 0).unwrap();
        let id2 = sched.submit(cancel_label("t2"), 0, "c2", 0).unwrap();
        sched.schedule_batch(10, 0);

        sched.complete_task(id1, SchedulerLane::Cancel);
        sched.complete_task(id2, SchedulerLane::Cancel);

        assert_eq!(sched.event_counts().get("complete"), Some(&2));
    }

    // -----------------------------------------------------------------------
    // Enrichment: all three lanes filled simultaneously
    // -----------------------------------------------------------------------

    #[test]
    fn all_three_lanes_filled_and_drained() {
        let mut sched = LaneScheduler::new(LaneConfig::default());

        for i in 0..3 {
            sched
                .submit(cancel_label(&format!("c{i}")), 0, &format!("cancel-{i}"), 0)
                .unwrap();
        }
        for i in 0..3 {
            sched
                .submit(
                    timed_label(&format!("ti{i}")),
                    (i + 1) as u64 * 10,
                    &format!("timed-{i}"),
                    0,
                )
                .unwrap();
        }
        for i in 0..3 {
            sched
                .submit(ready_label(&format!("r{i}")), 0, &format!("ready-{i}"), 0)
                .unwrap();
        }

        assert_eq!(sched.total_queue_depth(), 9);

        let batch = sched.schedule_batch(100, 100);
        // 3 cancel + 3 timed (all due) + 3 ready = 9
        assert_eq!(batch.len(), 9);

        // Verify lane ordering: cancel first, then timed, then ready.
        let lanes: Vec<_> = batch.iter().map(|t| t.label.lane).collect();
        let cancel_end = lanes
            .iter()
            .rposition(|l| *l == SchedulerLane::Cancel)
            .unwrap();
        let timed_start = lanes
            .iter()
            .position(|l| *l == SchedulerLane::Timed)
            .unwrap();
        let timed_end = lanes
            .iter()
            .rposition(|l| *l == SchedulerLane::Timed)
            .unwrap();
        let ready_start = lanes
            .iter()
            .position(|l| *l == SchedulerLane::Ready)
            .unwrap();
        assert!(cancel_end < timed_start);
        assert!(timed_end < ready_start);
    }

    // -----------------------------------------------------------------------
    // Enrichment: LaneError serde roundtrip for LaneMismatch
    // -----------------------------------------------------------------------

    #[test]
    fn lane_error_lane_mismatch_serde_roundtrip() {
        let err = LaneError::LaneMismatch {
            task_type: "saga_step_exec".to_string(),
            declared_lane: "timed".to_string(),
            required_lane: "ready".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: LaneError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn lane_error_empty_trace_id_serde_roundtrip() {
        let err = LaneError::EmptyTraceId;
        let json = serde_json::to_string(&err).unwrap();
        let back: LaneError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn lane_error_task_not_found_serde_roundtrip() {
        let err = LaneError::TaskNotFound { task_id: u64::MAX };
        let json = serde_json::to_string(&err).unwrap();
        let back: LaneError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
        assert!(json.contains(&u64::MAX.to_string()));
    }

    // -----------------------------------------------------------------------
    // Enrichment: LaneConfig serde with non-default values
    // -----------------------------------------------------------------------

    #[test]
    fn lane_config_serde_non_default() {
        let cfg = LaneConfig {
            cancel_max_depth: 1,
            timed_max_depth: 1,
            ready_max_depth: 1,
            ready_min_throughput: 0,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: LaneConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }
}
