//! Scheduler lanes for prioritized task scheduling with task-type
//! labeling and lane-aware observability.
//!
//! Three lanes model priority scheduling guarantees:
//! - `Cancel`: highest priority — cancellation cleanup, quarantine, drains.
//! - `Timed`: medium priority — deadline-sensitive (lease renewals, probes).
//! - `Ready`: normal priority — general work (extension dispatch, GC, sync).
//!
//! Cancel tasks are always scheduled first. Timed tasks with imminent
//! deadlines are promoted ahead of ready tasks. Ready tasks are currently
//! plain FIFO; `priority_sub_band` is recorded for observability and future
//! policy work, but this scheduler does not reorder on it yet. Anti-starvation
//! ensures ready tasks make progress even under cancel/timed pressure.
//!
//! Plan references: Section 10.11 item 25, 9G.8 (scheduler lane model),
//! Top-10 #4 (performance discipline), #8 (per-extension resource budget).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::resource_certificate_consumer::{
    BudgetEnforcer, EnforcedDimension, EnforcementDecision, EnforcementScope, SharedBudgetEnforcer,
};

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
    /// Optional fine-grained priority metadata within the lane.
    ///
    /// Lower values represent higher priority for any downstream policy that
    /// consumes this field, but the scheduler itself currently preserves plain
    /// FIFO ordering for ready-lane tasks.
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
// LanePressureSnapshot — operator-visible scheduler pressure evidence
// ---------------------------------------------------------------------------

/// Stable schema version for [`LanePressureSnapshot`].
pub const LANE_PRESSURE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Operator-visible scheduler pressure snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanePressureSnapshot {
    /// Snapshot schema version for downstream artifacts.
    pub schema_version: u32,
    /// Tick used to compute task wait ages.
    pub current_ticks: u64,
    /// Total queued task count across all scheduler lanes.
    pub total_queue_depth: usize,
    /// Per-lane pressure evidence in deterministic cancel/timed/ready order.
    pub lanes: Vec<LanePressureLaneSnapshot>,
    /// Timed-lane backlog grouped by deadline in ascending deadline order.
    pub timed_deadline_backlog: Vec<TimedDeadlineBacklogSnapshot>,
    /// Scheduler event counters copied in sorted key order.
    pub event_counts: BTreeMap<String, u64>,
    /// Count of scheduler admissions that were accepted under throttle.
    pub budget_throttle_count: u64,
}

/// Per-lane pressure evidence for a scheduler snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanePressureLaneSnapshot {
    /// Lane name.
    pub lane: String,
    /// Current queue depth.
    pub queue_depth: usize,
    /// Configured maximum queue depth for the lane.
    pub max_depth: usize,
    /// Whether the lane has reached its configured capacity.
    pub is_at_capacity: bool,
    /// Earliest submitted tick among currently queued tasks.
    pub oldest_submitted_tick: Option<u64>,
    /// Latest submitted tick among currently queued tasks.
    pub newest_submitted_tick: Option<u64>,
    /// Wait age for the oldest queued task, computed from `current_ticks`.
    pub oldest_wait_ticks: Option<u64>,
    /// Wait age for the newest queued task, computed from `current_ticks`.
    pub newest_wait_ticks: Option<u64>,
    /// Total tasks submitted to this lane.
    pub tasks_submitted: u64,
    /// Total tasks scheduled from this lane.
    pub tasks_scheduled: u64,
    /// Total tasks completed for this lane.
    pub tasks_completed: u64,
    /// Total timed-out tasks charged to this lane.
    pub tasks_timed_out: u64,
    /// Queued task counts by task type, sorted by task-type string.
    pub task_type_counts: BTreeMap<String, usize>,
    /// Queued task labels in deterministic lane queue order.
    pub queued_tasks: Vec<LanePressureTaskSnapshot>,
}

/// Stable queued-task label included in lane pressure snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanePressureTaskSnapshot {
    /// Scheduler-assigned task ID.
    pub task_id: u64,
    /// Lane name.
    pub lane: String,
    /// Task classification.
    pub task_type: String,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Fine-grained priority metadata recorded with the task label.
    pub priority_sub_band: u32,
    /// Deadline tick for timed tasks; `0` for tasks without a deadline.
    pub deadline_tick: u64,
    /// Tick at which the task was submitted.
    pub submitted_at: u64,
    /// Current queued wait age.
    pub wait_ticks: u64,
    /// Opaque payload identifier.
    pub payload_id: String,
}

/// Timed-lane backlog evidence for a single deadline bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimedDeadlineBacklogSnapshot {
    /// Deadline tick shared by the bucket.
    pub deadline_tick: u64,
    /// Number of queued timed-lane tasks in this bucket.
    pub queue_depth: usize,
    /// Earliest submitted tick in the bucket.
    pub oldest_submitted_tick: Option<u64>,
    /// Latest submitted tick in the bucket.
    pub newest_submitted_tick: Option<u64>,
    /// Wait age for the oldest queued task in the bucket.
    pub oldest_wait_ticks: Option<u64>,
    /// Wait age for the newest queued task in the bucket.
    pub newest_wait_ticks: Option<u64>,
    /// Task IDs in deterministic FIFO order within the deadline bucket.
    pub task_ids: Vec<u64>,
    /// Trace IDs in deterministic FIFO order within the deadline bucket.
    pub trace_ids: Vec<String>,
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
    /// Scheduler cannot allocate another unique task ID.
    TaskIdExhausted,
    /// Per-extension budget enforcer rejected admission.
    BudgetExceeded {
        extension_id: String,
        task_type: String,
        reason: String,
    },
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
            Self::TaskIdExhausted => f.write_str("task ID space exhausted"),
            Self::BudgetExceeded {
                extension_id,
                task_type,
                reason,
            } => write!(
                f,
                "scheduler admission for {task_type} rejected for extension '{extension_id}': {reason}"
            ),
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
    /// Next task ID to allocate. `0` is reserved as an internal exhausted
    /// sentinel so the scheduler can still issue `TaskId(u64::MAX)` exactly
    /// once before failing closed on subsequent submissions.
    next_task_id: u64,
    /// Cancel lane queue.
    cancel_queue: VecDeque<ScheduledTask>,
    /// Timed lane queue, indexed by `deadline_tick` so the smallest
    /// deadline can be retrieved in O(log n) via `BTreeMap::first_entry`.
    /// Tasks sharing a deadline are FIFO-ordered within the per-bucket
    /// `VecDeque`, preserving the deterministic insertion-order tiebreak.
    timed_queue: BTreeMap<u64, VecDeque<ScheduledTask>>,
    /// Cached total length of `timed_queue` so `queue_depth(Timed)` and
    /// metric updates remain O(1) (BTreeMap iteration would be O(n)).
    timed_queue_len: usize,
    /// Ready lane queue (FIFO within sub-bands).
    ready_queue: VecDeque<ScheduledTask>,
    /// Per-lane metrics.
    metrics: BTreeMap<String, LaneMetrics>,
    /// Accumulated events.
    events: Vec<SchedulerEvent>,
    /// Event counters.
    event_counts: BTreeMap<String, u64>,
    /// Resource budget enforcer for task scheduling.
    budget_enforcer: Option<SharedBudgetEnforcer>,
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
            timed_queue: BTreeMap::new(),
            timed_queue_len: 0,
            ready_queue: VecDeque::new(),
            metrics,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
            budget_enforcer: None,
        }
    }

    /// Set the budget enforcer for task scheduling.
    pub fn set_budget_enforcer(&mut self, enforcer: BudgetEnforcer) {
        self.set_shared_budget_enforcer(SharedBudgetEnforcer::new(enforcer));
    }

    /// Set a shared budget enforcer for task scheduling.
    pub(crate) fn set_shared_budget_enforcer(&mut self, enforcer: SharedBudgetEnforcer) {
        self.budget_enforcer = Some(enforcer);
    }

    fn validate_submission(&self, label: &TaskLabel) -> Result<(), LaneError> {
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
        let max_depth = match label.lane {
            SchedulerLane::Cancel => self.config.cancel_max_depth,
            SchedulerLane::Timed => self.config.timed_max_depth,
            SchedulerLane::Ready => self.config.ready_max_depth,
        };
        if self.queue_depth(label.lane) >= max_depth {
            return Err(LaneError::LaneFull {
                lane: label.lane.to_string(),
                max_depth,
            });
        }

        if self.next_task_id == 0 {
            return Err(LaneError::TaskIdExhausted);
        }

        Ok(())
    }

    /// Submit a task to the scheduler.
    pub fn submit(
        &mut self,
        label: TaskLabel,
        deadline_tick: u64,
        payload_id: &str,
        current_ticks: u64,
    ) -> Result<TaskId, LaneError> {
        self.validate_submission(&label)?;

        let task_id = self.allocate_task_id()?;

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
                self.timed_queue
                    .entry(task.deadline_tick)
                    .or_default()
                    .push_back(task);
                self.timed_queue_len = self.timed_queue_len.saturating_add(1);
                // Position is per-deadline FIFO within bucket; expose the
                // pre-insert total length for backward compatibility with
                // the original `len() - 1` semantic, since callers use
                // queue_position only for telemetry/diagnostics.
                self.timed_queue_len.saturating_sub(1)
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
                SchedulerLane::Timed => self.timed_queue_len,
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

    /// Submit a task on behalf of a specific extension, consulting the
    /// budget enforcer (when set) for per-extension scheduler admission.
    ///
    /// Behaviour matches [`submit`] when no budget enforcer is configured.
    /// When an enforcer is set:
    /// - `Reject` decisions return [`LaneError::BudgetExceeded`] without
    ///   ever queuing the task.
    /// - `Throttle` decisions admit the task but emit a `submit_throttled`
    ///   scheduler event so observers can record back-pressure.
    /// - `Allow` decisions admit the task with a normal `submit` event.
    pub fn submit_for_extension(
        &mut self,
        extension_id: &str,
        label: TaskLabel,
        deadline_tick: u64,
        payload_id: &str,
        current_ticks: u64,
    ) -> Result<TaskId, LaneError> {
        self.validate_submission(&label)?;

        let throttled =
            self.try_enforce_admission(extension_id, &label, deadline_tick, current_ticks)?;

        let task_id = self.submit(label.clone(), deadline_tick, payload_id, current_ticks)?;

        if throttled {
            let queue_position = self.queue_depth(label.lane).saturating_sub(1);
            self.emit_event(SchedulerEvent {
                task_id: task_id.0,
                lane: label.lane.to_string(),
                task_type: label.task_type.to_string(),
                trace_id: label.trace_id,
                queue_position,
                event: "submit_throttled".to_string(),
            });
            self.record_count("submit_throttled");
        }

        Ok(task_id)
    }

    /// Consult the budget enforcer for scheduler admission of a task.
    /// Returns `Ok(throttled)` indicating whether the enforcer requested
    /// throttling (the task is still admitted), and `Err(BudgetExceeded)`
    /// when the enforcer rejects admission. A `None` enforcer is a no-op
    /// returning `Ok(false)`.
    fn try_enforce_admission(
        &mut self,
        extension_id: &str,
        label: &TaskLabel,
        deadline_tick: u64,
        current_ticks: u64,
    ) -> Result<bool, LaneError> {
        let Some(enforcer) = self.budget_enforcer.as_ref() else {
            return Ok(false);
        };

        // Charge remaining deadline slack instead of the absolute scheduler
        // tick so admission stays invariant to uptime. We only have
        // scheduler-local ticks here, so this remains a conservative proxy
        // for wall-time until a tighter duration estimate is available.
        let remaining_ticks = deadline_tick.saturating_sub(current_ticks);
        let time_delta = if remaining_ticks > i64::MAX as u64 {
            i64::MAX
        } else {
            remaining_ticks as i64
        };
        let usage_deltas = [(EnforcedDimension::Time, time_delta)];
        let receipt = enforcer.write().enforce(
            extension_id,
            EnforcementScope::SchedulerAdmission {
                task_type: label.task_type.to_string(),
            },
            &usage_deltas,
        );

        match receipt.decision {
            EnforcementDecision::Allow => Ok(false),
            EnforcementDecision::Throttle { .. } => Ok(true),
            EnforcementDecision::Reject { reason } => Err(LaneError::BudgetExceeded {
                extension_id: extension_id.to_string(),
                task_type: label.task_type.to_string(),
                reason: reason.to_string(),
            }),
        }
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

        // 2. Timed lane: tasks with deadline <= current_ticks (smallest
        // deadline first). The BTreeMap keeps deadline buckets sorted, so
        // peek-min is O(log n) and we only touch tasks we actually
        // schedule (O(K log n) instead of the prior O(n log n) drain+sort).
        while batch.len() < batch_size {
            let due = match self.timed_queue.first_key_value() {
                Some((deadline, _)) => *deadline <= current_ticks,
                None => false,
            };
            if !due {
                break;
            }
            let Some(task) = self.pop_min_timed() else {
                break;
            };
            self.record_schedule(&task);
            batch.push(task);
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

        // Timeout expired timed tasks still in queue. Same min-heap walk:
        // a strictly-overdue head (deadline > 0 && < current_ticks) means
        // every task in that bucket is overdue, and the next bucket's
        // smallest deadline is >=, so we can stop as soon as the head is
        // not overdue. This is O(K' log n) where K' is the count expired
        // (typically the leftover when batch_size was hit early).
        let mut timed_expired = Vec::new();
        loop {
            let overdue = match self.timed_queue.first_key_value() {
                Some((deadline, _)) => *deadline > 0 && *deadline < current_ticks,
                None => false,
            };
            if !overdue {
                break;
            }
            let Some(task) = self.pop_min_timed() else {
                break;
            };
            timed_expired.push(task);
        }

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
            SchedulerLane::Timed => self.timed_queue_len,
            SchedulerLane::Ready => self.ready_queue.len(),
        }
    }

    /// Total queue depth across all lanes.
    pub fn total_queue_depth(&self) -> usize {
        self.cancel_queue.len() + self.timed_queue_len + self.ready_queue.len()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<SchedulerEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    /// Build an operator-visible pressure snapshot for all scheduler lanes.
    pub fn pressure_snapshot(&self, current_ticks: u64) -> LanePressureSnapshot {
        let lanes = vec![
            self.lane_pressure_snapshot(
                SchedulerLane::Cancel,
                self.cancel_queue.iter(),
                current_ticks,
            ),
            self.lane_pressure_snapshot(
                SchedulerLane::Timed,
                self.timed_queue.values().flat_map(|bucket| bucket.iter()),
                current_ticks,
            ),
            self.lane_pressure_snapshot(
                SchedulerLane::Ready,
                self.ready_queue.iter(),
                current_ticks,
            ),
        ];

        LanePressureSnapshot {
            schema_version: LANE_PRESSURE_SNAPSHOT_SCHEMA_VERSION,
            current_ticks,
            total_queue_depth: self.total_queue_depth(),
            lanes,
            timed_deadline_backlog: self.timed_deadline_backlog(current_ticks),
            event_counts: self.event_counts.clone(),
            budget_throttle_count: self
                .event_counts
                .get("submit_throttled")
                .copied()
                .unwrap_or(0),
        }
    }

    // -- Internal --

    fn lane_pressure_snapshot<'a, I>(
        &self,
        lane: SchedulerLane,
        tasks: I,
        current_ticks: u64,
    ) -> LanePressureLaneSnapshot
    where
        I: IntoIterator<Item = &'a ScheduledTask>,
    {
        let lane_name = lane.to_string();
        let metrics = self
            .metrics
            .get(&lane_name)
            .cloned()
            .unwrap_or_else(|| LaneMetrics {
                lane: lane_name.clone(),
                ..Default::default()
            });
        let max_depth = self.lane_max_depth(lane);
        let mut oldest_submitted_tick: Option<u64> = None;
        let mut newest_submitted_tick: Option<u64> = None;
        let mut task_type_counts = BTreeMap::new();
        let mut queued_tasks = Vec::new();

        for task in tasks {
            oldest_submitted_tick = Some(
                oldest_submitted_tick
                    .map(|oldest| oldest.min(task.submitted_at))
                    .unwrap_or(task.submitted_at),
            );
            newest_submitted_tick = Some(
                newest_submitted_tick
                    .map(|newest| newest.max(task.submitted_at))
                    .unwrap_or(task.submitted_at),
            );
            *task_type_counts
                .entry(task.label.task_type.to_string())
                .or_insert(0) += 1;
            queued_tasks.push(Self::task_pressure_snapshot(task, current_ticks));
        }

        LanePressureLaneSnapshot {
            lane: lane_name,
            queue_depth: metrics.queue_depth,
            max_depth,
            is_at_capacity: metrics.queue_depth >= max_depth,
            oldest_submitted_tick,
            newest_submitted_tick,
            oldest_wait_ticks: oldest_submitted_tick
                .map(|submitted_at| current_ticks.saturating_sub(submitted_at)),
            newest_wait_ticks: newest_submitted_tick
                .map(|submitted_at| current_ticks.saturating_sub(submitted_at)),
            tasks_submitted: metrics.tasks_submitted,
            tasks_scheduled: metrics.tasks_scheduled,
            tasks_completed: metrics.tasks_completed,
            tasks_timed_out: metrics.tasks_timed_out,
            task_type_counts,
            queued_tasks,
        }
    }

    fn timed_deadline_backlog(&self, current_ticks: u64) -> Vec<TimedDeadlineBacklogSnapshot> {
        self.timed_queue
            .iter()
            .map(|(deadline_tick, bucket)| {
                let oldest_submitted_tick = bucket.iter().map(|task| task.submitted_at).min();
                let newest_submitted_tick = bucket.iter().map(|task| task.submitted_at).max();
                TimedDeadlineBacklogSnapshot {
                    deadline_tick: *deadline_tick,
                    queue_depth: bucket.len(),
                    oldest_submitted_tick,
                    newest_submitted_tick,
                    oldest_wait_ticks: oldest_submitted_tick
                        .map(|submitted_at| current_ticks.saturating_sub(submitted_at)),
                    newest_wait_ticks: newest_submitted_tick
                        .map(|submitted_at| current_ticks.saturating_sub(submitted_at)),
                    task_ids: bucket.iter().map(|task| task.task_id.0).collect(),
                    trace_ids: bucket
                        .iter()
                        .map(|task| task.label.trace_id.clone())
                        .collect(),
                }
            })
            .collect()
    }

    fn task_pressure_snapshot(
        task: &ScheduledTask,
        current_ticks: u64,
    ) -> LanePressureTaskSnapshot {
        LanePressureTaskSnapshot {
            task_id: task.task_id.0,
            lane: task.label.lane.to_string(),
            task_type: task.label.task_type.to_string(),
            trace_id: task.label.trace_id.clone(),
            priority_sub_band: task.label.priority_sub_band,
            deadline_tick: task.deadline_tick,
            submitted_at: task.submitted_at,
            wait_ticks: current_ticks.saturating_sub(task.submitted_at),
            payload_id: task.payload_id.clone(),
        }
    }

    fn lane_max_depth(&self, lane: SchedulerLane) -> usize {
        match lane {
            SchedulerLane::Cancel => self.config.cancel_max_depth,
            SchedulerLane::Timed => self.config.timed_max_depth,
            SchedulerLane::Ready => self.config.ready_max_depth,
        }
    }

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
            m.queue_depth = self.timed_queue_len;
        }
        if let Some(m) = self.metrics.get_mut("ready") {
            m.queue_depth = self.ready_queue.len();
        }
    }

    fn emit_event(&mut self, event: SchedulerEvent) {
        self.events.push(event);
    }

    /// Pop the smallest-deadline task from `timed_queue`. FIFO within
    /// the per-deadline bucket. Removes empty buckets to keep the
    /// BTreeMap from growing unboundedly. O(log n) where n is the number
    /// of distinct deadline values currently queued.
    fn pop_min_timed(&mut self) -> Option<ScheduledTask> {
        let mut entry = self.timed_queue.first_entry()?;
        let task = entry.get_mut().pop_front()?;
        if entry.get().is_empty() {
            entry.remove_entry();
        }
        self.timed_queue_len = self.timed_queue_len.saturating_sub(1);
        Some(task)
    }

    fn allocate_task_id(&mut self) -> Result<TaskId, LaneError> {
        if self.next_task_id == 0 {
            return Err(LaneError::TaskIdExhausted);
        }

        let task_id = TaskId(self.next_task_id);
        self.next_task_id = self.next_task_id.checked_add(1).unwrap_or(0);
        Ok(task_id)
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

    fn snapshot_lane<'a>(
        snapshot: &'a LanePressureSnapshot,
        lane: &str,
    ) -> &'a LanePressureLaneSnapshot {
        snapshot
            .lanes
            .iter()
            .find(|entry| entry.lane.as_str() == lane)
            .expect("lane snapshot should be present")
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
        let id = sched
            .submit(cancel_label("t1"), 0, "payload-1", 0)
            .expect("serde deserialization should succeed");
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
        sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t2"), 0, "p2", 0)
            .expect("serde deserialization should succeed");
        assert!(matches!(
            sched.submit(cancel_label("t3"), 0, "p3", 0),
            Err(LaneError::LaneFull { .. })
        ));
    }

    // -- Schedule batch: lane priorities --

    #[test]
    fn cancel_tasks_scheduled_first() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(ready_label("t1"), 0, "ready-1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t2"), 0, "cancel-1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(timed_label("t3"), 100, "timed-1", 0)
            .expect("serde deserialization should succeed");

        let batch = sched.schedule_batch(10, 200);
        // Cancel should be first.
        assert_eq!(batch[0].label.lane, SchedulerLane::Cancel);
    }

    #[test]
    fn timed_tasks_scheduled_before_ready_when_due() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(ready_label("t1"), 0, "ready-1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(timed_label("t2"), 50, "timed-1", 0)
            .expect("serde deserialization should succeed");

        let batch = sched.schedule_batch(10, 100);
        // Timed task (deadline 50 <= current 100) should be before ready.
        let timed_pos = batch
            .iter()
            .position(|t| t.label.lane == SchedulerLane::Timed);
        let ready_pos = batch
            .iter()
            .position(|t| t.label.lane == SchedulerLane::Ready);
        assert!(
            timed_pos.expect("serde deserialization should succeed")
                < ready_pos.expect("serde deserialization should succeed")
        );
    }

    #[test]
    fn timed_tasks_not_scheduled_if_not_due() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(timed_label("t1"), 500, "timed-1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t2"), 0, "ready-1", 0)
            .expect("serde deserialization should succeed");

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
                .expect("serde deserialization should succeed");
        }
        // Add ready tasks.
        for i in 0..3 {
            sched
                .submit(ready_label(&format!("rt{i}")), 0, &format!("r{i}"), 0)
                .expect("serde deserialization should succeed");
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
        sched
            .submit(cancel_label("cancel-1"), 0, "c1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("ready-1"), 0, "r1", 0)
            .expect("serde deserialization should succeed");

        let batch = sched.schedule_batch(0, 0);
        assert!(batch.is_empty());
        assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 1);
        assert_eq!(sched.queue_depth(SchedulerLane::Ready), 1);
    }

    // -- Ready lane FIFO --

    #[test]
    fn ready_lane_fifo_ordering() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(ready_label("t1"), 0, "first", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t2"), 0, "second", 10)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t3"), 0, "third", 20)
            .expect("serde deserialization should succeed");

        let batch = sched.schedule_batch(10, 30);
        assert_eq!(batch[0].payload_id, "first");
        assert_eq!(batch[1].payload_id, "second");
        assert_eq!(batch[2].payload_id, "third");
    }

    // -- Timed lane deadline sorting --

    #[test]
    fn timed_lane_sorts_by_deadline() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(timed_label("t1"), 300, "late", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(timed_label("t2"), 100, "early", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(timed_label("t3"), 200, "mid", 0)
            .expect("serde deserialization should succeed");

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
        sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t2"), 0, "p2", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t3"), 0, "p3", 0)
            .expect("serde deserialization should succeed");

        let m = sched.lane_metrics();
        assert_eq!(m["cancel"].tasks_submitted, 2);
        assert_eq!(m["ready"].tasks_submitted, 1);
    }

    #[test]
    fn metrics_track_scheduling() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t2"), 0, "p2", 0)
            .expect("serde deserialization should succeed");
        sched.schedule_batch(10, 0);

        let m = sched.lane_metrics();
        assert_eq!(m["cancel"].tasks_scheduled, 1);
        assert_eq!(m["ready"].tasks_scheduled, 1);
    }

    #[test]
    fn metrics_track_completion() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let id = sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        sched.schedule_batch(10, 0);
        sched.complete_task(id, SchedulerLane::Cancel);

        let m = sched.lane_metrics();
        assert_eq!(m["cancel"].tasks_completed, 1);
    }

    // -- Audit events --

    #[test]
    fn submit_emits_event() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");

        let events = sched.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "submit");
        assert_eq!(events[0].lane, "cancel");
        assert_eq!(events[0].trace_id, "t1");
    }

    #[test]
    fn schedule_emits_events() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        sched.drain_events();

        sched.schedule_batch(10, 0);
        let events = sched.drain_events();
        assert!(!events.is_empty());
        assert_eq!(events[0].event, "schedule");
    }

    #[test]
    fn event_counts_track() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t2"), 0, "p2", 0)
            .expect("serde deserialization should succeed");
        sched.schedule_batch(10, 0);

        assert_eq!(sched.event_counts().get("submit"), Some(&2));
        assert_eq!(sched.event_counts().get("schedule"), Some(&2));
    }

    // -- Pressure snapshots --

    #[test]
    fn pressure_snapshot_empty_scheduler_has_all_lanes_and_zero_depths() {
        let sched = LaneScheduler::new(LaneConfig::default());

        let snapshot = sched.pressure_snapshot(42);

        assert_eq!(
            snapshot.schema_version,
            LANE_PRESSURE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(snapshot.current_ticks, 42);
        assert_eq!(snapshot.total_queue_depth, 0);
        assert_eq!(
            snapshot
                .lanes
                .iter()
                .map(|lane| lane.lane.as_str())
                .collect::<Vec<_>>(),
            vec!["cancel", "timed", "ready"]
        );
        for lane in &snapshot.lanes {
            assert_eq!(lane.queue_depth, 0);
            assert!(!lane.is_at_capacity);
            assert_eq!(lane.oldest_submitted_tick, None);
            assert_eq!(lane.newest_submitted_tick, None);
            assert_eq!(lane.oldest_wait_ticks, None);
            assert_eq!(lane.newest_wait_ticks, None);
            assert!(lane.task_type_counts.is_empty());
            assert!(lane.queued_tasks.is_empty());
        }
        assert!(snapshot.timed_deadline_backlog.is_empty());
        assert!(snapshot.event_counts.is_empty());
        assert_eq!(snapshot.budget_throttle_count, 0);
    }

    #[test]
    fn pressure_snapshot_reports_stable_lane_pressure_and_task_labels() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let cancel_id = sched
            .submit(cancel_label("trace-cancel"), 0, "cancel-payload", 10)
            .expect("cancel submit should succeed");
        let timed_late_id = sched
            .submit(timed_label("trace-timed-late"), 75, "timed-late", 11)
            .expect("timed submit should succeed");
        let timed_early_id = sched
            .submit(timed_label("trace-timed-early"), 50, "timed-early", 12)
            .expect("timed submit should succeed");
        let ready_id = sched
            .submit(ready_label("trace-ready"), 0, "ready-payload", 15)
            .expect("ready submit should succeed");

        let snapshot = sched.pressure_snapshot(20);

        assert_eq!(snapshot.total_queue_depth, 4);
        assert_eq!(snapshot.event_counts.get("submit"), Some(&4));

        let cancel = snapshot_lane(&snapshot, "cancel");
        assert_eq!(cancel.queue_depth, 1);
        assert_eq!(cancel.oldest_wait_ticks, Some(10));
        assert_eq!(cancel.queued_tasks[0].task_id, cancel_id.0);
        assert_eq!(cancel.queued_tasks[0].lane, "cancel");
        assert_eq!(cancel.queued_tasks[0].task_type, "cancel_cleanup");
        assert_eq!(cancel.queued_tasks[0].trace_id, "trace-cancel");

        let timed = snapshot_lane(&snapshot, "timed");
        assert_eq!(timed.queue_depth, 2);
        assert_eq!(timed.max_depth, LaneConfig::default().timed_max_depth);
        assert_eq!(timed.oldest_submitted_tick, Some(11));
        assert_eq!(timed.newest_submitted_tick, Some(12));
        assert_eq!(timed.oldest_wait_ticks, Some(9));
        assert_eq!(timed.newest_wait_ticks, Some(8));
        assert_eq!(timed.task_type_counts.get("lease_renewal"), Some(&2));
        assert_eq!(
            timed
                .queued_tasks
                .iter()
                .map(|task| (
                    task.task_id,
                    task.trace_id.as_str(),
                    task.task_type.as_str(),
                    task.deadline_tick,
                    task.wait_ticks
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    timed_early_id.0,
                    "trace-timed-early",
                    "lease_renewal",
                    50,
                    8,
                ),
                (timed_late_id.0, "trace-timed-late", "lease_renewal", 75, 9,),
            ]
        );

        let ready = snapshot_lane(&snapshot, "ready");
        assert_eq!(ready.queue_depth, 1);
        assert_eq!(ready.queued_tasks[0].task_id, ready_id.0);
        assert_eq!(ready.queued_tasks[0].trace_id, "trace-ready");
        assert_eq!(ready.queued_tasks[0].wait_ticks, 5);

        assert_eq!(
            snapshot
                .timed_deadline_backlog
                .iter()
                .map(|bucket| bucket.deadline_tick)
                .collect::<Vec<_>>(),
            vec![50, 75]
        );
        assert_eq!(
            snapshot.timed_deadline_backlog[0].task_ids,
            vec![timed_early_id.0]
        );
        assert_eq!(
            snapshot.timed_deadline_backlog[0].trace_ids,
            vec!["trace-timed-early"]
        );
        assert_eq!(
            snapshot.timed_deadline_backlog[1].task_ids,
            vec![timed_late_id.0]
        );

        let json = serde_json::to_string(&snapshot).expect("snapshot serialization should succeed");
        let restored: LanePressureSnapshot =
            serde_json::from_str(&json).expect("snapshot deserialization should succeed");
        assert_eq!(snapshot, restored);
    }

    #[test]
    fn pressure_snapshot_reports_saturated_lane_capacity() {
        let config = LaneConfig {
            cancel_max_depth: 2,
            ..Default::default()
        };
        let mut sched = LaneScheduler::new(config);
        sched
            .submit(cancel_label("sat-1"), 0, "payload-1", 5)
            .expect("first submit should succeed");
        sched
            .submit(cancel_label("sat-2"), 0, "payload-2", 6)
            .expect("second submit should succeed");

        assert!(matches!(
            sched.submit(cancel_label("sat-3"), 0, "payload-3", 7),
            Err(LaneError::LaneFull {
                lane,
                max_depth: 2,
            }) if lane == "cancel"
        ));

        let snapshot = sched.pressure_snapshot(10);
        let cancel = snapshot_lane(&snapshot, "cancel");
        assert_eq!(cancel.queue_depth, 2);
        assert_eq!(cancel.max_depth, 2);
        assert!(cancel.is_at_capacity);
        assert_eq!(cancel.oldest_wait_ticks, Some(5));
        assert_eq!(cancel.newest_wait_ticks, Some(4));
        assert_eq!(snapshot.event_counts.get("submit"), Some(&2));
        assert_eq!(
            cancel
                .queued_tasks
                .iter()
                .map(|task| task.trace_id.as_str())
                .collect::<Vec<_>>(),
            vec!["sat-1", "sat-2"]
        );
    }

    #[test]
    fn pressure_snapshot_carries_schedule_timeout_and_budget_throttle_counts() {
        let mut timed_sched = LaneScheduler::new(LaneConfig {
            ready_min_throughput: 0,
            ..Default::default()
        });
        timed_sched
            .submit(timed_label("trace-late"), 10, "late", 0)
            .expect("timed submit should succeed");
        timed_sched
            .submit(timed_label("trace-earlier"), 5, "earlier", 0)
            .expect("timed submit should succeed");
        let batch = timed_sched.schedule_batch(1, 20);
        assert_eq!(batch[0].payload_id, "earlier");

        let timed_snapshot = timed_sched.pressure_snapshot(25);
        assert_eq!(timed_snapshot.event_counts.get("submit"), Some(&2));
        assert_eq!(timed_snapshot.event_counts.get("schedule"), Some(&1));
        assert_eq!(timed_snapshot.event_counts.get("timeout"), Some(&1));
        let timed = snapshot_lane(&timed_snapshot, "timed");
        assert_eq!(timed.queue_depth, 0);
        assert_eq!(timed.tasks_scheduled, 1);
        assert_eq!(timed.tasks_timed_out, 1);
        assert!(timed_snapshot.timed_deadline_backlog.is_empty());

        let mut throttled_sched = LaneScheduler::new(LaneConfig::default());
        throttled_sched.set_budget_enforcer(admission_enforcer("ext-a", 100));
        throttled_sched
            .submit_for_extension("ext-a", ready_label("trace-throttle"), 95, "payload", 0)
            .expect("throttled admission should still queue the task");

        let throttled_snapshot = throttled_sched.pressure_snapshot(5);
        assert_eq!(
            throttled_snapshot.event_counts.get("submit_throttled"),
            Some(&1)
        );
        assert_eq!(throttled_snapshot.budget_throttle_count, 1);
        assert_eq!(
            snapshot_lane(&throttled_snapshot, "ready").queued_tasks[0].trace_id,
            "trace-throttle"
        );
    }

    // -- Serialization round-trips --

    #[test]
    fn task_label_serialization_round_trip() {
        let label = cancel_label("trace-1");
        let json = serde_json::to_string(&label).expect("serde deserialization should succeed");
        let restored: TaskLabel =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&task).expect("serde deserialization should succeed");
        let restored: ScheduledTask =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&m).expect("serde deserialization should succeed");
        let restored: LaneMetrics =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
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
            LaneError::BudgetExceeded {
                extension_id: "ext-a".to_string(),
                task_type: "extension_dispatch".to_string(),
                reason: "budget exceeded".to_string(),
            },
            LaneError::TaskIdExhausted,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let restored: LaneError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn submit_fails_closed_when_task_id_space_exhausted() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.next_task_id = 0;

        let err = sched
            .submit(ready_label("t1"), 0, "payload", 0)
            .expect_err("exhausted ID space must fail closed");

        assert_eq!(err, LaneError::TaskIdExhausted);
        assert_eq!(sched.queue_depth(SchedulerLane::Ready), 0);
        assert_eq!(sched.event_counts().get("submit"), None);
    }

    #[test]
    fn submit_allocates_max_task_id_before_marking_id_space_exhausted() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.next_task_id = u64::MAX;

        let task_id = sched
            .submit(ready_label("t1"), 0, "payload-max", 0)
            .expect("u64::MAX should be the last allocatable task ID");
        assert_eq!(task_id, TaskId(u64::MAX));
        assert_eq!(sched.next_task_id, 0);

        let err = sched
            .submit(ready_label("t2"), 0, "payload-overflow", 0)
            .expect_err("subsequent submissions must fail closed");
        assert_eq!(err, LaneError::TaskIdExhausted);
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
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: SchedulerEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
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
            sched
                .submit(ready_label("t1"), 0, "r1", 0)
                .expect("serde deserialization should succeed");
            sched
                .submit(cancel_label("t2"), 0, "c1", 0)
                .expect("serde deserialization should succeed");
            sched
                .submit(timed_label("t3"), 50, "ti1", 0)
                .expect("serde deserialization should succeed");
            sched
                .submit(ready_label("t4"), 0, "r2", 10)
                .expect("serde deserialization should succeed");
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
        sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(timed_label("t2"), 100, "p2", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t3"), 0, "p3", 0)
            .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");

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
        let id1 = sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        let id2 = sched
            .submit(ready_label("t2"), 0, "p2", 0)
            .expect("serde deserialization should succeed");
        let id3 = sched
            .submit(timed_label("t3"), 100, "p3", 0)
            .expect("serde deserialization should succeed");
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
        sched
            .submit(timed_label("t1"), 100, "p1", 0)
            .expect("serde deserialization should succeed");

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
        sched
            .submit(timed_label("t1"), 50, "early", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(timed_label("t2"), 200, "future", 0)
            .expect("serde deserialization should succeed");

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
        sched
            .submit(timed_label("t1"), 10, "p1", 0)
            .expect("serde deserialization should succeed");

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
        sched2
            .submit(timed_label("t1"), 10, "p1", 0)
            .expect("serde deserialization should succeed");
        sched2
            .submit(timed_label("t2"), 5, "p2", 0)
            .expect("serde deserialization should succeed");

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
            .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");

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
                .expect("serde deserialization should succeed");
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
            let json = serde_json::to_string(&lane).expect("serde deserialization should succeed");
            let back: SchedulerLane =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
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
            let json = serde_json::to_string(tt).expect("serde deserialization should succeed");
            let back: TaskType =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*tt, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: queue depths updated after scheduling
    // -----------------------------------------------------------------------

    #[test]
    fn queue_depths_updated_after_schedule() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(cancel_label("t1"), 0, "c1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t2"), 0, "c2", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t3"), 0, "r1", 0)
            .expect("serde deserialization should succeed");

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
        let id = sched
            .submit(ready_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&cfg).expect("serde deserialization should succeed");
        let back: LaneConfig =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&label).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&task).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&m).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let restored: LaneError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
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
        sched
            .submit(ready_label("t1"), 0, "ready-1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(timed_label("t2"), 10, "timed-1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t3"), 0, "cancel-1", 0)
            .expect("serde deserialization should succeed");

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
            let json = serde_json::to_string(&id).expect("serde deserialization should succeed");
            let back: TaskId =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&label).expect("serde deserialization should succeed");
        let back: TaskLabel =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(label, back);
        assert!(json.contains("\"Timed\"") || json.contains("\"timed\""));
    }

    #[test]
    fn task_label_serde_ready_lane() {
        let label = ready_label("trace-ready-serde");
        let json = serde_json::to_string(&label).expect("serde deserialization should succeed");
        let back: TaskLabel =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&label).expect("serde deserialization should succeed");
        let back: TaskLabel =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(label, back);
        assert!(json.contains("42"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: cancel queue FIFO ordering
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_lane_fifo_ordering() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(cancel_label("t1"), 0, "first", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t2"), 0, "second", 10)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t3"), 0, "third", 20)
            .expect("serde deserialization should succeed");

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
        sched
            .submit(cancel_label("t1"), 0, "c1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t2"), 0, "r1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t3"), 0, "r2", 0)
            .expect("serde deserialization should succeed");

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
        sched
            .submit(cancel_label("t1"), 0, "c1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t2"), 0, "c2", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t3"), 0, "r1", 0)
            .expect("serde deserialization should succeed");

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
        sched
            .submit(cancel_label("t1"), 0, "c1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t2"), 0, "c2", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t3"), 0, "r1", 0)
            .expect("serde deserialization should succeed");

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
        let id = sched
            .submit(timed_label("t1"), 50, "p1", 0)
            .expect("serde deserialization should succeed");
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
        sched
            .submit(cancel_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");

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
        sched
            .submit(cancel_label("t1"), 0, "c1", 0)
            .expect("serde deserialization should succeed");

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
                .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");

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
        sched
            .submit(cancel_label("t1"), 0, "c1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(cancel_label("t2"), 0, "c2", 0)
            .expect("serde deserialization should succeed");

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
        sched
            .submit(ready_label("t1"), 0, "p1", 42)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t2"), 0, "p2", 99)
            .expect("serde deserialization should succeed");

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
            .expect("serde deserialization should succeed");

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
        sched
            .submit(ready_label("t1"), 0, "p1", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t2"), 0, "p2", 0)
            .expect("serde deserialization should succeed");
        sched
            .submit(ready_label("t3"), 0, "p3", 0)
            .expect("serde deserialization should succeed");

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
        let id1 = sched
            .submit(cancel_label("t1"), 0, "c1", 0)
            .expect("serde deserialization should succeed");
        let id2 = sched
            .submit(cancel_label("t2"), 0, "c2", 0)
            .expect("serde deserialization should succeed");
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
                .expect("serde deserialization should succeed");
        }
        for i in 0..3 {
            sched
                .submit(
                    timed_label(&format!("ti{i}")),
                    (i + 1) as u64 * 10,
                    &format!("timed-{i}"),
                    0,
                )
                .expect("serde deserialization should succeed");
        }
        for i in 0..3 {
            sched
                .submit(ready_label(&format!("r{i}")), 0, &format!("ready-{i}"), 0)
                .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");
        let timed_start = lanes
            .iter()
            .position(|l| *l == SchedulerLane::Timed)
            .expect("serde deserialization should succeed");
        let timed_end = lanes
            .iter()
            .rposition(|l| *l == SchedulerLane::Timed)
            .expect("serde deserialization should succeed");
        let ready_start = lanes
            .iter()
            .position(|l| *l == SchedulerLane::Ready)
            .expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let back: LaneError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, back);
    }

    #[test]
    fn lane_error_empty_trace_id_serde_roundtrip() {
        let err = LaneError::EmptyTraceId;
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let back: LaneError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, back);
    }

    #[test]
    fn lane_error_task_not_found_serde_roundtrip() {
        let err = LaneError::TaskNotFound { task_id: u64::MAX };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let back: LaneError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
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
        let json = serde_json::to_string(&cfg).expect("serde deserialization should succeed");
        let back: LaneConfig =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(cfg, back);
    }

    // -----------------------------------------------------------------------
    // bd-38uej: scheduler-side budget enforcer wiring
    // -----------------------------------------------------------------------

    use crate::resource_certificate_consumer::{
        BudgetEnforcementPolicy, BudgetEnforcer, CertificateDigest, CertificateVerdict,
        ExtractedBound,
    };
    use crate::security_epoch::SecurityEpoch;

    fn admission_enforcer(extension_id: &str, time_bound: i64) -> BudgetEnforcer {
        let mut enforcer = BudgetEnforcer::new(
            BudgetEnforcementPolicy::default(),
            SecurityEpoch::from_raw(1),
        );
        enforcer
            .install_certificate(
                extension_id,
                CertificateDigest {
                    certificate_id: format!("cert-{extension_id}"),
                    region_id: format!("region-{extension_id}"),
                    epoch: SecurityEpoch::from_raw(1),
                    verdict: CertificateVerdict::Certified,
                    bounds: vec![
                        ExtractedBound {
                            dimension: EnforcedDimension::Time,
                            upper_bound_millionths: time_bound,
                            is_tight: true,
                            confidence_millionths: 1_000_000,
                        },
                        ExtractedBound {
                            dimension: EnforcedDimension::HostcallCount,
                            upper_bound_millionths: 1_000_000,
                            is_tight: true,
                            confidence_millionths: 1_000_000,
                        },
                    ],
                    abstention_count: 0,
                    min_confidence_millionths: 1_000_000,
                },
            )
            .expect("certificate install should succeed");
        enforcer
    }

    #[test]
    fn submit_for_extension_without_enforcer_matches_submit() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let id = sched
            .submit_for_extension("ext-a", ready_label("trace-a"), 100, "payload-a", 0)
            .expect("submit should succeed when no enforcer is wired");
        assert_eq!(id, TaskId(1));
        assert_eq!(
            sched.metrics.get("ready").map(|m| m.tasks_submitted),
            Some(1)
        );
    }

    #[test]
    fn submit_for_extension_admits_within_budget() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.set_budget_enforcer(admission_enforcer("ext-a", 1_000_000));

        let id = sched
            .submit_for_extension("ext-a", ready_label("trace-a"), 100, "payload-a", 0)
            .expect("admission within budget must succeed");
        assert_eq!(id, TaskId(1));
        assert_eq!(
            sched.metrics.get("ready").map(|m| m.tasks_submitted),
            Some(1)
        );
    }

    #[test]
    fn submit_for_extension_charges_remaining_deadline_slack() {
        let mut baseline = LaneScheduler::new(LaneConfig::default());
        baseline.set_budget_enforcer(admission_enforcer("ext-a", 150));
        baseline
            .submit_for_extension("ext-a", ready_label("trace-a"), 100, "payload-a", 0)
            .expect("baseline admission should succeed");
        let baseline_usage = baseline
            .budget_enforcer
            .as_ref()
            .expect("enforcer should be present")
            .read()
            .extension_state("ext-a")
            .expect("extension state should exist")
            .budgets
            .get(&EnforcedDimension::Time)
            .expect("time budget should exist")
            .current_usage_millionths;
        assert_eq!(baseline_usage, 100);

        let mut shifted = LaneScheduler::new(LaneConfig::default());
        shifted.set_budget_enforcer(admission_enforcer("ext-a", 150));
        shifted
            .submit_for_extension("ext-a", ready_label("trace-b"), 1_000, "payload-b", 900)
            .expect("identical slack must not depend on scheduler uptime");
        let shifted_usage = shifted
            .budget_enforcer
            .as_ref()
            .expect("enforcer should be present")
            .read()
            .extension_state("ext-a")
            .expect("extension state should exist")
            .budgets
            .get(&EnforcedDimension::Time)
            .expect("time budget should exist")
            .current_usage_millionths;
        assert_eq!(shifted_usage, 100);
    }

    #[test]
    fn submit_for_extension_does_not_consume_hostcall_budget_on_admission() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.set_budget_enforcer(admission_enforcer("ext-a", 1_000_000));

        sched
            .submit_for_extension("ext-a", ready_label("trace-a"), 100, "payload-a", 0)
            .expect("admission within budget must succeed");

        let hostcall_usage = sched
            .budget_enforcer
            .as_ref()
            .expect("enforcer should be present")
            .read()
            .extension_state("ext-a")
            .expect("extension state should exist")
            .budgets
            .get(&EnforcedDimension::HostcallCount)
            .expect("hostcall budget should exist")
            .current_usage_millionths;
        assert_eq!(hostcall_usage, 0);
    }

    #[test]
    fn submit_for_extension_rejects_over_budget_without_queueing() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        // Tight Time budget so a single 1_000_000-tick deadline pushes over
        // the policy's reject threshold (1_000_000 millionths == 100%).
        sched.set_budget_enforcer(admission_enforcer("ext-a", 100));

        let result =
            sched.submit_for_extension("ext-a", ready_label("trace-a"), 1_000_000, "payload-a", 0);
        assert!(matches!(result, Err(LaneError::BudgetExceeded { .. })));

        // Critical: rejection must not queue the task or bump submitted metrics.
        assert_eq!(sched.ready_queue.len(), 0);
        assert_eq!(
            sched.metrics.get("ready").map(|m| m.tasks_submitted),
            Some(0)
        );
    }

    #[test]
    fn submit_for_extension_does_not_charge_budget_when_scheduler_rejects() {
        let mut sched = LaneScheduler::new(LaneConfig {
            ready_max_depth: 0,
            ..LaneConfig::default()
        });
        sched.set_budget_enforcer(admission_enforcer("ext-a", 1_000_000));

        let result =
            sched.submit_for_extension("ext-a", ready_label("trace-a"), 100, "payload-a", 0);
        assert!(matches!(result, Err(LaneError::LaneFull { .. })));

        let enforcer = sched
            .budget_enforcer
            .as_ref()
            .expect("enforcer should be present");
        let enforcer = enforcer.read();
        assert_eq!(enforcer.decision_sequence(), 0);
        assert!(enforcer.all_receipts().is_empty());
        let state = enforcer
            .extension_state("ext-a")
            .expect("extension state should exist");
        assert_eq!(state.allow_count, 0);
        assert_eq!(state.throttle_count, 0);
        assert_eq!(state.reject_count, 0);
        let time_budget = state
            .budgets
            .get(&EnforcedDimension::Time)
            .expect("time budget should exist");
        assert_eq!(time_budget.current_usage_millionths, 0);
    }

    #[test]
    fn submit_for_extension_does_not_charge_budget_when_task_id_exhausted() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.set_budget_enforcer(admission_enforcer("ext-a", 1_000_000));
        sched.next_task_id = 0;

        let result =
            sched.submit_for_extension("ext-a", ready_label("trace-a"), 100, "payload-a", 0);
        assert_eq!(result, Err(LaneError::TaskIdExhausted));

        let enforcer = sched
            .budget_enforcer
            .as_ref()
            .expect("enforcer should be present");
        let enforcer = enforcer.read();
        assert_eq!(enforcer.decision_sequence(), 0);
        assert!(enforcer.all_receipts().is_empty());
        let state = enforcer
            .extension_state("ext-a")
            .expect("extension state should exist");
        assert_eq!(state.allow_count, 0);
        assert_eq!(state.throttle_count, 0);
        assert_eq!(state.reject_count, 0);
        let time_budget = state
            .budgets
            .get(&EnforcedDimension::Time)
            .expect("time budget should exist");
        assert_eq!(time_budget.current_usage_millionths, 0);
    }

    #[test]
    fn submit_for_extension_throttled_event_records_actual_queue_position() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched.set_budget_enforcer(admission_enforcer("ext-a", 100));
        sched
            .submit(ready_label("trace-a"), 0, "payload-a", 0)
            .expect("seed submit should succeed");
        sched.drain_events();

        let task_id = sched
            .submit_for_extension("ext-a", ready_label("trace-b"), 95, "payload-b", 0)
            .expect("throttled admission should still succeed");
        let events = sched.drain_events();
        let submit_event = events
            .iter()
            .find(|event| event.event == "submit")
            .expect("submit event should be present");
        assert_eq!(submit_event.queue_position, 1);

        let throttled_event = events
            .iter()
            .find(|event| event.event == "submit_throttled")
            .expect("submit_throttled event should be present");
        assert_eq!(throttled_event.task_id, task_id.0);
        assert_eq!(throttled_event.queue_position, 1);
    }

    // bd-3l528: timed-lane data structure switched from drain+sort+rebuild
    // VecDeque to BTreeMap<u64, VecDeque>. These tests pin the determinism
    // contract that the new min-heap structure must preserve.

    #[test]
    fn timed_lane_preserves_fifo_within_same_deadline_bucket() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        sched
            .submit(timed_label("t1"), 100, "first-at-100", 0)
            .expect("submit should succeed");
        sched
            .submit(timed_label("t2"), 100, "second-at-100", 0)
            .expect("submit should succeed");
        sched
            .submit(timed_label("t3"), 50, "early", 0)
            .expect("submit should succeed");
        sched
            .submit(timed_label("t4"), 100, "third-at-100", 0)
            .expect("submit should succeed");

        let batch = sched.schedule_batch(10, 200);
        let timed_payloads: Vec<_> = batch
            .iter()
            .filter(|t| t.label.lane == SchedulerLane::Timed)
            .map(|t| t.payload_id.as_str())
            .collect();
        assert_eq!(
            timed_payloads,
            vec!["early", "first-at-100", "second-at-100", "third-at-100",],
            "smallest deadline first; FIFO insertion order preserved within each per-deadline bucket"
        );
    }

    #[test]
    fn timed_lane_queue_depth_tracks_btreemap_total_across_buckets() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        for (i, deadline) in [100_u64, 100, 200, 100, 300, 200].iter().enumerate() {
            sched
                .submit(
                    timed_label(&format!("t{i}")),
                    *deadline,
                    &format!("p{i}"),
                    0,
                )
                .expect("submit should succeed");
        }
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 6);
        assert_eq!(sched.total_queue_depth(), 6);

        // Schedule with current_ticks far past every deadline. All 6 should
        // be drained, and the cached length must collapse back to zero.
        let batch = sched.schedule_batch(10, 1_000);
        assert_eq!(batch.len(), 6);
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 0);
        assert_eq!(sched.total_queue_depth(), 0);
    }

    #[test]
    fn timed_lane_partial_batch_leaves_remaining_in_min_heap_order() {
        let mut sched = LaneScheduler::new(LaneConfig::default());
        for (i, deadline) in [50_u64, 100, 150, 200, 250].iter().enumerate() {
            sched
                .submit(
                    timed_label(&format!("t{i}")),
                    *deadline,
                    &format!("p{i}"),
                    0,
                )
                .expect("submit should succeed");
        }

        // batch_size=2, current_ticks=100 → take the two smallest (50, 100).
        // Leftover deadlines 150/200/250 are all > 100, so the timeout
        // sweep does not expire them; they must persist in the queue in
        // min-heap order for the next round.
        let first = sched.schedule_batch(2, 100);
        let timed_first: Vec<_> = first
            .iter()
            .filter(|t| t.label.lane == SchedulerLane::Timed)
            .map(|t| t.payload_id.as_str())
            .collect();
        assert_eq!(timed_first, vec!["p0", "p1"]);
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 3);

        // Next batch advances current_ticks past the rest. The remaining
        // tasks come out in deadline order: 150, 200, 250.
        let second = sched.schedule_batch(10, 300);
        let timed_second: Vec<_> = second
            .iter()
            .filter(|t| t.label.lane == SchedulerLane::Timed)
            .map(|t| t.payload_id.as_str())
            .collect();
        assert_eq!(timed_second, vec!["p2", "p3", "p4"]);
        assert_eq!(sched.queue_depth(SchedulerLane::Timed), 0);
    }

    #[test]
    fn submit_for_extension_unknown_extension_under_default_policy_rejects() {
        // The default BudgetEnforcementPolicy is fail-closed on missing
        // certificates: an extension that has not installed a certificate
        // must be rejected at scheduler admission. This documents the
        // safety contract — opt-in fail-open requires constructing
        // BudgetEnforcementPolicy with `fail_closed_on_missing = false`.
        let mut sched = LaneScheduler::new(LaneConfig::default());
        let enforcer = BudgetEnforcer::new(
            BudgetEnforcementPolicy::default(),
            SecurityEpoch::from_raw(1),
        );
        sched.set_budget_enforcer(enforcer);

        let result =
            sched.submit_for_extension("ext-unknown", ready_label("trace-x"), 100, "payload-x", 0);
        assert!(matches!(result, Err(LaneError::BudgetExceeded { .. })));
        assert_eq!(sched.ready_queue.len(), 0);
    }
}
