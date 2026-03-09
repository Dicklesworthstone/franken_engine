// SPDX-License-Identifier: MIT
//! Swarm Control Loop: daily critical-path recompute, risk-budget reallocation,
//! and execution queue artifact generation.
//!
//! This module implements FRX-11.8: a recurring swarm-control loop that
//! recomputes critical path, rescores ready/near-ready tasks by EV/relevance/risk,
//! assigns wave membership, and produces a top-10 execution queue artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for swarm control loop artifacts.
pub const SWARM_CONTROL_SCHEMA_VERSION: &str = "1.0.0";

/// Maximum number of tasks in the dependency graph.
const MAX_GRAPH_TASKS: usize = 4096;

/// Maximum number of entries in the execution queue.
const MAX_QUEUE_SIZE: usize = 64;

/// Default queue depth for the top-N execution queue.
const DEFAULT_QUEUE_DEPTH: usize = 10;

/// Fixed-point scale: 1.0 = 1_000_000.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Wave assignment
// ---------------------------------------------------------------------------

/// Wave assignment for a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Wave {
    /// All dependencies resolved; can start immediately.
    ReadyNow,
    /// One or two dependencies remain; likely to unblock soon.
    ReadyNext,
    /// Three or more dependencies remain; not yet actionable.
    Gated,
}

impl fmt::Display for Wave {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadyNow => f.write_str("ready_now"),
            Self::ReadyNext => f.write_str("ready_next"),
            Self::Gated => f.write_str("gated"),
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-cutting signals
// ---------------------------------------------------------------------------

/// Aggregated cross-cutting signals from observability, adversarial testing,
/// stability scanning, unit testing, e2e testing, and logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossCuttingSignals {
    /// Observability quality index (0..=MILLION).
    pub observability_quality_millionths: i64,
    /// Catastrophic-tail aggregate CVaR score (lower = safer).
    pub catastrophic_tail_score_millionths: i64,
    /// Bifurcation-distance stability score (higher = more stable).
    pub bifurcation_distance_millionths: i64,
    /// Unit-test depth score (0..=MILLION).
    pub unit_depth_score_millionths: i64,
    /// End-to-end stability score (0..=MILLION).
    pub e2e_stability_score_millionths: i64,
    /// Logging integrity score (0..=MILLION).
    pub logging_integrity_score_millionths: i64,
}

impl Default for CrossCuttingSignals {
    fn default() -> Self {
        Self {
            observability_quality_millionths: MILLION,
            catastrophic_tail_score_millionths: 0,
            bifurcation_distance_millionths: MILLION,
            unit_depth_score_millionths: MILLION,
            e2e_stability_score_millionths: MILLION,
            logging_integrity_score_millionths: MILLION,
        }
    }
}

impl CrossCuttingSignals {
    /// Compute a composite health score (0..=MILLION).
    /// Equally weights positive signals and penalises catastrophic-tail risk.
    pub fn composite_health_millionths(&self) -> i64 {
        let positive_sum = self.observability_quality_millionths
            + self.bifurcation_distance_millionths
            + self.unit_depth_score_millionths
            + self.e2e_stability_score_millionths
            + self.logging_integrity_score_millionths;
        let avg_positive = positive_sum / 5;
        // Subtract tail risk (clamped so we don't go negative)
        (avg_positive - self.catastrophic_tail_score_millionths).max(0)
    }
}

impl fmt::Display for CrossCuttingSignals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "signals(obs={}, tail={}, bifurc={}, unit={}, e2e={}, log={})",
            self.observability_quality_millionths,
            self.catastrophic_tail_score_millionths,
            self.bifurcation_distance_millionths,
            self.unit_depth_score_millionths,
            self.e2e_stability_score_millionths,
            self.logging_integrity_score_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// Task node in the dependency graph
// ---------------------------------------------------------------------------

/// A single task in the swarm dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskNode {
    /// Unique task identifier.
    pub task_id: String,
    /// Human-readable title.
    pub title: String,
    /// IDs of tasks this one depends on (must complete before this one).
    pub depends_on: BTreeSet<String>,
    /// IDs of tasks that depend on this one.
    pub dependents: BTreeSet<String>,
    /// Whether this task is already completed.
    pub completed: bool,
    /// Expected impact score (0..=MILLION).
    pub impact_millionths: i64,
    /// Confidence in the impact estimate (0..=MILLION).
    pub confidence_millionths: i64,
    /// Reuse potential (0..=MILLION).
    pub reuse_millionths: i64,
    /// Estimated effort (0..=MILLION, higher = more effort).
    pub effort_millionths: i64,
    /// Implementation friction (0..=MILLION).
    pub friction_millionths: i64,
    /// Primary risk description.
    pub primary_risk: String,
    /// Countermeasure for the primary risk.
    pub countermeasure: String,
    /// Fallback trigger condition.
    pub fallback_trigger: String,
    /// Suggested first action.
    pub first_action: String,
    /// Assignee (empty if unassigned).
    pub assignee: String,
}

impl TaskNode {
    /// Compute EV score: impact × confidence / MILLION − friction.
    pub fn ev_millionths(&self) -> i64 {
        let raw_ev = (self.impact_millionths as i128 * self.confidence_millionths as i128
            / MILLION as i128) as i64;
        raw_ev - self.friction_millionths
    }

    /// Relevance score incorporating impact, confidence, reuse, and
    /// penalising effort and friction.
    pub fn relevance_millionths(&self) -> i64 {
        let ev = self.ev_millionths();
        let reuse_bonus = self.reuse_millionths / 4; // 25% weight
        let effort_penalty = self.effort_millionths / 2; // 50% weight
        (ev + reuse_bonus - effort_penalty).max(0)
    }
}

impl fmt::Display for TaskNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "task({}, ev={}, rel={}, done={})",
            self.task_id,
            self.ev_millionths(),
            self.relevance_millionths(),
            self.completed
        )
    }
}

// ---------------------------------------------------------------------------
// Execution queue entry
// ---------------------------------------------------------------------------

/// A single entry in the top-N execution queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueEntry {
    /// Rank in the queue (1-based).
    pub rank: u64,
    /// Task identifier.
    pub task_id: String,
    /// Task title.
    pub title: String,
    /// Impact score.
    pub impact_millionths: i64,
    /// Confidence score.
    pub confidence_millionths: i64,
    /// Reuse potential.
    pub reuse_millionths: i64,
    /// Effort estimate.
    pub effort_millionths: i64,
    /// Friction estimate.
    pub friction_millionths: i64,
    /// Computed EV.
    pub ev_millionths: i64,
    /// Computed relevance.
    pub relevance_millionths: i64,
    /// Primary risk description.
    pub primary_risk: String,
    /// Countermeasure.
    pub countermeasure: String,
    /// Fallback trigger condition.
    pub fallback_trigger: String,
    /// Suggested first action.
    pub first_action: String,
    /// Wave assignment.
    pub wave: Wave,
    /// Number of open (uncompleted) blockers.
    pub open_blocker_count: u64,
}

impl fmt::Display for QueueEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{}: {} (ev={}, rel={}, wave={})",
            self.rank, self.task_id, self.ev_millionths, self.relevance_millionths, self.wave
        )
    }
}

// ---------------------------------------------------------------------------
// Rationale delta
// ---------------------------------------------------------------------------

/// Records why the queue order changed between recomputation cycles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RationaleDelta {
    /// Task whose rank changed.
    pub task_id: String,
    /// Previous rank (0 = was not in queue).
    pub previous_rank: u64,
    /// New rank (0 = dropped from queue).
    pub new_rank: u64,
    /// Human-readable reason for the change.
    pub reason: String,
}

impl fmt::Display for RationaleDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "delta({}: {} → {}, {})",
            self.task_id, self.previous_rank, self.new_rank, self.reason
        )
    }
}

// ---------------------------------------------------------------------------
// Bottleneck report
// ---------------------------------------------------------------------------

/// A detected bottleneck in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bottleneck {
    /// Task that is a bottleneck.
    pub task_id: String,
    /// Number of downstream tasks that depend (transitively) on this one.
    pub downstream_count: u64,
    /// Whether the task is currently unassigned.
    pub unassigned: bool,
    /// Severity classification.
    pub severity: BottleneckSeverity,
}

/// Severity of a bottleneck.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BottleneckSeverity {
    /// Blocks fewer than 3 downstream tasks.
    Low,
    /// Blocks 3–9 downstream tasks.
    Medium,
    /// Blocks 10 or more downstream tasks.
    High,
    /// Blocks 10+ and is unassigned.
    Critical,
}

impl fmt::Display for BottleneckSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

impl fmt::Display for Bottleneck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bottleneck({}, downstream={}, severity={})",
            self.task_id, self.downstream_count, self.severity
        )
    }
}

// ---------------------------------------------------------------------------
// Risk budget state
// ---------------------------------------------------------------------------

/// Swarm-level risk budget tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRiskBudget {
    /// Total risk budget remaining (0..=MILLION).
    pub remaining_millionths: i64,
    /// Consumed risk budget.
    pub consumed_millionths: i64,
    /// Whether conservative mode has been triggered.
    pub conservative_mode: bool,
    /// Threshold below which conservative mode is activated.
    pub conservative_threshold_millionths: i64,
}

impl Default for SwarmRiskBudget {
    fn default() -> Self {
        Self {
            remaining_millionths: MILLION,
            consumed_millionths: 0,
            conservative_mode: false,
            conservative_threshold_millionths: 200_000,
        }
    }
}

impl SwarmRiskBudget {
    /// Consume a portion of the risk budget.
    /// Returns true if conservative mode was triggered by this consumption.
    pub fn consume(&mut self, amount_millionths: i64) -> bool {
        let clamped = amount_millionths.max(0).min(self.remaining_millionths);
        self.consumed_millionths += clamped;
        self.remaining_millionths -= clamped;
        if !self.conservative_mode
            && self.remaining_millionths <= self.conservative_threshold_millionths
        {
            self.conservative_mode = true;
            return true;
        }
        false
    }

    /// Reallocate risk budget with fresh capacity.
    pub fn reallocate(&mut self, new_total_millionths: i64) {
        let total = new_total_millionths.clamp(0, MILLION);
        self.remaining_millionths = total - self.consumed_millionths.min(total);
        self.conservative_mode =
            self.remaining_millionths <= self.conservative_threshold_millionths;
    }
}

impl fmt::Display for SwarmRiskBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "risk_budget(remaining={}, consumed={}, conservative={})",
            self.remaining_millionths, self.consumed_millionths, self.conservative_mode
        )
    }
}

// ---------------------------------------------------------------------------
// Queue artifact
// ---------------------------------------------------------------------------

/// The top-level queue artifact produced by each control loop iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueArtifact {
    /// Schema version.
    pub schema_version: String,
    /// Epoch at which this artifact was generated.
    pub epoch: SecurityEpoch,
    /// Timestamp (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Ordered execution queue (top-N).
    pub queue: Vec<QueueEntry>,
    /// Cross-cutting signal snapshot.
    pub signals: CrossCuttingSignals,
    /// Detected bottlenecks.
    pub bottlenecks: Vec<Bottleneck>,
    /// Risk budget state.
    pub risk_budget: SwarmRiskBudget,
    /// Rationale deltas from previous iteration.
    pub rationale_deltas: Vec<RationaleDelta>,
    /// Evidence IDs linked to this artifact.
    pub evidence_ids: Vec<String>,
    /// Total tasks in graph.
    pub total_tasks: u64,
    /// Completed tasks.
    pub completed_tasks: u64,
    /// Tasks in ready_now wave.
    pub ready_now_count: u64,
    /// Tasks in ready_next wave.
    pub ready_next_count: u64,
    /// Tasks in gated wave.
    pub gated_count: u64,
    /// Deterministic artifact hash.
    pub artifact_hash: ContentHash,
}

impl QueueArtifact {
    /// Completion percentage in millionths.
    pub fn completion_millionths(&self) -> i64 {
        if self.total_tasks == 0 {
            return MILLION;
        }
        (self.completed_tasks as i64 * MILLION) / self.total_tasks as i64
    }

    /// Whether conservative mode is active.
    pub fn is_conservative(&self) -> bool {
        self.risk_budget.conservative_mode
    }

    /// Number of critical bottlenecks.
    pub fn critical_bottleneck_count(&self) -> usize {
        self.bottlenecks
            .iter()
            .filter(|b| b.severity == BottleneckSeverity::Critical)
            .count()
    }
}

impl fmt::Display for QueueArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "queue_artifact(epoch={}, tasks={}/{}, ready_now={}, bottlenecks={}, conservative={})",
            self.epoch.as_u64(),
            self.completed_tasks,
            self.total_tasks,
            self.ready_now_count,
            self.bottlenecks.len(),
            self.risk_budget.conservative_mode
        )
    }
}

// ---------------------------------------------------------------------------
// Controller config and errors
// ---------------------------------------------------------------------------

/// Configuration for the swarm control loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlLoopConfig {
    /// Maximum queue depth.
    pub queue_depth: usize,
    /// Minimum composite health for non-conservative operation.
    pub min_health_millionths: i64,
    /// Risk budget conservative-mode threshold.
    pub conservative_threshold_millionths: i64,
    /// Number of open blockers for ready_next classification (max).
    pub ready_next_max_blockers: u64,
    /// Whether to include gated tasks in the queue.
    pub include_gated_in_queue: bool,
}

impl Default for ControlLoopConfig {
    fn default() -> Self {
        Self {
            queue_depth: DEFAULT_QUEUE_DEPTH,
            min_health_millionths: 400_000,
            conservative_threshold_millionths: 200_000,
            ready_next_max_blockers: 2,
            include_gated_in_queue: false,
        }
    }
}

/// Errors from the swarm control loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlLoopError {
    /// Dependency graph is empty.
    EmptyGraph,
    /// Too many tasks in the graph.
    TooManyTasks { count: usize, max: usize },
    /// Cycle detected in the dependency graph.
    CycleDetected { involved: Vec<String> },
    /// Unknown task referenced as a dependency.
    UnknownDependency {
        task_id: String,
        dependency_id: String,
    },
    /// Invalid configuration value.
    InvalidConfig { detail: String },
}

impl fmt::Display for ControlLoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGraph => f.write_str("dependency graph is empty"),
            Self::TooManyTasks { count, max } => {
                write!(f, "too many tasks: {count} exceeds max {max}")
            }
            Self::CycleDetected { involved } => {
                write!(f, "cycle detected involving: {}", involved.join(", "))
            }
            Self::UnknownDependency {
                task_id,
                dependency_id,
            } => {
                write!(f, "task {task_id} depends on unknown {dependency_id}")
            }
            Self::InvalidConfig { detail } => {
                write!(f, "invalid config: {detail}")
            }
        }
    }
}

impl std::error::Error for ControlLoopError {}

// ---------------------------------------------------------------------------
// Swarm control loop
// ---------------------------------------------------------------------------

/// The swarm control loop controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmControlLoop {
    /// Configuration.
    pub config: ControlLoopConfig,
    /// Current epoch.
    pub epoch: SecurityEpoch,
    /// Task graph (task_id → TaskNode).
    pub graph: BTreeMap<String, TaskNode>,
    /// Risk budget state.
    pub risk_budget: SwarmRiskBudget,
    /// Previous queue (for computing rationale deltas).
    previous_queue: Vec<QueueEntry>,
    /// Number of recomputation iterations performed.
    pub iteration_count: u64,
}

impl SwarmControlLoop {
    /// Create a new swarm control loop.
    pub fn new(config: ControlLoopConfig) -> Result<Self, ControlLoopError> {
        if config.queue_depth == 0 || config.queue_depth > MAX_QUEUE_SIZE {
            return Err(ControlLoopError::InvalidConfig {
                detail: format!(
                    "queue_depth {} must be in 1..={}",
                    config.queue_depth, MAX_QUEUE_SIZE
                ),
            });
        }
        if config.min_health_millionths < 0 || config.min_health_millionths > MILLION {
            return Err(ControlLoopError::InvalidConfig {
                detail: format!(
                    "min_health_millionths {} must be in 0..={}",
                    config.min_health_millionths, MILLION
                ),
            });
        }
        let risk_budget = SwarmRiskBudget {
            conservative_threshold_millionths: config.conservative_threshold_millionths,
            ..Default::default()
        };
        Ok(Self {
            config,
            epoch: SecurityEpoch::from_raw(0),
            graph: BTreeMap::new(),
            risk_budget,
            previous_queue: Vec::new(),
            iteration_count: 0,
        })
    }

    /// Add a task to the dependency graph.
    pub fn add_task(&mut self, task: TaskNode) -> Result<(), ControlLoopError> {
        if self.graph.len() >= MAX_GRAPH_TASKS {
            return Err(ControlLoopError::TooManyTasks {
                count: self.graph.len() + 1,
                max: MAX_GRAPH_TASKS,
            });
        }
        self.graph.insert(task.task_id.clone(), task);
        Ok(())
    }

    /// Mark a task as completed.
    pub fn complete_task(&mut self, task_id: &str) -> bool {
        if let Some(node) = self.graph.get_mut(task_id) {
            node.completed = true;
            true
        } else {
            false
        }
    }

    /// Validate the graph: check for unknown dependencies and cycles.
    pub fn validate(&self) -> Result<(), ControlLoopError> {
        if self.graph.is_empty() {
            return Err(ControlLoopError::EmptyGraph);
        }

        // Check for unknown dependencies.
        for (task_id, node) in &self.graph {
            for dep_id in &node.depends_on {
                if !self.graph.contains_key(dep_id) {
                    return Err(ControlLoopError::UnknownDependency {
                        task_id: task_id.clone(),
                        dependency_id: dep_id.clone(),
                    });
                }
            }
        }

        // Cycle detection via iterative removal.
        let mut remaining: BTreeSet<&str> = self.graph.keys().map(String::as_str).collect();
        let mut progress = true;
        while progress {
            progress = false;
            let snapshot: Vec<&str> = remaining.iter().copied().collect();
            for id in snapshot {
                let node = &self.graph[id];
                let all_deps_resolved = node.depends_on.iter().all(|d| {
                    !remaining.contains(d.as_str()) || self.graph.get(d).is_none_or(|n| n.completed)
                });
                if all_deps_resolved || node.completed {
                    remaining.remove(id);
                    progress = true;
                }
            }
        }

        if !remaining.is_empty() {
            return Err(ControlLoopError::CycleDetected {
                involved: remaining.iter().map(|s| s.to_string()).collect(),
            });
        }

        Ok(())
    }

    /// Compute the wave assignment for a task.
    fn wave_for(&self, node: &TaskNode) -> Wave {
        if node.completed {
            return Wave::ReadyNow;
        }
        let open_blockers = self.open_blocker_count(node);
        if open_blockers == 0 {
            Wave::ReadyNow
        } else if open_blockers <= self.config.ready_next_max_blockers {
            Wave::ReadyNext
        } else {
            Wave::Gated
        }
    }

    /// Count open (uncompleted) blockers for a task.
    fn open_blocker_count(&self, node: &TaskNode) -> u64 {
        node.depends_on
            .iter()
            .filter(|dep_id| {
                self.graph
                    .get(dep_id.as_str())
                    .is_some_and(|d| !d.completed)
            })
            .count() as u64
    }

    /// Compute transitive downstream count for a task.
    fn downstream_count(&self, task_id: &str) -> u64 {
        let mut visited = BTreeSet::new();
        let mut stack = vec![task_id.to_string()];
        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(node) = self.graph.get(&current) {
                for dep_id in &node.dependents {
                    if !visited.contains(dep_id) {
                        stack.push(dep_id.clone());
                    }
                }
            }
        }
        // Subtract 1 to exclude the task itself.
        visited.len().saturating_sub(1) as u64
    }

    /// Detect bottlenecks in the graph.
    fn detect_bottlenecks(&self) -> Vec<Bottleneck> {
        let mut bottlenecks = Vec::new();
        for (task_id, node) in &self.graph {
            if node.completed {
                continue;
            }
            let downstream = self.downstream_count(task_id);
            if downstream == 0 {
                continue;
            }
            let unassigned = node.assignee.is_empty();
            let severity = if downstream >= 10 && unassigned {
                BottleneckSeverity::Critical
            } else if downstream >= 10 {
                BottleneckSeverity::High
            } else if downstream >= 3 {
                BottleneckSeverity::Medium
            } else {
                BottleneckSeverity::Low
            };
            bottlenecks.push(Bottleneck {
                task_id: task_id.clone(),
                downstream_count: downstream,
                unassigned,
                severity,
            });
        }
        bottlenecks.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.downstream_count.cmp(&a.downstream_count))
        });
        bottlenecks
    }

    /// Build a queue entry from a task node.
    fn build_entry(&self, node: &TaskNode, rank: u64) -> QueueEntry {
        QueueEntry {
            rank,
            task_id: node.task_id.clone(),
            title: node.title.clone(),
            impact_millionths: node.impact_millionths,
            confidence_millionths: node.confidence_millionths,
            reuse_millionths: node.reuse_millionths,
            effort_millionths: node.effort_millionths,
            friction_millionths: node.friction_millionths,
            ev_millionths: node.ev_millionths(),
            relevance_millionths: node.relevance_millionths(),
            primary_risk: node.primary_risk.clone(),
            countermeasure: node.countermeasure.clone(),
            fallback_trigger: node.fallback_trigger.clone(),
            first_action: node.first_action.clone(),
            wave: self.wave_for(node),
            open_blocker_count: self.open_blocker_count(node),
        }
    }

    /// Compute rationale deltas between previous and new queue.
    fn compute_deltas(&self, new_queue: &[QueueEntry]) -> Vec<RationaleDelta> {
        let mut deltas = Vec::new();
        let prev_ranks: BTreeMap<&str, u64> = self
            .previous_queue
            .iter()
            .map(|e| (e.task_id.as_str(), e.rank))
            .collect();
        let new_ranks: BTreeMap<&str, u64> = new_queue
            .iter()
            .map(|e| (e.task_id.as_str(), e.rank))
            .collect();

        // Tasks that moved or appeared.
        for entry in new_queue {
            let prev = prev_ranks.get(entry.task_id.as_str()).copied().unwrap_or(0);
            if prev != entry.rank {
                let reason = if prev == 0 {
                    "entered queue".to_string()
                } else if entry.rank < prev {
                    "promoted (higher EV/relevance)".to_string()
                } else {
                    "demoted (lower EV/relevance)".to_string()
                };
                deltas.push(RationaleDelta {
                    task_id: entry.task_id.clone(),
                    previous_rank: prev,
                    new_rank: entry.rank,
                    reason,
                });
            }
        }

        // Tasks that dropped out.
        for prev_entry in &self.previous_queue {
            if !new_ranks.contains_key(prev_entry.task_id.as_str()) {
                deltas.push(RationaleDelta {
                    task_id: prev_entry.task_id.clone(),
                    previous_rank: prev_entry.rank,
                    new_rank: 0,
                    reason: "dropped from queue".to_string(),
                });
            }
        }

        deltas
    }

    /// Run one iteration of the control loop and produce a queue artifact.
    pub fn recompute(
        &mut self,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
        signals: CrossCuttingSignals,
        evidence_ids: Vec<String>,
    ) -> Result<QueueArtifact, ControlLoopError> {
        self.validate()?;
        self.epoch = epoch;

        // Check if health is below threshold → force conservative mode.
        let health = signals.composite_health_millionths();
        if health < self.config.min_health_millionths {
            let deficit = self.config.min_health_millionths - health;
            self.risk_budget.consume(deficit);
        }

        // Collect non-completed tasks and sort by relevance.
        let mut candidates: Vec<&TaskNode> = self.graph.values().filter(|n| !n.completed).collect();

        candidates.sort_by(|a, b| {
            let wave_a = self.wave_for(a);
            let wave_b = self.wave_for(b);
            wave_a
                .cmp(&wave_b)
                .then_with(|| b.relevance_millionths().cmp(&a.relevance_millionths()))
                .then_with(|| b.ev_millionths().cmp(&a.ev_millionths()))
        });

        // Filter based on config.
        if !self.config.include_gated_in_queue {
            candidates.retain(|n| self.wave_for(n) != Wave::Gated);
        }

        // Build queue entries.
        let queue: Vec<QueueEntry> = candidates
            .iter()
            .take(self.config.queue_depth)
            .enumerate()
            .map(|(i, node)| self.build_entry(node, (i + 1) as u64))
            .collect();

        // Compute rationale deltas.
        let deltas = self.compute_deltas(&queue);

        // Detect bottlenecks.
        let bottlenecks = self.detect_bottlenecks();

        // Compute wave counts.
        let total_tasks = self.graph.len() as u64;
        let completed_tasks = self.graph.values().filter(|n| n.completed).count() as u64;
        let ready_now_count = self
            .graph
            .values()
            .filter(|n| !n.completed && self.wave_for(n) == Wave::ReadyNow)
            .count() as u64;
        let ready_next_count = self
            .graph
            .values()
            .filter(|n| !n.completed && self.wave_for(n) == Wave::ReadyNext)
            .count() as u64;
        let gated_count = self
            .graph
            .values()
            .filter(|n| !n.completed && self.wave_for(n) == Wave::Gated)
            .count() as u64;

        // Compute artifact hash.
        let hash_input = serde_json::to_vec(&(&queue, &signals, &bottlenecks, &self.risk_budget))
            .unwrap_or_default();
        let artifact_hash = ContentHash::compute(&hash_input);

        // Save current queue for next iteration's delta computation.
        self.previous_queue = queue.clone();
        self.iteration_count += 1;

        Ok(QueueArtifact {
            schema_version: SWARM_CONTROL_SCHEMA_VERSION.to_string(),
            epoch,
            timestamp_ns,
            queue,
            signals,
            bottlenecks,
            risk_budget: self.risk_budget.clone(),
            rationale_deltas: deltas,
            evidence_ids,
            total_tasks,
            completed_tasks,
            ready_now_count,
            ready_next_count,
            gated_count,
            artifact_hash,
        })
    }

    /// Number of tasks in the graph.
    pub fn task_count(&self) -> usize {
        self.graph.len()
    }

    /// Number of completed tasks.
    pub fn completed_count(&self) -> usize {
        self.graph.values().filter(|n| n.completed).count()
    }
}

impl fmt::Display for SwarmControlLoop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "swarm_control(epoch={}, tasks={}, completed={}, iterations={})",
            self.epoch.as_u64(),
            self.graph.len(),
            self.completed_count(),
            self.iteration_count
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(id: &str, deps: &[&str]) -> TaskNode {
        TaskNode {
            task_id: id.to_string(),
            title: format!("Task {id}"),
            depends_on: deps.iter().map(|d| d.to_string()).collect(),
            dependents: BTreeSet::new(),
            completed: false,
            impact_millionths: 800_000,
            confidence_millionths: 900_000,
            reuse_millionths: 200_000,
            effort_millionths: 300_000,
            friction_millionths: 100_000,
            primary_risk: "none".to_string(),
            countermeasure: "n/a".to_string(),
            fallback_trigger: "never".to_string(),
            first_action: "start".to_string(),
            assignee: "agent-1".to_string(),
        }
    }

    fn make_unassigned_task(id: &str, deps: &[&str]) -> TaskNode {
        let mut t = make_task(id, deps);
        t.assignee = String::new();
        t
    }

    fn default_loop() -> SwarmControlLoop {
        SwarmControlLoop::new(ControlLoopConfig::default()).unwrap()
    }

    fn add_chain(ctrl: &mut SwarmControlLoop, ids: &[&str]) {
        for (i, id) in ids.iter().enumerate() {
            let deps: Vec<&str> = if i > 0 { vec![ids[i - 1]] } else { vec![] };
            let mut task = make_task(id, &deps);
            // Wire up dependents for the previous task.
            if i > 0
                && let Some(prev) = ctrl.graph.get_mut(ids[i - 1])
            {
                prev.dependents.insert(id.to_string());
            }
            task.dependents = if i + 1 < ids.len() {
                let mut s = BTreeSet::new();
                s.insert(ids[i + 1].to_string());
                s
            } else {
                BTreeSet::new()
            };
            ctrl.add_task(task).unwrap();
        }
    }

    // ── Wave tests ─────────────────────────────────────────────────────

    #[test]
    fn wave_display() {
        assert_eq!(Wave::ReadyNow.to_string(), "ready_now");
        assert_eq!(Wave::ReadyNext.to_string(), "ready_next");
        assert_eq!(Wave::Gated.to_string(), "gated");
    }

    #[test]
    fn wave_serde_roundtrip() {
        for w in [Wave::ReadyNow, Wave::ReadyNext, Wave::Gated] {
            let json = serde_json::to_string(&w).unwrap();
            let back: Wave = serde_json::from_str(&json).unwrap();
            assert_eq!(back, w);
        }
    }

    #[test]
    fn wave_ordering() {
        assert!(Wave::ReadyNow < Wave::ReadyNext);
        assert!(Wave::ReadyNext < Wave::Gated);
    }

    // ── CrossCuttingSignals tests ──────────────────────────────────────

    #[test]
    fn signals_default_is_healthy() {
        let s = CrossCuttingSignals::default();
        assert_eq!(s.composite_health_millionths(), MILLION);
    }

    #[test]
    fn signals_composite_health_penalises_tail_risk() {
        let s = CrossCuttingSignals {
            catastrophic_tail_score_millionths: 500_000,
            ..Default::default()
        };
        assert_eq!(s.composite_health_millionths(), 500_000);
    }

    #[test]
    fn signals_composite_health_floors_at_zero() {
        let s = CrossCuttingSignals {
            catastrophic_tail_score_millionths: 2_000_000,
            ..Default::default()
        };
        assert_eq!(s.composite_health_millionths(), 0);
    }

    #[test]
    fn signals_display() {
        let s = CrossCuttingSignals::default();
        let d = s.to_string();
        assert!(d.contains("obs="));
        assert!(d.contains("tail="));
    }

    #[test]
    fn signals_serde_roundtrip() {
        let s = CrossCuttingSignals::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: CrossCuttingSignals = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    // ── TaskNode tests ─────────────────────────────────────────────────

    #[test]
    fn task_node_ev_computation() {
        let t = make_task("t1", &[]);
        // EV = impact * confidence / MILLION - friction
        // = 800_000 * 900_000 / 1_000_000 - 100_000
        // = 720_000 - 100_000 = 620_000
        assert_eq!(t.ev_millionths(), 620_000);
    }

    #[test]
    fn task_node_relevance_computation() {
        let t = make_task("t1", &[]);
        let ev = t.ev_millionths();
        let reuse_bonus = t.reuse_millionths / 4;
        let effort_penalty = t.effort_millionths / 2;
        assert_eq!(t.relevance_millionths(), ev + reuse_bonus - effort_penalty);
    }

    #[test]
    fn task_node_display() {
        let t = make_task("t1", &[]);
        let d = t.to_string();
        assert!(d.contains("t1"));
        assert!(d.contains("ev="));
        assert!(d.contains("done=false"));
    }

    #[test]
    fn task_node_serde_roundtrip() {
        let t = make_task("t1", &["dep1"]);
        let json = serde_json::to_string(&t).unwrap();
        let back: TaskNode = serde_json::from_str(&json).unwrap();
        assert_eq!(back.task_id, t.task_id);
        assert_eq!(back.depends_on, t.depends_on);
    }

    // ── QueueEntry tests ───────────────────────────────────────────────

    #[test]
    fn queue_entry_display() {
        let e = QueueEntry {
            rank: 1,
            task_id: "t1".to_string(),
            title: "Task 1".to_string(),
            impact_millionths: 800_000,
            confidence_millionths: 900_000,
            reuse_millionths: 200_000,
            effort_millionths: 300_000,
            friction_millionths: 100_000,
            ev_millionths: 620_000,
            relevance_millionths: 520_000,
            primary_risk: "none".to_string(),
            countermeasure: "n/a".to_string(),
            fallback_trigger: "never".to_string(),
            first_action: "start".to_string(),
            wave: Wave::ReadyNow,
            open_blocker_count: 0,
        };
        let d = e.to_string();
        assert!(d.contains("#1"));
        assert!(d.contains("t1"));
        assert!(d.contains("ready_now"));
    }

    // ── RationaleDelta tests ───────────────────────────────────────────

    #[test]
    fn rationale_delta_display() {
        let d = RationaleDelta {
            task_id: "t1".to_string(),
            previous_rank: 3,
            new_rank: 1,
            reason: "promoted".to_string(),
        };
        assert!(d.to_string().contains("3 → 1"));
    }

    // ── Bottleneck tests ───────────────────────────────────────────────

    #[test]
    fn bottleneck_severity_ordering() {
        assert!(BottleneckSeverity::Low < BottleneckSeverity::Medium);
        assert!(BottleneckSeverity::Medium < BottleneckSeverity::High);
        assert!(BottleneckSeverity::High < BottleneckSeverity::Critical);
    }

    #[test]
    fn bottleneck_severity_display() {
        assert_eq!(BottleneckSeverity::Low.to_string(), "low");
        assert_eq!(BottleneckSeverity::Medium.to_string(), "medium");
        assert_eq!(BottleneckSeverity::High.to_string(), "high");
        assert_eq!(BottleneckSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn bottleneck_display() {
        let b = Bottleneck {
            task_id: "t1".to_string(),
            downstream_count: 5,
            unassigned: false,
            severity: BottleneckSeverity::Medium,
        };
        assert!(b.to_string().contains("downstream=5"));
    }

    // ── SwarmRiskBudget tests ──────────────────────────────────────────

    #[test]
    fn risk_budget_default() {
        let b = SwarmRiskBudget::default();
        assert_eq!(b.remaining_millionths, MILLION);
        assert_eq!(b.consumed_millionths, 0);
        assert!(!b.conservative_mode);
    }

    #[test]
    fn risk_budget_consume_triggers_conservative() {
        let mut b = SwarmRiskBudget::default();
        let triggered = b.consume(850_000);
        assert!(triggered);
        assert!(b.conservative_mode);
        assert_eq!(b.remaining_millionths, 150_000);
    }

    #[test]
    fn risk_budget_consume_does_not_overshoot() {
        let mut b = SwarmRiskBudget::default();
        b.consume(MILLION + 100);
        assert_eq!(b.remaining_millionths, 0);
        assert_eq!(b.consumed_millionths, MILLION);
    }

    #[test]
    fn risk_budget_reallocate() {
        let mut b = SwarmRiskBudget::default();
        b.consume(600_000);
        b.reallocate(800_000);
        assert_eq!(b.remaining_millionths, 200_000);
        assert!(b.conservative_mode); // 200_000 <= 200_000 threshold
    }

    #[test]
    fn risk_budget_serde_roundtrip() {
        let b = SwarmRiskBudget::default();
        let json = serde_json::to_string(&b).unwrap();
        let back: SwarmRiskBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn risk_budget_display() {
        let b = SwarmRiskBudget::default();
        assert!(b.to_string().contains("remaining="));
    }

    // ── ControlLoopConfig tests ────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let c = ControlLoopConfig::default();
        assert_eq!(c.queue_depth, 10);
        assert_eq!(c.ready_next_max_blockers, 2);
        assert!(!c.include_gated_in_queue);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = ControlLoopConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: ControlLoopConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    // ── ControlLoopError tests ─────────────────────────────────────────

    #[test]
    fn error_display_all_variants() {
        let errors = [
            (ControlLoopError::EmptyGraph, "empty"),
            (
                ControlLoopError::TooManyTasks {
                    count: 5000,
                    max: 4096,
                },
                "5000",
            ),
            (
                ControlLoopError::CycleDetected {
                    involved: vec!["a".to_string(), "b".to_string()],
                },
                "cycle",
            ),
            (
                ControlLoopError::UnknownDependency {
                    task_id: "t1".to_string(),
                    dependency_id: "t99".to_string(),
                },
                "unknown",
            ),
            (
                ControlLoopError::InvalidConfig {
                    detail: "bad".to_string(),
                },
                "invalid",
            ),
        ];
        let mut seen = BTreeSet::new();
        for (err, keyword) in &errors {
            let s = err.to_string();
            assert!(s.contains(keyword), "expected '{keyword}' in '{s}'");
            assert!(seen.insert(s));
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ControlLoopError::EmptyGraph);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = ControlLoopError::TooManyTasks {
            count: 5000,
            max: 4096,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: ControlLoopError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
    }

    // ── SwarmControlLoop construction tests ────────────────────────────

    #[test]
    fn new_creates_loop() {
        let ctrl = default_loop();
        assert_eq!(ctrl.task_count(), 0);
        assert_eq!(ctrl.iteration_count, 0);
    }

    #[test]
    fn new_rejects_zero_queue_depth() {
        let result = SwarmControlLoop::new(ControlLoopConfig {
            queue_depth: 0,
            ..Default::default()
        });
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_excessive_queue_depth() {
        let result = SwarmControlLoop::new(ControlLoopConfig {
            queue_depth: MAX_QUEUE_SIZE + 1,
            ..Default::default()
        });
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_negative_health() {
        let result = SwarmControlLoop::new(ControlLoopConfig {
            min_health_millionths: -1,
            ..Default::default()
        });
        assert!(result.is_err());
    }

    // ── Graph manipulation tests ───────────────────────────────────────

    #[test]
    fn add_task_and_count() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        assert_eq!(ctrl.task_count(), 1);
    }

    #[test]
    fn complete_task_updates_status() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        assert!(ctrl.complete_task("t1"));
        assert_eq!(ctrl.completed_count(), 1);
    }

    #[test]
    fn complete_unknown_task_returns_false() {
        let mut ctrl = default_loop();
        assert!(!ctrl.complete_task("nonexistent"));
    }

    // ── Validation tests ───────────────────────────────────────────────

    #[test]
    fn validate_empty_graph_fails() {
        let ctrl = default_loop();
        assert!(matches!(ctrl.validate(), Err(ControlLoopError::EmptyGraph)));
    }

    #[test]
    fn validate_unknown_dependency_fails() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &["unknown"])).unwrap();
        assert!(matches!(
            ctrl.validate(),
            Err(ControlLoopError::UnknownDependency { .. })
        ));
    }

    #[test]
    fn validate_cycle_detected() {
        let mut ctrl = default_loop();
        let mut t1 = make_task("t1", &["t2"]);
        let mut t2 = make_task("t2", &["t1"]);
        t1.dependents.insert("t2".to_string());
        t2.dependents.insert("t1".to_string());
        ctrl.add_task(t1).unwrap();
        ctrl.add_task(t2).unwrap();
        assert!(matches!(
            ctrl.validate(),
            Err(ControlLoopError::CycleDetected { .. })
        ));
    }

    #[test]
    fn validate_valid_chain_ok() {
        let mut ctrl = default_loop();
        add_chain(&mut ctrl, &["t1", "t2", "t3"]);
        assert!(ctrl.validate().is_ok());
    }

    // ── Wave assignment tests ──────────────────────────────────────────

    #[test]
    fn wave_ready_now_no_deps() {
        let ctrl = default_loop();
        let t = make_task("t1", &[]);
        assert_eq!(ctrl.wave_for(&t), Wave::ReadyNow);
    }

    #[test]
    fn wave_ready_next_one_blocker() {
        let mut ctrl = default_loop();
        add_chain(&mut ctrl, &["dep1", "t1"]);
        let t1 = ctrl.graph.get("t1").unwrap();
        assert_eq!(ctrl.wave_for(t1), Wave::ReadyNext);
    }

    #[test]
    fn wave_gated_many_blockers() {
        let mut ctrl = default_loop();
        let mut t = make_task("t1", &["d1", "d2", "d3"]);
        ctrl.add_task(make_task("d1", &[])).unwrap();
        ctrl.add_task(make_task("d2", &[])).unwrap();
        ctrl.add_task(make_task("d3", &[])).unwrap();
        t.dependents = BTreeSet::new();
        ctrl.add_task(t).unwrap();
        let t1 = ctrl.graph.get("t1").unwrap();
        assert_eq!(ctrl.wave_for(t1), Wave::Gated);
    }

    #[test]
    fn wave_transitions_on_completion() {
        let mut ctrl = default_loop();
        add_chain(&mut ctrl, &["d1", "d2", "t1"]);
        // Initially gated (2 blockers > ready_next_max_blockers default of 2)
        // Actually: t1 depends on d2, d2 depends on d1.
        // t1 has 1 open blocker (d2 which is open). So ReadyNext.
        let t1 = ctrl.graph.get("t1").unwrap();
        assert_eq!(ctrl.wave_for(t1), Wave::ReadyNext);

        // Complete d2 → t1 becomes ReadyNow
        ctrl.complete_task("d1");
        ctrl.complete_task("d2");
        let t1 = ctrl.graph.get("t1").unwrap();
        assert_eq!(ctrl.wave_for(t1), Wave::ReadyNow);
    }

    // ── Bottleneck detection tests ─────────────────────────────────────

    #[test]
    fn bottleneck_detection_identifies_root() {
        let mut ctrl = default_loop();
        // t1 → t2 → t3 → t4: t1 blocks everything
        add_chain(&mut ctrl, &["t1", "t2", "t3", "t4"]);
        let bottlenecks = ctrl.detect_bottlenecks();
        assert!(!bottlenecks.is_empty());
        assert_eq!(bottlenecks[0].task_id, "t1");
        assert!(bottlenecks[0].downstream_count >= 3);
    }

    #[test]
    fn bottleneck_completed_excluded() {
        let mut ctrl = default_loop();
        add_chain(&mut ctrl, &["t1", "t2"]);
        ctrl.complete_task("t1");
        let bottlenecks = ctrl.detect_bottlenecks();
        assert!(
            bottlenecks.iter().all(|b| b.task_id != "t1"),
            "completed tasks should not be bottlenecks"
        );
    }

    #[test]
    fn bottleneck_unassigned_is_critical() {
        let mut ctrl = default_loop();
        let mut root = make_unassigned_task("root", &[]);
        // Create 10 dependents to make it High severity, plus unassigned → Critical
        let mut deps = BTreeSet::new();
        for i in 0..11 {
            let id = format!("d{i}");
            deps.insert(id.clone());
            ctrl.add_task(make_task(&id, &["root"])).unwrap();
        }
        root.dependents = deps;
        ctrl.add_task(root).unwrap();
        let bottlenecks = ctrl.detect_bottlenecks();
        let root_bn = bottlenecks.iter().find(|b| b.task_id == "root").unwrap();
        assert_eq!(root_bn.severity, BottleneckSeverity::Critical);
    }

    // ── Recompute tests ────────────────────────────────────────────────

    #[test]
    fn recompute_produces_artifact() {
        let mut ctrl = default_loop();
        add_chain(&mut ctrl, &["t1", "t2", "t3"]);
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000_000,
                CrossCuttingSignals::default(),
                vec!["ev-001".to_string()],
            )
            .unwrap();
        assert_eq!(artifact.schema_version, SWARM_CONTROL_SCHEMA_VERSION);
        assert_eq!(artifact.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(artifact.total_tasks, 3);
        assert_eq!(artifact.completed_tasks, 0);
        assert!(!artifact.queue.is_empty());
    }

    #[test]
    fn recompute_increments_iteration() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        ctrl.recompute(
            SecurityEpoch::from_raw(1),
            1_000,
            CrossCuttingSignals::default(),
            vec![],
        )
        .unwrap();
        assert_eq!(ctrl.iteration_count, 1);
        ctrl.recompute(
            SecurityEpoch::from_raw(2),
            2_000,
            CrossCuttingSignals::default(),
            vec![],
        )
        .unwrap();
        assert_eq!(ctrl.iteration_count, 2);
    }

    #[test]
    fn recompute_empty_graph_fails() {
        let mut ctrl = default_loop();
        assert!(
            ctrl.recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .is_err()
        );
    }

    #[test]
    fn recompute_queue_respects_depth() {
        let mut ctrl = SwarmControlLoop::new(ControlLoopConfig {
            queue_depth: 2,
            ..Default::default()
        })
        .unwrap();
        for i in 0..5 {
            ctrl.add_task(make_task(&format!("t{i}"), &[])).unwrap();
        }
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();
        assert_eq!(artifact.queue.len(), 2);
    }

    #[test]
    fn recompute_excludes_gated_by_default() {
        let mut ctrl = default_loop();
        let mut root = make_task("root", &[]);
        root.dependents = ["d1", "d2", "d3"].iter().map(|s| s.to_string()).collect();
        ctrl.add_task(root).unwrap();
        // These tasks have 3 open blockers each — should be excluded from queue
        for i in 1..=3 {
            ctrl.add_task(make_task(&format!("d{i}"), &["root"]))
                .unwrap();
        }
        // But they each have 1 blocker so they're ReadyNext.
        // Add a truly gated task.
        let gated = make_task("gated", &["d1", "d2", "d3"]);
        ctrl.add_task(gated).unwrap();

        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();
        assert!(
            artifact.queue.iter().all(|e| e.task_id != "gated"),
            "gated tasks should be excluded"
        );
    }

    #[test]
    fn recompute_includes_gated_when_configured() {
        let mut ctrl = SwarmControlLoop::new(ControlLoopConfig {
            include_gated_in_queue: true,
            ..Default::default()
        })
        .unwrap();
        ctrl.add_task(make_task("root", &[])).unwrap();
        ctrl.add_task(make_task("d1", &["root"])).unwrap();
        ctrl.add_task(make_task("d2", &["root"])).unwrap();
        ctrl.add_task(make_task("d3", &["root"])).unwrap();
        let gated = make_task("gated", &["d1", "d2", "d3"]);
        ctrl.add_task(gated).unwrap();
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();
        assert!(artifact.queue.iter().any(|e| e.task_id == "gated"));
    }

    // ── Rationale delta tests ──────────────────────────────────────────

    #[test]
    fn rationale_delta_on_first_run() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();
        // First run: all entries are "entered queue".
        assert!(!artifact.rationale_deltas.is_empty());
        assert!(
            artifact.rationale_deltas[0]
                .reason
                .contains("entered queue")
        );
    }

    #[test]
    fn rationale_delta_on_completion() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        ctrl.add_task(make_task("t2", &[])).unwrap();
        ctrl.recompute(
            SecurityEpoch::from_raw(1),
            1_000,
            CrossCuttingSignals::default(),
            vec![],
        )
        .unwrap();

        // Complete t1 → it drops from queue.
        ctrl.complete_task("t1");
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(2),
                2_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();
        let dropped = artifact.rationale_deltas.iter().find(|d| d.task_id == "t1");
        assert!(dropped.is_some());
        assert!(dropped.unwrap().reason.contains("dropped"));
    }

    // ── Conservative mode tests ────────────────────────────────────────

    #[test]
    fn low_health_triggers_conservative() {
        let mut ctrl = SwarmControlLoop::new(ControlLoopConfig {
            conservative_threshold_millionths: 800_000,
            ..Default::default()
        })
        .unwrap();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        let bad_signals = CrossCuttingSignals {
            observability_quality_millionths: 100_000,
            catastrophic_tail_score_millionths: 500_000,
            bifurcation_distance_millionths: 100_000,
            unit_depth_score_millionths: 100_000,
            e2e_stability_score_millionths: 100_000,
            logging_integrity_score_millionths: 100_000,
        };
        let artifact = ctrl
            .recompute(SecurityEpoch::from_raw(1), 1_000, bad_signals, vec![])
            .unwrap();
        assert!(artifact.is_conservative());
    }

    #[test]
    fn healthy_signals_no_conservative() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();
        assert!(!artifact.is_conservative());
    }

    // ── Queue artifact accessors ───────────────────────────────────────

    #[test]
    fn artifact_completion_millionths() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        ctrl.add_task(make_task("t2", &[])).unwrap();
        ctrl.complete_task("t1");
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();
        assert_eq!(artifact.completion_millionths(), 500_000);
    }

    #[test]
    fn artifact_completion_empty() {
        let a = QueueArtifact {
            schema_version: SWARM_CONTROL_SCHEMA_VERSION.to_string(),
            epoch: SecurityEpoch::from_raw(0),
            timestamp_ns: 0,
            queue: vec![],
            signals: CrossCuttingSignals::default(),
            bottlenecks: vec![],
            risk_budget: SwarmRiskBudget::default(),
            rationale_deltas: vec![],
            evidence_ids: vec![],
            total_tasks: 0,
            completed_tasks: 0,
            ready_now_count: 0,
            ready_next_count: 0,
            gated_count: 0,
            artifact_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(a.completion_millionths(), MILLION);
    }

    #[test]
    fn artifact_critical_bottleneck_count() {
        let a = QueueArtifact {
            schema_version: SWARM_CONTROL_SCHEMA_VERSION.to_string(),
            epoch: SecurityEpoch::from_raw(0),
            timestamp_ns: 0,
            queue: vec![],
            signals: CrossCuttingSignals::default(),
            bottlenecks: vec![
                Bottleneck {
                    task_id: "t1".to_string(),
                    downstream_count: 15,
                    unassigned: true,
                    severity: BottleneckSeverity::Critical,
                },
                Bottleneck {
                    task_id: "t2".to_string(),
                    downstream_count: 5,
                    unassigned: false,
                    severity: BottleneckSeverity::Medium,
                },
            ],
            risk_budget: SwarmRiskBudget::default(),
            rationale_deltas: vec![],
            evidence_ids: vec![],
            total_tasks: 10,
            completed_tasks: 3,
            ready_now_count: 2,
            ready_next_count: 3,
            gated_count: 2,
            artifact_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(a.critical_bottleneck_count(), 1);
    }

    #[test]
    fn artifact_display() {
        let mut ctrl = default_loop();
        add_chain(&mut ctrl, &["t1", "t2"]);
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();
        let d = artifact.to_string();
        assert!(d.contains("queue_artifact"));
        assert!(d.contains("epoch=1"));
    }

    #[test]
    fn artifact_serde_roundtrip() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec!["ev-001".to_string()],
            )
            .unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        let back: QueueArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back.epoch, artifact.epoch);
        assert_eq!(back.queue.len(), artifact.queue.len());
        assert_eq!(back.evidence_ids, artifact.evidence_ids);
    }

    // ── SwarmControlLoop display and serde ──────────────────────────────

    #[test]
    fn loop_display() {
        let ctrl = default_loop();
        let d = ctrl.to_string();
        assert!(d.contains("swarm_control"));
        assert!(d.contains("tasks=0"));
    }

    #[test]
    fn loop_serde_roundtrip() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        let json = serde_json::to_string(&ctrl).unwrap();
        let back: SwarmControlLoop = serde_json::from_str(&json).unwrap();
        assert_eq!(back.task_count(), 1);
    }

    // ── Queue ordering tests ───────────────────────────────────────────

    #[test]
    fn queue_orders_ready_now_before_ready_next() {
        let mut ctrl = default_loop();
        // t1 is ready_now (no deps), t2 is ready_next (depends on t1)
        let mut t1 = make_task("t1", &[]);
        t1.dependents.insert("t2".to_string());
        t1.impact_millionths = 500_000; // lower EV
        ctrl.add_task(t1).unwrap();

        let mut t2 = make_task("t2", &["t1"]);
        t2.impact_millionths = 900_000; // higher EV
        ctrl.add_task(t2).unwrap();

        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();

        // t1 (ready_now) should come before t2 (ready_next) despite lower EV
        assert_eq!(artifact.queue[0].task_id, "t1");
        assert_eq!(artifact.queue[1].task_id, "t2");
    }

    #[test]
    fn queue_orders_by_relevance_within_wave() {
        let mut ctrl = default_loop();
        let mut t1 = make_task("t1", &[]);
        t1.impact_millionths = 500_000;
        ctrl.add_task(t1).unwrap();

        let mut t2 = make_task("t2", &[]);
        t2.impact_millionths = 900_000;
        ctrl.add_task(t2).unwrap();

        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();

        // t2 has higher impact → higher relevance → should be first
        assert_eq!(artifact.queue[0].task_id, "t2");
        assert_eq!(artifact.queue[1].task_id, "t1");
    }

    // ── Evidence ID linkage test ───────────────────────────────────────

    #[test]
    fn evidence_ids_preserved() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec!["ev-001".to_string(), "ev-002".to_string()],
            )
            .unwrap();
        assert_eq!(artifact.evidence_ids.len(), 2);
        assert_eq!(artifact.evidence_ids[0], "ev-001");
    }

    // ── Wave count tests ───────────────────────────────────────────────

    #[test]
    fn wave_counts_computed_correctly() {
        let mut ctrl = default_loop();
        // 1 ready_now, 1 ready_next, 1 gated
        let mut root = make_task("root", &[]);
        root.dependents = ["mid", "gated_dep1", "gated_dep2"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        ctrl.add_task(root).unwrap();

        let mut mid = make_task("mid", &["root"]);
        mid.dependents.insert("leaf".to_string());
        ctrl.add_task(mid).unwrap();

        ctrl.add_task(make_task("gated_dep1", &["root"])).unwrap();
        ctrl.add_task(make_task("gated_dep2", &["root"])).unwrap();

        let leaf = make_task("leaf", &["mid", "gated_dep1", "gated_dep2"]);
        ctrl.add_task(leaf).unwrap();

        let artifact = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();

        assert_eq!(artifact.ready_now_count, 1); // root
        assert!(artifact.ready_next_count >= 1); // mid, gated_dep1, gated_dep2 (1 blocker each)
        assert!(artifact.total_tasks == 5);
    }

    // ── Artifact hash determinism ──────────────────────────────────────

    #[test]
    fn artifact_hash_deterministic() {
        let mut ctrl1 = default_loop();
        ctrl1.add_task(make_task("t1", &[])).unwrap();
        let a1 = ctrl1
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();

        let mut ctrl2 = default_loop();
        ctrl2.add_task(make_task("t1", &[])).unwrap();
        let a2 = ctrl2
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();

        assert_eq!(a1.artifact_hash, a2.artifact_hash);
    }

    #[test]
    fn artifact_hash_changes_with_different_data() {
        let mut ctrl = default_loop();
        ctrl.add_task(make_task("t1", &[])).unwrap();
        let a1 = ctrl
            .recompute(
                SecurityEpoch::from_raw(1),
                1_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();

        // Add another task and recompute.
        ctrl.add_task(make_task("t2", &[])).unwrap();
        let a2 = ctrl
            .recompute(
                SecurityEpoch::from_raw(2),
                2_000,
                CrossCuttingSignals::default(),
                vec![],
            )
            .unwrap();

        assert_ne!(a1.artifact_hash, a2.artifact_hash);
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-26) --

    #[test]
    fn queue_entry_serde_roundtrip() {
        let entry = QueueEntry {
            rank: 1,
            task_id: "t-1".into(),
            title: "First task".into(),
            impact_millionths: 800_000,
            confidence_millionths: 900_000,
            reuse_millionths: 400_000,
            effort_millionths: 300_000,
            friction_millionths: 100_000,
            ev_millionths: 620_000,
            relevance_millionths: 570_000,
            primary_risk: "risk".into(),
            countermeasure: "cm".into(),
            fallback_trigger: "trigger".into(),
            first_action: "action".into(),
            wave: Wave::ReadyNow,
            open_blocker_count: 0,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: QueueEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn rationale_delta_serde_roundtrip() {
        let delta = RationaleDelta {
            task_id: "t-1".into(),
            previous_rank: 3,
            new_rank: 1,
            reason: "dependency resolved".into(),
        };
        let json = serde_json::to_string(&delta).unwrap();
        let back: RationaleDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(delta, back);
    }

    #[test]
    fn bottleneck_serde_roundtrip() {
        let b = Bottleneck {
            task_id: "t-core".into(),
            downstream_count: 12,
            unassigned: true,
            severity: BottleneckSeverity::Critical,
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: Bottleneck = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn bottleneck_severity_serde_roundtrip_all_variants() {
        let variants = [
            BottleneckSeverity::Low,
            BottleneckSeverity::Medium,
            BottleneckSeverity::High,
            BottleneckSeverity::Critical,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: BottleneckSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn control_loop_error_serde_roundtrip_all_variants() {
        let variants = vec![
            ControlLoopError::EmptyGraph,
            ControlLoopError::TooManyTasks {
                count: 5000,
                max: 4096,
            },
            ControlLoopError::CycleDetected {
                involved: vec!["a".into(), "b".into()],
            },
            ControlLoopError::UnknownDependency {
                task_id: "t1".into(),
                dependency_id: "t99".into(),
            },
            ControlLoopError::InvalidConfig {
                detail: "bad".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ControlLoopError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn rationale_delta_display_contains_task_and_ranks() {
        let d = RationaleDelta {
            task_id: "task-x".into(),
            previous_rank: 5,
            new_rank: 2,
            reason: "improvement".into(),
        };
        let s = d.to_string();
        assert!(s.contains("task-x"));
        assert!(s.contains("5"));
        assert!(s.contains("2"));
    }
}
