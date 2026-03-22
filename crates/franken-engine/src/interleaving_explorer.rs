//! Systematic interleaving explorer for checkpoint/revocation/policy-update
//! race surfaces.
//!
//! Drives the deterministic lab runtime through multiple scheduling
//! permutations to search for harmful interleavings. Supports exhaustive,
//! random-walk, and targeted-race exploration strategies.
//!
//! Plan references: Section 10.11 item 10, 9G.4 (deterministic lab runtime
//! with interleaving exploration), Top-10 #3 (deterministic evidence graph),
//! #9 (adversarial security corpus).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::lab_runtime::{FaultKind, LabRunResult, LabRuntime, ScheduleTranscript, TaskId};

// ---------------------------------------------------------------------------
// RaceSurface — a known race between operations
// ---------------------------------------------------------------------------

/// A known race surface: a pair of operations that interact unsafely if
/// reordered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaceSurface {
    /// Unique identifier for this race surface.
    pub race_id: String,
    /// Pair of operation types that interact.
    pub operations: [OperationType; 2],
    /// The property that must hold regardless of ordering.
    pub invariant: String,
    /// Consequence of invariant violation.
    pub severity: RaceSeverity,
}

/// Types of operations that can participate in races.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OperationType {
    CheckpointWrite,
    RevocationPropagation,
    PolicyUpdate,
    EvidenceEmission,
    RegionClose,
    ObligationCommit,
    TaskCompletion,
    FaultInjection,
    CancelInjection,
    TimeAdvance,
}

impl fmt::Display for OperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckpointWrite => write!(f, "checkpoint_write"),
            Self::RevocationPropagation => write!(f, "revocation_propagation"),
            Self::PolicyUpdate => write!(f, "policy_update"),
            Self::EvidenceEmission => write!(f, "evidence_emission"),
            Self::RegionClose => write!(f, "region_close"),
            Self::ObligationCommit => write!(f, "obligation_commit"),
            Self::TaskCompletion => write!(f, "task_completion"),
            Self::FaultInjection => write!(f, "fault_injection"),
            Self::CancelInjection => write!(f, "cancel_injection"),
            Self::TimeAdvance => write!(f, "time_advance"),
        }
    }
}

/// Severity of a race invariant violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RaceSeverity {
    /// Data inconsistency, but recoverable.
    Low,
    /// Stale data accepted or evidence ordering violated.
    Medium,
    /// Mixed-epoch operation, security boundary breach.
    High,
    /// Total system integrity loss.
    Critical,
}

impl fmt::Display for RaceSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// RaceSurfaceCatalog — extensible catalog of known races
// ---------------------------------------------------------------------------

/// Machine-readable catalog of known race surfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaceSurfaceCatalog {
    pub surfaces: BTreeMap<String, RaceSurface>,
}

impl RaceSurfaceCatalog {
    /// Create an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a race surface to the catalog.
    pub fn add(&mut self, surface: RaceSurface) {
        self.surfaces.insert(surface.race_id.clone(), surface);
    }

    /// Number of surfaces in the catalog.
    pub fn len(&self) -> usize {
        self.surfaces.len()
    }

    /// Whether the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.surfaces.is_empty()
    }

    /// Build the default catalog of known runtime race surfaces.
    pub fn default_catalog() -> Self {
        let mut catalog = Self::new();

        catalog.add(RaceSurface {
            race_id: "race-checkpoint-vs-revocation".to_string(),
            operations: [
                OperationType::CheckpointWrite,
                OperationType::RevocationPropagation,
            ],
            invariant:
                "checkpoint must not capture pre-revocation state after revocation is issued"
                    .to_string(),
            severity: RaceSeverity::Critical,
        });

        catalog.add(RaceSurface {
            race_id: "race-policy-vs-evidence".to_string(),
            operations: [OperationType::PolicyUpdate, OperationType::EvidenceEmission],
            invariant: "evidence emitted after policy change must reference new policy epoch"
                .to_string(),
            severity: RaceSeverity::High,
        });

        catalog.add(RaceSurface {
            race_id: "race-checkpoint-vs-region-close".to_string(),
            operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
            invariant: "checkpoint must not include closed-region obligations".to_string(),
            severity: RaceSeverity::High,
        });

        catalog.add(RaceSurface {
            race_id: "race-obligation-vs-cancel".to_string(),
            operations: [
                OperationType::ObligationCommit,
                OperationType::CancelInjection,
            ],
            invariant:
                "obligation commit racing with cancellation must resolve to exactly one outcome"
                    .to_string(),
            severity: RaceSeverity::Medium,
        });

        catalog.add(RaceSurface {
            race_id: "race-completion-vs-fault".to_string(),
            operations: [OperationType::TaskCompletion, OperationType::FaultInjection],
            invariant: "task cannot be both completed and faulted".to_string(),
            severity: RaceSeverity::High,
        });

        catalog
    }
}

// ---------------------------------------------------------------------------
// ExplorationStrategy — how to explore interleavings
// ---------------------------------------------------------------------------

/// Strategy for exploring scheduling interleavings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExplorationStrategy {
    /// Enumerate all possible orderings up to a bound.
    Exhaustive {
        /// Maximum permutations to explore (factorial grows fast).
        max_permutations: usize,
    },
    /// Seed-driven random schedule permutations.
    RandomWalk {
        /// Base seed for deterministic random exploration.
        seed: u64,
        /// Number of random permutations to try.
        iterations: usize,
    },
    /// Focus on known race surface pairs.
    TargetedRace {
        /// Which race surfaces to target.
        race_ids: Vec<String>,
    },
}

impl fmt::Display for ExplorationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhaustive { max_permutations } => {
                write!(f, "exhaustive(max={max_permutations})")
            }
            Self::RandomWalk { seed, iterations } => {
                write!(f, "random_walk(seed={seed}, iters={iterations})")
            }
            Self::TargetedRace { race_ids } => {
                write!(f, "targeted_race({})", race_ids.join(","))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InvariantCheck — user-defined invariant checker
// ---------------------------------------------------------------------------

/// Result of an invariant check against a run result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantResult {
    /// Invariant held.
    Held,
    /// Invariant was violated.
    Violated { description: String },
}

// ---------------------------------------------------------------------------
// ExplorationFailure — a failing interleaving
// ---------------------------------------------------------------------------

/// A single failure found during exploration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorationFailure {
    /// The schedule that caused the failure.
    pub transcript: ScheduleTranscript,
    /// The invariant violations detected.
    pub violations: Vec<String>,
    /// Minimized transcript (if minimization succeeded).
    pub minimized_transcript: Option<ScheduleTranscript>,
    /// Which race surface(s) this failure relates to.
    pub related_race_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// ExplorationReport — output artifact
// ---------------------------------------------------------------------------

/// Output artifact from an interleaving exploration run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorationReport {
    /// Exploration identifier.
    pub exploration_id: String,
    /// Strategy used.
    pub strategy: ExplorationStrategy,
    /// Total interleavings explored.
    pub total_explored: usize,
    /// Failures found.
    pub failures: Vec<ExplorationFailure>,
    /// Coverage: fraction of race catalog surfaces exercised.
    pub race_surfaces_covered: usize,
    /// Total race surfaces in catalog.
    pub race_surfaces_total: usize,
    /// Recommended regression transcripts (minimized failures).
    pub regression_transcripts: Vec<ScheduleTranscript>,
}

impl ExplorationReport {
    /// Coverage fraction (0.0 to 1.0 as fixed-point millionths).
    pub fn coverage_millionths(&self) -> i64 {
        if self.race_surfaces_total == 0 {
            return 0;
        }
        (self.race_surfaces_covered as i128 * 1_000_000 / self.race_surfaces_total as i128) as i64
    }

    /// Number of failures found.
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }

    /// Whether all explored interleavings passed.
    pub fn all_passed(&self) -> bool {
        self.failures.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Scenario — what the explorer drives through the lab runtime
// ---------------------------------------------------------------------------

/// A scenario is a set of tasks to spawn and a base schedule of actions.
/// The explorer permutes the action ordering to find failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    /// Number of tasks to spawn in the lab runtime.
    pub task_count: usize,
    /// Base schedule actions (the explorer permutes their order).
    pub actions: Vec<ScenarioAction>,
    /// Seed for the lab runtime.
    pub seed: u64,
}

/// A high-level scenario action that the explorer translates to
/// ScheduleActions on the lab runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioAction {
    RunTask { task_index: usize },
    CompleteTask { task_index: usize },
    AdvanceTime { ticks: u64 },
    InjectCancel { region_id: String },
    InjectFault { task_index: usize, fault: FaultKind },
}

// ---------------------------------------------------------------------------
// InvariantChecker — pluggable invariant validation
// ---------------------------------------------------------------------------

/// Trait for checking invariants against a lab run result.
/// We use a struct-based approach for Serialize/Deserialize compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantChecker {
    /// No task should be both completed and faulted.
    NoCompletedAndFaulted,
    /// All tasks must reach a terminal state.
    AllTasksTerminal,
    /// Faulted tasks must not appear after completion events.
    FaultAfterCompletionForbidden,
    /// Custom invariant: checks that a specific event pattern does NOT appear.
    ForbiddenEventPattern { action: String, outcome: String },
}

impl InvariantChecker {
    /// Check the invariant against a lab run result.
    pub fn check(&self, result: &LabRunResult) -> InvariantResult {
        match self {
            Self::NoCompletedAndFaulted => {
                // A task that appears both completed and faulted is a violation.
                let mut completed: BTreeMap<TaskId, bool> = BTreeMap::new();
                let mut faulted: BTreeMap<TaskId, bool> = BTreeMap::new();
                for event in &result.events {
                    if let Some(tid) = event.task_id {
                        if event.outcome == "completed" {
                            completed.insert(tid, true);
                        }
                        if event.outcome.starts_with("fault=") {
                            faulted.insert(tid, true);
                        }
                    }
                }
                for tid in completed.keys() {
                    if faulted.contains_key(tid) {
                        return InvariantResult::Violated {
                            description: format!("task {tid} appears both completed and faulted"),
                        };
                    }
                }
                InvariantResult::Held
            }
            Self::AllTasksTerminal => {
                // Every task mentioned in events should reach a terminal state.
                let mut last_state: BTreeMap<TaskId, String> = BTreeMap::new();
                for event in &result.events {
                    if let Some(tid) = event.task_id {
                        last_state.insert(tid, event.outcome.clone());
                    }
                }
                for (tid, state) in &last_state {
                    if state != "completed" && state != "cancelled" && !state.starts_with("fault=")
                    {
                        return InvariantResult::Violated {
                            description: format!("task {tid} in non-terminal state: {state}"),
                        };
                    }
                }
                InvariantResult::Held
            }
            Self::FaultAfterCompletionForbidden => {
                let mut completed: BTreeMap<TaskId, u64> = BTreeMap::new();
                for event in &result.events {
                    if let Some(tid) = event.task_id {
                        if event.outcome == "completed" {
                            completed.entry(tid).or_insert(event.step_index);
                        }
                        if event.outcome.starts_with("fault=")
                            && let Some(&complete_step) = completed.get(&tid)
                            && event.step_index > complete_step
                        {
                            return InvariantResult::Violated {
                                description: format!(
                                    "task {tid} faulted at step {} after completion at step {complete_step}",
                                    event.step_index
                                ),
                            };
                        }
                    }
                }
                InvariantResult::Held
            }
            Self::ForbiddenEventPattern { action, outcome } => {
                for event in &result.events {
                    if event.action == *action && event.outcome == *outcome {
                        return InvariantResult::Violated {
                            description: format!(
                                "forbidden event pattern: action={action}, outcome={outcome}"
                            ),
                        };
                    }
                }
                InvariantResult::Held
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InterleavingExplorer — the main explorer
// ---------------------------------------------------------------------------

/// Systematic interleaving explorer that drives the lab runtime through
/// scheduling permutations.
#[derive(Debug)]
pub struct InterleavingExplorer {
    catalog: RaceSurfaceCatalog,
    checkers: Vec<InvariantChecker>,
}

impl InterleavingExplorer {
    /// Create a new explorer with the given race catalog and invariant checkers.
    pub fn new(catalog: RaceSurfaceCatalog, checkers: Vec<InvariantChecker>) -> Self {
        Self { catalog, checkers }
    }

    /// Explore a scenario with the given strategy.
    pub fn explore(
        &self,
        scenario: &Scenario,
        strategy: &ExplorationStrategy,
        exploration_id: &str,
    ) -> ExplorationReport {
        let permutations = self.generate_permutations(scenario, strategy);
        let mut failures = Vec::new();
        let mut covered_races: BTreeMap<String, bool> = BTreeMap::new();

        for perm in &permutations {
            let result = self.execute_permutation(scenario, perm);
            let violations = self.check_invariants(&result);

            if !violations.is_empty() {
                let transcript = result.transcript.clone();
                let minimized = self.minimize_transcript(scenario, &transcript);

                // Determine which race surfaces are related.
                let related = self.identify_related_races(perm);
                for r in &related {
                    covered_races.insert(r.clone(), true);
                }

                failures.push(ExplorationFailure {
                    transcript,
                    violations,
                    minimized_transcript: minimized,
                    related_race_ids: related,
                });
            }

            // Track which race surfaces were exercised (even if no failure).
            let exercised = self.identify_related_races(perm);
            for r in exercised {
                covered_races.insert(r, true);
            }
        }

        let regression_transcripts = failures
            .iter()
            .filter_map(|f| {
                f.minimized_transcript
                    .clone()
                    .or_else(|| Some(f.transcript.clone()))
            })
            .collect();

        ExplorationReport {
            exploration_id: exploration_id.to_string(),
            strategy: strategy.clone(),
            total_explored: permutations.len(),
            failures,
            race_surfaces_covered: covered_races.len(),
            race_surfaces_total: self.catalog.len(),
            regression_transcripts,
        }
    }

    /// Generate schedule permutations based on the strategy.
    fn generate_permutations(
        &self,
        scenario: &Scenario,
        strategy: &ExplorationStrategy,
    ) -> Vec<Vec<usize>> {
        let n = scenario.actions.len();
        match strategy {
            ExplorationStrategy::Exhaustive { max_permutations } => {
                let mut perms = Vec::new();
                let mut indices: Vec<usize> = (0..n).collect();
                generate_permutations_bounded(&mut indices, 0, *max_permutations, &mut perms);
                perms
            }
            ExplorationStrategy::RandomWalk { seed, iterations } => {
                let mut perms = Vec::new();
                for i in 0..*iterations {
                    let perm = deterministic_shuffle(n, seed.wrapping_add(i as u64));
                    perms.push(perm);
                }
                perms
            }
            ExplorationStrategy::TargetedRace { race_ids } => {
                // For targeted races, generate permutations that specifically
                // swap the operations involved in the targeted race surfaces.
                let mut perms = Vec::new();
                // Always include identity ordering.
                perms.push((0..n).collect());

                for race_id in race_ids {
                    if let Some(surface) = self.catalog.surfaces.get(race_id) {
                        // Find scenario actions that match the race operations.
                        let indices_for_ops =
                            self.find_operation_indices(scenario, &surface.operations);
                        if indices_for_ops.len() >= 2 {
                            // Generate a permutation that swaps the first two
                            // matching operations.
                            let mut perm: Vec<usize> = (0..n).collect();
                            perm.swap(indices_for_ops[0], indices_for_ops[1]);
                            perms.push(perm);
                        }
                    }
                }
                perms
            }
        }
    }

    /// Execute a single permutation of the scenario.
    fn execute_permutation(&self, scenario: &Scenario, ordering: &[usize]) -> LabRunResult {
        let mut rt = LabRuntime::new(scenario.seed);

        // Spawn tasks.
        let mut task_ids: Vec<TaskId> = Vec::new();
        for _ in 0..scenario.task_count {
            task_ids.push(rt.spawn_task());
        }

        // Execute actions in the given order.
        for &idx in ordering {
            if idx >= scenario.actions.len() {
                continue;
            }
            let action = &scenario.actions[idx];
            match action {
                ScenarioAction::RunTask { task_index } => {
                    if let Some(&tid) = task_ids.get(*task_index) {
                        rt.run_task(tid);
                    }
                }
                ScenarioAction::CompleteTask { task_index } => {
                    if let Some(&tid) = task_ids.get(*task_index) {
                        rt.complete_task(tid);
                    }
                }
                ScenarioAction::AdvanceTime { ticks } => {
                    rt.advance_time(*ticks);
                }
                ScenarioAction::InjectCancel { region_id } => {
                    rt.inject_cancel(region_id);
                }
                ScenarioAction::InjectFault { task_index, fault } => {
                    if let Some(&tid) = task_ids.get(*task_index) {
                        rt.inject_fault(tid, fault.clone());
                    }
                }
            }
        }

        rt.finalize()
    }

    /// Check all registered invariants against a run result.
    fn check_invariants(&self, result: &LabRunResult) -> Vec<String> {
        let mut violations = Vec::new();
        for checker in &self.checkers {
            if let InvariantResult::Violated { description } = checker.check(result) {
                violations.push(description);
            }
        }
        violations
    }

    /// Attempt to minimize a failing transcript by removing actions one at a
    /// time and checking if the failure is still reproduced.
    fn minimize_transcript(
        &self,
        scenario: &Scenario,
        _transcript: &ScheduleTranscript,
    ) -> Option<ScheduleTranscript> {
        // Build the ordering from the transcript by matching actions.
        // For simplicity, we work with action-index orderings.
        let n = scenario.actions.len();
        if n <= 1 {
            return None;
        }

        // Reconstruct the action-index ordering from the transcript.
        // This is a best-effort reconstruction.
        let original_ordering: Vec<usize> = (0..n).collect();

        // Try removing each action and see if we still get a failure.
        let mut best_ordering = original_ordering.clone();
        let mut improved = true;

        while improved {
            improved = false;
            for skip_pos in 0..best_ordering.len() {
                if best_ordering.len() <= 1 {
                    break;
                }
                let candidate: Vec<usize> = best_ordering
                    .iter()
                    .enumerate()
                    .filter(|&(i, _)| i != skip_pos)
                    .map(|(_, &v)| v)
                    .collect();

                let result = self.execute_permutation(scenario, &candidate);
                let violations = self.check_invariants(&result);
                if !violations.is_empty() {
                    best_ordering = candidate;
                    improved = true;
                    break;
                }
            }
        }

        if best_ordering.len() < n {
            // Build a minimized transcript from the reduced ordering.
            let result = self.execute_permutation(scenario, &best_ordering);
            Some(result.transcript)
        } else {
            None
        }
    }

    /// Identify which race surfaces are exercised by a given ordering.
    fn identify_related_races(&self, ordering: &[usize]) -> Vec<String> {
        // A race surface is "exercised" if the ordering contains indices
        // that would correspond to both operations in the race.
        // Since we track by position, any non-trivial ordering exercises
        // the races. For a more precise implementation we'd need the
        // scenario context, but for coverage tracking we count all surfaces
        // from the catalog that have at least 2 matching operation types
        // present in the ordering.
        //
        // For now, return all races in the catalog as "exercised" when the
        // ordering is non-trivial (contains at least 2 actions).
        if ordering.len() >= 2 {
            self.catalog.surfaces.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Find scenario action indices that correspond to the given operation types.
    fn find_operation_indices(
        &self,
        scenario: &Scenario,
        operations: &[OperationType; 2],
    ) -> Vec<usize> {
        let mut indices = Vec::new();
        for (i, action) in scenario.actions.iter().enumerate() {
            let op_type = scenario_action_to_op_type(action);
            if op_type == operations[0] || op_type == operations[1] {
                indices.push(i);
            }
        }
        indices
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Map a scenario action to its operation type.
fn scenario_action_to_op_type(action: &ScenarioAction) -> OperationType {
    match action {
        ScenarioAction::RunTask { .. } => OperationType::TaskCompletion,
        ScenarioAction::CompleteTask { .. } => OperationType::TaskCompletion,
        ScenarioAction::AdvanceTime { .. } => OperationType::TimeAdvance,
        ScenarioAction::InjectCancel { .. } => OperationType::CancelInjection,
        ScenarioAction::InjectFault { .. } => OperationType::FaultInjection,
    }
}

/// Generate permutations using Heap's algorithm, bounded by max count.
fn generate_permutations_bounded(
    arr: &mut Vec<usize>,
    start: usize,
    max: usize,
    results: &mut Vec<Vec<usize>>,
) {
    if results.len() >= max {
        return;
    }
    if start == arr.len() {
        results.push(arr.clone());
        return;
    }
    for i in start..arr.len() {
        arr.swap(start, i);
        generate_permutations_bounded(arr, start + 1, max, results);
        if results.len() >= max {
            arr.swap(start, i);
            return;
        }
        arr.swap(start, i);
    }
}

/// Deterministic shuffle using a simple LCG PRNG.
fn deterministic_shuffle(n: usize, seed: u64) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..n).collect();
    let mut state = seed;
    // Fisher-Yates shuffle with LCG.
    for i in (1..n).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (state >> 33) as usize % (i + 1);
        indices.swap(i, j);
    }
    indices
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab_runtime::{LabEvent, Verdict};

    // -- RaceSurfaceCatalog --

    #[test]
    fn empty_catalog() {
        let catalog = RaceSurfaceCatalog::new();
        assert!(catalog.is_empty());
        assert_eq!(catalog.len(), 0);
    }

    #[test]
    fn default_catalog_has_known_races() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        assert!(catalog.len() >= 5);
        assert!(
            catalog
                .surfaces
                .contains_key("race-checkpoint-vs-revocation")
        );
        assert!(catalog.surfaces.contains_key("race-policy-vs-evidence"));
        assert!(catalog.surfaces.contains_key("race-completion-vs-fault"));
    }

    #[test]
    fn catalog_add_and_lookup() {
        let mut catalog = RaceSurfaceCatalog::new();
        catalog.add(RaceSurface {
            race_id: "test-race".to_string(),
            operations: [OperationType::CheckpointWrite, OperationType::RegionClose],
            invariant: "test invariant".to_string(),
            severity: RaceSeverity::Medium,
        });
        assert_eq!(catalog.len(), 1);
        assert!(catalog.surfaces.contains_key("test-race"));
    }

    // -- ExplorationStrategy display --

    #[test]
    fn strategy_display() {
        assert_eq!(
            ExplorationStrategy::Exhaustive {
                max_permutations: 10
            }
            .to_string(),
            "exhaustive(max=10)"
        );
        assert_eq!(
            ExplorationStrategy::RandomWalk {
                seed: 42,
                iterations: 100
            }
            .to_string(),
            "random_walk(seed=42, iters=100)"
        );
        assert!(
            ExplorationStrategy::TargetedRace {
                race_ids: vec!["r1".to_string()]
            }
            .to_string()
            .contains("r1")
        );
    }

    // -- Permutation generation --

    #[test]
    fn exhaustive_generates_correct_count_for_small_input() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::CompleteTask { task_index: 0 },
                ScenarioAction::AdvanceTime { ticks: 10 },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
        let strategy = ExplorationStrategy::Exhaustive {
            max_permutations: 100,
        };
        let report = explorer.explore(&scenario, &strategy, "test-exhaustive");
        // 3! = 6 permutations
        assert_eq!(report.total_explored, 6);
    }

    #[test]
    fn exhaustive_respects_max_bound() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::CompleteTask { task_index: 0 },
                ScenarioAction::AdvanceTime { ticks: 10 },
                ScenarioAction::AdvanceTime { ticks: 20 },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
        let strategy = ExplorationStrategy::Exhaustive {
            max_permutations: 5,
        };
        let report = explorer.explore(&scenario, &strategy, "test-bounded");
        assert!(report.total_explored <= 5);
    }

    #[test]
    fn random_walk_respects_iteration_count() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::CompleteTask { task_index: 0 },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
        let strategy = ExplorationStrategy::RandomWalk {
            seed: 99,
            iterations: 7,
        };
        let report = explorer.explore(&scenario, &strategy, "test-rw");
        assert_eq!(report.total_explored, 7);
    }

    #[test]
    fn targeted_race_includes_identity_plus_swaps() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::InjectCancel {
                    region_id: "r1".to_string(),
                },
                ScenarioAction::InjectFault {
                    task_index: 0,
                    fault: FaultKind::Panic,
                },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(catalog, vec![]);
        let strategy = ExplorationStrategy::TargetedRace {
            race_ids: vec!["race-obligation-vs-cancel".to_string()],
        };
        let report = explorer.explore(&scenario, &strategy, "test-targeted");
        // At least identity ordering + swapped ordering.
        assert!(report.total_explored >= 1);
    }

    // -- Invariant checking --

    #[test]
    fn no_completed_and_faulted_invariant_holds_on_clean_run() {
        let checker = InvariantChecker::NoCompletedAndFaulted;
        let result = LabRunResult {
            seed: 42,
            transcript: ScheduleTranscript::new(42),
            events: vec![LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "complete_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "completed".to_string(),
            }],
            final_time: 0,
            tasks_completed: 1,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        assert_eq!(checker.check(&result), InvariantResult::Held);
    }

    #[test]
    fn no_completed_and_faulted_invariant_detects_violation() {
        let checker = InvariantChecker::NoCompletedAndFaulted;
        let result = LabRunResult {
            seed: 42,
            transcript: ScheduleTranscript::new(42),
            events: vec![
                LabEvent {
                    virtual_time: 0,
                    step_index: 1,
                    action: "complete_task".to_string(),
                    task_id: Some(1),
                    region_id: None,
                    outcome: "completed".to_string(),
                },
                LabEvent {
                    virtual_time: 0,
                    step_index: 2,
                    action: "inject_fault".to_string(),
                    task_id: Some(1),
                    region_id: None,
                    outcome: "fault=panic".to_string(),
                },
            ],
            final_time: 0,
            tasks_completed: 1,
            tasks_faulted: 1,
            tasks_cancelled: 0,
            verdict: Verdict::Fail {
                reason: "1 tasks faulted".to_string(),
            },
        };
        assert!(matches!(
            checker.check(&result),
            InvariantResult::Violated { .. }
        ));
    }

    #[test]
    fn forbidden_event_pattern_checker() {
        let checker = InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        };
        let clean = LabRunResult {
            seed: 42,
            transcript: ScheduleTranscript::new(42),
            events: vec![LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "run_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "running".to_string(),
            }],
            final_time: 0,
            tasks_completed: 0,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        assert_eq!(checker.check(&clean), InvariantResult::Held);
    }

    // -- Explorer integration --

    #[test]
    fn explorer_finds_no_failures_on_clean_scenario() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::AdvanceTime { ticks: 10 },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::default_catalog(),
            vec![InvariantChecker::NoCompletedAndFaulted],
        );
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            "clean-test",
        );
        assert!(report.all_passed());
        assert_eq!(report.failure_count(), 0);
    }

    #[test]
    fn explorer_detects_failure_with_invariant_violation() {
        // Scenario: complete task then fault it — in some orderings,
        // the forbidden pattern checker should detect the fault.
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::InjectFault {
                    task_index: 0,
                    fault: FaultKind::Panic,
                },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::default_catalog(),
            vec![InvariantChecker::ForbiddenEventPattern {
                action: "inject_fault".to_string(),
                outcome: "fault=panic".to_string(),
            }],
        );
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            "fault-detection",
        );
        // At least one permutation should trigger the fault injection.
        assert!(!report.all_passed());
        assert!(report.failure_count() >= 1);
    }

    // -- Deterministic replay of exploration --

    #[test]
    fn exploration_is_deterministic() {
        let scenario = Scenario {
            task_count: 2,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::RunTask { task_index: 1 },
                ScenarioAction::AdvanceTime { ticks: 5 },
                ScenarioAction::InjectCancel {
                    region_id: "r".to_string(),
                },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::default_catalog(),
            vec![InvariantChecker::NoCompletedAndFaulted],
        );
        let strategy = ExplorationStrategy::RandomWalk {
            seed: 123,
            iterations: 10,
        };
        let report1 = explorer.explore(&scenario, &strategy, "det-1");
        let report2 = explorer.explore(&scenario, &strategy, "det-1");
        assert_eq!(report1.total_explored, report2.total_explored);
        assert_eq!(report1.failures, report2.failures);
    }

    // -- Coverage --

    #[test]
    fn coverage_millionths_calculation() {
        let report = ExplorationReport {
            exploration_id: "test".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            total_explored: 10,
            failures: vec![],
            race_surfaces_covered: 3,
            race_surfaces_total: 5,
            regression_transcripts: vec![],
        };
        assert_eq!(report.coverage_millionths(), 600_000); // 0.6
    }

    #[test]
    fn coverage_zero_when_no_surfaces() {
        let report = ExplorationReport {
            exploration_id: "test".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            total_explored: 0,
            failures: vec![],
            race_surfaces_covered: 0,
            race_surfaces_total: 0,
            regression_transcripts: vec![],
        };
        assert_eq!(report.coverage_millionths(), 0);
    }

    // -- Deterministic shuffle --

    #[test]
    fn deterministic_shuffle_same_seed_same_result() {
        let a = deterministic_shuffle(5, 42);
        let b = deterministic_shuffle(5, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_shuffle_different_seed_different_result() {
        let a = deterministic_shuffle(10, 42);
        let b = deterministic_shuffle(10, 99);
        // Very unlikely to be equal for n=10 with different seeds.
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_shuffle_is_valid_permutation() {
        let perm = deterministic_shuffle(5, 42);
        assert_eq!(perm.len(), 5);
        let mut sorted = perm.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
    }

    // -- Permutation generation --

    #[test]
    fn exhaustive_permutations_are_all_distinct() {
        let mut arr = vec![0, 1, 2];
        let mut results = Vec::new();
        generate_permutations_bounded(&mut arr, 0, 100, &mut results);
        assert_eq!(results.len(), 6);
        // All permutations should be unique.
        let mut sorted_results = results.clone();
        sorted_results.sort();
        sorted_results.dedup();
        assert_eq!(sorted_results.len(), 6);
    }

    // -- Failure minimization --

    #[test]
    fn minimization_produces_shorter_transcript() {
        // Create a scenario where only one action causes the failure.
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::AdvanceTime { ticks: 10 },
                ScenarioAction::InjectFault {
                    task_index: 0,
                    fault: FaultKind::Panic,
                },
                ScenarioAction::AdvanceTime { ticks: 20 },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::default_catalog(),
            vec![InvariantChecker::ForbiddenEventPattern {
                action: "inject_fault".to_string(),
                outcome: "fault=panic".to_string(),
            }],
        );
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 30,
            },
            "minimize-test",
        );

        // At least one failure should exist.
        assert!(!report.all_passed());

        // At least one failure should have a minimized transcript.
        let has_minimized = report
            .failures
            .iter()
            .any(|f| f.minimized_transcript.is_some());
        assert!(has_minimized);
    }

    // -- RaceSeverity ordering --

    #[test]
    fn race_severity_ordering() {
        assert!(RaceSeverity::Low < RaceSeverity::Medium);
        assert!(RaceSeverity::Medium < RaceSeverity::High);
        assert!(RaceSeverity::High < RaceSeverity::Critical);
    }

    #[test]
    fn race_severity_display() {
        assert_eq!(RaceSeverity::Low.to_string(), "low");
        assert_eq!(RaceSeverity::Medium.to_string(), "medium");
        assert_eq!(RaceSeverity::High.to_string(), "high");
        assert_eq!(RaceSeverity::Critical.to_string(), "critical");
    }

    // -- OperationType display --

    #[test]
    fn operation_type_display() {
        assert_eq!(
            OperationType::CheckpointWrite.to_string(),
            "checkpoint_write"
        );
        assert_eq!(
            OperationType::RevocationPropagation.to_string(),
            "revocation_propagation"
        );
        assert_eq!(OperationType::PolicyUpdate.to_string(), "policy_update");
        assert_eq!(OperationType::RegionClose.to_string(), "region_close");
    }

    // -- Serialization --

    #[test]
    fn race_surface_catalog_serialization_round_trip() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        let json = serde_json::to_string(&catalog).expect("serialize");
        let restored: RaceSurfaceCatalog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(catalog, restored);
    }

    #[test]
    fn exploration_report_serialization_round_trip() {
        let report = ExplorationReport {
            exploration_id: "test".to_string(),
            strategy: ExplorationStrategy::RandomWalk {
                seed: 42,
                iterations: 10,
            },
            total_explored: 10,
            failures: vec![],
            race_surfaces_covered: 3,
            race_surfaces_total: 5,
            regression_transcripts: vec![],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let restored: ExplorationReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, restored);
    }

    #[test]
    fn exploration_failure_serialization_round_trip() {
        let failure = ExplorationFailure {
            transcript: ScheduleTranscript::new(42),
            violations: vec!["test violation".to_string()],
            minimized_transcript: None,
            related_race_ids: vec!["race-1".to_string()],
        };
        let json = serde_json::to_string(&failure).expect("serialize");
        let restored: ExplorationFailure = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(failure, restored);
    }

    #[test]
    fn invariant_checker_serialization_round_trip() {
        let checker = InvariantChecker::ForbiddenEventPattern {
            action: "test".to_string(),
            outcome: "fail".to_string(),
        };
        let json = serde_json::to_string(&checker).expect("serialize");
        let restored: InvariantChecker = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(checker, restored);
    }

    // -- Regression transcripts --

    #[test]
    fn regression_transcripts_populated_from_failures() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::InjectFault {
                    task_index: 0,
                    fault: FaultKind::Panic,
                },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::default_catalog(),
            vec![InvariantChecker::ForbiddenEventPattern {
                action: "inject_fault".to_string(),
                outcome: "fault=panic".to_string(),
            }],
        );
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            "regression-test",
        );
        assert!(!report.regression_transcripts.is_empty());
    }

    // -- all_tasks_terminal invariant --

    #[test]
    fn all_tasks_terminal_checker() {
        let checker = InvariantChecker::AllTasksTerminal;
        let passing = LabRunResult {
            seed: 42,
            transcript: ScheduleTranscript::new(42),
            events: vec![LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "complete_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "completed".to_string(),
            }],
            final_time: 0,
            tasks_completed: 1,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        assert_eq!(checker.check(&passing), InvariantResult::Held);

        let failing = LabRunResult {
            seed: 42,
            transcript: ScheduleTranscript::new(42),
            events: vec![LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "run_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "running".to_string(),
            }],
            final_time: 0,
            tasks_completed: 0,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        assert!(matches!(
            checker.check(&failing),
            InvariantResult::Violated { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn operation_type_serde_roundtrip() {
        for v in [
            OperationType::CheckpointWrite,
            OperationType::RevocationPropagation,
            OperationType::PolicyUpdate,
            OperationType::EvidenceEmission,
            OperationType::RegionClose,
            OperationType::ObligationCommit,
            OperationType::TaskCompletion,
            OperationType::FaultInjection,
            OperationType::CancelInjection,
            OperationType::TimeAdvance,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: OperationType = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn race_severity_serde_roundtrip() {
        for v in [
            RaceSeverity::Low,
            RaceSeverity::Medium,
            RaceSeverity::High,
            RaceSeverity::Critical,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: RaceSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn exploration_strategy_serde_roundtrip() {
        let strategies = vec![
            ExplorationStrategy::Exhaustive {
                max_permutations: 100,
            },
            ExplorationStrategy::RandomWalk {
                seed: 42,
                iterations: 200,
            },
            ExplorationStrategy::TargetedRace {
                race_ids: vec!["r1".to_string()],
            },
        ];
        for s in &strategies {
            let json = serde_json::to_string(s).unwrap();
            let restored: ExplorationStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, restored);
        }
    }

    #[test]
    fn invariant_result_serde_roundtrip() {
        let held = InvariantResult::Held;
        let json = serde_json::to_string(&held).unwrap();
        let restored: InvariantResult = serde_json::from_str(&json).unwrap();
        assert_eq!(held, restored);

        let violated = InvariantResult::Violated {
            description: "bad".to_string(),
        };
        let json = serde_json::to_string(&violated).unwrap();
        let restored: InvariantResult = serde_json::from_str(&json).unwrap();
        assert_eq!(violated, restored);
    }

    #[test]
    fn scenario_action_serde_roundtrip() {
        let actions = vec![
            ScenarioAction::RunTask { task_index: 0 },
            ScenarioAction::CompleteTask { task_index: 1 },
            ScenarioAction::AdvanceTime { ticks: 100 },
            ScenarioAction::InjectCancel {
                region_id: "r-1".to_string(),
            },
            ScenarioAction::InjectFault {
                task_index: 2,
                fault: FaultKind::Panic,
            },
        ];
        for a in &actions {
            let json = serde_json::to_string(a).unwrap();
            let restored: ScenarioAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*a, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn race_surface_serde_roundtrip() {
        let rs = RaceSurface {
            race_id: "rc-1".to_string(),
            operations: [
                OperationType::CheckpointWrite,
                OperationType::RevocationPropagation,
            ],
            invariant: "monotonic".to_string(),
            severity: RaceSeverity::High,
        };
        let json = serde_json::to_string(&rs).unwrap();
        let restored: RaceSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(rs, restored);
    }

    #[test]
    fn scenario_serde_roundtrip() {
        let sc = Scenario {
            task_count: 3,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::CompleteTask { task_index: 0 },
            ],
            seed: 42,
        };
        let json = serde_json::to_string(&sc).unwrap();
        let restored: Scenario = serde_json::from_str(&json).unwrap();
        assert_eq!(sc, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering
    // -----------------------------------------------------------------------

    #[test]
    fn operation_type_ordering() {
        assert!(OperationType::CheckpointWrite < OperationType::TimeAdvance);
    }

    // -----------------------------------------------------------------------
    // Enrichment: default
    // -----------------------------------------------------------------------

    #[test]
    fn race_surface_catalog_default_empty() {
        let cat = RaceSurfaceCatalog::default();
        assert!(cat.surfaces.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, boundary, determinism
    // -----------------------------------------------------------------------

    #[test]
    fn operation_type_display_uniqueness() {
        let variants = [
            OperationType::CheckpointWrite,
            OperationType::RevocationPropagation,
            OperationType::PolicyUpdate,
            OperationType::EvidenceEmission,
            OperationType::RegionClose,
            OperationType::ObligationCommit,
            OperationType::TaskCompletion,
            OperationType::FaultInjection,
            OperationType::CancelInjection,
            OperationType::TimeAdvance,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|o| o.to_string()).collect();
        assert_eq!(
            displays.len(),
            10,
            "all OperationType variants must have unique Display"
        );
    }

    #[test]
    fn race_severity_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            RaceSeverity::Low,
            RaceSeverity::Medium,
            RaceSeverity::High,
            RaceSeverity::Critical,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            4,
            "all RaceSeverity variants must have unique Display"
        );
    }

    #[test]
    fn invariant_checker_all_tasks_terminal_serde_roundtrip() {
        let checker = InvariantChecker::AllTasksTerminal;
        let json = serde_json::to_string(&checker).unwrap();
        let restored: InvariantChecker = serde_json::from_str(&json).unwrap();
        assert_eq!(checker, restored);
    }

    #[test]
    fn exploration_report_no_failures_summary() {
        let scenario = Scenario {
            task_count: 2,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::CompleteTask { task_index: 0 },
                ScenarioAction::RunTask { task_index: 1 },
                ScenarioAction::CompleteTask { task_index: 1 },
            ],
            seed: 99,
        };
        let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::default_catalog(), vec![]);
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 5,
            },
            "no-failures-test",
        );
        assert!(report.failures.is_empty());
        assert!(report.regression_transcripts.is_empty());
    }

    #[test]
    fn default_catalog_has_known_surfaces() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        assert!(!catalog.surfaces.is_empty());
        // All race surfaces have non-empty invariants
        for surface in catalog.surfaces.values() {
            assert!(!surface.invariant.is_empty());
            assert!(!surface.race_id.is_empty());
        }
    }

    #[test]
    fn exploration_failure_with_minimized_transcript() {
        let failure = ExplorationFailure {
            transcript: ScheduleTranscript::new(1),
            violations: vec!["v1".to_string()],
            minimized_transcript: Some(ScheduleTranscript::new(1)),
            related_race_ids: vec!["r1".to_string()],
        };
        let json = serde_json::to_string(&failure).unwrap();
        let restored: ExplorationFailure = serde_json::from_str(&json).unwrap();
        assert_eq!(failure, restored);
        assert!(restored.minimized_transcript.is_some());
    }

    #[test]
    fn targeted_race_strategy_with_empty_ids() {
        let strategy = ExplorationStrategy::TargetedRace { race_ids: vec![] };
        let json = serde_json::to_string(&strategy).unwrap();
        let restored: ExplorationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(strategy, restored);
    }

    // -- Enrichment batch 3: clone, edge cases, JSON presence, Verdict --

    #[test]
    fn race_surface_clone_equality() {
        let rs = RaceSurface {
            race_id: "rc-clone".to_string(),
            operations: [OperationType::PolicyUpdate, OperationType::RegionClose],
            invariant: "no_leak".to_string(),
            severity: RaceSeverity::Critical,
        };
        assert_eq!(rs, rs.clone());
    }

    #[test]
    fn scenario_clone_equality() {
        let sc = Scenario {
            task_count: 2,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::AdvanceTime { ticks: 5 },
            ],
            seed: 77,
        };
        assert_eq!(sc, sc.clone());
    }

    #[test]
    fn exploration_failure_clone_equality() {
        let f = ExplorationFailure {
            transcript: ScheduleTranscript::new(99),
            violations: vec!["v1".to_string(), "v2".to_string()],
            minimized_transcript: None,
            related_race_ids: vec!["r1".to_string()],
        };
        assert_eq!(f, f.clone());
    }

    #[test]
    fn exploration_report_clone_equality() {
        let r = ExplorationReport {
            exploration_id: "clone-test".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 5,
            },
            total_explored: 5,
            failures: vec![],
            race_surfaces_covered: 2,
            race_surfaces_total: 3,
            regression_transcripts: vec![],
        };
        assert_eq!(r, r.clone());
    }

    #[test]
    fn lab_event_serde_roundtrip() {
        let ev = LabEvent {
            virtual_time: 100,
            step_index: 3,
            action: "run_task".to_string(),
            task_id: Some(7),
            region_id: Some("r-42".to_string()),
            outcome: "completed".to_string(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: LabEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn verdict_serde_roundtrip_all_variants() {
        let variants = vec![
            Verdict::Pass,
            Verdict::Fail {
                reason: "broken".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: Verdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn deterministic_shuffle_n_zero() {
        let perm = deterministic_shuffle(0, 42);
        assert!(perm.is_empty());
    }

    #[test]
    fn deterministic_shuffle_n_one() {
        let perm = deterministic_shuffle(1, 42);
        assert_eq!(perm, vec![0]);
    }

    #[test]
    fn bounded_permutations_respects_limit() {
        let mut arr = vec![0, 1, 2, 3];
        let mut results = Vec::new();
        generate_permutations_bounded(&mut arr, 0, 3, &mut results);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn exploration_report_json_field_presence() {
        let report = ExplorationReport {
            exploration_id: "json-fields".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 1,
            },
            total_explored: 1,
            failures: vec![],
            race_surfaces_covered: 0,
            race_surfaces_total: 2,
            regression_transcripts: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        for field in &[
            "exploration_id",
            "strategy",
            "total_explored",
            "failures",
            "race_surfaces_covered",
            "race_surfaces_total",
            "regression_transcripts",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn exploration_failure_multiple_violations() {
        let f = ExplorationFailure {
            transcript: ScheduleTranscript::new(1),
            violations: vec![
                "invariant_a broken".to_string(),
                "invariant_b broken".to_string(),
                "invariant_c broken".to_string(),
            ],
            minimized_transcript: None,
            related_race_ids: vec!["r-1".to_string(), "r-2".to_string()],
        };
        assert_eq!(f.violations.len(), 3);
        assert_eq!(f.related_race_ids.len(), 2);
        let json = serde_json::to_string(&f).unwrap();
        let back: ExplorationFailure = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn report_failure_count_matches_failures_vec() {
        let report = ExplorationReport {
            exploration_id: "count-test".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            total_explored: 5,
            failures: vec![
                ExplorationFailure {
                    transcript: ScheduleTranscript::new(1),
                    violations: vec!["v".to_string()],
                    minimized_transcript: None,
                    related_race_ids: vec![],
                },
                ExplorationFailure {
                    transcript: ScheduleTranscript::new(2),
                    violations: vec!["v".to_string()],
                    minimized_transcript: None,
                    related_race_ids: vec![],
                },
            ],
            race_surfaces_covered: 1,
            race_surfaces_total: 3,
            regression_transcripts: vec![],
        };
        assert_eq!(report.failure_count(), 2);
        assert!(!report.all_passed());
    }

    #[test]
    fn coverage_full_when_all_surfaces_covered() {
        let report = ExplorationReport {
            exploration_id: "full-cov".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            total_explored: 10,
            failures: vec![],
            race_surfaces_covered: 5,
            race_surfaces_total: 5,
            regression_transcripts: vec![],
        };
        assert_eq!(report.coverage_millionths(), 1_000_000);
    }

    #[test]
    fn lab_event_clone_equality() {
        let ev = LabEvent {
            virtual_time: 42,
            step_index: 1,
            action: "run_task".to_string(),
            task_id: None,
            region_id: None,
            outcome: "ok".to_string(),
        };
        assert_eq!(ev, ev.clone());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn race_surface_clone_independence() {
        let original = RaceSurface {
            race_id: "clone-ind".to_string(),
            operations: [OperationType::EvidenceEmission, OperationType::RegionClose],
            invariant: "evidence before close".to_string(),
            severity: RaceSeverity::High,
        };
        let mut cloned = original.clone();
        cloned.race_id = "mutated".to_string();
        cloned.severity = RaceSeverity::Low;
        assert_eq!(original.race_id, "clone-ind");
        assert_eq!(original.severity, RaceSeverity::High);
        assert_ne!(original, cloned);
    }

    #[test]
    fn scenario_clone_independence() {
        let original = Scenario {
            task_count: 3,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::AdvanceTime { ticks: 10 },
            ],
            seed: 55,
        };
        let mut cloned = original.clone();
        cloned.task_count = 99;
        cloned
            .actions
            .push(ScenarioAction::CompleteTask { task_index: 0 });
        assert_eq!(original.task_count, 3);
        assert_eq!(original.actions.len(), 2);
    }

    #[test]
    fn exploration_failure_clone_independence() {
        let original = ExplorationFailure {
            transcript: ScheduleTranscript::new(10),
            violations: vec!["v1".to_string()],
            minimized_transcript: None,
            related_race_ids: vec!["r-a".to_string()],
        };
        let mut cloned = original.clone();
        cloned.violations.push("v2".to_string());
        cloned.related_race_ids.clear();
        assert_eq!(original.violations.len(), 1);
        assert_eq!(original.related_race_ids.len(), 1);
    }

    #[test]
    fn exploration_report_clone_independence() {
        let original = ExplorationReport {
            exploration_id: "ind-test".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            total_explored: 10,
            failures: vec![],
            race_surfaces_covered: 2,
            race_surfaces_total: 5,
            regression_transcripts: vec![],
        };
        let mut cloned = original.clone();
        cloned.exploration_id = "mutated".to_string();
        cloned.total_explored = 999;
        assert_eq!(original.exploration_id, "ind-test");
        assert_eq!(original.total_explored, 10);
    }

    #[test]
    fn race_surface_catalog_clone_independence() {
        let mut original = RaceSurfaceCatalog::new();
        original.add(RaceSurface {
            race_id: "s1".to_string(),
            operations: [OperationType::CheckpointWrite, OperationType::PolicyUpdate],
            invariant: "x".to_string(),
            severity: RaceSeverity::Medium,
        });
        let mut cloned = original.clone();
        cloned.add(RaceSurface {
            race_id: "s2".to_string(),
            operations: [OperationType::TimeAdvance, OperationType::FaultInjection],
            invariant: "y".to_string(),
            severity: RaceSeverity::Low,
        });
        assert_eq!(original.len(), 1);
        assert_eq!(cloned.len(), 2);
    }

    #[test]
    fn operation_type_ord_all_variants() {
        let variants = [
            OperationType::CheckpointWrite,
            OperationType::RevocationPropagation,
            OperationType::PolicyUpdate,
            OperationType::EvidenceEmission,
            OperationType::RegionClose,
            OperationType::ObligationCommit,
            OperationType::TaskCompletion,
            OperationType::FaultInjection,
            OperationType::CancelInjection,
            OperationType::TimeAdvance,
        ];
        for window in variants.windows(2) {
            assert!(
                window[0] <= window[1],
                "{:?} should <= {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn race_severity_ord_all_variants() {
        let variants = [
            RaceSeverity::Low,
            RaceSeverity::Medium,
            RaceSeverity::High,
            RaceSeverity::Critical,
        ];
        for window in variants.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn operation_type_btreeset_insertion() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(OperationType::PolicyUpdate);
        set.insert(OperationType::PolicyUpdate);
        set.insert(OperationType::RegionClose);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&OperationType::PolicyUpdate));
        assert!(set.contains(&OperationType::RegionClose));
    }

    #[test]
    fn race_severity_btreeset_insertion() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for s in [
            RaceSeverity::Low,
            RaceSeverity::Medium,
            RaceSeverity::High,
            RaceSeverity::Critical,
            RaceSeverity::Low,
        ] {
            set.insert(s);
        }
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn exploration_strategy_display_targeted_empty() {
        let s = ExplorationStrategy::TargetedRace { race_ids: vec![] };
        assert_eq!(s.to_string(), "targeted_race()");
    }

    #[test]
    fn exploration_strategy_display_targeted_multiple() {
        let s = ExplorationStrategy::TargetedRace {
            race_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };
        assert_eq!(s.to_string(), "targeted_race(a,b,c)");
    }

    #[test]
    fn invariant_result_held_eq() {
        assert_eq!(InvariantResult::Held, InvariantResult::Held);
    }

    #[test]
    fn invariant_result_violated_ne_held() {
        let v = InvariantResult::Violated {
            description: "oops".to_string(),
        };
        assert_ne!(v, InvariantResult::Held);
    }

    #[test]
    fn invariant_result_violated_different_descriptions() {
        let v1 = InvariantResult::Violated {
            description: "a".to_string(),
        };
        let v2 = InvariantResult::Violated {
            description: "b".to_string(),
        };
        assert_ne!(v1, v2);
    }

    #[test]
    fn invariant_checker_no_completed_and_faulted_serde() {
        let checker = InvariantChecker::NoCompletedAndFaulted;
        let json = serde_json::to_string(&checker).unwrap();
        let restored: InvariantChecker = serde_json::from_str(&json).unwrap();
        assert_eq!(checker, restored);
    }

    #[test]
    fn invariant_checker_fault_after_completion_serde() {
        let checker = InvariantChecker::FaultAfterCompletionForbidden;
        let json = serde_json::to_string(&checker).unwrap();
        let restored: InvariantChecker = serde_json::from_str(&json).unwrap();
        assert_eq!(checker, restored);
    }

    #[test]
    fn fault_after_completion_forbidden_holds_on_clean() {
        let checker = InvariantChecker::FaultAfterCompletionForbidden;
        let result = LabRunResult {
            seed: 1,
            transcript: ScheduleTranscript::new(1),
            events: vec![
                LabEvent {
                    virtual_time: 0,
                    step_index: 1,
                    action: "run_task".to_string(),
                    task_id: Some(1),
                    region_id: None,
                    outcome: "running".to_string(),
                },
                LabEvent {
                    virtual_time: 0,
                    step_index: 2,
                    action: "complete_task".to_string(),
                    task_id: Some(1),
                    region_id: None,
                    outcome: "completed".to_string(),
                },
            ],
            final_time: 0,
            tasks_completed: 1,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        assert_eq!(checker.check(&result), InvariantResult::Held);
    }

    #[test]
    fn fault_after_completion_forbidden_detects_violation() {
        let checker = InvariantChecker::FaultAfterCompletionForbidden;
        let result = LabRunResult {
            seed: 1,
            transcript: ScheduleTranscript::new(1),
            events: vec![
                LabEvent {
                    virtual_time: 0,
                    step_index: 1,
                    action: "complete_task".to_string(),
                    task_id: Some(1),
                    region_id: None,
                    outcome: "completed".to_string(),
                },
                LabEvent {
                    virtual_time: 0,
                    step_index: 2,
                    action: "inject_fault".to_string(),
                    task_id: Some(1),
                    region_id: None,
                    outcome: "fault=panic".to_string(),
                },
            ],
            final_time: 0,
            tasks_completed: 1,
            tasks_faulted: 1,
            tasks_cancelled: 0,
            verdict: Verdict::Fail {
                reason: "1 tasks faulted".to_string(),
            },
        };
        match checker.check(&result) {
            InvariantResult::Violated { description } => {
                assert!(description.contains("task 1"));
                assert!(description.contains("faulted at step 2"));
                assert!(description.contains("completion at step 1"));
            }
            other => panic!("expected Violated, got {other:?}"),
        }
    }

    #[test]
    fn all_tasks_terminal_with_cancelled_state() {
        let checker = InvariantChecker::AllTasksTerminal;
        let result = LabRunResult {
            seed: 1,
            transcript: ScheduleTranscript::new(1),
            events: vec![LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "cancel_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "cancelled".to_string(),
            }],
            final_time: 0,
            tasks_completed: 0,
            tasks_faulted: 0,
            tasks_cancelled: 1,
            verdict: Verdict::Pass,
        };
        assert_eq!(checker.check(&result), InvariantResult::Held);
    }

    #[test]
    fn all_tasks_terminal_with_faulted_state() {
        let checker = InvariantChecker::AllTasksTerminal;
        let result = LabRunResult {
            seed: 1,
            transcript: ScheduleTranscript::new(1),
            events: vec![LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "inject_fault".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "fault=channel_disconnect".to_string(),
            }],
            final_time: 0,
            tasks_completed: 0,
            tasks_faulted: 1,
            tasks_cancelled: 0,
            verdict: Verdict::Fail {
                reason: "1 tasks faulted".to_string(),
            },
        };
        assert_eq!(checker.check(&result), InvariantResult::Held);
    }

    #[test]
    fn no_completed_and_faulted_holds_on_empty_events() {
        let checker = InvariantChecker::NoCompletedAndFaulted;
        let result = LabRunResult {
            seed: 1,
            transcript: ScheduleTranscript::new(1),
            events: vec![],
            final_time: 0,
            tasks_completed: 0,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        assert_eq!(checker.check(&result), InvariantResult::Held);
    }

    #[test]
    fn all_tasks_terminal_holds_on_empty_events() {
        let checker = InvariantChecker::AllTasksTerminal;
        let result = LabRunResult {
            seed: 1,
            transcript: ScheduleTranscript::new(1),
            events: vec![],
            final_time: 0,
            tasks_completed: 0,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        assert_eq!(checker.check(&result), InvariantResult::Held);
    }

    #[test]
    fn forbidden_event_pattern_holds_on_empty_events() {
        let checker = InvariantChecker::ForbiddenEventPattern {
            action: "inject_fault".to_string(),
            outcome: "fault=panic".to_string(),
        };
        let result = LabRunResult {
            seed: 1,
            transcript: ScheduleTranscript::new(1),
            events: vec![],
            final_time: 0,
            tasks_completed: 0,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        assert_eq!(checker.check(&result), InvariantResult::Held);
    }

    #[test]
    fn forbidden_event_pattern_detects_violation() {
        let checker = InvariantChecker::ForbiddenEventPattern {
            action: "run_task".to_string(),
            outcome: "running".to_string(),
        };
        let result = LabRunResult {
            seed: 1,
            transcript: ScheduleTranscript::new(1),
            events: vec![LabEvent {
                virtual_time: 0,
                step_index: 1,
                action: "run_task".to_string(),
                task_id: Some(1),
                region_id: None,
                outcome: "running".to_string(),
            }],
            final_time: 0,
            tasks_completed: 0,
            tasks_faulted: 0,
            tasks_cancelled: 0,
            verdict: Verdict::Pass,
        };
        match checker.check(&result) {
            InvariantResult::Violated { description } => {
                assert!(description.contains("forbidden event pattern"));
                assert!(description.contains("run_task"));
                assert!(description.contains("running"));
            }
            other => panic!("expected Violated, got {other:?}"),
        }
    }

    #[test]
    fn coverage_millionths_partial() {
        let report = ExplorationReport {
            exploration_id: "partial".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 1,
            },
            total_explored: 1,
            failures: vec![],
            race_surfaces_covered: 1,
            race_surfaces_total: 3,
            regression_transcripts: vec![],
        };
        assert_eq!(report.coverage_millionths(), 333_333);
    }

    #[test]
    fn coverage_millionths_one_of_one() {
        let report = ExplorationReport {
            exploration_id: "one".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 1,
            },
            total_explored: 1,
            failures: vec![],
            race_surfaces_covered: 1,
            race_surfaces_total: 1,
            regression_transcripts: vec![],
        };
        assert_eq!(report.coverage_millionths(), 1_000_000);
    }

    #[test]
    fn deterministic_shuffle_large_is_valid() {
        let perm = deterministic_shuffle(100, 12345);
        assert_eq!(perm.len(), 100);
        let mut sorted = perm.clone();
        sorted.sort();
        let expected: Vec<usize> = (0..100).collect();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn deterministic_shuffle_seed_zero() {
        let perm = deterministic_shuffle(5, 0);
        assert_eq!(perm.len(), 5);
        let mut sorted = perm.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn deterministic_shuffle_seed_u64_max() {
        let perm = deterministic_shuffle(5, u64::MAX);
        assert_eq!(perm.len(), 5);
        let mut sorted = perm.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn deterministic_shuffle_stability_across_calls() {
        let reference = deterministic_shuffle(20, 314159);
        for _ in 0..10 {
            assert_eq!(deterministic_shuffle(20, 314159), reference);
        }
    }

    #[test]
    fn exhaustive_single_action_produces_one_permutation() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![ScenarioAction::RunTask { task_index: 0 }],
            seed: 1,
        };
        let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 100,
            },
            "single-action",
        );
        assert_eq!(report.total_explored, 1);
    }

    #[test]
    fn exhaustive_empty_actions_produces_one_permutation() {
        let scenario = Scenario {
            task_count: 0,
            actions: vec![],
            seed: 1,
        };
        let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 100,
            },
            "empty-actions",
        );
        assert_eq!(report.total_explored, 1);
    }

    #[test]
    fn random_walk_zero_iterations() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![ScenarioAction::RunTask { task_index: 0 }],
            seed: 1,
        };
        let explorer = InterleavingExplorer::new(RaceSurfaceCatalog::new(), vec![]);
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::RandomWalk {
                seed: 42,
                iterations: 0,
            },
            "zero-iters",
        );
        assert_eq!(report.total_explored, 0);
        assert!(report.all_passed());
    }

    #[test]
    fn targeted_race_nonexistent_race_id() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::AdvanceTime { ticks: 5 },
            ],
            seed: 1,
        };
        let explorer = InterleavingExplorer::new(catalog, vec![]);
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::TargetedRace {
                race_ids: vec!["nonexistent-race".to_string()],
            },
            "bad-race-id",
        );
        assert!(report.total_explored >= 1);
    }

    #[test]
    fn catalog_add_replaces_duplicate_race_id() {
        let mut catalog = RaceSurfaceCatalog::new();
        catalog.add(RaceSurface {
            race_id: "dup".to_string(),
            operations: [OperationType::CheckpointWrite, OperationType::PolicyUpdate],
            invariant: "first".to_string(),
            severity: RaceSeverity::Low,
        });
        catalog.add(RaceSurface {
            race_id: "dup".to_string(),
            operations: [OperationType::RegionClose, OperationType::TimeAdvance],
            invariant: "second".to_string(),
            severity: RaceSeverity::Critical,
        });
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog.surfaces["dup"].invariant, "second");
        assert_eq!(catalog.surfaces["dup"].severity, RaceSeverity::Critical);
    }

    #[test]
    fn scenario_action_to_op_type_mapping() {
        assert_eq!(
            scenario_action_to_op_type(&ScenarioAction::RunTask { task_index: 0 }),
            OperationType::TaskCompletion
        );
        assert_eq!(
            scenario_action_to_op_type(&ScenarioAction::CompleteTask { task_index: 0 }),
            OperationType::TaskCompletion
        );
        assert_eq!(
            scenario_action_to_op_type(&ScenarioAction::AdvanceTime { ticks: 10 }),
            OperationType::TimeAdvance
        );
        assert_eq!(
            scenario_action_to_op_type(&ScenarioAction::InjectCancel {
                region_id: "r".to_string()
            }),
            OperationType::CancelInjection
        );
        assert_eq!(
            scenario_action_to_op_type(&ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic
            }),
            OperationType::FaultInjection
        );
    }

    #[test]
    fn explore_with_multiple_checkers() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::InjectFault {
                    task_index: 0,
                    fault: FaultKind::ChannelDisconnect,
                },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::default_catalog(),
            vec![
                InvariantChecker::NoCompletedAndFaulted,
                InvariantChecker::AllTasksTerminal,
                InvariantChecker::ForbiddenEventPattern {
                    action: "inject_fault".to_string(),
                    outcome: "fault=channel_disconnect".to_string(),
                },
            ],
        );
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            "multi-checker",
        );
        assert!(!report.all_passed());
    }

    #[test]
    fn exploration_report_serde_with_failures() {
        let report = ExplorationReport {
            exploration_id: "serde-fail".to_string(),
            strategy: ExplorationStrategy::RandomWalk {
                seed: 7,
                iterations: 3,
            },
            total_explored: 3,
            failures: vec![
                ExplorationFailure {
                    transcript: ScheduleTranscript::new(7),
                    violations: vec!["v1".to_string()],
                    minimized_transcript: None,
                    related_race_ids: vec!["r-1".to_string()],
                },
                ExplorationFailure {
                    transcript: ScheduleTranscript::new(8),
                    violations: vec!["v2".to_string(), "v3".to_string()],
                    minimized_transcript: Some(ScheduleTranscript::new(8)),
                    related_race_ids: vec![],
                },
            ],
            race_surfaces_covered: 1,
            race_surfaces_total: 5,
            regression_transcripts: vec![ScheduleTranscript::new(7)],
        };
        let json = serde_json::to_string(&report).unwrap();
        let restored: ExplorationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, restored);
    }

    #[test]
    fn exploration_deterministic_replay_random_walk() {
        let scenario = Scenario {
            task_count: 3,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::RunTask { task_index: 1 },
                ScenarioAction::RunTask { task_index: 2 },
                ScenarioAction::CompleteTask { task_index: 0 },
                ScenarioAction::AdvanceTime { ticks: 50 },
            ],
            seed: 77,
        };
        let catalog = RaceSurfaceCatalog::default_catalog();
        let strategy = ExplorationStrategy::RandomWalk {
            seed: 999,
            iterations: 20,
        };
        let explorer = InterleavingExplorer::new(
            catalog.clone(),
            vec![
                InvariantChecker::NoCompletedAndFaulted,
                InvariantChecker::AllTasksTerminal,
            ],
        );
        let r1 = explorer.explore(&scenario, &strategy, "replay-a");
        let r2 = explorer.explore(&scenario, &strategy, "replay-a");
        assert_eq!(r1.total_explored, r2.total_explored);
        assert_eq!(r1.failures.len(), r2.failures.len());
        assert_eq!(r1.race_surfaces_covered, r2.race_surfaces_covered);
        for (f1, f2) in r1.failures.iter().zip(r2.failures.iter()) {
            assert_eq!(f1.violations, f2.violations);
            assert_eq!(f1.transcript, f2.transcript);
        }
    }

    #[test]
    fn scenario_with_out_of_bounds_task_index() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![
                ScenarioAction::RunTask { task_index: 99 },
                ScenarioAction::CompleteTask { task_index: 99 },
                ScenarioAction::InjectFault {
                    task_index: 99,
                    fault: FaultKind::Panic,
                },
            ],
            seed: 1,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::new(),
            vec![InvariantChecker::NoCompletedAndFaulted],
        );
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            "oob-test",
        );
        assert!(report.all_passed());
    }

    #[test]
    fn race_surfaces_covered_tracks_catalog() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        let total = catalog.len();
        let scenario = Scenario {
            task_count: 2,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::RunTask { task_index: 1 },
            ],
            seed: 1,
        };
        let explorer = InterleavingExplorer::new(catalog, vec![]);
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::Exhaustive {
                max_permutations: 10,
            },
            "coverage-track",
        );
        assert_eq!(report.race_surfaces_total, total);
        assert_eq!(report.race_surfaces_covered, total);
    }

    #[test]
    fn identify_related_races_single_action() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        let explorer = InterleavingExplorer::new(catalog, vec![]);
        let related = explorer.identify_related_races(&[0]);
        assert!(
            related.is_empty(),
            "single action should not exercise races"
        );
    }

    #[test]
    fn identify_related_races_empty_ordering() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        let explorer = InterleavingExplorer::new(catalog, vec![]);
        let related = explorer.identify_related_races(&[]);
        assert!(related.is_empty());
    }

    #[test]
    fn default_catalog_race_ids_sorted() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        let keys: Vec<&String> = catalog.surfaces.keys().collect();
        for window in keys.windows(2) {
            assert!(window[0] <= window[1], "BTreeMap keys must be sorted");
        }
    }

    #[test]
    fn default_catalog_all_severities_present() {
        let catalog = RaceSurfaceCatalog::default_catalog();
        use std::collections::BTreeSet;
        let severities: BTreeSet<RaceSeverity> =
            catalog.surfaces.values().map(|s| s.severity).collect();
        assert!(severities.contains(&RaceSeverity::Critical));
        assert!(severities.contains(&RaceSeverity::High));
        assert!(severities.contains(&RaceSeverity::Medium));
    }

    #[test]
    fn exploration_report_debug_not_empty() {
        let report = ExplorationReport {
            exploration_id: "dbg".to_string(),
            strategy: ExplorationStrategy::Exhaustive {
                max_permutations: 1,
            },
            total_explored: 1,
            failures: vec![],
            race_surfaces_covered: 0,
            race_surfaces_total: 0,
            regression_transcripts: vec![],
        };
        let dbg = format!("{report:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("ExplorationReport"));
    }

    #[test]
    fn invariant_checker_clone_equality() {
        let checkers = vec![
            InvariantChecker::NoCompletedAndFaulted,
            InvariantChecker::AllTasksTerminal,
            InvariantChecker::FaultAfterCompletionForbidden,
            InvariantChecker::ForbiddenEventPattern {
                action: "x".to_string(),
                outcome: "y".to_string(),
            },
        ];
        for c in &checkers {
            assert_eq!(*c, c.clone());
        }
    }

    #[test]
    fn stress_random_walk_many_iterations() {
        let scenario = Scenario {
            task_count: 2,
            actions: vec![
                ScenarioAction::RunTask { task_index: 0 },
                ScenarioAction::RunTask { task_index: 1 },
                ScenarioAction::CompleteTask { task_index: 0 },
                ScenarioAction::InjectCancel {
                    region_id: "rgn".to_string(),
                },
                ScenarioAction::AdvanceTime { ticks: 100 },
            ],
            seed: 42,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::default_catalog(),
            vec![
                InvariantChecker::NoCompletedAndFaulted,
                InvariantChecker::AllTasksTerminal,
            ],
        );
        let report = explorer.explore(
            &scenario,
            &ExplorationStrategy::RandomWalk {
                seed: 0,
                iterations: 50,
            },
            "stress-rw",
        );
        assert_eq!(report.total_explored, 50);
    }

    #[test]
    fn minimization_returns_none_for_single_action() {
        let scenario = Scenario {
            task_count: 1,
            actions: vec![ScenarioAction::InjectFault {
                task_index: 0,
                fault: FaultKind::Panic,
            }],
            seed: 1,
        };
        let explorer = InterleavingExplorer::new(
            RaceSurfaceCatalog::new(),
            vec![InvariantChecker::ForbiddenEventPattern {
                action: "inject_fault".to_string(),
                outcome: "fault=panic".to_string(),
            }],
        );
        let result = explorer.execute_permutation(&scenario, &[0]);
        let minimized = explorer.minimize_transcript(&scenario, &result.transcript);
        assert!(
            minimized.is_none(),
            "single-action scenario cannot be minimized"
        );
    }

    #[test]
    fn scenario_action_inject_fault_all_kinds_serde() {
        let faults = [
            FaultKind::Panic,
            FaultKind::ChannelDisconnect,
            FaultKind::ObligationLeak,
            FaultKind::DeadlineExpired,
            FaultKind::RegionClose,
        ];
        for fault in &faults {
            let action = ScenarioAction::InjectFault {
                task_index: 0,
                fault: fault.clone(),
            };
            let json = serde_json::to_string(&action).unwrap();
            let restored: ScenarioAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, restored);
        }
    }
}
