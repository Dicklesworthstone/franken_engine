//! Obligation tracking for two-phase safety-critical operations.
//!
//! Integrates the obligation primitives from [`region_lifecycle`] and
//! [`obligation_channel`] into the extension-host subsystem, ensuring every
//! two-phase operation creates an obligation that must resolve before region
//! close.
//!
//! Two-phase operation categories:
//! - **ResourceAlloc**: memory, file handles, sockets — cleanup guaranteed.
//! - **PermissionGrant**: capability grant — audit trail mandatory.
//! - **StateMutation**: transactional change — rollback-on-failure.
//! - **EvidenceCommit**: begin-evidence → commit-evidence atomic pair.
//!
//! Unresolved obligations at region close are treated as leaks and handled
//! according to [`ObligationLeakPolicy`]: fatal in lab mode, evidence + failover
//! in production.
//!
//! Plan reference: Section 10.13 item 8, bd-m9pa.
//! Dependencies: bd-1ukb (region cells), bd-1bl (obligation channels),
//!               bd-2wz9 (cancellation), bd-uvmm (evidence).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::execution_cell::{CellError, CellKind, ExecutionCell};
use crate::region_lifecycle::RegionState;

// ---------------------------------------------------------------------------
// TwoPhaseCategory — classification of two-phase operations
// ---------------------------------------------------------------------------

/// Category of a two-phase safety-critical operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TwoPhaseCategory {
    /// Resource allocation with guaranteed cleanup (memory, handles, sockets).
    ResourceAlloc,
    /// Permission grant with mandatory audit trail.
    PermissionGrant,
    /// Transactional state mutation with rollback-on-failure.
    StateMutation,
    /// Evidence begin/commit atomic pair.
    EvidenceCommit,
}

impl fmt::Display for TwoPhaseCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceAlloc => write!(f, "resource_alloc"),
            Self::PermissionGrant => write!(f, "permission_grant"),
            Self::StateMutation => write!(f, "state_mutation"),
            Self::EvidenceCommit => write!(f, "evidence_commit"),
        }
    }
}

// ---------------------------------------------------------------------------
// TwoPhaseOperation — a tracked two-phase operation
// ---------------------------------------------------------------------------

/// A tracked two-phase operation within an execution cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoPhaseOperation {
    /// Unique operation identifier.
    pub operation_id: String,
    /// Cell this operation belongs to.
    pub cell_id: String,
    /// Category of the operation.
    pub category: TwoPhaseCategory,
    /// Human-readable description.
    pub description: String,
    /// Trace ID for request correlation.
    pub trace_id: String,
    /// Current phase.
    pub phase: OperationPhase,
}

/// Phase of a two-phase operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OperationPhase {
    /// Phase 1 started (obligation created, awaiting phase 2).
    Phase1Active,
    /// Phase 2 completed (obligation committed).
    Committed,
    /// Operation rolled back (obligation aborted).
    Aborted,
    /// Operation leaked (region closed without resolution).
    Leaked,
}

impl fmt::Display for OperationPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Phase1Active => write!(f, "phase1_active"),
            Self::Committed => write!(f, "committed"),
            Self::Aborted => write!(f, "aborted"),
            Self::Leaked => write!(f, "leaked"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationIntegrationError
// ---------------------------------------------------------------------------

/// Error from obligation integration operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationIntegrationError {
    /// Cell is not in a state that accepts new operations.
    CellNotRunning {
        cell_id: String,
        current_state: RegionState,
    },
    /// Operation not found in tracker.
    OperationNotFound { operation_id: String },
    /// Operation already resolved (idempotent protection).
    AlreadyResolved {
        operation_id: String,
        current_phase: OperationPhase,
    },
    /// Duplicate operation ID.
    DuplicateOperation { operation_id: String },
    /// Cell error propagated from execution cell layer.
    CellError { message: String },
}

impl fmt::Display for ObligationIntegrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CellNotRunning {
                cell_id,
                current_state,
            } => write!(
                f,
                "cell {cell_id} not running (state: {current_state}), cannot start operation"
            ),
            Self::OperationNotFound { operation_id } => {
                write!(f, "operation not found: {operation_id}")
            }
            Self::AlreadyResolved {
                operation_id,
                current_phase,
            } => write!(
                f,
                "operation {operation_id} already resolved (phase: {current_phase})"
            ),
            Self::DuplicateOperation { operation_id } => {
                write!(f, "duplicate operation ID: {operation_id}")
            }
            Self::CellError { message } => write!(f, "cell error: {message}"),
        }
    }
}

impl std::error::Error for ObligationIntegrationError {}

impl ObligationIntegrationError {
    /// Stable error code for structured logging.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::CellNotRunning { .. } => "obligation_cell_not_running",
            Self::OperationNotFound { .. } => "obligation_operation_not_found",
            Self::AlreadyResolved { .. } => "obligation_already_resolved",
            Self::DuplicateOperation { .. } => "obligation_duplicate_operation",
            Self::CellError { .. } => "obligation_cell_error",
        }
    }
}

impl From<CellError> for ObligationIntegrationError {
    fn from(err: CellError) -> Self {
        Self::CellError {
            message: err.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationEvent — structured evidence for obligation operations
// ---------------------------------------------------------------------------

/// Structured event emitted by obligation tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationEvent {
    /// Trace ID for request correlation.
    pub trace_id: String,
    /// Cell ID.
    pub cell_id: String,
    /// Cell kind.
    pub cell_kind: CellKind,
    /// Operation ID.
    pub operation_id: String,
    /// Operation category.
    pub category: TwoPhaseCategory,
    /// Event type.
    pub event: String,
    /// Outcome.
    pub outcome: String,
    /// Component name.
    pub component: String,
    /// Current operation phase.
    pub phase: OperationPhase,
}

// ---------------------------------------------------------------------------
// LeakPolicy — how to handle unresolved obligations
// ---------------------------------------------------------------------------

/// How to handle unresolved obligations at region close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LeakPolicy {
    /// Lab mode: unresolved obligations are fatal errors.
    Lab,
    /// Production mode: emit evidence, force-resolve, continue.
    #[default]
    Production,
}

// ---------------------------------------------------------------------------
// LeakRecord — record of a detected obligation leak
// ---------------------------------------------------------------------------

/// Record of an obligation that leaked (was not resolved before region close).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakRecord {
    /// Operation that leaked.
    pub operation_id: String,
    /// Cell where the leak occurred.
    pub cell_id: String,
    /// Category of the leaked operation.
    pub category: TwoPhaseCategory,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Description of the operation.
    pub description: String,
}

// ---------------------------------------------------------------------------
// ObligationTracker — tracks two-phase operations across cells
// ---------------------------------------------------------------------------

/// Tracks two-phase safety-critical operations across execution cells.
///
/// Each operation creates a region obligation when phase 1 begins, and the
/// obligation is resolved when phase 2 completes (commit) or fails (abort).
/// Unresolved obligations at region close are detected as leaks.
#[derive(Debug)]
pub struct ObligationTracker {
    /// All tracked operations, keyed by operation ID.
    operations: BTreeMap<String, TwoPhaseOperation>,
    /// Sequence counter for deterministic ordering.
    sequence: u64,
    /// Leak handling policy.
    leak_policy: LeakPolicy,
    /// Detected leaks.
    leaks: Vec<LeakRecord>,
    /// Event log for evidence emission.
    events: Vec<ObligationEvent>,
    /// Statistics per category.
    stats: BTreeMap<TwoPhaseCategory, CategoryStats>,
}

/// Per-category statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryStats {
    /// Total operations started.
    pub started: u64,
    /// Operations committed.
    pub committed: u64,
    /// Operations aborted.
    pub aborted: u64,
    /// Operations leaked.
    pub leaked: u64,
}

/// Input for [`ObligationTracker::emit_event`] to stay within clippy's argument limit.
struct EmitObligationEventInput<'a> {
    trace_id: &'a str,
    cell_id: &'a str,
    cell_kind: CellKind,
    operation_id: &'a str,
    category: TwoPhaseCategory,
    event: &'a str,
    outcome: &'a str,
    phase: OperationPhase,
}

impl Default for ObligationTracker {
    fn default() -> Self {
        Self::new(LeakPolicy::default())
    }
}

impl ObligationTracker {
    /// Create a new tracker with the specified leak policy.
    pub fn new(leak_policy: LeakPolicy) -> Self {
        Self {
            operations: BTreeMap::new(),
            sequence: 0,
            leak_policy,
            leaks: Vec::new(),
            events: Vec::new(),
            stats: BTreeMap::new(),
        }
    }

    /// Create a tracker in lab mode (leaks are fatal).
    pub fn lab() -> Self {
        Self::new(LeakPolicy::Lab)
    }

    /// Start a two-phase operation: creates a region obligation in the cell.
    pub fn begin_operation(
        &mut self,
        cell: &mut ExecutionCell,
        operation_id: impl Into<String>,
        category: TwoPhaseCategory,
        description: impl Into<String>,
    ) -> Result<(), ObligationIntegrationError> {
        let operation_id = operation_id.into();
        let description = description.into();

        // Reject if cell is not running
        if cell.state() != RegionState::Running {
            return Err(ObligationIntegrationError::CellNotRunning {
                cell_id: cell.cell_id().to_string(),
                current_state: cell.state(),
            });
        }

        // Reject duplicate operation IDs
        if self.operations.contains_key(&operation_id) {
            return Err(ObligationIntegrationError::DuplicateOperation { operation_id });
        }

        // Register obligation in the cell's region
        cell.register_obligation(&operation_id, &description);

        self.sequence = self.sequence.saturating_add(1);

        let op = TwoPhaseOperation {
            operation_id: operation_id.clone(),
            cell_id: cell.cell_id().to_string(),
            category,
            description,
            trace_id: cell.trace_id().to_string(),
            phase: OperationPhase::Phase1Active,
        };

        self.emit_event(EmitObligationEventInput {
            trace_id: &op.trace_id,
            cell_id: &op.cell_id,
            cell_kind: cell.kind(),
            operation_id: &op.operation_id,
            category,
            event: "begin",
            outcome: "phase1_active",
            phase: OperationPhase::Phase1Active,
        });

        self.stats.entry(category).or_default().started += 1;
        self.operations.insert(operation_id, op);
        Ok(())
    }

    /// Commit phase 2: resolves the obligation as committed.
    pub fn commit_operation(
        &mut self,
        cell: &mut ExecutionCell,
        operation_id: &str,
    ) -> Result<(), ObligationIntegrationError> {
        if cell.state() == RegionState::Closed {
            return Err(ObligationIntegrationError::CellNotRunning {
                cell_id: cell.cell_id().to_string(),
                current_state: cell.state(),
            });
        }

        let op = self.operations.get(operation_id).ok_or_else(|| {
            ObligationIntegrationError::OperationNotFound {
                operation_id: operation_id.to_string(),
            }
        })?;

        if op.phase != OperationPhase::Phase1Active {
            return Err(ObligationIntegrationError::AlreadyResolved {
                operation_id: operation_id.to_string(),
                current_phase: op.phase,
            });
        }

        cell.commit_obligation(operation_id)?;

        let (trace_id, cell_id, op_id, category) = {
            let op = self
                .operations
                .get_mut(operation_id)
                .expect("checked above");
            op.phase = OperationPhase::Committed;
            (
                op.trace_id.clone(),
                op.cell_id.clone(),
                op.operation_id.clone(),
                op.category,
            )
        };

        self.emit_event(EmitObligationEventInput {
            trace_id: &trace_id,
            cell_id: &cell_id,
            cell_kind: cell.kind(),
            operation_id: &op_id,
            category,
            event: "commit",
            outcome: "committed",
            phase: OperationPhase::Committed,
        });

        self.stats.entry(category).or_default().committed += 1;
        Ok(())
    }

    /// Abort the operation: resolves the obligation as aborted (rollback).
    pub fn abort_operation(
        &mut self,
        cell: &mut ExecutionCell,
        operation_id: &str,
    ) -> Result<(), ObligationIntegrationError> {
        if cell.state() == RegionState::Closed {
            return Err(ObligationIntegrationError::CellNotRunning {
                cell_id: cell.cell_id().to_string(),
                current_state: cell.state(),
            });
        }

        let op = self.operations.get(operation_id).ok_or_else(|| {
            ObligationIntegrationError::OperationNotFound {
                operation_id: operation_id.to_string(),
            }
        })?;

        if op.phase != OperationPhase::Phase1Active {
            return Err(ObligationIntegrationError::AlreadyResolved {
                operation_id: operation_id.to_string(),
                current_phase: op.phase,
            });
        }

        cell.abort_obligation(operation_id)?;

        let (trace_id, cell_id, op_id, category) = {
            let op = self
                .operations
                .get_mut(operation_id)
                .expect("checked above");
            op.phase = OperationPhase::Aborted;
            (
                op.trace_id.clone(),
                op.cell_id.clone(),
                op.operation_id.clone(),
                op.category,
            )
        };

        self.emit_event(EmitObligationEventInput {
            trace_id: &trace_id,
            cell_id: &cell_id,
            cell_kind: cell.kind(),
            operation_id: &op_id,
            category,
            event: "abort",
            outcome: "aborted",
            phase: OperationPhase::Aborted,
        });

        self.stats.entry(category).or_default().aborted += 1;
        Ok(())
    }

    /// Detect leaks: scan for operations whose cell is no longer running.
    ///
    /// In lab mode, returns the leaks for assertion failure.
    /// In production mode, emits evidence and records the leaks.
    pub fn detect_leaks(&mut self, cell: &ExecutionCell) -> Vec<LeakRecord> {
        let mut leaks = Vec::new();

        // Only check if cell is in a terminal state
        if cell.state() != RegionState::Closed {
            return leaks;
        }

        let cell_id = cell.cell_id();
        let pending_ops: Vec<String> = self
            .operations
            .iter()
            .filter(|(_, op)| op.cell_id == cell_id && op.phase == OperationPhase::Phase1Active)
            .map(|(id, _)| id.clone())
            .collect();

        for op_id in pending_ops {
            let Some((leak, trace_id, cell_id_str, op_id_str, category)) =
                self.operations.get_mut(&op_id).map(|op| {
                    op.phase = OperationPhase::Leaked;
                    (
                        LeakRecord {
                            operation_id: op.operation_id.clone(),
                            cell_id: op.cell_id.clone(),
                            category: op.category,
                            trace_id: op.trace_id.clone(),
                            description: op.description.clone(),
                        },
                        op.trace_id.clone(),
                        op.cell_id.clone(),
                        op.operation_id.clone(),
                        op.category,
                    )
                })
            else {
                continue;
            };

            self.emit_event(EmitObligationEventInput {
                trace_id: &trace_id,
                cell_id: &cell_id_str,
                cell_kind: cell.kind(),
                operation_id: &op_id_str,
                category,
                event: "leak_detected",
                outcome: "leaked",
                phase: OperationPhase::Leaked,
            });

            match self.leak_policy {
                LeakPolicy::Lab => self.emit_event(EmitObligationEventInput {
                    trace_id: &trace_id,
                    cell_id: &cell_id_str,
                    cell_kind: cell.kind(),
                    operation_id: &op_id_str,
                    category,
                    event: "lab_failure",
                    outcome: "fatal",
                    phase: OperationPhase::Leaked,
                }),
                LeakPolicy::Production => self.emit_event(EmitObligationEventInput {
                    trace_id: &trace_id,
                    cell_id: &cell_id_str,
                    cell_kind: cell.kind(),
                    operation_id: &op_id_str,
                    category,
                    event: "production_fallback",
                    outcome: "forced_cleanup",
                    phase: OperationPhase::Leaked,
                }),
            }

            self.stats.entry(category).or_default().leaked += 1;
            self.leaks.push(leak.clone());
            leaks.push(leak);
        }

        leaks
    }

    /// Check if any leaks have been detected.
    pub fn has_leaks(&self) -> bool {
        !self.leaks.is_empty()
    }

    /// Whether current tracker state should fail a lab/frankenlab run.
    pub fn should_fail_run(&self) -> bool {
        self.leak_policy == LeakPolicy::Lab && self.has_leaks()
    }

    /// All detected leaks.
    pub fn leaks(&self) -> &[LeakRecord] {
        &self.leaks
    }

    /// Leak policy.
    pub fn leak_policy(&self) -> LeakPolicy {
        self.leak_policy
    }

    /// Number of active (phase 1) operations.
    pub fn active_count(&self) -> usize {
        self.operations
            .values()
            .filter(|op| op.phase == OperationPhase::Phase1Active)
            .count()
    }

    /// Total operations tracked.
    pub fn total_count(&self) -> usize {
        self.operations.len()
    }

    /// Get an operation by ID.
    pub fn get_operation(&self, operation_id: &str) -> Option<&TwoPhaseOperation> {
        self.operations.get(operation_id)
    }

    /// Statistics per category.
    pub fn category_stats(&self) -> &BTreeMap<TwoPhaseCategory, CategoryStats> {
        &self.stats
    }

    /// Drain accumulated events for evidence emission.
    pub fn drain_events(&mut self) -> Vec<ObligationEvent> {
        std::mem::take(&mut self.events)
    }

    /// View accumulated events.
    pub fn events(&self) -> &[ObligationEvent] {
        &self.events
    }

    fn emit_event(&mut self, input: EmitObligationEventInput<'_>) {
        self.events.push(ObligationEvent {
            trace_id: input.trace_id.to_string(),
            cell_id: input.cell_id.to_string(),
            cell_kind: input.cell_kind,
            operation_id: input.operation_id.to_string(),
            category: input.category,
            event: input.event.to_string(),
            outcome: input.outcome.to_string(),
            component: "obligation_integration".to_string(),
            phase: input.phase,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{MockBudget, MockCx};
    use crate::region_lifecycle::{CancelReason, DrainDeadline};

    fn mock_cx(budget_ms: u64) -> MockCx {
        MockCx::new(
            crate::control_plane::mocks::trace_id_from_seed(1),
            MockBudget::new(budget_ms),
        )
    }

    // -----------------------------------------------------------------------
    // TwoPhaseCategory
    // -----------------------------------------------------------------------

    #[test]
    fn category_display() {
        assert_eq!(
            TwoPhaseCategory::ResourceAlloc.to_string(),
            "resource_alloc"
        );
        assert_eq!(
            TwoPhaseCategory::PermissionGrant.to_string(),
            "permission_grant"
        );
        assert_eq!(
            TwoPhaseCategory::StateMutation.to_string(),
            "state_mutation"
        );
        assert_eq!(
            TwoPhaseCategory::EvidenceCommit.to_string(),
            "evidence_commit"
        );
    }

    #[test]
    fn category_serde_roundtrip() {
        for cat in [
            TwoPhaseCategory::ResourceAlloc,
            TwoPhaseCategory::PermissionGrant,
            TwoPhaseCategory::StateMutation,
            TwoPhaseCategory::EvidenceCommit,
        ] {
            let json = serde_json::to_string(&cat).expect("serialize");
            let restored: TwoPhaseCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(cat, restored);
        }
    }

    #[test]
    fn category_ordering() {
        assert!(TwoPhaseCategory::ResourceAlloc < TwoPhaseCategory::PermissionGrant);
        assert!(TwoPhaseCategory::PermissionGrant < TwoPhaseCategory::StateMutation);
        assert!(TwoPhaseCategory::StateMutation < TwoPhaseCategory::EvidenceCommit);
    }

    // -----------------------------------------------------------------------
    // OperationPhase
    // -----------------------------------------------------------------------

    #[test]
    fn phase_display() {
        assert_eq!(OperationPhase::Phase1Active.to_string(), "phase1_active");
        assert_eq!(OperationPhase::Committed.to_string(), "committed");
        assert_eq!(OperationPhase::Aborted.to_string(), "aborted");
        assert_eq!(OperationPhase::Leaked.to_string(), "leaked");
    }

    #[test]
    fn phase_serde_roundtrip() {
        for phase in [
            OperationPhase::Phase1Active,
            OperationPhase::Committed,
            OperationPhase::Aborted,
            OperationPhase::Leaked,
        ] {
            let json = serde_json::to_string(&phase).expect("serialize");
            let restored: OperationPhase = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(phase, restored);
        }
    }

    // -----------------------------------------------------------------------
    // ObligationIntegrationError
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_and_codes() {
        let errors = vec![
            ObligationIntegrationError::CellNotRunning {
                cell_id: "c1".to_string(),
                current_state: RegionState::Closed,
            },
            ObligationIntegrationError::OperationNotFound {
                operation_id: "op-1".to_string(),
            },
            ObligationIntegrationError::AlreadyResolved {
                operation_id: "op-1".to_string(),
                current_phase: OperationPhase::Committed,
            },
            ObligationIntegrationError::DuplicateOperation {
                operation_id: "op-1".to_string(),
            },
            ObligationIntegrationError::CellError {
                message: "cell broke".to_string(),
            },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
            assert!(!err.error_code().is_empty());
        }
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = ObligationIntegrationError::CellNotRunning {
            cell_id: "c".to_string(),
            current_state: RegionState::Closed,
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: ObligationIntegrationError =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored);
    }

    // -----------------------------------------------------------------------
    // ObligationTracker — begin/commit lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn begin_and_commit_operation() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "alloc-1",
                TwoPhaseCategory::ResourceAlloc,
                "allocate memory buffer",
            )
            .expect("begin");

        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.total_count(), 1);
        assert_eq!(cell.pending_obligations(), 1);

        tracker
            .commit_operation(&mut cell, "alloc-1")
            .expect("commit");

        assert_eq!(tracker.active_count(), 0);
        assert_eq!(cell.pending_obligations(), 0);

        let op = tracker.get_operation("alloc-1").expect("exists");
        assert_eq!(op.phase, OperationPhase::Committed);
    }

    #[test]
    fn begin_and_abort_operation() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "perm-1",
                TwoPhaseCategory::PermissionGrant,
                "grant network access",
            )
            .expect("begin");

        tracker.abort_operation(&mut cell, "perm-1").expect("abort");

        let op = tracker.get_operation("perm-1").expect("exists");
        assert_eq!(op.phase, OperationPhase::Aborted);
        assert_eq!(cell.pending_obligations(), 0);
    }

    // -----------------------------------------------------------------------
    // Rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn begin_rejected_when_cell_not_running() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let mut tracker = ObligationTracker::default();
        let err = tracker
            .begin_operation(
                &mut cell,
                "op-1",
                TwoPhaseCategory::ResourceAlloc,
                "too late",
            )
            .unwrap_err();

        assert_eq!(err.error_code(), "obligation_cell_not_running");
    }

    #[test]
    fn begin_rejected_duplicate_id() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "first")
            .expect("first begin");

        let err = tracker
            .begin_operation(
                &mut cell,
                "op-1",
                TwoPhaseCategory::ResourceAlloc,
                "duplicate",
            )
            .unwrap_err();

        assert_eq!(err.error_code(), "obligation_duplicate_operation");
    }

    #[test]
    fn commit_nonexistent_fails() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        let err = tracker
            .commit_operation(&mut cell, "nonexistent")
            .unwrap_err();
        assert_eq!(err.error_code(), "obligation_operation_not_found");
    }

    #[test]
    fn commit_already_committed_fails() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "op-1", TwoPhaseCategory::StateMutation, "tx")
            .unwrap();
        tracker.commit_operation(&mut cell, "op-1").unwrap();

        let err = tracker.commit_operation(&mut cell, "op-1").unwrap_err();
        assert_eq!(err.error_code(), "obligation_already_resolved");
    }

    #[test]
    fn abort_already_aborted_fails() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "op-1", TwoPhaseCategory::StateMutation, "tx")
            .unwrap();
        tracker.abort_operation(&mut cell, "op-1").unwrap();

        let err = tracker.abort_operation(&mut cell, "op-1").unwrap_err();
        assert_eq!(err.error_code(), "obligation_already_resolved");
    }

    // -----------------------------------------------------------------------
    // Leak detection
    // -----------------------------------------------------------------------

    #[test]
    fn detect_leaks_on_closed_cell() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "leak-1",
                TwoPhaseCategory::ResourceAlloc,
                "will leak",
            )
            .unwrap();

        // Close the cell (obligation is force-aborted by drain timeout)
        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        let leaks = tracker.detect_leaks(&cell);
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].operation_id, "leak-1");
        assert_eq!(leaks[0].category, TwoPhaseCategory::ResourceAlloc);

        assert!(tracker.has_leaks());
        assert_eq!(tracker.leaks().len(), 1);
    }

    #[test]
    fn no_leaks_when_all_committed() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "op-1",
                TwoPhaseCategory::EvidenceCommit,
                "evidence",
            )
            .unwrap();
        tracker.commit_operation(&mut cell, "op-1").unwrap();

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let leaks = tracker.detect_leaks(&cell);
        assert!(leaks.is_empty());
        assert!(!tracker.has_leaks());
    }

    #[test]
    fn no_leaks_when_cell_still_running() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "op-1",
                TwoPhaseCategory::ResourceAlloc,
                "pending",
            )
            .unwrap();

        // Cell still running — detect_leaks should not flag anything
        let leaks = tracker.detect_leaks(&cell);
        assert!(leaks.is_empty());
    }

    #[test]
    fn multiple_leaks_from_same_cell() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "leak-1",
                TwoPhaseCategory::ResourceAlloc,
                "alloc",
            )
            .unwrap();
        tracker
            .begin_operation(
                &mut cell,
                "leak-2",
                TwoPhaseCategory::PermissionGrant,
                "perm",
            )
            .unwrap();

        cell.close(
            &mut cx,
            CancelReason::Quarantine,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        let leaks = tracker.detect_leaks(&cell);
        assert_eq!(leaks.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Evidence emission
    // -----------------------------------------------------------------------

    #[test]
    fn begin_commit_emits_events() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "op-1", TwoPhaseCategory::StateMutation, "tx")
            .unwrap();
        tracker.commit_operation(&mut cell, "op-1").unwrap();

        let events = tracker.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "begin");
        assert_eq!(events[0].phase, OperationPhase::Phase1Active);
        assert_eq!(events[1].event, "commit");
        assert_eq!(events[1].phase, OperationPhase::Committed);
    }

    #[test]
    fn leak_detection_emits_events() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
            .unwrap();

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        tracker.detect_leaks(&cell);

        let events = tracker.events();
        let leak_event = events.iter().find(|e| e.event == "leak_detected");
        assert!(leak_event.is_some());
        assert_eq!(leak_event.unwrap().outcome, "leaked");
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "op-1", TwoPhaseCategory::EvidenceCommit, "ev")
            .unwrap();

        let events = tracker.drain_events();
        assert!(!events.is_empty());
        assert!(tracker.events().is_empty());
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------

    #[test]
    fn category_stats_accumulate() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "alloc-1", TwoPhaseCategory::ResourceAlloc, "a1")
            .unwrap();
        tracker
            .begin_operation(&mut cell, "alloc-2", TwoPhaseCategory::ResourceAlloc, "a2")
            .unwrap();
        tracker
            .begin_operation(&mut cell, "perm-1", TwoPhaseCategory::PermissionGrant, "p1")
            .unwrap();

        tracker.commit_operation(&mut cell, "alloc-1").unwrap();
        tracker.abort_operation(&mut cell, "alloc-2").unwrap();

        let stats = tracker.category_stats();
        let alloc_stats = stats.get(&TwoPhaseCategory::ResourceAlloc).unwrap();
        assert_eq!(alloc_stats.started, 2);
        assert_eq!(alloc_stats.committed, 1);
        assert_eq!(alloc_stats.aborted, 1);

        let perm_stats = stats.get(&TwoPhaseCategory::PermissionGrant).unwrap();
        assert_eq!(perm_stats.started, 1);
        assert_eq!(perm_stats.committed, 0);
    }

    // -----------------------------------------------------------------------
    // LeakPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn lab_mode_tracker() {
        let tracker = ObligationTracker::lab();
        assert_eq!(tracker.leak_policy(), LeakPolicy::Lab);
    }

    #[test]
    fn default_production_mode() {
        let tracker = ObligationTracker::default();
        assert_eq!(tracker.leak_policy(), LeakPolicy::Production);
    }

    #[test]
    fn lab_policy_marks_failure_gate_and_emits_lab_failure_event() {
        let mut cell = ExecutionCell::new("ext-lab", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::lab();

        tracker
            .begin_operation(&mut cell, "op-lab", TwoPhaseCategory::ResourceAlloc, "leak")
            .unwrap();
        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 1 },
        )
        .unwrap();

        tracker.detect_leaks(&cell);
        assert!(tracker.should_fail_run());
        assert!(tracker.events().iter().any(|event| {
            event.event == "lab_failure"
                && event.outcome == "fatal"
                && event.operation_id == "op-lab"
        }));
    }

    #[test]
    fn production_policy_logs_fallback_and_does_not_mark_failure_gate() {
        let mut cell = ExecutionCell::new("ext-prod", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "op-prod",
                TwoPhaseCategory::PermissionGrant,
                "leak",
            )
            .unwrap();
        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 1 },
        )
        .unwrap();

        tracker.detect_leaks(&cell);
        assert!(!tracker.should_fail_run());
        assert!(tracker.events().iter().any(|event| {
            event.event == "production_fallback"
                && event.outcome == "forced_cleanup"
                && event.operation_id == "op-prod"
        }));
    }

    // -----------------------------------------------------------------------
    // Multi-category operations
    // -----------------------------------------------------------------------

    #[test]
    fn mixed_category_operations() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "alloc-1",
                TwoPhaseCategory::ResourceAlloc,
                "buffer",
            )
            .unwrap();
        tracker
            .begin_operation(
                &mut cell,
                "tx-1",
                TwoPhaseCategory::StateMutation,
                "update config",
            )
            .unwrap();
        tracker
            .begin_operation(
                &mut cell,
                "ev-1",
                TwoPhaseCategory::EvidenceCommit,
                "evidence batch",
            )
            .unwrap();

        assert_eq!(tracker.active_count(), 3);
        assert_eq!(cell.pending_obligations(), 3);

        tracker.commit_operation(&mut cell, "alloc-1").unwrap();
        tracker.commit_operation(&mut cell, "tx-1").unwrap();
        tracker.commit_operation(&mut cell, "ev-1").unwrap();

        assert_eq!(tracker.active_count(), 0);
        assert_eq!(cell.pending_obligations(), 0);
    }

    // -----------------------------------------------------------------------
    // Cancellation interaction
    // -----------------------------------------------------------------------

    #[test]
    fn obligations_during_cancellation() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "alloc-1",
                TwoPhaseCategory::ResourceAlloc,
                "buffer",
            )
            .unwrap();

        // Initiate close with short drain deadline
        cell.initiate_close(
            &mut cx,
            CancelReason::Quarantine,
            DrainDeadline { max_ticks: 10 },
        )
        .unwrap();

        // Resolve obligation during drain
        tracker.commit_operation(&mut cell, "alloc-1").unwrap();

        let result = cell.finalize().unwrap();
        assert!(result.success);
        assert_eq!(result.obligations_committed, 1);
    }

    // -----------------------------------------------------------------------
    // Deterministic replay
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_events() {
        let run = || -> Vec<ObligationEvent> {
            let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
            let mut tracker = ObligationTracker::default();

            tracker
                .begin_operation(
                    &mut cell,
                    "alloc-1",
                    TwoPhaseCategory::ResourceAlloc,
                    "buffer",
                )
                .unwrap();
            tracker
                .begin_operation(&mut cell, "tx-1", TwoPhaseCategory::StateMutation, "config")
                .unwrap();
            tracker.commit_operation(&mut cell, "alloc-1").unwrap();
            tracker.abort_operation(&mut cell, "tx-1").unwrap();
            tracker.drain_events()
        };

        let e1 = run();
        let e2 = run();
        assert_eq!(e1, e2);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn two_phase_operation_serde_roundtrip() {
        let op = TwoPhaseOperation {
            operation_id: "op-1".to_string(),
            cell_id: "c".to_string(),
            category: TwoPhaseCategory::ResourceAlloc,
            description: "alloc buffer".to_string(),
            trace_id: "t".to_string(),
            phase: OperationPhase::Phase1Active,
        };
        let json = serde_json::to_string(&op).expect("serialize");
        let restored: TwoPhaseOperation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(op, restored);
    }

    #[test]
    fn obligation_event_serde_roundtrip() {
        let event = ObligationEvent {
            trace_id: "t".to_string(),
            cell_id: "c".to_string(),
            cell_kind: CellKind::Extension,
            operation_id: "op-1".to_string(),
            category: TwoPhaseCategory::EvidenceCommit,
            event: "begin".to_string(),
            outcome: "phase1_active".to_string(),
            component: "obligation_integration".to_string(),
            phase: OperationPhase::Phase1Active,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: ObligationEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn leak_record_serde_roundtrip() {
        let leak = LeakRecord {
            operation_id: "op-1".to_string(),
            cell_id: "c".to_string(),
            category: TwoPhaseCategory::ResourceAlloc,
            trace_id: "t".to_string(),
            description: "leaked buffer".to_string(),
        };
        let json = serde_json::to_string(&leak).expect("serialize");
        let restored: LeakRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(leak, restored);
    }

    #[test]
    fn category_stats_serde_roundtrip() {
        let stats = CategoryStats {
            started: 5,
            committed: 3,
            aborted: 1,
            leaked: 1,
        };
        let json = serde_json::to_string(&stats).expect("serialize");
        let restored: CategoryStats = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(stats, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment tests (bd-m9pa audit)
    // -----------------------------------------------------------------------

    #[test]
    fn parent_region_closed_before_obligation_fulfillment() {
        // Create a region, create obligation, close region before fulfilling.
        let mut cell = ExecutionCell::new("ext-close", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::lab();

        tracker
            .begin_operation(
                &mut cell,
                "unfulfilled-1",
                TwoPhaseCategory::ResourceAlloc,
                "buffer not freed",
            )
            .unwrap();

        // Close the cell — obligation force-aborted by timeout
        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        // Detect leaks — lab mode
        let leaks = tracker.detect_leaks(&cell);
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].operation_id, "unfulfilled-1");

        // Verify leak event emitted
        let leak_events: Vec<_> = tracker
            .events()
            .iter()
            .filter(|e| e.event == "leak_detected")
            .collect();
        assert_eq!(leak_events.len(), 1);
        assert_eq!(leak_events[0].outcome, "leaked");
        assert_eq!(leak_events[0].operation_id, "unfulfilled-1");
    }

    #[test]
    fn fulfillment_after_region_cancel_rejected() {
        // Create region with obligation, cancel region, attempt fulfillment.
        let mut cell = ExecutionCell::new("ext-cancel", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "op-cancel",
                TwoPhaseCategory::PermissionGrant,
                "grant revoked",
            )
            .unwrap();

        // Close the cell (cancel + drain + finalize)
        cell.close(
            &mut cx,
            CancelReason::Revocation,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        // Attempt to commit after close — cell obligation already resolved
        let result = tracker.commit_operation(&mut cell, "op-cancel");
        assert!(result.is_err());
    }

    #[test]
    fn new_obligation_during_drain_rejected() {
        // Region enters drain phase, then attempt to create new obligation.
        let mut cell = ExecutionCell::new("ext-drain", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        // Initiate close (enters CancelRequested → Draining)
        cell.initiate_close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 100 },
        )
        .unwrap();

        // Attempt to begin new obligation during drain
        let result = tracker.begin_operation(
            &mut cell,
            "new-during-drain",
            TwoPhaseCategory::StateMutation,
            "should be rejected",
        );

        // Cell is not Running, so begin_operation must reject
        assert!(result.is_err());
        match result.unwrap_err() {
            ObligationIntegrationError::CellNotRunning { current_state, .. } => {
                // Cell should be in Draining state
                assert_ne!(current_state, RegionState::Running);
            }
            other => panic!("expected CellNotRunning, got: {other}"),
        }
    }

    #[test]
    fn session_cell_obligations_tracked_independently() {
        // Create extension cell with session child, both with obligations.
        let mut ext_cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut ext_cell,
                "ext-alloc",
                TwoPhaseCategory::ResourceAlloc,
                "extension buffer",
            )
            .unwrap();

        // Create a session cell
        let mut session_cell = ext_cell.create_session("sess-1", "t").unwrap();

        tracker
            .begin_operation(
                &mut session_cell,
                "sess-alloc",
                TwoPhaseCategory::ResourceAlloc,
                "session buffer",
            )
            .unwrap();

        assert_eq!(tracker.active_count(), 2);

        // Commit only the session obligation
        tracker
            .commit_operation(&mut session_cell, "sess-alloc")
            .unwrap();

        assert_eq!(tracker.active_count(), 1);

        // The remaining active one belongs to ext_cell
        let op = tracker.get_operation("ext-alloc").unwrap();
        assert_eq!(op.phase, OperationPhase::Phase1Active);
    }

    #[test]
    fn all_four_categories_in_single_lifecycle() {
        // Exercise all four two-phase categories in one extension lifecycle.
        let mut cell = ExecutionCell::new("ext-all", CellKind::Extension, "t");
        let mut cx = mock_cx(500);
        let mut tracker = ObligationTracker::default();

        let categories = [
            ("res-1", TwoPhaseCategory::ResourceAlloc, "memory alloc"),
            ("perm-1", TwoPhaseCategory::PermissionGrant, "network grant"),
            ("state-1", TwoPhaseCategory::StateMutation, "config update"),
            ("ev-1", TwoPhaseCategory::EvidenceCommit, "evidence batch"),
        ];

        for (id, cat, desc) in &categories {
            tracker
                .begin_operation(&mut cell, *id, *cat, *desc)
                .unwrap();
        }
        assert_eq!(tracker.active_count(), 4);
        assert_eq!(cell.pending_obligations(), 4);

        // Commit first two, abort the rest
        tracker.commit_operation(&mut cell, "res-1").unwrap();
        tracker.commit_operation(&mut cell, "perm-1").unwrap();
        tracker.abort_operation(&mut cell, "state-1").unwrap();
        tracker.abort_operation(&mut cell, "ev-1").unwrap();

        assert_eq!(tracker.active_count(), 0);
        assert_eq!(cell.pending_obligations(), 0);

        // Close cleanly
        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let leaks = tracker.detect_leaks(&cell);
        assert!(leaks.is_empty());

        // Verify stats
        let stats = tracker.category_stats();
        for (_, cat, _) in &categories {
            assert_eq!(stats[cat].started, 1);
        }
        assert_eq!(stats[&TwoPhaseCategory::ResourceAlloc].committed, 1);
        assert_eq!(stats[&TwoPhaseCategory::StateMutation].aborted, 1);
    }

    #[test]
    fn leak_record_contains_correct_metadata() {
        let mut cell = ExecutionCell::new("ext-meta", CellKind::Extension, "trace-42");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "meta-op",
                TwoPhaseCategory::PermissionGrant,
                "grant with metadata",
            )
            .unwrap();

        cell.close(
            &mut cx,
            CancelReason::Quarantine,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        let leaks = tracker.detect_leaks(&cell);
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].operation_id, "meta-op");
        assert_eq!(leaks[0].cell_id, "ext-meta");
        assert_eq!(leaks[0].category, TwoPhaseCategory::PermissionGrant);
        assert_eq!(leaks[0].description, "grant with metadata");
    }

    #[test]
    fn obligation_event_component_field_stable() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "alloc")
            .unwrap();

        for event in tracker.events() {
            assert_eq!(event.component, "obligation_integration");
        }
    }

    #[test]
    fn operation_phase_leaked_is_terminal() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "op-leak",
                TwoPhaseCategory::ResourceAlloc,
                "will leak",
            )
            .unwrap();

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        tracker.detect_leaks(&cell);

        // Verify the operation phase is Leaked
        let op = tracker.get_operation("op-leak").unwrap();
        assert_eq!(op.phase, OperationPhase::Leaked);
    }

    #[test]
    fn leak_policy_serde_roundtrip() {
        for policy in [LeakPolicy::Lab, LeakPolicy::Production] {
            let json = serde_json::to_string(&policy).expect("serialize");
            let restored: LeakPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(policy, restored);
        }
    }

    #[test]
    fn error_from_cell_error() {
        let cell_err = CellError::CellNotFound {
            cell_id: "missing".to_string(),
        };
        let integration_err: ObligationIntegrationError = cell_err.into();
        assert_eq!(integration_err.error_code(), "obligation_cell_error");
        assert!(integration_err.to_string().contains("missing"));
    }

    // --- Enrichment tests ---

    #[test]
    fn category_display_uniqueness_btreeset() {
        let cats = [
            TwoPhaseCategory::ResourceAlloc,
            TwoPhaseCategory::PermissionGrant,
            TwoPhaseCategory::StateMutation,
            TwoPhaseCategory::EvidenceCommit,
        ];
        let displays: std::collections::BTreeSet<String> =
            cats.iter().map(|c| c.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn phase_display_uniqueness_btreeset() {
        let phases = [
            OperationPhase::Phase1Active,
            OperationPhase::Committed,
            OperationPhase::Aborted,
            OperationPhase::Leaked,
        ];
        let displays: std::collections::BTreeSet<String> =
            phases.iter().map(|p| p.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn error_display_uniqueness_btreeset() {
        let errors = [
            ObligationIntegrationError::CellNotRunning {
                cell_id: "c1".to_string(),
                current_state: RegionState::Closed,
            },
            ObligationIntegrationError::OperationNotFound {
                operation_id: "op-1".to_string(),
            },
            ObligationIntegrationError::AlreadyResolved {
                operation_id: "op-2".to_string(),
                current_phase: OperationPhase::Committed,
            },
            ObligationIntegrationError::DuplicateOperation {
                operation_id: "op-3".to_string(),
            },
            ObligationIntegrationError::CellError {
                message: "cell broke".to_string(),
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn error_codes_uniqueness_btreeset() {
        let errors = [
            ObligationIntegrationError::CellNotRunning {
                cell_id: "c1".to_string(),
                current_state: RegionState::Closed,
            },
            ObligationIntegrationError::OperationNotFound {
                operation_id: "op-1".to_string(),
            },
            ObligationIntegrationError::AlreadyResolved {
                operation_id: "op-2".to_string(),
                current_phase: OperationPhase::Committed,
            },
            ObligationIntegrationError::DuplicateOperation {
                operation_id: "op-3".to_string(),
            },
            ObligationIntegrationError::CellError {
                message: "cell error".to_string(),
            },
        ];
        let codes: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.error_code().to_string()).collect();
        assert_eq!(
            codes.len(),
            5,
            "all 5 error variants should have unique error codes"
        );
    }

    #[test]
    fn tracker_default_has_zero_counts() {
        let tracker = ObligationTracker::default();
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_count(), 0);
        assert!(!tracker.has_leaks());
        assert!(!tracker.should_fail_run());
    }

    #[test]
    fn get_operation_returns_none_for_missing() {
        let tracker = ObligationTracker::default();
        assert!(tracker.get_operation("nonexistent").is_none());
    }

    #[test]
    fn category_stats_default_empty() {
        let tracker = ObligationTracker::default();
        let stats = tracker.category_stats();
        assert!(stats.is_empty());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn leak_policy_serde_all_variants() {
        for policy in [LeakPolicy::Lab, LeakPolicy::Production] {
            let json = serde_json::to_string(&policy).unwrap();
            let back: LeakPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, back);
        }
    }

    #[test]
    fn obligation_event_all_phases_serde() {
        for phase in [
            OperationPhase::Phase1Active,
            OperationPhase::Committed,
            OperationPhase::Aborted,
            OperationPhase::Leaked,
        ] {
            let event = ObligationEvent {
                trace_id: "t".to_string(),
                cell_id: "c".to_string(),
                cell_kind: CellKind::Extension,
                operation_id: "op".to_string(),
                category: TwoPhaseCategory::ResourceAlloc,
                event: "test".to_string(),
                outcome: "ok".to_string(),
                component: "obligation_integration".to_string(),
                phase,
            };
            let json = serde_json::to_string(&event).unwrap();
            let back: ObligationEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event.phase, back.phase);
        }
    }

    #[test]
    fn error_code_all_variants_unique() {
        let errors = [
            ObligationIntegrationError::CellNotRunning {
                cell_id: "c".to_string(),
                current_state: RegionState::Closed,
            },
            ObligationIntegrationError::OperationNotFound {
                operation_id: "op".to_string(),
            },
            ObligationIntegrationError::AlreadyResolved {
                operation_id: "op".to_string(),
                current_phase: OperationPhase::Committed,
            },
            ObligationIntegrationError::DuplicateOperation {
                operation_id: "op".to_string(),
            },
            ObligationIntegrationError::CellError {
                message: "err".to_string(),
            },
        ];
        let codes: Vec<&str> = errors.iter().map(|e| e.error_code()).collect();
        let mut deduped = codes.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(codes.len(), deduped.len());
    }

    #[test]
    fn category_display_all_variants_unique() {
        let categories = [
            TwoPhaseCategory::ResourceAlloc,
            TwoPhaseCategory::PermissionGrant,
            TwoPhaseCategory::StateMutation,
            TwoPhaseCategory::EvidenceCommit,
        ];
        let mut displays: Vec<String> = categories.iter().map(|c| c.to_string()).collect();
        let original_len = displays.len();
        displays.sort();
        displays.dedup();
        assert_eq!(displays.len(), original_len);
    }

    #[test]
    fn phase_display_all_variants_unique() {
        let phases = [
            OperationPhase::Phase1Active,
            OperationPhase::Committed,
            OperationPhase::Aborted,
            OperationPhase::Leaked,
        ];
        let mut displays: Vec<String> = phases.iter().map(|p| p.to_string()).collect();
        let original_len = displays.len();
        displays.sort();
        displays.dedup();
        assert_eq!(displays.len(), original_len);
    }

    #[test]
    fn tracker_lab_marks_failure_on_leaks() {
        let mut cell = ExecutionCell::new("c1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::lab();
        assert_eq!(tracker.leak_policy(), LeakPolicy::Lab);
        assert!(!tracker.should_fail_run());

        tracker
            .begin_operation(
                &mut cell,
                "op-leak",
                TwoPhaseCategory::ResourceAlloc,
                "will leak",
            )
            .unwrap();
        // Close cell without resolving
        let mut cx = mock_cx(100);
        let _ = cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        );
        let leaks = tracker.detect_leaks(&cell);
        assert_eq!(leaks.len(), 1);
        assert!(tracker.should_fail_run());
    }

    #[test]
    fn active_and_total_count_track_operations() {
        let mut cell = ExecutionCell::new("c1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_count(), 0);

        tracker
            .begin_operation(&mut cell, "op1", TwoPhaseCategory::ResourceAlloc, "a")
            .unwrap();
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.total_count(), 1);

        tracker.commit_operation(&mut cell, "op1").unwrap();
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_count(), 1);
    }

    #[test]
    fn category_stats_serde_fields_preserved() {
        let stats = CategoryStats {
            started: 10,
            committed: 7,
            aborted: 2,
            leaked: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: CategoryStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats.started, back.started);
        assert_eq!(stats.committed, back.committed);
        assert_eq!(stats.aborted, back.aborted);
        assert_eq!(stats.leaked, back.leaked);
    }

    #[test]
    fn get_operation_returns_correct_phase() {
        let mut cell = ExecutionCell::new("c1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();
        tracker
            .begin_operation(
                &mut cell,
                "op-check",
                TwoPhaseCategory::StateMutation,
                "test",
            )
            .unwrap();
        let op = tracker.get_operation("op-check").unwrap();
        assert!(matches!(op.phase, OperationPhase::Phase1Active));
        assert_eq!(op.category, TwoPhaseCategory::StateMutation);
    }

    // -----------------------------------------------------------------------
    // Enrichment tests — PearlTower 2026-03-02
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_two_phase_category_clone_eq() {
        let cat = TwoPhaseCategory::StateMutation;
        let cloned = cat;
        assert_eq!(cat, cloned);
        let cat2 = TwoPhaseCategory::ResourceAlloc;
        assert_ne!(cat, cat2);
    }

    #[test]
    fn enrichment_two_phase_category_hash_consistency() {
        use std::collections::BTreeSet;
        use std::hash::{Hash, Hasher};
        let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
        let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
        TwoPhaseCategory::EvidenceCommit.hash(&mut hasher1);
        TwoPhaseCategory::EvidenceCommit.hash(&mut hasher2);
        assert_eq!(hasher1.finish(), hasher2.finish());

        // All four variants produce distinct hashes (with high probability)
        let hashes: BTreeSet<u64> = [
            TwoPhaseCategory::ResourceAlloc,
            TwoPhaseCategory::PermissionGrant,
            TwoPhaseCategory::StateMutation,
            TwoPhaseCategory::EvidenceCommit,
        ]
        .iter()
        .map(|c| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            c.hash(&mut h);
            h.finish()
        })
        .collect();
        assert_eq!(hashes.len(), 4);
    }

    #[test]
    fn enrichment_operation_phase_copy_semantics() {
        let phase = OperationPhase::Committed;
        let copied = phase;
        assert_eq!(phase, copied);
        // Both are still usable after copy
        assert_eq!(phase.to_string(), "committed");
        assert_eq!(copied.to_string(), "committed");
    }

    #[test]
    fn enrichment_operation_phase_ordering() {
        assert!(OperationPhase::Phase1Active < OperationPhase::Committed);
        assert!(OperationPhase::Committed < OperationPhase::Aborted);
        assert!(OperationPhase::Aborted < OperationPhase::Leaked);
    }

    #[test]
    fn enrichment_operation_phase_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        OperationPhase::Aborted.hash(&mut h1);
        OperationPhase::Aborted.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn enrichment_two_phase_operation_clone_eq() {
        let op = TwoPhaseOperation {
            operation_id: "op-x".to_string(),
            cell_id: "c-1".to_string(),
            category: TwoPhaseCategory::EvidenceCommit,
            description: "evidence pair".to_string(),
            trace_id: "trace-99".to_string(),
            phase: OperationPhase::Phase1Active,
        };
        let cloned = op.clone();
        assert_eq!(op, cloned);
    }

    #[test]
    fn enrichment_two_phase_operation_json_field_names() {
        let op = TwoPhaseOperation {
            operation_id: "op-json".to_string(),
            cell_id: "cell-json".to_string(),
            category: TwoPhaseCategory::PermissionGrant,
            description: "desc".to_string(),
            trace_id: "trace-json".to_string(),
            phase: OperationPhase::Committed,
        };
        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["operation_id"], "op-json");
        assert_eq!(json["cell_id"], "cell-json");
        assert_eq!(json["category"], "PermissionGrant");
        assert_eq!(json["description"], "desc");
        assert_eq!(json["trace_id"], "trace-json");
        assert_eq!(json["phase"], "Committed");
    }

    #[test]
    fn enrichment_obligation_event_json_field_names() {
        let event = ObligationEvent {
            trace_id: "t-1".to_string(),
            cell_id: "c-1".to_string(),
            cell_kind: CellKind::Session,
            operation_id: "op-1".to_string(),
            category: TwoPhaseCategory::StateMutation,
            event: "begin".to_string(),
            outcome: "phase1_active".to_string(),
            component: "obligation_integration".to_string(),
            phase: OperationPhase::Phase1Active,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["trace_id"], "t-1");
        assert_eq!(json["cell_id"], "c-1");
        assert_eq!(json["cell_kind"], "Session");
        assert_eq!(json["operation_id"], "op-1");
        assert_eq!(json["category"], "StateMutation");
        assert_eq!(json["event"], "begin");
        assert_eq!(json["outcome"], "phase1_active");
        assert_eq!(json["component"], "obligation_integration");
        assert_eq!(json["phase"], "Phase1Active");
    }

    #[test]
    fn enrichment_leak_record_json_field_names() {
        let leak = LeakRecord {
            operation_id: "op-leak".to_string(),
            cell_id: "cell-leak".to_string(),
            category: TwoPhaseCategory::ResourceAlloc,
            trace_id: "trace-leak".to_string(),
            description: "leaked resource".to_string(),
        };
        let json = serde_json::to_value(&leak).unwrap();
        assert_eq!(json["operation_id"], "op-leak");
        assert_eq!(json["cell_id"], "cell-leak");
        assert_eq!(json["category"], "ResourceAlloc");
        assert_eq!(json["trace_id"], "trace-leak");
        assert_eq!(json["description"], "leaked resource");
    }

    #[test]
    fn enrichment_leak_record_clone_eq() {
        let leak = LeakRecord {
            operation_id: "op-1".to_string(),
            cell_id: "c-1".to_string(),
            category: TwoPhaseCategory::StateMutation,
            trace_id: "t-1".to_string(),
            description: "test leak".to_string(),
        };
        let cloned = leak.clone();
        assert_eq!(leak, cloned);
    }

    #[test]
    fn enrichment_category_stats_default_all_zero() {
        let stats = CategoryStats::default();
        assert_eq!(stats.started, 0);
        assert_eq!(stats.committed, 0);
        assert_eq!(stats.aborted, 0);
        assert_eq!(stats.leaked, 0);
    }

    #[test]
    fn enrichment_category_stats_json_field_names() {
        let stats = CategoryStats {
            started: 42,
            committed: 30,
            aborted: 10,
            leaked: 2,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["started"], 42);
        assert_eq!(json["committed"], 30);
        assert_eq!(json["aborted"], 10);
        assert_eq!(json["leaked"], 2);
    }

    #[test]
    fn enrichment_error_display_contains_context() {
        let err = ObligationIntegrationError::CellNotRunning {
            cell_id: "cell-42".to_string(),
            current_state: RegionState::Draining,
        };
        let msg = err.to_string();
        assert!(msg.contains("cell-42"), "should contain cell_id");
        assert!(msg.contains("draining"), "should contain state display");

        let err2 = ObligationIntegrationError::AlreadyResolved {
            operation_id: "op-99".to_string(),
            current_phase: OperationPhase::Aborted,
        };
        let msg2 = err2.to_string();
        assert!(msg2.contains("op-99"), "should contain operation_id");
        assert!(msg2.contains("aborted"), "should contain phase display");
    }

    #[test]
    fn enrichment_error_serde_all_variants() {
        let errors = [
            ObligationIntegrationError::CellNotRunning {
                cell_id: "c".to_string(),
                current_state: RegionState::Running,
            },
            ObligationIntegrationError::OperationNotFound {
                operation_id: "op".to_string(),
            },
            ObligationIntegrationError::AlreadyResolved {
                operation_id: "op".to_string(),
                current_phase: OperationPhase::Leaked,
            },
            ObligationIntegrationError::DuplicateOperation {
                operation_id: "op".to_string(),
            },
            ObligationIntegrationError::CellError {
                message: "msg".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: ObligationIntegrationError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn enrichment_error_is_std_error() {
        let err = ObligationIntegrationError::OperationNotFound {
            operation_id: "x".to_string(),
        };
        // Verify it implements std::error::Error by using the trait
        let dyn_err: &dyn std::error::Error = &err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn enrichment_abort_nonexistent_fails() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();
        let err = tracker
            .abort_operation(&mut cell, "nonexistent")
            .unwrap_err();
        assert_eq!(err.error_code(), "obligation_operation_not_found");
    }

    #[test]
    fn enrichment_commit_after_abort_fails() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();
        tracker
            .begin_operation(&mut cell, "op-1", TwoPhaseCategory::ResourceAlloc, "res")
            .unwrap();
        tracker.abort_operation(&mut cell, "op-1").unwrap();
        let err = tracker.commit_operation(&mut cell, "op-1").unwrap_err();
        assert_eq!(err.error_code(), "obligation_already_resolved");
        match err {
            ObligationIntegrationError::AlreadyResolved { current_phase, .. } => {
                assert_eq!(current_phase, OperationPhase::Aborted);
            }
            other => panic!("expected AlreadyResolved, got: {other}"),
        }
    }

    #[test]
    fn enrichment_abort_emits_events() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();
        tracker
            .begin_operation(
                &mut cell,
                "op-abort-ev",
                TwoPhaseCategory::PermissionGrant,
                "perm",
            )
            .unwrap();
        tracker.abort_operation(&mut cell, "op-abort-ev").unwrap();

        let events = tracker.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "begin");
        assert_eq!(events[0].phase, OperationPhase::Phase1Active);
        assert_eq!(events[1].event, "abort");
        assert_eq!(events[1].phase, OperationPhase::Aborted);
        assert_eq!(events[1].operation_id, "op-abort-ev");
    }

    #[test]
    fn enrichment_leak_stats_increment() {
        let mut cell = ExecutionCell::new("ext-leak-stats", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "leak-stat-1",
                TwoPhaseCategory::EvidenceCommit,
                "evidence",
            )
            .unwrap();

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 5 },
        )
        .unwrap();

        tracker.detect_leaks(&cell);

        let stats = tracker.category_stats();
        let ev_stats = stats.get(&TwoPhaseCategory::EvidenceCommit).unwrap();
        assert_eq!(ev_stats.started, 1);
        assert_eq!(ev_stats.leaked, 1);
        assert_eq!(ev_stats.committed, 0);
        assert_eq!(ev_stats.aborted, 0);
    }

    #[test]
    fn enrichment_detect_leaks_idempotent_on_running_cell() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut tracker = ObligationTracker::default();

        tracker
            .begin_operation(
                &mut cell,
                "op-still-active",
                TwoPhaseCategory::ResourceAlloc,
                "alloc",
            )
            .unwrap();

        // Call detect_leaks multiple times on running cell — no leaks each time
        for _ in 0..3 {
            let leaks = tracker.detect_leaks(&cell);
            assert!(leaks.is_empty());
        }
        assert!(!tracker.has_leaks());
        assert_eq!(tracker.active_count(), 1);
    }
}
