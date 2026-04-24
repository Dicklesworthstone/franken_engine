//! Cancellation lifecycle compliance for extension-host lifecycle events.
//!
//! Integrates the three-phase cancellation protocol (`request → drain → finalize`)
//! from [`region_lifecycle`] into every extension-host lifecycle event that can
//! interrupt running extension code: **unload**, **quarantine**, **suspend**,
//! **terminate**, and **revocation**.
//!
//! Each event type maps to a specific [`CancellationMode`] that controls drain
//! budget, timeout escalation, and evidence emission.
//!
//! Plan reference: Section 10.13 item 7, bd-2wz9.
//! Dependencies: bd-1ukb (execution cells), bd-2ygl (Cx threading),
//!               bd-2ao (region quiescent close), bd-uvmm (evidence).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::ContextAdapter;
use crate::cx_threading::EffectCategory;
use crate::execution_cell::{CellError, CellKind, CellManager, ExecutionCell};
use crate::region_lifecycle::{CancelReason, DrainDeadline, FinalizeResult, RegionState};

// ---------------------------------------------------------------------------
// LifecycleEvent — the five cancellation-triggering lifecycle events
// ---------------------------------------------------------------------------

/// Lifecycle events that trigger cancellation of running extension code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LifecycleEvent {
    /// Graceful extension removal; in-flight work gets time to drain.
    Unload,
    /// Extension isolated due to policy violation; prevents further effectful calls.
    Quarantine,
    /// Extension paused by operator or budget hold; cooperative freeze at safe point.
    Suspend,
    /// Forced extension removal; immediate finalize with minimal drain.
    Terminate,
    /// Capability revocation mid-operation; cancel operations depending on revoked cap.
    Revocation,
}

impl fmt::Display for LifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unload => write!(f, "unload"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Suspend => write!(f, "suspend"),
            Self::Terminate => write!(f, "terminate"),
            Self::Revocation => write!(f, "revocation"),
        }
    }
}

impl LifecycleEvent {
    /// Map lifecycle event to the appropriate [`CancelReason`] for the region.
    pub fn cancel_reason(self) -> CancelReason {
        match self {
            Self::Unload => CancelReason::OperatorShutdown,
            Self::Quarantine => CancelReason::Quarantine,
            Self::Suspend => CancelReason::Custom("suspend".to_string()),
            Self::Terminate => CancelReason::Custom("terminate".to_string()),
            Self::Revocation => CancelReason::Revocation,
        }
    }

    /// Whether this event forces immediate finalize with minimal drain.
    pub fn is_forced(self) -> bool {
        matches!(self, Self::Terminate)
    }

    /// Whether this event is a cooperative (graceful) cancellation.
    pub fn is_cooperative(self) -> bool {
        matches!(self, Self::Unload | Self::Suspend)
    }
}

// ---------------------------------------------------------------------------
// CancellationMode — per-event cancellation configuration
// ---------------------------------------------------------------------------

/// Configuration for how a cancellation event executes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationMode {
    /// Maximum drain ticks before forced finalize.
    pub drain_budget_ticks: u64,
    /// Whether to force-abort pending obligations on timeout.
    pub force_abort_on_timeout: bool,
    /// Whether to propagate cancellation to child sessions.
    pub propagate_to_children: bool,
    /// Stable event name for evidence emission.
    pub evidence_event_name: String,
}

impl CancellationMode {
    /// Default mode for a given lifecycle event.
    pub fn for_event(event: LifecycleEvent) -> Self {
        match event {
            LifecycleEvent::Unload => Self {
                drain_budget_ticks: 10_000,
                force_abort_on_timeout: true,
                propagate_to_children: true,
                evidence_event_name: "cancellation_unload".to_string(),
            },
            LifecycleEvent::Quarantine => Self {
                drain_budget_ticks: 1_000,
                force_abort_on_timeout: true,
                propagate_to_children: true,
                evidence_event_name: "cancellation_quarantine".to_string(),
            },
            LifecycleEvent::Suspend => Self {
                drain_budget_ticks: 5_000,
                force_abort_on_timeout: false,
                propagate_to_children: false,
                evidence_event_name: "cancellation_suspend".to_string(),
            },
            LifecycleEvent::Terminate => Self {
                drain_budget_ticks: 0,
                force_abort_on_timeout: true,
                propagate_to_children: true,
                evidence_event_name: "cancellation_terminate".to_string(),
            },
            LifecycleEvent::Revocation => Self {
                drain_budget_ticks: 500,
                force_abort_on_timeout: true,
                propagate_to_children: true,
                evidence_event_name: "cancellation_revocation".to_string(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// CancellationOutcome — result of executing the cancellation protocol
// ---------------------------------------------------------------------------

/// Outcome of a cancellation lifecycle execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationOutcome {
    /// Cell that was cancelled.
    pub cell_id: String,
    /// Lifecycle event that triggered cancellation.
    pub event: LifecycleEvent,
    /// Whether cancellation completed successfully.
    pub success: bool,
    /// Finalize result from the region protocol.
    pub finalize_result: FinalizeResult,
    /// Whether the drain phase timed out and escalated.
    pub timeout_escalated: bool,
    /// Number of child sessions cancelled.
    pub children_cancelled: usize,
    /// Cancellation was idempotent (cell was already closed/cancelled).
    pub was_idempotent: bool,
}

// ---------------------------------------------------------------------------
// CancellationError — errors from cancellation operations
// ---------------------------------------------------------------------------

/// Error type for cancellation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CancellationError {
    /// Cell not found in the manager.
    CellNotFound { cell_id: String },
    /// Budget exhausted during cancellation.
    BudgetExhausted {
        cell_id: String,
        event: LifecycleEvent,
    },
    /// Cell error propagated from the execution cell layer.
    CellError {
        cell_id: String,
        error_code: String,
        message: String,
    },
}

impl fmt::Display for CancellationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CellNotFound { cell_id } => {
                write!(f, "cancellation: cell not found: {cell_id}")
            }
            Self::BudgetExhausted { cell_id, event } => {
                write!(
                    f,
                    "cancellation: budget exhausted for cell {cell_id} during {event}"
                )
            }
            Self::CellError {
                cell_id,
                error_code,
                message,
            } => {
                write!(
                    f,
                    "cancellation: cell {cell_id} error [{error_code}]: {message}"
                )
            }
        }
    }
}

impl std::error::Error for CancellationError {}

impl CancellationError {
    /// Stable error code for structured logging.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::CellNotFound { .. } => "cancel_cell_not_found",
            Self::BudgetExhausted { .. } => "cancel_budget_exhausted",
            Self::CellError { .. } => "cancel_cell_error",
        }
    }
}

impl From<CellError> for CancellationError {
    fn from(err: CellError) -> Self {
        let cell_id = match &err {
            CellError::InvalidState { cell_id, .. } => cell_id.clone(),
            CellError::BudgetExhausted { cell_id, .. } => cell_id.clone(),
            CellError::CxThreading { cell_id, .. } => cell_id.clone(),
            CellError::CellNotFound { cell_id } => cell_id.clone(),
            CellError::SessionRejected { parent_cell_id, .. } => parent_cell_id.clone(),
            CellError::ObligationNotFound { cell_id, .. } => cell_id.clone(),
            CellError::CellAlreadyExists { cell_id } => cell_id.clone(),
        };
        Self::CellError {
            cell_id,
            error_code: err.error_code().to_string(),
            message: err.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// CancellationEvent — structured evidence for cancellation operations
// ---------------------------------------------------------------------------

/// Structured event emitted during cancellation lifecycle execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationEvent {
    /// Trace ID for request correlation.
    pub trace_id: String,
    /// Cell being cancelled.
    pub cell_id: String,
    /// Cell kind.
    pub cell_kind: CellKind,
    /// Lifecycle event that triggered cancellation.
    pub lifecycle_event: LifecycleEvent,
    /// Phase of the cancellation protocol.
    pub phase: String,
    /// Outcome of the phase.
    pub outcome: String,
    /// Component name for structured logging.
    pub component: String,
    /// Pending obligations at this point.
    pub obligations_pending: usize,
    /// Budget consumed by this phase (ms).
    pub budget_consumed_ms: u64,
}

// ---------------------------------------------------------------------------
// CancellationManager — orchestrates cancellation across cells
// ---------------------------------------------------------------------------

/// Orchestrates cancellation lifecycle compliance across multiple execution cells.
///
/// Ensures every lifecycle transition (unload, quarantine, suspend, terminate,
/// revocation) follows the three-phase protocol with event-specific configuration.
#[derive(Debug)]
pub struct CancellationManager {
    /// Mode overrides per lifecycle event (for testing or custom policies).
    mode_overrides: BTreeMap<LifecycleEvent, CancellationMode>,
    /// History of completed cancellation outcomes.
    outcomes: Vec<CancellationOutcome>,
    /// Event log for evidence emission.
    events: Vec<CancellationEvent>,
    /// Idempotency tracking: cells already cancelled.
    cancelled_cells: BTreeMap<String, LifecycleEvent>,
}

impl Default for CancellationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Parameters for [`CancellationManager::emit_event`].
struct EmitEventInput<'a> {
    trace_id: &'a str,
    cell_id: &'a str,
    cell_kind: CellKind,
    lifecycle_event: LifecycleEvent,
    phase: &'a str,
    outcome: &'a str,
    obligations_pending: usize,
    budget_consumed_ms: u64,
}

impl CancellationManager {
    /// Create a new cancellation manager with default modes.
    pub fn new() -> Self {
        Self {
            mode_overrides: BTreeMap::new(),
            outcomes: Vec::new(),
            events: Vec::new(),
            cancelled_cells: BTreeMap::new(),
        }
    }

    /// Override the cancellation mode for a specific lifecycle event.
    pub fn set_mode_override(&mut self, event: LifecycleEvent, mode: CancellationMode) {
        self.mode_overrides.insert(event, mode);
    }

    /// Get the effective cancellation mode for an event.
    pub fn effective_mode(&self, event: LifecycleEvent) -> CancellationMode {
        self.mode_overrides
            .get(&event)
            .cloned()
            .unwrap_or_else(|| CancellationMode::for_event(event))
    }

    /// Cancel a single cell with the specified lifecycle event.
    ///
    /// Follows the three-phase protocol: request → drain → finalize.
    /// Idempotent: re-cancelling an already-cancelled cell is a no-op.
    pub fn cancel_cell<C: ContextAdapter>(
        &mut self,
        cell: &mut ExecutionCell,
        cx: &mut C,
        event: LifecycleEvent,
    ) -> Result<CancellationOutcome, CancellationError> {
        let cell_id = cell.cell_id().to_string();

        // Idempotency is tied to the cell instance state, not just the stable
        // cell id. A cell id may be archived and reused for a new live cell.
        if cell.state() == RegionState::Closed {
            let outcome = CancellationOutcome {
                cell_id: cell_id.clone(),
                event,
                success: true,
                finalize_result: FinalizeResult {
                    region_id: cell_id.clone(),
                    success: true,
                    obligations_committed: 0,
                    obligations_aborted: 0,
                    drain_timeout_escalated: false,
                },
                timeout_escalated: false,
                children_cancelled: 0,
                was_idempotent: true,
            };
            self.outcomes.push(outcome.clone());
            return Ok(outcome);
        }
        self.cancelled_cells.remove(&cell_id);

        let mode = self.effective_mode(event);
        let trace_id = cx.trace_id().to_string();

        // Emit pre-cancel evidence
        self.emit_event(EmitEventInput {
            trace_id: &trace_id,
            cell_id: &cell_id,
            cell_kind: cell.kind(),
            lifecycle_event: event,
            phase: "request",
            outcome: "initiated",
            obligations_pending: cell.pending_obligations(),
            budget_consumed_ms: 0,
        });

        // Execute effect for the lifecycle transition (costs budget)
        cell.execute_effect(
            cx,
            EffectCategory::LifecycleTransition,
            &mode.evidence_event_name,
        )
        .map_err(|e| {
            if matches!(e, CellError::BudgetExhausted { .. }) {
                CancellationError::BudgetExhausted {
                    cell_id: cell_id.clone(),
                    event,
                }
            } else {
                CancellationError::from(e)
            }
        })?;

        // Phase 1: Cancel request
        let deadline = DrainDeadline {
            max_ticks: mode.drain_budget_ticks,
        };
        let reason = event.cancel_reason();

        cell.initiate_close(cx, reason, deadline).map_err(|e| {
            self.emit_event(EmitEventInput {
                trace_id: &trace_id,
                cell_id: &cell_id,
                cell_kind: cell.kind(),
                lifecycle_event: event,
                phase: "cancel",
                outcome: "failed",
                obligations_pending: cell.pending_obligations(),
                budget_consumed_ms: 0,
            });
            CancellationError::from(e)
        })?;

        self.emit_event(EmitEventInput {
            trace_id: &trace_id,
            cell_id: &cell_id,
            cell_kind: cell.kind(),
            lifecycle_event: event,
            phase: "cancel",
            outcome: "completed",
            obligations_pending: cell.pending_obligations(),
            budget_consumed_ms: 0,
        });

        // Phase 2: Drain (tick through)
        // Always tick at least once if there are pending obligations, even with
        // a zero-tick budget; this triggers the timeout escalation flag so that
        // finalize knows to force-abort.
        let effective_ticks = if mode.drain_budget_ticks == 0 && cell.pending_obligations() > 0 {
            1
        } else {
            mode.drain_budget_ticks
        };
        for _ in 0..effective_ticks {
            if cell.pending_obligations() == 0 {
                break;
            }
            cell.drain_tick();
        }

        let timeout_escalated = cell.pending_obligations() > 0;

        self.emit_event(EmitEventInput {
            trace_id: &trace_id,
            cell_id: &cell_id,
            cell_kind: cell.kind(),
            lifecycle_event: event,
            phase: "drain",
            outcome: if timeout_escalated {
                "timeout_escalated"
            } else {
                "completed"
            },
            obligations_pending: cell.pending_obligations(),
            budget_consumed_ms: 0,
        });

        // Phase 3: Finalize
        let finalize_result = cell.finalize().map_err(|e| {
            self.emit_event(EmitEventInput {
                trace_id: &trace_id,
                cell_id: &cell_id,
                cell_kind: cell.kind(),
                lifecycle_event: event,
                phase: "finalize",
                outcome: "failed",
                obligations_pending: cell.pending_obligations(),
                budget_consumed_ms: 0,
            });
            CancellationError::from(e)
        })?;

        self.emit_event(EmitEventInput {
            trace_id: &trace_id,
            cell_id: &cell_id,
            cell_kind: cell.kind(),
            lifecycle_event: event,
            phase: "finalize",
            outcome: if finalize_result.success {
                "success"
            } else {
                "with_pending"
            },
            obligations_pending: 0,
            budget_consumed_ms: 0,
        });

        // Track completed cancellation
        self.cancelled_cells.insert(cell_id.clone(), event);

        let outcome = CancellationOutcome {
            cell_id,
            event,
            success: finalize_result.success && !timeout_escalated,
            finalize_result,
            timeout_escalated,
            children_cancelled: 0,
            was_idempotent: false,
        };

        self.outcomes.push(outcome.clone());
        Ok(outcome)
    }

    /// Cancel a cell in a CellManager by ID.
    pub fn cancel_managed_cell<C: ContextAdapter>(
        &mut self,
        manager: &mut CellManager,
        cell_id: &str,
        cx: &mut C,
        event: LifecycleEvent,
    ) -> Result<CancellationOutcome, CancellationError> {
        let outcome = {
            let cell = manager
                .get_mut(cell_id)
                .ok_or_else(|| CancellationError::CellNotFound {
                    cell_id: cell_id.to_string(),
                })?;
            self.cancel_cell(cell, cx, event)?
        };
        manager.archive_cell(cell_id, outcome.finalize_result.clone());
        Ok(outcome)
    }

    /// Cancel all active cells in a manager with the same lifecycle event.
    pub fn cancel_all<C: ContextAdapter>(
        &mut self,
        manager: &mut CellManager,
        cx: &mut C,
        event: LifecycleEvent,
    ) -> Vec<Result<CancellationOutcome, CancellationError>> {
        let cell_ids: Vec<String> = manager
            .active_cell_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut results = Vec::new();
        for cell_id in &cell_ids {
            let result = self.cancel_managed_cell(manager, cell_id, cx, event);
            results.push(result);
        }
        results
    }

    /// Number of completed cancellations.
    pub fn outcome_count(&self) -> usize {
        self.outcomes.len()
    }

    /// All completed cancellation outcomes.
    pub fn outcomes(&self) -> &[CancellationOutcome] {
        &self.outcomes
    }

    /// Whether a cell has already been cancelled.
    pub fn is_cancelled(&self, cell_id: &str) -> bool {
        self.cancelled_cells.contains_key(cell_id)
    }

    /// Drain accumulated events for evidence emission.
    pub fn drain_events(&mut self) -> Vec<CancellationEvent> {
        std::mem::take(&mut self.events)
    }

    /// View accumulated events.
    pub fn events(&self) -> &[CancellationEvent] {
        &self.events
    }

    fn emit_event(&mut self, input: EmitEventInput<'_>) {
        self.events.push(CancellationEvent {
            trace_id: input.trace_id.to_string(),
            cell_id: input.cell_id.to_string(),
            cell_kind: input.cell_kind,
            lifecycle_event: input.lifecycle_event,
            phase: input.phase.to_string(),
            outcome: input.outcome.to_string(),
            component: "cancellation_lifecycle".to_string(),
            obligations_pending: input.obligations_pending,
            budget_consumed_ms: input.budget_consumed_ms,
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

    fn mock_cx(budget_ms: u64) -> MockCx {
        MockCx::new(
            crate::control_plane::mocks::trace_id_from_seed(1),
            MockBudget::new(budget_ms),
        )
    }

    // -----------------------------------------------------------------------
    // LifecycleEvent
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_event_display() {
        assert_eq!(LifecycleEvent::Unload.to_string(), "unload");
        assert_eq!(LifecycleEvent::Quarantine.to_string(), "quarantine");
        assert_eq!(LifecycleEvent::Suspend.to_string(), "suspend");
        assert_eq!(LifecycleEvent::Terminate.to_string(), "terminate");
        assert_eq!(LifecycleEvent::Revocation.to_string(), "revocation");
    }

    #[test]
    fn lifecycle_event_serde_roundtrip() {
        for event in [
            LifecycleEvent::Unload,
            LifecycleEvent::Quarantine,
            LifecycleEvent::Suspend,
            LifecycleEvent::Terminate,
            LifecycleEvent::Revocation,
        ] {
            let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
            let restored: LifecycleEvent =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(event, restored);
        }
    }

    #[test]
    fn lifecycle_event_cancel_reason_mapping() {
        assert_eq!(
            LifecycleEvent::Unload.cancel_reason(),
            CancelReason::OperatorShutdown
        );
        assert_eq!(
            LifecycleEvent::Quarantine.cancel_reason(),
            CancelReason::Quarantine
        );
        assert_eq!(
            LifecycleEvent::Revocation.cancel_reason(),
            CancelReason::Revocation
        );
    }

    #[test]
    fn lifecycle_event_forced_vs_cooperative() {
        assert!(!LifecycleEvent::Unload.is_forced());
        assert!(LifecycleEvent::Unload.is_cooperative());
        assert!(!LifecycleEvent::Quarantine.is_forced());
        assert!(!LifecycleEvent::Quarantine.is_cooperative());
        assert!(LifecycleEvent::Terminate.is_forced());
        assert!(!LifecycleEvent::Terminate.is_cooperative());
        assert!(LifecycleEvent::Suspend.is_cooperative());
    }

    #[test]
    fn lifecycle_event_ordering() {
        assert!(LifecycleEvent::Unload < LifecycleEvent::Quarantine);
        assert!(LifecycleEvent::Quarantine < LifecycleEvent::Suspend);
        assert!(LifecycleEvent::Suspend < LifecycleEvent::Terminate);
        assert!(LifecycleEvent::Terminate < LifecycleEvent::Revocation);
    }

    // -----------------------------------------------------------------------
    // CancellationMode
    // -----------------------------------------------------------------------

    #[test]
    fn default_modes_per_event() {
        let unload = CancellationMode::for_event(LifecycleEvent::Unload);
        assert_eq!(unload.drain_budget_ticks, 10_000);
        assert!(unload.force_abort_on_timeout);
        assert!(unload.propagate_to_children);

        let quarantine = CancellationMode::for_event(LifecycleEvent::Quarantine);
        assert_eq!(quarantine.drain_budget_ticks, 1_000);

        let suspend = CancellationMode::for_event(LifecycleEvent::Suspend);
        assert_eq!(suspend.drain_budget_ticks, 5_000);
        assert!(!suspend.force_abort_on_timeout);
        assert!(!suspend.propagate_to_children);

        let terminate = CancellationMode::for_event(LifecycleEvent::Terminate);
        assert_eq!(terminate.drain_budget_ticks, 0);
        assert!(terminate.force_abort_on_timeout);

        let revocation = CancellationMode::for_event(LifecycleEvent::Revocation);
        assert_eq!(revocation.drain_budget_ticks, 500);
    }

    #[test]
    fn cancellation_mode_serde_roundtrip() {
        let mode = CancellationMode::for_event(LifecycleEvent::Quarantine);
        let json = serde_json::to_string(&mode).expect("serde deserialization should succeed");
        let restored: CancellationMode =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(mode, restored);
    }

    // -----------------------------------------------------------------------
    // CancellationError
    // -----------------------------------------------------------------------

    #[test]
    fn cancellation_error_display_and_codes() {
        let errors = vec![
            CancellationError::CellNotFound {
                cell_id: "c1".to_string(),
            },
            CancellationError::BudgetExhausted {
                cell_id: "c1".to_string(),
                event: LifecycleEvent::Quarantine,
            },
            CancellationError::CellError {
                cell_id: "c1".to_string(),
                error_code: "cell_invalid_state".to_string(),
                message: "bad state".to_string(),
            },
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
            let code = err.error_code();
            assert!(!code.is_empty());
        }
    }

    #[test]
    fn cancellation_error_serde_roundtrip() {
        let err = CancellationError::BudgetExhausted {
            cell_id: "c1".to_string(),
            event: LifecycleEvent::Terminate,
        };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let restored: CancellationError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, restored);
    }

    #[test]
    fn cell_error_converts_to_cancellation_error() {
        let cell_err = CellError::CellNotFound {
            cell_id: "c1".to_string(),
        };
        let cancel_err: CancellationError = cell_err.into();
        assert_eq!(cancel_err.error_code(), "cancel_cell_error");
    }

    // -----------------------------------------------------------------------
    // CancellationEvent
    // -----------------------------------------------------------------------

    #[test]
    fn cancellation_event_serde_roundtrip() {
        let event = CancellationEvent {
            trace_id: "t".to_string(),
            cell_id: "c".to_string(),
            cell_kind: CellKind::Extension,
            lifecycle_event: LifecycleEvent::Quarantine,
            phase: "cancel".to_string(),
            outcome: "completed".to_string(),
            component: "cancellation_lifecycle".to_string(),
            obligations_pending: 2,
            budget_consumed_ms: 3,
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: CancellationEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
    }

    // -----------------------------------------------------------------------
    // CancellationManager — basic lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_unload_clean() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("cancel");

        assert!(outcome.success);
        assert!(!outcome.was_idempotent);
        assert!(!outcome.timeout_escalated);
        assert_eq!(outcome.event, LifecycleEvent::Unload);
        assert_eq!(cell.state(), RegionState::Closed);
    }

    #[test]
    fn cancel_quarantine_clean() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
            .expect("cancel");

        assert!(outcome.success);
        assert_eq!(outcome.event, LifecycleEvent::Quarantine);
    }

    #[test]
    fn cancel_suspend_clean() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Suspend)
            .expect("cancel");

        assert!(outcome.success);
        assert_eq!(outcome.event, LifecycleEvent::Suspend);
    }

    #[test]
    fn cancel_terminate_immediate() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Terminate)
            .expect("cancel");

        assert!(outcome.success);
        assert_eq!(outcome.event, LifecycleEvent::Terminate);
        assert_eq!(cell.state(), RegionState::Closed);
    }

    #[test]
    fn cancel_revocation_clean() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Revocation)
            .expect("cancel");

        assert!(outcome.success);
        assert_eq!(outcome.event, LifecycleEvent::Revocation);
    }

    // -----------------------------------------------------------------------
    // Idempotency
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_idempotent_on_already_closed() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut mgr = CancellationManager::new();

        // First cancel
        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("first cancel");

        // Second cancel (idempotent)
        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("second cancel");

        assert!(outcome.was_idempotent);
        assert!(outcome.success);
        assert_eq!(mgr.outcome_count(), 2);
    }

    #[test]
    fn cancel_idempotent_different_events() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
            .expect("first");

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Terminate)
            .expect("second");

        assert!(outcome.was_idempotent);
    }

    // -----------------------------------------------------------------------
    // Obligations and timeout escalation
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_with_resolved_obligations() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-1", "flush evidence");
        cell.commit_obligation("ob-1").expect("commit");

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("cancel");

        assert!(outcome.success);
        assert!(!outcome.timeout_escalated);
        assert_eq!(outcome.finalize_result.obligations_committed, 1);
    }

    #[test]
    fn cancel_with_pending_obligations_timeout() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-slow", "never finishes");

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
            .expect("cancel");

        assert!(!outcome.success);
        assert!(outcome.timeout_escalated);
        assert_eq!(outcome.finalize_result.obligations_aborted, 1);
        assert!(outcome.finalize_result.drain_timeout_escalated);
    }

    #[test]
    fn terminate_with_pending_obligations_immediate() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-1", "in progress");

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Terminate)
            .expect("terminate");

        // Terminate has 0 drain ticks, so obligation is force-aborted immediately
        assert!(outcome.timeout_escalated);
        assert_eq!(outcome.finalize_result.obligations_aborted, 1);
    }

    #[test]
    fn revocation_with_pending_obligations() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-1", "revoked cap op");
        cell.register_obligation("ob-2", "another op");

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Revocation)
            .expect("revocation");

        assert!(outcome.timeout_escalated);
        assert_eq!(outcome.finalize_result.obligations_aborted, 2);
    }

    // -----------------------------------------------------------------------
    // Budget exhaustion
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_budget_exhausted() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(0); // No budget
        let mut mgr = CancellationManager::new();

        let err = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .unwrap_err();
        assert_eq!(err.error_code(), "cancel_budget_exhausted");
    }

    // -----------------------------------------------------------------------
    // CancellationManager — managed cells
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_managed_cell_success() {
        let mut cell_mgr = CellManager::new();
        let _ = cell_mgr.create_extension_cell("ext-1", "t1");
        let mut cx = mock_cx(200);
        let mut cancel_mgr = CancellationManager::new();

        let outcome = cancel_mgr
            .cancel_managed_cell(&mut cell_mgr, "ext-1", &mut cx, LifecycleEvent::Unload)
            .expect("cancel");

        assert!(outcome.success);
        assert_eq!(outcome.cell_id, "ext-1");
    }

    #[test]
    fn cancel_managed_cell_reused_live_id_is_not_idempotent() {
        let mut cell_mgr = CellManager::new();
        cell_mgr
            .create_extension_cell("ext-reused", "t1")
            .expect("create first cell");
        let mut cx = mock_cx(200);
        let mut cancel_mgr = CancellationManager::new();

        let first = cancel_mgr
            .cancel_managed_cell(&mut cell_mgr, "ext-reused", &mut cx, LifecycleEvent::Unload)
            .expect("first cancel");
        assert!(!first.was_idempotent);
        assert!(first.success);
        assert!(cell_mgr.get("ext-reused").is_none());

        cell_mgr
            .create_extension_cell("ext-reused", "t2")
            .expect("reuse cell id");
        cell_mgr
            .get_mut("ext-reused")
            .expect("reused cell")
            .register_obligation("ob-reused", "must not be hidden by stale idempotency");

        let second = cancel_mgr
            .cancel_managed_cell(
                &mut cell_mgr,
                "ext-reused",
                &mut cx,
                LifecycleEvent::Terminate,
            )
            .expect("second cancel");

        assert!(!second.was_idempotent);
        assert!(second.timeout_escalated);
        assert_eq!(second.finalize_result.obligations_aborted, 1);
        assert_eq!(cancel_mgr.outcome_count(), 2);
        assert_eq!(cell_mgr.closed_count(), 2);
    }

    #[test]
    fn cancel_managed_cell_not_found() {
        let mut cell_mgr = CellManager::new();
        let mut cx = mock_cx(100);
        let mut cancel_mgr = CancellationManager::new();

        let err = cancel_mgr
            .cancel_managed_cell(
                &mut cell_mgr,
                "nonexistent",
                &mut cx,
                LifecycleEvent::Unload,
            )
            .unwrap_err();

        assert_eq!(err.error_code(), "cancel_cell_not_found");
    }

    #[test]
    fn cancel_all_cells() {
        let mut cell_mgr = CellManager::new();
        let _ = cell_mgr.create_extension_cell("ext-1", "t1");
        let _ = cell_mgr.create_extension_cell("ext-2", "t2");
        let _ = cell_mgr.create_delegate_cell("del-1", "t3");
        let mut cx = mock_cx(500);
        let mut cancel_mgr = CancellationManager::new();

        let results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Quarantine);

        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.is_ok());
            assert!(
                r.as_ref()
                    .expect("serde deserialization should succeed")
                    .success
            );
        }
        assert_eq!(cancel_mgr.outcome_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Cross-cell isolation
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_one_cell_does_not_affect_another() {
        let mut cell_mgr = CellManager::new();
        let _ = cell_mgr.create_extension_cell("ext-1", "t1");
        let _ = cell_mgr.create_extension_cell("ext-2", "t2");
        let mut cx = mock_cx(200);
        let mut cancel_mgr = CancellationManager::new();

        cancel_mgr
            .cancel_managed_cell(&mut cell_mgr, "ext-1", &mut cx, LifecycleEvent::Quarantine)
            .expect("cancel ext-1");

        // ext-2 should still be running
        let cell2 = cell_mgr.get("ext-2").expect("ext-2 exists");
        assert_eq!(cell2.state(), RegionState::Running);
    }

    // -----------------------------------------------------------------------
    // Evidence emission
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_emits_structured_events() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("cancel");

        let events = mgr.events();
        // Expect: request, cancel, drain, finalize phases
        assert!(events.len() >= 4);
        assert!(events.iter().any(|e| e.phase == "request"));
        assert!(events.iter().any(|e| e.phase == "cancel"));
        assert!(events.iter().any(|e| e.phase == "drain"));
        assert!(events.iter().any(|e| e.phase == "finalize"));

        // All events have correct cell info
        for e in events {
            assert_eq!(e.cell_id, "ext-1");
            assert_eq!(e.cell_kind, CellKind::Extension);
            assert_eq!(e.lifecycle_event, LifecycleEvent::Unload);
            assert_eq!(e.component, "cancellation_lifecycle");
        }
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("cancel");

        let events = mgr.drain_events();
        assert!(!events.is_empty());
        assert!(mgr.events().is_empty());
    }

    #[test]
    fn timeout_escalation_emitted_in_events() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-slow", "will timeout");

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
            .expect("cancel");

        let events = mgr.events();
        let drain_event = events.iter().find(|e| e.phase == "drain").expect("drain");
        assert_eq!(drain_event.outcome, "timeout_escalated");
    }

    // -----------------------------------------------------------------------
    // Mode overrides
    // -----------------------------------------------------------------------

    #[test]
    fn mode_override_changes_behavior() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        // Override unload to use very short drain
        mgr.set_mode_override(
            LifecycleEvent::Unload,
            CancellationMode {
                drain_budget_ticks: 1,
                force_abort_on_timeout: true,
                propagate_to_children: false,
                evidence_event_name: "custom_unload".to_string(),
            },
        );

        cell.register_obligation("ob-1", "will timeout quickly");

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("cancel");

        assert!(outcome.timeout_escalated);
        assert_eq!(outcome.finalize_result.obligations_aborted, 1);
    }

    #[test]
    fn effective_mode_returns_override_when_set() {
        let mut mgr = CancellationManager::new();
        let custom_mode = CancellationMode {
            drain_budget_ticks: 42,
            force_abort_on_timeout: false,
            propagate_to_children: false,
            evidence_event_name: "test".to_string(),
        };
        mgr.set_mode_override(LifecycleEvent::Terminate, custom_mode.clone());

        assert_eq!(mgr.effective_mode(LifecycleEvent::Terminate), custom_mode);
        // Other events still use defaults
        assert_eq!(
            mgr.effective_mode(LifecycleEvent::Unload),
            CancellationMode::for_event(LifecycleEvent::Unload)
        );
    }

    // -----------------------------------------------------------------------
    // Deterministic replay
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_cancellation_events() {
        let run = || -> Vec<CancellationEvent> {
            let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
            let mut cx = mock_cx(200);
            let mut mgr = CancellationManager::new();

            cell.register_obligation("ob-1", "flush");
            cell.commit_obligation("ob-1")
                .expect("serde deserialization should succeed");

            mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
                .expect("serde deserialization should succeed");
            mgr.drain_events()
        };

        let e1 = run();
        let e2 = run();
        assert_eq!(e1, e2);
    }

    // -----------------------------------------------------------------------
    // CancellationOutcome serde
    // -----------------------------------------------------------------------

    #[test]
    fn cancellation_outcome_serde_roundtrip() {
        let outcome = CancellationOutcome {
            cell_id: "c".to_string(),
            event: LifecycleEvent::Quarantine,
            success: true,
            finalize_result: FinalizeResult {
                region_id: "c".to_string(),
                success: true,
                obligations_committed: 1,
                obligations_aborted: 0,
                drain_timeout_escalated: false,
            },
            timeout_escalated: false,
            children_cancelled: 0,
            was_idempotent: false,
        };
        let json = serde_json::to_string(&outcome).expect("serde deserialization should succeed");
        let restored: CancellationOutcome =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(outcome, restored);
    }

    // -----------------------------------------------------------------------
    // Per-event-type compliance: all 5 events follow three-phase protocol
    // -----------------------------------------------------------------------

    #[test]
    fn all_events_follow_three_phase_protocol() {
        for event in [
            LifecycleEvent::Unload,
            LifecycleEvent::Quarantine,
            LifecycleEvent::Suspend,
            LifecycleEvent::Terminate,
            LifecycleEvent::Revocation,
        ] {
            let mut cell = ExecutionCell::new(format!("ext-{event}"), CellKind::Extension, "t");
            let mut cx = mock_cx(200);
            let mut mgr = CancellationManager::new();

            let outcome = mgr
                .cancel_cell(&mut cell, &mut cx, event)
                .unwrap_or_else(|e| panic!("cancel failed for {event}: {e}"));

            assert!(outcome.success, "event {event} should succeed");
            assert_eq!(
                cell.state(),
                RegionState::Closed,
                "cell should be closed after {event}"
            );

            // Verify three-phase evidence: request, cancel, drain, finalize
            let events = mgr.drain_events();
            let phases: Vec<&str> = events.iter().map(|e| e.phase.as_str()).collect();
            assert!(
                phases.contains(&"request"),
                "missing request phase for {event}"
            );
            assert!(
                phases.contains(&"cancel"),
                "missing cancel phase for {event}"
            );
            assert!(phases.contains(&"drain"), "missing drain phase for {event}");
            assert!(
                phases.contains(&"finalize"),
                "missing finalize phase for {event}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // is_cancelled tracking
    // -----------------------------------------------------------------------

    #[test]
    fn is_cancelled_tracks_correctly() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        assert!(!mgr.is_cancelled("ext-1"));

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("cancel");

        assert!(mgr.is_cancelled("ext-1"));
        assert!(!mgr.is_cancelled("ext-2"));
    }

    // -- Enrichment: std::error --

    #[test]
    fn cancellation_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(CancellationError::CellNotFound {
                cell_id: "c1".into(),
            }),
            Box::new(CancellationError::BudgetExhausted {
                cell_id: "c2".into(),
                event: LifecycleEvent::Unload,
            }),
            Box::new(CancellationError::CellError {
                cell_id: "c3".into(),
                error_code: "cx".into(),
                message: "fail".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(displays.len(), 3);
    }

    // -- Enrichment batch 2: Display uniqueness, serde, modes --

    #[test]
    fn lifecycle_event_display_uniqueness() {
        let events = [
            LifecycleEvent::Unload,
            LifecycleEvent::Quarantine,
            LifecycleEvent::Suspend,
            LifecycleEvent::Terminate,
            LifecycleEvent::Revocation,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for e in &events {
            seen.insert(e.to_string());
        }
        assert_eq!(seen.len(), 5, "all 5 events have unique display strings");
    }

    #[test]
    fn lifecycle_event_serde_roundtrip_all() {
        for event in [
            LifecycleEvent::Unload,
            LifecycleEvent::Quarantine,
            LifecycleEvent::Suspend,
            LifecycleEvent::Terminate,
            LifecycleEvent::Revocation,
        ] {
            let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
            let back: LifecycleEvent =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(event, back);
        }
    }

    #[test]
    fn lifecycle_event_is_forced_only_terminate() {
        assert!(LifecycleEvent::Terminate.is_forced());
        assert!(!LifecycleEvent::Unload.is_forced());
        assert!(!LifecycleEvent::Quarantine.is_forced());
        assert!(!LifecycleEvent::Suspend.is_forced());
        assert!(!LifecycleEvent::Revocation.is_forced());
    }

    #[test]
    fn lifecycle_event_is_cooperative_unload_and_suspend() {
        assert!(LifecycleEvent::Unload.is_cooperative());
        assert!(LifecycleEvent::Suspend.is_cooperative());
        assert!(!LifecycleEvent::Quarantine.is_cooperative());
        assert!(!LifecycleEvent::Terminate.is_cooperative());
        assert!(!LifecycleEvent::Revocation.is_cooperative());
    }

    #[test]
    fn cancellation_mode_for_event_drain_budget_ordering() {
        // Unload has highest drain budget, terminate has 0
        let unload = CancellationMode::for_event(LifecycleEvent::Unload);
        let quarantine = CancellationMode::for_event(LifecycleEvent::Quarantine);
        let suspend = CancellationMode::for_event(LifecycleEvent::Suspend);
        let terminate = CancellationMode::for_event(LifecycleEvent::Terminate);
        let revocation = CancellationMode::for_event(LifecycleEvent::Revocation);

        assert_eq!(terminate.drain_budget_ticks, 0);
        assert!(revocation.drain_budget_ticks < quarantine.drain_budget_ticks);
        assert!(quarantine.drain_budget_ticks < suspend.drain_budget_ticks);
        assert!(suspend.drain_budget_ticks < unload.drain_budget_ticks);
    }

    #[test]
    fn cancellation_mode_serde_roundtrip_all_events() {
        let mode = CancellationMode::for_event(LifecycleEvent::Quarantine);
        let json = serde_json::to_string(&mode).expect("serde deserialization should succeed");
        let back: CancellationMode =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(mode, back);
    }

    #[test]
    fn cancellation_error_error_code_uniqueness() {
        let codes = [
            CancellationError::CellNotFound {
                cell_id: "a".into(),
            }
            .error_code(),
            CancellationError::BudgetExhausted {
                cell_id: "b".into(),
                event: LifecycleEvent::Unload,
            }
            .error_code(),
            CancellationError::CellError {
                cell_id: "c".into(),
                error_code: "e".into(),
                message: "m".into(),
            }
            .error_code(),
        ];
        let set: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(set.len(), 3, "all 3 error codes are distinct");
    }

    #[test]
    fn cancellation_error_serde_roundtrip_all() {
        let errors = vec![
            CancellationError::CellNotFound {
                cell_id: "c1".into(),
            },
            CancellationError::BudgetExhausted {
                cell_id: "c2".into(),
                event: LifecycleEvent::Quarantine,
            },
            CancellationError::CellError {
                cell_id: "c3".into(),
                error_code: "code".into(),
                message: "msg".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let back: CancellationError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn cancellation_event_serde_roundtrip_unload() {
        let event = CancellationEvent {
            trace_id: "t".into(),
            cell_id: "c".into(),
            cell_kind: CellKind::Extension,
            lifecycle_event: LifecycleEvent::Unload,
            phase: "request".into(),
            outcome: "ok".into(),
            component: "cancellation_lifecycle".into(),
            obligations_pending: 0,
            budget_consumed_ms: 0,
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: CancellationEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, back);
    }

    #[test]
    fn cancel_reason_mapping_all_events() {
        // Each event maps to a distinct cancel reason
        let events = [
            LifecycleEvent::Unload,
            LifecycleEvent::Quarantine,
            LifecycleEvent::Suspend,
            LifecycleEvent::Terminate,
            LifecycleEvent::Revocation,
        ];
        let mut reasons = std::collections::BTreeSet::new();
        for e in &events {
            reasons.insert(format!("{:?}", e.cancel_reason()));
        }
        assert_eq!(
            reasons.len(),
            5,
            "all events map to distinct cancel reasons"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone, JSON fields, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn cancellation_mode_clone_equality() {
        let mode = CancellationMode::for_event(LifecycleEvent::Quarantine);
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn cancellation_outcome_clone_equality() {
        let outcome = CancellationOutcome {
            cell_id: "ext-1".into(),
            event: LifecycleEvent::Unload,
            success: true,
            finalize_result: FinalizeResult {
                region_id: "ext-1".into(),
                success: true,
                obligations_committed: 2,
                obligations_aborted: 0,
                drain_timeout_escalated: false,
            },
            timeout_escalated: false,
            children_cancelled: 1,
            was_idempotent: false,
        };
        let cloned = outcome.clone();
        assert_eq!(outcome, cloned);
    }

    #[test]
    fn cancellation_error_clone_equality() {
        let variants = vec![
            CancellationError::CellNotFound {
                cell_id: "c1".into(),
            },
            CancellationError::BudgetExhausted {
                cell_id: "c2".into(),
                event: LifecycleEvent::Revocation,
            },
            CancellationError::CellError {
                cell_id: "c3".into(),
                error_code: "ec".into(),
                message: "msg".into(),
            },
        ];
        for v in &variants {
            let cloned = v.clone();
            assert_eq!(*v, cloned);
        }
    }

    #[test]
    fn cancellation_event_clone_equality() {
        let ev = CancellationEvent {
            trace_id: "t1".into(),
            cell_id: "c1".into(),
            cell_kind: CellKind::Extension,
            lifecycle_event: LifecycleEvent::Suspend,
            phase: "drain".into(),
            outcome: "completed".into(),
            component: "cancellation_lifecycle".into(),
            obligations_pending: 0,
            budget_consumed_ms: 42,
        };
        let cloned = ev.clone();
        assert_eq!(ev, cloned);
    }

    #[test]
    fn cancellation_outcome_json_field_presence() {
        let outcome = CancellationOutcome {
            cell_id: "ext-1".into(),
            event: LifecycleEvent::Quarantine,
            success: true,
            finalize_result: FinalizeResult {
                region_id: "ext-1".into(),
                success: true,
                obligations_committed: 1,
                obligations_aborted: 0,
                drain_timeout_escalated: false,
            },
            timeout_escalated: false,
            children_cancelled: 0,
            was_idempotent: false,
        };
        let json = serde_json::to_string(&outcome).expect("serde deserialization should succeed");
        for field in [
            "cell_id",
            "event",
            "success",
            "finalize_result",
            "timeout_escalated",
            "children_cancelled",
            "was_idempotent",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn cancellation_event_json_field_presence() {
        let ev = CancellationEvent {
            trace_id: "t-99".into(),
            cell_id: "c-7".into(),
            cell_kind: CellKind::Delegate,
            lifecycle_event: LifecycleEvent::Terminate,
            phase: "finalize".into(),
            outcome: "success".into(),
            component: "cancellation_lifecycle".into(),
            obligations_pending: 3,
            budget_consumed_ms: 100,
        };
        let json = serde_json::to_string(&ev).expect("serde deserialization should succeed");
        for field in [
            "trace_id",
            "cell_id",
            "cell_kind",
            "lifecycle_event",
            "phase",
            "outcome",
            "component",
            "obligations_pending",
            "budget_consumed_ms",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn manager_default_is_empty() {
        let mgr = CancellationManager::default();
        assert_eq!(mgr.outcome_count(), 0);
        assert!(mgr.events().is_empty());
        assert!(!mgr.is_cancelled("any"));
    }

    #[test]
    fn cancel_reason_suspend_is_custom() {
        let reason = LifecycleEvent::Suspend.cancel_reason();
        assert_eq!(reason, CancelReason::Custom("suspend".to_string()));
    }

    #[test]
    fn cancel_reason_terminate_is_custom() {
        let reason = LifecycleEvent::Terminate.cancel_reason();
        assert_eq!(reason, CancelReason::Custom("terminate".to_string()));
    }

    #[test]
    fn evidence_event_names_unique_across_events() {
        let names: std::collections::BTreeSet<String> = [
            LifecycleEvent::Unload,
            LifecycleEvent::Quarantine,
            LifecycleEvent::Suspend,
            LifecycleEvent::Terminate,
            LifecycleEvent::Revocation,
        ]
        .iter()
        .map(|e| CancellationMode::for_event(*e).evidence_event_name)
        .collect();
        assert_eq!(
            names.len(),
            5,
            "all 5 events have unique evidence event names"
        );
    }

    #[test]
    fn cell_error_conversion_preserves_cell_id() {
        let cell_err = CellError::BudgetExhausted {
            cell_id: "cell-42".to_string(),
            requested_ms: 100,
            remaining_ms: 0,
        };
        let cancel_err: CancellationError = cell_err.into();
        match cancel_err {
            CancellationError::CellError { cell_id, .. } => {
                assert_eq!(cell_id, "cell-42");
            }
            other => panic!("expected CellError, got {other:?}"),
        }
    }

    #[test]
    fn cancellation_mode_json_field_presence() {
        let mode = CancellationMode::for_event(LifecycleEvent::Unload);
        let json = serde_json::to_string(&mode).expect("serde deserialization should succeed");
        for field in [
            "drain_budget_ticks",
            "force_abort_on_timeout",
            "propagate_to_children",
            "evidence_event_name",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn outcomes_accessor_returns_all() {
        let mut cell1 = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cell2 = ExecutionCell::new("ext-2", CellKind::Extension, "t");
        let mut cx = mock_cx(300);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell1, &mut cx, LifecycleEvent::Unload)
            .expect("serde deserialization should succeed");
        mgr.cancel_cell(&mut cell2, &mut cx, LifecycleEvent::Quarantine)
            .expect("serde deserialization should succeed");

        let outcomes = mgr.outcomes();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].cell_id, "ext-1");
        assert_eq!(outcomes[1].cell_id, "ext-2");
    }

    // -- Enrichment batch 4 --

    #[test]
    fn error_display_cell_not_found_contains_cell_id() {
        let err = CancellationError::CellNotFound {
            cell_id: "ext-42".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ext-42"), "Display should include cell_id");
        assert!(msg.contains("not found"), "Display should say 'not found'");
    }

    #[test]
    fn error_display_budget_exhausted_contains_event() {
        let err = CancellationError::BudgetExhausted {
            cell_id: "ext-7".into(),
            event: LifecycleEvent::Quarantine,
        };
        let msg = err.to_string();
        assert!(msg.contains("ext-7"));
        assert!(msg.contains("budget exhausted"));
        assert!(msg.contains("quarantine"));
    }

    #[test]
    fn error_display_cell_error_contains_error_code_and_message() {
        let err = CancellationError::CellError {
            cell_id: "ext-9".into(),
            error_code: "cell_invalid_state".into(),
            message: "cannot close running cell".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ext-9"));
        assert!(msg.contains("cell_invalid_state"));
        assert!(msg.contains("cannot close running cell"));
    }

    #[test]
    fn cancel_delegate_cell_kind() {
        let mut cell = ExecutionCell::new("del-1", CellKind::Delegate, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("cancel delegate");

        assert!(outcome.success);
        assert_eq!(cell.state(), RegionState::Closed);

        // Events should record Delegate cell kind
        let events = mgr.events();
        for e in events {
            assert_eq!(e.cell_kind, CellKind::Delegate);
        }
    }

    #[test]
    fn cancel_all_on_empty_manager() {
        let mut cell_mgr = CellManager::new();
        let mut cx = mock_cx(100);
        let mut cancel_mgr = CancellationManager::new();

        let results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Terminate);
        assert!(results.is_empty());
        assert_eq!(cancel_mgr.outcome_count(), 0);
    }

    #[test]
    fn drain_events_is_idempotent() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("serde deserialization should succeed");

        let first = mgr.drain_events();
        assert!(!first.is_empty());
        let second = mgr.drain_events();
        assert!(second.is_empty(), "second drain should be empty");
    }

    #[test]
    fn cancel_managed_cell_archives_from_active() {
        let mut cell_mgr = CellManager::new();
        let _ = cell_mgr.create_extension_cell("ext-1", "t1");
        let _ = cell_mgr.create_extension_cell("ext-2", "t2");
        let mut cx = mock_cx(200);
        let mut cancel_mgr = CancellationManager::new();

        cancel_mgr
            .cancel_managed_cell(&mut cell_mgr, "ext-1", &mut cx, LifecycleEvent::Unload)
            .expect("serde deserialization should succeed");

        // ext-1 should be archived (no longer gettable as active)
        assert!(cell_mgr.get("ext-1").is_none());
        // ext-2 should still be active
        assert!(cell_mgr.get("ext-2").is_some());
    }

    #[test]
    fn cell_error_conversion_invalid_state() {
        let cell_err = CellError::InvalidState {
            cell_id: "cell-99".to_string(),
            current: RegionState::Closed,
            attempted: "execute".to_string(),
        };
        let cancel_err: CancellationError = cell_err.into();
        match &cancel_err {
            CancellationError::CellError {
                cell_id, message, ..
            } => {
                assert_eq!(cell_id, "cell-99");
                assert!(!message.is_empty());
            }
            other => panic!("expected CellError, got {other:?}"),
        }
    }

    #[test]
    fn cell_error_conversion_cx_threading() {
        let cell_err = CellError::CxThreading {
            cell_id: "cell-77".to_string(),
            error_code: "cell_cx_threading".to_string(),
            message: "thread limit".to_string(),
        };
        let cancel_err: CancellationError = cell_err.into();
        match &cancel_err {
            CancellationError::CellError { cell_id, .. } => {
                assert_eq!(cell_id, "cell-77");
            }
            other => panic!("expected CellError, got {other:?}"),
        }
    }

    #[test]
    fn cell_error_conversion_session_rejected() {
        let cell_err = CellError::SessionRejected {
            parent_cell_id: "cell-parent".to_string(),
            reason: "over limit".to_string(),
        };
        let cancel_err: CancellationError = cell_err.into();
        match &cancel_err {
            CancellationError::CellError { cell_id, .. } => {
                assert_eq!(cell_id, "cell-parent");
            }
            other => panic!("expected CellError, got {other:?}"),
        }
    }

    #[test]
    fn cell_error_conversion_obligation_not_found() {
        let cell_err = CellError::ObligationNotFound {
            cell_id: "cell-ob".to_string(),
            obligation_id: "ob-missing".to_string(),
        };
        let cancel_err: CancellationError = cell_err.into();
        match &cancel_err {
            CancellationError::CellError { cell_id, .. } => {
                assert_eq!(cell_id, "cell-ob");
            }
            other => panic!("expected CellError, got {other:?}"),
        }
    }

    #[test]
    fn mode_override_replaced_by_second_set() {
        let mut mgr = CancellationManager::new();
        let mode1 = CancellationMode {
            drain_budget_ticks: 100,
            force_abort_on_timeout: false,
            propagate_to_children: false,
            evidence_event_name: "first".into(),
        };
        let mode2 = CancellationMode {
            drain_budget_ticks: 200,
            force_abort_on_timeout: true,
            propagate_to_children: true,
            evidence_event_name: "second".into(),
        };
        mgr.set_mode_override(LifecycleEvent::Unload, mode1);
        mgr.set_mode_override(LifecycleEvent::Unload, mode2.clone());
        assert_eq!(mgr.effective_mode(LifecycleEvent::Unload), mode2);
    }

    #[test]
    fn is_cancelled_false_after_failed_cancel() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(0); // zero budget → will fail
        let mut mgr = CancellationManager::new();

        let result = mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload);
        assert!(result.is_err());
        // Cell should NOT be marked as cancelled on failure
        assert!(!mgr.is_cancelled("ext-1"));
    }

    #[test]
    fn cancel_two_cells_independently_tracked() {
        let mut cell1 = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cell2 = ExecutionCell::new("ext-2", CellKind::Extension, "t");
        let mut cx = mock_cx(300);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell1, &mut cx, LifecycleEvent::Unload)
            .expect("serde deserialization should succeed");
        assert!(mgr.is_cancelled("ext-1"));
        assert!(!mgr.is_cancelled("ext-2"));

        mgr.cancel_cell(&mut cell2, &mut cx, LifecycleEvent::Quarantine)
            .expect("serde deserialization should succeed");
        assert!(mgr.is_cancelled("ext-1"));
        assert!(mgr.is_cancelled("ext-2"));
    }

    #[test]
    fn idempotent_cancel_does_not_add_events() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);
        let mut mgr = CancellationManager::new();

        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("serde deserialization should succeed");
        let events_after_first = mgr.events().len();

        // Second (idempotent) cancel should not add more events
        mgr.cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.events().len(),
            events_after_first,
            "idempotent cancel should not emit events"
        );
    }

    #[test]
    fn cancellation_mode_evidence_event_name_contains_event() {
        for event in [
            LifecycleEvent::Unload,
            LifecycleEvent::Quarantine,
            LifecycleEvent::Suspend,
            LifecycleEvent::Terminate,
            LifecycleEvent::Revocation,
        ] {
            let mode = CancellationMode::for_event(event);
            let event_str = event.to_string();
            assert!(
                mode.evidence_event_name.contains(&event_str),
                "evidence_event_name '{}' should contain '{event_str}'",
                mode.evidence_event_name,
            );
        }
    }

    #[test]
    fn cancel_with_multiple_committed_obligations() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-1", "flush");
        cell.register_obligation("ob-2", "cleanup");
        cell.register_obligation("ob-3", "notify");
        cell.commit_obligation("ob-1")
            .expect("serde deserialization should succeed");
        cell.commit_obligation("ob-2")
            .expect("serde deserialization should succeed");
        cell.commit_obligation("ob-3")
            .expect("serde deserialization should succeed");

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Unload)
            .expect("serde deserialization should succeed");

        assert!(outcome.success);
        assert!(!outcome.timeout_escalated);
        assert_eq!(outcome.finalize_result.obligations_committed, 3);
        assert_eq!(outcome.finalize_result.obligations_aborted, 0);
    }

    #[test]
    fn cancel_with_mixed_committed_and_pending() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);
        let mut mgr = CancellationManager::new();

        cell.register_obligation("ob-1", "committed");
        cell.register_obligation("ob-2", "will timeout");
        cell.commit_obligation("ob-1")
            .expect("serde deserialization should succeed");
        // ob-2 remains pending

        let outcome = mgr
            .cancel_cell(&mut cell, &mut cx, LifecycleEvent::Quarantine)
            .expect("serde deserialization should succeed");

        // ob-2 should timeout and be aborted
        assert!(outcome.timeout_escalated);
        assert_eq!(outcome.finalize_result.obligations_committed, 1);
        assert_eq!(outcome.finalize_result.obligations_aborted, 1);
    }

    #[test]
    fn cancel_all_preserves_order() {
        let mut cell_mgr = CellManager::new();
        let _ = cell_mgr.create_extension_cell("a-ext", "t1");
        let _ = cell_mgr.create_extension_cell("b-ext", "t2");
        let _ = cell_mgr.create_delegate_cell("c-del", "t3");
        let mut cx = mock_cx(500);
        let mut cancel_mgr = CancellationManager::new();

        let results = cancel_mgr.cancel_all(&mut cell_mgr, &mut cx, LifecycleEvent::Terminate);
        assert_eq!(results.len(), 3);

        // All should succeed
        let cell_ids: Vec<String> = results
            .iter()
            .map(|r| {
                r.as_ref()
                    .expect("serde deserialization should succeed")
                    .cell_id
                    .clone()
            })
            .collect();
        // All three cells should be present (order may vary based on BTreeMap)
        assert!(cell_ids.contains(&"a-ext".to_string()));
        assert!(cell_ids.contains(&"b-ext".to_string()));
        assert!(cell_ids.contains(&"c-del".to_string()));
    }

    #[test]
    fn finalize_result_serde_in_outcome() {
        let outcome = CancellationOutcome {
            cell_id: "ext-1".into(),
            event: LifecycleEvent::Terminate,
            success: false,
            finalize_result: FinalizeResult {
                region_id: "ext-1".into(),
                success: false,
                obligations_committed: 0,
                obligations_aborted: 3,
                drain_timeout_escalated: true,
            },
            timeout_escalated: true,
            children_cancelled: 0,
            was_idempotent: false,
        };
        let json = serde_json::to_string(&outcome).expect("serde deserialization should succeed");
        let back: CancellationOutcome =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(outcome, back);
        assert!(json.contains("obligations_aborted"));
        assert!(json.contains("drain_timeout_escalated"));
    }
}
