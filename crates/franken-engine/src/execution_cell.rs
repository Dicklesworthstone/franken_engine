//! Region-per-extension/session execution cells with quiescent close.
//!
//! Integrates the region-based execution model from [`region_lifecycle`] with
//! [`cx_threading::CxThreadedGateway`] so that each loaded extension or active
//! session runs in an isolated execution cell.  Cell teardown follows the
//! quiescent close protocol: drain → finalize → destroy, guaranteeing no
//! dangling work survives cell destruction.
//!
//! Each cell carries a `ContextAdapter` (Cx) that provides trace context,
//! budget, and cancellation, threaded through every effectful operation.
//!
//! Plan references: Section 10.13 item 6, bd-1ukb.
//! Dependencies: bd-2ygl (Cx threading), bd-2ao (region quiescent close),
//!               bd-23om (adapter layer).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::ContextAdapter;
use crate::cx_threading::{CxThreadedEvent, EffectCategory};
use crate::region_lifecycle::{
    CancelReason, DrainDeadline, FinalizeResult, Region, RegionEvent, RegionState,
};

// ---------------------------------------------------------------------------
// CellKind — classification of execution cells
// ---------------------------------------------------------------------------

/// Classification of an execution cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CellKind {
    /// Cell hosting a loaded extension.
    Extension,
    /// Cell hosting an active session within an extension.
    Session,
    /// Cell hosting a delegate computation.
    Delegate,
}

impl fmt::Display for CellKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Extension => write!(f, "extension"),
            Self::Session => write!(f, "session"),
            Self::Delegate => write!(f, "delegate"),
        }
    }
}

// ---------------------------------------------------------------------------
// CellError — errors from cell operations
// ---------------------------------------------------------------------------

/// Error type for execution cell operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellError {
    /// Region is not in a state that allows the requested operation.
    InvalidState {
        cell_id: String,
        current: RegionState,
        attempted: String,
    },
    /// Budget exhausted.
    BudgetExhausted {
        cell_id: String,
        requested_ms: u64,
        remaining_ms: u64,
    },
    /// Cx-threading error propagated from the gateway.
    CxThreading {
        cell_id: String,
        error_code: String,
        message: String,
    },
    /// Cell not found in the cell manager.
    CellNotFound { cell_id: String },
    /// Session creation rejected (cell not running).
    SessionRejected {
        parent_cell_id: String,
        reason: String,
    },
    /// Obligation not found.
    ObligationNotFound {
        cell_id: String,
        obligation_id: String,
    },
}

impl fmt::Display for CellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState {
                cell_id,
                current,
                attempted,
            } => write!(f, "cell {cell_id}: invalid state {current} for {attempted}"),
            Self::BudgetExhausted {
                cell_id,
                requested_ms,
                remaining_ms,
            } => write!(
                f,
                "cell {cell_id}: budget exhausted (need {requested_ms}ms, have {remaining_ms}ms)"
            ),
            Self::CxThreading {
                cell_id,
                error_code,
                message,
            } => write!(f, "cell {cell_id}: cx error [{error_code}]: {message}"),
            Self::CellNotFound { cell_id } => write!(f, "cell not found: {cell_id}"),
            Self::SessionRejected {
                parent_cell_id,
                reason,
            } => write!(f, "session rejected in cell {parent_cell_id}: {reason}"),
            Self::ObligationNotFound {
                cell_id,
                obligation_id,
            } => write!(f, "obligation {obligation_id} not found in cell {cell_id}"),
        }
    }
}

impl std::error::Error for CellError {}

impl CellError {
    /// Stable error code for structured logging.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidState { .. } => "cell_invalid_state",
            Self::BudgetExhausted { .. } => "cell_budget_exhausted",
            Self::CxThreading { .. } => "cell_cx_threading",
            Self::CellNotFound { .. } => "cell_not_found",
            Self::SessionRejected { .. } => "cell_session_rejected",
            Self::ObligationNotFound { .. } => "cell_obligation_not_found",
        }
    }
}

// ---------------------------------------------------------------------------
// CellEvent — structured evidence for cell operations
// ---------------------------------------------------------------------------

/// Structured event emitted by cell operations.
///
/// Fields follow the canonical structured-log schema required by Section 10.13:
/// `trace_id`, `decision_id`, `policy_id`, `component`, `event`, `outcome`,
/// `error_code`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellEvent {
    pub trace_id: String,
    pub cell_id: String,
    pub cell_kind: CellKind,
    pub decision_id: String,
    pub policy_id: String,
    pub event: String,
    pub component: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub region_state: RegionState,
    pub budget_consumed_ms: u64,
}

// ---------------------------------------------------------------------------
// ExecutionCell — a single isolated execution region with Cx-gated effects
// ---------------------------------------------------------------------------

/// Budget cost for cell-level operations (region transitions).
const CELL_TRANSITION_BUDGET_MS: u64 = 2;

/// An isolated execution cell wrapping a [`Region`] with Cx-gated effectful
/// operations and budget accounting.
#[derive(Debug)]
pub struct ExecutionCell {
    cell_id: String,
    kind: CellKind,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    region: Region,
    total_budget_consumed_ms: u64,
    events: Vec<CellEvent>,
    effect_log: Vec<CxThreadedEvent>,
    sequence_counter: u64,
}

impl ExecutionCell {
    /// Create a new execution cell in Running state.
    pub fn new(cell_id: impl Into<String>, kind: CellKind, trace_id: impl Into<String>) -> Self {
        let cell_id = cell_id.into();
        let trace_id = trace_id.into();
        let region = Region::new(&cell_id, kind.to_string(), &trace_id);

        Self {
            cell_id,
            kind,
            trace_id,
            decision_id: String::new(),
            policy_id: String::new(),
            region,
            total_budget_consumed_ms: 0,
            events: Vec::new(),
            effect_log: Vec::new(),
            sequence_counter: 0,
        }
    }

    /// Create a new execution cell with full structured-log context.
    pub fn with_context(
        cell_id: impl Into<String>,
        kind: CellKind,
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        let cell_id = cell_id.into();
        let trace_id = trace_id.into();
        let region = Region::new(&cell_id, kind.to_string(), &trace_id);

        Self {
            cell_id,
            kind,
            trace_id,
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            region,
            total_budget_consumed_ms: 0,
            events: Vec::new(),
            effect_log: Vec::new(),
            sequence_counter: 0,
        }
    }

    /// Cell identifier.
    pub fn cell_id(&self) -> &str {
        &self.cell_id
    }

    /// Cell kind.
    pub fn kind(&self) -> CellKind {
        self.kind
    }

    /// Current region state.
    pub fn state(&self) -> RegionState {
        self.region.state()
    }

    /// Trace ID.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Total budget consumed by operations in this cell.
    pub fn total_budget_consumed_ms(&self) -> u64 {
        self.total_budget_consumed_ms
    }

    /// Number of pending obligations.
    pub fn pending_obligations(&self) -> usize {
        self.region.pending_obligations()
    }

    /// Number of child regions (sessions).
    pub fn session_count(&self) -> usize {
        self.region.child_count()
    }

    /// Create a child session cell.
    ///
    /// Only allowed when the parent cell is in `Running` state.
    /// Inherits `decision_id` and `policy_id` from the parent cell.
    pub fn create_session(
        &mut self,
        session_id: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Result<ExecutionCell, CellError> {
        if self.region.state() != RegionState::Running {
            return Err(CellError::SessionRejected {
                parent_cell_id: self.cell_id.clone(),
                reason: format!("parent cell is {:?}, not Running", self.region.state()),
            });
        }

        let session_id = session_id.into();
        let trace_id = trace_id.into();
        let child_region = Region::new(&session_id, CellKind::Session.to_string(), &trace_id);
        self.region.add_child(child_region.clone());

        Ok(ExecutionCell {
            cell_id: session_id,
            kind: CellKind::Session,
            trace_id,
            decision_id: self.decision_id.clone(),
            policy_id: self.policy_id.clone(),
            region: child_region,
            total_budget_consumed_ms: 0,
            events: Vec::new(),
            effect_log: Vec::new(),
            sequence_counter: 0,
        })
    }

    /// Execute an effectful operation within this cell, consuming budget.
    ///
    /// Returns the sequence number of the operation.
    pub fn execute_effect<C: ContextAdapter>(
        &mut self,
        cx: &mut C,
        category: EffectCategory,
        operation_name: &str,
    ) -> Result<u64, CellError> {
        // Only running cells accept new work
        if self.region.state() != RegionState::Running {
            return Err(CellError::InvalidState {
                cell_id: self.cell_id.clone(),
                current: self.region.state(),
                attempted: format!("execute_effect({operation_name})"),
            });
        }

        let cost = category.budget_cost_ms();
        cx.consume_budget(cost)
            .map_err(|_| CellError::BudgetExhausted {
                cell_id: self.cell_id.clone(),
                requested_ms: cost,
                remaining_ms: cx.budget().remaining_ms(),
            })?;

        self.total_budget_consumed_ms = self.total_budget_consumed_ms.saturating_add(cost);
        self.sequence_counter = self.sequence_counter.saturating_add(1);
        let seq = self.sequence_counter;

        self.effect_log.push(CxThreadedEvent {
            trace_id: cx.trace_id().to_string(),
            category,
            component: format!("execution-cell-{}", self.cell_id),
            operation: operation_name.to_string(),
            outcome: "ok".to_string(),
            budget_consumed_ms: cost,
            budget_remaining_ms: cx.budget().remaining_ms(),
            error_code: None,
        });

        self.emit_event(operation_name, "ok", cost);
        Ok(seq)
    }

    /// Register an obligation that must resolve before finalize.
    pub fn register_obligation(
        &mut self,
        obligation_id: impl Into<String>,
        description: impl Into<String>,
    ) {
        self.region.register_obligation(obligation_id, description);
    }

    /// Commit (resolve) an obligation.
    pub fn commit_obligation(&mut self, obligation_id: &str) -> Result<(), CellError> {
        if self.region.commit_obligation(obligation_id) {
            Ok(())
        } else {
            Err(CellError::ObligationNotFound {
                cell_id: self.cell_id.clone(),
                obligation_id: obligation_id.to_string(),
            })
        }
    }

    /// Abort an obligation.
    pub fn abort_obligation(&mut self, obligation_id: &str) -> Result<(), CellError> {
        if self.region.abort_obligation(obligation_id) {
            Ok(())
        } else {
            Err(CellError::ObligationNotFound {
                cell_id: self.cell_id.clone(),
                obligation_id: obligation_id.to_string(),
            })
        }
    }

    /// Initiate quiescent close: cancel → drain → finalize.
    ///
    /// Consumes budget for the transition. The cell must be in Running state.
    pub fn initiate_close<C: ContextAdapter>(
        &mut self,
        cx: &mut C,
        reason: CancelReason,
        deadline: DrainDeadline,
    ) -> Result<(), CellError> {
        cx.consume_budget(CELL_TRANSITION_BUDGET_MS)
            .map_err(|_| CellError::BudgetExhausted {
                cell_id: self.cell_id.clone(),
                requested_ms: CELL_TRANSITION_BUDGET_MS,
                remaining_ms: cx.budget().remaining_ms(),
            })?;

        self.total_budget_consumed_ms = self
            .total_budget_consumed_ms
            .saturating_add(CELL_TRANSITION_BUDGET_MS);

        self.region
            .cancel(reason)
            .map_err(|e| CellError::InvalidState {
                cell_id: self.cell_id.clone(),
                current: e.current_state,
                attempted: "cancel".to_string(),
            })?;

        self.emit_event("cancel", "initiated", CELL_TRANSITION_BUDGET_MS);

        self.region
            .drain(deadline)
            .map_err(|e| CellError::InvalidState {
                cell_id: self.cell_id.clone(),
                current: e.current_state,
                attempted: "drain".to_string(),
            })?;

        self.emit_event("drain", "started", 0);
        Ok(())
    }

    /// Advance drain by one tick. Returns true if deadline exceeded.
    pub fn drain_tick(&mut self) -> bool {
        self.region.drain_tick()
    }

    /// Finalize the cell after drain completes.
    pub fn finalize(&mut self) -> Result<FinalizeResult, CellError> {
        let result = self
            .region
            .finalize()
            .map_err(|e| CellError::InvalidState {
                cell_id: self.cell_id.clone(),
                current: e.current_state,
                attempted: "finalize".to_string(),
            })?;

        let outcome = if result.success {
            "finalize_success"
        } else {
            "finalize_with_pending"
        };
        self.emit_event("finalize", outcome, 0);
        Ok(result)
    }

    /// Full quiescent close: cancel → drain (with ticks) → finalize.
    pub fn close<C: ContextAdapter>(
        &mut self,
        cx: &mut C,
        reason: CancelReason,
        deadline: DrainDeadline,
    ) -> Result<FinalizeResult, CellError> {
        self.initiate_close(cx, reason, deadline)?;

        // Tick through drain
        let max = deadline.max_ticks;
        for _ in 0..max {
            if self.region.pending_obligations() == 0 {
                break;
            }
            self.drain_tick();
        }

        self.finalize()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<CellEvent> {
        std::mem::take(&mut self.events)
    }

    /// Drain accumulated region events.
    pub fn drain_region_events(&mut self) -> Vec<RegionEvent> {
        self.region.drain_events()
    }

    /// Accumulated effect log.
    pub fn effect_log(&self) -> &[CxThreadedEvent] {
        &self.effect_log
    }

    /// Events.
    pub fn events(&self) -> &[CellEvent] {
        &self.events
    }

    /// Decision ID for structured logging.
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    /// Policy ID for structured logging.
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    fn emit_event(&mut self, event: &str, outcome: &str, budget_consumed_ms: u64) {
        self.emit_event_with_error(event, outcome, budget_consumed_ms, None);
    }

    fn emit_event_with_error(
        &mut self,
        event: &str,
        outcome: &str,
        budget_consumed_ms: u64,
        error_code: Option<&str>,
    ) {
        self.events.push(CellEvent {
            trace_id: self.trace_id.clone(),
            cell_id: self.cell_id.clone(),
            cell_kind: self.kind,
            decision_id: self.decision_id.clone(),
            policy_id: self.policy_id.clone(),
            event: event.to_string(),
            component: "execution_cell".to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
            region_state: self.region.state(),
            budget_consumed_ms,
        });
    }
}

// ---------------------------------------------------------------------------
// CellManager — manages multiple concurrent execution cells
// ---------------------------------------------------------------------------

/// Manages multiple concurrent execution cells with isolation guarantees.
#[derive(Debug, Default)]
pub struct CellManager {
    cells: BTreeMap<String, ExecutionCell>,
    closed_cells: Vec<(String, FinalizeResult)>,
}

impl CellManager {
    /// Create an empty cell manager.
    pub fn new() -> Self {
        Self {
            cells: BTreeMap::new(),
            closed_cells: Vec::new(),
        }
    }

    /// Create and register a new extension cell.
    pub fn create_extension_cell(
        &mut self,
        cell_id: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> &mut ExecutionCell {
        let cell_id = cell_id.into();
        let cell = ExecutionCell::new(&cell_id, CellKind::Extension, trace_id);
        match self.cells.entry(cell_id) {
            std::collections::btree_map::Entry::Occupied(mut o) => {
                o.insert(cell);
                o.into_mut()
            }
            std::collections::btree_map::Entry::Vacant(v) => v.insert(cell),
        }
    }

    /// Create and register a new delegate cell.
    pub fn create_delegate_cell(
        &mut self,
        cell_id: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> &mut ExecutionCell {
        let cell_id = cell_id.into();
        let cell = ExecutionCell::new(&cell_id, CellKind::Delegate, trace_id);
        match self.cells.entry(cell_id) {
            std::collections::btree_map::Entry::Occupied(mut o) => {
                o.insert(cell);
                o.into_mut()
            }
            std::collections::btree_map::Entry::Vacant(v) => v.insert(cell),
        }
    }

    /// Register a pre-created cell.
    pub fn insert_cell(
        &mut self,
        cell_id: impl Into<String>,
        cell: ExecutionCell,
    ) -> &mut ExecutionCell {
        let cell_id = cell_id.into();
        match self.cells.entry(cell_id) {
            std::collections::btree_map::Entry::Occupied(mut o) => {
                o.insert(cell);
                o.into_mut()
            }
            std::collections::btree_map::Entry::Vacant(v) => v.insert(cell),
        }
    }

    /// Get a reference to a cell.
    pub fn get(&self, cell_id: &str) -> Option<&ExecutionCell> {
        self.cells.get(cell_id)
    }

    /// Get a mutable reference to a cell.
    pub fn get_mut(&mut self, cell_id: &str) -> Option<&mut ExecutionCell> {
        self.cells.get_mut(cell_id)
    }

    /// Move a finalized cell to the closed set.
    pub fn archive_cell(&mut self, cell_id: &str, result: FinalizeResult) {
        if let Some(cell) = self.cells.remove(cell_id) {
            let _ = cell;
        }
        self.closed_cells.push((cell_id.to_string(), result));
    }

    /// Close a cell and move it to the closed set.
    pub fn close_cell<C: ContextAdapter>(
        &mut self,
        cell_id: &str,
        cx: &mut C,
        reason: CancelReason,
        deadline: DrainDeadline,
    ) -> Result<FinalizeResult, CellError> {
        let cell = self
            .cells
            .get_mut(cell_id)
            .ok_or_else(|| CellError::CellNotFound {
                cell_id: cell_id.to_string(),
            })?;

        let result = cell.close(cx, reason, deadline)?;
        let cell_id_owned = cell_id.to_string();

        // Move to closed set
        if let Some(cell) = self.cells.remove(cell_id) {
            let _ = cell;
        }
        self.closed_cells.push((cell_id_owned, result.clone()));
        Ok(result)
    }

    /// Number of active (open) cells.
    pub fn active_count(&self) -> usize {
        self.cells.len()
    }

    /// Number of closed cells.
    pub fn closed_count(&self) -> usize {
        self.closed_cells.len()
    }

    /// All active cell IDs.
    pub fn active_cell_ids(&self) -> Vec<&str> {
        self.cells.keys().map(String::as_str).collect()
    }

    /// Closed cell results.
    pub fn closed_results(&self) -> &[(String, FinalizeResult)] {
        &self.closed_cells
    }

    /// Close all active cells.
    pub fn close_all<C: ContextAdapter>(
        &mut self,
        cx: &mut C,
        reason: CancelReason,
        deadline: DrainDeadline,
    ) -> Vec<Result<FinalizeResult, CellError>> {
        let cell_ids: Vec<String> = self.cells.keys().cloned().collect();
        let mut results = Vec::new();
        for cell_id in cell_ids {
            results.push(self.close_cell(&cell_id, cx, reason.clone(), deadline));
        }
        results
    }
}

// ---------------------------------------------------------------------------
// LifecycleEvidenceEntry — structured evidence for lifecycle transitions
// ---------------------------------------------------------------------------

/// Evidence entry emitted at extension-host lifecycle boundaries.
///
/// Each entry captures the full structured-log schema required by Section 10.13
/// acceptance criteria: `trace_id`, `decision_id`, `policy_id`, `component`,
/// `event`, `outcome`, `error_code`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvidenceEntry {
    pub sequence: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub cell_id: String,
    pub cell_kind: CellKind,
    pub region_state: RegionState,
    pub budget_consumed_ms: u64,
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// CellCloseReport — detailed report from a cell close operation
// ---------------------------------------------------------------------------

/// Detailed, deterministic report from closing an execution cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellCloseReport {
    pub cell_id: String,
    pub cell_kind: CellKind,
    pub close_reason: String,
    pub success: bool,
    pub obligations_committed: usize,
    pub obligations_aborted: usize,
    pub drain_timeout_escalated: bool,
    pub budget_consumed_ms: u64,
    pub evidence_entries_emitted: u64,
}

// ---------------------------------------------------------------------------
// ExtensionHostBinding — lifecycle integration layer
// ---------------------------------------------------------------------------

/// Wires execution cells into the extension-host lifecycle so that:
///
/// - **Extension load** creates a new execution region.
/// - **Session start** creates a sub-region scoped to the session lifetime.
/// - **Region close** follows the quiescent protocol: cancel → drain → finalize.
/// - No extension or session code can outlive its region.
///
/// All lifecycle transitions emit structured evidence via
/// [`LifecycleEvidenceEntry`].
///
/// Plan reference: Section 10.13 item 6, bd-1ukb.
#[derive(Debug)]
pub struct ExtensionHostBinding {
    manager: CellManager,
    evidence_log: Vec<LifecycleEvidenceEntry>,
    event_sequence: u64,
    default_drain_deadline: DrainDeadline,
}

impl ExtensionHostBinding {
    /// Create a new binding with the given default drain deadline.
    pub fn new(default_drain_deadline: DrainDeadline) -> Self {
        Self {
            manager: CellManager::new(),
            evidence_log: Vec::new(),
            event_sequence: 0,
            default_drain_deadline,
        }
    }

    /// Access the underlying cell manager.
    pub fn manager(&self) -> &CellManager {
        &self.manager
    }

    /// Mutable access to the underlying cell manager.
    pub fn manager_mut(&mut self) -> &mut CellManager {
        &mut self.manager
    }

    /// Load an extension, creating an isolated execution cell.
    ///
    /// Returns the cell ID (same as the extension_id) on success.
    pub fn load_extension<C: ContextAdapter>(
        &mut self,
        extension_id: impl Into<String>,
        cx: &mut C,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Result<String, CellError> {
        let ext_id = extension_id.into();
        let decision_id = decision_id.into();
        let policy_id = policy_id.into();
        let trace_id = cx.trace_id().to_string();

        // Budget check: extension load costs 1 transition unit
        cx.consume_budget(CELL_TRANSITION_BUDGET_MS)
            .map_err(|_| CellError::BudgetExhausted {
                cell_id: ext_id.clone(),
                requested_ms: CELL_TRANSITION_BUDGET_MS,
                remaining_ms: cx.budget().remaining_ms(),
            })?;

        let cell = ExecutionCell::with_context(
            &ext_id,
            CellKind::Extension,
            &trace_id,
            &decision_id,
            &policy_id,
        );
        self.manager.cells.insert(ext_id.clone(), cell);

        self.emit_evidence(
            &trace_id,
            &decision_id,
            &policy_id,
            "extension_load",
            "ok",
            None,
            &ext_id,
            CellKind::Extension,
            RegionState::Running,
            CELL_TRANSITION_BUDGET_MS,
        );

        Ok(ext_id)
    }

    /// Start a session within an extension, creating a sub-region.
    ///
    /// The session inherits the parent extension's decision and policy context.
    pub fn start_session(
        &mut self,
        extension_id: &str,
        session_id: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Result<String, CellError> {
        let session_id = session_id.into();
        let trace_id = trace_id.into();

        let (decision_id, policy_id, session_cell) = {
            let cell =
                self.manager
                    .get_mut(extension_id)
                    .ok_or_else(|| CellError::CellNotFound {
                        cell_id: extension_id.to_string(),
                    })?;

            let decision_id = cell.decision_id.clone();
            let policy_id = cell.policy_id.clone();

            let session_cell = cell.create_session(&session_id, &trace_id)?;
            (decision_id, policy_id, session_cell)
        };

        self.manager.insert_cell(&session_id, session_cell);

        self.emit_evidence(
            &trace_id,
            &decision_id,
            &policy_id,
            "session_start",
            "ok",
            None,
            &session_id,
            CellKind::Session,
            RegionState::Running,
            0,
        );

        Ok(session_id)
    }

    /// Unload an extension using the quiescent close protocol.
    ///
    /// This follows: cancel → drain → finalize → destroy.
    pub fn unload_extension<C: ContextAdapter>(
        &mut self,
        extension_id: &str,
        cx: &mut C,
        reason: CancelReason,
    ) -> Result<CellCloseReport, CellError> {
        let cell = self
            .manager
            .cells
            .get(extension_id)
            .ok_or_else(|| CellError::CellNotFound {
                cell_id: extension_id.to_string(),
            })?;

        let decision_id = cell.decision_id.clone();
        let policy_id = cell.policy_id.clone();
        let trace_id = cell.trace_id.clone();
        let kind = cell.kind();
        let budget_before_close = cell.total_budget_consumed_ms();

        let deadline = self.default_drain_deadline;
        let result = self
            .manager
            .close_cell(extension_id, cx, reason.clone(), deadline)?;

        // Budget includes all prior execute_effect calls plus the close transition.
        let total_budget = budget_before_close.saturating_add(CELL_TRANSITION_BUDGET_MS);

        let report = CellCloseReport {
            cell_id: extension_id.to_string(),
            cell_kind: kind,
            close_reason: format!("{reason:?}"),
            success: result.success,
            obligations_committed: result.obligations_committed,
            obligations_aborted: result.obligations_aborted,
            drain_timeout_escalated: result.drain_timeout_escalated,
            budget_consumed_ms: total_budget,
            evidence_entries_emitted: 1,
        };

        let outcome = if result.success {
            "unload_success"
        } else {
            "unload_with_pending"
        };
        let error_code = if result.drain_timeout_escalated {
            Some("drain_timeout_escalated")
        } else {
            None
        };

        self.emit_evidence(
            &trace_id,
            &decision_id,
            &policy_id,
            "extension_unload",
            outcome,
            error_code,
            extension_id,
            kind,
            RegionState::Closed,
            CELL_TRANSITION_BUDGET_MS,
        );

        Ok(report)
    }

    /// Unload all extensions using the quiescent close protocol.
    pub fn unload_all<C: ContextAdapter>(
        &mut self,
        cx: &mut C,
        reason: CancelReason,
    ) -> Vec<Result<CellCloseReport, CellError>> {
        let cell_ids: Vec<String> = self.manager.cells.keys().cloned().collect();
        let mut reports = Vec::new();
        for cell_id in cell_ids {
            reports.push(self.unload_extension(&cell_id, cx, reason.clone()));
        }
        reports
    }

    /// Accumulated lifecycle evidence entries.
    pub fn evidence_log(&self) -> &[LifecycleEvidenceEntry] {
        &self.evidence_log
    }

    /// Filter evidence by category event name.
    pub fn evidence_for_event(&self, event: &str) -> Vec<&LifecycleEvidenceEntry> {
        self.evidence_log
            .iter()
            .filter(|e| e.event == event)
            .collect()
    }

    /// Number of active extensions.
    pub fn active_extension_count(&self) -> usize {
        self.manager.active_count()
    }

    /// Number of evidence entries emitted.
    pub fn evidence_count(&self) -> u64 {
        self.event_sequence
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_evidence(
        &mut self,
        trace_id: &str,
        decision_id: &str,
        policy_id: &str,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
        cell_id: &str,
        cell_kind: CellKind,
        region_state: RegionState,
        budget_consumed_ms: u64,
    ) {
        let seq = self.event_sequence;
        self.event_sequence += 1;
        self.evidence_log.push(LifecycleEvidenceEntry {
            sequence: seq,
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            component: "extension_host_binding".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
            cell_id: cell_id.to_string(),
            cell_kind,
            region_state,
            budget_consumed_ms,
            metadata: BTreeMap::new(),
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
    // CellKind
    // -----------------------------------------------------------------------

    #[test]
    fn cell_kind_display() {
        assert_eq!(CellKind::Extension.to_string(), "extension");
        assert_eq!(CellKind::Session.to_string(), "session");
        assert_eq!(CellKind::Delegate.to_string(), "delegate");
    }

    #[test]
    fn cell_kind_ordering() {
        assert!(CellKind::Extension < CellKind::Session);
        assert!(CellKind::Session < CellKind::Delegate);
    }

    #[test]
    fn cell_kind_serde_roundtrip() {
        for kind in [CellKind::Extension, CellKind::Session, CellKind::Delegate] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: CellKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }

    // -----------------------------------------------------------------------
    // CellError
    // -----------------------------------------------------------------------

    #[test]
    fn cell_error_display_and_codes() {
        let errors = vec![
            CellError::InvalidState {
                cell_id: "c1".to_string(),
                current: RegionState::Closed,
                attempted: "execute".to_string(),
            },
            CellError::BudgetExhausted {
                cell_id: "c1".to_string(),
                requested_ms: 10,
                remaining_ms: 5,
            },
            CellError::CxThreading {
                cell_id: "c1".to_string(),
                error_code: "cx_budget_exhausted".to_string(),
                message: "no budget".to_string(),
            },
            CellError::CellNotFound {
                cell_id: "c99".to_string(),
            },
            CellError::SessionRejected {
                parent_cell_id: "c1".to_string(),
                reason: "not running".to_string(),
            },
            CellError::ObligationNotFound {
                cell_id: "c1".to_string(),
                obligation_id: "ob-999".to_string(),
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
    fn cell_error_serde_roundtrip() {
        let err = CellError::InvalidState {
            cell_id: "c1".to_string(),
            current: RegionState::Running,
            attempted: "finalize".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: CellError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored);
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — creation and basic properties
    // -----------------------------------------------------------------------

    #[test]
    fn new_cell_starts_running() {
        let cell = ExecutionCell::new("ext-1", CellKind::Extension, "trace-1");
        assert_eq!(cell.cell_id(), "ext-1");
        assert_eq!(cell.kind(), CellKind::Extension);
        assert_eq!(cell.state(), RegionState::Running);
        assert_eq!(cell.trace_id(), "trace-1");
        assert_eq!(cell.total_budget_consumed_ms(), 0);
        assert_eq!(cell.pending_obligations(), 0);
        assert_eq!(cell.session_count(), 0);
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — execute_effect
    // -----------------------------------------------------------------------

    #[test]
    fn execute_effect_consumes_budget() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        let seq = cell
            .execute_effect(&mut cx, EffectCategory::Hostcall, "read_data")
            .expect("effect");
        assert_eq!(seq, 1);
        assert_eq!(cell.total_budget_consumed_ms(), 1); // HOSTCALL_BUDGET_COST_MS
    }

    #[test]
    fn execute_effect_increments_sequence() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        let s1 = cell
            .execute_effect(&mut cx, EffectCategory::Hostcall, "op1")
            .unwrap();
        let s2 = cell
            .execute_effect(&mut cx, EffectCategory::PolicyCheck, "op2")
            .unwrap();
        let s3 = cell
            .execute_effect(&mut cx, EffectCategory::TelemetryEmit, "op3")
            .unwrap();

        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
    }

    #[test]
    fn execute_effect_emits_event_and_effect_log() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.execute_effect(&mut cx, EffectCategory::Hostcall, "read_data")
            .unwrap();

        assert_eq!(cell.events().len(), 1);
        assert_eq!(cell.events()[0].event, "read_data");
        assert_eq!(cell.events()[0].outcome, "ok");

        assert_eq!(cell.effect_log().len(), 1);
        assert_eq!(cell.effect_log()[0].operation, "read_data");
        assert_eq!(cell.effect_log()[0].category, EffectCategory::Hostcall);
    }

    #[test]
    fn execute_effect_rejects_when_not_running() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        // Close the cell first
        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let err = cell
            .execute_effect(&mut cx, EffectCategory::Hostcall, "op")
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_invalid_state");
    }

    #[test]
    fn execute_effect_budget_exhausted() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(0); // No budget

        let err = cell
            .execute_effect(&mut cx, EffectCategory::Hostcall, "op")
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_budget_exhausted");
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — obligations
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_lifecycle() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        cell.register_obligation("ob-1", "flush evidence");
        cell.register_obligation("ob-2", "release locks");

        assert_eq!(cell.pending_obligations(), 2);

        cell.commit_obligation("ob-1").unwrap();
        assert_eq!(cell.pending_obligations(), 1);

        cell.abort_obligation("ob-2").unwrap();
        assert_eq!(cell.pending_obligations(), 0);
    }

    #[test]
    fn obligation_not_found_error() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let err = cell.commit_obligation("nonexistent").unwrap_err();
        assert_eq!(err.error_code(), "cell_obligation_not_found");
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — quiescent close
    // -----------------------------------------------------------------------

    #[test]
    fn full_close_lifecycle() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        let result = cell
            .close(
                &mut cx,
                CancelReason::OperatorShutdown,
                DrainDeadline::default(),
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(cell.state(), RegionState::Closed);
        assert!(cell.total_budget_consumed_ms() >= CELL_TRANSITION_BUDGET_MS);
    }

    #[test]
    fn close_with_obligations() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.register_obligation("ob-1", "flush");
        cell.commit_obligation("ob-1").unwrap();

        let result = cell
            .close(
                &mut cx,
                CancelReason::OperatorShutdown,
                DrainDeadline::default(),
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(result.obligations_committed, 1);
    }

    #[test]
    fn close_with_pending_obligations_and_timeout() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.register_obligation("ob-1", "slow task");

        let result = cell
            .close(
                &mut cx,
                CancelReason::BudgetExhausted,
                DrainDeadline { max_ticks: 5 },
            )
            .unwrap();

        // Obligation was force-aborted by timeout escalation
        assert!(result.drain_timeout_escalated);
        assert_eq!(result.obligations_aborted, 1);
    }

    #[test]
    fn initiate_close_then_tick_then_finalize() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.register_obligation("ob-1", "flush");
        cell.initiate_close(
            &mut cx,
            CancelReason::Quarantine,
            DrainDeadline { max_ticks: 10 },
        )
        .unwrap();

        assert_eq!(cell.state(), RegionState::Draining);

        // Resolve obligation during drain
        cell.commit_obligation("ob-1").unwrap();

        let result = cell.finalize().unwrap();
        assert!(result.success);
        assert_eq!(result.obligations_committed, 1);
    }

    #[test]
    fn close_budget_exhausted() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(1); // Only 1ms, need 2ms for transition

        let err = cell
            .close(
                &mut cx,
                CancelReason::OperatorShutdown,
                DrainDeadline::default(),
            )
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_budget_exhausted");
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — sessions
    // -----------------------------------------------------------------------

    #[test]
    fn create_session_in_running_cell() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let session = cell.create_session("sess-1", "t-sess").unwrap();

        assert_eq!(session.cell_id(), "sess-1");
        assert_eq!(session.kind(), CellKind::Session);
        assert_eq!(session.state(), RegionState::Running);
        assert_eq!(cell.session_count(), 1);
    }

    #[test]
    fn create_session_rejected_when_not_running() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let err = cell.create_session("sess-1", "t").unwrap_err();
        assert_eq!(err.error_code(), "cell_session_rejected");
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — events and evidence
    // -----------------------------------------------------------------------

    #[test]
    fn close_emits_structured_events() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let events = cell.events();
        // cancel, drain, finalize
        assert!(events.len() >= 3);
        assert!(events.iter().any(|e| e.event == "cancel"));
        assert!(events.iter().any(|e| e.event == "drain"));
        assert!(events.iter().any(|e| e.event == "finalize"));
    }

    #[test]
    fn region_events_accessible() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let region_events = cell.drain_region_events();
        assert!(!region_events.is_empty());
    }

    // -----------------------------------------------------------------------
    // CellManager
    // -----------------------------------------------------------------------

    #[test]
    fn manager_create_and_retrieve_cells() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-1", "t1");
        mgr.create_extension_cell("ext-2", "t2");
        mgr.create_delegate_cell("del-1", "t3");

        assert_eq!(mgr.active_count(), 3);
        assert_eq!(mgr.closed_count(), 0);

        let ids = mgr.active_cell_ids();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"ext-1"));
        assert!(ids.contains(&"ext-2"));
        assert!(ids.contains(&"del-1"));
    }

    #[test]
    fn manager_get_cell() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-1", "t1");

        let cell = mgr.get("ext-1").expect("cell exists");
        assert_eq!(cell.kind(), CellKind::Extension);
    }

    #[test]
    fn manager_close_cell() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-1", "t1");
        let mut cx = mock_cx(100);

        let result = mgr
            .close_cell(
                "ext-1",
                &mut cx,
                CancelReason::OperatorShutdown,
                DrainDeadline::default(),
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.closed_count(), 1);
    }

    #[test]
    fn manager_close_nonexistent_cell() {
        let mut mgr = CellManager::new();
        let mut cx = mock_cx(100);

        let err = mgr
            .close_cell(
                "nonexistent",
                &mut cx,
                CancelReason::OperatorShutdown,
                DrainDeadline::default(),
            )
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_not_found");
    }

    #[test]
    fn manager_close_all() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-1", "t1");
        mgr.create_extension_cell("ext-2", "t2");
        let mut cx = mock_cx(200);

        let results = mgr.close_all(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        );

        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(r.is_ok());
        }
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.closed_count(), 2);
    }

    // -----------------------------------------------------------------------
    // Cross-cell isolation
    // -----------------------------------------------------------------------

    #[test]
    fn cells_are_isolated() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-1", "t1");
        mgr.create_extension_cell("ext-2", "t2");

        let mut cx = mock_cx(100);

        // Execute effect in ext-1
        mgr.get_mut("ext-1")
            .unwrap()
            .execute_effect(&mut cx, EffectCategory::Hostcall, "op1")
            .unwrap();

        // Close ext-1
        mgr.close_cell(
            "ext-1",
            &mut cx,
            CancelReason::Quarantine,
            DrainDeadline::default(),
        )
        .unwrap();

        // ext-2 is still running and unaffected
        let cell2 = mgr.get("ext-2").unwrap();
        assert_eq!(cell2.state(), RegionState::Running);
        assert_eq!(cell2.total_budget_consumed_ms(), 0);

        // Can still execute effects in ext-2
        mgr.get_mut("ext-2")
            .unwrap()
            .execute_effect(&mut cx, EffectCategory::Hostcall, "op2")
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // Deterministic replay
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<CellEvent> {
            let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
            let mut cx = mock_cx(200);

            cell.execute_effect(&mut cx, EffectCategory::Hostcall, "read")
                .unwrap();
            cell.execute_effect(&mut cx, EffectCategory::PolicyCheck, "check")
                .unwrap();
            cell.register_obligation("ob-1", "flush");
            cell.commit_obligation("ob-1").unwrap();
            cell.close(
                &mut cx,
                CancelReason::OperatorShutdown,
                DrainDeadline::default(),
            )
            .unwrap();
            cell.drain_events()
        };

        let e1 = run();
        let e2 = run();
        assert_eq!(e1, e2);
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    #[test]
    fn cell_event_serde_roundtrip() {
        let event = CellEvent {
            trace_id: "t".to_string(),
            cell_id: "c".to_string(),
            cell_kind: CellKind::Extension,
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            event: "execute_effect".to_string(),
            component: "execution_cell".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            region_state: RegionState::Running,
            budget_consumed_ms: 1,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: CellEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn cell_event_serde_with_error_code() {
        let event = CellEvent {
            trace_id: "t".to_string(),
            cell_id: "c".to_string(),
            cell_kind: CellKind::Extension,
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            event: "execute_effect".to_string(),
            component: "execution_cell".to_string(),
            outcome: "error".to_string(),
            error_code: Some("budget_exhausted".to_string()),
            region_state: RegionState::Running,
            budget_consumed_ms: 0,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: CellEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
        assert_eq!(restored.error_code.as_deref(), Some("budget_exhausted"));
    }

    #[test]
    fn cell_error_all_variants_serde() {
        let errors = vec![
            CellError::InvalidState {
                cell_id: "c".to_string(),
                current: RegionState::Closed,
                attempted: "exec".to_string(),
            },
            CellError::BudgetExhausted {
                cell_id: "c".to_string(),
                requested_ms: 10,
                remaining_ms: 0,
            },
            CellError::CxThreading {
                cell_id: "c".to_string(),
                error_code: "err".to_string(),
                message: "msg".to_string(),
            },
            CellError::CellNotFound {
                cell_id: "c".to_string(),
            },
            CellError::SessionRejected {
                parent_cell_id: "c".to_string(),
                reason: "r".to_string(),
            },
            CellError::ObligationNotFound {
                cell_id: "c".to_string(),
                obligation_id: "ob".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: CellError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_effects_accumulate_budget() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        for _ in 0..10 {
            cell.execute_effect(&mut cx, EffectCategory::Hostcall, "op")
                .unwrap();
        }

        assert_eq!(cell.total_budget_consumed_ms(), 10); // 10 * 1ms
        assert_eq!(cell.effect_log().len(), 10);
    }

    #[test]
    fn drain_tick_on_running_cell_returns_false() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        assert!(!cell.drain_tick());
    }

    #[test]
    fn manager_closed_results_accessible() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-1", "t1");
        let mut cx = mock_cx(100);

        mgr.close_cell(
            "ext-1",
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let results = mgr.closed_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "ext-1");
        assert!(results[0].1.success);
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — with_context constructor
    // -----------------------------------------------------------------------

    #[test]
    fn with_context_sets_decision_and_policy() {
        let cell = ExecutionCell::with_context(
            "ext-1",
            CellKind::Extension,
            "t-1",
            "decision-42",
            "policy-v3",
        );
        assert_eq!(cell.cell_id(), "ext-1");
        assert_eq!(cell.decision_id(), "decision-42");
        assert_eq!(cell.policy_id(), "policy-v3");
        assert_eq!(cell.state(), RegionState::Running);
    }

    #[test]
    fn with_context_events_carry_structured_fields() {
        let mut cell = ExecutionCell::with_context(
            "ext-1",
            CellKind::Extension,
            "t-1",
            "decision-42",
            "policy-v3",
        );
        let mut cx = mock_cx(100);

        cell.execute_effect(&mut cx, EffectCategory::Hostcall, "read_data")
            .unwrap();

        let ev = &cell.events()[0];
        assert_eq!(ev.decision_id, "decision-42");
        assert_eq!(ev.policy_id, "policy-v3");
        assert_eq!(ev.component, "execution_cell");
        assert!(ev.error_code.is_none());
    }

    #[test]
    fn session_inherits_context_from_parent() {
        let mut cell = ExecutionCell::with_context(
            "ext-1",
            CellKind::Extension,
            "t-1",
            "decision-42",
            "policy-v3",
        );
        let session = cell.create_session("sess-1", "t-sess-1").unwrap();
        assert_eq!(session.decision_id(), "decision-42");
        assert_eq!(session.policy_id(), "policy-v3");
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — close events carry structured log fields
    // -----------------------------------------------------------------------

    #[test]
    fn close_events_have_stable_structured_fields() {
        let mut cell =
            ExecutionCell::with_context("ext-1", CellKind::Extension, "t-1", "d-1", "p-1");
        let mut cx = mock_cx(100);

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        for ev in cell.events() {
            assert_eq!(ev.trace_id, "t-1");
            assert_eq!(ev.decision_id, "d-1");
            assert_eq!(ev.policy_id, "p-1");
            assert_eq!(ev.component, "execution_cell");
            assert!(!ev.event.is_empty());
            assert!(!ev.outcome.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — adversarial: double close
    // -----------------------------------------------------------------------

    #[test]
    fn double_close_returns_invalid_state() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(200);

        cell.close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let err = cell
            .close(
                &mut cx,
                CancelReason::OperatorShutdown,
                DrainDeadline::default(),
            )
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_invalid_state");
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — adversarial: session creation during drain
    // -----------------------------------------------------------------------

    #[test]
    fn session_creation_during_drain_rejected() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.register_obligation("ob-1", "slow");
        cell.initiate_close(
            &mut cx,
            CancelReason::Quarantine,
            DrainDeadline { max_ticks: 10 },
        )
        .unwrap();
        assert_eq!(cell.state(), RegionState::Draining);

        let err = cell.create_session("sess-late", "t-late").unwrap_err();
        assert_eq!(err.error_code(), "cell_session_rejected");
    }

    // -----------------------------------------------------------------------
    // ExecutionCell — effect execution after initiate_close
    // -----------------------------------------------------------------------

    #[test]
    fn effect_rejected_after_initiate_close() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.initiate_close(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline::default(),
        )
        .unwrap();

        let err = cell
            .execute_effect(&mut cx, EffectCategory::Hostcall, "late_op")
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_invalid_state");
    }

    // -----------------------------------------------------------------------
    // CellManager — close with mixed obligation states
    // -----------------------------------------------------------------------

    #[test]
    fn manager_close_all_with_mixed_obligations() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-1", "t1");
        mgr.create_extension_cell("ext-2", "t2");

        // ext-1: has committed obligation
        mgr.get_mut("ext-1")
            .unwrap()
            .register_obligation("ob-1", "flush");
        mgr.get_mut("ext-1")
            .unwrap()
            .commit_obligation("ob-1")
            .unwrap();

        // ext-2: has pending obligation (will timeout)
        mgr.get_mut("ext-2")
            .unwrap()
            .register_obligation("ob-2", "never-done");

        let mut cx = mock_cx(200);
        let results = mgr.close_all(
            &mut cx,
            CancelReason::OperatorShutdown,
            DrainDeadline { max_ticks: 3 },
        );

        assert_eq!(results.len(), 2);
        // Both should succeed (one normally, one with timeout escalation)
        for r in &results {
            assert!(r.is_ok());
        }

        let r1 = &results[0].as_ref().unwrap();
        assert!(r1.success);
        assert_eq!(r1.obligations_committed, 1);

        let r2 = &results[1].as_ref().unwrap();
        assert!(r2.drain_timeout_escalated);
        assert_eq!(r2.obligations_aborted, 1);
    }

    // -----------------------------------------------------------------------
    // LifecycleEvidenceEntry — serde
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_evidence_entry_serde_roundtrip() {
        let entry = LifecycleEvidenceEntry {
            sequence: 0,
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "extension_host_binding".to_string(),
            event: "extension_load".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            cell_id: "ext-1".to_string(),
            cell_kind: CellKind::Extension,
            region_state: RegionState::Running,
            budget_consumed_ms: 2,
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: LifecycleEvidenceEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, restored);
    }

    // -----------------------------------------------------------------------
    // CellCloseReport — serde
    // -----------------------------------------------------------------------

    #[test]
    fn cell_close_report_serde_roundtrip() {
        let report = CellCloseReport {
            cell_id: "ext-1".to_string(),
            cell_kind: CellKind::Extension,
            close_reason: "OperatorShutdown".to_string(),
            success: true,
            obligations_committed: 2_usize,
            obligations_aborted: 0_usize,
            drain_timeout_escalated: false,
            budget_consumed_ms: 2,
            evidence_entries_emitted: 1,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let restored: CellCloseReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, restored);
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — basic lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn binding_load_and_unload_extension() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(200);

        let ext_id = binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        assert_eq!(ext_id, "ext-1");
        assert_eq!(binding.active_extension_count(), 1);

        let report = binding
            .unload_extension("ext-1", &mut cx, CancelReason::OperatorShutdown)
            .unwrap();
        assert!(report.success);
        assert_eq!(report.cell_kind, CellKind::Extension);
        assert_eq!(binding.active_extension_count(), 0);
    }

    #[test]
    fn binding_load_emits_evidence() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(200);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();

        let evidence = binding.evidence_log();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].event, "extension_load");
        assert_eq!(evidence[0].outcome, "ok");
        assert_eq!(evidence[0].decision_id, "d-1");
        assert_eq!(evidence[0].policy_id, "p-1");
        assert_eq!(evidence[0].cell_kind, CellKind::Extension);
        assert_eq!(evidence[0].region_state, RegionState::Running);
    }

    #[test]
    fn binding_unload_emits_evidence() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(200);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        binding
            .unload_extension("ext-1", &mut cx, CancelReason::OperatorShutdown)
            .unwrap();

        let unload_evidence = binding.evidence_for_event("extension_unload");
        assert_eq!(unload_evidence.len(), 1);
        assert_eq!(unload_evidence[0].outcome, "unload_success");
        assert_eq!(unload_evidence[0].region_state, RegionState::Closed);
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — sessions
    // -----------------------------------------------------------------------

    #[test]
    fn binding_start_session_emits_evidence() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(200);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();

        let sess_id = binding
            .start_session("ext-1", "sess-1", "t-sess-1")
            .unwrap();
        assert_eq!(sess_id, "sess-1");

        let sess_evidence = binding.evidence_for_event("session_start");
        assert_eq!(sess_evidence.len(), 1);
        assert_eq!(sess_evidence[0].decision_id, "d-1");
        assert_eq!(sess_evidence[0].policy_id, "p-1");
        assert_eq!(sess_evidence[0].cell_kind, CellKind::Session);
    }

    #[test]
    fn binding_session_on_nonexistent_extension_fails() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());

        let err = binding
            .start_session("nonexistent", "sess-1", "t")
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_not_found");
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — full lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn binding_full_lifecycle_load_session_unload() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);

        // Load extension
        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();

        // Start sessions
        binding.start_session("ext-1", "sess-1", "t-s1").unwrap();
        binding.start_session("ext-1", "sess-2", "t-s2").unwrap();

        // Execute effects in the extension cell
        binding
            .manager_mut()
            .get_mut("ext-1")
            .unwrap()
            .execute_effect(&mut cx, EffectCategory::Hostcall, "read")
            .unwrap();

        // Unload extension (quiescent close)
        let report = binding
            .unload_extension("ext-1", &mut cx, CancelReason::OperatorShutdown)
            .unwrap();
        assert!(report.success);

        // Verify evidence trace
        assert_eq!(binding.evidence_count(), 4); // load + 2 sessions + unload
        let events: Vec<&str> = binding
            .evidence_log()
            .iter()
            .map(|e| e.event.as_str())
            .collect();
        assert_eq!(
            events,
            vec![
                "extension_load",
                "session_start",
                "session_start",
                "extension_unload"
            ]
        );
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — concurrent extension isolation
    // -----------------------------------------------------------------------

    #[test]
    fn binding_concurrent_extensions_isolated() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        binding
            .load_extension("ext-2", &mut cx, "d-2", "p-2")
            .unwrap();

        // Execute effects in ext-1
        binding
            .manager_mut()
            .get_mut("ext-1")
            .unwrap()
            .execute_effect(&mut cx, EffectCategory::Hostcall, "op1")
            .unwrap();

        // Quarantine ext-1
        let report = binding
            .unload_extension("ext-1", &mut cx, CancelReason::Quarantine)
            .unwrap();
        assert!(report.success);

        // ext-2 is still running, unaffected
        let cell2 = binding.manager().get("ext-2").unwrap();
        assert_eq!(cell2.state(), RegionState::Running);
        assert_eq!(cell2.total_budget_consumed_ms(), 0);

        // Can still execute effects in ext-2
        binding
            .manager_mut()
            .get_mut("ext-2")
            .unwrap()
            .execute_effect(&mut cx, EffectCategory::Hostcall, "op2")
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — timeout escalation with pending obligations
    // -----------------------------------------------------------------------

    #[test]
    fn binding_unload_timeout_escalation() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline { max_ticks: 3 });
        let mut cx = mock_cx(500);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();

        // Register obligation that will never resolve
        binding
            .manager_mut()
            .get_mut("ext-1")
            .unwrap()
            .register_obligation("ob-stuck", "never completes");

        let report = binding
            .unload_extension("ext-1", &mut cx, CancelReason::BudgetExhausted)
            .unwrap();
        assert!(report.drain_timeout_escalated);
        assert_eq!(report.obligations_aborted, 1);

        // Evidence records the escalation
        let unload = &binding.evidence_for_event("extension_unload")[0];
        assert_eq!(
            unload.error_code.as_deref(),
            Some("drain_timeout_escalated")
        );
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — unload all
    // -----------------------------------------------------------------------

    #[test]
    fn binding_unload_all_extensions() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        binding
            .load_extension("ext-2", &mut cx, "d-2", "p-2")
            .unwrap();
        binding
            .load_extension("ext-3", &mut cx, "d-3", "p-3")
            .unwrap();

        let reports = binding.unload_all(&mut cx, CancelReason::OperatorShutdown);
        assert_eq!(reports.len(), 3);
        for r in &reports {
            assert!(r.as_ref().unwrap().success);
        }
        assert_eq!(binding.active_extension_count(), 0);
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — load budget exhausted
    // -----------------------------------------------------------------------

    #[test]
    fn binding_load_budget_exhausted() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(0); // No budget

        let err = binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_budget_exhausted");
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — unload nonexistent
    // -----------------------------------------------------------------------

    #[test]
    fn binding_unload_nonexistent_extension() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(100);

        let err = binding
            .unload_extension("ghost", &mut cx, CancelReason::OperatorShutdown)
            .unwrap_err();
        assert_eq!(err.error_code(), "cell_not_found");
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — deterministic evidence sequence
    // -----------------------------------------------------------------------

    #[test]
    fn binding_deterministic_evidence_sequence() {
        let run = || -> Vec<LifecycleEvidenceEntry> {
            let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
            let mut cx = mock_cx(500);

            binding
                .load_extension("ext-1", &mut cx, "d-1", "p-1")
                .unwrap();
            binding.start_session("ext-1", "sess-1", "t-s1").unwrap();
            binding
                .unload_extension("ext-1", &mut cx, CancelReason::OperatorShutdown)
                .unwrap();
            binding.evidence_log().to_vec()
        };

        let e1 = run();
        let e2 = run();
        assert_eq!(e1, e2);
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — evidence_for_event filter
    // -----------------------------------------------------------------------

    #[test]
    fn binding_evidence_filter_by_event() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        binding
            .load_extension("ext-2", &mut cx, "d-2", "p-2")
            .unwrap();
        binding.start_session("ext-1", "sess-1", "t-s1").unwrap();

        let loads = binding.evidence_for_event("extension_load");
        assert_eq!(loads.len(), 2);

        let sessions = binding.evidence_for_event("session_start");
        assert_eq!(sessions.len(), 1);

        let unloads = binding.evidence_for_event("extension_unload");
        assert_eq!(unloads.len(), 0);
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — evidence sequence numbers are monotonic
    // -----------------------------------------------------------------------

    #[test]
    fn binding_evidence_sequence_monotonic() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        binding.start_session("ext-1", "sess-1", "t-s1").unwrap();
        binding
            .load_extension("ext-2", &mut cx, "d-2", "p-2")
            .unwrap();

        let seqs: Vec<u64> = binding.evidence_log().iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — cancel reason variants in close reports
    // -----------------------------------------------------------------------

    #[test]
    fn binding_close_report_cancel_reasons() {
        let reasons = [
            CancelReason::OperatorShutdown,
            CancelReason::Quarantine,
            CancelReason::Revocation,
            CancelReason::BudgetExhausted,
            CancelReason::ParentClosing,
        ];

        for (i, reason) in reasons.iter().enumerate() {
            let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
            let mut cx = mock_cx(500);

            let ext_id = format!("ext-{i}");
            binding
                .load_extension(&ext_id, &mut cx, "d-1", "p-1")
                .unwrap();
            let report = binding
                .unload_extension(&ext_id, &mut cx, reason.clone())
                .unwrap();
            assert!(report.success);
            assert!(
                !report.close_reason.is_empty(),
                "close_reason should contain the reason"
            );
        }
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — session on closed extension
    // -----------------------------------------------------------------------

    #[test]
    fn binding_session_on_unloaded_extension_fails() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(200);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        binding
            .unload_extension("ext-1", &mut cx, CancelReason::OperatorShutdown)
            .unwrap();

        let err = binding.start_session("ext-1", "sess-1", "t").unwrap_err();
        assert_eq!(err.error_code(), "cell_not_found");
    }

    // -----------------------------------------------------------------------
    // ExtensionHostBinding — multiple sessions per extension
    // -----------------------------------------------------------------------

    // -- Enrichment: std::error --

    #[test]
    fn cell_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(CellError::InvalidState {
                cell_id: "c1".into(),
                current: RegionState::Running,
                attempted: "finalize".into(),
            }),
            Box::new(CellError::BudgetExhausted {
                cell_id: "c2".into(),
                requested_ms: 100,
                remaining_ms: 0,
            }),
            Box::new(CellError::CxThreading {
                cell_id: "c3".into(),
                error_code: "cx_budget_exhausted".into(),
                message: "thread fail".into(),
            }),
            Box::new(CellError::CellNotFound {
                cell_id: "c4".into(),
            }),
            Box::new(CellError::SessionRejected {
                parent_cell_id: "c5".into(),
                reason: "max sessions".into(),
            }),
            Box::new(CellError::ObligationNotFound {
                cell_id: "c6".into(),
                obligation_id: "ob-99".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 variants produce distinct messages"
        );
    }

    #[test]
    fn binding_multiple_sessions_per_extension() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();

        for i in 0..5 {
            binding
                .start_session("ext-1", format!("sess-{i}"), format!("t-s{i}"))
                .unwrap();
        }

        let cell = binding.manager().get("ext-1").unwrap();
        assert_eq!(cell.session_count(), 5);
    }

    // -- Enrichment: CellError error_code exhaustive --

    #[test]
    fn cell_error_error_code_all_variants() {
        let cases: Vec<(CellError, &str)> = vec![
            (
                CellError::InvalidState {
                    cell_id: "c".into(),
                    current: RegionState::Running,
                    attempted: "op".into(),
                },
                "cell_invalid_state",
            ),
            (
                CellError::BudgetExhausted {
                    cell_id: "c".into(),
                    requested_ms: 10,
                    remaining_ms: 0,
                },
                "cell_budget_exhausted",
            ),
            (
                CellError::CxThreading {
                    cell_id: "c".into(),
                    error_code: "e".into(),
                    message: "m".into(),
                },
                "cell_cx_threading",
            ),
            (
                CellError::CellNotFound {
                    cell_id: "c".into(),
                },
                "cell_not_found",
            ),
            (
                CellError::SessionRejected {
                    parent_cell_id: "c".into(),
                    reason: "r".into(),
                },
                "cell_session_rejected",
            ),
            (
                CellError::ObligationNotFound {
                    cell_id: "c".into(),
                    obligation_id: "ob".into(),
                },
                "cell_obligation_not_found",
            ),
        ];
        for (err, expected_code) in &cases {
            assert_eq!(err.error_code(), *expected_code);
        }
    }

    // -- Enrichment: CellError Display format verification --

    #[test]
    fn cell_error_display_format_contains_cell_id() {
        let err = CellError::BudgetExhausted {
            cell_id: "my-cell-42".into(),
            requested_ms: 50,
            remaining_ms: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("my-cell-42"));
        assert!(msg.contains("50"));
        assert!(msg.contains("3"));

        let err2 = CellError::CxThreading {
            cell_id: "cx-cell".into(),
            error_code: "EBUDGET".into(),
            message: "out of budget".into(),
        };
        let msg2 = err2.to_string();
        assert!(msg2.contains("cx-cell"));
        assert!(msg2.contains("EBUDGET"));
        assert!(msg2.contains("out of budget"));
    }

    // -- Enrichment: CellKind Hash distinct --

    #[test]
    fn cell_kind_hash_distinct() {
        use std::collections::BTreeSet;
        let kinds = [CellKind::Extension, CellKind::Session, CellKind::Delegate];
        let set: BTreeSet<CellKind> = kinds.iter().copied().collect();
        assert_eq!(set.len(), 3);
    }

    // -- Enrichment: CellManager archive_cell --

    #[test]
    fn manager_archive_cell_moves_to_closed() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-1", "t1");
        assert_eq!(mgr.active_count(), 1);

        let result = FinalizeResult {
            region_id: "ext-1".into(),
            success: true,
            obligations_committed: 0,
            obligations_aborted: 0,
            drain_timeout_escalated: false,
        };
        mgr.archive_cell("ext-1", result);
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.closed_count(), 1);
        assert!(mgr.get("ext-1").is_none());
    }

    // -- Enrichment: CellManager insert_cell --

    #[test]
    fn manager_insert_cell_registers_pre_created() {
        let mut mgr = CellManager::new();
        let cell = ExecutionCell::with_context("custom-1", CellKind::Delegate, "t", "d", "p");
        mgr.insert_cell("custom-1", cell);

        assert_eq!(mgr.active_count(), 1);
        let retrieved = mgr.get("custom-1").unwrap();
        assert_eq!(retrieved.kind(), CellKind::Delegate);
        assert_eq!(retrieved.decision_id(), "d");
    }

    // -- Enrichment: CellManager create_delegate_cell kind --

    #[test]
    fn manager_delegate_cell_has_delegate_kind() {
        let mut mgr = CellManager::new();
        mgr.create_delegate_cell("del-1", "t1");
        let cell = mgr.get("del-1").unwrap();
        assert_eq!(cell.kind(), CellKind::Delegate);
        assert_eq!(cell.state(), RegionState::Running);
    }

    // -- Enrichment: CellManager active_cell_ids sorted --

    #[test]
    fn manager_active_cell_ids_sorted() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("zz-last", "t1");
        mgr.create_extension_cell("aa-first", "t2");
        mgr.create_extension_cell("mm-middle", "t3");

        let ids = mgr.active_cell_ids();
        assert_eq!(ids, vec!["aa-first", "mm-middle", "zz-last"]);
    }

    // -- Enrichment: drain_events empties buffer --

    #[test]
    fn drain_events_empties_cell_event_buffer() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let mut cx = mock_cx(100);

        cell.execute_effect(&mut cx, EffectCategory::Hostcall, "op1")
            .unwrap();
        assert_eq!(cell.events().len(), 1);

        let drained = cell.drain_events();
        assert_eq!(drained.len(), 1);
        assert!(cell.events().is_empty());
    }

    // -- Enrichment: session executes effects independently --

    #[test]
    fn session_cell_executes_effects_independently() {
        let mut parent =
            ExecutionCell::with_context("ext-1", CellKind::Extension, "t-parent", "d-1", "p-1");
        let mut session = parent.create_session("sess-1", "t-sess").unwrap();
        let mut cx = mock_cx(100);

        let seq = session
            .execute_effect(&mut cx, EffectCategory::Hostcall, "sess_op")
            .unwrap();
        assert_eq!(seq, 1);
        assert_eq!(session.total_budget_consumed_ms(), 1);
        assert_eq!(session.effect_log().len(), 1);

        // Parent is unaffected
        assert_eq!(parent.total_budget_consumed_ms(), 0);
        assert_eq!(parent.effect_log().len(), 0);
    }

    // -- Enrichment: LifecycleEvidenceEntry with error_code --

    #[test]
    fn lifecycle_evidence_entry_serde_with_error_code() {
        let entry = LifecycleEvidenceEntry {
            sequence: 5,
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "extension_host_binding".into(),
            event: "extension_unload".into(),
            outcome: "unload_with_pending".into(),
            error_code: Some("drain_timeout_escalated".into()),
            cell_id: "ext-1".into(),
            cell_kind: CellKind::Extension,
            region_state: RegionState::Closed,
            budget_consumed_ms: 2,
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: LifecycleEvidenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
        assert_eq!(
            restored.error_code.as_deref(),
            Some("drain_timeout_escalated")
        );
    }

    // -- Enrichment: LifecycleEvidenceEntry with metadata --

    #[test]
    fn lifecycle_evidence_entry_serde_with_metadata() {
        let mut metadata = BTreeMap::new();
        metadata.insert("extension_version".to_string(), "1.2.3".to_string());
        metadata.insert("publisher".to_string(), "acme-corp".to_string());

        let entry = LifecycleEvidenceEntry {
            sequence: 0,
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "extension_host_binding".into(),
            event: "extension_load".into(),
            outcome: "ok".into(),
            error_code: None,
            cell_id: "ext-1".into(),
            cell_kind: CellKind::Extension,
            region_state: RegionState::Running,
            budget_consumed_ms: 2,
            metadata,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: LifecycleEvidenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
        assert_eq!(restored.metadata.len(), 2);
        assert_eq!(restored.metadata["publisher"], "acme-corp");
    }

    // -- Enrichment: binding evidence_count matches log length --

    #[test]
    fn binding_evidence_count_matches_log_length() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);

        assert_eq!(binding.evidence_count(), 0);
        assert_eq!(binding.evidence_log().len(), 0);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        assert_eq!(binding.evidence_count(), 1);
        assert_eq!(
            binding.evidence_log().len() as u64,
            binding.evidence_count()
        );

        binding.start_session("ext-1", "sess-1", "t-s1").unwrap();
        assert_eq!(binding.evidence_count(), 2);
        assert_eq!(
            binding.evidence_log().len() as u64,
            binding.evidence_count()
        );
    }

    // -- Enrichment: abort_obligation not found --

    #[test]
    fn abort_obligation_not_found_error() {
        let mut cell = ExecutionCell::new("ext-1", CellKind::Extension, "t");
        let err = cell.abort_obligation("ghost-ob").unwrap_err();
        assert_eq!(err.error_code(), "cell_obligation_not_found");
        assert!(err.to_string().contains("ghost-ob"));
    }

    // -- Enrichment: CellCloseReport field access --

    #[test]
    fn cell_close_report_timeout_escalation_fields() {
        let report = CellCloseReport {
            cell_id: "ext-timeout".into(),
            cell_kind: CellKind::Extension,
            close_reason: "BudgetExhausted".into(),
            success: true,
            obligations_committed: 3,
            obligations_aborted: 2,
            drain_timeout_escalated: true,
            budget_consumed_ms: 42,
            evidence_entries_emitted: 1,
        };
        assert!(report.drain_timeout_escalated);
        assert_eq!(report.obligations_aborted, 2);
        assert_eq!(report.obligations_committed, 3);
        assert_eq!(report.budget_consumed_ms, 42);

        // Serde preserves all fields
        let json = serde_json::to_string(&report).unwrap();
        let restored: CellCloseReport = serde_json::from_str(&json).unwrap();
        assert!(restored.drain_timeout_escalated);
        assert_eq!(restored.close_reason, "BudgetExhausted");
    }

    // -- Enrichment: session close report via binding --

    #[test]
    fn binding_load_duplicate_extension_overwrites() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);

        binding
            .load_extension("ext-1", &mut cx, "d-1", "p-1")
            .unwrap();
        // Loading again with same ID overwrites
        binding
            .load_extension("ext-1", &mut cx, "d-2", "p-2")
            .unwrap();

        let cell = binding.manager().get("ext-1").unwrap();
        assert_eq!(cell.decision_id(), "d-2");
        assert_eq!(cell.policy_id(), "p-2");
    }

    // -- Enrichment: PearlTower 2026-02-26 session 7 --

    #[test]
    fn delegate_cell_trace_id_propagated() {
        let mut mgr = CellManager::new();
        let cell = mgr.create_delegate_cell("del-1", "trace-del");
        assert_eq!(cell.trace_id(), "trace-del");
        assert_eq!(cell.kind(), CellKind::Delegate);
        assert_eq!(cell.cell_id(), "del-1");
    }

    #[test]
    fn closed_results_contain_finalize_result_details() {
        let mut mgr = CellManager::new();
        mgr.create_extension_cell("ext-close", "t-close");
        let mut cx = mock_cx(200);
        let result = mgr
            .close_cell(
                "ext-close",
                &mut cx,
                CancelReason::OperatorShutdown,
                DrainDeadline::default(),
            )
            .unwrap();
        assert!(result.success);

        let closed = mgr.closed_results();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].0, "ext-close");
        assert!(closed[0].1.success);
    }

    #[test]
    fn with_context_propagates_all_fields() {
        let cell = ExecutionCell::with_context(
            "ctx-cell",
            CellKind::Session,
            "trace-ctx",
            "decision-ctx",
            "policy-ctx",
        );
        assert_eq!(cell.cell_id(), "ctx-cell");
        assert_eq!(cell.kind(), CellKind::Session);
        assert_eq!(cell.trace_id(), "trace-ctx");
        assert_eq!(cell.decision_id(), "decision-ctx");
        assert_eq!(cell.policy_id(), "policy-ctx");
        assert_eq!(cell.state(), RegionState::Running);
    }

    #[test]
    fn effect_log_accumulates_multiple_categories() {
        let mut cell = ExecutionCell::new("ext-el", CellKind::Extension, "t-el");
        let mut cx = mock_cx(500);

        cell.execute_effect(&mut cx, EffectCategory::Hostcall, "op-hc")
            .unwrap();
        cell.execute_effect(&mut cx, EffectCategory::PolicyCheck, "op-pc")
            .unwrap();
        cell.execute_effect(&mut cx, EffectCategory::TelemetryEmit, "op-te")
            .unwrap();

        let log = cell.effect_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].category, EffectCategory::Hostcall);
        assert_eq!(log[1].category, EffectCategory::PolicyCheck);
        assert_eq!(log[2].category, EffectCategory::TelemetryEmit);
        assert_eq!(log[0].operation, "op-hc");
        assert_eq!(log[1].operation, "op-pc");
        assert_eq!(log[2].operation, "op-te");
    }

    #[test]
    fn cell_kind_display_delegate() {
        assert_eq!(CellKind::Delegate.to_string(), "delegate");
    }

    #[test]
    fn cell_event_fields_carry_cell_kind_and_state() {
        let mut cell = ExecutionCell::with_context("ev-cell", CellKind::Extension, "t", "d", "p");
        let mut cx = mock_cx(200);
        cell.execute_effect(&mut cx, EffectCategory::Hostcall, "some-op")
            .unwrap();

        let events = cell.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].cell_kind, CellKind::Extension);
        assert_eq!(events[0].region_state, RegionState::Running);
        assert_eq!(events[0].decision_id, "d");
        assert_eq!(events[0].policy_id, "p");
        assert!(events[0].budget_consumed_ms > 0);
    }

    #[test]
    fn binding_evidence_entries_have_correct_cell_kind() {
        let mut binding = ExtensionHostBinding::new(DrainDeadline::default());
        let mut cx = mock_cx(500);
        binding
            .load_extension("ext-kind", &mut cx, "d", "p")
            .unwrap();

        let evidence = binding.evidence_log();
        assert!(!evidence.is_empty());
        assert_eq!(evidence[0].cell_kind, CellKind::Extension);
        assert_eq!(evidence[0].event, "extension_load");
    }

    #[test]
    fn create_session_inherits_parent_context() {
        let mut parent =
            ExecutionCell::with_context("ext-p", CellKind::Extension, "t-p", "d-p", "p-p");
        let session = parent.create_session("sess-1", "t-sess").unwrap();
        assert_eq!(session.kind(), CellKind::Session);
        assert_eq!(session.decision_id(), "d-p");
        assert_eq!(session.policy_id(), "p-p");
        assert_eq!(session.trace_id(), "t-sess");
        assert_eq!(parent.session_count(), 1);
    }
}
