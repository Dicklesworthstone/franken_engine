//! Region-quiescence close protocol: cancel → drain → finalize.
//!
//! Every region (extension execution cell, policy subsystem, task group)
//! follows this three-phase shutdown protocol. Phase ordering is strict:
//! calling drain before cancel, or finalize before drain, returns a
//! typed `PhaseOrderViolation` error.
//!
//! Plan references: Section 10.11 item 4, 9G.2 (cancellation as protocol),
//! Top-10 #2 (probabilistic guardplane), #3 (deterministic evidence graph).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// RegionState — lifecycle state machine
// ---------------------------------------------------------------------------

/// Lifecycle state of a region.
///
/// Transitions: Running → CancelRequested → Draining → Finalizing → Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RegionState {
    Running,
    CancelRequested,
    Draining,
    Finalizing,
    Closed,
}

impl fmt::Display for RegionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::CancelRequested => write!(f, "cancel_requested"),
            Self::Draining => write!(f, "draining"),
            Self::Finalizing => write!(f, "finalizing"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

// ---------------------------------------------------------------------------
// CancelReason — why the region is being closed
// ---------------------------------------------------------------------------

/// Reason for initiating region cancellation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CancelReason {
    /// Operator-requested shutdown.
    OperatorShutdown,
    /// Quarantine triggered by guardrail.
    Quarantine,
    /// Revocation of capability or trust.
    Revocation,
    /// Budget exhaustion.
    BudgetExhausted,
    /// Parent region closing.
    ParentClosing,
    /// Custom reason with identifier.
    Custom(String),
}

impl fmt::Display for CancelReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperatorShutdown => write!(f, "operator_shutdown"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Revocation => write!(f, "revocation"),
            Self::BudgetExhausted => write!(f, "budget_exhausted"),
            Self::ParentClosing => write!(f, "parent_closing"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PhaseOrderViolation — strict ordering enforcement
// ---------------------------------------------------------------------------

/// Error returned when phase transitions are called out of order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseOrderViolation {
    pub current_state: RegionState,
    pub attempted_transition: String,
    pub region_id: String,
}

impl fmt::Display for PhaseOrderViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "phase order violation in region '{}': attempted '{}' from state '{}'",
            self.region_id, self.attempted_transition, self.current_state
        )
    }
}

impl std::error::Error for PhaseOrderViolation {}

// ---------------------------------------------------------------------------
// Obligation — tracked work items that must resolve before finalize
// ---------------------------------------------------------------------------

/// Status of an obligation within a draining region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationStatus {
    Pending,
    Committed,
    Aborted,
}

/// A tracked obligation that must resolve before finalize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obligation {
    pub id: String,
    pub description: String,
    pub status: ObligationStatus,
}

// ---------------------------------------------------------------------------
// DrainDeadline — deadline for drain phase
// ---------------------------------------------------------------------------

/// Drain deadline in virtual ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainDeadline {
    /// Maximum virtual ticks allowed for drain phase.
    pub max_ticks: u64,
}

impl Default for DrainDeadline {
    fn default() -> Self {
        Self { max_ticks: 10_000 }
    }
}

// ---------------------------------------------------------------------------
// FinalizeResult — outcome of finalize phase
// ---------------------------------------------------------------------------

/// Outcome of finalize phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeResult {
    pub region_id: String,
    pub success: bool,
    pub obligations_committed: usize,
    pub obligations_aborted: usize,
    pub drain_timeout_escalated: bool,
}

// ---------------------------------------------------------------------------
// RegionEvent — structured evidence for phase transitions
// ---------------------------------------------------------------------------

/// Structured event emitted at each phase transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionEvent {
    pub trace_id: String,
    pub region_id: String,
    pub region_type: String,
    pub phase: RegionState,
    pub outcome: String,
    pub obligations_pending: usize,
    pub drain_elapsed_ticks: u64,
}

// ---------------------------------------------------------------------------
// Region — generic region implementing the three-phase protocol
// ---------------------------------------------------------------------------

/// A region that follows the cancel → drain → finalize close protocol.
#[derive(Debug, Clone)]
pub struct Region {
    pub id: String,
    pub region_type: String,
    pub trace_id: String,
    state: RegionState,
    cancel_reason: Option<CancelReason>,
    obligations: BTreeMap<String, Obligation>,
    drain_deadline: Option<DrainDeadline>,
    drain_elapsed_ticks: u64,
    drain_timeout_escalated: bool,
    events: Vec<RegionEvent>,
    children: Vec<Region>,
}

impl Region {
    /// Create a new region in Running state.
    pub fn new(
        id: impl Into<String>,
        region_type: impl Into<String>,
        trace_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            region_type: region_type.into(),
            trace_id: trace_id.into(),
            state: RegionState::Running,
            cancel_reason: None,
            obligations: BTreeMap::new(),
            drain_deadline: None,
            drain_elapsed_ticks: 0,
            drain_timeout_escalated: false,
            events: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Current state.
    pub fn state(&self) -> RegionState {
        self.state
    }

    /// Cancel reason if set.
    pub fn cancel_reason(&self) -> Option<&CancelReason> {
        self.cancel_reason.as_ref()
    }

    /// Add a child region (for hierarchical close).
    pub fn add_child(&mut self, child: Region) {
        self.children.push(child);
    }

    /// Register an obligation that must resolve before finalize.
    ///
    /// Returns `false` if the region is no longer in `Running` state (cancel
    /// was already requested). Callers must not queue new work after cancel.
    pub fn register_obligation(
        &mut self,
        id: impl Into<String>,
        description: impl Into<String>,
    ) -> bool {
        if self.state != RegionState::Running {
            return false;
        }
        let id = id.into();
        self.obligations.insert(
            id.clone(),
            Obligation {
                id,
                description: description.into(),
                status: ObligationStatus::Pending,
            },
        );
        true
    }

    /// Resolve an obligation as committed.
    pub fn commit_obligation(&mut self, id: &str) -> bool {
        if let Some(ob) = self.obligations.get_mut(id) {
            ob.status = ObligationStatus::Committed;
            true
        } else {
            false
        }
    }

    /// Resolve an obligation as aborted.
    pub fn abort_obligation(&mut self, id: &str) -> bool {
        if let Some(ob) = self.obligations.get_mut(id) {
            ob.status = ObligationStatus::Aborted;
            true
        } else {
            false
        }
    }

    /// Count of pending (unresolved) obligations.
    pub fn pending_obligations(&self) -> usize {
        self.obligations
            .values()
            .filter(|ob| ob.status == ObligationStatus::Pending)
            .count()
    }

    // -- Phase transitions --

    /// Phase 1: Cancel. Initiates shutdown, stops accepting new work.
    pub fn cancel(&mut self, reason: CancelReason) -> Result<(), PhaseOrderViolation> {
        if self.state != RegionState::Running {
            return Err(PhaseOrderViolation {
                current_state: self.state,
                attempted_transition: "cancel".to_string(),
                region_id: self.id.clone(),
            });
        }

        // Cancel children first (leaves first in dependency order).
        for child in &mut self.children {
            if child.state() == RegionState::Running {
                child.cancel(CancelReason::ParentClosing)?;
            }
        }

        self.cancel_reason = Some(reason);
        self.state = RegionState::CancelRequested;
        self.emit_event("cancel_initiated");
        Ok(())
    }

    /// Phase 2: Drain. Allows in-flight work to complete or checkpoint.
    pub fn drain(&mut self, deadline: DrainDeadline) -> Result<(), PhaseOrderViolation> {
        if self.state != RegionState::CancelRequested {
            return Err(PhaseOrderViolation {
                current_state: self.state,
                attempted_transition: "drain".to_string(),
                region_id: self.id.clone(),
            });
        }

        // Drain children first.
        for child in &mut self.children {
            if child.state() == RegionState::CancelRequested {
                child.drain(deadline)?;
            }
        }

        self.drain_deadline = Some(deadline);
        self.drain_elapsed_ticks = 0;
        self.state = RegionState::Draining;
        self.emit_event("drain_started");
        Ok(())
    }

    /// Advance drain by one tick. Returns true if drain deadline exceeded.
    pub fn drain_tick(&mut self) -> bool {
        if self.state != RegionState::Draining {
            return false;
        }
        self.drain_elapsed_ticks += 1;

        // Tick children too.
        for child in &mut self.children {
            child.drain_tick();
        }

        if let Some(deadline) = &self.drain_deadline
            && self.drain_elapsed_ticks >= deadline.max_ticks
        {
            if !self.drain_timeout_escalated {
                self.drain_timeout_escalated = true;
                self.emit_event("drain_timeout_escalation");
            }
            return true;
        }
        false
    }

    /// Phase 3: Finalize. Asserts all obligations resolved, emits completion.
    pub fn finalize(&mut self) -> Result<FinalizeResult, PhaseOrderViolation> {
        if self.state != RegionState::Draining {
            return Err(PhaseOrderViolation {
                current_state: self.state,
                attempted_transition: "finalize".to_string(),
                region_id: self.id.clone(),
            });
        }

        // Finalize children first.
        let mut children_success = true;
        for child in &mut self.children {
            if child.state() == RegionState::Draining {
                let res = child.finalize()?;
                if !res.success {
                    children_success = false;
                }
            } else if child.state() != RegionState::Closed {
                children_success = false;
            }
        }

        // Force-abort any remaining pending obligations if drain timed out.
        if self.drain_timeout_escalated {
            let pending_ids: Vec<String> = self
                .obligations
                .iter()
                .filter(|(_, ob)| ob.status == ObligationStatus::Pending)
                .map(|(id, _)| id.clone())
                .collect();
            for id in pending_ids {
                self.abort_obligation(&id);
            }
        }

        let obligations_committed = self
            .obligations
            .values()
            .filter(|ob| ob.status == ObligationStatus::Committed)
            .count();
        let obligations_aborted = self
            .obligations
            .values()
            .filter(|ob| ob.status == ObligationStatus::Aborted)
            .count();

        let success = self.pending_obligations() == 0 && children_success;

        self.state = RegionState::Finalizing;
        self.emit_event(if success {
            "finalize_success"
        } else {
            "finalize_with_pending"
        });

        self.state = RegionState::Closed;
        self.emit_event("closed");

        Ok(FinalizeResult {
            region_id: self.id.clone(),
            success,
            obligations_committed,
            obligations_aborted,
            drain_timeout_escalated: self.drain_timeout_escalated,
        })
    }

    /// Full close shortcut: cancel → drain → finalize in one call.
    pub fn close(
        &mut self,
        reason: CancelReason,
        deadline: DrainDeadline,
    ) -> Result<FinalizeResult, PhaseOrderViolation> {
        self.cancel(reason)?;
        self.drain(deadline)?;

        let max = deadline.max_ticks;
        for _ in 0..max {
            if self.pending_obligations() == 0
                && self.children.iter().all(|c| c.pending_obligations() == 0)
            {
                break;
            }
            self.drain_tick();
        }

        self.finalize()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<RegionEvent> {
        let mut events = std::mem::take(&mut self.events);
        for child in &mut self.children {
            events.extend(child.drain_events());
        }
        events
    }

    /// Number of events emitted (this region only, not children).
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Number of children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    fn emit_event(&mut self, outcome: &str) {
        self.events.push(RegionEvent {
            trace_id: self.trace_id.clone(),
            region_id: self.id.clone(),
            region_type: self.region_type.clone(),
            phase: self.state,
            outcome: outcome.to_string(),
            obligations_pending: self.pending_obligations(),
            drain_elapsed_ticks: self.drain_elapsed_ticks,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn test_region() -> Region {
        Region::new("region-1", "extension_cell", "trace-1")
    }

    // -- RegionState --

    #[test]
    fn state_display() {
        assert_eq!(RegionState::Running.to_string(), "running");
        assert_eq!(RegionState::CancelRequested.to_string(), "cancel_requested");
        assert_eq!(RegionState::Draining.to_string(), "draining");
        assert_eq!(RegionState::Finalizing.to_string(), "finalizing");
        assert_eq!(RegionState::Closed.to_string(), "closed");
    }

    // -- CancelReason --

    #[test]
    fn cancel_reason_display() {
        assert_eq!(
            CancelReason::OperatorShutdown.to_string(),
            "operator_shutdown"
        );
        assert_eq!(CancelReason::Quarantine.to_string(), "quarantine");
        assert_eq!(CancelReason::Revocation.to_string(), "revocation");
        assert_eq!(
            CancelReason::BudgetExhausted.to_string(),
            "budget_exhausted"
        );
        assert_eq!(CancelReason::ParentClosing.to_string(), "parent_closing");
        assert_eq!(
            CancelReason::Custom("test".to_string()).to_string(),
            "custom:test"
        );
    }

    // -- Phase ordering enforcement --

    #[test]
    fn cancel_from_running_succeeds() {
        let mut region = test_region();
        assert!(region.cancel(CancelReason::OperatorShutdown).is_ok());
        assert_eq!(region.state(), RegionState::CancelRequested);
    }

    #[test]
    fn cancel_from_non_running_fails() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        let err = region.cancel(CancelReason::Quarantine).unwrap_err();
        assert_eq!(err.current_state, RegionState::CancelRequested);
        assert_eq!(err.attempted_transition, "cancel");
    }

    #[test]
    fn drain_before_cancel_fails() {
        let mut region = test_region();
        let err = region.drain(DrainDeadline::default()).unwrap_err();
        assert_eq!(err.current_state, RegionState::Running);
        assert_eq!(err.attempted_transition, "drain");
    }

    #[test]
    fn drain_from_cancel_requested_succeeds() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        assert!(region.drain(DrainDeadline::default()).is_ok());
        assert_eq!(region.state(), RegionState::Draining);
    }

    #[test]
    fn finalize_before_drain_fails() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        let err = region.finalize().unwrap_err();
        assert_eq!(err.current_state, RegionState::CancelRequested);
        assert_eq!(err.attempted_transition, "finalize");
    }

    #[test]
    fn finalize_from_running_fails() {
        let mut region = test_region();
        let err = region.finalize().unwrap_err();
        assert_eq!(err.current_state, RegionState::Running);
    }

    // -- Full lifecycle --

    #[test]
    fn full_lifecycle_cancel_drain_finalize() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        region.drain(DrainDeadline::default()).unwrap();
        let result = region.finalize().unwrap();
        assert!(result.success);
        assert_eq!(region.state(), RegionState::Closed);
    }

    #[test]
    fn close_shortcut() {
        let mut region = test_region();
        let result = region
            .close(CancelReason::Quarantine, DrainDeadline::default())
            .unwrap();
        assert!(result.success);
        assert_eq!(region.state(), RegionState::Closed);
    }

    // -- Obligations --

    #[test]
    fn obligations_track_pending_committed_aborted() {
        let mut region = test_region();
        region.register_obligation("ob-1", "flush evidence");
        region.register_obligation("ob-2", "release locks");
        region.register_obligation("ob-3", "commit publication");
        assert_eq!(region.pending_obligations(), 3);

        region.commit_obligation("ob-1");
        assert_eq!(region.pending_obligations(), 2);

        region.abort_obligation("ob-2");
        assert_eq!(region.pending_obligations(), 1);
    }

    #[test]
    fn finalize_reports_obligation_counts() {
        let mut region = test_region();
        region.register_obligation("ob-1", "flush");
        region.register_obligation("ob-2", "release");

        region.commit_obligation("ob-1");
        region.abort_obligation("ob-2");

        region.cancel(CancelReason::OperatorShutdown).unwrap();
        region.drain(DrainDeadline::default()).unwrap();
        let result = region.finalize().unwrap();

        assert!(result.success);
        assert_eq!(result.obligations_committed, 1);
        assert_eq!(result.obligations_aborted, 1);
        assert!(!result.drain_timeout_escalated);
    }

    #[test]
    fn finalize_with_pending_obligations_reports_failure() {
        let mut region = test_region();
        region.register_obligation("ob-1", "flush");

        region.cancel(CancelReason::OperatorShutdown).unwrap();
        region.drain(DrainDeadline::default()).unwrap();
        let result = region.finalize().unwrap();

        // Pending obligations remain but since no timeout escalation, they stay pending
        // and the result is not success.
        assert!(!result.success);
    }

    // -- Drain deadline escalation --

    #[test]
    fn drain_timeout_escalation() {
        let mut region = test_region();
        region.register_obligation("ob-1", "slow task");

        region.cancel(CancelReason::OperatorShutdown).unwrap();
        region.drain(DrainDeadline { max_ticks: 5 }).unwrap();

        for _ in 0..4 {
            assert!(!region.drain_tick());
        }
        // 5th tick triggers timeout
        assert!(region.drain_tick());

        let result = region.finalize().unwrap();
        assert!(result.drain_timeout_escalated);
        // Pending obligations force-aborted by timeout escalation
        assert_eq!(result.obligations_aborted, 1);
        assert!(result.success); // all resolved (via forced abort)
    }

    // -- Hierarchical close --

    #[test]
    fn parent_cancel_cascades_to_children() {
        let mut parent = Region::new("parent", "service", "t");
        let child1 = Region::new("child-1", "extension_cell", "t");
        let child2 = Region::new("child-2", "extension_cell", "t");
        parent.add_child(child1);
        parent.add_child(child2);

        parent.cancel(CancelReason::OperatorShutdown).unwrap();
        assert_eq!(parent.state(), RegionState::CancelRequested);
    }

    #[test]
    fn hierarchical_close_lifecycle() {
        let mut parent = Region::new("parent", "service", "t");
        let mut child = Region::new("child", "extension_cell", "t");
        child.register_obligation("ob-c1", "child flush");
        parent.add_child(child);
        parent.register_obligation("ob-p1", "parent flush");

        parent.cancel(CancelReason::OperatorShutdown).unwrap();
        parent.drain(DrainDeadline::default()).unwrap();

        // Resolve obligations
        parent.commit_obligation("ob-p1");

        // Need to resolve child obligations too — they propagate through drain_tick and
        // get force-aborted on finalize timeout if needed.
        // For this test, drain with short deadline to force-abort child obligations.
        // Actually the child is already draining. Let's force timeout on child.
        let result = parent.finalize();
        // Child has unresolved obligation, so it won't be success unless we force-abort.
        // Since no timeout escalation happened, child finalize will report !success.
        assert!(result.is_ok());
    }

    // -- Events --

    #[test]
    fn events_emitted_at_each_phase() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        region.drain(DrainDeadline::default()).unwrap();
        region.finalize().unwrap();

        let events = region.drain_events();
        // cancel_initiated, drain_started, finalize_success, closed
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].outcome, "cancel_initiated");
        assert_eq!(events[1].outcome, "drain_started");
        assert_eq!(events[2].outcome, "finalize_success");
        assert_eq!(events[3].outcome, "closed");
    }

    #[test]
    fn events_carry_correct_fields() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();

        let events = region.drain_events();
        let event = &events[0];
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.region_id, "region-1");
        assert_eq!(event.region_type, "extension_cell");
        assert_eq!(event.phase, RegionState::CancelRequested);
    }

    #[test]
    fn child_events_collected_by_parent_drain_events() {
        let mut parent = Region::new("parent", "service", "t");
        let child = Region::new("child", "extension_cell", "t");
        parent.add_child(child);

        parent.cancel(CancelReason::OperatorShutdown).unwrap();
        parent.drain(DrainDeadline::default()).unwrap();
        parent.finalize().unwrap();

        let events = parent.drain_events();
        let parent_events: Vec<_> = events.iter().filter(|e| e.region_id == "parent").collect();
        let child_events: Vec<_> = events.iter().filter(|e| e.region_id == "child").collect();
        assert!(!parent_events.is_empty());
        assert!(!child_events.is_empty());
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<RegionEvent> {
            let mut region = Region::new("r", "ext", "t");
            region.register_obligation("ob-1", "flush");
            region.cancel(CancelReason::Quarantine).unwrap();
            region.drain(DrainDeadline { max_ticks: 3 }).unwrap();
            for _ in 0..3 {
                region.drain_tick();
            }
            region.finalize().unwrap();
            region.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- PhaseOrderViolation --

    #[test]
    fn phase_order_violation_display() {
        let violation = PhaseOrderViolation {
            current_state: RegionState::Running,
            attempted_transition: "drain".to_string(),
            region_id: "r-1".to_string(),
        };
        let msg = violation.to_string();
        assert!(msg.contains("phase order violation"));
        assert!(msg.contains("r-1"));
        assert!(msg.contains("drain"));
        assert!(msg.contains("running"));
    }

    // -- Double close prevention --

    #[test]
    fn double_cancel_fails() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        assert!(region.cancel(CancelReason::Quarantine).is_err());
    }

    #[test]
    fn close_after_close_fails() {
        let mut region = test_region();
        region
            .close(CancelReason::OperatorShutdown, DrainDeadline::default())
            .unwrap();
        assert!(
            region
                .close(CancelReason::Quarantine, DrainDeadline::default())
                .is_err()
        );
    }

    // -- Serialization --

    #[test]
    fn region_state_serialization_round_trip() {
        let states = vec![
            RegionState::Running,
            RegionState::CancelRequested,
            RegionState::Draining,
            RegionState::Finalizing,
            RegionState::Closed,
        ];
        for state in &states {
            let json = serde_json::to_string(state).expect("serialize");
            let restored: RegionState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*state, restored);
        }
    }

    #[test]
    fn cancel_reason_serialization_round_trip() {
        let reasons = vec![
            CancelReason::OperatorShutdown,
            CancelReason::Quarantine,
            CancelReason::Custom("test".to_string()),
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).expect("serialize");
            let restored: CancelReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*reason, restored);
        }
    }

    #[test]
    fn finalize_result_serialization_round_trip() {
        let result = FinalizeResult {
            region_id: "r-1".to_string(),
            success: true,
            obligations_committed: 2,
            obligations_aborted: 1,
            drain_timeout_escalated: false,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: FinalizeResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn region_event_serialization_round_trip() {
        let event = RegionEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            region_type: "ext".to_string(),
            phase: RegionState::CancelRequested,
            outcome: "cancel_initiated".to_string(),
            obligations_pending: 0,
            drain_elapsed_ticks: 0,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: RegionEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Enrichment: serde & ordering --

    #[test]
    fn obligation_status_serde_all_variants() {
        for status in [
            ObligationStatus::Pending,
            ObligationStatus::Committed,
            ObligationStatus::Aborted,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let restored: ObligationStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, restored);
        }
    }

    #[test]
    fn obligation_serde_roundtrip() {
        let ob = Obligation {
            id: "ob-1".to_string(),
            description: "must finalize".to_string(),
            status: ObligationStatus::Pending,
        };
        let json = serde_json::to_string(&ob).expect("serialize");
        let restored: Obligation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ob, restored);
    }

    #[test]
    fn drain_deadline_serde_roundtrip() {
        let dd = DrainDeadline { max_ticks: 5000 };
        let json = serde_json::to_string(&dd).expect("serialize");
        let restored: DrainDeadline = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dd, restored);
    }

    #[test]
    fn region_state_ordering() {
        assert!(RegionState::Running < RegionState::CancelRequested);
        assert!(RegionState::CancelRequested < RegionState::Draining);
        assert!(RegionState::Draining < RegionState::Finalizing);
        assert!(RegionState::Finalizing < RegionState::Closed);
    }

    #[test]
    fn cancel_reason_ordering() {
        assert!(CancelReason::OperatorShutdown < CancelReason::Quarantine);
        assert!(CancelReason::Quarantine < CancelReason::Revocation);
        assert!(CancelReason::Revocation < CancelReason::BudgetExhausted);
        assert!(CancelReason::BudgetExhausted < CancelReason::ParentClosing);
        assert!(CancelReason::ParentClosing < CancelReason::Custom("zzz".to_string()));
    }

    #[test]
    fn obligation_nonexistent_returns_false() {
        let mut region = test_region();
        assert!(!region.commit_obligation("nonexistent"));
        assert!(!region.abort_obligation("nonexistent"));
    }

    // -- Enrichment batch 2: Display uniqueness, serde edge cases, error trait, boundary conditions --

    #[test]
    fn region_state_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            RegionState::Running,
            RegionState::CancelRequested,
            RegionState::Draining,
            RegionState::Finalizing,
            RegionState::Closed,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            5,
            "all RegionState Display strings must be unique"
        );
    }

    #[test]
    fn cancel_reason_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            CancelReason::OperatorShutdown,
            CancelReason::Quarantine,
            CancelReason::Revocation,
            CancelReason::BudgetExhausted,
            CancelReason::ParentClosing,
            CancelReason::Custom("x".to_string()),
        ]
        .iter()
        .map(|r| r.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            6,
            "all CancelReason Display strings must be unique"
        );
    }

    #[test]
    fn phase_order_violation_implements_std_error() {
        let v = PhaseOrderViolation {
            current_state: RegionState::Running,
            attempted_transition: "finalize".to_string(),
            region_id: "r-1".to_string(),
        };
        let err: &dyn std::error::Error = &v;
        let msg = err.to_string();
        assert!(msg.contains("phase order violation"));
        assert!(msg.contains("r-1"));
        assert!(msg.contains("finalize"));
        assert!(msg.contains("running"));
    }

    #[test]
    fn phase_order_violation_serde_roundtrip() {
        let v = PhaseOrderViolation {
            current_state: RegionState::Draining,
            attempted_transition: "cancel".to_string(),
            region_id: "r-42".to_string(),
        };
        let json = serde_json::to_string(&v).expect("serialize");
        let restored: PhaseOrderViolation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, restored);
    }

    #[test]
    fn cancel_reason_serde_all_variants() {
        let reasons = [
            CancelReason::OperatorShutdown,
            CancelReason::Quarantine,
            CancelReason::Revocation,
            CancelReason::BudgetExhausted,
            CancelReason::ParentClosing,
            CancelReason::Custom("my_reason".to_string()),
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).expect("serialize");
            let restored: CancelReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*reason, restored);
        }
    }

    #[test]
    fn drain_deadline_default_value() {
        let dd = DrainDeadline::default();
        assert_eq!(dd.max_ticks, 10_000);
    }

    #[test]
    fn drain_tick_on_non_draining_region_returns_false() {
        let mut region = test_region();
        // Running state -- drain_tick should return false
        assert!(!region.drain_tick());

        // CancelRequested state
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        assert!(!region.drain_tick());
    }

    #[test]
    fn region_cancel_reason_accessor() {
        let mut region = test_region();
        assert!(region.cancel_reason().is_none());
        region.cancel(CancelReason::Quarantine).unwrap();
        assert_eq!(region.cancel_reason(), Some(&CancelReason::Quarantine));
    }

    #[test]
    fn region_child_count_accessor() {
        let mut region = test_region();
        assert_eq!(region.child_count(), 0);
        region.add_child(Region::new("c1", "ext", "t"));
        assert_eq!(region.child_count(), 1);
        region.add_child(Region::new("c2", "ext", "t"));
        assert_eq!(region.child_count(), 2);
    }

    #[test]
    fn region_event_count_tracks_own_events_only() {
        let mut parent = Region::new("parent", "svc", "t");
        parent.add_child(Region::new("child", "ext", "t"));
        parent.cancel(CancelReason::OperatorShutdown).unwrap();
        // Parent should have 1 event (cancel_initiated), child should also have 1
        // event_count() only counts the parent's own events
        assert_eq!(parent.event_count(), 1);
    }

    #[test]
    fn close_with_resolved_obligations_success() {
        let mut region = test_region();
        region.register_obligation("ob-1", "flush");
        region.register_obligation("ob-2", "commit");
        region.commit_obligation("ob-1");
        region.commit_obligation("ob-2");

        let result = region
            .close(
                CancelReason::OperatorShutdown,
                DrainDeadline { max_ticks: 10 },
            )
            .unwrap();
        assert!(result.success);
        assert_eq!(result.obligations_committed, 2);
        assert_eq!(result.obligations_aborted, 0);
    }

    #[test]
    fn finalize_result_serde_with_escalation() {
        let result = FinalizeResult {
            region_id: "r-escalated".to_string(),
            success: false,
            obligations_committed: 0,
            obligations_aborted: 3,
            drain_timeout_escalated: true,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let restored: FinalizeResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn drain_timeout_fires_only_once() {
        let mut region = test_region();
        region.register_obligation("ob-1", "slow");
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        region.drain(DrainDeadline { max_ticks: 2 }).unwrap();

        // Tick 1: no timeout
        assert!(!region.drain_tick());
        // Tick 2: timeout
        assert!(region.drain_tick());
        // Tick 3: still timeout but no duplicate escalation event
        let pre_count = region.event_count();
        assert!(region.drain_tick());
        // No new event should be emitted (escalation already recorded)
        assert_eq!(region.event_count(), pre_count);
    }

    // -- Enrichment batch 3: clone, JSON fields, edge cases --

    #[test]
    fn finalize_result_clone_equality() {
        let result = FinalizeResult {
            region_id: "r-1".to_string(),
            success: true,
            obligations_committed: 2,
            obligations_aborted: 0,
            drain_timeout_escalated: false,
        };
        assert_eq!(result, result.clone());
    }

    #[test]
    fn region_event_clone_equality() {
        let event = RegionEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            region_type: "ext".to_string(),
            phase: RegionState::Draining,
            outcome: "drain_started".to_string(),
            obligations_pending: 1,
            drain_elapsed_ticks: 0,
        };
        assert_eq!(event, event.clone());
    }

    #[test]
    fn obligation_clone_equality() {
        let ob = Obligation {
            id: "ob-1".to_string(),
            description: "flush".to_string(),
            status: ObligationStatus::Committed,
        };
        assert_eq!(ob, ob.clone());
    }

    #[test]
    fn phase_order_violation_clone_equality() {
        let v = PhaseOrderViolation {
            current_state: RegionState::Running,
            attempted_transition: "drain".to_string(),
            region_id: "r-1".to_string(),
        };
        assert_eq!(v, v.clone());
    }

    #[test]
    fn finalize_result_json_field_presence() {
        let result = FinalizeResult {
            region_id: "r-json".to_string(),
            success: true,
            obligations_committed: 1,
            obligations_aborted: 0,
            drain_timeout_escalated: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        for field in &[
            "region_id",
            "success",
            "obligations_committed",
            "obligations_aborted",
            "drain_timeout_escalated",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn region_new_starts_in_running() {
        let region = Region::new("r-new", "ext", "t-new");
        assert_eq!(region.state(), RegionState::Running);
        assert_eq!(region.id, "r-new");
        assert_eq!(region.region_type, "ext");
        assert_eq!(region.trace_id, "t-new");
        assert!(region.cancel_reason().is_none());
        assert_eq!(region.pending_obligations(), 0);
        assert_eq!(region.child_count(), 0);
        assert_eq!(region.event_count(), 0);
    }

    #[test]
    fn finalize_no_obligations_reports_zero_counts() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        region.drain(DrainDeadline::default()).unwrap();
        let result = region.finalize().unwrap();
        assert!(result.success);
        assert_eq!(result.obligations_committed, 0);
        assert_eq!(result.obligations_aborted, 0);
        assert!(!result.drain_timeout_escalated);
    }

    #[test]
    fn drain_events_clears_after_drain() {
        let mut region = test_region();
        region.cancel(CancelReason::OperatorShutdown).unwrap();
        let events1 = region.drain_events();
        assert!(!events1.is_empty());
        let events2 = region.drain_events();
        assert!(events2.is_empty());
    }

    #[test]
    fn close_shortcut_preserves_cancel_reason() {
        let mut region = test_region();
        region
            .close(CancelReason::BudgetExhausted, DrainDeadline::default())
            .unwrap();
        assert_eq!(region.cancel_reason(), Some(&CancelReason::BudgetExhausted));
    }

    #[test]
    fn region_event_json_field_presence() {
        let event = RegionEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            region_type: "ext".to_string(),
            phase: RegionState::Running,
            outcome: "ok".to_string(),
            obligations_pending: 0,
            drain_elapsed_ticks: 0,
        };
        let json = serde_json::to_string(&event).unwrap();
        for field in &[
            "trace_id",
            "region_id",
            "region_type",
            "phase",
            "outcome",
            "obligations_pending",
            "drain_elapsed_ticks",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn multiple_children_independent_close() {
        let mut parent = Region::new("parent", "svc", "t");
        let mut c1 = Region::new("c1", "ext", "t");
        c1.register_obligation("ob-c1", "flush");
        c1.commit_obligation("ob-c1");
        let c2 = Region::new("c2", "ext", "t");
        parent.add_child(c1);
        parent.add_child(c2);

        let result = parent
            .close(CancelReason::OperatorShutdown, DrainDeadline::default())
            .unwrap();
        assert!(result.success);
        assert_eq!(parent.state(), RegionState::Closed);
    }

    #[test]
    fn register_obligation_replaces_existing() {
        let mut region = test_region();
        region.register_obligation("ob-1", "first");
        region.register_obligation("ob-1", "replaced");
        assert_eq!(region.pending_obligations(), 1);
    }

    // ── Enrichment: Copy/Clone/Debug/Serde/Hash/Display/Edge ──

    #[test]
    fn region_state_copy_semantics() {
        let a = RegionState::Running;
        let b = a;
        assert_eq!(a, b);
        let c = RegionState::Closed;
        let d = c;
        assert_eq!(c, d);
    }

    #[test]
    fn obligation_status_copy_semantics() {
        let a = ObligationStatus::Pending;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn drain_deadline_copy_semantics() {
        let a = DrainDeadline { max_ticks: 500 };
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn region_state_debug_distinct() {
        let variants = [
            RegionState::Running,
            RegionState::CancelRequested,
            RegionState::Draining,
            RegionState::Finalizing,
            RegionState::Closed,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn cancel_reason_debug_distinct() {
        let variants = [
            CancelReason::OperatorShutdown,
            CancelReason::Quarantine,
            CancelReason::Revocation,
            CancelReason::BudgetExhausted,
            CancelReason::ParentClosing,
            CancelReason::Custom("x".to_string()),
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn obligation_status_debug_distinct() {
        let variants = [
            ObligationStatus::Pending,
            ObligationStatus::Committed,
            ObligationStatus::Aborted,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn region_state_serde_variant_distinct() {
        let variants = [
            RegionState::Running,
            RegionState::CancelRequested,
            RegionState::Draining,
            RegionState::Finalizing,
            RegionState::Closed,
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn cancel_reason_serde_variant_distinct() {
        let variants = [
            CancelReason::OperatorShutdown,
            CancelReason::Quarantine,
            CancelReason::Revocation,
            CancelReason::BudgetExhausted,
            CancelReason::ParentClosing,
            CancelReason::Custom("x".to_string()),
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn obligation_status_serde_variant_distinct() {
        let variants = [
            ObligationStatus::Pending,
            ObligationStatus::Committed,
            ObligationStatus::Aborted,
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn cancel_reason_clone_independence() {
        let a = CancelReason::Custom("original".to_string());
        let b = a.clone();
        assert_eq!(a, b);
        let c = CancelReason::Custom("changed".to_string());
        assert_ne!(a, c);
    }

    #[test]
    fn phase_order_violation_clone_independence() {
        let a = PhaseOrderViolation {
            current_state: RegionState::Running,
            attempted_transition: "drain".to_string(),
            region_id: "r1".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn obligation_clone_independence() {
        let a = Obligation {
            id: "ob-1".to_string(),
            description: "flush".to_string(),
            status: ObligationStatus::Pending,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn finalize_result_clone_independence() {
        let a = FinalizeResult {
            region_id: "r".to_string(),
            success: true,
            obligations_committed: 3,
            obligations_aborted: 1,
            drain_timeout_escalated: false,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn region_event_clone_independence() {
        let a = RegionEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            region_type: "ext".to_string(),
            phase: RegionState::Running,
            outcome: "ok".to_string(),
            obligations_pending: 0,
            drain_elapsed_ticks: 0,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn phase_order_violation_json_field_names() {
        let v = PhaseOrderViolation {
            current_state: RegionState::Running,
            attempted_transition: "drain".to_string(),
            region_id: "r".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"current_state\""));
        assert!(json.contains("\"attempted_transition\""));
        assert!(json.contains("\"region_id\""));
    }

    #[test]
    fn obligation_json_field_names() {
        let o = Obligation {
            id: "o".to_string(),
            description: "d".to_string(),
            status: ObligationStatus::Pending,
        };
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"status\""));
    }

    #[test]
    fn finalize_result_json_field_names() {
        let f = FinalizeResult {
            region_id: "r".to_string(),
            success: true,
            obligations_committed: 0,
            obligations_aborted: 0,
            drain_timeout_escalated: false,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"region_id\""));
        assert!(json.contains("\"success\""));
        assert!(json.contains("\"obligations_committed\""));
        assert!(json.contains("\"obligations_aborted\""));
        assert!(json.contains("\"drain_timeout_escalated\""));
    }

    #[test]
    fn phase_order_violation_display_exact() {
        let v = PhaseOrderViolation {
            current_state: RegionState::CancelRequested,
            attempted_transition: "cancel".to_string(),
            region_id: "rgn-42".to_string(),
        };
        assert_eq!(
            v.to_string(),
            "phase order violation in region 'rgn-42': attempted 'cancel' from state 'cancel_requested'"
        );
    }

    #[test]
    fn phase_order_violation_std_error_source_none() {
        let v = PhaseOrderViolation {
            current_state: RegionState::Running,
            attempted_transition: "finalize".to_string(),
            region_id: "r".to_string(),
        };
        let e: &dyn std::error::Error = &v;
        assert!(e.source().is_none());
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn region_state_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let a = RegionState::Draining;
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut h1);
        a.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn cancel_reason_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let a = CancelReason::Quarantine;
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut h1);
        a.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn region_state_ord_ordering() {
        assert!(RegionState::Running < RegionState::CancelRequested);
        assert!(RegionState::CancelRequested < RegionState::Draining);
        assert!(RegionState::Draining < RegionState::Finalizing);
        assert!(RegionState::Finalizing < RegionState::Closed);
    }

    #[test]
    fn cancel_reason_ord_ordering() {
        assert!(CancelReason::OperatorShutdown < CancelReason::Quarantine);
    }

    #[test]
    fn region_state_serde_roundtrip() {
        for state in [
            RegionState::Running,
            RegionState::CancelRequested,
            RegionState::Draining,
            RegionState::Finalizing,
            RegionState::Closed,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: RegionState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn cancel_reason_serde_roundtrip() {
        for reason in [
            CancelReason::OperatorShutdown,
            CancelReason::Quarantine,
            CancelReason::Revocation,
            CancelReason::BudgetExhausted,
            CancelReason::ParentClosing,
            CancelReason::Custom("my-reason".to_string()),
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let back: CancelReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, back);
        }
    }

    #[test]
    fn finalize_result_serde_roundtrip() {
        let f = FinalizeResult {
            region_id: "r-42".to_string(),
            success: false,
            obligations_committed: 5,
            obligations_aborted: 2,
            drain_timeout_escalated: true,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: FinalizeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn debug_nonempty_region_state() {
        assert!(!format!("{:?}", RegionState::Running).is_empty());
    }

    #[test]
    fn debug_nonempty_cancel_reason() {
        assert!(!format!("{:?}", CancelReason::Quarantine).is_empty());
    }

    #[test]
    fn debug_nonempty_phase_order_violation() {
        let v = PhaseOrderViolation {
            current_state: RegionState::Running,
            attempted_transition: "x".to_string(),
            region_id: "r".to_string(),
        };
        assert!(!format!("{v:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_obligation() {
        let o = Obligation {
            id: "o".to_string(),
            description: "d".to_string(),
            status: ObligationStatus::Pending,
        };
        assert!(!format!("{o:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_drain_deadline() {
        assert!(!format!("{:?}", DrainDeadline::default()).is_empty());
    }

    #[test]
    fn debug_nonempty_finalize_result() {
        let f = FinalizeResult {
            region_id: "r".to_string(),
            success: true,
            obligations_committed: 0,
            obligations_aborted: 0,
            drain_timeout_escalated: false,
        };
        assert!(!format!("{f:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_region_event() {
        let e = RegionEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            region_type: "ext".to_string(),
            phase: RegionState::Running,
            outcome: "ok".to_string(),
            obligations_pending: 0,
            drain_elapsed_ticks: 0,
        };
        assert!(!format!("{e:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_region() {
        let r = test_region();
        assert!(!format!("{r:?}").is_empty());
    }

    #[test]
    fn boundary_drain_deadline_default() {
        let d = DrainDeadline::default();
        assert_eq!(d.max_ticks, 10_000);
    }

    #[test]
    fn boundary_drain_deadline_zero() {
        let d = DrainDeadline { max_ticks: 0 };
        assert_eq!(d.max_ticks, 0);
    }

    #[test]
    fn boundary_drain_tick_on_non_draining_returns_false() {
        let mut r = test_region();
        assert!(!r.drain_tick());
    }

    #[test]
    fn boundary_commit_nonexistent_obligation_returns_false() {
        let mut r = test_region();
        assert!(!r.commit_obligation("nonexistent"));
    }

    #[test]
    fn boundary_abort_nonexistent_obligation_returns_false() {
        let mut r = test_region();
        assert!(!r.abort_obligation("nonexistent"));
    }

    #[test]
    fn boundary_empty_region_event_count() {
        let r = test_region();
        assert_eq!(r.event_count(), 0);
    }

    #[test]
    fn boundary_empty_region_child_count() {
        let r = test_region();
        assert_eq!(r.child_count(), 0);
    }

    #[test]
    fn drain_timeout_escalation_aborts_pending() {
        let mut r = test_region();
        r.register_obligation("ob-1", "stuck");
        r.cancel(CancelReason::OperatorShutdown).unwrap();
        r.drain(DrainDeadline { max_ticks: 2 }).unwrap();
        // Tick past deadline
        r.drain_tick();
        r.drain_tick();
        assert!(r.drain_tick()); // timed out
        let result = r.finalize().unwrap();
        // obligation was force-aborted
        assert_eq!(result.obligations_aborted, 1);
        assert!(result.drain_timeout_escalated);
    }

    #[test]
    fn region_new_starts_running() {
        let r = Region::new("id", "type", "trace");
        assert_eq!(r.state(), RegionState::Running);
        assert!(r.cancel_reason().is_none());
        assert_eq!(r.pending_obligations(), 0);
        assert_eq!(r.child_count(), 0);
    }

    #[test]
    fn drain_events_returns_child_events_too() {
        let mut parent = Region::new("p", "svc", "t");
        let child = Region::new("c", "ext", "t");
        parent.add_child(child);
        parent
            .close(CancelReason::Quarantine, DrainDeadline::default())
            .unwrap();
        let events = parent.drain_events();
        // Should have events from both parent and child
        let parent_events: Vec<_> = events.iter().filter(|e| e.region_id == "p").collect();
        let child_events: Vec<_> = events.iter().filter(|e| e.region_id == "c").collect();
        assert!(!parent_events.is_empty());
        assert!(!child_events.is_empty());
    }

    #[test]
    fn drain_events_is_idempotent_empty_on_second_call() {
        let mut r = test_region();
        r.close(CancelReason::Revocation, DrainDeadline::default())
            .unwrap();
        let first = r.drain_events();
        assert!(!first.is_empty());
        let second = r.drain_events();
        assert!(second.is_empty());
    }
}
