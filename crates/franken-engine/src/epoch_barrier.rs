//! Epoch transition barrier preventing mixed-epoch critical operations.
//!
//! When a security epoch advances, all in-flight critical operations must
//! either complete under the old epoch or be aborted — no operation may
//! straddle the boundary.  The [`EpochBarrier`] provides read-side
//! [`EpochGuard`]s for critical operations and a write-side transition
//! protocol that drains in-flight guards before advancing.
//!
//! Plan references: Section 10.11 item 19, 9G.6 (epoch-scoped validity,
//! key derivation with transition barriers), Top-10 #5 (supply-chain
//! trust), Top-10 #10 (provenance, revocation fabric).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::{SecurityEpoch, TransitionReason};

// ---------------------------------------------------------------------------
// BarrierState — phase of the epoch barrier
// ---------------------------------------------------------------------------

/// Current phase of the epoch barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BarrierState {
    /// Normal operation — guards can be acquired.
    Open,
    /// Transition in progress — new guards are rejected, draining old ones.
    Draining,
    /// Transition is complete but barrier has not yet reopened (finalization).
    Finalizing,
}

impl fmt::Display for BarrierState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Open => "open",
            Self::Draining => "draining",
            Self::Finalizing => "finalizing",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// BarrierError — typed barrier failures
// ---------------------------------------------------------------------------

/// Typed error for epoch barrier operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BarrierError {
    /// Guard acquisition rejected because the barrier is transitioning.
    EpochTransitioning {
        current_epoch: SecurityEpoch,
        state: BarrierState,
    },
    /// Transition cannot start because one is already in progress.
    TransitionAlreadyInProgress { current_epoch: SecurityEpoch },
    /// Drain timeout expired with guards still held.
    DrainTimeout {
        epoch: SecurityEpoch,
        remaining_guards: u64,
        timeout_ms: u64,
    },
    /// Attempted to complete a transition that was not in progress.
    NoTransitionInProgress,
    /// New epoch is not strictly greater than the current epoch.
    NonMonotonicTransition {
        current: SecurityEpoch,
        attempted: SecurityEpoch,
    },
}

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochTransitioning {
                current_epoch,
                state,
            } => write!(
                f,
                "barrier is {state}, cannot acquire guard at {current_epoch}"
            ),
            Self::TransitionAlreadyInProgress { current_epoch } => {
                write!(f, "transition already in progress at {current_epoch}")
            }
            Self::DrainTimeout {
                epoch,
                remaining_guards,
                timeout_ms,
            } => write!(
                f,
                "drain timeout at {epoch}: {remaining_guards} guards remaining after {timeout_ms}ms"
            ),
            Self::NoTransitionInProgress => write!(f, "no transition in progress to complete"),
            Self::NonMonotonicTransition { current, attempted } => write!(
                f,
                "non-monotonic transition: current {current}, attempted {attempted}"
            ),
        }
    }
}

impl std::error::Error for BarrierError {}

// ---------------------------------------------------------------------------
// CriticalOpKind — categorizes operations needing the barrier
// ---------------------------------------------------------------------------

/// Categories of critical operations that must use the epoch barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CriticalOpKind {
    /// Decision-contract evaluation (policy action selection).
    DecisionEval,
    /// Evidence entry emission.
    EvidenceEmission,
    /// Key derivation and session establishment.
    KeyDerivation,
    /// Capability token issuance and validation.
    CapabilityCheck,
    /// Revocation check execution.
    RevocationCheck,
    /// Remote operation initiation.
    RemoteOperation,
}

impl fmt::Display for CriticalOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::DecisionEval => "decision_eval",
            Self::EvidenceEmission => "evidence_emission",
            Self::KeyDerivation => "key_derivation",
            Self::CapabilityCheck => "capability_check",
            Self::RevocationCheck => "revocation_check",
            Self::RemoteOperation => "remote_operation",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// EpochGuard — read-side guard for critical operations
// ---------------------------------------------------------------------------

/// Guard token returned by [`EpochBarrier::enter_critical`].
///
/// Represents an in-flight critical operation bound to a specific epoch.
/// When dropped (via [`EpochBarrier::release_guard`]), decrements the
/// in-flight count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochGuard {
    /// Unique guard identifier for tracking.
    pub guard_id: u64,
    /// Epoch under which this operation is executing.
    pub epoch: SecurityEpoch,
    /// Kind of critical operation.
    pub op_kind: CriticalOpKind,
    /// Trace identifier for correlation.
    pub trace_id: String,
}

impl fmt::Display for EpochGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EpochGuard(#{}, {}, {})",
            self.guard_id, self.epoch, self.op_kind
        )
    }
}

// ---------------------------------------------------------------------------
// TransitionEvidence — structured evidence for epoch transitions
// ---------------------------------------------------------------------------

/// Structured evidence emitted for every epoch transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionEvidence {
    /// Epoch before transition.
    pub old_epoch: SecurityEpoch,
    /// Epoch after transition.
    pub new_epoch: SecurityEpoch,
    /// Reason for the transition.
    pub reason: TransitionReason,
    /// Number of in-flight guards when transition started.
    pub in_flight_at_start: u64,
    /// Number of in-flight guards when transition completed.
    pub in_flight_at_complete: u64,
    /// Number of guards forcibly cancelled.
    pub forced_cancellations: u64,
    /// Transition duration in milliseconds (0 for deterministic mode).
    pub duration_ms: u64,
    /// Trace identifier.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// BarrierConfig
// ---------------------------------------------------------------------------

/// Configuration for the epoch barrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BarrierConfig {
    /// Drain timeout in milliseconds before forced cancellation.
    /// Default: 5000ms.
    pub drain_timeout_ms: u64,
    /// Whether this barrier runs in deterministic test mode.
    /// In deterministic mode, timing is fixed and transitions are instant.
    pub deterministic: bool,
}

impl Default for BarrierConfig {
    fn default() -> Self {
        Self {
            drain_timeout_ms: 5000,
            deterministic: false,
        }
    }
}

impl BarrierConfig {
    /// Create a config for deterministic test mode.
    pub fn deterministic() -> Self {
        Self {
            drain_timeout_ms: 0,
            deterministic: true,
        }
    }
}

// ---------------------------------------------------------------------------
// EpochBarrier — the barrier state machine
// ---------------------------------------------------------------------------

/// Epoch transition barrier enforcing that no critical operation
/// straddles an epoch boundary.
///
/// Read-side: [`enter_critical`] / [`release_guard`].
/// Write-side: [`begin_transition`] / [`complete_transition`].
#[derive(Debug)]
pub struct EpochBarrier {
    config: BarrierConfig,
    current_epoch: SecurityEpoch,
    state: BarrierState,
    in_flight_count: u64,
    next_guard_id: u64,
    pending_new_epoch: Option<SecurityEpoch>,
    pending_reason: Option<TransitionReason>,
    pending_trace_id: Option<String>,
    in_flight_at_transition_start: u64,
    forced_cancellations: u64,
    evidence: Vec<TransitionEvidence>,
}

impl EpochBarrier {
    /// Create a new barrier at the given epoch.
    pub fn new(epoch: SecurityEpoch, config: BarrierConfig) -> Self {
        Self {
            config,
            current_epoch: epoch,
            state: BarrierState::Open,
            in_flight_count: 0,
            next_guard_id: 1,
            pending_new_epoch: None,
            pending_reason: None,
            pending_trace_id: None,
            in_flight_at_transition_start: 0,
            forced_cancellations: 0,
            evidence: Vec::new(),
        }
    }

    /// The current epoch.
    pub fn current_epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// The current barrier state.
    pub fn state(&self) -> BarrierState {
        self.state
    }

    /// Number of in-flight guards.
    pub fn in_flight(&self) -> u64 {
        self.in_flight_count
    }

    /// Acquire a read-side guard for a critical operation.
    ///
    /// Fails if the barrier is transitioning (draining or finalizing).
    pub fn enter_critical(
        &mut self,
        op_kind: CriticalOpKind,
        trace_id: &str,
    ) -> Result<EpochGuard, BarrierError> {
        if self.state != BarrierState::Open {
            return Err(BarrierError::EpochTransitioning {
                current_epoch: self.current_epoch,
                state: self.state,
            });
        }

        let guard_id = self.next_guard_id;
        self.next_guard_id = self.next_guard_id.saturating_add(1);
        self.in_flight_count = self.in_flight_count.saturating_add(1);

        Ok(EpochGuard {
            guard_id,
            epoch: self.current_epoch,
            op_kind,
            trace_id: trace_id.to_string(),
        })
    }

    /// Release a guard, decrementing the in-flight count.
    ///
    /// Returns `true` if the guard was valid (epoch matches current or
    /// pending transition), `false` if the guard is stale.
    pub fn release_guard(&mut self, guard: &EpochGuard) -> bool {
        // Only accept guards from the current epoch.
        if guard.epoch != self.current_epoch {
            return false;
        }
        if self.in_flight_count == 0 {
            return false;
        }
        self.in_flight_count -= 1;
        true
    }

    /// Begin an epoch transition.
    ///
    /// Moves the barrier to `Draining` state.  New `enter_critical`
    /// calls will be rejected.  Returns the number of in-flight guards
    /// that must drain before the transition can complete.
    pub fn begin_transition(
        &mut self,
        new_epoch: SecurityEpoch,
        reason: TransitionReason,
        trace_id: &str,
    ) -> Result<u64, BarrierError> {
        if self.state != BarrierState::Open {
            return Err(BarrierError::TransitionAlreadyInProgress {
                current_epoch: self.current_epoch,
            });
        }

        if new_epoch <= self.current_epoch {
            return Err(BarrierError::NonMonotonicTransition {
                current: self.current_epoch,
                attempted: new_epoch,
            });
        }

        self.state = BarrierState::Draining;
        self.pending_new_epoch = Some(new_epoch);
        self.pending_reason = Some(reason);
        self.pending_trace_id = Some(trace_id.to_string());
        self.in_flight_at_transition_start = self.in_flight_count;
        self.forced_cancellations = 0;

        Ok(self.in_flight_count)
    }

    /// Force-cancel remaining in-flight guards.
    ///
    /// Used when drain timeout expires.  Resets in-flight count to zero
    /// and records the number of forced cancellations.
    pub fn force_cancel_remaining(&mut self) -> Result<u64, BarrierError> {
        if self.state != BarrierState::Draining {
            return Err(BarrierError::NoTransitionInProgress);
        }

        let cancelled = self.in_flight_count;
        self.forced_cancellations = self.forced_cancellations.saturating_add(cancelled);
        self.in_flight_count = 0;
        Ok(cancelled)
    }

    /// Check if the barrier is ready to complete the transition.
    ///
    /// Returns `true` if all in-flight guards have been released or
    /// force-cancelled.
    pub fn can_complete(&self) -> bool {
        self.state == BarrierState::Draining && self.in_flight_count == 0
    }

    /// Complete the transition, advancing to the new epoch.
    ///
    /// Fails if there are still in-flight guards or no transition
    /// is in progress.
    pub fn complete_transition(&mut self) -> Result<TransitionEvidence, BarrierError> {
        if self.state != BarrierState::Draining {
            return Err(BarrierError::NoTransitionInProgress);
        }

        if self.in_flight_count > 0 {
            return Err(BarrierError::DrainTimeout {
                epoch: self.current_epoch,
                remaining_guards: self.in_flight_count,
                timeout_ms: self.config.drain_timeout_ms,
            });
        }

        let old_epoch = self.current_epoch;
        let new_epoch = self.pending_new_epoch.take().expect("pending epoch set");
        let reason = self.pending_reason.take().expect("pending reason set");
        let trace_id = self.pending_trace_id.take().expect("pending trace set");

        let evidence = TransitionEvidence {
            old_epoch,
            new_epoch,
            reason,
            in_flight_at_start: self.in_flight_at_transition_start,
            in_flight_at_complete: 0,
            forced_cancellations: self.forced_cancellations,
            duration_ms: 0,
            trace_id,
        };

        self.current_epoch = new_epoch;
        self.state = BarrierState::Open;
        self.forced_cancellations = 0;
        self.in_flight_at_transition_start = 0;

        self.evidence.push(evidence.clone());
        Ok(evidence)
    }

    /// Execute a full transition cycle: begin, force-cancel if needed,
    /// and complete.
    ///
    /// Convenience method for deterministic test mode or when immediate
    /// transition is acceptable.
    pub fn transition_now(
        &mut self,
        new_epoch: SecurityEpoch,
        reason: TransitionReason,
        trace_id: &str,
    ) -> Result<TransitionEvidence, BarrierError> {
        self.begin_transition(new_epoch, reason, trace_id)?;

        if self.in_flight_count > 0 {
            self.force_cancel_remaining()?;
        }

        self.complete_transition()
    }

    /// Recorded transition evidence.
    pub fn evidence(&self) -> &[TransitionEvidence] {
        &self.evidence
    }

    /// The barrier configuration.
    pub fn config(&self) -> &BarrierConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn det_barrier(epoch: u64) -> EpochBarrier {
        EpochBarrier::new(
            SecurityEpoch::from_raw(epoch),
            BarrierConfig::deterministic(),
        )
    }

    // -- Basic guard lifecycle --

    #[test]
    fn enter_and_release_guard() {
        let mut barrier = det_barrier(1);
        let guard = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .expect("enter");
        assert_eq!(barrier.in_flight(), 1);
        assert_eq!(guard.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(guard.op_kind, CriticalOpKind::DecisionEval);

        assert!(barrier.release_guard(&guard));
        assert_eq!(barrier.in_flight(), 0);
    }

    #[test]
    fn multiple_concurrent_guards() {
        let mut barrier = det_barrier(1);
        let g1 = barrier
            .enter_critical(CriticalOpKind::EvidenceEmission, "t1")
            .expect("g1");
        let g2 = barrier
            .enter_critical(CriticalOpKind::KeyDerivation, "t2")
            .expect("g2");
        let g3 = barrier
            .enter_critical(CriticalOpKind::CapabilityCheck, "t3")
            .expect("g3");
        assert_eq!(barrier.in_flight(), 3);

        barrier.release_guard(&g1);
        barrier.release_guard(&g2);
        barrier.release_guard(&g3);
        assert_eq!(barrier.in_flight(), 0);
    }

    #[test]
    fn guard_ids_are_unique() {
        let mut barrier = det_barrier(1);
        let g1 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .expect("g1");
        let g2 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t2")
            .expect("g2");
        assert_ne!(g1.guard_id, g2.guard_id);
    }

    // -- Guard acquisition during transition --

    #[test]
    fn enter_rejected_during_drain() {
        let mut barrier = det_barrier(1);
        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t1",
            )
            .expect("begin");

        let err = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t2")
            .unwrap_err();
        assert!(matches!(
            err,
            BarrierError::EpochTransitioning {
                state: BarrierState::Draining,
                ..
            }
        ));
    }

    // -- Transition lifecycle --

    #[test]
    fn clean_transition_with_no_in_flight() {
        let mut barrier = det_barrier(1);

        let in_flight = barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "trace-1",
            )
            .expect("begin");
        assert_eq!(in_flight, 0);
        assert_eq!(barrier.state(), BarrierState::Draining);

        let evidence = barrier.complete_transition().expect("complete");
        assert_eq!(evidence.old_epoch, SecurityEpoch::from_raw(1));
        assert_eq!(evidence.new_epoch, SecurityEpoch::from_raw(2));
        assert_eq!(evidence.in_flight_at_start, 0);
        assert_eq!(evidence.forced_cancellations, 0);
        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(2));
        assert_eq!(barrier.state(), BarrierState::Open);
    }

    #[test]
    fn transition_with_guards_drained() {
        let mut barrier = det_barrier(1);

        // Acquire two guards.
        let g1 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .expect("g1");
        let g2 = barrier
            .enter_critical(CriticalOpKind::EvidenceEmission, "t2")
            .expect("g2");

        // Begin transition — should report 2 in flight.
        let in_flight = barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::RevocationFrontierAdvance,
                "trace-2",
            )
            .expect("begin");
        assert_eq!(in_flight, 2);
        assert!(!barrier.can_complete());

        // Release guards.
        barrier.release_guard(&g1);
        assert!(!barrier.can_complete());
        barrier.release_guard(&g2);
        assert!(barrier.can_complete());

        // Complete.
        let evidence = barrier.complete_transition().expect("complete");
        assert_eq!(evidence.in_flight_at_start, 2);
        assert_eq!(evidence.forced_cancellations, 0);
        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(2));
    }

    #[test]
    fn transition_with_forced_cancellation() {
        let mut barrier = det_barrier(1);

        let _g1 = barrier
            .enter_critical(CriticalOpKind::RemoteOperation, "t1")
            .expect("g1");
        let _g2 = barrier
            .enter_critical(CriticalOpKind::KeyDerivation, "t2")
            .expect("g2");

        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::GuardrailConfigChange,
                "trace-3",
            )
            .expect("begin");

        // Force cancel instead of waiting.
        let cancelled = barrier.force_cancel_remaining().expect("force cancel");
        assert_eq!(cancelled, 2);
        assert_eq!(barrier.in_flight(), 0);

        let evidence = barrier.complete_transition().expect("complete");
        assert_eq!(evidence.forced_cancellations, 2);
    }

    // -- transition_now convenience --

    #[test]
    fn transition_now_with_no_guards() {
        let mut barrier = det_barrier(1);
        let evidence = barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::LossMatrixUpdate,
                "trace-now",
            )
            .expect("now");
        assert_eq!(evidence.old_epoch, SecurityEpoch::from_raw(1));
        assert_eq!(evidence.new_epoch, SecurityEpoch::from_raw(2));
        assert_eq!(evidence.forced_cancellations, 0);
    }

    #[test]
    fn transition_now_force_cancels_in_flight() {
        let mut barrier = det_barrier(5);
        let _g = barrier
            .enter_critical(CriticalOpKind::RevocationCheck, "t1")
            .expect("g");

        let evidence = barrier
            .transition_now(
                SecurityEpoch::from_raw(6),
                TransitionReason::OperatorManualBump,
                "trace-force",
            )
            .expect("now");
        assert_eq!(evidence.forced_cancellations, 1);
        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(6));
    }

    // -- Error conditions --

    #[test]
    fn double_transition_rejected() {
        let mut barrier = det_barrier(1);
        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t1",
            )
            .expect("begin");

        let err = barrier
            .begin_transition(
                SecurityEpoch::from_raw(3),
                TransitionReason::PolicyKeyRotation,
                "t2",
            )
            .unwrap_err();
        assert!(matches!(
            err,
            BarrierError::TransitionAlreadyInProgress { .. }
        ));
    }

    #[test]
    fn non_monotonic_transition_rejected() {
        let mut barrier = det_barrier(5);
        let err = barrier
            .begin_transition(
                SecurityEpoch::from_raw(3),
                TransitionReason::PolicyKeyRotation,
                "t1",
            )
            .unwrap_err();
        assert!(matches!(err, BarrierError::NonMonotonicTransition { .. }));
    }

    #[test]
    fn same_epoch_transition_rejected() {
        let mut barrier = det_barrier(5);
        let err = barrier
            .begin_transition(
                SecurityEpoch::from_raw(5),
                TransitionReason::PolicyKeyRotation,
                "t1",
            )
            .unwrap_err();
        assert!(matches!(err, BarrierError::NonMonotonicTransition { .. }));
    }

    #[test]
    fn complete_without_transition_rejected() {
        let mut barrier = det_barrier(1);
        let err = barrier.complete_transition().unwrap_err();
        assert!(matches!(err, BarrierError::NoTransitionInProgress));
    }

    #[test]
    fn complete_with_guards_still_held_rejected() {
        let mut barrier = det_barrier(1);
        let _g = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .expect("g");

        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t1",
            )
            .expect("begin");

        let err = barrier.complete_transition().unwrap_err();
        assert!(matches!(err, BarrierError::DrainTimeout { .. }));
    }

    // -- Sequential transitions --

    #[test]
    fn sequential_transitions() {
        let mut barrier = det_barrier(1);

        for i in 2..=5 {
            let evidence = barrier
                .transition_now(
                    SecurityEpoch::from_raw(i),
                    TransitionReason::PolicyKeyRotation,
                    &format!("trace-{i}"),
                )
                .expect("transition");
            assert_eq!(evidence.new_epoch, SecurityEpoch::from_raw(i));
        }

        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(5));
        assert_eq!(barrier.evidence().len(), 4);
    }

    // -- Post-transition guard acquisition --

    #[test]
    fn guards_work_after_transition() {
        let mut barrier = det_barrier(1);
        barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t1",
            )
            .expect("transition");

        let guard = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t2")
            .expect("guard");
        assert_eq!(guard.epoch, SecurityEpoch::from_raw(2));
        barrier.release_guard(&guard);
    }

    // -- Evidence recording --

    #[test]
    fn evidence_records_transition_details() {
        let mut barrier = det_barrier(10);

        let _g = barrier
            .enter_critical(CriticalOpKind::EvidenceEmission, "t1")
            .expect("g");

        barrier
            .transition_now(
                SecurityEpoch::from_raw(11),
                TransitionReason::RemoteTrustConfigChange,
                "trace-detail",
            )
            .expect("transition");

        let ev = &barrier.evidence()[0];
        assert_eq!(ev.old_epoch, SecurityEpoch::from_raw(10));
        assert_eq!(ev.new_epoch, SecurityEpoch::from_raw(11));
        assert_eq!(ev.reason, TransitionReason::RemoteTrustConfigChange);
        assert_eq!(ev.in_flight_at_start, 1);
        assert_eq!(ev.forced_cancellations, 1);
        assert_eq!(ev.trace_id, "trace-detail");
    }

    // -- Display and error formatting --

    #[test]
    fn barrier_state_display() {
        assert_eq!(BarrierState::Open.to_string(), "open");
        assert_eq!(BarrierState::Draining.to_string(), "draining");
        assert_eq!(BarrierState::Finalizing.to_string(), "finalizing");
    }

    #[test]
    fn critical_op_kind_display() {
        assert_eq!(CriticalOpKind::DecisionEval.to_string(), "decision_eval");
        assert_eq!(
            CriticalOpKind::EvidenceEmission.to_string(),
            "evidence_emission"
        );
        assert_eq!(CriticalOpKind::KeyDerivation.to_string(), "key_derivation");
        assert_eq!(
            CriticalOpKind::CapabilityCheck.to_string(),
            "capability_check"
        );
        assert_eq!(
            CriticalOpKind::RevocationCheck.to_string(),
            "revocation_check"
        );
        assert_eq!(
            CriticalOpKind::RemoteOperation.to_string(),
            "remote_operation"
        );
    }

    #[test]
    fn barrier_error_display() {
        let err = BarrierError::EpochTransitioning {
            current_epoch: SecurityEpoch::from_raw(5),
            state: BarrierState::Draining,
        };
        assert_eq!(
            err.to_string(),
            "barrier is draining, cannot acquire guard at epoch:5"
        );
    }

    #[test]
    fn epoch_guard_display() {
        let guard = EpochGuard {
            guard_id: 42,
            epoch: SecurityEpoch::from_raw(3),
            op_kind: CriticalOpKind::KeyDerivation,
            trace_id: "t".to_string(),
        };
        assert_eq!(
            guard.to_string(),
            "EpochGuard(#42, epoch:3, key_derivation)"
        );
    }

    // -- Serialization --

    #[test]
    fn transition_evidence_serialization_round_trip() {
        let evidence = TransitionEvidence {
            old_epoch: SecurityEpoch::from_raw(1),
            new_epoch: SecurityEpoch::from_raw(2),
            reason: TransitionReason::PolicyKeyRotation,
            in_flight_at_start: 3,
            in_flight_at_complete: 0,
            forced_cancellations: 1,
            duration_ms: 0,
            trace_id: "test-trace".to_string(),
        };
        let json = serde_json::to_string(&evidence).expect("serialize");
        let restored: TransitionEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(evidence, restored);
    }

    #[test]
    fn barrier_error_serialization_round_trip() {
        let errors = vec![
            BarrierError::EpochTransitioning {
                current_epoch: SecurityEpoch::from_raw(1),
                state: BarrierState::Draining,
            },
            BarrierError::TransitionAlreadyInProgress {
                current_epoch: SecurityEpoch::from_raw(2),
            },
            BarrierError::DrainTimeout {
                epoch: SecurityEpoch::from_raw(3),
                remaining_guards: 5,
                timeout_ms: 5000,
            },
            BarrierError::NoTransitionInProgress,
            BarrierError::NonMonotonicTransition {
                current: SecurityEpoch::from_raw(5),
                attempted: SecurityEpoch::from_raw(3),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: BarrierError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn epoch_guard_serialization_round_trip() {
        let guard = EpochGuard {
            guard_id: 7,
            epoch: SecurityEpoch::from_raw(3),
            op_kind: CriticalOpKind::RemoteOperation,
            trace_id: "t-123".to_string(),
        };
        let json = serde_json::to_string(&guard).expect("serialize");
        let restored: EpochGuard = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(guard, restored);
    }

    // -- Enrichment: serde, Display, std::error --

    #[test]
    fn barrier_state_serde_all_variants() {
        for state in [
            BarrierState::Open,
            BarrierState::Draining,
            BarrierState::Finalizing,
        ] {
            let json = serde_json::to_string(&state).expect("serialize");
            let restored: BarrierState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(state, restored);
        }
    }

    #[test]
    fn critical_op_kind_serde_all_variants() {
        for kind in [
            CriticalOpKind::DecisionEval,
            CriticalOpKind::EvidenceEmission,
            CriticalOpKind::KeyDerivation,
            CriticalOpKind::CapabilityCheck,
            CriticalOpKind::RevocationCheck,
            CriticalOpKind::RemoteOperation,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: CriticalOpKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn barrier_error_implements_std_error() {
        let epoch = SecurityEpoch::from_raw(5);
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(BarrierError::EpochTransitioning {
                current_epoch: epoch,
                state: BarrierState::Draining,
            }),
            Box::new(BarrierError::TransitionAlreadyInProgress {
                current_epoch: epoch,
            }),
            Box::new(BarrierError::DrainTimeout {
                epoch,
                remaining_guards: 3,
                timeout_ms: 5000,
            }),
            Box::new(BarrierError::NoTransitionInProgress),
            Box::new(BarrierError::NonMonotonicTransition {
                current: epoch,
                attempted: SecurityEpoch::from_raw(2),
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
            5,
            "all 5 variants produce distinct messages"
        );
    }

    #[test]
    fn barrier_config_serialization_round_trip() {
        let config = BarrierConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: BarrierConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    // --- enrichment tests ---

    #[test]
    fn release_stale_guard_from_old_epoch_returns_false() {
        let mut barrier = det_barrier(1);
        let guard = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t")
            .unwrap();
        barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        assert!(!barrier.release_guard(&guard));
    }

    #[test]
    fn force_cancel_when_not_draining_returns_error() {
        let mut barrier = det_barrier(1);
        let err = barrier.force_cancel_remaining().unwrap_err();
        assert!(matches!(err, BarrierError::NoTransitionInProgress));
    }

    #[test]
    fn barrier_config_default_values() {
        let cfg = BarrierConfig::default();
        assert_eq!(cfg.drain_timeout_ms, 5000);
        assert!(!cfg.deterministic);
    }

    #[test]
    fn barrier_config_deterministic_values() {
        let cfg = BarrierConfig::deterministic();
        assert_eq!(cfg.drain_timeout_ms, 0);
        assert!(cfg.deterministic);
    }

    #[test]
    fn barrier_config_accessor() {
        let barrier = det_barrier(1);
        assert!(barrier.config().deterministic);
    }

    #[test]
    fn barrier_starts_open_with_zero_in_flight() {
        let barrier = det_barrier(1);
        assert_eq!(barrier.state(), BarrierState::Open);
        assert_eq!(barrier.in_flight(), 0);
        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(1));
    }

    #[test]
    fn release_guard_on_empty_barrier_returns_false() {
        let mut barrier = det_barrier(1);
        let fake_guard = EpochGuard {
            guard_id: 999,
            epoch: SecurityEpoch::from_raw(1),
            op_kind: CriticalOpKind::DecisionEval,
            trace_id: "fake".to_string(),
        };
        assert!(!barrier.release_guard(&fake_guard));
    }

    #[test]
    fn evidence_starts_empty() {
        let barrier = det_barrier(1);
        assert!(barrier.evidence().is_empty());
    }

    #[test]
    fn can_complete_is_false_when_open() {
        let barrier = det_barrier(1);
        assert!(!barrier.can_complete());
    }

    #[test]
    fn critical_op_kind_ordering() {
        assert!(CriticalOpKind::DecisionEval < CriticalOpKind::EvidenceEmission);
        assert!(CriticalOpKind::EvidenceEmission < CriticalOpKind::KeyDerivation);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, error Display, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn barrier_state_display_all_unique() {
        let states = [
            BarrierState::Open,
            BarrierState::Draining,
            BarrierState::Finalizing,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for s in &states {
            seen.insert(s.to_string());
        }
        assert_eq!(
            seen.len(),
            3,
            "all 3 BarrierState Display strings must be unique"
        );
    }

    #[test]
    fn critical_op_kind_display_all_unique() {
        let kinds = [
            CriticalOpKind::DecisionEval,
            CriticalOpKind::EvidenceEmission,
            CriticalOpKind::KeyDerivation,
            CriticalOpKind::CapabilityCheck,
            CriticalOpKind::RevocationCheck,
            CriticalOpKind::RemoteOperation,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for k in &kinds {
            seen.insert(k.to_string());
        }
        assert_eq!(
            seen.len(),
            6,
            "all 6 CriticalOpKind Display strings must be unique"
        );
    }

    #[test]
    fn barrier_error_display_all_variants() {
        let variants = [
            BarrierError::EpochTransitioning {
                current_epoch: SecurityEpoch::from_raw(1),
                state: BarrierState::Draining,
            },
            BarrierError::TransitionAlreadyInProgress {
                current_epoch: SecurityEpoch::from_raw(2),
            },
            BarrierError::DrainTimeout {
                epoch: SecurityEpoch::from_raw(3),
                remaining_guards: 5,
                timeout_ms: 1000,
            },
            BarrierError::NoTransitionInProgress,
            BarrierError::NonMonotonicTransition {
                current: SecurityEpoch::from_raw(5),
                attempted: SecurityEpoch::from_raw(3),
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = v.to_string();
            assert!(!msg.is_empty());
            seen.insert(msg);
        }
        assert_eq!(
            seen.len(),
            5,
            "all 5 BarrierError variants produce distinct Display"
        );
    }

    #[test]
    fn transition_evidence_serde_with_forced_cancellations() {
        let evidence = TransitionEvidence {
            old_epoch: SecurityEpoch::from_raw(10),
            new_epoch: SecurityEpoch::from_raw(11),
            reason: TransitionReason::OperatorManualBump,
            in_flight_at_start: 5,
            in_flight_at_complete: 0,
            forced_cancellations: 5,
            duration_ms: 42,
            trace_id: "t-forced".to_string(),
        };
        let json = serde_json::to_string(&evidence).expect("serialize");
        let restored: TransitionEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(evidence, restored);
    }

    #[test]
    fn guard_display_format() {
        let guard = EpochGuard {
            guard_id: 1,
            epoch: SecurityEpoch::from_raw(10),
            op_kind: CriticalOpKind::RemoteOperation,
            trace_id: "tx".to_string(),
        };
        let display = guard.to_string();
        assert!(display.contains("#1"));
        assert!(display.contains("epoch:10"));
        assert!(display.contains("remote_operation"));
    }

    #[test]
    fn transition_now_multiple_sequential() {
        let mut barrier = det_barrier(1);
        for epoch in 2..=10 {
            barrier
                .transition_now(
                    SecurityEpoch::from_raw(epoch),
                    TransitionReason::PolicyKeyRotation,
                    &format!("t-{epoch}"),
                )
                .unwrap();
        }
        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(10));
        assert_eq!(barrier.evidence().len(), 9);
    }

    #[test]
    fn evidence_accumulates_across_transitions() {
        let mut barrier = det_barrier(1);
        assert!(barrier.evidence().is_empty());

        barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t1",
            )
            .unwrap();
        assert_eq!(barrier.evidence().len(), 1);

        barrier
            .transition_now(
                SecurityEpoch::from_raw(3),
                TransitionReason::PolicyKeyRotation,
                "t2",
            )
            .unwrap();
        assert_eq!(barrier.evidence().len(), 2);
    }

    #[test]
    fn barrier_error_source_is_none() {
        let err = BarrierError::NoTransitionInProgress;
        assert!(std::error::Error::source(&err).is_none());
    }

    // -- Enrichment batch 3: force cancel edge cases, guard lifecycle, high epochs --

    #[test]
    fn force_cancel_with_zero_in_flight_returns_zero() {
        let mut barrier = det_barrier(1);
        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        let cancelled = barrier.force_cancel_remaining().unwrap();
        assert_eq!(cancelled, 0);
        assert_eq!(barrier.in_flight(), 0);
    }

    #[test]
    fn guard_ids_monotonically_increase() {
        let mut barrier = det_barrier(1);
        let mut prev_id = 0;
        for i in 0..10 {
            let guard = barrier
                .enter_critical(CriticalOpKind::DecisionEval, &format!("t-{i}"))
                .unwrap();
            assert!(guard.guard_id > prev_id);
            prev_id = guard.guard_id;
        }
    }

    #[test]
    fn all_critical_op_kinds_acquire_guards() {
        let mut barrier = det_barrier(1);
        let kinds = [
            CriticalOpKind::DecisionEval,
            CriticalOpKind::EvidenceEmission,
            CriticalOpKind::KeyDerivation,
            CriticalOpKind::CapabilityCheck,
            CriticalOpKind::RevocationCheck,
            CriticalOpKind::RemoteOperation,
        ];
        for kind in &kinds {
            let guard = barrier.enter_critical(*kind, "t").unwrap();
            assert_eq!(guard.op_kind, *kind);
        }
        assert_eq!(barrier.in_flight(), 6);
    }

    #[test]
    fn release_guard_twice_second_fails() {
        let mut barrier = det_barrier(1);
        let guard = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t")
            .unwrap();
        assert!(barrier.release_guard(&guard));
        // Second release: in_flight is 0, returns false
        assert!(!barrier.release_guard(&guard));
    }

    #[test]
    fn guard_from_different_epoch_release_fails() {
        let mut barrier = det_barrier(1);
        let fake = EpochGuard {
            guard_id: 1,
            epoch: SecurityEpoch::from_raw(999),
            op_kind: CriticalOpKind::DecisionEval,
            trace_id: "t".to_string(),
        };
        assert!(!barrier.release_guard(&fake));
    }

    #[test]
    fn barrier_error_display_drain_timeout() {
        let err = BarrierError::DrainTimeout {
            epoch: SecurityEpoch::from_raw(7),
            remaining_guards: 3,
            timeout_ms: 5000,
        };
        let msg = err.to_string();
        assert!(msg.contains("epoch:7"));
        assert!(msg.contains("3 guards remaining"));
        assert!(msg.contains("5000ms"));
    }

    #[test]
    fn barrier_error_display_non_monotonic() {
        let err = BarrierError::NonMonotonicTransition {
            current: SecurityEpoch::from_raw(10),
            attempted: SecurityEpoch::from_raw(5),
        };
        let msg = err.to_string();
        assert!(msg.contains("epoch:10"));
        assert!(msg.contains("epoch:5"));
    }

    #[test]
    fn deterministic_evidence_sequence() {
        let run = || -> Vec<TransitionEvidence> {
            let mut barrier = det_barrier(1);
            let _g = barrier
                .enter_critical(CriticalOpKind::EvidenceEmission, "t1")
                .unwrap();
            barrier
                .transition_now(
                    SecurityEpoch::from_raw(2),
                    TransitionReason::PolicyKeyRotation,
                    "trace-det",
                )
                .unwrap();
            barrier
                .transition_now(
                    SecurityEpoch::from_raw(3),
                    TransitionReason::LossMatrixUpdate,
                    "trace-det-2",
                )
                .unwrap();
            barrier.evidence().to_vec()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn barrier_config_deterministic_serde_roundtrip() {
        let cfg = BarrierConfig::deterministic();
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: BarrierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
        assert!(restored.deterministic);
        assert_eq!(restored.drain_timeout_ms, 0);
    }

    #[test]
    fn mixed_guard_kinds_all_drained_before_complete() {
        let mut barrier = det_barrier(1);
        let g1 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .unwrap();
        let g2 = barrier
            .enter_critical(CriticalOpKind::KeyDerivation, "t2")
            .unwrap();
        let g3 = barrier
            .enter_critical(CriticalOpKind::RevocationCheck, "t3")
            .unwrap();

        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        assert_eq!(barrier.in_flight(), 3);
        assert!(!barrier.can_complete());

        barrier.release_guard(&g1);
        barrier.release_guard(&g2);
        assert!(!barrier.can_complete());

        barrier.release_guard(&g3);
        assert!(barrier.can_complete());

        let evidence = barrier.complete_transition().unwrap();
        assert_eq!(evidence.in_flight_at_start, 3);
        assert_eq!(evidence.forced_cancellations, 0);
    }

    #[test]
    fn transition_evidence_correct_trace_id() {
        let mut barrier = det_barrier(1);
        barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "unique-trace-abc",
            )
            .unwrap();
        assert_eq!(barrier.evidence()[0].trace_id, "unique-trace-abc");
    }

    #[test]
    fn barrier_error_transition_already_in_progress_display() {
        let err = BarrierError::TransitionAlreadyInProgress {
            current_epoch: SecurityEpoch::from_raw(42),
        };
        let msg = err.to_string();
        assert!(msg.contains("transition already in progress"));
        assert!(msg.contains("epoch:42"));
    }

    #[test]
    fn barrier_error_no_transition_display() {
        let err = BarrierError::NoTransitionInProgress;
        assert_eq!(err.to_string(), "no transition in progress to complete");
    }

    #[test]
    fn guard_ids_persist_across_transitions() {
        let mut barrier = det_barrier(1);
        let g1 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t")
            .unwrap();
        barrier.release_guard(&g1);

        barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();

        let g2 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t")
            .unwrap();
        // Guard IDs should continue increasing
        assert!(g2.guard_id > g1.guard_id);
    }

    #[test]
    fn complete_transition_resets_state_to_open() {
        let mut barrier = det_barrier(1);
        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        assert_eq!(barrier.state(), BarrierState::Draining);

        barrier.complete_transition().unwrap();
        assert_eq!(barrier.state(), BarrierState::Open);
        // Should be able to acquire guards again
        let guard = barrier
            .enter_critical(CriticalOpKind::CapabilityCheck, "t")
            .unwrap();
        assert_eq!(guard.epoch, SecurityEpoch::from_raw(2));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: JSON field-name stability
    // -----------------------------------------------------------------------

    #[test]
    fn barrier_state_json_field_names_open() {
        let json = serde_json::to_value(BarrierState::Open).unwrap();
        assert_eq!(json, serde_json::json!("Open"));
    }

    #[test]
    fn barrier_state_json_field_names_draining() {
        let json = serde_json::to_value(BarrierState::Draining).unwrap();
        assert_eq!(json, serde_json::json!("Draining"));
    }

    #[test]
    fn barrier_state_json_field_names_finalizing() {
        let json = serde_json::to_value(BarrierState::Finalizing).unwrap();
        assert_eq!(json, serde_json::json!("Finalizing"));
    }

    #[test]
    fn critical_op_kind_json_field_names_all() {
        let expected = [
            (CriticalOpKind::DecisionEval, "DecisionEval"),
            (CriticalOpKind::EvidenceEmission, "EvidenceEmission"),
            (CriticalOpKind::KeyDerivation, "KeyDerivation"),
            (CriticalOpKind::CapabilityCheck, "CapabilityCheck"),
            (CriticalOpKind::RevocationCheck, "RevocationCheck"),
            (CriticalOpKind::RemoteOperation, "RemoteOperation"),
        ];
        for (kind, name) in expected {
            let json = serde_json::to_value(kind).unwrap();
            assert_eq!(json, serde_json::json!(name));
        }
    }

    #[test]
    fn epoch_guard_json_field_names() {
        let guard = EpochGuard {
            guard_id: 1,
            epoch: SecurityEpoch::from_raw(5),
            op_kind: CriticalOpKind::DecisionEval,
            trace_id: "x".to_string(),
        };
        let val = serde_json::to_value(&guard).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("guard_id"));
        assert!(obj.contains_key("epoch"));
        assert!(obj.contains_key("op_kind"));
        assert!(obj.contains_key("trace_id"));
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn transition_evidence_json_field_names() {
        let ev = TransitionEvidence {
            old_epoch: SecurityEpoch::from_raw(1),
            new_epoch: SecurityEpoch::from_raw(2),
            reason: TransitionReason::PolicyKeyRotation,
            in_flight_at_start: 0,
            in_flight_at_complete: 0,
            forced_cancellations: 0,
            duration_ms: 0,
            trace_id: "t".to_string(),
        };
        let val = serde_json::to_value(&ev).unwrap();
        let obj = val.as_object().unwrap();
        for key in [
            "old_epoch",
            "new_epoch",
            "reason",
            "in_flight_at_start",
            "in_flight_at_complete",
            "forced_cancellations",
            "duration_ms",
            "trace_id",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 8);
    }

    #[test]
    fn barrier_config_json_field_names() {
        let cfg = BarrierConfig::default();
        let val = serde_json::to_value(&cfg).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("drain_timeout_ms"));
        assert!(obj.contains_key("deterministic"));
        assert_eq!(obj.len(), 2);
    }

    #[test]
    fn barrier_error_epoch_transitioning_json_field_names() {
        let err = BarrierError::EpochTransitioning {
            current_epoch: SecurityEpoch::from_raw(1),
            state: BarrierState::Draining,
        };
        let val = serde_json::to_value(&err).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("EpochTransitioning"));
        let inner = obj["EpochTransitioning"].as_object().unwrap();
        assert!(inner.contains_key("current_epoch"));
        assert!(inner.contains_key("state"));
    }

    #[test]
    fn barrier_error_drain_timeout_json_field_names() {
        let err = BarrierError::DrainTimeout {
            epoch: SecurityEpoch::from_raw(1),
            remaining_guards: 3,
            timeout_ms: 5000,
        };
        let val = serde_json::to_value(&err).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("DrainTimeout"));
        let inner = obj["DrainTimeout"].as_object().unwrap();
        assert!(inner.contains_key("epoch"));
        assert!(inner.contains_key("remaining_guards"));
        assert!(inner.contains_key("timeout_ms"));
    }

    #[test]
    fn barrier_error_non_monotonic_json_field_names() {
        let err = BarrierError::NonMonotonicTransition {
            current: SecurityEpoch::from_raw(5),
            attempted: SecurityEpoch::from_raw(3),
        };
        let val = serde_json::to_value(&err).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("NonMonotonicTransition"));
        let inner = obj["NonMonotonicTransition"].as_object().unwrap();
        assert!(inner.contains_key("current"));
        assert!(inner.contains_key("attempted"));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 5: Debug distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn barrier_state_debug_all_distinct() {
        let states = [
            BarrierState::Open,
            BarrierState::Draining,
            BarrierState::Finalizing,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for s in &states {
            seen.insert(format!("{s:?}"));
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn critical_op_kind_debug_all_distinct() {
        let kinds = [
            CriticalOpKind::DecisionEval,
            CriticalOpKind::EvidenceEmission,
            CriticalOpKind::KeyDerivation,
            CriticalOpKind::CapabilityCheck,
            CriticalOpKind::RevocationCheck,
            CriticalOpKind::RemoteOperation,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for k in &kinds {
            seen.insert(format!("{k:?}"));
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn barrier_error_debug_all_distinct() {
        let variants = [
            BarrierError::EpochTransitioning {
                current_epoch: SecurityEpoch::from_raw(1),
                state: BarrierState::Draining,
            },
            BarrierError::TransitionAlreadyInProgress {
                current_epoch: SecurityEpoch::from_raw(1),
            },
            BarrierError::DrainTimeout {
                epoch: SecurityEpoch::from_raw(1),
                remaining_guards: 1,
                timeout_ms: 1,
            },
            BarrierError::NoTransitionInProgress,
            BarrierError::NonMonotonicTransition {
                current: SecurityEpoch::from_raw(1),
                attempted: SecurityEpoch::from_raw(0),
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            seen.insert(format!("{v:?}"));
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn epoch_guard_debug_contains_fields() {
        let guard = EpochGuard {
            guard_id: 42,
            epoch: SecurityEpoch::from_raw(7),
            op_kind: CriticalOpKind::CapabilityCheck,
            trace_id: "trace-dbg".to_string(),
        };
        let dbg = format!("{guard:?}");
        assert!(dbg.contains("42"));
        assert!(dbg.contains("CapabilityCheck"));
        assert!(dbg.contains("trace-dbg"));
    }

    #[test]
    fn transition_evidence_debug_contains_epochs() {
        let ev = TransitionEvidence {
            old_epoch: SecurityEpoch::from_raw(10),
            new_epoch: SecurityEpoch::from_raw(11),
            reason: TransitionReason::PolicyKeyRotation,
            in_flight_at_start: 2,
            in_flight_at_complete: 0,
            forced_cancellations: 1,
            duration_ms: 0,
            trace_id: "dbg-ev".to_string(),
        };
        let dbg = format!("{ev:?}");
        assert!(dbg.contains("old_epoch"));
        assert!(dbg.contains("new_epoch"));
        assert!(dbg.contains("dbg-ev"));
    }

    #[test]
    fn barrier_config_debug_contains_fields() {
        let cfg = BarrierConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("drain_timeout_ms"));
        assert!(dbg.contains("deterministic"));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 6: Clone independence
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_guard_clone_independence() {
        let guard = EpochGuard {
            guard_id: 10,
            epoch: SecurityEpoch::from_raw(3),
            op_kind: CriticalOpKind::EvidenceEmission,
            trace_id: "clone-test".to_string(),
        };
        let cloned = guard.clone();
        assert_eq!(guard, cloned);
        // Mutations on clone don't affect original (trace_id is String)
        let mut modified = cloned;
        modified.guard_id = 999;
        assert_ne!(guard.guard_id, modified.guard_id);
    }

    #[test]
    fn transition_evidence_clone_independence() {
        let ev = TransitionEvidence {
            old_epoch: SecurityEpoch::from_raw(1),
            new_epoch: SecurityEpoch::from_raw(2),
            reason: TransitionReason::LossMatrixUpdate,
            in_flight_at_start: 5,
            in_flight_at_complete: 0,
            forced_cancellations: 3,
            duration_ms: 100,
            trace_id: "clone-ev".to_string(),
        };
        let cloned = ev.clone();
        assert_eq!(ev, cloned);
        let mut modified = cloned;
        modified.forced_cancellations = 999;
        assert_ne!(ev.forced_cancellations, modified.forced_cancellations);
    }

    #[test]
    fn barrier_config_clone_independence() {
        let cfg = BarrierConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
        let mut modified = cloned;
        modified.drain_timeout_ms = 99999;
        assert_ne!(cfg.drain_timeout_ms, modified.drain_timeout_ms);
    }

    #[test]
    fn barrier_error_clone_independence() {
        let err = BarrierError::DrainTimeout {
            epoch: SecurityEpoch::from_raw(5),
            remaining_guards: 10,
            timeout_ms: 3000,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 7: Copy semantics
    // -----------------------------------------------------------------------

    #[test]
    fn barrier_state_copy_semantics() {
        let state = BarrierState::Open;
        let copied = state;
        // Both are still valid after copy
        assert_eq!(state, copied);
        assert_eq!(state, BarrierState::Open);
    }

    #[test]
    fn critical_op_kind_copy_semantics() {
        let kind = CriticalOpKind::KeyDerivation;
        let copied = kind;
        assert_eq!(kind, copied);
        assert_eq!(kind, CriticalOpKind::KeyDerivation);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 8: Hash consistency (CriticalOpKind)
    // -----------------------------------------------------------------------

    #[test]
    fn critical_op_kind_hash_consistent_across_calls() {
        use std::hash::{Hash, Hasher};
        let kind = CriticalOpKind::RevocationCheck;
        let hash1 = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            kind.hash(&mut h);
            h.finish()
        };
        let hash2 = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            kind.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn critical_op_kind_hash_distinct_for_different_variants() {
        use std::hash::{Hash, Hasher};
        let kinds = [
            CriticalOpKind::DecisionEval,
            CriticalOpKind::EvidenceEmission,
            CriticalOpKind::KeyDerivation,
            CriticalOpKind::CapabilityCheck,
            CriticalOpKind::RevocationCheck,
            CriticalOpKind::RemoteOperation,
        ];
        let mut hashes = std::collections::BTreeSet::new();
        for k in &kinds {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            k.hash(&mut h);
            hashes.insert(h.finish());
        }
        assert_eq!(
            hashes.len(),
            6,
            "all CriticalOpKind hashes should be distinct"
        );
    }

    #[test]
    fn critical_op_kind_btreeset_contains_all_variants() {
        let mut set = std::collections::BTreeSet::new();
        set.insert(CriticalOpKind::DecisionEval);
        set.insert(CriticalOpKind::EvidenceEmission);
        set.insert(CriticalOpKind::KeyDerivation);
        set.insert(CriticalOpKind::CapabilityCheck);
        set.insert(CriticalOpKind::RevocationCheck);
        set.insert(CriticalOpKind::RemoteOperation);
        assert_eq!(set.len(), 6);
        // Inserting duplicate should not increase size
        set.insert(CriticalOpKind::DecisionEval);
        assert_eq!(set.len(), 6);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 9: Serde variant distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn barrier_state_serde_variant_json_strings_distinct() {
        let states = [
            BarrierState::Open,
            BarrierState::Draining,
            BarrierState::Finalizing,
        ];
        let mut json_strs = std::collections::BTreeSet::new();
        for s in &states {
            json_strs.insert(serde_json::to_string(s).unwrap());
        }
        assert_eq!(json_strs.len(), 3);
    }

    #[test]
    fn critical_op_kind_serde_variant_json_strings_distinct() {
        let kinds = [
            CriticalOpKind::DecisionEval,
            CriticalOpKind::EvidenceEmission,
            CriticalOpKind::KeyDerivation,
            CriticalOpKind::CapabilityCheck,
            CriticalOpKind::RevocationCheck,
            CriticalOpKind::RemoteOperation,
        ];
        let mut json_strs = std::collections::BTreeSet::new();
        for k in &kinds {
            json_strs.insert(serde_json::to_string(k).unwrap());
        }
        assert_eq!(json_strs.len(), 6);
    }

    #[test]
    fn barrier_error_serde_variant_json_strings_distinct() {
        let errors = [
            BarrierError::EpochTransitioning {
                current_epoch: SecurityEpoch::from_raw(1),
                state: BarrierState::Draining,
            },
            BarrierError::TransitionAlreadyInProgress {
                current_epoch: SecurityEpoch::from_raw(1),
            },
            BarrierError::DrainTimeout {
                epoch: SecurityEpoch::from_raw(1),
                remaining_guards: 1,
                timeout_ms: 1,
            },
            BarrierError::NoTransitionInProgress,
            BarrierError::NonMonotonicTransition {
                current: SecurityEpoch::from_raw(1),
                attempted: SecurityEpoch::from_raw(0),
            },
        ];
        let mut json_strs = std::collections::BTreeSet::new();
        for e in &errors {
            json_strs.insert(serde_json::to_string(e).unwrap());
        }
        assert_eq!(json_strs.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 10: Boundary and edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn barrier_at_epoch_zero() {
        let mut barrier = det_barrier(0);
        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(0));
        let guard = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t0")
            .unwrap();
        assert_eq!(guard.epoch, SecurityEpoch::from_raw(0));
        barrier.release_guard(&guard);
    }

    #[test]
    fn barrier_transition_from_zero_to_one() {
        let mut barrier = det_barrier(0);
        let ev = barrier
            .transition_now(
                SecurityEpoch::from_raw(1),
                TransitionReason::OperatorManualBump,
                "t-zero-one",
            )
            .unwrap();
        assert_eq!(ev.old_epoch, SecurityEpoch::from_raw(0));
        assert_eq!(ev.new_epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn barrier_at_high_epoch() {
        let high = u64::MAX - 1;
        let mut barrier = det_barrier(high);
        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(high));
        let ev = barrier
            .transition_now(
                SecurityEpoch::from_raw(u64::MAX),
                TransitionReason::PolicyKeyRotation,
                "t-high",
            )
            .unwrap();
        assert_eq!(ev.new_epoch, SecurityEpoch::from_raw(u64::MAX));
    }

    #[test]
    fn large_number_of_guards() {
        let mut barrier = det_barrier(1);
        let mut guards = Vec::new();
        for i in 0..100 {
            let guard = barrier
                .enter_critical(CriticalOpKind::EvidenceEmission, &format!("t-{i}"))
                .unwrap();
            guards.push(guard);
        }
        assert_eq!(barrier.in_flight(), 100);
        for g in &guards {
            barrier.release_guard(g);
        }
        assert_eq!(barrier.in_flight(), 0);
    }

    #[test]
    fn transition_with_many_force_cancelled_guards() {
        let mut barrier = det_barrier(1);
        for i in 0..50 {
            let _g = barrier
                .enter_critical(CriticalOpKind::CapabilityCheck, &format!("t-{i}"))
                .unwrap();
        }
        assert_eq!(barrier.in_flight(), 50);

        let ev = barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::RevocationFrontierAdvance,
                "t-mass-cancel",
            )
            .unwrap();
        assert_eq!(ev.forced_cancellations, 50);
        assert_eq!(ev.in_flight_at_start, 50);
    }

    #[test]
    fn transition_evidence_reason_preserved() {
        let reasons = [
            TransitionReason::PolicyKeyRotation,
            TransitionReason::RevocationFrontierAdvance,
            TransitionReason::GuardrailConfigChange,
            TransitionReason::LossMatrixUpdate,
            TransitionReason::RemoteTrustConfigChange,
            TransitionReason::OperatorManualBump,
        ];
        let mut barrier = det_barrier(1);
        for (i, reason) in reasons.iter().enumerate() {
            let epoch = (i as u64) + 2;
            let ev = barrier
                .transition_now(
                    SecurityEpoch::from_raw(epoch),
                    reason.clone(),
                    &format!("t-reason-{i}"),
                )
                .unwrap();
            assert_eq!(ev.reason, *reason);
        }
        assert_eq!(barrier.evidence().len(), 6);
    }

    #[test]
    fn guard_trace_id_preserved_through_serde() {
        let guard = EpochGuard {
            guard_id: 1,
            epoch: SecurityEpoch::from_raw(1),
            op_kind: CriticalOpKind::DecisionEval,
            trace_id: "a/b/c:complex-trace-id_123".to_string(),
        };
        let json = serde_json::to_string(&guard).unwrap();
        let restored: EpochGuard = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.trace_id, "a/b/c:complex-trace-id_123");
    }

    #[test]
    fn evidence_trace_id_with_special_chars() {
        let mut barrier = det_barrier(1);
        let trace = "trace/with:special-chars_and.dots";
        barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                trace,
            )
            .unwrap();
        assert_eq!(barrier.evidence()[0].trace_id, trace);
    }

    #[test]
    fn empty_trace_id_allowed() {
        let mut barrier = det_barrier(1);
        let guard = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "")
            .unwrap();
        assert_eq!(guard.trace_id, "");
        barrier.release_guard(&guard);
    }

    #[test]
    fn barrier_error_epoch_transitioning_finalizing_state() {
        let err = BarrierError::EpochTransitioning {
            current_epoch: SecurityEpoch::from_raw(3),
            state: BarrierState::Finalizing,
        };
        let msg = err.to_string();
        assert!(msg.contains("finalizing"));
        assert!(msg.contains("epoch:3"));
    }

    #[test]
    fn barrier_error_drain_timeout_zero_remaining() {
        let err = BarrierError::DrainTimeout {
            epoch: SecurityEpoch::from_raw(1),
            remaining_guards: 0,
            timeout_ms: 0,
        };
        let msg = err.to_string();
        assert!(msg.contains("0 guards remaining"));
        assert!(msg.contains("0ms"));
    }

    #[test]
    fn barrier_error_non_monotonic_same_epoch_display() {
        let err = BarrierError::NonMonotonicTransition {
            current: SecurityEpoch::from_raw(5),
            attempted: SecurityEpoch::from_raw(5),
        };
        let msg = err.to_string();
        assert!(msg.contains("non-monotonic"));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 11: Transition protocol edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn begin_transition_returns_correct_in_flight_count() {
        let mut barrier = det_barrier(1);
        let _g1 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .unwrap();
        let _g2 = barrier
            .enter_critical(CriticalOpKind::KeyDerivation, "t2")
            .unwrap();
        let _g3 = barrier
            .enter_critical(CriticalOpKind::RemoteOperation, "t3")
            .unwrap();

        let in_flight = barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        assert_eq!(in_flight, 3);
    }

    #[test]
    fn partial_drain_then_force_cancel() {
        let mut barrier = det_barrier(1);
        let g1 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .unwrap();
        let _g2 = barrier
            .enter_critical(CriticalOpKind::KeyDerivation, "t2")
            .unwrap();
        let _g3 = barrier
            .enter_critical(CriticalOpKind::RemoteOperation, "t3")
            .unwrap();

        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();

        // Release one guard manually
        barrier.release_guard(&g1);
        assert_eq!(barrier.in_flight(), 2);

        // Force cancel the remaining 2
        let cancelled = barrier.force_cancel_remaining().unwrap();
        assert_eq!(cancelled, 2);
        assert!(barrier.can_complete());

        let ev = barrier.complete_transition().unwrap();
        assert_eq!(ev.in_flight_at_start, 3);
        assert_eq!(ev.forced_cancellations, 2);
    }

    #[test]
    fn transition_now_non_monotonic_returns_error() {
        let mut barrier = det_barrier(10);
        let err = barrier
            .transition_now(
                SecurityEpoch::from_raw(5),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap_err();
        assert!(matches!(err, BarrierError::NonMonotonicTransition { .. }));
    }

    #[test]
    fn guard_epoch_matches_barrier_epoch_at_acquisition() {
        let mut barrier = det_barrier(42);
        let guard = barrier
            .enter_critical(CriticalOpKind::EvidenceEmission, "t")
            .unwrap();
        assert_eq!(guard.epoch, barrier.current_epoch());
    }

    #[test]
    fn barrier_state_after_begin_transition() {
        let mut barrier = det_barrier(1);
        assert_eq!(barrier.state(), BarrierState::Open);

        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        assert_eq!(barrier.state(), BarrierState::Draining);
    }

    #[test]
    fn evidence_in_flight_at_complete_is_zero() {
        let mut barrier = det_barrier(1);
        let _g = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t")
            .unwrap();
        let ev = barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        assert_eq!(ev.in_flight_at_complete, 0);
    }

    #[test]
    fn evidence_duration_ms_is_zero_in_deterministic_mode() {
        let mut barrier = det_barrier(1);
        let ev = barrier
            .transition_now(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        assert_eq!(ev.duration_ms, 0);
    }

    #[test]
    fn multiple_force_cancels_accumulate() {
        let mut barrier = det_barrier(1);
        let _g1 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .unwrap();

        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();

        // First force cancel: cancels the 1 in-flight guard
        let cancelled1 = barrier.force_cancel_remaining().unwrap();
        assert_eq!(cancelled1, 1);

        // Second force cancel: nothing to cancel
        let cancelled2 = barrier.force_cancel_remaining().unwrap();
        assert_eq!(cancelled2, 0);

        let ev = barrier.complete_transition().unwrap();
        // forced_cancellations accumulates: 1 + 0 = 1
        assert_eq!(ev.forced_cancellations, 1);
    }

    #[test]
    fn can_complete_false_when_guards_still_held() {
        let mut barrier = det_barrier(1);
        let _g = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t")
            .unwrap();
        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "t",
            )
            .unwrap();
        assert!(!barrier.can_complete());
    }

    #[test]
    fn epoch_skipping_allowed() {
        let mut barrier = det_barrier(1);
        let ev = barrier
            .transition_now(
                SecurityEpoch::from_raw(100),
                TransitionReason::OperatorManualBump,
                "skip",
            )
            .unwrap();
        assert_eq!(ev.old_epoch, SecurityEpoch::from_raw(1));
        assert_eq!(ev.new_epoch, SecurityEpoch::from_raw(100));
        assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(100));
    }

    #[test]
    fn serde_roundtrip_barrier_config_custom_timeout() {
        let cfg = BarrierConfig {
            drain_timeout_ms: 999_999,
            deterministic: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: BarrierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
    }

    #[test]
    fn serde_roundtrip_guard_all_op_kinds() {
        for (i, kind) in [
            CriticalOpKind::DecisionEval,
            CriticalOpKind::EvidenceEmission,
            CriticalOpKind::KeyDerivation,
            CriticalOpKind::CapabilityCheck,
            CriticalOpKind::RevocationCheck,
            CriticalOpKind::RemoteOperation,
        ]
        .iter()
        .enumerate()
        {
            let guard = EpochGuard {
                guard_id: i as u64,
                epoch: SecurityEpoch::from_raw(1),
                op_kind: *kind,
                trace_id: format!("serde-{i}"),
            };
            let json = serde_json::to_string(&guard).unwrap();
            let restored: EpochGuard = serde_json::from_str(&json).unwrap();
            assert_eq!(guard, restored);
        }
    }

    #[test]
    fn serde_roundtrip_evidence_all_transition_reasons() {
        let reasons = [
            TransitionReason::PolicyKeyRotation,
            TransitionReason::RevocationFrontierAdvance,
            TransitionReason::GuardrailConfigChange,
            TransitionReason::LossMatrixUpdate,
            TransitionReason::RemoteTrustConfigChange,
            TransitionReason::OperatorManualBump,
        ];
        for (i, reason) in reasons.iter().enumerate() {
            let ev = TransitionEvidence {
                old_epoch: SecurityEpoch::from_raw(i as u64),
                new_epoch: SecurityEpoch::from_raw(i as u64 + 1),
                reason: reason.clone(),
                in_flight_at_start: i as u64,
                in_flight_at_complete: 0,
                forced_cancellations: 0,
                duration_ms: i as u64 * 10,
                trace_id: format!("reason-{i}"),
            };
            let json = serde_json::to_string(&ev).unwrap();
            let restored: TransitionEvidence = serde_json::from_str(&json).unwrap();
            assert_eq!(ev, restored);
        }
    }

    #[test]
    fn barrier_error_epoch_transitioning_with_each_state() {
        for state in [
            BarrierState::Open,
            BarrierState::Draining,
            BarrierState::Finalizing,
        ] {
            let err = BarrierError::EpochTransitioning {
                current_epoch: SecurityEpoch::from_raw(1),
                state,
            };
            let json = serde_json::to_string(&err).unwrap();
            let restored: BarrierError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, restored);
        }
    }
}
