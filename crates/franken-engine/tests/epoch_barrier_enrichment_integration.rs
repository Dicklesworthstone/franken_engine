#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

//! Enrichment integration tests for the `epoch_barrier` module.
//!
//! Covers: serde roundtrips for all types, Display distinctness, Default
//! values, deterministic behavior, advanced transition scenarios, edge
//! cases, evidence recording, and guard lifecycle interactions.

use std::collections::BTreeSet;

use frankenengine_engine::epoch_barrier::{
    BarrierConfig, BarrierError, BarrierState, CriticalOpKind, EpochBarrier, EpochGuard,
    TransitionEvidence,
};
use frankenengine_engine::security_epoch::{SecurityEpoch, TransitionReason};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn det_barrier(epoch: u64) -> EpochBarrier {
    EpochBarrier::new(
        SecurityEpoch::from_raw(epoch),
        BarrierConfig::deterministic(),
    )
}

// ===========================================================================
// BarrierState — serde and Display
// ===========================================================================

#[test]
fn barrier_state_serde_roundtrip_all_variants() {
    let variants = [
        BarrierState::Open,
        BarrierState::Draining,
        BarrierState::Finalizing,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: BarrierState = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn barrier_state_display_all_distinct() {
    let mut set = BTreeSet::new();
    set.insert(BarrierState::Open.to_string());
    set.insert(BarrierState::Draining.to_string());
    set.insert(BarrierState::Finalizing.to_string());
    assert_eq!(set.len(), 3);
}

#[test]
fn barrier_state_display_lowercase() {
    assert_eq!(BarrierState::Open.to_string(), "open");
    assert_eq!(BarrierState::Draining.to_string(), "draining");
    assert_eq!(BarrierState::Finalizing.to_string(), "finalizing");
}

#[test]
fn barrier_state_clone_copy_eq() {
    let s = BarrierState::Draining;
    let s2 = s;
    assert_eq!(s, s2);
}

// ===========================================================================
// CriticalOpKind — serde and Display
// ===========================================================================

#[test]
fn critical_op_kind_serde_roundtrip_all_variants() {
    let variants = [
        CriticalOpKind::DecisionEval,
        CriticalOpKind::EvidenceEmission,
        CriticalOpKind::KeyDerivation,
        CriticalOpKind::CapabilityCheck,
        CriticalOpKind::RevocationCheck,
        CriticalOpKind::RemoteOperation,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: CriticalOpKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn critical_op_kind_display_all_distinct() {
    let mut set = BTreeSet::new();
    set.insert(CriticalOpKind::DecisionEval.to_string());
    set.insert(CriticalOpKind::EvidenceEmission.to_string());
    set.insert(CriticalOpKind::KeyDerivation.to_string());
    set.insert(CriticalOpKind::CapabilityCheck.to_string());
    set.insert(CriticalOpKind::RevocationCheck.to_string());
    set.insert(CriticalOpKind::RemoteOperation.to_string());
    assert_eq!(set.len(), 6);
}

#[test]
fn critical_op_kind_display_snake_case() {
    assert_eq!(CriticalOpKind::DecisionEval.to_string(), "decision_eval");
    assert_eq!(CriticalOpKind::EvidenceEmission.to_string(), "evidence_emission");
    assert_eq!(CriticalOpKind::KeyDerivation.to_string(), "key_derivation");
    assert_eq!(CriticalOpKind::CapabilityCheck.to_string(), "capability_check");
    assert_eq!(CriticalOpKind::RevocationCheck.to_string(), "revocation_check");
    assert_eq!(CriticalOpKind::RemoteOperation.to_string(), "remote_operation");
}

#[test]
fn critical_op_kind_ord() {
    assert!(CriticalOpKind::DecisionEval < CriticalOpKind::EvidenceEmission);
    assert!(CriticalOpKind::EvidenceEmission < CriticalOpKind::KeyDerivation);
}

// ===========================================================================
// BarrierConfig — Default, serde
// ===========================================================================

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
fn barrier_config_serde_roundtrip() {
    let cfg = BarrierConfig {
        drain_timeout_ms: 12345,
        deterministic: true,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: BarrierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn barrier_config_default_serde_roundtrip() {
    let cfg = BarrierConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: BarrierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// EpochGuard — serde and Display
// ===========================================================================

#[test]
fn epoch_guard_serde_roundtrip() {
    let guard = EpochGuard {
        guard_id: 42,
        epoch: SecurityEpoch::from_raw(7),
        op_kind: CriticalOpKind::KeyDerivation,
        trace_id: "trace-001".to_string(),
    };
    let json = serde_json::to_string(&guard).unwrap();
    let back: EpochGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard, back);
}

#[test]
fn epoch_guard_display_contains_id_epoch_and_kind() {
    let guard = EpochGuard {
        guard_id: 5,
        epoch: SecurityEpoch::from_raw(10),
        op_kind: CriticalOpKind::CapabilityCheck,
        trace_id: "t".to_string(),
    };
    let display = guard.to_string();
    assert!(display.contains("#5"), "display={display}");
    assert!(display.contains("capability_check"), "display={display}");
}

#[test]
fn epoch_guard_fields_accessible() {
    let guard = EpochGuard {
        guard_id: 99,
        epoch: SecurityEpoch::from_raw(3),
        op_kind: CriticalOpKind::RevocationCheck,
        trace_id: "my-trace".to_string(),
    };
    assert_eq!(guard.guard_id, 99);
    assert_eq!(guard.epoch, SecurityEpoch::from_raw(3));
    assert_eq!(guard.op_kind, CriticalOpKind::RevocationCheck);
    assert_eq!(guard.trace_id, "my-trace");
}

// ===========================================================================
// TransitionEvidence — serde
// ===========================================================================

#[test]
fn transition_evidence_serde_roundtrip() {
    let ev = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(1),
        new_epoch: SecurityEpoch::from_raw(2),
        reason: TransitionReason::PolicyKeyRotation,
        in_flight_at_start: 5,
        in_flight_at_complete: 0,
        forced_cancellations: 3,
        duration_ms: 42,
        trace_id: "tr-1".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: TransitionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn transition_evidence_fields_accessible() {
    let ev = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(10),
        new_epoch: SecurityEpoch::from_raw(11),
        reason: TransitionReason::RevocationFrontierAdvance,
        in_flight_at_start: 2,
        in_flight_at_complete: 0,
        forced_cancellations: 1,
        duration_ms: 100,
        trace_id: "trace-xyz".to_string(),
    };
    assert_eq!(ev.old_epoch, SecurityEpoch::from_raw(10));
    assert_eq!(ev.new_epoch, SecurityEpoch::from_raw(11));
    assert_eq!(ev.in_flight_at_start, 2);
    assert_eq!(ev.in_flight_at_complete, 0);
    assert_eq!(ev.forced_cancellations, 1);
    assert_eq!(ev.duration_ms, 100);
    assert_eq!(ev.trace_id, "trace-xyz");
}

// ===========================================================================
// BarrierError — serde and Display
// ===========================================================================

#[test]
fn barrier_error_serde_roundtrip_all_variants() {
    let variants = vec![
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
            current: SecurityEpoch::from_raw(10),
            attempted: SecurityEpoch::from_raw(5),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: BarrierError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn barrier_error_display_all_distinct() {
    let displays: Vec<String> = vec![
        BarrierError::EpochTransitioning {
            current_epoch: SecurityEpoch::from_raw(1),
            state: BarrierState::Draining,
        }
        .to_string(),
        BarrierError::TransitionAlreadyInProgress {
            current_epoch: SecurityEpoch::from_raw(2),
        }
        .to_string(),
        BarrierError::DrainTimeout {
            epoch: SecurityEpoch::from_raw(3),
            remaining_guards: 5,
            timeout_ms: 5000,
        }
        .to_string(),
        BarrierError::NoTransitionInProgress.to_string(),
        BarrierError::NonMonotonicTransition {
            current: SecurityEpoch::from_raw(10),
            attempted: SecurityEpoch::from_raw(5),
        }
        .to_string(),
    ];
    let set: BTreeSet<&str> = displays.iter().map(String::as_str).collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn barrier_error_display_epoch_transitioning_contains_state() {
    let err = BarrierError::EpochTransitioning {
        current_epoch: SecurityEpoch::from_raw(1),
        state: BarrierState::Draining,
    };
    let msg = err.to_string();
    assert!(msg.contains("draining"), "msg={msg}");
}

#[test]
fn barrier_error_display_drain_timeout_contains_guard_count() {
    let err = BarrierError::DrainTimeout {
        epoch: SecurityEpoch::from_raw(3),
        remaining_guards: 7,
        timeout_ms: 5000,
    };
    let msg = err.to_string();
    assert!(msg.contains("7"), "msg={msg}");
    assert!(msg.contains("5000"), "msg={msg}");
}

#[test]
fn barrier_error_display_non_monotonic() {
    let err = BarrierError::NonMonotonicTransition {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    let msg = err.to_string();
    assert!(msg.contains("non-monotonic"), "msg={msg}");
}

// ===========================================================================
// EpochBarrier — advanced transition scenarios
// ===========================================================================

#[test]
fn transition_now_with_no_guards_succeeds() {
    let mut barrier = det_barrier(1);
    let ev = barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t1",
        )
        .unwrap();
    assert_eq!(ev.old_epoch, SecurityEpoch::from_raw(1));
    assert_eq!(ev.new_epoch, SecurityEpoch::from_raw(2));
    assert_eq!(ev.in_flight_at_start, 0);
    assert_eq!(ev.forced_cancellations, 0);
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(2));
    assert_eq!(barrier.state(), BarrierState::Open);
}

#[test]
fn transition_now_with_active_guards_force_cancels() {
    let mut barrier = det_barrier(1);
    let _g = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .unwrap();
    let ev = barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::RevocationFrontierAdvance,
            "t2",
        )
        .unwrap();
    assert_eq!(ev.forced_cancellations, 1);
    assert_eq!(barrier.in_flight(), 0);
}

#[test]
fn multiple_sequential_transitions_accumulate_evidence() {
    let mut barrier = det_barrier(1);
    for i in 2..=5 {
        barrier
            .transition_now(
                SecurityEpoch::from_raw(i),
                TransitionReason::PolicyKeyRotation,
                &format!("t-{i}"),
            )
            .unwrap();
    }
    assert_eq!(barrier.evidence().len(), 4);
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(5));
}

#[test]
fn non_monotonic_transition_rejected() {
    let mut barrier = det_barrier(10);
    let err = barrier
        .begin_transition(
            SecurityEpoch::from_raw(5),
            TransitionReason::PolicyKeyRotation,
            "t1",
        )
        .unwrap_err();
    assert!(matches!(
        err,
        BarrierError::NonMonotonicTransition { .. }
    ));
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
    assert!(matches!(
        err,
        BarrierError::NonMonotonicTransition { .. }
    ));
}

#[test]
fn enter_critical_during_draining_rejected() {
    let mut barrier = det_barrier(1);
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::RevocationFrontierAdvance,
            "t1",
        )
        .unwrap();
    let err = barrier
        .enter_critical(CriticalOpKind::KeyDerivation, "t2")
        .unwrap_err();
    assert!(matches!(
        err,
        BarrierError::EpochTransitioning { state: BarrierState::Draining, .. }
    ));
}

#[test]
fn complete_transition_with_guards_fails() {
    let mut barrier = det_barrier(1);
    let _g = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .unwrap();
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t2",
        )
        .unwrap();
    let err = barrier.complete_transition().unwrap_err();
    assert!(matches!(err, BarrierError::DrainTimeout { .. }));
}

#[test]
fn release_stale_guard_returns_false() {
    let mut barrier = det_barrier(1);
    let guard = barrier
        .enter_critical(CriticalOpKind::EvidenceEmission, "t1")
        .unwrap();
    barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::RevocationFrontierAdvance,
            "t2",
        )
        .unwrap();
    // guard is from epoch 1, barrier is now at epoch 2
    assert!(!barrier.release_guard(&guard));
}

#[test]
fn can_complete_is_false_when_open() {
    let barrier = det_barrier(1);
    assert!(!barrier.can_complete());
}

#[test]
fn can_complete_is_true_after_drain_with_zero_guards() {
    let mut barrier = det_barrier(1);
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t1",
        )
        .unwrap();
    assert!(barrier.can_complete());
}

#[test]
fn force_cancel_remaining_when_not_draining_fails() {
    let mut barrier = det_barrier(1);
    let err = barrier.force_cancel_remaining().unwrap_err();
    assert!(matches!(err, BarrierError::NoTransitionInProgress));
}

#[test]
fn complete_transition_when_open_fails() {
    let mut barrier = det_barrier(1);
    let err = barrier.complete_transition().unwrap_err();
    assert!(matches!(err, BarrierError::NoTransitionInProgress));
}

#[test]
fn config_accessor_returns_correct_config() {
    let cfg = BarrierConfig {
        drain_timeout_ms: 999,
        deterministic: true,
    };
    let barrier = EpochBarrier::new(SecurityEpoch::from_raw(1), cfg.clone());
    assert_eq!(*barrier.config(), cfg);
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn deterministic_transition_cycle_produces_same_evidence() {
    let run = || {
        let mut barrier = det_barrier(1);
        for i in 2..=4 {
            barrier
                .enter_critical(CriticalOpKind::DecisionEval, &format!("t-{i}"))
                .unwrap();
            barrier
                .transition_now(
                    SecurityEpoch::from_raw(i),
                    TransitionReason::PolicyKeyRotation,
                    &format!("trans-{i}"),
                )
                .unwrap();
        }
        serde_json::to_string(barrier.evidence()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn guard_ids_are_monotonically_increasing() {
    let mut barrier = det_barrier(1);
    let g1 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t")
        .unwrap();
    let g2 = barrier
        .enter_critical(CriticalOpKind::EvidenceEmission, "t")
        .unwrap();
    let g3 = barrier
        .enter_critical(CriticalOpKind::KeyDerivation, "t")
        .unwrap();
    assert!(g1.guard_id < g2.guard_id);
    assert!(g2.guard_id < g3.guard_id);
}

#[test]
fn enter_critical_all_six_op_kinds() {
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
        barrier.enter_critical(*kind, "t").unwrap();
    }
    assert_eq!(barrier.in_flight(), 6);
}

#[test]
fn begin_transition_returns_inflight_count() {
    let mut barrier = det_barrier(1);
    barrier.enter_critical(CriticalOpKind::DecisionEval, "t").unwrap();
    barrier.enter_critical(CriticalOpKind::EvidenceEmission, "t").unwrap();
    let count = barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn double_begin_transition_fails() {
    let mut barrier = det_barrier(1);
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap();
    let err = barrier
        .begin_transition(
            SecurityEpoch::from_raw(3),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap_err();
    assert!(matches!(
        err,
        BarrierError::TransitionAlreadyInProgress { .. }
    ));
}

#[test]
fn drain_then_release_then_complete() {
    let mut barrier = det_barrier(1);
    let g1 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t")
        .unwrap();
    let g2 = barrier
        .enter_critical(CriticalOpKind::KeyDerivation, "t")
        .unwrap();
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap();
    assert!(!barrier.can_complete());
    barrier.release_guard(&g1);
    assert!(!barrier.can_complete());
    barrier.release_guard(&g2);
    assert!(barrier.can_complete());
    let ev = barrier.complete_transition().unwrap();
    assert_eq!(ev.forced_cancellations, 0);
    assert_eq!(ev.in_flight_at_start, 2);
}

#[test]
fn evidence_empty_before_any_transition() {
    let barrier = det_barrier(1);
    assert!(barrier.evidence().is_empty());
}

#[test]
fn release_guard_with_zero_inflight_returns_false() {
    let mut barrier = det_barrier(1);
    let guard = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "t".to_string(),
    };
    // barrier has 0 in-flight
    assert!(!barrier.release_guard(&guard));
}
