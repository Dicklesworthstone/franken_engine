#![forbid(unsafe_code)]

//! Integration tests for the `epoch_barrier` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! barrier construction, guard lifecycle, epoch transitions, error
//! conditions, evidence recording, Display impls, and serde round-trips.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

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

fn default_barrier(epoch: u64) -> EpochBarrier {
    EpochBarrier::new(SecurityEpoch::from_raw(epoch), BarrierConfig::default())
}

// ---------------------------------------------------------------------------
// 1. Construction
// ---------------------------------------------------------------------------

#[test]
fn new_barrier_starts_open_at_given_epoch() {
    let barrier = det_barrier(42);
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(42));
    assert_eq!(barrier.state(), BarrierState::Open);
    assert_eq!(barrier.in_flight(), 0);
    assert!(barrier.evidence().is_empty());
}

#[test]
fn barrier_with_default_config() {
    let barrier = default_barrier(1);
    assert_eq!(barrier.config().drain_timeout_ms, 5000);
    assert!(!barrier.config().deterministic);
}

#[test]
fn barrier_with_deterministic_config() {
    let barrier = det_barrier(1);
    assert_eq!(barrier.config().drain_timeout_ms, 0);
    assert!(barrier.config().deterministic);
}

#[test]
fn barrier_at_genesis_epoch() {
    let barrier = EpochBarrier::new(SecurityEpoch::GENESIS, BarrierConfig::deterministic());
    assert_eq!(barrier.current_epoch(), SecurityEpoch::GENESIS);
    assert_eq!(barrier.current_epoch().as_u64(), 0);
}

// ---------------------------------------------------------------------------
// 2. Guard lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enter_critical_returns_guard_with_correct_fields() {
    let mut barrier = det_barrier(7);
    let guard = barrier
        .enter_critical(CriticalOpKind::KeyDerivation, "trace-abc")
        .expect("enter");
    assert_eq!(guard.guard_id, 1);
    assert_eq!(guard.epoch, SecurityEpoch::from_raw(7));
    assert_eq!(guard.op_kind, CriticalOpKind::KeyDerivation);
    assert_eq!(guard.trace_id, "trace-abc");
}

#[test]
fn guard_ids_increment_monotonically() {
    let mut barrier = det_barrier(1);
    let g1 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .expect("g1");
    let g2 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t2")
        .expect("g2");
    let g3 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t3")
        .expect("g3");
    assert_eq!(g1.guard_id, 1);
    assert_eq!(g2.guard_id, 2);
    assert_eq!(g3.guard_id, 3);
}

#[test]
fn in_flight_count_tracks_guards() {
    let mut barrier = det_barrier(1);
    assert_eq!(barrier.in_flight(), 0);

    let g1 = barrier
        .enter_critical(CriticalOpKind::EvidenceEmission, "t1")
        .expect("g1");
    assert_eq!(barrier.in_flight(), 1);

    let g2 = barrier
        .enter_critical(CriticalOpKind::CapabilityCheck, "t2")
        .expect("g2");
    assert_eq!(barrier.in_flight(), 2);

    assert!(barrier.release_guard(&g1));
    assert_eq!(barrier.in_flight(), 1);

    assert!(barrier.release_guard(&g2));
    assert_eq!(barrier.in_flight(), 0);
}

#[test]
fn release_stale_guard_returns_false() {
    let mut barrier = det_barrier(1);
    let guard = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .expect("g");

    // Transition to epoch 2, which force-cancels the guard.
    barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "tr",
        )
        .expect("transition");

    // Now the guard's epoch (1) does not match current (2).
    assert!(!barrier.release_guard(&guard));
}

#[test]
fn release_guard_when_in_flight_zero_returns_false() {
    let barrier = det_barrier(1);
    let fake_guard = EpochGuard {
        guard_id: 99,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "fake".to_string(),
    };
    // Need a mutable barrier to call release_guard.
    let mut barrier = barrier;
    assert!(!barrier.release_guard(&fake_guard));
}

// ---------------------------------------------------------------------------
// 3. Transition lifecycle (begin + drain + complete)
// ---------------------------------------------------------------------------

#[test]
fn clean_transition_no_in_flight() {
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
    assert!(barrier.can_complete());

    let evidence = barrier.complete_transition().expect("complete");
    assert_eq!(evidence.old_epoch, SecurityEpoch::from_raw(1));
    assert_eq!(evidence.new_epoch, SecurityEpoch::from_raw(2));
    assert_eq!(evidence.reason, TransitionReason::PolicyKeyRotation);
    assert_eq!(evidence.in_flight_at_start, 0);
    assert_eq!(evidence.in_flight_at_complete, 0);
    assert_eq!(evidence.forced_cancellations, 0);
    assert_eq!(evidence.trace_id, "trace-1");
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(2));
    assert_eq!(barrier.state(), BarrierState::Open);
}

#[test]
fn transition_drains_guards_before_completing() {
    let mut barrier = det_barrier(1);
    let g1 = barrier
        .enter_critical(CriticalOpKind::RevocationCheck, "t1")
        .expect("g1");
    let g2 = barrier
        .enter_critical(CriticalOpKind::RemoteOperation, "t2")
        .expect("g2");

    let in_flight = barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::RevocationFrontierAdvance,
            "trace-2",
        )
        .expect("begin");
    assert_eq!(in_flight, 2);
    assert!(!barrier.can_complete());

    barrier.release_guard(&g1);
    assert!(!barrier.can_complete());
    barrier.release_guard(&g2);
    assert!(barrier.can_complete());

    let evidence = barrier.complete_transition().expect("complete");
    assert_eq!(evidence.in_flight_at_start, 2);
    assert_eq!(evidence.forced_cancellations, 0);
}

#[test]
fn force_cancel_clears_in_flight_guards() {
    let mut barrier = det_barrier(1);
    let _g1 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .expect("g1");
    let _g2 = barrier
        .enter_critical(CriticalOpKind::EvidenceEmission, "t2")
        .expect("g2");
    let _g3 = barrier
        .enter_critical(CriticalOpKind::KeyDerivation, "t3")
        .expect("g3");

    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::GuardrailConfigChange,
            "trace-3",
        )
        .expect("begin");

    let cancelled = barrier.force_cancel_remaining().expect("cancel");
    assert_eq!(cancelled, 3);
    assert_eq!(barrier.in_flight(), 0);
    assert!(barrier.can_complete());

    let evidence = barrier.complete_transition().expect("complete");
    assert_eq!(evidence.forced_cancellations, 3);
    assert_eq!(evidence.in_flight_at_start, 3);
}

// ---------------------------------------------------------------------------
// 4. transition_now convenience
// ---------------------------------------------------------------------------

#[test]
fn transition_now_no_guards() {
    let mut barrier = det_barrier(10);
    let evidence = barrier
        .transition_now(
            SecurityEpoch::from_raw(11),
            TransitionReason::LossMatrixUpdate,
            "trace-now",
        )
        .expect("now");
    assert_eq!(evidence.old_epoch, SecurityEpoch::from_raw(10));
    assert_eq!(evidence.new_epoch, SecurityEpoch::from_raw(11));
    assert_eq!(evidence.forced_cancellations, 0);
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(11));
}

#[test]
fn transition_now_force_cancels_in_flight() {
    let mut barrier = det_barrier(5);
    let _g = barrier
        .enter_critical(CriticalOpKind::CapabilityCheck, "t1")
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
    assert_eq!(barrier.state(), BarrierState::Open);
}

// ---------------------------------------------------------------------------
// 5. Error conditions
// ---------------------------------------------------------------------------

#[test]
fn enter_rejected_during_draining() {
    let mut barrier = det_barrier(1);
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
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

#[test]
fn double_begin_transition_rejected() {
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
            TransitionReason::GuardrailConfigChange,
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
    let mut barrier = det_barrier(10);
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
fn same_epoch_transition_rejected() {
    let mut barrier = det_barrier(10);
    let err = barrier
        .begin_transition(
            SecurityEpoch::from_raw(10),
            TransitionReason::PolicyKeyRotation,
            "t1",
        )
        .unwrap_err();
    match err {
        BarrierError::NonMonotonicTransition { current, attempted } => {
            assert_eq!(current, SecurityEpoch::from_raw(10));
            assert_eq!(attempted, SecurityEpoch::from_raw(10));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn complete_without_transition_rejected() {
    let mut barrier = det_barrier(1);
    let err = barrier.complete_transition().unwrap_err();
    assert!(matches!(err, BarrierError::NoTransitionInProgress));
}

#[test]
fn complete_with_guards_held_rejected() {
    let mut barrier = det_barrier(1);
    let _g = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .expect("g");

    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t2",
        )
        .expect("begin");

    let err = barrier.complete_transition().unwrap_err();
    match err {
        BarrierError::DrainTimeout {
            remaining_guards, ..
        } => {
            assert_eq!(remaining_guards, 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn force_cancel_when_not_draining_rejected() {
    let mut barrier = det_barrier(1);
    let err = barrier.force_cancel_remaining().unwrap_err();
    assert!(matches!(err, BarrierError::NoTransitionInProgress));
}

// ---------------------------------------------------------------------------
// 6. Sequential transitions
// ---------------------------------------------------------------------------

#[test]
fn sequential_transitions_accumulate_evidence() {
    let mut barrier = det_barrier(1);

    for i in 2..=6 {
        barrier
            .transition_now(
                SecurityEpoch::from_raw(i),
                TransitionReason::PolicyKeyRotation,
                &format!("trace-{i}"),
            )
            .expect("transition");
    }

    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(6));
    assert_eq!(barrier.evidence().len(), 5);

    for (idx, ev) in barrier.evidence().iter().enumerate() {
        let expected_old = (idx as u64) + 1;
        let expected_new = (idx as u64) + 2;
        assert_eq!(ev.old_epoch, SecurityEpoch::from_raw(expected_old));
        assert_eq!(ev.new_epoch, SecurityEpoch::from_raw(expected_new));
    }
}

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
    assert!(barrier.release_guard(&guard));
    assert_eq!(barrier.in_flight(), 0);
}

// ---------------------------------------------------------------------------
// 7. Evidence recording
// ---------------------------------------------------------------------------

#[test]
fn evidence_records_all_transition_details() {
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

    assert_eq!(barrier.evidence().len(), 1);
    let ev = &barrier.evidence()[0];
    assert_eq!(ev.old_epoch, SecurityEpoch::from_raw(10));
    assert_eq!(ev.new_epoch, SecurityEpoch::from_raw(11));
    assert_eq!(ev.reason, TransitionReason::RemoteTrustConfigChange);
    assert_eq!(ev.in_flight_at_start, 1);
    assert_eq!(ev.forced_cancellations, 1);
    assert_eq!(ev.trace_id, "trace-detail");
    assert_eq!(ev.duration_ms, 0);
}

#[test]
fn evidence_empty_initially() {
    let barrier = det_barrier(1);
    assert!(barrier.evidence().is_empty());
}

// ---------------------------------------------------------------------------
// 8. Display impls
// ---------------------------------------------------------------------------

#[test]
fn barrier_state_display() {
    assert_eq!(BarrierState::Open.to_string(), "open");
    assert_eq!(BarrierState::Draining.to_string(), "draining");
    assert_eq!(BarrierState::Finalizing.to_string(), "finalizing");
}

#[test]
fn critical_op_kind_display_all_variants() {
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

#[test]
fn barrier_error_display_epoch_transitioning() {
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
fn barrier_error_display_transition_already_in_progress() {
    let err = BarrierError::TransitionAlreadyInProgress {
        current_epoch: SecurityEpoch::from_raw(3),
    };
    assert_eq!(err.to_string(), "transition already in progress at epoch:3");
}

#[test]
fn barrier_error_display_drain_timeout() {
    let err = BarrierError::DrainTimeout {
        epoch: SecurityEpoch::from_raw(4),
        remaining_guards: 7,
        timeout_ms: 5000,
    };
    assert_eq!(
        err.to_string(),
        "drain timeout at epoch:4: 7 guards remaining after 5000ms"
    );
}

#[test]
fn barrier_error_display_no_transition() {
    let err = BarrierError::NoTransitionInProgress;
    assert_eq!(err.to_string(), "no transition in progress to complete");
}

#[test]
fn barrier_error_display_non_monotonic() {
    let err = BarrierError::NonMonotonicTransition {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(3),
    };
    assert_eq!(
        err.to_string(),
        "non-monotonic transition: current epoch:10, attempted epoch:3"
    );
}

// ---------------------------------------------------------------------------
// 9. Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn barrier_state_serde_roundtrip() {
    let states = [
        BarrierState::Open,
        BarrierState::Draining,
        BarrierState::Finalizing,
    ];
    for state in &states {
        let json = serde_json::to_string(state).expect("serialize");
        let restored: BarrierState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*state, restored);
    }
}

#[test]
fn critical_op_kind_serde_roundtrip() {
    let ops = [
        CriticalOpKind::DecisionEval,
        CriticalOpKind::EvidenceEmission,
        CriticalOpKind::KeyDerivation,
        CriticalOpKind::CapabilityCheck,
        CriticalOpKind::RevocationCheck,
        CriticalOpKind::RemoteOperation,
    ];
    for op in &ops {
        let json = serde_json::to_string(op).expect("serialize");
        let restored: CriticalOpKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*op, restored);
    }
}

#[test]
fn epoch_guard_serde_roundtrip() {
    let guard = EpochGuard {
        guard_id: 99,
        epoch: SecurityEpoch::from_raw(7),
        op_kind: CriticalOpKind::RemoteOperation,
        trace_id: "trace-xyz".to_string(),
    };
    let json = serde_json::to_string(&guard).expect("serialize");
    let restored: EpochGuard = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(guard, restored);
}

#[test]
fn transition_evidence_serde_roundtrip() {
    let evidence = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(1),
        new_epoch: SecurityEpoch::from_raw(2),
        reason: TransitionReason::OperatorManualBump,
        in_flight_at_start: 5,
        in_flight_at_complete: 0,
        forced_cancellations: 3,
        duration_ms: 42,
        trace_id: "serde-test".to_string(),
    };
    let json = serde_json::to_string(&evidence).expect("serialize");
    let restored: TransitionEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(evidence, restored);
}

#[test]
fn barrier_error_serde_roundtrip_all_variants() {
    let errors = vec![
        BarrierError::EpochTransitioning {
            current_epoch: SecurityEpoch::from_raw(1),
            state: BarrierState::Draining,
        },
        BarrierError::EpochTransitioning {
            current_epoch: SecurityEpoch::from_raw(2),
            state: BarrierState::Finalizing,
        },
        BarrierError::TransitionAlreadyInProgress {
            current_epoch: SecurityEpoch::from_raw(3),
        },
        BarrierError::DrainTimeout {
            epoch: SecurityEpoch::from_raw(4),
            remaining_guards: 10,
            timeout_ms: 5000,
        },
        BarrierError::NoTransitionInProgress,
        BarrierError::NonMonotonicTransition {
            current: SecurityEpoch::from_raw(10),
            attempted: SecurityEpoch::from_raw(5),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: BarrierError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

#[test]
fn barrier_config_serde_roundtrip() {
    let configs = [BarrierConfig::default(), BarrierConfig::deterministic()];
    for config in &configs {
        let json = serde_json::to_string(config).expect("serialize");
        let restored: BarrierConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*config, restored);
    }
}

// ---------------------------------------------------------------------------
// 10. Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_produces_identical_evidence() {
    let run = || -> Vec<TransitionEvidence> {
        let mut barrier = det_barrier(1);

        let _g1 = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t1")
            .expect("g1");
        let g2 = barrier
            .enter_critical(CriticalOpKind::EvidenceEmission, "t2")
            .expect("g2");

        barrier
            .begin_transition(
                SecurityEpoch::from_raw(2),
                TransitionReason::PolicyKeyRotation,
                "trace-replay",
            )
            .expect("begin");

        barrier.release_guard(&g2);
        barrier.force_cancel_remaining().expect("cancel");
        barrier.complete_transition().expect("complete");

        let _g3 = barrier
            .enter_critical(CriticalOpKind::KeyDerivation, "t3")
            .expect("g3");

        barrier
            .transition_now(
                SecurityEpoch::from_raw(3),
                TransitionReason::LossMatrixUpdate,
                "trace-replay-2",
            )
            .expect("now");

        barrier.evidence().to_vec()
    };

    let run1 = run();
    let run2 = run();
    assert_eq!(run1.len(), run2.len());
    for (e1, e2) in run1.iter().zip(run2.iter()) {
        assert_eq!(e1, e2);
    }
}

#[test]
fn deterministic_replay_serde_evidence_stability() {
    let mut barrier = det_barrier(1);
    barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::RevocationFrontierAdvance,
            "serde-replay",
        )
        .expect("transition");

    let json1 = serde_json::to_string(barrier.evidence()).expect("serialize1");
    let json2 = serde_json::to_string(barrier.evidence()).expect("serialize2");
    assert_eq!(json1, json2);
}

// ---------------------------------------------------------------------------
// 11. Mixed scenarios
// ---------------------------------------------------------------------------

#[test]
fn all_critical_op_kinds_can_acquire_guards() {
    let mut barrier = det_barrier(1);
    let kinds = [
        CriticalOpKind::DecisionEval,
        CriticalOpKind::EvidenceEmission,
        CriticalOpKind::KeyDerivation,
        CriticalOpKind::CapabilityCheck,
        CriticalOpKind::RevocationCheck,
        CriticalOpKind::RemoteOperation,
    ];
    let mut guards = Vec::new();
    for (idx, kind) in kinds.iter().enumerate() {
        let g = barrier
            .enter_critical(*kind, &format!("trace-{idx}"))
            .expect("enter");
        guards.push(g);
    }
    assert_eq!(barrier.in_flight(), 6);

    for g in &guards {
        assert!(barrier.release_guard(g));
    }
    assert_eq!(barrier.in_flight(), 0);
}

#[test]
fn all_transition_reasons_work() {
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];

    let mut barrier = det_barrier(1);
    for (idx, reason) in reasons.iter().enumerate() {
        let new_epoch = SecurityEpoch::from_raw((idx as u64) + 2);
        let evidence = barrier
            .transition_now(new_epoch, reason.clone(), &format!("trace-{idx}"))
            .expect("transition");
        assert_eq!(evidence.reason, *reason);
    }
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(7));
}

#[test]
fn large_epoch_gap_transition() {
    let mut barrier = det_barrier(1);
    let evidence = barrier
        .transition_now(
            SecurityEpoch::from_raw(1_000_000),
            TransitionReason::OperatorManualBump,
            "big-jump",
        )
        .expect("transition");
    assert_eq!(evidence.old_epoch, SecurityEpoch::from_raw(1));
    assert_eq!(evidence.new_epoch, SecurityEpoch::from_raw(1_000_000));
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(1_000_000));
}

#[test]
fn barrier_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(BarrierError::NoTransitionInProgress);
    assert!(!err.to_string().is_empty());
}

#[test]
fn can_complete_false_when_open() {
    let barrier = det_barrier(1);
    assert!(!barrier.can_complete());
}

#[test]
fn force_cancel_zero_returns_zero() {
    let mut barrier = det_barrier(1);
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .expect("begin");

    let cancelled = barrier.force_cancel_remaining().expect("cancel");
    assert_eq!(cancelled, 0);
}
