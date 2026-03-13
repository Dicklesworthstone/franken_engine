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

// ---------------------------------------------------------------------------
// Enrichment tests — appended batch
// ---------------------------------------------------------------------------

// -- BarrierState: Clone, Copy, Debug, serde, Display edge cases --

#[test]
fn enrichment_barrier_state_clone_eq() {
    let orig = BarrierState::Draining;
    let cloned = orig.clone();
    assert_eq!(orig, cloned);
}

#[test]
fn enrichment_barrier_state_copy_after_move() {
    let a = BarrierState::Finalizing;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_eq!(a, BarrierState::Finalizing);
}

#[test]
fn enrichment_barrier_state_debug_open() {
    let dbg = format!("{:?}", BarrierState::Open);
    assert_eq!(dbg, "Open");
}

#[test]
fn enrichment_barrier_state_debug_draining() {
    let dbg = format!("{:?}", BarrierState::Draining);
    assert_eq!(dbg, "Draining");
}

#[test]
fn enrichment_barrier_state_debug_finalizing() {
    let dbg = format!("{:?}", BarrierState::Finalizing);
    assert_eq!(dbg, "Finalizing");
}

#[test]
fn enrichment_barrier_state_display_not_debug() {
    // Display uses lowercase, Debug uses PascalCase
    let state = BarrierState::Open;
    assert_ne!(format!("{state}"), format!("{state:?}"));
}

#[test]
fn enrichment_barrier_state_serde_open_json_string() {
    let json = serde_json::to_string(&BarrierState::Open).unwrap();
    assert_eq!(json, "\"Open\"");
}

#[test]
fn enrichment_barrier_state_serde_draining_json_string() {
    let json = serde_json::to_string(&BarrierState::Draining).unwrap();
    assert_eq!(json, "\"Draining\"");
}

#[test]
fn enrichment_barrier_state_serde_finalizing_json_string() {
    let json = serde_json::to_string(&BarrierState::Finalizing).unwrap();
    assert_eq!(json, "\"Finalizing\"");
}

#[test]
fn enrichment_barrier_state_deserialize_invalid_variant() {
    let result = serde_json::from_str::<BarrierState>("\"Closed\"");
    assert!(result.is_err());
}

// -- CriticalOpKind: ordering, hash, serde edge cases --

#[test]
fn enrichment_critical_op_kind_ord_total_order() {
    let mut kinds = vec![
        CriticalOpKind::RemoteOperation,
        CriticalOpKind::DecisionEval,
        CriticalOpKind::KeyDerivation,
        CriticalOpKind::CapabilityCheck,
        CriticalOpKind::EvidenceEmission,
        CriticalOpKind::RevocationCheck,
    ];
    kinds.sort();
    // Verify DecisionEval is smallest
    assert_eq!(kinds[0], CriticalOpKind::DecisionEval);
    // Verify sorted order is stable across runs
    let mut kinds2 = kinds.clone();
    kinds2.sort();
    assert_eq!(kinds, kinds2);
}

#[test]
fn enrichment_critical_op_kind_partial_eq_reflexive() {
    let kinds = [
        CriticalOpKind::DecisionEval,
        CriticalOpKind::EvidenceEmission,
        CriticalOpKind::KeyDerivation,
        CriticalOpKind::CapabilityCheck,
        CriticalOpKind::RevocationCheck,
        CriticalOpKind::RemoteOperation,
    ];
    for k in &kinds {
        assert_eq!(*k, *k);
    }
}

#[test]
fn enrichment_critical_op_kind_deserialize_invalid() {
    let result = serde_json::from_str::<CriticalOpKind>("\"UnknownOp\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_critical_op_kind_clone_copy_roundtrip() {
    let kind = CriticalOpKind::CapabilityCheck;
    let cloned = kind.clone();
    let copied = kind;
    assert_eq!(kind, cloned);
    assert_eq!(kind, copied);
    assert_eq!(cloned, copied);
}

#[test]
fn enrichment_critical_op_kind_display_lowercase_underscore() {
    // All display strings should be lowercase with underscores
    let kinds = [
        CriticalOpKind::DecisionEval,
        CriticalOpKind::EvidenceEmission,
        CriticalOpKind::KeyDerivation,
        CriticalOpKind::CapabilityCheck,
        CriticalOpKind::RevocationCheck,
        CriticalOpKind::RemoteOperation,
    ];
    for k in &kinds {
        let s = k.to_string();
        assert_eq!(s, s.to_lowercase(), "Display should be lowercase");
        assert!(s.contains('_'), "Display should contain underscore");
    }
}

// -- BarrierError: Display formatting, serde, Debug --

#[test]
fn enrichment_barrier_error_epoch_transitioning_finalizing_display() {
    let err = BarrierError::EpochTransitioning {
        current_epoch: SecurityEpoch::from_raw(99),
        state: BarrierState::Finalizing,
    };
    let msg = err.to_string();
    assert!(msg.contains("finalizing"));
    assert!(msg.contains("epoch:99"));
    assert!(msg.contains("cannot acquire guard"));
}

#[test]
fn enrichment_barrier_error_drain_timeout_zero_guards() {
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
fn enrichment_barrier_error_non_monotonic_same_epoch() {
    let err = BarrierError::NonMonotonicTransition {
        current: SecurityEpoch::from_raw(5),
        attempted: SecurityEpoch::from_raw(5),
    };
    let msg = err.to_string();
    assert!(msg.contains("non-monotonic"));
    // Both should show epoch:5
    assert_eq!(msg.matches("epoch:5").count(), 2);
}

#[test]
fn enrichment_barrier_error_clone_all_variants() {
    let variants = vec![
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
    for v in &variants {
        let cloned = v.clone();
        assert_eq!(*v, cloned);
    }
}

#[test]
fn enrichment_barrier_error_debug_contains_variant_name() {
    let err = BarrierError::NoTransitionInProgress;
    let dbg = format!("{err:?}");
    assert!(dbg.contains("NoTransitionInProgress"));
}

#[test]
fn enrichment_barrier_error_debug_drain_timeout_fields() {
    let err = BarrierError::DrainTimeout {
        epoch: SecurityEpoch::from_raw(42),
        remaining_guards: 7,
        timeout_ms: 3000,
    };
    let dbg = format!("{err:?}");
    assert!(dbg.contains("DrainTimeout"));
    assert!(dbg.contains("7"));
    assert!(dbg.contains("3000"));
}

#[test]
fn enrichment_barrier_error_serde_no_transition_roundtrip() {
    let err = BarrierError::NoTransitionInProgress;
    let json = serde_json::to_string(&err).unwrap();
    let restored: BarrierError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_barrier_error_serde_transition_already_json_shape() {
    let err = BarrierError::TransitionAlreadyInProgress {
        current_epoch: SecurityEpoch::from_raw(77),
    };
    let val = serde_json::to_value(&err).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("TransitionAlreadyInProgress"));
    let inner = obj["TransitionAlreadyInProgress"].as_object().unwrap();
    assert!(inner.contains_key("current_epoch"));
    assert_eq!(inner.len(), 1);
}

#[test]
fn enrichment_barrier_error_source_none_all_variants() {
    let variants: Vec<BarrierError> = vec![
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
            current: SecurityEpoch::from_raw(2),
            attempted: SecurityEpoch::from_raw(1),
        },
    ];
    for v in &variants {
        assert!(std::error::Error::source(v).is_none());
    }
}

// -- EpochGuard: serde, Display, Debug, Clone --

#[test]
fn enrichment_epoch_guard_display_all_op_kinds() {
    let kinds = [
        (CriticalOpKind::DecisionEval, "decision_eval"),
        (CriticalOpKind::EvidenceEmission, "evidence_emission"),
        (CriticalOpKind::KeyDerivation, "key_derivation"),
        (CriticalOpKind::CapabilityCheck, "capability_check"),
        (CriticalOpKind::RevocationCheck, "revocation_check"),
        (CriticalOpKind::RemoteOperation, "remote_operation"),
    ];
    for (idx, (kind, expected_str)) in kinds.iter().enumerate() {
        let guard = EpochGuard {
            guard_id: (idx as u64) + 1,
            epoch: SecurityEpoch::from_raw(10),
            op_kind: *kind,
            trace_id: "t".to_string(),
        };
        let display = guard.to_string();
        assert!(
            display.contains(expected_str),
            "display for {kind:?} should contain '{expected_str}', got '{display}'"
        );
        assert!(display.contains("EpochGuard("));
        assert!(display.contains("epoch:10"));
    }
}

#[test]
fn enrichment_epoch_guard_display_large_guard_id() {
    let guard = EpochGuard {
        guard_id: u64::MAX,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "t".to_string(),
    };
    let display = guard.to_string();
    assert!(display.contains(&format!("#{}", u64::MAX)));
}

#[test]
fn enrichment_epoch_guard_clone_trace_id_independence() {
    let guard = EpochGuard {
        guard_id: 5,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::KeyDerivation,
        trace_id: "original".to_string(),
    };
    let mut cloned = guard.clone();
    cloned.trace_id = "modified".to_string();
    assert_eq!(guard.trace_id, "original");
    assert_eq!(cloned.trace_id, "modified");
}

#[test]
fn enrichment_epoch_guard_eq_differs_by_guard_id() {
    let g1 = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "t".to_string(),
    };
    let g2 = EpochGuard {
        guard_id: 2,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "t".to_string(),
    };
    assert_ne!(g1, g2);
}

#[test]
fn enrichment_epoch_guard_eq_differs_by_epoch() {
    let g1 = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "t".to_string(),
    };
    let g2 = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(2),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "t".to_string(),
    };
    assert_ne!(g1, g2);
}

#[test]
fn enrichment_epoch_guard_eq_differs_by_op_kind() {
    let g1 = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "t".to_string(),
    };
    let g2 = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::KeyDerivation,
        trace_id: "t".to_string(),
    };
    assert_ne!(g1, g2);
}

#[test]
fn enrichment_epoch_guard_eq_differs_by_trace_id() {
    let g1 = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "aaa".to_string(),
    };
    let g2 = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "bbb".to_string(),
    };
    assert_ne!(g1, g2);
}

#[test]
fn enrichment_epoch_guard_serde_empty_trace_id() {
    let guard = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: String::new(),
    };
    let json = serde_json::to_string(&guard).unwrap();
    let restored: EpochGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard, restored);
    assert!(restored.trace_id.is_empty());
}

#[test]
fn enrichment_epoch_guard_serde_unicode_trace_id() {
    let guard = EpochGuard {
        guard_id: 1,
        epoch: SecurityEpoch::from_raw(1),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "trace-\u{00e9}\u{00e8}\u{00ea}".to_string(),
    };
    let json = serde_json::to_string(&guard).unwrap();
    let restored: EpochGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard, restored);
}

// -- TransitionEvidence: serde, Debug, Clone edge cases --

#[test]
fn enrichment_transition_evidence_serde_zero_fields() {
    let ev = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(0),
        new_epoch: SecurityEpoch::from_raw(1),
        reason: TransitionReason::PolicyKeyRotation,
        in_flight_at_start: 0,
        in_flight_at_complete: 0,
        forced_cancellations: 0,
        duration_ms: 0,
        trace_id: String::new(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let restored: TransitionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
}

#[test]
fn enrichment_transition_evidence_serde_max_u64_fields() {
    let ev = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(u64::MAX - 1),
        new_epoch: SecurityEpoch::from_raw(u64::MAX),
        reason: TransitionReason::OperatorManualBump,
        in_flight_at_start: u64::MAX,
        in_flight_at_complete: u64::MAX,
        forced_cancellations: u64::MAX,
        duration_ms: u64::MAX,
        trace_id: "max".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let restored: TransitionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
}

#[test]
fn enrichment_transition_evidence_clone_deep() {
    let ev = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(1),
        new_epoch: SecurityEpoch::from_raw(2),
        reason: TransitionReason::RevocationFrontierAdvance,
        in_flight_at_start: 3,
        in_flight_at_complete: 0,
        forced_cancellations: 2,
        duration_ms: 100,
        trace_id: "deep-clone".to_string(),
    };
    let mut cloned = ev.clone();
    cloned.trace_id = "mutated".to_string();
    cloned.forced_cancellations = 999;
    assert_eq!(ev.trace_id, "deep-clone");
    assert_eq!(ev.forced_cancellations, 2);
}

#[test]
fn enrichment_transition_evidence_debug_all_field_names() {
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
    let dbg = format!("{ev:?}");
    for field in [
        "old_epoch",
        "new_epoch",
        "reason",
        "in_flight_at_start",
        "in_flight_at_complete",
        "forced_cancellations",
        "duration_ms",
        "trace_id",
    ] {
        assert!(dbg.contains(field), "Debug should contain field '{field}'");
    }
}

#[test]
fn enrichment_transition_evidence_eq_reflexive() {
    let ev = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(1),
        new_epoch: SecurityEpoch::from_raw(2),
        reason: TransitionReason::GuardrailConfigChange,
        in_flight_at_start: 1,
        in_flight_at_complete: 0,
        forced_cancellations: 1,
        duration_ms: 50,
        trace_id: "reflexive".to_string(),
    };
    assert_eq!(ev, ev.clone());
}

#[test]
fn enrichment_transition_evidence_ne_by_reason() {
    let ev1 = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(1),
        new_epoch: SecurityEpoch::from_raw(2),
        reason: TransitionReason::PolicyKeyRotation,
        in_flight_at_start: 0,
        in_flight_at_complete: 0,
        forced_cancellations: 0,
        duration_ms: 0,
        trace_id: "t".to_string(),
    };
    let ev2 = TransitionEvidence {
        reason: TransitionReason::LossMatrixUpdate,
        ..ev1.clone()
    };
    assert_ne!(ev1, ev2);
}

// -- BarrierConfig: serde, Debug, Clone, Default --

#[test]
fn enrichment_barrier_config_default_serde_json_fields() {
    let cfg = BarrierConfig::default();
    let val = serde_json::to_value(&cfg).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(obj["drain_timeout_ms"], 5000);
    assert_eq!(obj["deterministic"], false);
}

#[test]
fn enrichment_barrier_config_deterministic_serde_json_fields() {
    let cfg = BarrierConfig::deterministic();
    let val = serde_json::to_value(&cfg).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(obj["drain_timeout_ms"], 0);
    assert_eq!(obj["deterministic"], true);
}

#[test]
fn enrichment_barrier_config_custom_values_serde() {
    let cfg = BarrierConfig {
        drain_timeout_ms: 999,
        deterministic: false,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: BarrierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
    assert_eq!(restored.drain_timeout_ms, 999);
}

#[test]
fn enrichment_barrier_config_debug_values() {
    let cfg = BarrierConfig {
        drain_timeout_ms: 12345,
        deterministic: true,
    };
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("12345"));
    assert!(dbg.contains("true"));
}

#[test]
fn enrichment_barrier_config_eq_ne() {
    let a = BarrierConfig::default();
    let b = BarrierConfig::deterministic();
    assert_ne!(a, b);
    assert_eq!(a, a.clone());
    assert_eq!(b, b.clone());
}

// -- EpochBarrier: construction and accessor edge cases --

#[test]
fn enrichment_barrier_at_max_epoch() {
    let barrier = EpochBarrier::new(
        SecurityEpoch::from_raw(u64::MAX),
        BarrierConfig::deterministic(),
    );
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(u64::MAX));
    assert_eq!(barrier.state(), BarrierState::Open);
    assert_eq!(barrier.in_flight(), 0);
}

#[test]
fn enrichment_barrier_config_accessor_returns_reference() {
    let cfg = BarrierConfig {
        drain_timeout_ms: 777,
        deterministic: false,
    };
    let barrier = EpochBarrier::new(SecurityEpoch::from_raw(1), cfg.clone());
    assert_eq!(barrier.config().drain_timeout_ms, 777);
    assert_eq!(*barrier.config(), cfg);
}

#[test]
fn enrichment_barrier_debug_contains_state() {
    let barrier = det_barrier(5);
    let dbg = format!("{barrier:?}");
    assert!(dbg.contains("Open"), "Debug should show state");
    assert!(dbg.contains("EpochBarrier"));
}

// -- Guard lifecycle edge cases --

#[test]
fn enrichment_enter_critical_empty_trace_id() {
    let mut barrier = det_barrier(1);
    let guard = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "")
        .unwrap();
    assert!(guard.trace_id.is_empty());
    assert!(barrier.release_guard(&guard));
}

#[test]
fn enrichment_enter_critical_long_trace_id() {
    let mut barrier = det_barrier(1);
    let long_trace = "x".repeat(10_000);
    let guard = barrier
        .enter_critical(CriticalOpKind::DecisionEval, &long_trace)
        .unwrap();
    assert_eq!(guard.trace_id.len(), 10_000);
    assert!(barrier.release_guard(&guard));
}

#[test]
fn enrichment_guard_id_starts_at_one() {
    let mut barrier = det_barrier(1);
    let guard = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t")
        .unwrap();
    assert_eq!(guard.guard_id, 1);
}

#[test]
fn enrichment_guard_ids_persist_after_force_cancel() {
    let mut barrier = det_barrier(1);
    let _g1 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .unwrap();
    let _g2 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t2")
        .unwrap();

    barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap();

    let g3 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t3")
        .unwrap();
    // Guard IDs should be 3 (1 and 2 were used before transition)
    assert_eq!(g3.guard_id, 3);
}

#[test]
fn enrichment_release_guard_wrong_epoch_with_inflight() {
    let mut barrier = det_barrier(1);
    let _g1 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .unwrap();
    let wrong_epoch_guard = EpochGuard {
        guard_id: 99,
        epoch: SecurityEpoch::from_raw(999),
        op_kind: CriticalOpKind::DecisionEval,
        trace_id: "wrong".to_string(),
    };
    // Even though in_flight > 0, wrong epoch returns false
    assert!(!barrier.release_guard(&wrong_epoch_guard));
    assert_eq!(barrier.in_flight(), 1);
}

// -- Transition error edge cases --

#[test]
fn enrichment_begin_transition_epoch_minus_one() {
    let mut barrier = det_barrier(10);
    let err = barrier
        .begin_transition(
            SecurityEpoch::from_raw(9),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap_err();
    match err {
        BarrierError::NonMonotonicTransition { current, attempted } => {
            assert_eq!(current, SecurityEpoch::from_raw(10));
            assert_eq!(attempted, SecurityEpoch::from_raw(9));
        }
        other => panic!("expected NonMonotonicTransition, got {other:?}"),
    }
}

#[test]
fn enrichment_begin_transition_epoch_zero_from_nonzero() {
    let mut barrier = det_barrier(5);
    let err = barrier
        .begin_transition(
            SecurityEpoch::from_raw(0),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap_err();
    assert!(matches!(err, BarrierError::NonMonotonicTransition { .. }));
}

#[test]
fn enrichment_enter_rejected_during_finalizing_state() {
    // BarrierState::Finalizing would reject guards too, but the current
    // implementation only goes to Draining before completing. Test that
    // enter_critical checks != Open.
    let mut barrier = det_barrier(1);
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap();
    // In Draining state
    let err = barrier
        .enter_critical(CriticalOpKind::EvidenceEmission, "t")
        .unwrap_err();
    match err {
        BarrierError::EpochTransitioning {
            state,
            current_epoch,
        } => {
            assert_eq!(state, BarrierState::Draining);
            assert_eq!(current_epoch, SecurityEpoch::from_raw(1));
        }
        other => panic!("expected EpochTransitioning, got {other:?}"),
    }
}

#[test]
fn enrichment_transition_now_non_monotonic() {
    let mut barrier = det_barrier(10);
    let err = barrier
        .transition_now(
            SecurityEpoch::from_raw(5),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap_err();
    assert!(matches!(err, BarrierError::NonMonotonicTransition { .. }));
    // Barrier should still be in Open state after rejected transition
    assert_eq!(barrier.state(), BarrierState::Open);
}

#[test]
fn enrichment_transition_now_same_epoch() {
    let mut barrier = det_barrier(7);
    let err = barrier
        .transition_now(
            SecurityEpoch::from_raw(7),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap_err();
    assert!(matches!(err, BarrierError::NonMonotonicTransition { .. }));
}

// -- Force cancel edge cases --

#[test]
fn enrichment_force_cancel_then_force_cancel_again_returns_zero() {
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

    let first_cancel = barrier.force_cancel_remaining().unwrap();
    assert_eq!(first_cancel, 1);

    // Second force cancel should return 0
    let second_cancel = barrier.force_cancel_remaining().unwrap();
    assert_eq!(second_cancel, 0);
}

#[test]
fn enrichment_force_cancel_partial_release_then_cancel() {
    let mut barrier = det_barrier(1);
    let g1 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .unwrap();
    let _g2 = barrier
        .enter_critical(CriticalOpKind::KeyDerivation, "t2")
        .unwrap();
    let _g3 = barrier
        .enter_critical(CriticalOpKind::RevocationCheck, "t3")
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

    // Force cancel remaining
    let cancelled = barrier.force_cancel_remaining().unwrap();
    assert_eq!(cancelled, 2);
    assert_eq!(barrier.in_flight(), 0);

    let evidence = barrier.complete_transition().unwrap();
    assert_eq!(evidence.in_flight_at_start, 3);
    assert_eq!(evidence.forced_cancellations, 2);
}

// -- Evidence correctness --

#[test]
fn enrichment_evidence_trace_ids_preserved_across_transitions() {
    let mut barrier = det_barrier(1);
    let traces = ["alpha", "bravo", "charlie"];
    for (i, trace) in traces.iter().enumerate() {
        barrier
            .transition_now(
                SecurityEpoch::from_raw((i as u64) + 2),
                TransitionReason::PolicyKeyRotation,
                trace,
            )
            .unwrap();
    }
    for (i, trace) in traces.iter().enumerate() {
        assert_eq!(barrier.evidence()[i].trace_id, *trace);
    }
}

#[test]
fn enrichment_evidence_reasons_preserved() {
    let mut barrier = det_barrier(1);
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    for (i, reason) in reasons.iter().enumerate() {
        barrier
            .transition_now(
                SecurityEpoch::from_raw((i as u64) + 2),
                reason.clone(),
                &format!("t-{i}"),
            )
            .unwrap();
    }
    assert_eq!(barrier.evidence().len(), 6);
    for (i, reason) in reasons.iter().enumerate() {
        assert_eq!(barrier.evidence()[i].reason, *reason);
    }
}

#[test]
fn enrichment_evidence_duration_ms_zero_in_deterministic() {
    let mut barrier = det_barrier(1);
    barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap();
    assert_eq!(barrier.evidence()[0].duration_ms, 0);
}

#[test]
fn enrichment_evidence_in_flight_at_complete_always_zero() {
    let mut barrier = det_barrier(1);
    let _g = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t")
        .unwrap();
    barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap();
    // in_flight_at_complete is always 0 since transition completes only when drained
    assert_eq!(barrier.evidence()[0].in_flight_at_complete, 0);
}

// -- Determinism --

#[test]
fn enrichment_deterministic_replay_many_transitions() {
    let run = || -> String {
        let mut barrier = det_barrier(1);
        for i in 2..=20 {
            let _g = barrier
                .enter_critical(CriticalOpKind::DecisionEval, &format!("g-{i}"))
                .unwrap();
            barrier
                .transition_now(
                    SecurityEpoch::from_raw(i),
                    TransitionReason::PolicyKeyRotation,
                    &format!("t-{i}"),
                )
                .unwrap();
        }
        serde_json::to_string(barrier.evidence()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_deterministic_guard_ids_across_runs() {
    let run = || -> Vec<u64> {
        let mut barrier = det_barrier(1);
        let mut ids = Vec::new();
        for i in 0..5 {
            let g = barrier
                .enter_critical(CriticalOpKind::DecisionEval, &format!("t-{i}"))
                .unwrap();
            ids.push(g.guard_id);
            barrier.release_guard(&g);
        }
        ids
    };
    assert_eq!(run(), run());
}

// -- Serde JSON field name stability --

#[test]
fn enrichment_barrier_error_no_transition_json_string() {
    let err = BarrierError::NoTransitionInProgress;
    let json = serde_json::to_string(&err).unwrap();
    // Unit variant serializes as a string
    assert_eq!(json, "\"NoTransitionInProgress\"");
}

#[test]
fn enrichment_barrier_error_non_monotonic_json_field_names() {
    let err = BarrierError::NonMonotonicTransition {
        current: SecurityEpoch::from_raw(100),
        attempted: SecurityEpoch::from_raw(50),
    };
    let val = serde_json::to_value(&err).unwrap();
    let inner = val["NonMonotonicTransition"].as_object().unwrap();
    assert!(inner.contains_key("current"));
    assert!(inner.contains_key("attempted"));
    assert_eq!(inner.len(), 2);
}

#[test]
fn enrichment_epoch_guard_json_value_types() {
    let guard = EpochGuard {
        guard_id: 42,
        epoch: SecurityEpoch::from_raw(7),
        op_kind: CriticalOpKind::RevocationCheck,
        trace_id: "val-types".to_string(),
    };
    let val = serde_json::to_value(&guard).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj["guard_id"].is_u64());
    assert!(obj["op_kind"].is_string());
    assert!(obj["trace_id"].is_string());
    assert_eq!(obj["guard_id"].as_u64().unwrap(), 42);
    assert_eq!(obj["op_kind"].as_str().unwrap(), "RevocationCheck");
    assert_eq!(obj["trace_id"].as_str().unwrap(), "val-types");
}

#[test]
fn enrichment_transition_evidence_json_value_types() {
    let ev = TransitionEvidence {
        old_epoch: SecurityEpoch::from_raw(10),
        new_epoch: SecurityEpoch::from_raw(11),
        reason: TransitionReason::LossMatrixUpdate,
        in_flight_at_start: 3,
        in_flight_at_complete: 0,
        forced_cancellations: 2,
        duration_ms: 42,
        trace_id: "vt".to_string(),
    };
    let val = serde_json::to_value(&ev).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj["in_flight_at_start"].is_u64());
    assert!(obj["in_flight_at_complete"].is_u64());
    assert!(obj["forced_cancellations"].is_u64());
    assert!(obj["duration_ms"].is_u64());
    assert!(obj["trace_id"].is_string());
    assert_eq!(obj["in_flight_at_start"].as_u64().unwrap(), 3);
    assert_eq!(obj["forced_cancellations"].as_u64().unwrap(), 2);
}

// -- Mixed scenarios --

#[test]
fn enrichment_many_guards_then_transition_now() {
    let mut barrier = det_barrier(1);
    for i in 0..50 {
        let _g = barrier
            .enter_critical(CriticalOpKind::DecisionEval, &format!("t-{i}"))
            .unwrap();
    }
    assert_eq!(barrier.in_flight(), 50);

    let evidence = barrier
        .transition_now(
            SecurityEpoch::from_raw(2),
            TransitionReason::OperatorManualBump,
            "bulk",
        )
        .unwrap();
    assert_eq!(evidence.in_flight_at_start, 50);
    assert_eq!(evidence.forced_cancellations, 50);
    assert_eq!(barrier.in_flight(), 0);
}

#[test]
fn enrichment_rapid_sequential_transitions_epoch_monotonicity() {
    let mut barrier = det_barrier(1);
    for i in 2..=100 {
        barrier
            .transition_now(
                SecurityEpoch::from_raw(i),
                TransitionReason::PolicyKeyRotation,
                &format!("t-{i}"),
            )
            .unwrap();
    }
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(100));
    assert_eq!(barrier.evidence().len(), 99);

    // Verify monotonicity in evidence
    for ev in barrier.evidence() {
        assert!(
            ev.new_epoch > ev.old_epoch,
            "evidence must show strictly increasing epochs"
        );
    }
}

#[test]
fn enrichment_guard_acquire_release_across_many_transitions() {
    let mut barrier = det_barrier(1);
    for i in 2..=10 {
        let guard = barrier
            .enter_critical(CriticalOpKind::CapabilityCheck, &format!("pre-{i}"))
            .unwrap();
        assert_eq!(guard.epoch, SecurityEpoch::from_raw(i - 1));
        barrier.release_guard(&guard);

        barrier
            .transition_now(
                SecurityEpoch::from_raw(i),
                TransitionReason::PolicyKeyRotation,
                &format!("t-{i}"),
            )
            .unwrap();
    }
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(10));
}

#[test]
fn enrichment_transition_with_mixed_release_and_cancel() {
    let mut barrier = det_barrier(1);
    let g1 = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t1")
        .unwrap();
    let _g2 = barrier
        .enter_critical(CriticalOpKind::KeyDerivation, "t2")
        .unwrap();
    let g3 = barrier
        .enter_critical(CriticalOpKind::RevocationCheck, "t3")
        .unwrap();
    let _g4 = barrier
        .enter_critical(CriticalOpKind::RemoteOperation, "t4")
        .unwrap();

    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::GuardrailConfigChange,
            "mixed",
        )
        .unwrap();

    // Release 2 guards manually
    barrier.release_guard(&g1);
    barrier.release_guard(&g3);
    assert_eq!(barrier.in_flight(), 2);

    // Force cancel the remaining 2
    let cancelled = barrier.force_cancel_remaining().unwrap();
    assert_eq!(cancelled, 2);

    let evidence = barrier.complete_transition().unwrap();
    assert_eq!(evidence.in_flight_at_start, 4);
    assert_eq!(evidence.forced_cancellations, 2);
}

#[test]
fn enrichment_state_after_failed_transition_remains_open() {
    let mut barrier = det_barrier(10);

    // Attempt non-monotonic
    let _ = barrier.begin_transition(
        SecurityEpoch::from_raw(5),
        TransitionReason::PolicyKeyRotation,
        "t",
    );
    assert_eq!(barrier.state(), BarrierState::Open);

    // Should still be usable
    let guard = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t")
        .unwrap();
    assert_eq!(guard.epoch, SecurityEpoch::from_raw(10));
    barrier.release_guard(&guard);
}

#[test]
fn enrichment_can_complete_false_when_open_no_transition() {
    let mut barrier = det_barrier(1);
    let _g = barrier
        .enter_critical(CriticalOpKind::DecisionEval, "t")
        .unwrap();
    // Even with in_flight guards, can_complete is false if not draining
    assert!(!barrier.can_complete());
}

#[test]
fn enrichment_evidence_serde_roundtrip_vec() {
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
    let json = serde_json::to_string(barrier.evidence()).unwrap();
    let restored: Vec<TransitionEvidence> = serde_json::from_str(&json).unwrap();
    assert_eq!(barrier.evidence().len(), restored.len());
    for (orig, rest) in barrier.evidence().iter().zip(restored.iter()) {
        assert_eq!(orig, rest);
    }
}

#[test]
fn enrichment_large_epoch_jump() {
    let mut barrier = det_barrier(1);
    let evidence = barrier
        .transition_now(
            SecurityEpoch::from_raw(u64::MAX),
            TransitionReason::OperatorManualBump,
            "max-jump",
        )
        .unwrap();
    assert_eq!(evidence.old_epoch, SecurityEpoch::from_raw(1));
    assert_eq!(evidence.new_epoch, SecurityEpoch::from_raw(u64::MAX));
    assert_eq!(barrier.current_epoch(), SecurityEpoch::from_raw(u64::MAX));
}

#[test]
fn enrichment_begin_transition_returns_exact_in_flight_count() {
    let mut barrier = det_barrier(1);
    for _ in 0..7 {
        let _ = barrier
            .enter_critical(CriticalOpKind::DecisionEval, "t")
            .unwrap();
    }
    let in_flight = barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::PolicyKeyRotation,
            "t",
        )
        .unwrap();
    assert_eq!(in_flight, 7);
    assert_eq!(barrier.in_flight(), 7);
}

#[test]
fn enrichment_complete_transition_returns_evidence_matching_stored() {
    let mut barrier = det_barrier(1);
    barrier
        .begin_transition(
            SecurityEpoch::from_raw(2),
            TransitionReason::LossMatrixUpdate,
            "matching",
        )
        .unwrap();
    let returned_evidence = barrier.complete_transition().unwrap();

    // The returned evidence should match what's stored
    assert_eq!(barrier.evidence().len(), 1);
    assert_eq!(barrier.evidence()[0], returned_evidence);
}

#[test]
fn enrichment_barrier_state_open_after_multiple_transitions() {
    let mut barrier = det_barrier(1);
    for i in 2..=5 {
        barrier
            .begin_transition(
                SecurityEpoch::from_raw(i),
                TransitionReason::PolicyKeyRotation,
                &format!("t-{i}"),
            )
            .unwrap();
        assert_eq!(barrier.state(), BarrierState::Draining);
        barrier.complete_transition().unwrap();
        assert_eq!(barrier.state(), BarrierState::Open);
    }
}
