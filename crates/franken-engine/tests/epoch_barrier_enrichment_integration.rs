//! Enrichment integration tests for `epoch_barrier` module.
//!
//! Covers: BarrierState, BarrierError, CriticalOpKind, EpochGuard,
//! TransitionEvidence, BarrierConfig, EpochBarrier — full transition lifecycle,
//! guard acquire/release, drain with force-cancel, non-monotonic rejection,
//! concurrent guard tracking, error paths, serde roundtrips, Display uniqueness.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::epoch_barrier::*;
use frankenengine_engine::security_epoch::{SecurityEpoch, TransitionReason};

// ── helpers ──────────────────────────────────────────────────────────────

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn det_barrier(e: u64) -> EpochBarrier {
    EpochBarrier::new(epoch(e), BarrierConfig::deterministic())
}

fn all_op_kinds() -> Vec<CriticalOpKind> {
    vec![
        CriticalOpKind::DecisionEval,
        CriticalOpKind::EvidenceEmission,
        CriticalOpKind::KeyDerivation,
        CriticalOpKind::CapabilityCheck,
        CriticalOpKind::RevocationCheck,
        CriticalOpKind::RemoteOperation,
    ]
}

fn all_reasons() -> Vec<TransitionReason> {
    vec![
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ]
}

// ── test: full lifecycle with guards drained before complete ─────────────

#[test]
fn enrichment_full_lifecycle_guard_drain_then_complete() {
    let mut barrier = det_barrier(1);

    let g1 = barrier.enter_critical(CriticalOpKind::DecisionEval, "t1").unwrap();
    let g2 = barrier.enter_critical(CriticalOpKind::EvidenceEmission, "t2").unwrap();
    let g3 = barrier.enter_critical(CriticalOpKind::KeyDerivation, "t3").unwrap();

    assert_eq!(barrier.in_flight(), 3);

    let in_flight = barrier.begin_transition(epoch(2), TransitionReason::PolicyKeyRotation, "tr").unwrap();
    assert_eq!(in_flight, 3);
    assert_eq!(barrier.state(), BarrierState::Draining);
    assert!(!barrier.can_complete());

    assert!(barrier.release_guard(&g1));
    assert!(barrier.release_guard(&g2));
    assert!(!barrier.can_complete());
    assert!(barrier.release_guard(&g3));
    assert!(barrier.can_complete());

    let ev = barrier.complete_transition().unwrap();
    assert_eq!(ev.old_epoch, epoch(1));
    assert_eq!(ev.new_epoch, epoch(2));
    assert_eq!(ev.in_flight_at_start, 3);
    assert_eq!(ev.forced_cancellations, 0);
    assert_eq!(barrier.state(), BarrierState::Open);
    assert_eq!(barrier.current_epoch(), epoch(2));
}

// ── test: transition_now force-cancels in-flight guards ──────────────────

#[test]
fn enrichment_transition_now_force_cancels_multiple_guards() {
    let mut barrier = det_barrier(10);
    for i in 0..5 {
        let _g = barrier.enter_critical(CriticalOpKind::CapabilityCheck, &format!("t{i}")).unwrap();
    }
    assert_eq!(barrier.in_flight(), 5);

    let ev = barrier.transition_now(epoch(11), TransitionReason::OperatorManualBump, "force").unwrap();
    assert_eq!(ev.forced_cancellations, 5);
    assert_eq!(ev.in_flight_at_start, 5);
    assert_eq!(barrier.current_epoch(), epoch(11));
    assert_eq!(barrier.in_flight(), 0);
}

// ── test: non-monotonic transition rejection ─────────────────────────────

#[test]
fn enrichment_non_monotonic_transition_rejected_lower_epoch() {
    let mut barrier = det_barrier(10);
    let err = barrier.begin_transition(epoch(5), TransitionReason::PolicyKeyRotation, "t").unwrap_err();
    assert!(matches!(err, BarrierError::NonMonotonicTransition { current, attempted }
        if current == epoch(10) && attempted == epoch(5)));
}

#[test]
fn enrichment_non_monotonic_transition_rejected_same_epoch() {
    let mut barrier = det_barrier(7);
    let err = barrier.begin_transition(epoch(7), TransitionReason::PolicyKeyRotation, "t").unwrap_err();
    assert!(matches!(err, BarrierError::NonMonotonicTransition { .. }));
}

// ── test: guard acquisition rejected during drain ────────────────────────

#[test]
fn enrichment_guard_rejected_while_draining() {
    let mut barrier = det_barrier(1);
    barrier.begin_transition(epoch(2), TransitionReason::LossMatrixUpdate, "t").unwrap();
    let err = barrier.enter_critical(CriticalOpKind::RemoteOperation, "t2").unwrap_err();
    assert!(matches!(err, BarrierError::EpochTransitioning { state: BarrierState::Draining, .. }));
}

// ── test: double transition rejected ─────────────────────────────────────

#[test]
fn enrichment_double_transition_begin_rejected() {
    let mut barrier = det_barrier(1);
    barrier.begin_transition(epoch(2), TransitionReason::PolicyKeyRotation, "t1").unwrap();
    let err = barrier.begin_transition(epoch(3), TransitionReason::PolicyKeyRotation, "t2").unwrap_err();
    assert!(matches!(err, BarrierError::TransitionAlreadyInProgress { .. }));
}

// ── test: complete without transition returns error ───────────────────────

#[test]
fn enrichment_complete_without_transition_is_error() {
    let mut barrier = det_barrier(1);
    let err = barrier.complete_transition().unwrap_err();
    assert!(matches!(err, BarrierError::NoTransitionInProgress));
}

// ── test: complete with guards held returns drain timeout ────────────────

#[test]
fn enrichment_complete_with_held_guards_returns_drain_timeout() {
    let mut barrier = det_barrier(1);
    let _g = barrier.enter_critical(CriticalOpKind::DecisionEval, "t").unwrap();
    barrier.begin_transition(epoch(2), TransitionReason::PolicyKeyRotation, "t").unwrap();
    let err = barrier.complete_transition().unwrap_err();
    assert!(matches!(err, BarrierError::DrainTimeout { remaining_guards: 1, .. }));
}

// ── test: force cancel when not draining is error ────────────────────────

#[test]
fn enrichment_force_cancel_when_not_draining() {
    let mut barrier = det_barrier(1);
    let err = barrier.force_cancel_remaining().unwrap_err();
    assert!(matches!(err, BarrierError::NoTransitionInProgress));
}

// ── test: force cancel with zero in-flight returns zero ──────────────────

#[test]
fn enrichment_force_cancel_zero_in_flight() {
    let mut barrier = det_barrier(1);
    barrier.begin_transition(epoch(2), TransitionReason::PolicyKeyRotation, "t").unwrap();
    let cancelled = barrier.force_cancel_remaining().unwrap();
    assert_eq!(cancelled, 0);
}

// ── test: stale guard from old epoch cannot be released ──────────────────

#[test]
fn enrichment_stale_guard_release_after_transition() {
    let mut barrier = det_barrier(1);
    let old_guard = barrier.enter_critical(CriticalOpKind::DecisionEval, "t").unwrap();
    barrier.transition_now(epoch(2), TransitionReason::PolicyKeyRotation, "t").unwrap();
    assert!(!barrier.release_guard(&old_guard));
}

// ── test: guard from wrong epoch on empty barrier ────────────────────────

#[test]
fn enrichment_release_guard_wrong_epoch_returns_false() {
    let mut barrier = det_barrier(5);
    let fake = EpochGuard {
        guard_id: 999,
        epoch: epoch(99),
        op_kind: CriticalOpKind::RevocationCheck,
        trace_id: "fake".to_string(),
    };
    assert!(!barrier.release_guard(&fake));
}

// ── test: guard IDs are monotonically increasing ─────────────────────────

#[test]
fn enrichment_guard_ids_monotonically_increase() {
    let mut barrier = det_barrier(1);
    let mut prev = 0u64;
    for i in 0..20 {
        let g = barrier.enter_critical(CriticalOpKind::DecisionEval, &format!("t{i}")).unwrap();
        assert!(g.guard_id > prev);
        prev = g.guard_id;
    }
}

// ── test: guard IDs persist across transitions ───────────────────────────

#[test]
fn enrichment_guard_ids_persist_across_transitions() {
    let mut barrier = det_barrier(1);
    let g1 = barrier.enter_critical(CriticalOpKind::DecisionEval, "t").unwrap();
    barrier.release_guard(&g1);
    barrier.transition_now(epoch(2), TransitionReason::PolicyKeyRotation, "t").unwrap();
    let g2 = barrier.enter_critical(CriticalOpKind::DecisionEval, "t").unwrap();
    assert!(g2.guard_id > g1.guard_id);
}

// ── test: sequential transitions accumulate evidence ─────────────────────

#[test]
fn enrichment_sequential_transitions_accumulate_evidence() {
    let mut barrier = det_barrier(1);
    for i in 2..=6 {
        barrier.transition_now(epoch(i), TransitionReason::PolicyKeyRotation, &format!("t{i}")).unwrap();
    }
    assert_eq!(barrier.evidence().len(), 5);
    assert_eq!(barrier.current_epoch(), epoch(6));
    for (idx, ev) in barrier.evidence().iter().enumerate() {
        assert_eq!(ev.old_epoch, epoch((idx as u64) + 1));
        assert_eq!(ev.new_epoch, epoch((idx as u64) + 2));
    }
}

// ── test: all op kinds can acquire guards ────────────────────────────────

#[test]
fn enrichment_all_op_kinds_acquire_guards() {
    let mut barrier = det_barrier(1);
    for kind in all_op_kinds() {
        let guard = barrier.enter_critical(kind, "t").unwrap();
        assert_eq!(guard.op_kind, kind);
    }
    assert_eq!(barrier.in_flight(), 6);
}

// ── test: all transition reasons preserved in evidence ───────────────────

#[test]
fn enrichment_all_transition_reasons_preserved() {
    let mut barrier = det_barrier(1);
    for (i, reason) in all_reasons().iter().enumerate() {
        let ev = barrier
            .transition_now(epoch((i as u64) + 2), reason.clone(), &format!("r{i}"))
            .unwrap();
        assert_eq!(ev.reason, *reason);
    }
    assert_eq!(barrier.evidence().len(), 6);
}

// ── test: partial drain then force cancel ────────────────────────────────

#[test]
fn enrichment_partial_drain_then_force_cancel() {
    let mut barrier = det_barrier(1);
    let g1 = barrier.enter_critical(CriticalOpKind::DecisionEval, "t1").unwrap();
    let _g2 = barrier.enter_critical(CriticalOpKind::KeyDerivation, "t2").unwrap();
    let _g3 = barrier.enter_critical(CriticalOpKind::RemoteOperation, "t3").unwrap();

    barrier.begin_transition(epoch(2), TransitionReason::PolicyKeyRotation, "t").unwrap();
    barrier.release_guard(&g1);
    assert_eq!(barrier.in_flight(), 2);

    let cancelled = barrier.force_cancel_remaining().unwrap();
    assert_eq!(cancelled, 2);
    assert!(barrier.can_complete());

    let ev = barrier.complete_transition().unwrap();
    assert_eq!(ev.in_flight_at_start, 3);
    assert_eq!(ev.forced_cancellations, 2);
}

// ── test: epoch skipping allowed ─────────────────────────────────────────

#[test]
fn enrichment_epoch_skipping_allowed() {
    let mut barrier = det_barrier(1);
    let ev = barrier.transition_now(epoch(1000), TransitionReason::OperatorManualBump, "skip").unwrap();
    assert_eq!(ev.old_epoch, epoch(1));
    assert_eq!(ev.new_epoch, epoch(1000));
}

// ── test: barrier at high epoch value ────────────────────────────────────

#[test]
fn enrichment_barrier_high_epoch() {
    let high = u64::MAX - 1;
    let mut barrier = det_barrier(high);
    let ev = barrier.transition_now(epoch(u64::MAX), TransitionReason::PolicyKeyRotation, "t").unwrap();
    assert_eq!(ev.new_epoch, epoch(u64::MAX));
}

// ── test: barrier at epoch zero ──────────────────────────────────────────

#[test]
fn enrichment_barrier_at_epoch_zero() {
    let mut barrier = det_barrier(0);
    let guard = barrier.enter_critical(CriticalOpKind::DecisionEval, "t").unwrap();
    assert_eq!(guard.epoch, epoch(0));
    barrier.release_guard(&guard);
    let ev = barrier.transition_now(epoch(1), TransitionReason::OperatorManualBump, "t").unwrap();
    assert_eq!(ev.old_epoch, epoch(0));
}

// ── test: BarrierState Display uniqueness ────────────────────────────────

#[test]
fn enrichment_barrier_state_display_uniqueness() {
    let states = [BarrierState::Open, BarrierState::Draining, BarrierState::Finalizing];
    let strs: BTreeSet<String> = states.iter().map(|s| s.to_string()).collect();
    assert_eq!(strs.len(), 3);
}

// ── test: CriticalOpKind Display uniqueness ──────────────────────────────

#[test]
fn enrichment_critical_op_kind_display_uniqueness() {
    let strs: BTreeSet<String> = all_op_kinds().iter().map(|k| k.to_string()).collect();
    assert_eq!(strs.len(), 6);
}

// ── test: BarrierError Display uniqueness ────────────────────────────────

#[test]
fn enrichment_barrier_error_display_all_unique() {
    let variants = vec![
        BarrierError::EpochTransitioning { current_epoch: epoch(1), state: BarrierState::Draining },
        BarrierError::TransitionAlreadyInProgress { current_epoch: epoch(2) },
        BarrierError::DrainTimeout { epoch: epoch(3), remaining_guards: 5, timeout_ms: 1000 },
        BarrierError::NoTransitionInProgress,
        BarrierError::NonMonotonicTransition { current: epoch(5), attempted: epoch(3) },
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(strs.len(), 5);
}

// ── test: BarrierError implements std::error::Error ──────────────────────

#[test]
fn enrichment_barrier_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(BarrierError::NoTransitionInProgress);
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

// ── test: EpochGuard Display format ──────────────────────────────────────

#[test]
fn enrichment_epoch_guard_display_format() {
    let guard = EpochGuard {
        guard_id: 42,
        epoch: epoch(7),
        op_kind: CriticalOpKind::KeyDerivation,
        trace_id: "trace-42".to_string(),
    };
    let s = guard.to_string();
    assert!(s.contains("#42"));
    assert!(s.contains("key_derivation"));
}

// ── test: serde roundtrip BarrierState all variants ──────────────────────

#[test]
fn enrichment_serde_barrier_state_all_variants() {
    for state in [BarrierState::Open, BarrierState::Draining, BarrierState::Finalizing] {
        let json = serde_json::to_string(&state).unwrap();
        let back: BarrierState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

// ── test: serde roundtrip CriticalOpKind all variants ────────────────────

#[test]
fn enrichment_serde_critical_op_kind_all_variants() {
    for kind in all_op_kinds() {
        let json = serde_json::to_string(&kind).unwrap();
        let back: CriticalOpKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ── test: serde roundtrip EpochGuard ─────────────────────────────────────

#[test]
fn enrichment_serde_epoch_guard_roundtrip() {
    let guard = EpochGuard {
        guard_id: 7,
        epoch: epoch(3),
        op_kind: CriticalOpKind::RemoteOperation,
        trace_id: "t-123".to_string(),
    };
    let json = serde_json::to_string(&guard).unwrap();
    let back: EpochGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard, back);
}

// ── test: serde roundtrip TransitionEvidence ─────────────────────────────

#[test]
fn enrichment_serde_transition_evidence_roundtrip() {
    let ev = TransitionEvidence {
        old_epoch: epoch(1),
        new_epoch: epoch(2),
        reason: TransitionReason::PolicyKeyRotation,
        in_flight_at_start: 3,
        in_flight_at_complete: 0,
        forced_cancellations: 1,
        duration_ms: 0,
        trace_id: "test-trace".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: TransitionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ── test: serde roundtrip BarrierError all variants ──────────────────────

#[test]
fn enrichment_serde_barrier_error_all_variants() {
    let variants = vec![
        BarrierError::EpochTransitioning { current_epoch: epoch(1), state: BarrierState::Draining },
        BarrierError::TransitionAlreadyInProgress { current_epoch: epoch(2) },
        BarrierError::DrainTimeout { epoch: epoch(3), remaining_guards: 5, timeout_ms: 5000 },
        BarrierError::NoTransitionInProgress,
        BarrierError::NonMonotonicTransition { current: epoch(5), attempted: epoch(3) },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let back: BarrierError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ── test: serde roundtrip BarrierConfig ──────────────────────────────────

#[test]
fn enrichment_serde_barrier_config_roundtrip() {
    for cfg in [BarrierConfig::default(), BarrierConfig::deterministic()] {
        let json = serde_json::to_string(&cfg).unwrap();
        let back: BarrierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }
}

// ── test: BarrierConfig default values ───────────────────────────────────

#[test]
fn enrichment_barrier_config_default_values() {
    let cfg = BarrierConfig::default();
    assert_eq!(cfg.drain_timeout_ms, 5000);
    assert!(!cfg.deterministic);
}

// ── test: BarrierConfig deterministic values ─────────────────────────────

#[test]
fn enrichment_barrier_config_deterministic_values() {
    let cfg = BarrierConfig::deterministic();
    assert_eq!(cfg.drain_timeout_ms, 0);
    assert!(cfg.deterministic);
}

// ── test: config() accessor ──────────────────────────────────────────────

#[test]
fn enrichment_barrier_config_accessor() {
    let barrier = det_barrier(1);
    assert!(barrier.config().deterministic);
    assert_eq!(barrier.config().drain_timeout_ms, 0);
}

// ── test: deterministic replay produces identical evidence ───────────────

#[test]
fn enrichment_deterministic_replay() {
    let run = || -> Vec<TransitionEvidence> {
        let mut b = det_barrier(1);
        let _g = b.enter_critical(CriticalOpKind::EvidenceEmission, "t1").unwrap();
        b.transition_now(epoch(2), TransitionReason::PolicyKeyRotation, "trace-det").unwrap();
        b.transition_now(epoch(3), TransitionReason::LossMatrixUpdate, "trace-det-2").unwrap();
        b.evidence().to_vec()
    };
    assert_eq!(run(), run());
}

// ── test: evidence duration_ms is zero in deterministic mode ─────────────

#[test]
fn enrichment_evidence_duration_zero_in_deterministic() {
    let mut barrier = det_barrier(1);
    let ev = barrier.transition_now(epoch(2), TransitionReason::PolicyKeyRotation, "t").unwrap();
    assert_eq!(ev.duration_ms, 0);
}

// ── test: empty trace IDs allowed ────────────────────────────────────────

#[test]
fn enrichment_empty_trace_ids_allowed() {
    let mut barrier = det_barrier(1);
    let guard = barrier.enter_critical(CriticalOpKind::DecisionEval, "").unwrap();
    assert_eq!(guard.trace_id, "");
    barrier.release_guard(&guard);
    let ev = barrier.transition_now(epoch(2), TransitionReason::PolicyKeyRotation, "").unwrap();
    assert_eq!(ev.trace_id, "");
}

// ── test: large number of guards ─────────────────────────────────────────

#[test]
fn enrichment_large_number_of_guards() {
    let mut barrier = det_barrier(1);
    let mut guards = Vec::new();
    for i in 0..200 {
        guards.push(barrier.enter_critical(CriticalOpKind::EvidenceEmission, &format!("t{i}")).unwrap());
    }
    assert_eq!(barrier.in_flight(), 200);
    for g in &guards {
        barrier.release_guard(g);
    }
    assert_eq!(barrier.in_flight(), 0);
}

// ── test: transition evidence trace_id preserved ─────────────────────────

#[test]
fn enrichment_evidence_trace_id_preserved() {
    let mut barrier = det_barrier(1);
    barrier.transition_now(epoch(2), TransitionReason::PolicyKeyRotation, "unique-trace-xyz").unwrap();
    assert_eq!(barrier.evidence()[0].trace_id, "unique-trace-xyz");
}

// ── test: clone independence of TransitionEvidence ───────────────────────

#[test]
fn enrichment_transition_evidence_clone_independence() {
    let ev = TransitionEvidence {
        old_epoch: epoch(1),
        new_epoch: epoch(2),
        reason: TransitionReason::LossMatrixUpdate,
        in_flight_at_start: 5,
        in_flight_at_complete: 0,
        forced_cancellations: 3,
        duration_ms: 100,
        trace_id: "clone-ev".to_string(),
    };
    let mut cloned = ev.clone();
    cloned.forced_cancellations = 999;
    assert_ne!(ev.forced_cancellations, cloned.forced_cancellations);
    assert_eq!(ev.forced_cancellations, 3);
}

// ── test: JSON field names for TransitionEvidence ────────────────────────

#[test]
fn enrichment_transition_evidence_json_field_names() {
    let ev = TransitionEvidence {
        old_epoch: epoch(1),
        new_epoch: epoch(2),
        reason: TransitionReason::PolicyKeyRotation,
        in_flight_at_start: 0,
        in_flight_at_complete: 0,
        forced_cancellations: 0,
        duration_ms: 0,
        trace_id: "t".to_string(),
    };
    let val = serde_json::to_value(&ev).unwrap();
    let obj = val.as_object().unwrap();
    for key in ["old_epoch", "new_epoch", "reason", "in_flight_at_start",
                "in_flight_at_complete", "forced_cancellations", "duration_ms", "trace_id"] {
        assert!(obj.contains_key(key), "missing field: {key}");
    }
    assert_eq!(obj.len(), 8);
}

// ── test: JSON field names for EpochGuard ────────────────────────────────

#[test]
fn enrichment_epoch_guard_json_field_names() {
    let guard = EpochGuard {
        guard_id: 1,
        epoch: epoch(5),
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

// ── test: BarrierError Display content checks ────────────────────────────

#[test]
fn enrichment_barrier_error_display_content() {
    let err = BarrierError::DrainTimeout { epoch: epoch(7), remaining_guards: 3, timeout_ms: 5000 };
    let msg = err.to_string();
    assert!(msg.contains("3 guards remaining"));
    assert!(msg.contains("5000ms"));

    let err2 = BarrierError::NonMonotonicTransition { current: epoch(10), attempted: epoch(5) };
    let msg2 = err2.to_string();
    assert!(msg2.contains("non-monotonic"));
}

// ── test: can_complete false when open ────────────────────────────────────

#[test]
fn enrichment_can_complete_false_when_open() {
    let barrier = det_barrier(1);
    assert!(!barrier.can_complete());
}

// ── test: evidence starts empty ──────────────────────────────────────────

#[test]
fn enrichment_evidence_starts_empty() {
    let barrier = det_barrier(1);
    assert!(barrier.evidence().is_empty());
}

// ── test: release guard twice - second fails ─────────────────────────────

#[test]
fn enrichment_release_guard_twice_second_fails() {
    let mut barrier = det_barrier(1);
    let guard = barrier.enter_critical(CriticalOpKind::DecisionEval, "t").unwrap();
    assert!(barrier.release_guard(&guard));
    assert!(!barrier.release_guard(&guard));
}

// ── test: transition_now with non-monotonic returns error ────────────────

#[test]
fn enrichment_transition_now_non_monotonic_error() {
    let mut barrier = det_barrier(10);
    let err = barrier.transition_now(epoch(5), TransitionReason::PolicyKeyRotation, "t").unwrap_err();
    assert!(matches!(err, BarrierError::NonMonotonicTransition { .. }));
}
