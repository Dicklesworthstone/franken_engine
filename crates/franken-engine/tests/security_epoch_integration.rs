//! Integration tests for the `security_epoch` module.
//!
//! Tests SecurityEpoch, EpochTracker, EpochMetadata, validity windows,
//! monotonicity enforcement, transition history, and serde roundtrips.

#![forbid(unsafe_code)]
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

use frankenengine_engine::security_epoch::{
    EpochMetadata, EpochTracker, EpochValidationError, MonotonicityViolation, SecurityEpoch,
    TransitionReason, TransitionRecord,
};

// ---------------------------------------------------------------------------
// SecurityEpoch
// ---------------------------------------------------------------------------

#[test]
fn genesis_epoch_is_zero() {
    assert_eq!(SecurityEpoch::GENESIS.as_u64(), 0);
}

#[test]
fn from_raw_roundtrip() {
    let epoch = SecurityEpoch::from_raw(42);
    assert_eq!(epoch.as_u64(), 42);
}

#[test]
fn next_increments_by_one() {
    let epoch = SecurityEpoch::from_raw(5);
    assert_eq!(epoch.next().as_u64(), 6);
}

#[test]
fn next_saturates_at_max() {
    let epoch = SecurityEpoch::from_raw(u64::MAX);
    assert_eq!(epoch.next().as_u64(), u64::MAX);
}

#[test]
fn epoch_ordering() {
    let a = SecurityEpoch::from_raw(1);
    let b = SecurityEpoch::from_raw(2);
    assert!(a < b);
    assert!(b > a);
    assert_eq!(a, SecurityEpoch::from_raw(1));
}

#[test]
fn epoch_display() {
    let epoch = SecurityEpoch::from_raw(42);
    assert_eq!(epoch.to_string(), "epoch:42");
}

#[test]
fn epoch_serde_roundtrip() {
    let epoch = SecurityEpoch::from_raw(99);
    let json = serde_json::to_string(&epoch).unwrap();
    let decoded: SecurityEpoch = serde_json::from_str(&json).unwrap();
    assert_eq!(epoch, decoded);
}

// ---------------------------------------------------------------------------
// TransitionReason
// ---------------------------------------------------------------------------

#[test]
fn transition_reason_display_all() {
    let cases = [
        (TransitionReason::PolicyKeyRotation, "policy_key_rotation"),
        (
            TransitionReason::RevocationFrontierAdvance,
            "revocation_frontier_advance",
        ),
        (
            TransitionReason::GuardrailConfigChange,
            "guardrail_config_change",
        ),
        (TransitionReason::LossMatrixUpdate, "loss_matrix_update"),
        (
            TransitionReason::RemoteTrustConfigChange,
            "remote_trust_config_change",
        ),
        (TransitionReason::OperatorManualBump, "operator_manual_bump"),
    ];
    for (reason, expected) in &cases {
        assert_eq!(reason.to_string(), *expected);
    }
}

#[test]
fn transition_reason_serde_roundtrip() {
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let decoded: TransitionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, &decoded);
    }
}

// ---------------------------------------------------------------------------
// EpochMetadata
// ---------------------------------------------------------------------------

#[test]
fn open_ended_metadata() {
    let epoch = SecurityEpoch::from_raw(5);
    let meta = EpochMetadata::open_ended(epoch);
    assert_eq!(meta.epoch_id, epoch);
    assert_eq!(meta.valid_from_epoch, epoch);
    assert!(meta.valid_until_epoch.is_none());
}

#[test]
fn windowed_metadata() {
    let current = SecurityEpoch::from_raw(5);
    let from = SecurityEpoch::from_raw(3);
    let until = SecurityEpoch::from_raw(10);
    let meta = EpochMetadata::windowed(current, from, until);
    assert_eq!(meta.epoch_id, current);
    assert_eq!(meta.valid_from_epoch, from);
    assert_eq!(meta.valid_until_epoch, Some(until));
}

#[test]
fn epoch_metadata_serde_roundtrip() {
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(3),
        SecurityEpoch::from_raw(10),
    );
    let json = serde_json::to_string(&meta).unwrap();
    let decoded: EpochMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, decoded);
}

// ---------------------------------------------------------------------------
// EpochValidationError
// ---------------------------------------------------------------------------

#[test]
fn validation_error_display_all_variants() {
    let errors: Vec<(EpochValidationError, &str)> = vec![
        (
            EpochValidationError::NotYetValid {
                current_epoch: SecurityEpoch::from_raw(1),
                valid_from: SecurityEpoch::from_raw(5),
            },
            "not yet valid",
        ),
        (
            EpochValidationError::Expired {
                current_epoch: SecurityEpoch::from_raw(10),
                valid_until: SecurityEpoch::from_raw(5),
            },
            "expired",
        ),
        (
            EpochValidationError::FutureArtifact {
                current_epoch: SecurityEpoch::from_raw(5),
                artifact_epoch: SecurityEpoch::from_raw(10),
            },
            "future epoch",
        ),
        (
            EpochValidationError::InvertedWindow {
                valid_from: SecurityEpoch::from_raw(10),
                valid_until: SecurityEpoch::from_raw(5),
            },
            "inverted",
        ),
    ];
    for (err, substr) in &errors {
        let msg = format!("{err}");
        assert!(msg.contains(substr), "'{msg}' should contain '{substr}'");
    }
}

#[test]
fn validation_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(EpochValidationError::Expired {
        current_epoch: SecurityEpoch::from_raw(10),
        valid_until: SecurityEpoch::from_raw(5),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn validation_error_serde_roundtrip() {
    let err = EpochValidationError::NotYetValid {
        current_epoch: SecurityEpoch::from_raw(1),
        valid_from: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&err).unwrap();
    let decoded: EpochValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, decoded);
}

// ---------------------------------------------------------------------------
// MonotonicityViolation
// ---------------------------------------------------------------------------

#[test]
fn monotonicity_violation_display() {
    let v = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    let msg = v.to_string();
    assert!(msg.contains("monotonicity violation"));
}

#[test]
fn monotonicity_violation_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn monotonicity_violation_serde_roundtrip() {
    let v = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: MonotonicityViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// ---------------------------------------------------------------------------
// TransitionRecord
// ---------------------------------------------------------------------------

#[test]
fn transition_record_serde_roundtrip() {
    let rec = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(5),
        new_epoch: SecurityEpoch::from_raw(6),
        reason: TransitionReason::PolicyKeyRotation,
        trace_id: "trace-1".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let decoded: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, decoded);
}

// ---------------------------------------------------------------------------
// EpochTracker
// ---------------------------------------------------------------------------

#[test]
fn tracker_new_starts_at_genesis() {
    let tracker = EpochTracker::new();
    assert_eq!(tracker.current(), SecurityEpoch::GENESIS);
    assert_eq!(tracker.transition_count(), 0);
}

#[test]
fn tracker_default_is_genesis() {
    let tracker = EpochTracker::default();
    assert_eq!(tracker.current(), SecurityEpoch::GENESIS);
}

#[test]
fn tracker_from_persisted() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(42));
    assert_eq!(tracker.current().as_u64(), 42);
}

#[test]
fn tracker_advance() {
    let mut tracker = EpochTracker::new();
    let e1 = tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    assert_eq!(e1.as_u64(), 1);
    assert_eq!(tracker.current().as_u64(), 1);
    assert_eq!(tracker.transition_count(), 1);
}

#[test]
fn tracker_advance_multiple() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    tracker
        .advance(TransitionReason::LossMatrixUpdate, "t2")
        .unwrap();
    tracker
        .advance(TransitionReason::GuardrailConfigChange, "t3")
        .unwrap();
    assert_eq!(tracker.current().as_u64(), 3);
    assert_eq!(tracker.transition_count(), 3);
}

#[test]
fn tracker_advance_at_max_fails() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(u64::MAX));
    let err = tracker
        .advance(TransitionReason::OperatorManualBump, "t1")
        .unwrap_err();
    assert_eq!(err.current.as_u64(), u64::MAX);
}

#[test]
fn tracker_transition_counts() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t2")
        .unwrap();
    tracker
        .advance(TransitionReason::LossMatrixUpdate, "t3")
        .unwrap();

    assert_eq!(
        tracker.transition_counts().get("policy_key_rotation"),
        Some(&2)
    );
    assert_eq!(
        tracker.transition_counts().get("loss_matrix_update"),
        Some(&1)
    );
}

#[test]
fn tracker_transitions_history() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    let transitions = tracker.transitions();
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].previous_epoch, SecurityEpoch::GENESIS);
    assert_eq!(transitions[0].new_epoch, SecurityEpoch::from_raw(1));
    assert_eq!(transitions[0].trace_id, "t1");
}

// ---------------------------------------------------------------------------
// EpochTracker — verify_persisted
// ---------------------------------------------------------------------------

#[test]
fn verify_persisted_higher_epoch_succeeds() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    assert_eq!(tracker.current().as_u64(), 1);

    tracker
        .verify_persisted(SecurityEpoch::from_raw(5))
        .unwrap();
    assert_eq!(tracker.current().as_u64(), 5);
}

#[test]
fn verify_persisted_same_epoch_succeeds() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(10));
    tracker
        .verify_persisted(SecurityEpoch::from_raw(10))
        .unwrap();
    assert_eq!(tracker.current().as_u64(), 10);
}

#[test]
fn verify_persisted_lower_epoch_fails() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(10));
    let err = tracker
        .verify_persisted(SecurityEpoch::from_raw(5))
        .unwrap_err();
    assert_eq!(err.current.as_u64(), 10);
    assert_eq!(err.attempted.as_u64(), 5);
}

// ---------------------------------------------------------------------------
// EpochTracker — validate_artifact
// ---------------------------------------------------------------------------

#[test]
fn validate_artifact_open_ended_current_epoch() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    let meta = tracker.stamp_open_ended();
    tracker.validate_artifact(&meta).unwrap();
}

#[test]
fn validate_artifact_windowed_valid() {
    let mut tracker = EpochTracker::new();
    for _ in 0..5 {
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t")
            .unwrap();
    }
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(3),
        SecurityEpoch::from_raw(2),
        SecurityEpoch::from_raw(10),
    );
    tracker.validate_artifact(&meta).unwrap();
}

#[test]
fn validate_artifact_not_yet_valid() {
    let tracker = EpochTracker::new(); // epoch 0
    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(0));
    let meta_future = EpochMetadata {
        epoch_id: SecurityEpoch::GENESIS,
        valid_from_epoch: SecurityEpoch::from_raw(5),
        valid_until_epoch: None,
    };
    tracker.validate_artifact(&meta).unwrap(); // control: this is valid
    let errors = tracker.validate_artifact(&meta_future).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::NotYetValid { .. }))
    );
}

#[test]
fn validate_artifact_expired() {
    let mut tracker = EpochTracker::new();
    for _ in 0..10 {
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t")
            .unwrap();
    }
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(5),
    );
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::Expired { .. }))
    );
}

#[test]
fn validate_artifact_future_artifact() {
    let tracker = EpochTracker::new(); // epoch 0
    let meta = EpochMetadata {
        epoch_id: SecurityEpoch::from_raw(5),
        valid_from_epoch: SecurityEpoch::GENESIS,
        valid_until_epoch: None,
    };
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::FutureArtifact { .. }))
    );
}

#[test]
fn validate_artifact_inverted_window() {
    let tracker = EpochTracker::new();
    let meta = EpochMetadata::windowed(
        SecurityEpoch::GENESIS,
        SecurityEpoch::from_raw(10),
        SecurityEpoch::from_raw(5),
    );
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::InvertedWindow { .. }))
    );
}

// ---------------------------------------------------------------------------
// EpochTracker — stamp methods
// ---------------------------------------------------------------------------

#[test]
fn stamp_open_ended_uses_current_epoch() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    let meta = tracker.stamp_open_ended();
    assert_eq!(meta.epoch_id, tracker.current());
    assert_eq!(meta.valid_from_epoch, tracker.current());
    assert!(meta.valid_until_epoch.is_none());
}

#[test]
fn stamp_windowed_uses_current_epoch() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    let meta = tracker.stamp_windowed(SecurityEpoch::from_raw(0), SecurityEpoch::from_raw(10));
    assert_eq!(meta.epoch_id, tracker.current());
    assert_eq!(meta.valid_from_epoch, SecurityEpoch::GENESIS);
    assert_eq!(meta.valid_until_epoch, Some(SecurityEpoch::from_raw(10)));
}

// ---------------------------------------------------------------------------
// EpochTracker serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn epoch_tracker_serde_roundtrip() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    tracker
        .advance(TransitionReason::LossMatrixUpdate, "t2")
        .unwrap();
    let json = serde_json::to_string(&tracker).unwrap();
    let decoded: EpochTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.current(), tracker.current());
    assert_eq!(decoded.transition_count(), tracker.transition_count());
}
