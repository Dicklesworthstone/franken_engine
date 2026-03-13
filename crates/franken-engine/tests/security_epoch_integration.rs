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

// ===========================================================================
// Enrichment tests (PearlTower 2026-03-12)
// ===========================================================================

// ---------------------------------------------------------------------------
// SecurityEpoch — Debug, Clone, Display, serde edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_security_epoch_debug_contains_value() {
    let epoch = SecurityEpoch::from_raw(99);
    let dbg = format!("{epoch:?}");
    assert!(
        dbg.contains("99"),
        "Debug output should contain the value: {dbg}"
    );
}

#[test]
fn enrichment_security_epoch_debug_genesis() {
    let dbg = format!("{:?}", SecurityEpoch::GENESIS);
    assert!(
        dbg.contains("0"),
        "Debug of GENESIS should contain 0: {dbg}"
    );
}

#[test]
fn enrichment_security_epoch_clone_on_copy_identity() {
    let a = SecurityEpoch::from_raw(77);
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.as_u64(), b.as_u64());
}

#[test]
fn enrichment_security_epoch_display_genesis() {
    assert_eq!(SecurityEpoch::GENESIS.to_string(), "epoch:0");
}

#[test]
fn enrichment_security_epoch_display_large_value() {
    let epoch = SecurityEpoch::from_raw(1_000_000);
    assert_eq!(epoch.to_string(), "epoch:1000000");
}

#[test]
fn enrichment_security_epoch_display_max() {
    let epoch = SecurityEpoch::from_raw(u64::MAX);
    assert_eq!(epoch.to_string(), format!("epoch:{}", u64::MAX));
}

#[test]
fn enrichment_security_epoch_serde_zero() {
    let epoch = SecurityEpoch::from_raw(0);
    let json = serde_json::to_string(&epoch).unwrap();
    let decoded: SecurityEpoch = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, SecurityEpoch::GENESIS);
}

#[test]
fn enrichment_security_epoch_serde_max() {
    let epoch = SecurityEpoch::from_raw(u64::MAX);
    let json = serde_json::to_string(&epoch).unwrap();
    let decoded: SecurityEpoch = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.as_u64(), u64::MAX);
}

#[test]
fn enrichment_security_epoch_json_is_integer() {
    let epoch = SecurityEpoch::from_raw(42);
    let json = serde_json::to_string(&epoch).unwrap();
    assert_eq!(json, "42");
}

#[test]
fn enrichment_security_epoch_ordering_reflexive() {
    let a = SecurityEpoch::from_raw(5);
    assert!(a >= a);
    assert!(a <= a);
    assert_eq!(a, a);
}

#[test]
fn enrichment_security_epoch_ordering_chain() {
    let a = SecurityEpoch::from_raw(1);
    let b = SecurityEpoch::from_raw(2);
    let c = SecurityEpoch::from_raw(3);
    assert!(a < b);
    assert!(b < c);
    assert!(a < c); // transitivity
}

#[test]
fn enrichment_security_epoch_next_from_genesis() {
    assert_eq!(SecurityEpoch::GENESIS.next().as_u64(), 1);
}

#[test]
fn enrichment_security_epoch_next_chain() {
    let e = SecurityEpoch::from_raw(0);
    assert_eq!(e.next().next().next().as_u64(), 3);
}

#[test]
fn enrichment_security_epoch_next_near_max() {
    let e = SecurityEpoch::from_raw(u64::MAX - 1);
    assert_eq!(e.next().as_u64(), u64::MAX);
    // One more should saturate
    assert_eq!(e.next().next().as_u64(), u64::MAX);
}

#[test]
fn enrichment_security_epoch_from_raw_preserves_all_bits() {
    let vals = [0u64, 1, 255, 65535, u64::MAX / 2, u64::MAX - 1, u64::MAX];
    for v in vals {
        assert_eq!(SecurityEpoch::from_raw(v).as_u64(), v);
    }
}

#[test]
fn enrichment_security_epoch_genesis_const_is_zero() {
    assert_eq!(SecurityEpoch::GENESIS, SecurityEpoch::from_raw(0));
}

// ---------------------------------------------------------------------------
// TransitionReason — Debug, Clone, serde, Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transition_reason_debug_all_variants() {
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    for r in &reasons {
        let dbg = format!("{r:?}");
        assert!(!dbg.is_empty(), "Debug should be non-empty");
    }
}

#[test]
fn enrichment_transition_reason_clone_independence() {
    let original = TransitionReason::RemoteTrustConfigChange;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_transition_reason_inequality() {
    let a = TransitionReason::PolicyKeyRotation;
    let b = TransitionReason::OperatorManualBump;
    assert_ne!(a, b);
}

#[test]
fn enrichment_transition_reason_display_no_spaces() {
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    for r in &reasons {
        let s = r.to_string();
        assert!(
            !s.contains(' '),
            "Display should be snake_case without spaces: {s}"
        );
    }
}

#[test]
fn enrichment_transition_reason_serde_json_string() {
    let reason = TransitionReason::LossMatrixUpdate;
    let json = serde_json::to_string(&reason).unwrap();
    assert!(
        json.starts_with('"'),
        "Enum should serialize as JSON string: {json}"
    );
    assert!(json.ends_with('"'));
}

#[test]
fn enrichment_transition_reason_serde_all_six_distinct() {
    use std::collections::BTreeSet;
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    let jsons: BTreeSet<String> = reasons
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    assert_eq!(jsons.len(), 6, "All 6 reasons should produce distinct JSON");
}

// ---------------------------------------------------------------------------
// EpochMetadata — Debug, Clone, serde, JSON fields, edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_epoch_metadata_debug_contains_struct_name() {
    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(1));
    let dbg = format!("{meta:?}");
    assert!(
        dbg.contains("EpochMetadata"),
        "Debug should name the struct: {dbg}"
    );
}

#[test]
fn enrichment_epoch_metadata_clone_independence() {
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(2),
        SecurityEpoch::from_raw(8),
    );
    let cloned = meta.clone();
    assert_eq!(meta, cloned);
}

#[test]
fn enrichment_epoch_metadata_open_ended_json_field_names() {
    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(3));
    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("\"epoch_id\""), "Missing epoch_id field");
    assert!(
        json.contains("\"valid_from_epoch\""),
        "Missing valid_from_epoch"
    );
    assert!(
        json.contains("\"valid_until_epoch\""),
        "Missing valid_until_epoch"
    );
}

#[test]
fn enrichment_epoch_metadata_open_ended_null_until() {
    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(10));
    let json = serde_json::to_string(&meta).unwrap();
    assert!(
        json.contains("\"valid_until_epoch\":null"),
        "open_ended should serialize valid_until_epoch as null: {json}"
    );
}

#[test]
fn enrichment_epoch_metadata_windowed_json_has_until_value() {
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(3),
        SecurityEpoch::from_raw(10),
    );
    let json = serde_json::to_string(&meta).unwrap();
    assert!(
        !json.contains("null"),
        "windowed metadata should not have null in JSON: {json}"
    );
}

#[test]
fn enrichment_epoch_metadata_serde_roundtrip_open_ended() {
    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(0));
    let json = serde_json::to_string(&meta).unwrap();
    let decoded: EpochMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, decoded);
}

#[test]
fn enrichment_epoch_metadata_serde_roundtrip_windowed_at_max() {
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(u64::MAX),
        SecurityEpoch::from_raw(0),
        SecurityEpoch::from_raw(u64::MAX),
    );
    let json = serde_json::to_string(&meta).unwrap();
    let decoded: EpochMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, decoded);
}

#[test]
fn enrichment_epoch_metadata_windowed_same_from_until() {
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(5),
    );
    assert_eq!(meta.valid_from_epoch, meta.valid_until_epoch.unwrap());
}

#[test]
fn enrichment_epoch_metadata_equality_reflexive() {
    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(7));
    assert_eq!(meta, meta);
}

#[test]
fn enrichment_epoch_metadata_inequality_different_epoch_id() {
    let a = EpochMetadata::open_ended(SecurityEpoch::from_raw(1));
    let b = EpochMetadata::open_ended(SecurityEpoch::from_raw(2));
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// EpochValidationError — Debug, Clone, Display exact, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_epoch_validation_error_debug_all_variants() {
    let errors = vec![
        EpochValidationError::NotYetValid {
            current_epoch: SecurityEpoch::from_raw(1),
            valid_from: SecurityEpoch::from_raw(5),
        },
        EpochValidationError::Expired {
            current_epoch: SecurityEpoch::from_raw(10),
            valid_until: SecurityEpoch::from_raw(5),
        },
        EpochValidationError::FutureArtifact {
            current_epoch: SecurityEpoch::from_raw(3),
            artifact_epoch: SecurityEpoch::from_raw(7),
        },
        EpochValidationError::InvertedWindow {
            valid_from: SecurityEpoch::from_raw(10),
            valid_until: SecurityEpoch::from_raw(3),
        },
    ];
    for err in &errors {
        let dbg = format!("{err:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_epoch_validation_error_clone_equality() {
    let err = EpochValidationError::NotYetValid {
        current_epoch: SecurityEpoch::from_raw(1),
        valid_from: SecurityEpoch::from_raw(10),
    };
    assert_eq!(err, err.clone());
}

#[test]
fn enrichment_epoch_validation_error_not_yet_valid_display_exact() {
    let err = EpochValidationError::NotYetValid {
        current_epoch: SecurityEpoch::from_raw(0),
        valid_from: SecurityEpoch::from_raw(100),
    };
    assert_eq!(
        err.to_string(),
        "artifact not yet valid: current epoch:0, valid_from epoch:100"
    );
}

#[test]
fn enrichment_epoch_validation_error_expired_display_exact() {
    let err = EpochValidationError::Expired {
        current_epoch: SecurityEpoch::from_raw(50),
        valid_until: SecurityEpoch::from_raw(20),
    };
    assert_eq!(
        err.to_string(),
        "artifact expired: current epoch:50, valid_until epoch:20"
    );
}

#[test]
fn enrichment_epoch_validation_error_future_display_exact() {
    let err = EpochValidationError::FutureArtifact {
        current_epoch: SecurityEpoch::from_raw(10),
        artifact_epoch: SecurityEpoch::from_raw(99),
    };
    assert_eq!(
        err.to_string(),
        "artifact from future epoch: current epoch:10, artifact epoch:99"
    );
}

#[test]
fn enrichment_epoch_validation_error_inverted_display_exact() {
    let err = EpochValidationError::InvertedWindow {
        valid_from: SecurityEpoch::from_raw(50),
        valid_until: SecurityEpoch::from_raw(10),
    };
    assert_eq!(
        err.to_string(),
        "inverted validity window: from epoch:50 > until epoch:10"
    );
}

#[test]
fn enrichment_epoch_validation_error_serde_all_variants() {
    let variants = vec![
        EpochValidationError::NotYetValid {
            current_epoch: SecurityEpoch::from_raw(0),
            valid_from: SecurityEpoch::from_raw(1),
        },
        EpochValidationError::Expired {
            current_epoch: SecurityEpoch::from_raw(100),
            valid_until: SecurityEpoch::from_raw(50),
        },
        EpochValidationError::FutureArtifact {
            current_epoch: SecurityEpoch::from_raw(1),
            artifact_epoch: SecurityEpoch::from_raw(999),
        },
        EpochValidationError::InvertedWindow {
            valid_from: SecurityEpoch::from_raw(20),
            valid_until: SecurityEpoch::from_raw(10),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let decoded: EpochValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

#[test]
fn enrichment_epoch_validation_error_source_none_all() {
    let errors = vec![
        EpochValidationError::NotYetValid {
            current_epoch: SecurityEpoch::from_raw(0),
            valid_from: SecurityEpoch::from_raw(1),
        },
        EpochValidationError::Expired {
            current_epoch: SecurityEpoch::from_raw(5),
            valid_until: SecurityEpoch::from_raw(2),
        },
        EpochValidationError::FutureArtifact {
            current_epoch: SecurityEpoch::from_raw(1),
            artifact_epoch: SecurityEpoch::from_raw(5),
        },
        EpochValidationError::InvertedWindow {
            valid_from: SecurityEpoch::from_raw(9),
            valid_until: SecurityEpoch::from_raw(3),
        },
    ];
    for e in &errors {
        let dyn_err: &dyn std::error::Error = e;
        assert!(dyn_err.source().is_none());
    }
}

#[test]
fn enrichment_epoch_validation_error_inequality_different_variants() {
    let a = EpochValidationError::NotYetValid {
        current_epoch: SecurityEpoch::from_raw(1),
        valid_from: SecurityEpoch::from_raw(5),
    };
    let b = EpochValidationError::Expired {
        current_epoch: SecurityEpoch::from_raw(1),
        valid_until: SecurityEpoch::from_raw(5),
    };
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// MonotonicityViolation — Debug, Display exact, Clone, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_monotonicity_violation_debug_contains_struct() {
    let v = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    let dbg = format!("{v:?}");
    assert!(
        dbg.contains("MonotonicityViolation"),
        "Debug should name struct: {dbg}"
    );
}

#[test]
fn enrichment_monotonicity_violation_display_exact() {
    let v = MonotonicityViolation {
        current: SecurityEpoch::from_raw(100),
        attempted: SecurityEpoch::from_raw(50),
    };
    assert_eq!(
        v.to_string(),
        "epoch monotonicity violation: current epoch:100, attempted epoch:50"
    );
}

#[test]
fn enrichment_monotonicity_violation_clone_independence() {
    let v = MonotonicityViolation {
        current: SecurityEpoch::from_raw(7),
        attempted: SecurityEpoch::from_raw(3),
    };
    let c = v.clone();
    assert_eq!(v, c);
}

#[test]
fn enrichment_monotonicity_violation_serde_at_max() {
    let v = MonotonicityViolation {
        current: SecurityEpoch::from_raw(u64::MAX),
        attempted: SecurityEpoch::from_raw(u64::MAX),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: MonotonicityViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn enrichment_monotonicity_violation_json_field_names() {
    let v = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&v).unwrap();
    assert!(
        json.contains("\"current\""),
        "Missing 'current' field: {json}"
    );
    assert!(
        json.contains("\"attempted\""),
        "Missing 'attempted' field: {json}"
    );
}

#[test]
fn enrichment_monotonicity_violation_source_none() {
    let v = MonotonicityViolation {
        current: SecurityEpoch::from_raw(5),
        attempted: SecurityEpoch::from_raw(2),
    };
    let e: &dyn std::error::Error = &v;
    assert!(e.source().is_none());
}

#[test]
fn enrichment_monotonicity_violation_equality() {
    let a = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    let b = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    assert_eq!(a, b);
}

#[test]
fn enrichment_monotonicity_violation_inequality() {
    let a = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    let b = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(6),
    };
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// TransitionRecord — Debug, Clone, serde, fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transition_record_debug_contains_struct() {
    let rec = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(0),
        new_epoch: SecurityEpoch::from_raw(1),
        reason: TransitionReason::PolicyKeyRotation,
        trace_id: "trace-debug".to_string(),
    };
    let dbg = format!("{rec:?}");
    assert!(
        dbg.contains("TransitionRecord"),
        "Debug should name struct: {dbg}"
    );
}

#[test]
fn enrichment_transition_record_clone_independence() {
    let rec = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(5),
        new_epoch: SecurityEpoch::from_raw(6),
        reason: TransitionReason::GuardrailConfigChange,
        trace_id: "clone-test".to_string(),
    };
    let cloned = rec.clone();
    assert_eq!(rec, cloned);
}

#[test]
fn enrichment_transition_record_json_field_names() {
    let rec = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(0),
        new_epoch: SecurityEpoch::from_raw(1),
        reason: TransitionReason::PolicyKeyRotation,
        trace_id: "field-check".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    for field in &["previous_epoch", "new_epoch", "reason", "trace_id"] {
        assert!(
            json.contains(field),
            "Missing field {field} in JSON: {json}"
        );
    }
}

#[test]
fn enrichment_transition_record_serde_all_reasons() {
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    for (i, reason) in reasons.iter().enumerate() {
        let rec = TransitionRecord {
            previous_epoch: SecurityEpoch::from_raw(i as u64),
            new_epoch: SecurityEpoch::from_raw(i as u64 + 1),
            reason: reason.clone(),
            trace_id: format!("r-{i}"),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let decoded: TransitionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, decoded);
    }
}

#[test]
fn enrichment_transition_record_empty_trace_id() {
    let rec = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(0),
        new_epoch: SecurityEpoch::from_raw(1),
        reason: TransitionReason::PolicyKeyRotation,
        trace_id: String::new(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let decoded: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.trace_id, "");
}

#[test]
fn enrichment_transition_record_inequality() {
    let a = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(0),
        new_epoch: SecurityEpoch::from_raw(1),
        reason: TransitionReason::PolicyKeyRotation,
        trace_id: "a".to_string(),
    };
    let b = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(0),
        new_epoch: SecurityEpoch::from_raw(1),
        reason: TransitionReason::PolicyKeyRotation,
        trace_id: "b".to_string(),
    };
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// EpochTracker — Debug, Clone, Default, serde, advance, validate edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_epoch_tracker_debug_contains_struct() {
    let tracker = EpochTracker::new();
    let dbg = format!("{tracker:?}");
    assert!(
        dbg.contains("EpochTracker"),
        "Debug should name struct: {dbg}"
    );
}

#[test]
fn enrichment_epoch_tracker_clone_deep_equality() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    tracker
        .advance(TransitionReason::LossMatrixUpdate, "t2")
        .unwrap();
    let cloned = tracker.clone();
    assert_eq!(cloned.current(), tracker.current());
    assert_eq!(cloned.transition_count(), tracker.transition_count());
    assert_eq!(cloned.transitions().len(), tracker.transitions().len());
    assert_eq!(
        cloned.transition_counts().len(),
        tracker.transition_counts().len()
    );
}

#[test]
fn enrichment_epoch_tracker_clone_independence() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    let mut cloned = tracker.clone();
    cloned
        .advance(TransitionReason::LossMatrixUpdate, "t2")
        .unwrap();
    assert_eq!(tracker.current().as_u64(), 1);
    assert_eq!(cloned.current().as_u64(), 2);
}

#[test]
fn enrichment_epoch_tracker_default_transition_count_zero() {
    let tracker = EpochTracker::default();
    assert_eq!(tracker.transition_count(), 0);
    assert!(tracker.transitions().is_empty());
    assert!(tracker.transition_counts().is_empty());
}

#[test]
fn enrichment_epoch_tracker_serde_preserves_transitions() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::RevocationFrontierAdvance, "rev-1")
        .unwrap();
    tracker
        .advance(TransitionReason::OperatorManualBump, "manual-1")
        .unwrap();
    let json = serde_json::to_string(&tracker).unwrap();
    let decoded: EpochTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.transitions().len(), 2);
    assert_eq!(
        decoded.transitions()[0].reason,
        TransitionReason::RevocationFrontierAdvance
    );
    assert_eq!(
        decoded.transitions()[1].reason,
        TransitionReason::OperatorManualBump
    );
}

#[test]
fn enrichment_epoch_tracker_serde_json_field_names() {
    let tracker = EpochTracker::new();
    let json = serde_json::to_string(&tracker).unwrap();
    assert!(
        json.contains("\"current_epoch\""),
        "Missing current_epoch: {json}"
    );
    assert!(
        json.contains("\"transitions\""),
        "Missing transitions: {json}"
    );
    assert!(
        json.contains("\"transition_counts\""),
        "Missing transition_counts: {json}"
    );
}

#[test]
fn enrichment_epoch_tracker_serde_deterministic() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "d1")
        .unwrap();
    tracker
        .advance(TransitionReason::LossMatrixUpdate, "d2")
        .unwrap();
    let json1 = serde_json::to_string(&tracker).unwrap();
    let json2 = serde_json::to_string(&tracker).unwrap();
    assert_eq!(json1, json2, "Serialization must be deterministic");
}

#[test]
fn enrichment_epoch_tracker_advance_error_does_not_change_state() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(u64::MAX));
    let count_before = tracker.transition_count();
    let current_before = tracker.current();
    let _err = tracker
        .advance(TransitionReason::PolicyKeyRotation, "fail")
        .unwrap_err();
    assert_eq!(tracker.current(), current_before);
    assert_eq!(tracker.transition_count(), count_before);
}

#[test]
fn enrichment_epoch_tracker_advance_returns_new_epoch() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(100));
    let new = tracker
        .advance(TransitionReason::GuardrailConfigChange, "ret")
        .unwrap();
    assert_eq!(new.as_u64(), 101);
    assert_eq!(tracker.current(), new);
}

#[test]
fn enrichment_epoch_tracker_advance_trace_id_preserved() {
    let mut tracker = EpochTracker::new();
    let trace = "very-long-trace-id-with-dashes-and-numbers-123";
    tracker
        .advance(TransitionReason::PolicyKeyRotation, trace)
        .unwrap();
    assert_eq!(tracker.transitions()[0].trace_id, trace);
}

#[test]
fn enrichment_epoch_tracker_transition_count_keys_are_display_strings() {
    let mut tracker = EpochTracker::new();
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
    ];
    for (i, reason) in reasons.iter().enumerate() {
        tracker.advance(reason.clone(), &format!("t{i}")).unwrap();
    }
    for reason in &reasons {
        let key = reason.to_string();
        assert!(
            tracker.transition_counts().contains_key(&key),
            "transition_counts should use Display as key: {key}"
        );
    }
}

#[test]
fn enrichment_epoch_tracker_from_persisted_empty_history() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(999));
    assert_eq!(tracker.transition_count(), 0);
    assert!(tracker.transitions().is_empty());
    assert!(tracker.transition_counts().is_empty());
}

#[test]
fn enrichment_epoch_tracker_from_persisted_at_genesis() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::GENESIS);
    assert_eq!(tracker.current(), SecurityEpoch::GENESIS);
}

#[test]
fn enrichment_epoch_tracker_from_persisted_at_max() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(u64::MAX));
    assert_eq!(tracker.current().as_u64(), u64::MAX);
}

// ---------------------------------------------------------------------------
// EpochTracker — verify_persisted edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_persisted_at_genesis_to_genesis() {
    let mut tracker = EpochTracker::new();
    tracker.verify_persisted(SecurityEpoch::GENESIS).unwrap();
    assert_eq!(tracker.current(), SecurityEpoch::GENESIS);
}

#[test]
fn enrichment_verify_persisted_does_not_affect_history() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "t1")
        .unwrap();
    tracker
        .verify_persisted(SecurityEpoch::from_raw(10))
        .unwrap();
    assert_eq!(
        tracker.transition_count(),
        1,
        "verify_persisted should not add to history"
    );
}

#[test]
fn enrichment_verify_persisted_error_preserves_epoch() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(20));
    let _err = tracker
        .verify_persisted(SecurityEpoch::from_raw(10))
        .unwrap_err();
    assert_eq!(tracker.current().as_u64(), 20);
}

#[test]
fn enrichment_verify_persisted_max_to_max_ok() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(u64::MAX));
    tracker
        .verify_persisted(SecurityEpoch::from_raw(u64::MAX))
        .unwrap();
    assert_eq!(tracker.current().as_u64(), u64::MAX);
}

// ---------------------------------------------------------------------------
// EpochTracker — validate_artifact deep edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_artifact_genesis_open_ended_at_genesis() {
    let tracker = EpochTracker::new();
    let meta = EpochMetadata::open_ended(SecurityEpoch::GENESIS);
    assert!(tracker.validate_artifact(&meta).is_ok());
}

#[test]
fn enrichment_validate_artifact_future_by_one() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(6));
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::FutureArtifact { .. }))
    );
}

#[test]
fn enrichment_validate_artifact_expired_by_one() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(6));
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(3),
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
fn enrichment_validate_artifact_not_yet_valid_by_one() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(4));
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(4),
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(10),
    );
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::NotYetValid { .. }))
    );
}

#[test]
fn enrichment_validate_artifact_at_exact_from_boundary_passes() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(10),
    );
    assert!(tracker.validate_artifact(&meta).is_ok());
}

#[test]
fn enrichment_validate_artifact_at_exact_until_boundary_passes() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(10));
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(3),
        SecurityEpoch::from_raw(10),
    );
    assert!(tracker.validate_artifact(&meta).is_ok());
}

#[test]
fn enrichment_validate_artifact_inverted_and_not_yet_valid() {
    // valid_from(10) > valid_until(5), and current epoch(3) < valid_from(10)
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(3));
    let meta = EpochMetadata {
        epoch_id: SecurityEpoch::from_raw(3),
        valid_from_epoch: SecurityEpoch::from_raw(10),
        valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
    };
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::InvertedWindow { .. }))
    );
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::NotYetValid { .. }))
    );
}

#[test]
fn enrichment_validate_artifact_all_four_errors_simultaneously() {
    // Craft metadata that triggers all four errors at once:
    // - epoch_id > current => FutureArtifact
    // - valid_from > valid_until => InvertedWindow
    // - valid_from > current => NotYetValid
    // - valid_until < current => Expired
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(8));
    let meta = EpochMetadata {
        epoch_id: SecurityEpoch::from_raw(20),         // future: 20 > 8
        valid_from_epoch: SecurityEpoch::from_raw(15), // not yet valid: 15 > 8; also inverted: 15 > 5
        valid_until_epoch: Some(SecurityEpoch::from_raw(5)), // expired: 5 < 8
    };
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert_eq!(
        errors.len(),
        4,
        "Should collect all 4 error types, got: {errors:?}"
    );
}

#[test]
fn enrichment_validate_artifact_open_ended_past_epoch_still_valid() {
    let mut tracker = EpochTracker::new();
    let meta = EpochMetadata::open_ended(SecurityEpoch::GENESIS);
    for _ in 0..50 {
        tracker
            .advance(TransitionReason::PolicyKeyRotation, "t")
            .unwrap();
    }
    assert!(
        tracker.validate_artifact(&meta).is_ok(),
        "Open-ended artifact from epoch 0 should still be valid at epoch 50"
    );
}

#[test]
fn enrichment_validate_artifact_windowed_wide_range() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(500));
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(100),
        SecurityEpoch::from_raw(0),
        SecurityEpoch::from_raw(1000),
    );
    assert!(tracker.validate_artifact(&meta).is_ok());
}

// ---------------------------------------------------------------------------
// EpochTracker — stamp methods edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stamp_open_ended_at_genesis() {
    let tracker = EpochTracker::new();
    let meta = tracker.stamp_open_ended();
    assert_eq!(meta.epoch_id, SecurityEpoch::GENESIS);
    assert_eq!(meta.valid_from_epoch, SecurityEpoch::GENESIS);
    assert!(meta.valid_until_epoch.is_none());
}

#[test]
fn enrichment_stamp_windowed_inverted_is_allowed() {
    // stamp_windowed does not validate the window — it just sets the fields
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    let meta = tracker.stamp_windowed(SecurityEpoch::from_raw(10), SecurityEpoch::from_raw(3));
    assert_eq!(meta.epoch_id, SecurityEpoch::from_raw(5));
    assert_eq!(meta.valid_from_epoch, SecurityEpoch::from_raw(10));
    assert_eq!(meta.valid_until_epoch, Some(SecurityEpoch::from_raw(3)));
}

#[test]
fn enrichment_stamp_windowed_same_from_and_until() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    let meta = tracker.stamp_windowed(SecurityEpoch::from_raw(5), SecurityEpoch::from_raw(5));
    assert_eq!(meta.valid_from_epoch, meta.valid_until_epoch.unwrap());
}

#[test]
fn enrichment_stamp_open_ended_then_validate_self() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(10));
    let meta = tracker.stamp_open_ended();
    assert!(tracker.validate_artifact(&meta).is_ok());
}

#[test]
fn enrichment_stamp_windowed_then_validate_within() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    let meta = tracker.stamp_windowed(SecurityEpoch::from_raw(0), SecurityEpoch::from_raw(100));
    assert!(tracker.validate_artifact(&meta).is_ok());
}

// ---------------------------------------------------------------------------
// EpochTracker — transition history chain correctness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transition_chain_is_sequential() {
    let mut tracker = EpochTracker::new();
    for i in 0..10 {
        tracker
            .advance(TransitionReason::PolicyKeyRotation, &format!("t{i}"))
            .unwrap();
    }
    let transitions = tracker.transitions();
    for i in 0..transitions.len() {
        assert_eq!(
            transitions[i].new_epoch,
            transitions[i].previous_epoch.next(),
            "transition {i}: new_epoch should be previous_epoch + 1"
        );
        if i > 0 {
            assert_eq!(
                transitions[i].previous_epoch,
                transitions[i - 1].new_epoch,
                "transition {i}: previous_epoch should match prior new_epoch"
            );
        }
    }
}

#[test]
fn enrichment_transition_counts_sum_equals_transition_count() {
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
    tracker
        .advance(TransitionReason::GuardrailConfigChange, "t4")
        .unwrap();
    tracker
        .advance(TransitionReason::RevocationFrontierAdvance, "t5")
        .unwrap();
    let sum: u64 = tracker.transition_counts().values().sum();
    assert_eq!(sum as usize, tracker.transition_count());
}

// ---------------------------------------------------------------------------
// Determinism — repeated operations produce identical results
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_multiple_serializations() {
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(2),
        SecurityEpoch::from_raw(10),
    );
    let j1 = serde_json::to_string(&meta).unwrap();
    let j2 = serde_json::to_string(&meta).unwrap();
    let j3 = serde_json::to_string(&meta).unwrap();
    assert_eq!(j1, j2);
    assert_eq!(j2, j3);
}

#[test]
fn enrichment_determinism_validation_error_serialization() {
    let err = EpochValidationError::FutureArtifact {
        current_epoch: SecurityEpoch::from_raw(3),
        artifact_epoch: SecurityEpoch::from_raw(99),
    };
    let j1 = serde_json::to_string(&err).unwrap();
    let j2 = serde_json::to_string(&err).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn enrichment_determinism_transition_record_serialization() {
    let rec = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(0),
        new_epoch: SecurityEpoch::from_raw(1),
        reason: TransitionReason::PolicyKeyRotation,
        trace_id: "det-test".to_string(),
    };
    let j1 = serde_json::to_string(&rec).unwrap();
    let j2 = serde_json::to_string(&rec).unwrap();
    assert_eq!(j1, j2);
}

// ---------------------------------------------------------------------------
// Cross-cutting: combined workflow scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_lifecycle_advance_stamp_validate() {
    let mut tracker = EpochTracker::new();
    // Advance through several epochs
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "init")
        .unwrap();
    tracker
        .advance(TransitionReason::GuardrailConfigChange, "gc")
        .unwrap();
    tracker
        .advance(TransitionReason::LossMatrixUpdate, "lm")
        .unwrap();

    // Stamp at current epoch
    let meta = tracker.stamp_windowed(SecurityEpoch::from_raw(1), SecurityEpoch::from_raw(5));
    assert!(tracker.validate_artifact(&meta).is_ok());

    // Advance past the window
    for _ in 0..3 {
        tracker
            .advance(TransitionReason::OperatorManualBump, "bump")
            .unwrap();
    }
    // Now at epoch 6, but valid_until is 5
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, EpochValidationError::Expired { .. }))
    );
}

#[test]
fn enrichment_serde_roundtrip_tracker_then_advance() {
    let mut tracker = EpochTracker::new();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "before-persist")
        .unwrap();

    let json = serde_json::to_string(&tracker).unwrap();
    let mut restored: EpochTracker = serde_json::from_str(&json).unwrap();

    // The restored tracker should still be functional
    let new_epoch = restored
        .advance(TransitionReason::LossMatrixUpdate, "after-restore")
        .unwrap();
    assert_eq!(new_epoch.as_u64(), 2);
    assert_eq!(restored.transition_count(), 2);
}

#[test]
fn enrichment_advance_many_then_validate_early_artifact() {
    let mut tracker = EpochTracker::new();
    let early_meta = tracker.stamp_open_ended();

    for i in 0..200 {
        tracker
            .advance(TransitionReason::PolicyKeyRotation, &format!("t{i}"))
            .unwrap();
    }
    assert_eq!(tracker.current().as_u64(), 200);
    // Open-ended artifacts from epoch 0 are still valid
    assert!(tracker.validate_artifact(&early_meta).is_ok());
}

#[test]
fn enrichment_verify_persisted_then_stamp_then_validate() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    tracker
        .verify_persisted(SecurityEpoch::from_raw(15))
        .unwrap();
    let meta = tracker.stamp_open_ended();
    assert_eq!(meta.epoch_id.as_u64(), 15);
    assert!(tracker.validate_artifact(&meta).is_ok());
}

#[test]
fn enrichment_multiple_reason_types_interleaved() {
    let mut tracker = EpochTracker::new();
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::PolicyKeyRotation,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
        TransitionReason::PolicyKeyRotation,
    ];
    for (i, reason) in reasons.iter().enumerate() {
        tracker.advance(reason.clone(), &format!("t{i}")).unwrap();
    }
    assert_eq!(tracker.current().as_u64(), 8);
    assert_eq!(tracker.transition_counts()["policy_key_rotation"], 3);
    assert_eq!(
        tracker.transition_counts()["revocation_frontier_advance"],
        1
    );
    assert_eq!(tracker.transition_counts()["guardrail_config_change"], 1);
    assert_eq!(tracker.transition_counts()["loss_matrix_update"], 1);
    assert_eq!(tracker.transition_counts()["remote_trust_config_change"], 1);
    assert_eq!(tracker.transition_counts()["operator_manual_bump"], 1);
}

#[test]
fn enrichment_transition_counts_btreemap_deterministic_order() {
    let mut tracker = EpochTracker::new();
    // Insert in non-alphabetical order
    tracker
        .advance(TransitionReason::RemoteTrustConfigChange, "r")
        .unwrap();
    tracker
        .advance(TransitionReason::PolicyKeyRotation, "p")
        .unwrap();
    tracker
        .advance(TransitionReason::GuardrailConfigChange, "g")
        .unwrap();

    let keys: Vec<&String> = tracker.transition_counts().keys().collect();
    // BTreeMap should produce alphabetical ordering
    let mut sorted_keys = keys.clone();
    sorted_keys.sort();
    assert_eq!(keys, sorted_keys, "BTreeMap keys should be in sorted order");
}

#[test]
fn enrichment_security_epoch_btreeset_deduplication() {
    use std::collections::BTreeSet;
    let epochs: BTreeSet<SecurityEpoch> = (0..10)
        .map(SecurityEpoch::from_raw)
        .chain((0..10).map(SecurityEpoch::from_raw))
        .collect();
    assert_eq!(epochs.len(), 10, "Duplicate epochs should be deduplicated");
}

#[test]
fn enrichment_epoch_metadata_serde_roundtrip_genesis() {
    let meta = EpochMetadata::open_ended(SecurityEpoch::GENESIS);
    let json = serde_json::to_string(&meta).unwrap();
    let decoded: EpochMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, decoded);
    assert_eq!(decoded.epoch_id, SecurityEpoch::GENESIS);
}

#[test]
fn enrichment_epoch_tracker_new_has_empty_counts() {
    let tracker = EpochTracker::new();
    assert!(tracker.transition_counts().is_empty());
}

#[test]
fn enrichment_monotonicity_violation_at_advance_max_fields() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(u64::MAX));
    let err = tracker
        .advance(TransitionReason::PolicyKeyRotation, "overflow")
        .unwrap_err();
    assert_eq!(err.current.as_u64(), u64::MAX);
    assert_eq!(err.attempted.as_u64(), u64::MAX);
    // Display should mention both
    let msg = err.to_string();
    assert!(msg.contains(&u64::MAX.to_string()));
}

#[test]
fn enrichment_validate_multiple_artifacts_same_tracker() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    let valid = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(3),
        SecurityEpoch::from_raw(10),
    );
    let expired = EpochMetadata::windowed(
        SecurityEpoch::from_raw(2),
        SecurityEpoch::from_raw(1),
        SecurityEpoch::from_raw(3),
    );
    let future = EpochMetadata::open_ended(SecurityEpoch::from_raw(10));

    assert!(tracker.validate_artifact(&valid).is_ok());
    assert!(tracker.validate_artifact(&expired).is_err());
    assert!(tracker.validate_artifact(&future).is_err());
}

#[test]
fn enrichment_transition_record_trace_id_with_unicode() {
    let mut tracker = EpochTracker::new();
    let trace = "trace-\u{1F600}-emoji";
    tracker
        .advance(TransitionReason::PolicyKeyRotation, trace)
        .unwrap();
    let json = serde_json::to_string(&tracker).unwrap();
    let decoded: EpochTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.transitions()[0].trace_id, trace);
}
