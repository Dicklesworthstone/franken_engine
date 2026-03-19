//! Enrichment integration tests for the `security_epoch` module.
//!
//! Deep coverage of SecurityEpoch, EpochTracker, EpochMetadata, validity windows,
//! monotonicity enforcement, transition history, serde roundtrips, Display impls,
//! and cross-concern interactions.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeMap;

use frankenengine_engine::security_epoch::{
    EpochMetadata, EpochTracker, EpochValidationError, MonotonicityViolation, SecurityEpoch,
    TransitionReason, TransitionRecord,
};

// ---------------------------------------------------------------------------
// SecurityEpoch — extended edge cases and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_epoch_serde_genesis() {
    let e = SecurityEpoch::GENESIS;
    let json = serde_json::to_string(&e).unwrap();
    let back: SecurityEpoch = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert_eq!(back.as_u64(), 0);
}

#[test]
fn enrich_epoch_serde_max() {
    let e = SecurityEpoch::from_raw(u64::MAX);
    let json = serde_json::to_string(&e).unwrap();
    let back: SecurityEpoch = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrich_epoch_serde_multiple_values() {
    for v in [0u64, 1, 42, 1_000_000, u64::MAX - 1, u64::MAX] {
        let e = SecurityEpoch::from_raw(v);
        let json = serde_json::to_string(&e).unwrap();
        let back: SecurityEpoch = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn enrich_epoch_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let e1 = SecurityEpoch::from_raw(42);
    let e2 = SecurityEpoch::from_raw(42);
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    e1.hash(&mut h1);
    e2.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn enrich_epoch_next_chain_10() {
    let mut e = SecurityEpoch::GENESIS;
    for i in 1..=10u64 {
        e = e.next();
        assert_eq!(e.as_u64(), i);
    }
}

#[test]
fn enrich_epoch_near_max_next() {
    let e = SecurityEpoch::from_raw(u64::MAX - 1);
    assert_eq!(e.next().as_u64(), u64::MAX);
    assert_eq!(e.next().next().as_u64(), u64::MAX); // saturating
}

#[test]
fn enrich_epoch_display_large_number() {
    assert_eq!(
        SecurityEpoch::from_raw(999_999_999).to_string(),
        "epoch:999999999"
    );
}

#[test]
fn enrich_epoch_btree_key_ordering() {
    let mut map: BTreeMap<SecurityEpoch, &str> = BTreeMap::new();
    map.insert(SecurityEpoch::from_raw(5), "five");
    map.insert(SecurityEpoch::from_raw(1), "one");
    map.insert(SecurityEpoch::from_raw(10), "ten");
    let keys: Vec<u64> = map.keys().map(|k| k.as_u64()).collect();
    assert_eq!(keys, vec![1, 5, 10]);
}

// ---------------------------------------------------------------------------
// TransitionReason — serde and Display
// ---------------------------------------------------------------------------

#[test]
fn enrich_transition_reason_serde_all_six() {
    let variants = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    for reason in &variants {
        let json = serde_json::to_string(reason).unwrap();
        let back: TransitionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, &back);
    }
}

#[test]
fn enrich_transition_reason_display_unique() {
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    let displays: std::collections::BTreeSet<String> =
        reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

// ---------------------------------------------------------------------------
// EpochMetadata — construction edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_metadata_open_ended_serde() {
    let meta = EpochMetadata::open_ended(SecurityEpoch::from_raw(7));
    let json = serde_json::to_string(&meta).unwrap();
    let back: EpochMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, back);
    assert!(back.valid_until_epoch.is_none());
}

#[test]
fn enrich_metadata_windowed_serde() {
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(10),
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(20),
    );
    let json = serde_json::to_string(&meta).unwrap();
    let back: EpochMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, back);
}

#[test]
fn enrich_metadata_windowed_same_from_until() {
    let epoch = SecurityEpoch::from_raw(5);
    let meta = EpochMetadata::windowed(epoch, epoch, epoch);
    assert_eq!(meta.valid_from_epoch, meta.valid_until_epoch.unwrap());
}

// ---------------------------------------------------------------------------
// EpochValidationError — Display messages and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_validation_error_not_yet_valid_msg() {
    let err = EpochValidationError::NotYetValid {
        current_epoch: SecurityEpoch::from_raw(2),
        valid_from: SecurityEpoch::from_raw(5),
    };
    assert!(err.to_string().contains("not yet valid"));
}

#[test]
fn enrich_validation_error_expired_msg() {
    let err = EpochValidationError::Expired {
        current_epoch: SecurityEpoch::from_raw(10),
        valid_until: SecurityEpoch::from_raw(5),
    };
    assert!(err.to_string().contains("expired"));
}

#[test]
fn enrich_validation_error_future_msg() {
    let err = EpochValidationError::FutureArtifact {
        current_epoch: SecurityEpoch::from_raw(3),
        artifact_epoch: SecurityEpoch::from_raw(100),
    };
    assert!(err.to_string().contains("future"));
}

#[test]
fn enrich_validation_error_inverted_msg() {
    let err = EpochValidationError::InvertedWindow {
        valid_from: SecurityEpoch::from_raw(20),
        valid_until: SecurityEpoch::from_raw(10),
    };
    assert!(err.to_string().contains("inverted"));
}

#[test]
fn enrich_validation_error_serde_all() {
    let errors = [
        EpochValidationError::NotYetValid {
            current_epoch: SecurityEpoch::from_raw(1),
            valid_from: SecurityEpoch::from_raw(5),
        },
        EpochValidationError::Expired {
            current_epoch: SecurityEpoch::from_raw(10),
            valid_until: SecurityEpoch::from_raw(5),
        },
        EpochValidationError::FutureArtifact {
            current_epoch: SecurityEpoch::from_raw(1),
            artifact_epoch: SecurityEpoch::from_raw(99),
        },
        EpochValidationError::InvertedWindow {
            valid_from: SecurityEpoch::from_raw(20),
            valid_until: SecurityEpoch::from_raw(5),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: EpochValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &back);
    }
}

#[test]
fn enrich_validation_error_is_std_error() {
    let err = EpochValidationError::Expired {
        current_epoch: SecurityEpoch::from_raw(10),
        valid_until: SecurityEpoch::from_raw(5),
    };
    let e: &dyn std::error::Error = &err;
    assert!(!e.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// MonotonicityViolation — Display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_monotonicity_violation_serde() {
    let mv = MonotonicityViolation {
        current: SecurityEpoch::from_raw(100),
        attempted: SecurityEpoch::from_raw(50),
    };
    let json = serde_json::to_string(&mv).unwrap();
    let back: MonotonicityViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(mv, back);
}

#[test]
fn enrich_monotonicity_violation_display_contains_values() {
    let mv = MonotonicityViolation {
        current: SecurityEpoch::from_raw(100),
        attempted: SecurityEpoch::from_raw(50),
    };
    let msg = mv.to_string();
    assert!(msg.contains("100") || msg.contains("epoch:100"));
    assert!(msg.contains("50") || msg.contains("epoch:50"));
}

#[test]
fn enrich_monotonicity_violation_is_std_error() {
    let mv = MonotonicityViolation {
        current: SecurityEpoch::from_raw(10),
        attempted: SecurityEpoch::from_raw(5),
    };
    let e: &dyn std::error::Error = &mv;
    assert!(!e.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// TransitionRecord — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_transition_record_serde() {
    let record = TransitionRecord {
        previous_epoch: SecurityEpoch::from_raw(5),
        new_epoch: SecurityEpoch::from_raw(6),
        reason: TransitionReason::PolicyKeyRotation,
        trace_id: "trace-abc-123".to_string(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: TransitionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ---------------------------------------------------------------------------
// EpochTracker — deep state machine tests
// ---------------------------------------------------------------------------

#[test]
fn enrich_tracker_advance_all_six_reasons() {
    let mut tracker = EpochTracker::new();
    let reasons = [
        TransitionReason::PolicyKeyRotation,
        TransitionReason::RevocationFrontierAdvance,
        TransitionReason::GuardrailConfigChange,
        TransitionReason::LossMatrixUpdate,
        TransitionReason::RemoteTrustConfigChange,
        TransitionReason::OperatorManualBump,
    ];
    for (i, reason) in reasons.iter().enumerate() {
        let new = tracker.advance(reason.clone(), &format!("t{i}")).unwrap();
        assert_eq!(new.as_u64(), (i as u64) + 1);
    }
    assert_eq!(tracker.current().as_u64(), 6);
    assert_eq!(tracker.transition_count(), 6);
    assert_eq!(tracker.transition_counts().len(), 6);
}

#[test]
fn enrich_tracker_repeated_reason_accumulates() {
    let mut tracker = EpochTracker::new();
    for _ in 0..10 {
        tracker
            .advance(TransitionReason::LossMatrixUpdate, "t")
            .unwrap();
    }
    assert_eq!(tracker.transition_counts()["loss_matrix_update"], 10);
}

#[test]
fn enrich_tracker_transition_chain_integrity() {
    let mut tracker = EpochTracker::new();
    for i in 0..5 {
        tracker
            .advance(TransitionReason::PolicyKeyRotation, &format!("t{i}"))
            .unwrap();
    }
    let transitions = tracker.transitions();
    for i in 1..transitions.len() {
        assert_eq!(transitions[i].previous_epoch, transitions[i - 1].new_epoch);
    }
}

#[test]
fn enrich_tracker_at_u64_max_cannot_advance() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(u64::MAX));
    let err = tracker
        .advance(TransitionReason::PolicyKeyRotation, "t")
        .unwrap_err();
    assert_eq!(err.current.as_u64(), u64::MAX);
}

#[test]
fn enrich_tracker_verify_persisted_accept_higher() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(10));
    assert!(tracker.verify_persisted(SecurityEpoch::from_raw(20)).is_ok());
    assert_eq!(tracker.current().as_u64(), 20);
}

#[test]
fn enrich_tracker_verify_persisted_reject_lower() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(20));
    let err = tracker.verify_persisted(SecurityEpoch::from_raw(10)).unwrap_err();
    assert_eq!(err.current.as_u64(), 20);
    assert_eq!(tracker.current().as_u64(), 20); // unchanged
}

#[test]
fn enrich_tracker_default_eq_new() {
    let d = EpochTracker::default();
    let n = EpochTracker::new();
    assert_eq!(d.current(), n.current());
    assert_eq!(d.transition_count(), n.transition_count());
}

// ---------------------------------------------------------------------------
// validate_artifact — deep edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_validate_open_ended_stays_valid_after_many_advances() {
    let mut tracker = EpochTracker::new();
    let meta = tracker.stamp_open_ended();
    for _ in 0..50 {
        tracker.advance(TransitionReason::PolicyKeyRotation, "t").unwrap();
    }
    assert!(tracker.validate_artifact(&meta).is_ok());
}

#[test]
fn enrich_validate_windowed_at_exact_boundaries() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(3),
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(10),
    );
    assert!(tracker.validate_artifact(&meta).is_ok());
}

#[test]
fn enrich_validate_just_past_expiry() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(11));
    let meta = EpochMetadata::windowed(
        SecurityEpoch::from_raw(5),
        SecurityEpoch::from_raw(3),
        SecurityEpoch::from_raw(10),
    );
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(errors.iter().any(|e| matches!(e, EpochValidationError::Expired { .. })));
}

#[test]
fn enrich_validate_multi_error_collection() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(15));
    let meta = EpochMetadata {
        epoch_id: SecurityEpoch::from_raw(20),
        valid_from_epoch: SecurityEpoch::from_raw(12),
        valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
    };
    let errors = tracker.validate_artifact(&meta).unwrap_err();
    assert!(errors.len() >= 3);
}

// ---------------------------------------------------------------------------
// Stamping
// ---------------------------------------------------------------------------

#[test]
fn enrich_stamp_open_ended_matches_current() {
    let mut tracker = EpochTracker::new();
    tracker.advance(TransitionReason::PolicyKeyRotation, "t").unwrap();
    let meta = tracker.stamp_open_ended();
    assert_eq!(meta.epoch_id, tracker.current());
    assert_eq!(meta.valid_from_epoch, tracker.current());
    assert!(meta.valid_until_epoch.is_none());
}

#[test]
fn enrich_stamp_windowed_with_custom_range() {
    let tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(7));
    let meta = tracker.stamp_windowed(SecurityEpoch::from_raw(3), SecurityEpoch::from_raw(10));
    assert_eq!(meta.epoch_id.as_u64(), 7);
    assert_eq!(meta.valid_from_epoch.as_u64(), 3);
    assert_eq!(meta.valid_until_epoch, Some(SecurityEpoch::from_raw(10)));
}

// ---------------------------------------------------------------------------
// EpochTracker — serde full round-trip
// ---------------------------------------------------------------------------

#[test]
fn enrich_tracker_serde_with_transitions() {
    let mut tracker = EpochTracker::new();
    tracker.advance(TransitionReason::PolicyKeyRotation, "t1").unwrap();
    tracker.advance(TransitionReason::GuardrailConfigChange, "t2").unwrap();
    tracker.advance(TransitionReason::LossMatrixUpdate, "t3").unwrap();
    let json = serde_json::to_string(&tracker).unwrap();
    let restored: EpochTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.current().as_u64(), 3);
    assert_eq!(restored.transition_count(), 3);
    assert_eq!(restored.transitions()[0].trace_id, "t1");
}

// ---------------------------------------------------------------------------
// Complex scenario: verify_persisted -> advance -> validate
// ---------------------------------------------------------------------------

#[test]
fn enrich_scenario_persisted_advance_validate() {
    let mut tracker = EpochTracker::from_persisted(SecurityEpoch::from_raw(5));
    tracker.verify_persisted(SecurityEpoch::from_raw(10)).unwrap();
    tracker.advance(TransitionReason::PolicyKeyRotation, "t").unwrap();
    assert_eq!(tracker.current().as_u64(), 11);
    let meta = tracker.stamp_open_ended();
    assert!(tracker.validate_artifact(&meta).is_ok());
}

#[test]
fn enrich_deterministic_serialization() {
    let mut t1 = EpochTracker::new();
    t1.advance(TransitionReason::PolicyKeyRotation, "a").unwrap();
    let mut t2 = EpochTracker::new();
    t2.advance(TransitionReason::PolicyKeyRotation, "a").unwrap();
    assert_eq!(
        serde_json::to_string(&t1).unwrap(),
        serde_json::to_string(&t2).unwrap()
    );
}
