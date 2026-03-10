//! Edge-case tests for `replacement_lineage_log` module.
//!
//! Covers: ReplacementKind, LineageLogEntry, Merkle tree (inclusion proofs,
//! consistency proofs), LogCheckpoint, LineageQuery, LineageStep,
//! LineageVerification, AuditResult, LineageLogEvent, LineageLogError,
//! LineageLogConfig, ReplacementLineageLog operations, ProofDirection,
//! MerkleProofStep, EvidenceCategory, LineageIndexError,
//! EvidencePointerInput, EvidencePointer, DemotionReceiptInput,
//! ReplacementLineageEvidenceIndex, determinism, and edge-case scenarios.

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

use std::collections::{BTreeSet, HashSet};

use frankenengine_engine::engine_object_id::{self, ObjectDomain};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::replacement_lineage_log::{
    AuditResult, ConsistencyProof, DemotionReceiptInput, EvidenceCategory, EvidencePointer,
    EvidencePointerInput, InclusionProof, LineageChainEntry, LineageLogConfig, LineageLogError,
    LineageLogEvent, LineageQuery, LineageStep, LineageVerification, LogCheckpoint,
    MerkleProofStep, ProofDirection, ReplacementKind, ReplacementLineageEvidenceIndex,
    ReplacementLineageLog, ReplayJoinQuery, SlotLineageQuery, verify_consistency_proof,
    verify_inclusion_proof,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    ReplacementReceipt, SchemaVersion, SignatureBundle, ValidationArtifactKind,
    ValidationArtifactRef,
};
use frankenengine_engine::slot_registry::SlotId;
use frankenengine_engine::storage_adapter::{
    EventContext, InMemoryStorageAdapter, StorageError, StoreKind,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_slot_id(name: &str) -> SlotId {
    SlotId::new(name).expect("valid slot id")
}

fn test_receipt(slot_name: &str, old: &str, new: &str, ts: u64) -> ReplacementReceipt {
    let slot_id = test_slot_id(slot_name);
    let receipt_id = engine_object_id::derive_id(
        ObjectDomain::CheckpointArtifact,
        "test-zone",
        &engine_object_id::SchemaId::from_definition(b"test-receipt-schema"),
        &format!("{slot_name}|{old}|{new}|{ts}").into_bytes(),
    )
    .expect("valid id");

    ReplacementReceipt {
        receipt_id,
        schema_version: SchemaVersion::V1,
        slot_id,
        old_cell_digest: old.to_string(),
        new_cell_digest: new.to_string(),
        validation_artifacts: vec![ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "deadbeef".to_string(),
            passed: true,
            summary: "test artifact".to_string(),
        }],
        rollback_token: format!("rollback-{old}"),
        promotion_rationale: "test promotion".to_string(),
        timestamp_ns: ts,
        epoch: SecurityEpoch::from_raw(1),
        zone: "test-zone".to_string(),
        signature_bundle: SignatureBundle::new(1),
    }
}

fn test_context() -> EventContext {
    EventContext {
        trace_id: "trace-edge".to_string(),
        decision_id: "decision-edge".to_string(),
        policy_id: "policy-edge".to_string(),
    }
}

// ---------------------------------------------------------------------------
// ReplacementKind — Copy, Hash, Serde, Display, Ordering
// ---------------------------------------------------------------------------

#[test]
fn replacement_kind_is_copy() {
    let a = ReplacementKind::DelegateToNative;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn replacement_kind_hash_four_distinct() {
    let mut set = HashSet::new();
    set.insert(ReplacementKind::DelegateToNative);
    set.insert(ReplacementKind::Demotion);
    set.insert(ReplacementKind::Rollback);
    set.insert(ReplacementKind::RePromotion);
    assert_eq!(set.len(), 4);
}

#[test]
fn replacement_kind_as_str_all_four() {
    assert_eq!(
        ReplacementKind::DelegateToNative.as_str(),
        "delegate_to_native"
    );
    assert_eq!(ReplacementKind::Demotion.as_str(), "demotion");
    assert_eq!(ReplacementKind::Rollback.as_str(), "rollback");
    assert_eq!(ReplacementKind::RePromotion.as_str(), "re_promotion");
}

#[test]
fn replacement_kind_display_matches_as_str() {
    for kind in [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ] {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn replacement_kind_serde_stable_strings() {
    assert_eq!(
        serde_json::to_string(&ReplacementKind::DelegateToNative).unwrap(),
        "\"DelegateToNative\""
    );
    assert_eq!(
        serde_json::to_string(&ReplacementKind::Demotion).unwrap(),
        "\"Demotion\""
    );
    assert_eq!(
        serde_json::to_string(&ReplacementKind::Rollback).unwrap(),
        "\"Rollback\""
    );
    assert_eq!(
        serde_json::to_string(&ReplacementKind::RePromotion).unwrap(),
        "\"RePromotion\""
    );
}

#[test]
fn replacement_kind_ordering_exhaustive() {
    let mut kinds = [
        ReplacementKind::RePromotion,
        ReplacementKind::DelegateToNative,
        ReplacementKind::Rollback,
        ReplacementKind::Demotion,
    ];
    kinds.sort();
    assert_eq!(kinds[0], ReplacementKind::DelegateToNative);
    assert_eq!(kinds[1], ReplacementKind::Demotion);
    assert_eq!(kinds[2], ReplacementKind::Rollback);
    assert_eq!(kinds[3], ReplacementKind::RePromotion);
}

// ---------------------------------------------------------------------------
// ProofDirection — Serde, Copy
// ---------------------------------------------------------------------------

#[test]
fn proof_direction_is_copy() {
    let a = ProofDirection::Left;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn proof_direction_serde() {
    for dir in [ProofDirection::Left, ProofDirection::Right] {
        let json = serde_json::to_string(&dir).unwrap();
        let back: ProofDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(dir, back);
    }
}

// ---------------------------------------------------------------------------
// MerkleProofStep — Serde, Clone
// ---------------------------------------------------------------------------

#[test]
fn merkle_proof_step_serde() {
    let step = MerkleProofStep {
        sibling_hash: ContentHash::compute(b"sibling"),
        direction: ProofDirection::Right,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: MerkleProofStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

#[test]
fn merkle_proof_step_clone() {
    let step = MerkleProofStep {
        sibling_hash: ContentHash::compute(b"x"),
        direction: ProofDirection::Left,
    };
    assert_eq!(step, step.clone());
}

// ---------------------------------------------------------------------------
// InclusionProof — Serde, verification edge cases
// ---------------------------------------------------------------------------

#[test]
fn inclusion_proof_serde() {
    let proof = InclusionProof {
        entry_index: 0,
        entry_hash: ContentHash::compute(b"entry"),
        path: vec![MerkleProofStep {
            sibling_hash: ContentHash::compute(b"sib"),
            direction: ProofDirection::Right,
        }],
        root: ContentHash::compute(b"root"),
    };
    let json = serde_json::to_string(&proof).unwrap();
    let back: InclusionProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
}

#[test]
fn inclusion_proof_empty_path_single_entry() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    let proof = log.inclusion_proof(0).unwrap();
    assert!(proof.path.is_empty());
    assert!(verify_inclusion_proof(&proof));
}

#[test]
fn inclusion_proof_power_of_two_entries() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..16 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    for i in 0..16 {
        let proof = log.inclusion_proof(i).expect("proof exists");
        assert!(
            verify_inclusion_proof(&proof),
            "power-of-2 inclusion proof failed at index {i}"
        );
        // For 16 entries (perfect binary tree), proof path should have 4 steps.
        assert_eq!(proof.path.len(), 4, "entry {i} should have 4-step path");
    }
}

#[test]
fn inclusion_proof_two_entries() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..2 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    for i in 0..2 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof));
        assert_eq!(proof.path.len(), 1);
    }
}

#[test]
fn inclusion_proof_three_entries() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..3 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    for i in 0..3 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(
            verify_inclusion_proof(&proof),
            "3-entry inclusion proof failed at index {i}"
        );
    }
}

#[test]
fn inclusion_proof_tampered_entry_hash_fails_verification() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..4 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    let mut proof = log.inclusion_proof(1).unwrap();
    proof.entry_hash = ContentHash::compute(b"tampered");
    assert!(!verify_inclusion_proof(&proof));
}

#[test]
fn inclusion_proof_tampered_sibling_fails_verification() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..4 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    let mut proof = log.inclusion_proof(0).unwrap();
    if let Some(step) = proof.path.first_mut() {
        step.sibling_hash = ContentHash::compute(b"wrong-sibling");
    }
    assert!(!verify_inclusion_proof(&proof));
}

// ---------------------------------------------------------------------------
// ConsistencyProof — verification edge cases
// ---------------------------------------------------------------------------

#[test]
fn consistency_proof_serde() {
    let proof = ConsistencyProof {
        older_checkpoint_seq: 0,
        newer_checkpoint_seq: 1,
        older_log_length: 3,
        newer_log_length: 6,
        older_root: ContentHash::compute(b"older"),
        newer_root: ContentHash::compute(b"newer"),
        older_entry_hashes: vec![ContentHash::compute(b"a")],
        newer_entry_hashes: vec![ContentHash::compute(b"a"), ContentHash::compute(b"b")],
    };
    let json = serde_json::to_string(&proof).unwrap();
    let back: ConsistencyProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
}

#[test]
fn consistency_proof_older_longer_than_newer_fails() {
    let proof = ConsistencyProof {
        older_checkpoint_seq: 0,
        newer_checkpoint_seq: 1,
        older_log_length: 5,
        newer_log_length: 3,
        older_root: ContentHash::compute(b"x"),
        newer_root: ContentHash::compute(b"y"),
        older_entry_hashes: vec![],
        newer_entry_hashes: vec![],
    };
    assert!(!verify_consistency_proof(&proof));
}

#[test]
fn consistency_proof_length_mismatch_fails() {
    let proof = ConsistencyProof {
        older_checkpoint_seq: 0,
        newer_checkpoint_seq: 1,
        older_log_length: 2,
        newer_log_length: 3,
        older_root: ContentHash::compute(b"x"),
        newer_root: ContentHash::compute(b"y"),
        older_entry_hashes: vec![ContentHash::compute(b"a")], // length 1 != 2
        newer_entry_hashes: vec![
            ContentHash::compute(b"a"),
            ContentHash::compute(b"b"),
            ContentHash::compute(b"c"),
        ],
    };
    assert!(!verify_consistency_proof(&proof));
}

#[test]
fn consistency_proof_prefix_mismatch_fails() {
    let h1 = ContentHash::compute(b"entry1");
    let h2 = ContentHash::compute(b"entry2");
    let h3 = ContentHash::compute(b"entry3");
    let h_tampered = ContentHash::compute(b"tampered");
    let proof = ConsistencyProof {
        older_checkpoint_seq: 0,
        newer_checkpoint_seq: 1,
        older_log_length: 2,
        newer_log_length: 3,
        older_root: ContentHash::compute(b"x"),
        newer_root: ContentHash::compute(b"y"),
        older_entry_hashes: vec![h1, h2],
        newer_entry_hashes: vec![h_tampered, h3, ContentHash::compute(b"z")],
    };
    assert!(!verify_consistency_proof(&proof));
}

// ---------------------------------------------------------------------------
// LineageLogConfig — Default, Serde
// ---------------------------------------------------------------------------

#[test]
fn config_default_checkpoint_interval_100() {
    let config = LineageLogConfig::default();
    assert_eq!(config.checkpoint_interval, 100);
}

#[test]
fn config_default_max_entries_unlimited() {
    let config = LineageLogConfig::default();
    assert_eq!(config.max_entries_in_memory, 0);
}

#[test]
fn config_custom_serde() {
    let config = LineageLogConfig {
        checkpoint_interval: 10,
        max_entries_in_memory: 500,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: LineageLogConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// LineageLogError — Serde, Display
// ---------------------------------------------------------------------------

#[test]
fn error_sequence_mismatch_display() {
    let err = LineageLogError::SequenceMismatch {
        expected: 5,
        got: 3,
    };
    let s = format!("{err}");
    assert!(s.contains("5"));
    assert!(s.contains("3"));
    assert!(s.contains("sequence mismatch"));
}

#[test]
fn error_chain_break_display() {
    let err = LineageLogError::ChainBreak { sequence: 7 };
    let s = format!("{err}");
    assert!(s.contains("chain break"));
    assert!(s.contains("7"));
}

#[test]
fn error_duplicate_receipt_display() {
    let err = LineageLogError::DuplicateReceipt {
        receipt_id: "abc".to_string(),
    };
    let s = format!("{err}");
    assert!(s.contains("duplicate"));
    assert!(s.contains("abc"));
}

#[test]
fn error_checkpoint_beyond_log_display() {
    let err = LineageLogError::CheckpointBeyondLog {
        checkpoint_length: 10,
        log_length: 5,
    };
    let s = format!("{err}");
    assert!(s.contains("10"));
    assert!(s.contains("5"));
}

#[test]
fn error_checkpoint_not_found_display() {
    let err = LineageLogError::CheckpointNotFound { checkpoint_seq: 99 };
    let s = format!("{err}");
    assert!(s.contains("not found"));
    assert!(s.contains("99"));
}

#[test]
fn error_invalid_checkpoint_order_display() {
    let err = LineageLogError::InvalidCheckpointOrder { older: 2, newer: 1 };
    let s = format!("{err}");
    assert!(s.contains("invalid checkpoint order"));
}

#[test]
fn error_empty_log_display() {
    let err = LineageLogError::EmptyLog;
    assert!(format!("{err}").contains("empty"));
}

#[test]
fn error_serde_all_variants() {
    let errors = vec![
        LineageLogError::SequenceMismatch {
            expected: 1,
            got: 2,
        },
        LineageLogError::ChainBreak { sequence: 3 },
        LineageLogError::DuplicateReceipt {
            receipt_id: "r".into(),
        },
        LineageLogError::CheckpointBeyondLog {
            checkpoint_length: 5,
            log_length: 3,
        },
        LineageLogError::CheckpointNotFound { checkpoint_seq: 7 },
        LineageLogError::InvalidCheckpointOrder { older: 2, newer: 1 },
        LineageLogError::EmptyLog,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: LineageLogError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// LineageLogEvent — Serde, Clone
// ---------------------------------------------------------------------------

#[test]
fn lineage_log_event_serde() {
    let event = LineageLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "replacement_lineage_log".to_string(),
        event: "entry_appended".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LineageLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn lineage_log_event_with_error_code_serde() {
    let event = LineageLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "replacement_lineage_log".to_string(),
        event: "error".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("CHAIN_BREAK".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LineageLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn lineage_log_event_clone() {
    let event = LineageLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: Some("err".to_string()),
    };
    assert_eq!(event, event.clone());
}

// ---------------------------------------------------------------------------
// LineageStep — Serde
// ---------------------------------------------------------------------------

#[test]
fn lineage_step_serde() {
    let step = LineageStep {
        sequence: 0,
        kind: ReplacementKind::DelegateToNative,
        old_cell_digest: "old".to_string(),
        new_cell_digest: "new".to_string(),
        receipt_id: "r".to_string(),
        timestamp_ns: 1000,
        epoch: SecurityEpoch::from_raw(1),
        validation_artifact_count: 3,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: LineageStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

// ---------------------------------------------------------------------------
// LineageVerification — Serde
// ---------------------------------------------------------------------------

#[test]
fn lineage_verification_serde() {
    let v = LineageVerification {
        slot_id: test_slot_id("slot-v"),
        total_entries: 5,
        chain_valid: true,
        all_receipts_present: true,
        issues: Vec::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: LineageVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn lineage_verification_with_issues_serde() {
    let v = LineageVerification {
        slot_id: test_slot_id("slot-vi"),
        total_entries: 3,
        chain_valid: false,
        all_receipts_present: true,
        issues: vec!["hash mismatch".to_string()],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: LineageVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// AuditResult — Serde
// ---------------------------------------------------------------------------

#[test]
fn audit_result_serde() {
    let result = AuditResult {
        total_entries: 10,
        total_slots: 3,
        chain_valid: true,
        merkle_valid: true,
        checkpoint_count: 2,
        latest_checkpoint_seq: Some(1),
        issues: Vec::new(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn audit_result_no_checkpoints_serde() {
    let result = AuditResult {
        total_entries: 5,
        total_slots: 1,
        chain_valid: true,
        merkle_valid: true,
        checkpoint_count: 0,
        latest_checkpoint_seq: None,
        issues: Vec::new(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// LogCheckpoint — Serde
// ---------------------------------------------------------------------------

#[test]
fn log_checkpoint_serde() {
    let cp = LogCheckpoint {
        checkpoint_seq: 0,
        log_length: 5,
        merkle_root: ContentHash::compute(b"root"),
        timestamp_ns: 1000,
        epoch: SecurityEpoch::from_raw(1),
        checkpoint_hash: ContentHash::compute(b"cp"),
    };
    let json = serde_json::to_string(&cp).unwrap();
    let back: LogCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(cp, back);
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — append edge cases
// ---------------------------------------------------------------------------

#[test]
fn append_zero_timestamp() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 0);
    let seq = log.append(r, ReplacementKind::DelegateToNative, 0).unwrap();
    assert_eq!(seq, 0);
    assert_eq!(log.entries()[0].receipt.timestamp_ns, 0);
}

#[test]
fn append_all_replacement_kinds() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let kinds = [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let r = test_receipt(
            "slot-a",
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i as u64 + 1) * 100,
        );
        log.append(r, *kind, (i as u64 + 1) * 100).unwrap();
    }
    assert_eq!(log.len(), 4);
    for (i, kind) in kinds.iter().enumerate() {
        assert_eq!(log.entries()[i].kind, *kind);
    }
}

#[test]
fn append_duplicate_receipt_returns_error() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r.clone(), ReplacementKind::DelegateToNative, 100)
        .unwrap();
    let err = log.append(r, ReplacementKind::Demotion, 200).unwrap_err();
    assert!(matches!(err, LineageLogError::DuplicateReceipt { .. }));
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — auto-checkpoint
// ---------------------------------------------------------------------------

#[test]
fn auto_checkpoint_interval_3() {
    let config = LineageLogConfig {
        checkpoint_interval: 3,
        max_entries_in_memory: 0,
    };
    let mut log = ReplacementLineageLog::new(config);
    for i in 0..9 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    // Checkpoints at entries 2 (3 entries), 5 (6 entries), 8 (9 entries).
    assert_eq!(log.checkpoints().len(), 3);
}

#[test]
fn auto_checkpoint_disabled_when_interval_zero() {
    let config = LineageLogConfig {
        checkpoint_interval: 0,
        max_entries_in_memory: 0,
    };
    let mut log = ReplacementLineageLog::new(config);
    for i in 0..10 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    assert!(log.checkpoints().is_empty());
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — checkpoint edge cases
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_on_empty_log_returns_empty_error() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let err = log
        .create_checkpoint(100, SecurityEpoch::from_raw(1))
        .unwrap_err();
    assert!(matches!(err, LineageLogError::EmptyLog));
}

#[test]
fn multiple_checkpoints_have_increasing_sequences() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..5 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
        log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
            .unwrap();
    }
    assert_eq!(log.checkpoints().len(), 5);
    for (i, cp) in log.checkpoints().iter().enumerate() {
        assert_eq!(cp.checkpoint_seq, i as u64);
        assert_eq!(cp.log_length, (i as u64) + 1);
    }
}

#[test]
fn checkpoint_preserves_epoch() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    let epoch = SecurityEpoch::from_raw(42);
    log.create_checkpoint(100, epoch).unwrap();
    assert_eq!(log.checkpoints()[0].epoch, epoch);
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — hash chain integrity
// ---------------------------------------------------------------------------

#[test]
fn first_entry_predecessor_is_genesis() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    let genesis = ContentHash::compute(b"genesis");
    assert_eq!(log.entries()[0].predecessor_hash, genesis);
}

#[test]
fn chain_links_are_contiguous() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..10 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    for i in 1..10 {
        assert_eq!(
            log.entries()[i].predecessor_hash,
            log.entries()[i - 1].entry_hash,
            "chain break at index {i}"
        );
    }
}

#[test]
fn different_kinds_produce_different_hashes() {
    let mut log1 = ReplacementLineageLog::new(LineageLogConfig::default());
    let mut log2 = ReplacementLineageLog::new(LineageLogConfig::default());
    let r1 = test_receipt("slot-a", "old", "new", 100);
    let r2 = test_receipt("slot-a", "old", "new", 100);
    log1.append(r1, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    log2.append(r2, ReplacementKind::Rollback, 100).unwrap();
    assert_ne!(log1.entries()[0].entry_hash, log2.entries()[0].entry_hash);
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — Merkle root
// ---------------------------------------------------------------------------

#[test]
fn merkle_root_empty_log_is_deterministic() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    let root = log.merkle_root();
    assert_eq!(root, ContentHash::compute(b"empty_lineage_tree"));
}

#[test]
fn merkle_root_changes_on_append() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let root_empty = log.merkle_root();
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    assert_ne!(log.merkle_root(), root_empty);
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — query edge cases
// ---------------------------------------------------------------------------

#[test]
fn query_all_on_empty_log() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    let results = log.query(&LineageQuery::all());
    assert!(results.is_empty());
}

#[test]
fn query_combined_slot_and_kind() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r1 = test_receipt("slot-a", "old1", "new1", 100);
    let r2 = test_receipt("slot-a", "new1", "old1", 200);
    let r3 = test_receipt("slot-b", "old2", "new2", 300);
    log.append(r1, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    log.append(r2, ReplacementKind::Demotion, 200).unwrap();
    log.append(r3, ReplacementKind::DelegateToNative, 300)
        .unwrap();

    let mut kinds = BTreeSet::new();
    kinds.insert(ReplacementKind::DelegateToNative);
    let query = LineageQuery {
        slot_id: Some(test_slot_id("slot-a")),
        kinds: Some(kinds),
        min_timestamp_ns: None,
        max_timestamp_ns: None,
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(results[0].receipt.slot_id, test_slot_id("slot-a"));
}

#[test]
fn query_time_range_boundary_inclusive() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 1..=5 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    // Exact boundary match: min=200, max=400 should include 200, 300, 400.
    let query = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: Some(200),
        max_timestamp_ns: Some(400),
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 3);
}

#[test]
fn query_nonexistent_slot() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    let results = log.query(&LineageQuery::for_slot(test_slot_id("nonexistent")));
    assert!(results.is_empty());
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — slot_lineage edge cases
// ---------------------------------------------------------------------------

#[test]
fn slot_lineage_empty_for_unknown_slot() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    let lineage = log.slot_lineage(&test_slot_id("unknown"));
    assert!(lineage.is_empty());
}

#[test]
fn slot_lineage_step_has_validation_artifact_count() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    let lineage = log.slot_lineage(&test_slot_id("slot-a"));
    assert_eq!(lineage.len(), 1);
    assert_eq!(lineage[0].validation_artifact_count, 1); // test_receipt adds 1 artifact
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — verify_slot_lineage
// ---------------------------------------------------------------------------

#[test]
fn verify_slot_lineage_empty_slot_reports_issue() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    let v = log.verify_slot_lineage(&test_slot_id("empty"));
    assert_eq!(v.total_entries, 0);
    assert!(v.chain_valid);
    assert!(!v.issues.is_empty());
    assert!(v.issues[0].contains("no entries"));
}

#[test]
fn verify_slot_lineage_valid_chain() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..5 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    let v = log.verify_slot_lineage(&test_slot_id("slot-a"));
    assert!(v.chain_valid);
    assert!(v.issues.is_empty());
    assert_eq!(v.total_entries, 5);
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — audit edge cases
// ---------------------------------------------------------------------------

#[test]
fn audit_empty_log_is_valid() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    let audit = log.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.total_entries, 0);
    assert_eq!(audit.total_slots, 0);
    assert!(audit.issues.is_empty());
}

#[test]
fn audit_with_checkpoints_verifies_consistency() {
    let config = LineageLogConfig {
        checkpoint_interval: 3,
        max_entries_in_memory: 0,
    };
    let mut log = ReplacementLineageLog::new(config);
    for i in 0..9 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    let audit = log.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.total_entries, 9);
    assert_eq!(audit.checkpoint_count, 3);
    assert!(audit.issues.is_empty());
}

#[test]
fn audit_multi_slot_counts_unique() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let slots = ["alpha", "beta", "gamma", "alpha"]; // 3 unique
    for (i, slot) in slots.iter().enumerate() {
        let r = test_receipt(
            slot,
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i as u64) * 100,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i as u64) * 100)
            .unwrap();
    }
    let audit = log.audit();
    assert_eq!(audit.total_slots, 3);
    assert_eq!(audit.total_entries, 4);
}

#[test]
fn audit_latest_checkpoint_seq() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..3 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
        log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
            .unwrap();
    }
    let audit = log.audit();
    assert_eq!(audit.latest_checkpoint_seq, Some(2));
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — slot_ids
// ---------------------------------------------------------------------------

#[test]
fn slot_ids_empty_log() {
    let log = ReplacementLineageLog::new(LineageLogConfig::default());
    assert!(log.slot_ids().is_empty());
}

#[test]
fn slot_ids_deduplicates_and_sorts() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let slots = ["zebra", "apple", "zebra", "mango"];
    for (i, slot) in slots.iter().enumerate() {
        let r = test_receipt(
            slot,
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i as u64) * 100,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i as u64) * 100)
            .unwrap();
    }
    let ids = log.slot_ids();
    assert_eq!(ids.len(), 3);
    assert_eq!(ids[0].as_str(), "apple");
    assert_eq!(ids[1].as_str(), "mango");
    assert_eq!(ids[2].as_str(), "zebra");
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — consistency_proof edge cases
// ---------------------------------------------------------------------------

#[test]
fn consistency_proof_equal_seqs_fails() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    log.create_checkpoint(100, SecurityEpoch::from_raw(1))
        .unwrap();
    let err = log.consistency_proof(0, 0).unwrap_err();
    assert!(matches!(
        err,
        LineageLogError::InvalidCheckpointOrder { .. }
    ));
}

#[test]
fn consistency_proof_missing_older_fails() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    log.create_checkpoint(100, SecurityEpoch::from_raw(1))
        .unwrap();
    let err = log.consistency_proof(99, 0).unwrap_err();
    // 99 >= 0 triggers InvalidCheckpointOrder (not CheckpointNotFound).
    assert!(matches!(
        err,
        LineageLogError::InvalidCheckpointOrder { .. }
    ));
}

#[test]
fn consistency_proof_verifies_after_many_entries() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..20 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
        if i == 9 || i == 19 {
            log.create_checkpoint(i * 100, SecurityEpoch::from_raw(1))
                .unwrap();
        }
    }
    let proof = log.consistency_proof(0, 1).unwrap();
    assert!(verify_consistency_proof(&proof));
    assert_eq!(proof.older_log_length, 10);
    assert_eq!(proof.newer_log_length, 20);
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — events
// ---------------------------------------------------------------------------

#[test]
fn append_emits_entry_appended_event() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    assert!(!log.events().is_empty());
    assert_eq!(log.events()[0].event, "entry_appended");
    assert_eq!(log.events()[0].outcome, "ok");
    assert_eq!(log.events()[0].component, "replacement_lineage_log");
    assert_eq!(log.events()[0].policy_id, "replacement-lineage-policy");
}

#[test]
fn checkpoint_emits_checkpoint_created_event() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    let r = test_receipt("slot-a", "old", "new", 100);
    log.append(r, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    log.create_checkpoint(100, SecurityEpoch::from_raw(1))
        .unwrap();
    let cp_events: Vec<_> = log
        .events()
        .iter()
        .filter(|e| e.event == "checkpoint_created")
        .collect();
    assert_eq!(cp_events.len(), 1);
    assert_eq!(cp_events[0].outcome, "ok");
}

// ---------------------------------------------------------------------------
// ReplacementLineageLog — full serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn full_log_serde_roundtrip() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
    for i in 0..5 {
        let r = test_receipt("slot-a", &format!("old-{i}"), &format!("new-{i}"), i * 100);
        log.append(r, ReplacementKind::DelegateToNative, i * 100)
            .unwrap();
    }
    log.create_checkpoint(400, SecurityEpoch::from_raw(1))
        .unwrap();
    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log.len(), back.len());
    assert_eq!(log.merkle_root(), back.merkle_root());
    assert_eq!(log.checkpoints().len(), back.checkpoints().len());
}

// ---------------------------------------------------------------------------
// EvidenceCategory — Copy, Hash, Ordering, Serde, Display
// ---------------------------------------------------------------------------

#[test]
fn evidence_category_is_copy() {
    let a = EvidenceCategory::GateResult;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn evidence_category_hash_five_distinct() {
    let mut set = HashSet::new();
    set.insert(EvidenceCategory::GateResult);
    set.insert(EvidenceCategory::PerformanceBenchmark);
    set.insert(EvidenceCategory::SentinelRiskScore);
    set.insert(EvidenceCategory::DifferentialExecutionLog);
    set.insert(EvidenceCategory::Additional);
    assert_eq!(set.len(), 5);
}

#[test]
fn evidence_category_as_str_all_five() {
    assert_eq!(EvidenceCategory::GateResult.as_str(), "gate_result");
    assert_eq!(
        EvidenceCategory::PerformanceBenchmark.as_str(),
        "performance_benchmark"
    );
    assert_eq!(
        EvidenceCategory::SentinelRiskScore.as_str(),
        "sentinel_risk_score"
    );
    assert_eq!(
        EvidenceCategory::DifferentialExecutionLog.as_str(),
        "differential_execution_log"
    );
    assert_eq!(EvidenceCategory::Additional.as_str(), "additional");
}

#[test]
fn evidence_category_display_matches_as_str() {
    for cat in [
        EvidenceCategory::GateResult,
        EvidenceCategory::PerformanceBenchmark,
        EvidenceCategory::SentinelRiskScore,
        EvidenceCategory::DifferentialExecutionLog,
        EvidenceCategory::Additional,
    ] {
        assert_eq!(format!("{cat}"), cat.as_str());
    }
}

#[test]
fn evidence_category_ordering() {
    let mut cats = [
        EvidenceCategory::Additional,
        EvidenceCategory::GateResult,
        EvidenceCategory::SentinelRiskScore,
        EvidenceCategory::PerformanceBenchmark,
        EvidenceCategory::DifferentialExecutionLog,
    ];
    cats.sort();
    assert_eq!(cats[0], EvidenceCategory::GateResult);
    assert_eq!(cats[1], EvidenceCategory::PerformanceBenchmark);
    assert_eq!(cats[2], EvidenceCategory::SentinelRiskScore);
    assert_eq!(cats[3], EvidenceCategory::DifferentialExecutionLog);
    assert_eq!(cats[4], EvidenceCategory::Additional);
}

// ---------------------------------------------------------------------------
// EvidencePointerInput / EvidencePointer — Serde
// ---------------------------------------------------------------------------

#[test]
fn evidence_pointer_input_serde_with_none_passed() {
    let input = EvidencePointerInput {
        category: EvidenceCategory::Additional,
        artifact_digest: "digest".to_string(),
        passed: None,
        summary: "summary".to_string(),
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: EvidencePointerInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn evidence_pointer_serde_all_fields() {
    let ptr = EvidencePointer {
        receipt_id: "r-1".to_string(),
        category: EvidenceCategory::SentinelRiskScore,
        artifact_digest: "d".to_string(),
        passed: Some(false),
        summary: "risk high".to_string(),
    };
    let json = serde_json::to_string(&ptr).unwrap();
    let back: EvidencePointer = serde_json::from_str(&json).unwrap();
    assert_eq!(ptr, back);
}

// ---------------------------------------------------------------------------
// LineageIndexError — Serde, Display, std::error::Error, codes
// ---------------------------------------------------------------------------

#[test]
fn lineage_index_error_storage_display() {
    let err = frankenengine_engine::replacement_lineage_log::LineageIndexError::Storage(
        StorageError::NotFound {
            store: StoreKind::ReplacementLineage,
            key: "k".into(),
        },
    );
    let s = format!("{err}");
    assert!(s.contains("storage error"));
}

#[test]
fn lineage_index_error_serialization_display() {
    let err = frankenengine_engine::replacement_lineage_log::LineageIndexError::Serialization {
        operation: "encode".into(),
        detail: "bad json".into(),
    };
    let s = format!("{err}");
    assert!(s.contains("encode"));
    assert!(s.contains("bad json"));
}

#[test]
fn lineage_index_error_corrupt_record_display() {
    let err = frankenengine_engine::replacement_lineage_log::LineageIndexError::CorruptRecord {
        key: "k1".into(),
        detail: "truncated".into(),
    };
    let s = format!("{err}");
    assert!(s.contains("k1"));
    assert!(s.contains("truncated"));
}

#[test]
fn lineage_index_error_invalid_input_display() {
    let err = frankenengine_engine::replacement_lineage_log::LineageIndexError::InvalidInput {
        detail: "empty id".into(),
    };
    let s = format!("{err}");
    assert!(s.contains("empty id"));
}

#[test]
fn lineage_index_error_codes() {
    use frankenengine_engine::replacement_lineage_log::LineageIndexError;
    assert_eq!(
        LineageIndexError::Storage(StorageError::NotFound {
            store: StoreKind::ReplacementLineage,
            key: "k".into(),
        })
        .code(),
        "FE-LIDX-0001"
    );
    assert_eq!(
        LineageIndexError::Serialization {
            operation: "o".into(),
            detail: "d".into()
        }
        .code(),
        "FE-LIDX-0002"
    );
    assert_eq!(
        LineageIndexError::CorruptRecord {
            key: "k".into(),
            detail: "d".into()
        }
        .code(),
        "FE-LIDX-0003"
    );
    assert_eq!(
        LineageIndexError::InvalidInput { detail: "d".into() }.code(),
        "FE-LIDX-0004"
    );
}

#[test]
fn lineage_index_error_is_std_error() {
    use frankenengine_engine::replacement_lineage_log::LineageIndexError;
    let err = LineageIndexError::InvalidInput {
        detail: "test".into(),
    };
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// ReplacementLineageEvidenceIndex — edge cases
// ---------------------------------------------------------------------------

#[test]
fn evidence_index_empty_receipt_id_demotion_rejected() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let input = DemotionReceiptInput {
        receipt_id: "  ".to_string(), // whitespace only
        slot_id: test_slot_id("slot-x"),
        demoted_cell_digest: "d".to_string(),
        restored_cell_digest: "r".to_string(),
        demotion_reason: "test".to_string(),
        timestamp_ns: 100,
        rollback_token_used: "tok".to_string(),
        linked_replacement_receipt_id: None,
        evidence: Vec::new(),
    };
    let err = idx.index_demotion_receipt(input, &ctx).unwrap_err();
    assert!(matches!(
        err,
        frankenengine_engine::replacement_lineage_log::LineageIndexError::InvalidInput { .. }
    ));
}

#[test]
fn evidence_index_replacement_then_lookup_by_hash() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let receipt = test_receipt("slot-lookup", "old", "new", 1000);
    let record = idx
        .index_replacement_receipt(&receipt, ReplacementKind::DelegateToNative, &[], &ctx)
        .unwrap();
    let found = idx
        .replacement_by_content_hash(&record.receipt_content_hash, &ctx)
        .unwrap()
        .unwrap();
    assert_eq!(found.receipt_id, record.receipt_id);
    assert_eq!(found.slot_id, record.slot_id);
}

#[test]
fn evidence_index_missing_hash_returns_none() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let found = idx
        .replacement_by_content_hash("nonexistent", &ctx)
        .unwrap();
    assert!(found.is_none());
}

#[test]
fn evidence_index_demotion_then_lookup_by_hash() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let input = DemotionReceiptInput {
        receipt_id: "dem-lookup".to_string(),
        slot_id: test_slot_id("slot-dl"),
        demoted_cell_digest: "d".to_string(),
        restored_cell_digest: "r".to_string(),
        demotion_reason: "regression".to_string(),
        timestamp_ns: 2000,
        rollback_token_used: "tok".to_string(),
        linked_replacement_receipt_id: None,
        evidence: Vec::new(),
    };
    let record = idx.index_demotion_receipt(input, &ctx).unwrap();
    let found = idx
        .demotion_by_content_hash(&record.receipt_content_hash, &ctx)
        .unwrap()
        .unwrap();
    assert_eq!(found.receipt_id, "dem-lookup");
}

#[test]
fn evidence_index_demotion_missing_hash_returns_none() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let found = idx.demotion_by_content_hash("missing", &ctx).unwrap();
    assert!(found.is_none());
}

#[test]
fn evidence_index_slot_lineage_empty() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let slot_id = test_slot_id("empty-slot");
    let query = SlotLineageQuery::default();
    let chain = idx.slot_lineage(&slot_id, &query, &ctx).unwrap();
    assert!(chain.is_empty());
}

#[test]
fn evidence_index_slot_lineage_with_limit() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    for i in 0..5 {
        let r = test_receipt(
            "slot-lim",
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 100,
        );
        idx.index_replacement_receipt(&r, ReplacementKind::DelegateToNative, &[], &ctx)
            .unwrap();
    }
    let slot_id = test_slot_id("slot-lim");
    let query = SlotLineageQuery {
        min_timestamp_ns: None,
        max_timestamp_ns: None,
        limit: Some(2),
    };
    let chain = idx.slot_lineage(&slot_id, &query, &ctx).unwrap();
    assert_eq!(chain.len(), 2);
}

#[test]
fn evidence_index_replay_join_empty() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let query = ReplayJoinQuery::default();
    let rows = idx.replay_join(&query, &ctx).unwrap();
    assert!(rows.is_empty());
}

#[test]
fn evidence_index_replay_join_with_evidence_categories() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let receipt = test_receipt("slot-rj", "old", "new", 1000);
    let evidence = vec![
        EvidencePointerInput {
            category: EvidenceCategory::GateResult,
            artifact_digest: "gate-d".to_string(),
            passed: Some(true),
            summary: "gate ok".to_string(),
        },
        EvidencePointerInput {
            category: EvidenceCategory::PerformanceBenchmark,
            artifact_digest: "perf-d".to_string(),
            passed: Some(true),
            summary: "perf ok".to_string(),
        },
        EvidencePointerInput {
            category: EvidenceCategory::SentinelRiskScore,
            artifact_digest: "risk-d".to_string(),
            passed: Some(false),
            summary: "risk high".to_string(),
        },
        EvidencePointerInput {
            category: EvidenceCategory::DifferentialExecutionLog,
            artifact_digest: "diff-d".to_string(),
            passed: Some(true),
            summary: "diff ok".to_string(),
        },
        EvidencePointerInput {
            category: EvidenceCategory::Additional,
            artifact_digest: "add-d".to_string(),
            passed: None,
            summary: "extra".to_string(),
        },
    ];
    idx.index_replacement_receipt(&receipt, ReplacementKind::DelegateToNative, &evidence, &ctx)
        .unwrap();
    let query = ReplayJoinQuery::default();
    let rows = idx.replay_join(&query, &ctx).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    // Inline validation artifacts contribute gate_result + differential_execution_log.
    // Plus our supplemental evidence.
    assert!(!row.gate_results.is_empty());
    assert!(!row.performance_benchmarks.is_empty());
    assert!(!row.sentinel_risk_scores.is_empty());
    assert!(!row.differential_execution_logs.is_empty());
    assert!(!row.additional_evidence.is_empty());
}

#[test]
fn evidence_index_emits_events_on_operations() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();
    let receipt = test_receipt("slot-ev", "old", "new", 100);
    idx.index_replacement_receipt(&receipt, ReplacementKind::DelegateToNative, &[], &ctx)
        .unwrap();
    assert!(!idx.events().is_empty());
    assert_eq!(idx.events()[0].event, "index_replacement_receipt");
    assert_eq!(idx.events()[0].outcome, "ok");
    assert_eq!(idx.events()[0].component, "replacement_lineage_index");
}

#[test]
fn evidence_index_into_inner_recovers_adapter() {
    let adapter = InMemoryStorageAdapter::new();
    let idx = ReplacementLineageEvidenceIndex::new(adapter);
    let _recovered = idx.into_inner();
}

// ---------------------------------------------------------------------------
// SlotLineageQuery / ReplayJoinQuery — Serde
// ---------------------------------------------------------------------------

#[test]
fn slot_lineage_query_default_is_unfiltered() {
    let query = SlotLineageQuery::default();
    assert!(query.min_timestamp_ns.is_none());
    assert!(query.max_timestamp_ns.is_none());
    assert!(query.limit.is_none());
}

#[test]
fn replay_join_query_default_is_unfiltered() {
    let query = ReplayJoinQuery::default();
    assert!(query.slot_id.is_none());
    assert!(query.min_timestamp_ns.is_none());
    assert!(query.max_timestamp_ns.is_none());
    assert!(query.limit.is_none());
}

// ---------------------------------------------------------------------------
// LineageChainEntry — Serde
// ---------------------------------------------------------------------------

#[test]
fn lineage_chain_entry_serde() {
    let entry = LineageChainEntry {
        slot_id: test_slot_id("slot-ce"),
        timestamp_ns: 42,
        receipt_id: "r".to_string(),
        kind: ReplacementKind::Rollback,
        from_cell_digest: "f".to_string(),
        to_cell_digest: "t".to_string(),
        receipt_content_hash: "h".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: LineageChainEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// Determinism — 100 iterations
// ---------------------------------------------------------------------------

#[test]
fn deterministic_100_iterations_append_and_audit() {
    let mut reference_root = None;
    for _ in 0..100 {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-det", "old", "new", 42);
        log.append(r, ReplacementKind::DelegateToNative, 42)
            .unwrap();
        let root = log.merkle_root();
        if let Some(ref expected) = reference_root {
            assert_eq!(&root, expected);
        } else {
            reference_root = Some(root);
        }
    }
}

#[test]
fn deterministic_100_iterations_entry_hash() {
    let mut reference_hash = None;
    for _ in 0..100 {
        let mut log = ReplacementLineageLog::new(LineageLogConfig::default());
        let r = test_receipt("slot-det2", "old2", "new2", 99);
        log.append(r, ReplacementKind::Rollback, 99).unwrap();
        let hash = log.entries()[0].entry_hash.clone();
        if let Some(ref expected) = reference_hash {
            assert_eq!(&hash, expected);
        } else {
            reference_hash = Some(hash);
        }
    }
}

// ---------------------------------------------------------------------------
// Integration — full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn integration_full_lifecycle_log() {
    // 1. Create log, append entries across multiple slots and kinds.
    let config = LineageLogConfig {
        checkpoint_interval: 5,
        max_entries_in_memory: 0,
    };
    let mut log = ReplacementLineageLog::new(config);

    let r1 = test_receipt("slot-a", "delegate-v1", "native-v1", 100);
    let r2 = test_receipt("slot-b", "delegate-b1", "native-b1", 200);
    let r3 = test_receipt("slot-a", "native-v1", "delegate-v1", 300);
    let r4 = test_receipt("slot-a", "delegate-v1", "native-v2", 400);
    let r5 = test_receipt("slot-c", "delegate-c1", "native-c1", 500);

    log.append(r1, ReplacementKind::DelegateToNative, 100)
        .unwrap();
    log.append(r2, ReplacementKind::DelegateToNative, 200)
        .unwrap();
    log.append(r3, ReplacementKind::Demotion, 300).unwrap();
    log.append(r4, ReplacementKind::RePromotion, 400).unwrap();
    log.append(r5, ReplacementKind::DelegateToNative, 500)
        .unwrap();

    // 2. Auto-checkpoint at 5 entries.
    assert_eq!(log.checkpoints().len(), 1);

    // 3. Verify slot lineages.
    let lineage_a = log.slot_lineage(&test_slot_id("slot-a"));
    assert_eq!(lineage_a.len(), 3);
    assert_eq!(lineage_a[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(lineage_a[1].kind, ReplacementKind::Demotion);
    assert_eq!(lineage_a[2].kind, ReplacementKind::RePromotion);

    // 4. Verify slot_ids.
    let ids = log.slot_ids();
    assert_eq!(ids.len(), 3);

    // 5. Full audit passes.
    let audit = log.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert!(audit.issues.is_empty());
    assert_eq!(audit.total_entries, 5);
    assert_eq!(audit.total_slots, 3);

    // 6. Inclusion proofs valid for all entries.
    for i in 0..5 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof), "inclusion failed at {i}");
    }

    // 7. Serde roundtrip.
    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log.merkle_root(), back.merkle_root());
    assert_eq!(log.len(), back.len());
}

#[test]
fn integration_evidence_index_replacement_and_demotion_flow() {
    let mut idx = ReplacementLineageEvidenceIndex::new(InMemoryStorageAdapter::new());
    let ctx = test_context();

    // 1. Index a replacement receipt.
    let receipt = test_receipt("slot-int", "old", "new", 1000);
    let repl_record = idx
        .index_replacement_receipt(
            &receipt,
            ReplacementKind::DelegateToNative,
            &[EvidencePointerInput {
                category: EvidenceCategory::GateResult,
                artifact_digest: "gate-1".to_string(),
                passed: Some(true),
                summary: "passed".to_string(),
            }],
            &ctx,
        )
        .unwrap();

    // 2. Index a linked demotion receipt.
    let dem_input = DemotionReceiptInput {
        receipt_id: "dem-int".to_string(),
        slot_id: test_slot_id("slot-int"),
        demoted_cell_digest: "new".to_string(),
        restored_cell_digest: "old".to_string(),
        demotion_reason: "regression".to_string(),
        timestamp_ns: 2000,
        rollback_token_used: "rollback-old".to_string(),
        linked_replacement_receipt_id: Some(repl_record.receipt_id.clone()),
        evidence: vec![EvidencePointerInput {
            category: EvidenceCategory::SentinelRiskScore,
            artifact_digest: "risk-1".to_string(),
            passed: Some(false),
            summary: "risk detected".to_string(),
        }],
    };
    idx.index_demotion_receipt(dem_input, &ctx).unwrap();

    // 3. Query slot lineage.
    let chain = idx
        .slot_lineage(
            &test_slot_id("slot-int"),
            &SlotLineageQuery::default(),
            &ctx,
        )
        .unwrap();
    assert_eq!(chain.len(), 2); // replacement + demotion

    // 4. Replay join shows demotion linked to replacement.
    let rows = idx.replay_join(&ReplayJoinQuery::default(), &ctx).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].demotion_receipt_id.is_some());
    assert_eq!(rows[0].demotion_reason.as_deref(), Some("regression"));

    // 5. Events emitted for all operations.
    assert!(idx.events().len() >= 2);
}
